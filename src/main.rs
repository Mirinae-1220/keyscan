mod detect;
mod entropy;
mod finding;
mod hook;
mod report;
mod rules;
mod skip;
mod source;
mod validate;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};

use crate::finding::Finding;
use crate::report::{Format, Mode};
use crate::rules::Severity;
use crate::skip::Skip;

const CONFIG_FILE: &str = ".keyscan.toml";

#[derive(Parser)]
#[command(
    name = "keyscan",
    version,
    about = "git 레포에서 비밀값과 개인정보를 찾아 커밋 전에 막고 재발급 방법을 알려 줍니다"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// git이 관리하는 파일 전체 검사 (git 레포가 아니면 폴더 전체)
    Scan {
        /// 검사할 경로 (기본: 현재 폴더)
        path: Option<PathBuf>,
        #[command(flatten)]
        opts: Opts,
    },
    /// 스테이지된 변경에서 새로 추가된 줄만 검사 (pre-commit 훅용)
    Staged {
        #[command(flatten)]
        opts: Opts,
    },
    /// 모든 브랜치의 커밋 기록에서 추가된 줄 검사
    History {
        #[command(flatten)]
        opts: Opts,
    },
    /// .git/hooks/pre-commit에 `keyscan staged` 훅 설치
    InstallHook,
}

#[derive(Args)]
struct Opts {
    /// 출력 형식
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    /// 설정 파일 경로 (기본: 레포 최상위의 .keyscan.toml)
    #[arg(long)]
    config: Option<PathBuf>,
    /// 엔트로피 검사 끄기
    #[arg(long)]
    no_entropy: bool,
    /// 이 위험도 이상만 보고
    #[arg(long, value_enum, default_value = "low")]
    min_severity: Severity,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("오류: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn require_repo() -> Result<PathBuf> {
    match source::repo_root(Path::new("."))? {
        Some(top) => Ok(top),
        None => bail!("git 레포 안에서 실행하세요"),
    }
}

fn run(cli: Cli) -> Result<u8> {
    match cli.cmd {
        Cmd::Scan { path, opts } => {
            let dir = path.unwrap_or_else(|| PathBuf::from("."));
            if !dir.is_dir() {
                bail!("폴더가 아닙니다: {}", dir.display());
            }
            match source::repo_root(&dir)? {
                Some(top) => check(&top, &opts, Mode::Files, |skip, sink| {
                    source::scan_git(&dir, &top, skip, sink)
                }),
                None => check(&dir, &opts, Mode::Files, |skip, sink| {
                    source::scan_dir(&dir, skip, sink)
                }),
            }
        }
        Cmd::Staged { opts } => {
            let top = require_repo()?;
            check(&top, &opts, Mode::Files, |skip, sink| {
                source::scan_staged(&top, skip, sink)
            })
        }
        Cmd::History { opts } => {
            let top = require_repo()?;
            check(&top, &opts, Mode::History, |skip, sink| {
                source::scan_history(&top, skip, sink)
            })
        }
        Cmd::InstallHook => {
            hook::install()?;
            Ok(0)
        }
    }
}

fn check(
    base: &Path,
    opts: &Opts,
    mode: Mode,
    read: impl FnOnce(&Skip, &source::Sink) -> Result<source::Stats>,
) -> Result<u8> {
    let config = rules::load(
        opts.config.as_deref(),
        &base.join(CONFIG_FILE),
        opts.no_entropy,
    )?;
    let rules = &config.rules;
    let skip = Skip::load(base)?;

    let found = Mutex::new(Vec::new());
    let stats = read(&skip, &|l| {
        for hit in detect::detect_line(rules, config.entropy.as_ref(), l.path, l.text) {
            if rules[hit.rule].severity >= opts.min_severity {
                found.lock().unwrap().push(Finding {
                    rule: hit.rule,
                    path: l.path.to_string(),
                    line: l.line,
                    commit: l.commit.map(str::to_string),
                    masked: hit.masked,
                });
            }
        }
    })?;

    let mut findings = found.into_inner().unwrap();
    report::sort(rules, &mut findings);
    report::print(opts.format, rules, &findings, &stats, mode);

    Ok(if !findings.is_empty() {
        1
    } else if stats.errors > 0 {
        2
    } else {
        0
    })
}
