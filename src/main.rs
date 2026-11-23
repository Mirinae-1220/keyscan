mod detect;
mod finding;
mod hook;
mod report;
mod rules;
mod skip;
mod source;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};

use crate::finding::Finding;
use crate::rules::Severity;
use crate::skip::Skip;

const CONFIG_FILE: &str = ".keyscan.toml";

#[derive(Parser)]
#[command(
    name = "keyscan",
    version,
    about = "git 레포에서 비밀값을 찾아 커밋 전에 막고 재발급 방법을 알려 줍니다"
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
    /// .git/hooks/pre-commit에 `keyscan staged` 훅 설치
    InstallHook,
}

#[derive(Args)]
struct Opts {
    /// 설정 파일 경로 (기본: 레포 최상위의 .keyscan.toml)
    #[arg(long)]
    config: Option<PathBuf>,
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

fn run(cli: Cli) -> Result<u8> {
    match cli.cmd {
        Cmd::Scan { path, opts } => {
            let dir = path.unwrap_or_else(|| PathBuf::from("."));
            if !dir.is_dir() {
                bail!("폴더가 아닙니다: {}", dir.display());
            }
            match source::repo_root(&dir)? {
                Some(top) => check(&top, &opts, |skip, sink| {
                    source::scan_git(&dir, &top, skip, sink)
                }),
                None => check(&dir, &opts, |skip, sink| source::scan_dir(&dir, skip, sink)),
            }
        }
        Cmd::Staged { opts } => {
            let Some(top) = source::repo_root(Path::new("."))? else {
                bail!("git 레포 안에서 실행하세요");
            };
            check(&top, &opts, |skip, sink| {
                source::scan_staged(&top, skip, sink)
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
    read: impl FnOnce(&Skip, &mut source::Sink) -> Result<source::Stats>,
) -> Result<u8> {
    let rules = rules::load(opts.config.as_deref(), &base.join(CONFIG_FILE))?;
    let skip = Skip::load(base)?;

    let mut findings = Vec::new();
    let stats = read(&skip, &mut |path, line, text| {
        for hit in detect::detect_line(&rules, text) {
            if rules[hit.rule].severity >= opts.min_severity {
                findings.push(Finding {
                    rule: hit.rule,
                    path: path.to_string(),
                    line,
                    masked: hit.masked,
                });
            }
        }
    })?;

    report::print_text(&rules, &mut findings, stats.files);

    Ok(if !findings.is_empty() {
        1
    } else if stats.errors > 0 {
        2
    } else {
        0
    })
}
