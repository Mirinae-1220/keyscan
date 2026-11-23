use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::skip::Skip;

const BINARY_SNIFF: usize = 8000;

pub struct Stats {
    pub files: usize,
    pub errors: usize,
}

pub type Sink<'a> = dyn FnMut(&str, usize, &str) + 'a;

fn git(dir: &Path, args: &[&str]) -> Result<std::process::Output> {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .context("git을 실행하지 못했습니다. git이 설치되어 있고 PATH에 있는지 확인하세요")
}

fn git_ok(dir: &Path, args: &[&str]) -> Result<String> {
    let out = git(dir, args)?;
    if !out.status.success() {
        bail!(
            "git {} 실패: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn repo_root(dir: &Path) -> Result<Option<PathBuf>> {
    let out = git(dir, &["rev-parse", "--show-toplevel"])?;
    if !out.status.success() {
        return Ok(None);
    }
    let top = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(Some(PathBuf::from(top)))
}

fn is_binary(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(BINARY_SNIFF)].contains(&0)
}

fn scan_file(full: &Path, rel: &str, stats: &mut Stats, sink: &mut Sink) {
    let bytes = match fs::read(full) {
        Ok(b) => b,
        Err(e) if e.kind() == ErrorKind::NotFound => return,
        Err(e) => {
            eprintln!("경고: 파일을 읽지 못했습니다: {rel} ({e})");
            stats.errors += 1;
            return;
        }
    };
    stats.files += 1;
    if is_binary(&bytes) {
        return;
    }
    let text = String::from_utf8_lossy(&bytes);
    for (i, line) in text.lines().enumerate() {
        sink(rel, i + 1, line);
    }
}

pub fn scan_git(dir: &Path, top: &Path, skip: &Skip, sink: &mut Sink) -> Result<Stats> {
    let prefix = git_ok(dir, &["rev-parse", "--show-prefix"])?
        .trim()
        .to_string();
    let listed = git_ok(
        dir,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    )?;
    let mut paths: Vec<String> = listed
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(|p| format!("{prefix}{p}"))
        .collect();
    paths.sort();
    paths.dedup();

    let mut stats = Stats {
        files: 0,
        errors: 0,
    };
    for rel in paths {
        if skip.skips(&rel) {
            continue;
        }
        let full = top.join(&rel);
        if full.is_dir() {
            continue;
        }
        scan_file(&full, &rel, &mut stats, sink);
    }
    Ok(stats)
}

pub fn scan_dir(root: &Path, skip: &Skip, sink: &mut Sink) -> Result<Stats> {
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .filter_entry(|e| e.file_name() != ".git")
        .build();
    let mut stats = Stats {
        files: 0,
        errors: 0,
    };
    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("경고: 폴더를 읽지 못했습니다: {e}");
                stats.errors += 1;
                continue;
            }
        };
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        if skip.skips(&rel) {
            continue;
        }
        scan_file(entry.path(), &rel, &mut stats, sink);
    }
    Ok(stats)
}

pub fn scan_staged(top: &Path, skip: &Skip, sink: &mut Sink) -> Result<Stats> {
    let diff = git_ok(
        top,
        &[
            "-c",
            "core.quotepath=false",
            "diff",
            "--cached",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "-U0",
            "--diff-filter=d",
        ],
    )?;
    Ok(parse_diff(&diff, skip, sink))
}

fn parse_diff(diff: &str, skip: &Skip, sink: &mut Sink) -> Stats {
    let mut stats = Stats {
        files: 0,
        errors: 0,
    };
    let mut path: Option<String> = None;
    let mut in_hunk = false;
    let mut line_no = 0usize;
    for line in diff.lines() {
        if line.starts_with("diff --git ") {
            path = None;
            in_hunk = false;
            continue;
        }
        if !in_hunk {
            if let Some(p) = line.strip_prefix("+++ ") {
                path = p
                    .strip_prefix("b/")
                    .map(|p| p.trim_end_matches('\t').to_string())
                    .filter(|p| !skip.skips(p));
                if path.is_some() {
                    stats.files += 1;
                }
                continue;
            }
        }
        if let Some(rest) = line.strip_prefix("@@ ") {
            in_hunk = true;
            line_no = hunk_start(rest).unwrap_or(1);
            continue;
        }
        if !in_hunk {
            continue;
        }
        if let Some(added) = line.strip_prefix('+') {
            if let Some(p) = &path {
                sink(p, line_no, added);
            }
            line_no += 1;
        }
    }
    stats
}

fn hunk_start(rest: &str) -> Option<usize> {
    let plus = rest.split(' ').find(|s| s.starts_with('+'))?;
    plus[1..].split(',').next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_added_lines_with_numbers() {
        let diff = "diff --git a/a.txt b/a.txt\n\
                    index 1..2 100644\n\
                    --- a/a.txt\n\
                    +++ b/a.txt\n\
                    @@ -3,0 +4,2 @@ ctx\n\
                    +one\n\
                    +two\n\
                    @@ -10 +12 @@\n\
                    -old\n\
                    +new\n\
                    diff --git a/b.bin b/b.bin\n\
                    Binary files a/b.bin and b/b.bin differ\n";
        let mut got = Vec::new();
        let stats = parse_diff(
            diff,
            &Skip::load(Path::new("/nonexistent")).unwrap(),
            &mut |p, n, l| got.push(format!("{p}:{n}:{l}")),
        );
        assert_eq!(got, vec!["a.txt:4:one", "a.txt:5:two", "a.txt:12:new"]);
        assert_eq!(stats.files, 1);
    }

    #[test]
    fn detects_binary() {
        assert!(is_binary(b"abc\0def"));
        assert!(!is_binary(b"plain text"));
    }
}
