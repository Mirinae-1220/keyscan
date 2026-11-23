use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use anyhow::{Context, Result, bail};

use crate::skip::Skip;

const BINARY_SNIFF: usize = 8000;
const COMMIT_MARK: &str = "\0keyscan-commit ";

#[derive(Default)]
pub struct Stats {
    pub files: usize,
    pub commits: usize,
    pub errors: usize,
}

pub struct Line<'a> {
    pub path: &'a str,
    pub line: usize,
    pub commit: Option<&'a str>,
    pub text: &'a str,
}

pub type Sink<'a> = dyn Fn(Line) + Sync + 'a;

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

fn scan_file(full: &Path, rel: &str, sink: &Sink) -> Result<bool, std::io::Error> {
    let bytes = match fs::read(full) {
        Ok(b) => b,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if is_binary(&bytes) {
        return Ok(true);
    }
    let text = String::from_utf8_lossy(&bytes);
    for (i, line) in text.lines().enumerate() {
        sink(Line {
            path: rel,
            line: i + 1,
            commit: None,
            text: line,
        });
    }
    Ok(true)
}

fn scan_files(files: &[(PathBuf, String)], sink: &Sink) -> Stats {
    let next = AtomicUsize::new(0);
    let scanned = AtomicUsize::new(0);
    let errors = AtomicUsize::new(0);
    let workers = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(files.len().max(1));
    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((full, rel)) = files.get(i) else {
                        break;
                    };
                    match scan_file(full, rel, sink) {
                        Ok(true) => {
                            scanned.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(false) => {}
                        Err(e) => {
                            eprintln!("경고: 파일을 읽지 못했습니다: {rel} ({e})");
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
    });
    Stats {
        files: scanned.into_inner(),
        commits: 0,
        errors: errors.into_inner(),
    }
}

pub fn scan_git(dir: &Path, top: &Path, skip: &Skip, sink: &Sink) -> Result<Stats> {
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

    let files: Vec<(PathBuf, String)> = paths
        .into_iter()
        .filter(|rel| !skip.skips(rel))
        .map(|rel| (top.join(&rel), rel))
        .filter(|(full, _)| !full.is_dir())
        .collect();
    Ok(scan_files(&files, sink))
}

pub fn scan_dir(root: &Path, skip: &Skip, sink: &Sink) -> Result<Stats> {
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .filter_entry(|e| e.file_name() != ".git")
        .build();
    let mut files = Vec::new();
    let mut walk_errors = 0;
    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("경고: 폴더를 읽지 못했습니다: {e}");
                walk_errors += 1;
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
        files.push((entry.path().to_path_buf(), rel));
    }
    let mut stats = scan_files(&files, sink);
    stats.errors += walk_errors;
    Ok(stats)
}

const DIFF_ARGS: &[&str] = &["--no-color", "--no-ext-diff", "--no-textconv", "-U0"];

pub fn scan_staged(top: &Path, skip: &Skip, sink: &Sink) -> Result<Stats> {
    let mut args = vec!["-c", "core.quotepath=false", "diff", "--cached"];
    args.extend_from_slice(DIFF_ARGS);
    args.push("--diff-filter=d");
    let diff = git_ok(top, &args)?;
    Ok(parse_diff(&diff, skip, sink))
}

pub fn scan_history(top: &Path, skip: &Skip, sink: &Sink) -> Result<Stats> {
    let format = format!("--format={}%H", COMMIT_MARK.replace('\0', "%x00"));
    let mut args = vec!["-c", "core.quotepath=false", "log", "-p", "--all"];
    args.extend_from_slice(DIFF_ARGS);
    args.push(&format);
    let log = git_ok(top, &args)?;
    Ok(parse_diff(&log, skip, sink))
}

fn parse_diff(diff: &str, skip: &Skip, sink: &Sink) -> Stats {
    let mut stats = Stats::default();
    let mut commit: Option<&str> = None;
    let mut path: Option<String> = None;
    let mut in_hunk = false;
    let mut line_no = 0usize;
    for line in diff.lines() {
        if let Some(hash) = line.strip_prefix(COMMIT_MARK) {
            commit = Some(hash.trim());
            stats.commits += 1;
            path = None;
            in_hunk = false;
            continue;
        }
        if line.starts_with("diff --git ") {
            path = None;
            in_hunk = false;
            continue;
        }
        if !in_hunk && let Some(p) = line.strip_prefix("+++ ") {
            path = p
                .strip_prefix("b/")
                .map(|p| p.trim_end_matches('\t').to_string())
                .filter(|p| !skip.skips(p));
            if path.is_some() {
                stats.files += 1;
            }
            continue;
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
                sink(Line {
                    path: p,
                    line: line_no,
                    commit,
                    text: added,
                });
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

    fn collect(diff: &str) -> (Vec<String>, Stats) {
        let got = std::sync::Mutex::new(Vec::new());
        let stats = parse_diff(
            diff,
            &Skip::load(Path::new("/nonexistent")).unwrap(),
            &|l: Line| {
                got.lock().unwrap().push(format!(
                    "{}:{}:{}:{}",
                    l.commit.unwrap_or("-"),
                    l.path,
                    l.line,
                    l.text
                ))
            },
        );
        (got.into_inner().unwrap(), stats)
    }

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
        let (got, stats) = collect(diff);
        assert_eq!(
            got,
            vec!["-:a.txt:4:one", "-:a.txt:5:two", "-:a.txt:12:new"]
        );
        assert_eq!(stats.files, 1);
    }

    #[test]
    fn tracks_commits_in_log() {
        let log = format!(
            "{COMMIT_MARK}aaa\n\ndiff --git a/x b/x\n--- /dev/null\n+++ b/x\n@@ -0,0 +1 @@\n+first\n\
             {COMMIT_MARK}bbb\n\ndiff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,0 +2 @@\n+second\n"
        );
        let (got, stats) = collect(&log);
        assert_eq!(got, vec!["aaa:x:1:first", "bbb:x:2:second"]);
        assert_eq!(stats.commits, 2);
    }

    #[test]
    fn detects_binary() {
        assert!(is_binary(b"abc\0def"));
        assert!(!is_binary(b"plain text"));
    }
}
