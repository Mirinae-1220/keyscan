use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_keyscan");

fn bot_token() -> String {
    ["MT", &"A".repeat(24), ".", "Gabcde", ".", &"x".repeat(38)].concat()
}

fn github_token() -> String {
    ["gh", "p_", &"Z9y8".repeat(9)].concat()
}

struct Repo {
    dir: TempDir,
    gitconfig: PathBuf,
}

impl Repo {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let gitconfig = dir.path().join("..").join(format!(
            "keyscan-gitconfig-{}",
            dir.path().file_name().unwrap().to_string_lossy()
        ));
        fs::write(&gitconfig, "").unwrap();
        let repo = Repo { dir, gitconfig };
        repo.git(&["init", "-q"]);
        repo
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn env(&self, cmd: &mut Command) {
        cmd.current_dir(self.path())
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid");
    }

    fn git(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new("git");
        cmd.args(args);
        self.env(&mut cmd);
        cmd.output().unwrap()
    }

    fn write(&self, rel: &str, text: &str) {
        let p = self.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }

    fn commit_all(&self) {
        self.git(&["add", "-A"]);
        let out = self.git(&["commit", "-q", "-m", "test", "--no-verify"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn keyscan(&self, args: &[&str]) -> (i32, String, String) {
        let mut cmd = Command::new(BIN);
        cmd.args(args);
        self.env(&mut cmd);
        let out = cmd.output().unwrap();
        (
            out.status.code().unwrap(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.gitconfig);
    }
}

fn assert_no_secret(text: &str) {
    assert!(
        !text.contains(&bot_token()),
        "원문 봇 토큰이 출력됐습니다:\n{text}"
    );
    assert!(
        !text.contains(&github_token()),
        "원문 GitHub 토큰이 출력됐습니다:\n{text}"
    );
    assert!(
        !text.contains(&bot_token()[..20]),
        "봇 토큰 일부가 출력됐습니다:\n{text}"
    );
}

#[test]
fn scan_finds_committed_env_and_source_default() {
    let repo = Repo::new();
    repo.write(".env", &format!("DISCORD_TOKEN={}\n", bot_token()));
    repo.write(
        "src/config.rs",
        &format!(
            "fn main() {{}}\n\nconst DEFAULT: &str = \"{}\";\n",
            github_token()
        ),
    );
    repo.write("README.md", "hello\n");
    repo.commit_all();

    let (code, out, err) = repo.keyscan(&["scan"]);
    assert_eq!(code, 1, "{out}{err}");
    assert!(out.contains("[high] discord-bot-token"), "{out}");
    assert!(out.contains(".env:1"), "{out}");
    assert!(out.contains("[high] github-token"), "{out}");
    assert!(out.contains("src/config.rs:3"), "{out}");
    assert!(out.contains("해결: "), "{out}");
    assert!(out.contains("2건 발견 (파일 3개 검사)"), "{out}");
    assert_no_secret(&out);
    assert_no_secret(&err);
}

#[test]
fn scan_includes_untracked_but_not_gitignored() {
    let repo = Repo::new();
    repo.write(".gitignore", ".env\n");
    repo.write(".env", &format!("TOKEN={}\n", bot_token()));
    repo.write("new.txt", &format!("TOKEN={}\n", github_token()));

    let (code, out, _) = repo.keyscan(&["scan"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("new.txt:1"), "{out}");
    assert!(!out.contains(".env"), "{out}");
}

#[test]
fn scan_clean_repo_exits_zero() {
    let repo = Repo::new();
    repo.write("a.txt", "nothing here\n");
    repo.commit_all();
    let (code, out, _) = repo.keyscan(&["scan"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("찾은 것 없음 (파일 1개 검사)"), "{out}");
}

#[test]
fn scan_plain_folder_without_git() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join(".env"), format!("T={}\n", bot_token())).unwrap();
    let out = Command::new(BIN)
        .arg("scan")
        .arg(dir.path())
        .env("GIT_CEILING_DIRECTORIES", dir.path().parent().unwrap())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains(".env:1"), "{stdout}");
}

#[test]
fn allow_mark_and_ignore_file() {
    let repo = Repo::new();
    repo.write("a.txt", &format!("T={} # keyscan:allow\n", bot_token()));
    repo.write("fixtures/b.txt", &format!("T={}\n", bot_token()));
    repo.write(".keyscanignore", "fixtures/\n");
    let (code, out, _) = repo.keyscan(&["scan"]);
    assert_eq!(code, 0, "{out}");
}

#[test]
fn binary_files_are_skipped() {
    let repo = Repo::new();
    let mut bytes = b"\0\0\0".to_vec();
    bytes.extend_from_slice(bot_token().as_bytes());
    fs::write(repo.path().join("blob.bin"), bytes).unwrap();
    let (code, out, _) = repo.keyscan(&["scan"]);
    assert_eq!(code, 0, "{out}");
}

#[test]
fn config_disable_and_min_severity() {
    let repo = Repo::new();
    repo.write("a.txt", &format!("T={}\n", bot_token()));
    repo.write(".keyscan.toml", "disable = [\"discord-bot-token\"]\n");
    let (code, out, _) = repo.keyscan(&["scan"]);
    assert_eq!(code, 0, "{out}");

    fs::remove_file(repo.path().join(".keyscan.toml")).unwrap();
    let url = [
        "https://discord.com/api/web",
        "hooks/123456789012345678/",
        &"w".repeat(68),
    ]
    .concat();
    repo.write("a.txt", &format!("URL={url}\n"));
    let (code, out, _) = repo.keyscan(&["scan", "--min-severity", "high"]);
    assert_eq!(code, 0, "{out}");
    let (code, out, _) = repo.keyscan(&["scan"]);
    assert_eq!(code, 1, "{out}");
    assert!(!out.contains(&url[40..]), "{out}");
}

#[test]
fn user_rule_with_keywords() {
    let repo = Repo::new();
    repo.write(
        ".keyscan.toml",
        r#"
[[rule]]
id = "corp-key"
name = "사내 API 키"
regex = '\b[0-9a-f]{32}\b'
keywords = ["corp"]
severity = "high"
fix = "사내 키 관리 화면에서 재발급"
"#,
    );
    let hex = "0123456789abcdef".repeat(2);
    repo.write("a.txt", &format!("CORP_ID={hex}\ncommit {hex}\n"));
    let (code, out, _) = repo.keyscan(&["scan"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("1건 발견"), "{out}");
    assert!(out.contains("해결: 사내 키 관리 화면에서 재발급"), "{out}");
}

#[test]
fn errors_exit_two() {
    let repo = Repo::new();
    let (code, _, err) = repo.keyscan(&["scan", "--config", "missing.toml"]);
    assert_eq!(code, 2);
    assert!(err.contains("설정 파일"), "{err}");

    repo.write(".keyscan.toml", "disable = [\"no-such-rule\"]\n");
    let (code, _, _) = repo.keyscan(&["scan"]);
    assert_eq!(code, 2);

    repo.write(".keyscan.toml", "unknown = 1\n");
    let (code, _, _) = repo.keyscan(&["scan"]);
    assert_eq!(code, 2);

    let (code, _, _) = repo.keyscan(&["scan", "no-such-dir"]);
    assert_eq!(code, 2);
}

#[test]
fn staged_checks_only_added_lines() {
    let repo = Repo::new();
    repo.write("a.txt", &format!("old\nT={}\n", bot_token()));
    repo.commit_all();

    repo.write("a.txt", &format!("old\nT={}\nclean line\n", bot_token()));
    repo.git(&["add", "a.txt"]);
    let (code, out, _) = repo.keyscan(&["staged"]);
    assert_eq!(code, 0, "{out}");

    repo.write("b.txt", &format!("x\nTOKEN={}\n", github_token()));
    repo.git(&["add", "b.txt"]);
    let (code, out, err) = repo.keyscan(&["staged"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("b.txt:2"), "{out}");
    assert!(out.contains("(파일 2개 검사)"), "{out}");
    assert_no_secret(&out);
    assert_no_secret(&err);
}

#[test]
fn install_hook_blocks_commit_and_refuses_overwrite() {
    let repo = Repo::new();
    let (code, out, err) = repo.keyscan(&["install-hook"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(repo.path().join(".git/hooks/pre-commit").is_file());

    let (code, _, err) = repo.keyscan(&["install-hook"]);
    assert_eq!(code, 2);
    assert!(err.contains("덮어쓰지 않았습니다"), "{err}");

    let bin_dir = Path::new(BIN).parent().unwrap();
    let path = std::env::join_paths(std::iter::once(bin_dir.to_path_buf()).chain(
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
    ))
    .unwrap();

    repo.write(".env", &format!("DISCORD_TOKEN={}\n", bot_token()));
    repo.git(&["add", ".env"]);
    let mut cmd = Command::new("git");
    cmd.args(["commit", "-q", "-m", "leak"]).env("PATH", &path);
    repo.env(&mut cmd);
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "토큰이 든 커밋이 막히지 않았습니다");
    assert_no_secret(&String::from_utf8_lossy(&out.stdout));

    repo.git(&["rm", "-q", "--cached", ".env"]);
    repo.write("ok.txt", "fine\n");
    repo.git(&["add", "ok.txt"]);
    let mut cmd = Command::new("git");
    cmd.args(["commit", "-q", "-m", "ok"]).env("PATH", &path);
    repo.env(&mut cmd);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn history_finds_removed_secret_with_commit() {
    let repo = Repo::new();
    repo.write(
        "a.txt",
        &format!(
            "T={}
",
            bot_token()
        ),
    );
    repo.commit_all();
    let first = String::from_utf8_lossy(&repo.git(&["rev-parse", "--short=7", "HEAD"]).stdout)
        .trim()
        .to_string();
    repo.write(
        "a.txt", "clean
",
    );
    repo.commit_all();

    let (code, out, _) = repo.keyscan(&["scan"]);
    assert_eq!(code, 0, "{out}");

    let (code, out, err) = repo.keyscan(&["history"]);
    assert_eq!(code, 1, "{out}{err}");
    assert!(out.contains(&format!("a.txt:1 ({first})")), "{out}");
    assert!(out.contains("(커밋 2개 검사)"), "{out}");
    assert!(out.contains("이미 유출된 것으로 보고 재발급"), "{out}");
    assert_no_secret(&out);
}

#[test]
fn json_and_sarif_output() {
    let repo = Repo::new();
    repo.write(
        "a.txt",
        &format!(
            "x
T={}
",
            bot_token()
        ),
    );

    let (code, out, _) = repo.keyscan(&["scan", "--format", "json"]);
    assert_eq!(code, 1, "{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["count"], 1);
    assert_eq!(v["scanned"]["files"], 1);
    let f = &v["findings"][0];
    assert_eq!(f["rule"], "discord-bot-token");
    assert_eq!(f["path"], "a.txt");
    assert_eq!(f["line"], 2);
    assert_eq!(f["value"], "MTAA****");
    assert!(f["commit"].is_null());
    assert_no_secret(&out);

    let (code, out, _) = repo.keyscan(&["scan", "--format", "sarif"]);
    assert_eq!(code, 1, "{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["version"], "2.1.0");
    let r = &v["runs"][0]["results"][0];
    assert_eq!(r["ruleId"], "discord-bot-token");
    assert_eq!(r["level"], "error");
    assert_eq!(
        r["locations"][0]["physicalLocation"]["region"]["startLine"],
        2
    );
    assert_no_secret(&out);

    let clean = Repo::new();
    let (code, out, _) = clean.keyscan(&["scan", "--format", "json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["count"], 0);
}

#[test]
fn entropy_and_no_entropy_flag() {
    let repo = Repo::new();
    let value = "q8Zr2Lm9Xv4Tn7Kp1Wc6Hy3Bd5Fs0Gj";
    repo.write(
        "config.py",
        &format!(
            "API_SECRET = \"{value}\"
"
        ),
    );
    let (code, out, _) = repo.keyscan(&["scan"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("high-entropy"), "{out}");
    assert!(!out.contains(value), "{out}");
    let (code, out, _) = repo.keyscan(&["scan", "--no-entropy"]);
    assert_eq!(code, 0, "{out}");
}

#[test]
fn korean_personal_info_and_phone_opt_in() {
    let repo = Repo::new();
    repo.write(
        "users.csv",
        concat!(
            "name,rrn,phone
kim,900101",
            "-1234567,010-1234",
            "-5678
"
        ),
    );
    let (code, out, _) = repo.keyscan(&["scan"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("kr-rrn"), "{out}");
    assert!(out.contains("90****"), "{out}");
    assert!(!out.contains("kr-phone"), "{out}");
    assert!(!out.contains("1234567"), "{out}");

    repo.write(
        ".keyscan.toml",
        "enable = [\"kr-phone\"]
",
    );
    let (code, out, _) = repo.keyscan(&["scan"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("kr-phone"), "{out}");
    assert!(out.contains("01****"), "{out}");
    assert!(!out.contains("5678"), "{out}");
}
