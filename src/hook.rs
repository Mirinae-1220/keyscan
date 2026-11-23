use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};

const SCRIPT: &str = "#!/bin/sh\n# keyscan pre-commit hook\nexec keyscan staged\n";

pub fn install() -> Result<()> {
    let out = Command::new("git")
        .args(["rev-parse", "--git-path", "hooks"])
        .output()
        .context("git을 실행하지 못했습니다. git이 설치되어 있고 PATH에 있는지 확인하세요")?;
    if !out.status.success() {
        bail!("git 레포 안에서 실행하세요");
    }
    let dir = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    let path = dir.join("pre-commit");
    if path.exists() {
        bail!(
            "이미 pre-commit 훅이 있어 덮어쓰지 않았습니다: {}\n기존 훅에 `keyscan staged` 줄을 직접 추가하세요",
            path.display()
        );
    }
    fs::create_dir_all(&dir)
        .with_context(|| format!("훅 폴더를 만들지 못했습니다: {}", dir.display()))?;
    fs::write(&path, SCRIPT)
        .with_context(|| format!("훅을 쓰지 못했습니다: {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    }

    println!("pre-commit 훅을 설치했습니다: {}", path.display());
    Ok(())
}
