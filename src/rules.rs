use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Deserialize;

use crate::entropy::Thresholds;
use crate::validate::Validator;

const BUILTIN: &str = include_str!("rules.toml");
pub const ENTROPY_ID: &str = "high-entropy";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDef {
    id: String,
    name: String,
    regex: String,
    #[serde(default)]
    keywords: Vec<String>,
    severity: Severity,
    fix: String,
    #[serde(default)]
    validate: Option<Validator>,
    #[serde(default = "default_keep")]
    keep: usize,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default, rename = "checked")]
    _checked: Option<String>,
}

fn default_keep() -> usize {
    4
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct BuiltinFile {
    entropy: EntropyDef,
    rule: Vec<RuleDef>,
}

#[derive(Deserialize)]
struct EntropyDef {
    name: String,
    severity: Severity,
    fix: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct UserConfig {
    #[serde(default)]
    disable: Vec<String>,
    #[serde(default)]
    enable: Vec<String>,
    #[serde(default)]
    entropy: Thresholds,
    #[serde(default)]
    rule: Vec<RuleDef>,
}

pub struct Rule {
    pub id: String,
    pub name: String,
    pub regex: Option<Regex>,
    pub keywords: Vec<String>,
    pub severity: Severity,
    pub fix: String,
    pub validate: Option<Validator>,
    pub keep: usize,
    enabled: bool,
}

pub struct Config {
    pub rules: Vec<Rule>,
    pub entropy: Option<Thresholds>,
}

fn compile(def: RuleDef) -> Result<Rule> {
    let regex = Regex::new(&def.regex)
        .with_context(|| format!("규칙 `{}`의 정규식이 올바르지 않습니다", def.id))?;
    Ok(Rule {
        id: def.id,
        name: def.name,
        regex: Some(regex),
        keywords: def.keywords.iter().map(|k| k.to_lowercase()).collect(),
        severity: def.severity,
        fix: def.fix,
        validate: def.validate,
        keep: def.keep,
        enabled: def.enabled,
    })
}

fn all_builtin() -> Result<Vec<Rule>> {
    let file: BuiltinFile = toml::from_str(BUILTIN).context("내장 규칙 파일을 읽지 못했습니다")?;
    let mut rules: Vec<Rule> = file.rule.into_iter().map(compile).collect::<Result<_>>()?;
    rules.push(Rule {
        id: ENTROPY_ID.to_string(),
        name: file.entropy.name,
        regex: None,
        keywords: Vec::new(),
        severity: file.entropy.severity,
        fix: file.entropy.fix,
        validate: None,
        keep: 4,
        enabled: true,
    });
    Ok(rules)
}

#[cfg(test)]
pub fn builtin() -> Result<Vec<Rule>> {
    let mut rules = all_builtin()?;
    rules.retain(|r| r.enabled);
    Ok(rules)
}

pub fn load(explicit: Option<&Path>, default_path: &Path, no_entropy: bool) -> Result<Config> {
    let path = match explicit {
        Some(p) => Some(p),
        None if default_path.is_file() => Some(default_path),
        None => None,
    };
    let config = match path {
        Some(path) => {
            let text = fs::read_to_string(path)
                .with_context(|| format!("설정 파일을 읽지 못했습니다: {}", path.display()))?;
            toml::from_str(&text).with_context(|| {
                format!("설정 파일 형식이 올바르지 않습니다: {}", path.display())
            })?
        }
        None => UserConfig::default(),
    };

    let mut rules = all_builtin()?;
    let mut ids: HashSet<String> = rules.iter().map(|r| r.id.clone()).collect();
    for id in config.disable.iter().chain(&config.enable) {
        if !ids.contains(id) {
            bail!("설정 파일에 없는 규칙이 있습니다: {id}");
        }
    }
    for r in &mut rules {
        if config.enable.contains(&r.id) {
            r.enabled = true;
        }
        if config.disable.contains(&r.id) || (no_entropy && r.id == ENTROPY_ID) {
            r.enabled = false;
        }
    }
    for def in config.rule {
        if !ids.insert(def.id.clone()) {
            bail!("같은 id의 규칙이 이미 있습니다: {}", def.id);
        }
        rules.push(compile(def)?);
    }
    rules.retain(|r| r.enabled);
    let entropy = rules
        .iter()
        .any(|r| r.id == ENTROPY_ID)
        .then_some(config.entropy);
    Ok(Config { rules, entropy })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::detect_line;

    fn fake(parts: &[&str]) -> String {
        parts.concat()
    }

    fn hits(rules: &[Rule], id: &str, line: &str) -> usize {
        detect_line(rules, None, "a.txt", line)
            .iter()
            .filter(|h| rules[h.rule].id == id)
            .count()
    }

    #[test]
    fn builtin_rules_compile() {
        let rules = builtin().unwrap();
        assert!(rules.iter().any(|r| r.id == ENTROPY_ID));
        assert!(!rules.iter().any(|r| r.id == "kr-phone"));
    }

    #[test]
    fn github_token() {
        let r = builtin().unwrap();
        let body = "A1b2".repeat(9);
        assert_eq!(
            hits(
                &r,
                "github-token",
                &fake(&["token = \"gh", "p_", &body, "\""])
            ),
            1
        );
        assert_eq!(hits(&r, "github-token", &fake(&["gh", "o_", &body])), 1);
        assert_eq!(hits(&r, "github-token", &fake(&["gh", "p_", "short"])), 0);
        assert_eq!(hits(&r, "github-token", &fake(&["xgh", "p_", &body])), 0);
    }

    #[test]
    fn github_fine_grained() {
        let r = builtin().unwrap();
        let ok = fake(&["github", "_pat_", &"a".repeat(22), "_", &"B".repeat(59)]);
        assert_eq!(hits(&r, "github-fine-grained-pat", &ok), 1);
        let bad = fake(&["github", "_pat_", &"a".repeat(22)]);
        assert_eq!(hits(&r, "github-fine-grained-pat", &bad), 0);
    }

    #[test]
    fn google_api_key() {
        let r = builtin().unwrap();
        assert_eq!(
            hits(
                &r,
                "google-api-key",
                &fake(&["key: AI", "za", &"x".repeat(35)])
            ),
            1
        );
        assert_eq!(
            hits(&r, "google-api-key", &fake(&["AI", "za", "tooShort"])),
            0
        );
    }

    #[test]
    fn aws_access_key_id() {
        let r = builtin().unwrap();
        assert_eq!(
            hits(
                &r,
                "aws-access-key-id",
                &fake(&["AK", "IA", "ABCDEFGHIJ234567"])
            ),
            1
        );
        assert_eq!(
            hits(
                &r,
                "aws-access-key-id",
                &fake(&["AS", "IA", "ABCDEFGHIJ234567"])
            ),
            1
        );
        assert_eq!(
            hits(
                &r,
                "aws-access-key-id",
                &fake(&["AK", "IA", "0189018901890189"])
            ),
            0
        );
        assert_eq!(
            hits(
                &r,
                "aws-access-key-id",
                &fake(&["AK", "IA", "ABCDEFGHIJ2345678"])
            ),
            0
        );
    }

    #[test]
    fn discord_bot_token() {
        let r = builtin().unwrap();
        let token = fake(&["MT", &"A".repeat(24), ".", "Gabcde", ".", &"x".repeat(38)]);
        assert_eq!(
            hits(&r, "discord-bot-token", &format!("DISCORD_TOKEN={token}")),
            1
        );
        assert_eq!(hits(&r, "discord-bot-token", &format!("Bot {token}")), 1);
        let jwt = fake(&[
            "ey",
            "JhbGciOiJIUzI1NiJ9",
            ".",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            ".",
            &"s".repeat(43),
        ]);
        assert_eq!(hits(&r, "discord-bot-token", &jwt), 0);
        assert_eq!(hits(&r, "discord-bot-token", "version = 1.2.3"), 0);
    }

    #[test]
    fn discord_webhook() {
        let r = builtin().unwrap();
        let url = fake(&[
            "https://discord.com/api/web",
            "hooks/",
            "123456789012345678",
            "/",
            &"a".repeat(68),
        ]);
        assert_eq!(hits(&r, "discord-webhook", &url), 1);
        assert_eq!(
            hits(
                &r,
                "discord-webhook",
                "https://discord.com/api/channels/123"
            ),
            0
        );
    }

    #[test]
    fn private_key() {
        let r = builtin().unwrap();
        assert_eq!(
            hits(
                &r,
                "private-key",
                &fake(&["-----BEGIN ", "RSA PRIVATE KEY-----"])
            ),
            1
        );
        assert_eq!(
            hits(
                &r,
                "private-key",
                &fake(&["-----BEGIN ", "PRIVATE KEY-----"])
            ),
            1
        );
        assert_eq!(
            hits(
                &r,
                "private-key",
                &fake(&["-----BEGIN ", "OPENSSH PRIVATE KEY-----"])
            ),
            1
        );
        assert_eq!(hits(&r, "private-key", "-----BEGIN PUBLIC KEY-----"), 0);
    }

    #[test]
    fn kakao_needs_keyword() {
        let r = builtin().unwrap();
        let hex = "0123456789abcdef".repeat(2);
        assert_eq!(
            hits(&r, "kakao-app-key", &format!("KAKAO_REST_KEY={hex}")),
            1
        );
        assert_eq!(hits(&r, "kakao-app-key", &format!("commit {hex}")), 0);
    }

    #[test]
    fn naver_client_secret() {
        let r = builtin().unwrap();
        assert_eq!(
            hits(
                &r,
                "naver-client-secret",
                concat!("NAVER_CLIENT_SECRET", "=Ab3dE5gH9k")
            ),
            1
        );
        assert_eq!(
            hits(
                &r,
                "naver-client-secret",
                "NAVER_CLIENT_ID=Ab3dE5gH9kLm0pQ2rS4t"
            ),
            0
        );
        assert_eq!(
            hits(
                &r,
                "naver-client-secret",
                concat!("client_secret", " = Ab3dE5gH9k")
            ),
            0
        );
    }

    #[test]
    fn toss_secret_keys() {
        let r = builtin().unwrap();
        let body = "zXLkKEypNArWmo50nX3lmeax";
        assert_eq!(
            hits(&r, "toss-live-secret-key", &fake(&["live", "_sk_", body])),
            1
        );
        assert_eq!(
            hits(&r, "toss-live-secret-key", &fake(&["live", "_gsk_", body])),
            1
        );
        assert_eq!(
            hits(&r, "toss-test-secret-key", &fake(&["test", "_sk_", body])),
            1
        );
        assert_eq!(
            hits(&r, "toss-live-secret-key", &fake(&["live", "_ck_", body])),
            0
        );
    }

    #[test]
    fn korean_personal_info() {
        let r = builtin().unwrap();
        assert_eq!(
            hits(&r, "kr-rrn", concat!("주민번호: 900101", "-1234567")),
            1
        );
        assert_eq!(hits(&r, "kr-rrn", "id 901301-1234567"), 0);
        assert_eq!(hits(&r, "kr-rrn", "order 9001011234567"), 0);
        assert_eq!(hits(&r, "kr-rrn", "x 1900101-12345678"), 0);
        assert_eq!(
            hits(&r, "kr-card", concat!("card=4111-1111", "-1111-1111")),
            1
        );
        assert_eq!(
            hits(&r, "kr-card-plain", concat!("card=41111111", "11111111")),
            1
        );
        assert_eq!(
            hits(&r, "kr-card-plain", concat!("id=41111111", "11111111")),
            0
        );
        assert_eq!(hits(&r, "kr-card", "\"b\": 0.3019-6079-6117-7826"), 0);
        assert_eq!(
            hits(&r, "kr-card-plain", concat!("card 0.41111111", "11111111")),
            0
        );
        assert_eq!(
            hits(&r, "kr-card", concat!("card=4111-1111", "-1111-1112")),
            0
        );
        assert_eq!(hits(&r, "kr-brn", concat!("사업자 123-45", "-67891")), 1);
        assert_eq!(hits(&r, "kr-brn", concat!("사업자 123-45", "-67890")), 0);
    }

    #[test]
    fn personal_info_keeps_two_chars() {
        let r = builtin().unwrap();
        let h = detect_line(&r, None, "a.txt", concat!("900101", "-1234567"));
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].masked, "90****");
    }
}
