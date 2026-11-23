use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Deserialize;

const BUILTIN: &str = include_str!("rules.toml");

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
struct RuleDef {
    id: String,
    name: String,
    regex: String,
    #[serde(default)]
    keywords: Vec<String>,
    severity: Severity,
    fix: String,
}

#[derive(Deserialize)]
struct BuiltinFile {
    rule: Vec<RuleDef>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct UserConfig {
    #[serde(default)]
    disable: Vec<String>,
    #[serde(default)]
    rule: Vec<RuleDef>,
}

pub struct Rule {
    pub id: String,
    pub name: String,
    pub regex: Regex,
    pub keywords: Vec<String>,
    pub severity: Severity,
    pub fix: String,
}

fn compile(def: RuleDef) -> Result<Rule> {
    let regex = Regex::new(&def.regex)
        .with_context(|| format!("규칙 `{}`의 정규식이 올바르지 않습니다", def.id))?;
    Ok(Rule {
        id: def.id,
        name: def.name,
        regex,
        keywords: def.keywords.iter().map(|k| k.to_lowercase()).collect(),
        severity: def.severity,
        fix: def.fix,
    })
}

pub fn builtin() -> Result<Vec<Rule>> {
    let file: BuiltinFile = toml::from_str(BUILTIN).context("내장 규칙 파일을 읽지 못했습니다")?;
    file.rule.into_iter().map(compile).collect()
}

pub fn load(explicit: Option<&Path>, default_path: &Path) -> Result<Vec<Rule>> {
    let mut rules = builtin()?;
    let path = match explicit {
        Some(p) => p,
        None if default_path.is_file() => default_path,
        None => return Ok(rules),
    };
    let text = fs::read_to_string(path)
        .with_context(|| format!("설정 파일을 읽지 못했습니다: {}", path.display()))?;
    let config: UserConfig = toml::from_str(&text)
        .with_context(|| format!("설정 파일 형식이 올바르지 않습니다: {}", path.display()))?;

    let known: HashSet<String> = rules.iter().map(|r| r.id.clone()).collect();
    for id in &config.disable {
        if !known.contains(id) {
            bail!("설정 파일의 disable에 없는 규칙이 있습니다: {id}");
        }
    }
    rules.retain(|r| !config.disable.contains(&r.id));

    let mut ids: HashSet<String> = known;
    for def in config.rule {
        if !ids.insert(def.id.clone()) {
            bail!("같은 id의 규칙이 이미 있습니다: {}", def.id);
        }
        rules.push(compile(def)?);
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::detect_line;

    fn fake(parts: &[&str]) -> String {
        parts.concat()
    }

    fn hits(rules: &[Rule], id: &str, line: &str) -> usize {
        detect_line(rules, line)
            .iter()
            .filter(|h| rules[h.rule].id == id)
            .count()
    }

    #[test]
    fn builtin_rules_compile() {
        let rules = builtin().unwrap();
        assert_eq!(rules.len(), 7);
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
    fn keywords_required() {
        let mut r = builtin().unwrap();
        r.push(
            compile(RuleDef {
                id: "hex32".into(),
                name: "test".into(),
                regex: r"\b[0-9a-f]{32}\b".into(),
                keywords: vec!["Kakao".into()],
                severity: Severity::Medium,
                fix: "fix".into(),
            })
            .unwrap(),
        );
        let hex = "0123456789abcdef".repeat(2);
        assert_eq!(hits(&r, "hex32", &format!("KAKAO_KEY={hex}")), 1);
        assert_eq!(hits(&r, "hex32", &format!("commit {hex}")), 0);
    }
}
