use serde_json::{Value, json};

use crate::finding::Finding;
use crate::rules::{Rule, Severity};
use crate::source::Stats;

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Files,
    History,
}

const SHORT_HASH: usize = 7;

fn short(commit: &str) -> &str {
    &commit[..commit.len().min(SHORT_HASH)]
}

pub fn sort(rules: &[Rule], findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        rules[b.rule]
            .severity
            .cmp(&rules[a.rule].severity)
            .then(a.rule.cmp(&b.rule))
            .then_with(|| a.path.cmp(&b.path))
            .then(a.line.cmp(&b.line))
            .then_with(|| a.commit.cmp(&b.commit))
    });
}

pub fn print(format: Format, rules: &[Rule], findings: &[Finding], stats: &Stats, mode: Mode) {
    match format {
        Format::Text => print_text(rules, findings, stats, mode),
        Format::Json => println!("{}", to_json(rules, findings, stats, mode)),
        Format::Sarif => println!("{}", to_sarif(rules, findings)),
    }
}

fn location(f: &Finding) -> String {
    match &f.commit {
        Some(c) => format!("{}:{} ({})", f.path, f.line, short(c)),
        None => format!("{}:{}", f.path, f.line),
    }
}

fn print_text(rules: &[Rule], findings: &[Finding], stats: &Stats, mode: Mode) {
    let width = findings
        .iter()
        .map(|f| location(f).chars().count())
        .max()
        .unwrap_or(0);

    for group in findings.chunk_by(|a, b| a.rule == b.rule) {
        let rule = &rules[group[0].rule];
        println!("[{}] {}  {}", rule.severity.as_str(), rule.id, rule.name);
        for f in group {
            let l = location(f);
            let pad = " ".repeat(width - l.chars().count());
            println!("  {l}{pad}   {}", f.masked);
        }
        println!("  해결: {}", rule.fix);
        println!();
    }

    let scanned = match mode {
        Mode::Files => format!("파일 {}개 검사", stats.files),
        Mode::History => format!("커밋 {}개 검사", stats.commits),
    };
    if findings.is_empty() {
        println!("찾은 것 없음 ({scanned})");
        return;
    }
    println!("{}건 발견 ({scanned})", findings.len());
    if mode == Mode::History {
        println!();
        println!("기록에 남은 비밀값은 이미 유출된 것으로 보고 재발급해야 합니다.");
        println!(
            "기록에서 지우려면 git filter-repo 등으로 기록을 다시 써야 하고, 이미 복제된 사본에서는 지워지지 않습니다."
        );
    }
}

fn to_json(rules: &[Rule], findings: &[Finding], stats: &Stats, mode: Mode) -> Value {
    let items: Vec<Value> = findings
        .iter()
        .map(|f| {
            let r = &rules[f.rule];
            json!({
                "rule": r.id,
                "name": r.name,
                "severity": r.severity.as_str(),
                "path": f.path,
                "line": f.line,
                "commit": f.commit,
                "value": f.masked,
                "fix": r.fix,
            })
        })
        .collect();
    let scanned = match mode {
        Mode::Files => json!({ "files": stats.files }),
        Mode::History => json!({ "commits": stats.commits }),
    };
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "scanned": scanned,
        "count": findings.len(),
        "findings": items,
    })
}

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn to_sarif(rules: &[Rule], findings: &[Finding]) -> Value {
    let driver_rules: Vec<Value> = rules
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "shortDescription": { "text": r.name },
                "help": { "text": r.fix },
                "defaultConfiguration": { "level": sarif_level(r.severity) },
            })
        })
        .collect();
    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let r = &rules[f.rule];
            let mut result = json!({
                "ruleId": r.id,
                "ruleIndex": f.rule,
                "level": sarif_level(r.severity),
                "message": { "text": format!("{} {} 발견. 해결: {}", r.name, f.masked, r.fix) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.path },
                        "region": { "startLine": f.line },
                    }
                }],
            });
            if let Some(c) = &f.commit {
                result["properties"] = json!({ "commit": c });
            }
            result
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "keyscan",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": env!("CARGO_PKG_REPOSITORY"),
                    "rules": driver_rules,
                }
            },
            "results": results,
        }]
    })
}
