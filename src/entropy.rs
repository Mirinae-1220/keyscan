use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;

pub const MIN_LEN: usize = 20;

static ASSIGN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)([a-z0-9_.-]*(?:key|secret|token|passw(?:or)?d|pwd|auth|credential)[a-z0-9_.-]*)["']?\s*(?::=|=>|=|:)\s*[@"'`]?([^\s"'`,;]{20,})"#,
    )
    .unwrap()
});

const PLACEHOLDER: &[&str] = &[
    "example",
    "sample",
    "dummy",
    "placeholder",
    "changeme",
    "your",
    "xxxx",
    "****",
    "redacted",
];

const SKIP_FILES: &[&str] = &[
    ".lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "go.sum",
    ".min.js",
    ".min.css",
    ".map",
    ".svg",
];

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Thresholds {
    pub base64: f64,
    pub hex: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            base64: 4.5,
            hex: 3.5,
        }
    }
}

pub fn shannon(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    let mut other = std::collections::HashMap::new();
    let mut n = 0u32;
    for c in s.chars() {
        n += 1;
        if (c as u32) < 256 {
            counts[c as usize] += 1;
        } else {
            *other.entry(c).or_insert(0u32) += 1;
        }
    }
    if n == 0 {
        return 0.0;
    }
    let n = f64::from(n);
    counts
        .iter()
        .chain(other.values())
        .filter(|&&k| k > 0)
        .map(|&k| {
            let p = f64::from(k) / n;
            -p * p.log2()
        })
        .sum()
}

pub fn skips_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    SKIP_FILES.iter().any(|s| lower.ends_with(s))
}

fn looks_dynamic(v: &str) -> bool {
    v.contains("${")
        || v.contains("{{")
        || v.contains("%(")
        || v.contains("://")
        || v.contains('(')
        || v.contains('<')
        || v.starts_with('$')
        || v.starts_with("process.env")
}

static IDENT_SEGMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[A-Z]{1,4}|[A-Z]?[a-z]+)*[0-9]*$").unwrap());

fn class(c: char) -> Option<u8> {
    if c.is_ascii_uppercase() {
        Some(0)
    } else if c.is_ascii_lowercase() {
        Some(1)
    } else if c.is_ascii_digit() {
        Some(2)
    } else {
        None
    }
}

// 무작위 키는 대문자·소문자·숫자가 자주 바뀌고, `ToStage02_JumpAttack` 같은 식별자는 같은 종류가 길게 이어진다.
// 게임 데이터 29만 파일로 재 보니 이 비율 0.4 로 식별자 오탐이 848개에서 45개로 줄고, 무작위 키는 95% 이상 남았다.
fn switch_ratio(v: &str) -> f64 {
    let (mut pairs, mut switches) = (0u32, 0u32);
    let chars: Vec<char> = v.chars().collect();
    for w in chars.windows(2) {
        if let (Some(a), Some(b)) = (class(w[0]), class(w[1])) {
            pairs += 1;
            switches += u32::from(a != b);
        }
    }
    if pairs == 0 {
        0.0
    } else {
        f64::from(switches) / f64::from(pairs)
    }
}

fn looks_identifier(v: &str) -> bool {
    let segments: Vec<&str> = v.split(['_', '-', '.']).filter(|s| !s.is_empty()).collect();
    segments.len() >= 2 && segments.iter().all(|s| IDENT_SEGMENT.is_match(s))
}

fn looks_random(v: &str) -> bool {
    if looks_identifier(v) {
        return false;
    }
    let mixed_case =
        v.chars().any(|c| c.is_ascii_uppercase()) && v.chars().any(|c| c.is_ascii_lowercase());
    switch_ratio(v) >= if mixed_case { 0.4 } else { 0.2 }
}

// 길이 n 인 문자열의 엔트로피는 log2(n) 을 넘지 못해, 고정 기준값 4.5 로는 32자 이하 무작위 키를 대부분 놓친다.
// 그래서 짧은 값은 기준을 log2(n) 의 일정 비율로 낮추고, 대신 영문·숫자가 섞인 값만 본다.
const LENGTH_RATIO: f64 = 0.85;

fn threshold(v: &str, t: &Thresholds) -> f64 {
    if v.chars().all(|c| c.is_ascii_hexdigit()) {
        return t.hex;
    }
    let mixed = v.chars().any(|c| c.is_ascii_digit()) && v.chars().any(|c| c.is_ascii_alphabetic());
    if !mixed {
        return f64::INFINITY;
    }
    let n = v.chars().count() as f64;
    t.base64.min(LENGTH_RATIO * n.log2())
}

pub fn find<'a>(line: &'a str, t: &Thresholds) -> Vec<&'a str> {
    let mut out = Vec::new();
    for caps in ASSIGN.captures_iter(line) {
        let Some(m) = caps.get(2) else { continue };
        let v = m.as_str();
        if v.chars().count() < MIN_LEN || looks_dynamic(v) {
            continue;
        }
        let lower = v.to_lowercase();
        if PLACEHOLDER.iter().any(|p| lower.contains(p)) {
            continue;
        }
        if shannon(v) >= threshold(v, t) && looks_random(v) {
            out.push(v);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudo_random(seed: &mut u64, alphabet: &[u8], len: usize) -> String {
        (0..len)
            .map(|_| {
                *seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                alphabet[((*seed >> 33) % alphabet.len() as u64) as usize] as char
            })
            .collect()
    }

    #[test]
    fn entropy_values() {
        assert_eq!(shannon(""), 0.0);
        assert_eq!(shannon("aaaa"), 0.0);
        assert!((shannon("abcd") - 2.0).abs() < 1e-9);
    }

    #[test]
    fn catches_most_random_keys() {
        let t = Thresholds::default();
        let b62 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut seed = 7;
        for len in [20, 24, 32, 40, 64] {
            let caught = (0..1000)
                .filter(|_| {
                    let v = pseudo_random(&mut seed, b62, len);
                    !find(&format!("API_KEY = \"{v}\""), &t).is_empty()
                })
                .count();
            assert!(caught >= 900, "길이 {len}: 1000개 중 {caught}개만 잡음");
        }
    }

    #[test]
    fn skips_identifiers() {
        let t = Thresholds::default();
        for v in [
            "ToStage02_JumpAttack",
            "SGV_RoleCombat_ExBuff_04",
            "NewValid_StartPos_01",
            "gi73test4starclaymoreblazinglionfang",
            "MySuperLongVariableName",
        ] {
            assert!(
                find(&format!("\"key\": \"{v}\""), &t).is_empty(),
                "오탐: {v}"
            );
        }
    }
}
