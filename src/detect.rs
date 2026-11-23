use crate::entropy::{self, Thresholds};
use crate::finding::mask;
use crate::rules::{ENTROPY_ID, Rule};

pub const ALLOW_MARK: &str = "keyscan:allow";

pub struct Hit {
    pub rule: usize,
    pub masked: String,
}

pub fn detect_line(
    rules: &[Rule],
    entropy: Option<&Thresholds>,
    path: &str,
    line: &str,
) -> Vec<Hit> {
    if line.contains(ALLOW_MARK) {
        return Vec::new();
    }
    let lower = line.to_lowercase();
    let mut hits = Vec::new();
    let mut entropy_rule = None;
    for (i, rule) in rules.iter().enumerate() {
        let Some(regex) = &rule.regex else {
            if rule.id == ENTROPY_ID {
                entropy_rule = Some(i);
            }
            continue;
        };
        if !rule.keywords.is_empty() && !rule.keywords.iter().any(|k| lower.contains(k.as_str())) {
            continue;
        }
        for caps in regex.captures_iter(line) {
            let Some(m) = caps.name("secret").or_else(|| caps.get(0)) else {
                continue;
            };
            if rule.validate.is_some_and(|v| !v.check(m.as_str())) {
                continue;
            }
            hits.push(Hit {
                rule: i,
                masked: mask(m.as_str(), rule.keep),
            });
        }
    }

    if let (Some(i), Some(t)) = (entropy_rule, entropy)
        && hits.is_empty()
        && !entropy::skips_file(path)
    {
        for v in entropy::find(line, t) {
            hits.push(Hit {
                rule: i,
                masked: mask(v, 4),
            });
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::builtin;

    #[test]
    fn allow_mark_skips_line() {
        let rules = builtin().unwrap();
        let line = ["AK", "IA", "ABCDEFGHIJ234567"].concat();
        assert_eq!(detect_line(&rules, None, "a", &line).len(), 1);
        assert!(detect_line(&rules, None, "a", &format!("{line} # {ALLOW_MARK}")).is_empty());
    }

    #[test]
    fn masked_value_hides_secret() {
        let rules = builtin().unwrap();
        let secret = ["AK", "IA", "ABCDEFGHIJ234567"].concat();
        let hits = detect_line(&rules, None, "a", &secret);
        assert_eq!(hits[0].masked, "AKIA****");
    }

    #[test]
    fn entropy_only_when_no_rule_hit() {
        let rules = builtin().unwrap();
        let t = Thresholds::default();
        let value = "q8Zr2Lm9Xv4Tn7Kp1Wc6Hy3Bd5Fs0Gj";
        let line = format!("API_SECRET = \"{value}\"");
        let hits = detect_line(&rules, Some(&t), "config.py", &line);
        assert_eq!(hits.len(), 1);
        assert_eq!(rules[hits[0].rule].id, ENTROPY_ID);
        assert!(detect_line(&rules, None, "config.py", &line).is_empty());
        assert!(detect_line(&rules, Some(&t), "Cargo.lock", &line).is_empty());

        let token = ["AK", "IA", "ABCDEFGHIJ234567"].concat();
        let both = format!("AWS_KEY={token} SECRET={value}");
        let hits = detect_line(&rules, Some(&t), "a", &both);
        assert_eq!(hits.len(), 1);
        assert_eq!(rules[hits[0].rule].id, "aws-access-key-id");
    }

    #[test]
    fn entropy_ignores_ordinary_values() {
        let rules = builtin().unwrap();
        let t = Thresholds::default();
        for line in [
            "password = \"correcthorsebatterystaple\"",
            "API_KEY = os.environ[\"API_KEY_FROM_ENVIRONMENT\"]",
            "token: ${{ secrets.GITHUB_TOKEN_VALUE }}",
            "auth_url = \"https://accounts.example.com/o/oauth2/auth\"",
            "SECRET_KEY = \"your-secret-key-goes-here-please\"",
            "name = \"q8Zr2Lm9Xv4Tn7Kp1Wc6Hy3Bd5Fs0Gj\"",
        ] {
            assert!(
                detect_line(&rules, Some(&t), "a", line).is_empty(),
                "오탐: {line}"
            );
        }
    }
}
