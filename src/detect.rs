use crate::finding::mask;
use crate::rules::Rule;

pub const ALLOW_MARK: &str = "keyscan:allow";

pub struct Hit {
    pub rule: usize,
    pub masked: String,
}

pub fn detect_line(rules: &[Rule], line: &str) -> Vec<Hit> {
    if line.contains(ALLOW_MARK) {
        return Vec::new();
    }
    let lower = line.to_lowercase();
    let mut hits = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        if !rule.keywords.is_empty() && !rule.keywords.iter().any(|k| lower.contains(k.as_str())) {
            continue;
        }
        for caps in rule.regex.captures_iter(line) {
            let Some(m) = caps.name("secret").or_else(|| caps.get(0)) else {
                continue;
            };
            hits.push(Hit {
                rule: i,
                masked: mask(m.as_str(), 4),
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
        assert_eq!(detect_line(&rules, &line).len(), 1);
        assert!(detect_line(&rules, &format!("{line} # {ALLOW_MARK}")).is_empty());
    }

    #[test]
    fn masked_value_hides_secret() {
        let rules = builtin().unwrap();
        let secret = ["AK", "IA", "ABCDEFGHIJ234567"].concat();
        let hits = detect_line(&rules, &secret);
        assert_eq!(hits[0].masked, "AKIA****");
    }
}
