pub struct Finding {
    pub rule: usize,
    pub path: String,
    pub line: usize,
    pub masked: String,
}

pub fn mask(value: &str, keep: usize) -> String {
    if value.chars().count() <= keep {
        return "****".to_string();
    }
    let head: String = value.chars().take(keep).collect();
    format!("{head}****")
}

#[cfg(test)]
mod tests {
    use super::mask;

    #[test]
    fn keeps_prefix_only() {
        assert_eq!(mask("abcdefgh", 4), "abcd****");
        assert_eq!(mask("abcd", 4), "****");
        assert_eq!(mask("ab", 4), "****");
        assert_eq!(mask("가나다라마바", 2), "가나****");
    }
}
