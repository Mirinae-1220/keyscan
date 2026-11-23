use crate::finding::Finding;
use crate::rules::Rule;

pub fn print_text(rules: &[Rule], findings: &mut [Finding], files: usize) {
    findings.sort_by(|a, b| {
        rules[b.rule]
            .severity
            .cmp(&rules[a.rule].severity)
            .then(a.rule.cmp(&b.rule))
            .then_with(|| a.path.cmp(&b.path))
            .then(a.line.cmp(&b.line))
    });

    let loc = |f: &Finding| format!("{}:{}", f.path, f.line);
    let width = findings
        .iter()
        .map(|f| loc(f).chars().count())
        .max()
        .unwrap_or(0);

    for group in findings.chunk_by(|a, b| a.rule == b.rule) {
        let rule = &rules[group[0].rule];
        println!("[{}] {}  {}", rule.severity.as_str(), rule.id, rule.name);
        for f in group {
            let l = loc(f);
            let pad = " ".repeat(width - l.chars().count());
            println!("  {l}{pad}   {}", f.masked);
        }
        println!("  해결: {}", rule.fix);
        println!();
    }

    if findings.is_empty() {
        println!("찾은 것 없음 (파일 {files}개 검사)");
    } else {
        println!("{}건 발견 (파일 {files}개 검사)", findings.len());
    }
}
