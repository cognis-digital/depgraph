// Rust port of the depgraph core surface — fast, single static binary, zero deps.
//
// Mirrors the Python reference: parse a pip requirements.txt, run a
// Levenshtein typosquat check, and match pinned versions against a small
// embedded OSV-style advisory set. Same JSON output shape.
//
// Run:   cargo run -- requirements.txt   (or pipe on stdin)
// Test:  cargo test
use std::io::Read;
use std::{env, fs};

pub const POPULAR: &[&str] = &[
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "pillow",
    "lxml", "cryptography", "colorama", "python-dateutil", "setuptools",
];

pub struct Advisory {
    pub id: &'static str,
    pub alias: &'static str,
    pub pkg: &'static str,
    pub sev: &'static str,
    pub introduced: &'static str,
    pub fixed: &'static str,
}

pub const ADVISORIES: &[Advisory] = &[
    Advisory { id: "GHSA-j8r2-6x86-q33q", alias: "CVE-2023-32681", pkg: "requests", sev: "MEDIUM", introduced: "2.3.0", fixed: "2.31.0" },
    Advisory { id: "GHSA-9wx4-h78v-vm56", alias: "CVE-2021-33503", pkg: "urllib3", sev: "HIGH", introduced: "0", fixed: "1.26.5" },
    Advisory { id: "GHSA-h5c8-rqwp-cp95", alias: "CVE-2022-22817", pkg: "pillow", sev: "CRITICAL", introduced: "0", fixed: "9.0.0" },
    Advisory { id: "GHSA-8q59-q68h-6hv4", alias: "CVE-2022-2309", pkg: "lxml", sev: "MEDIUM", introduced: "0", fixed: "4.9.1" },
];

pub fn sev_penalty(sev: &str) -> f64 {
    match sev { "LOW" => 1.0, "MEDIUM" => 2.5, "HIGH" => 4.0, "CRITICAL" => 6.5, _ => 2.0 }
}

pub fn parse_version(v: &str) -> Vec<i64> {
    let v = v.trim_start_matches(|c| c == 'v' || c == 'V' || c == '=');
    let head: String = v.chars().take_while(|c| *c != '+' && *c != ' ' && *c != '-').collect();
    let mut out: Vec<i64> = Vec::new();
    let mut cur = String::new();
    for c in head.chars() {
        if c.is_ascii_digit() { cur.push(c); }
        else if !cur.is_empty() { out.push(cur.parse().unwrap_or(0)); cur.clear(); }
    }
    if !cur.is_empty() { out.push(cur.parse().unwrap_or(0)); }
    out.truncate(4);
    if out.is_empty() { vec![0] } else { out }
}

pub fn version_compare(a: &str, b: &str) -> i32 {
    let ta = parse_version(a);
    let tb = parse_version(b);
    let n = ta.len().max(tb.len());
    for i in 0..n {
        let x = *ta.get(i).unwrap_or(&0);
        let y = *tb.get(i).unwrap_or(&0);
        if x != y { return if x < y { -1 } else { 1 }; }
    }
    0
}

pub fn in_range(version: &str, a: &Advisory) -> bool {
    if version_compare(version, a.introduced) < 0 { return false; }
    if !a.fixed.is_empty() && version_compare(version, a.fixed) >= 0 { return false; }
    true
}

pub fn levenshtein(a: &str, b: &str) -> usize {
    if a == b { return 0; }
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() { return b.len(); }
    if b.is_empty() { return a.len(); }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i];
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur.push((prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost));
        }
        prev = cur;
    }
    prev[b.len()]
}

pub fn typosquat_match(name: &str) -> Option<&'static str> {
    let ln = name.to_lowercase();
    if POPULAR.contains(&ln.as_str()) { return None; }
    let mut best: Option<&'static str> = None;
    let mut best_d = 99;
    for cand in POPULAR {
        if (cand.len() as i64 - ln.len() as i64).abs() > 2 { continue; }
        let d = levenshtein(&ln, cand);
        if d < best_d { best_d = d; best = Some(cand); }
    }
    if best_d == 1 { best } else { None }
}

pub struct Dep { pub name: String, pub version: Option<String> }

pub fn parse_requirements(text: &str) -> Vec<Dep> {
    let mut deps = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty()
            || line.starts_with(['-', '.', '/'])
            || line.starts_with("git+")
            || line.starts_with("http") { continue; }
        let name: String = line.chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
            .collect();
        if name.is_empty() { continue; }
        let rest = &line[name.len()..];
        let version = if let Some(idx) = rest.find("==").or_else(|| rest.find("~=")) {
            let after = rest[idx + 2..].trim();
            let v: String = after.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || ".*+!-".contains(*c))
                .collect();
            if v.is_empty() { None } else { Some(v) }
        } else { None };
        deps.push(Dep { name, version });
    }
    deps
}

pub fn score_to_grade(s: f64) -> char {
    if s >= 9.0 { 'A' } else if s >= 7.5 { 'B' } else if s >= 6.0 { 'C' }
    else if s >= 4.0 { 'D' } else { 'F' }
}

pub fn score_dep(d: &Dep) -> (f64, char, usize, usize) {
    // returns (score, grade, vuln_count, finding_count)
    let mut penalty = 0.0;
    let mut vulns = 0;
    let mut findings = 0;
    for a in ADVISORIES {
        if a.pkg == d.name.to_lowercase() {
            if let Some(v) = &d.version {
                if in_range(v, a) { penalty += sev_penalty(a.sev); vulns += 1; findings += 1; }
            }
        }
    }
    if typosquat_match(&d.name).is_some() { penalty += 5.0; findings += 1; }
    if d.version.is_none() { penalty += 1.5; findings += 1; }
    let score = (10.0 - penalty).max(0.0);
    (score, score_to_grade(score), vulns, findings)
}

fn json_escape(s: &str) -> String { s.replace('\\', "\\\\").replace('"', "\\\"") }

pub fn audit_json(text: &str) -> String {
    let deps = parse_requirements(text);
    let mut total = 0.0;
    let mut vuln_count = 0;
    let mut items = Vec::new();
    for d in &deps {
        let (score, grade, vulns, findings) = score_dep(d);
        total += score;
        vuln_count += vulns;
        items.push(format!(
            "{{\"name\":\"{}\",\"version\":{},\"score\":{:.2},\"grade\":\"{}\",\"findings\":{}}}",
            json_escape(&d.name),
            d.version.as_ref().map(|v| format!("\"{}\"", json_escape(v))).unwrap_or_else(|| "null".into()),
            score, grade, findings
        ));
    }
    let proj = if deps.is_empty() { 10.0 } else { total / deps.len() as f64 };
    format!(
        "{{\"tool\":\"depgraph\",\"version\":\"2.1.0\",\"dependency_count\":{},\"vuln_count\":{},\"project_score\":{:.2},\"project_grade\":\"{}\",\"dependencies\":[{}]}}",
        deps.len(), vuln_count, proj, score_to_grade(proj), items.join(",")
    )
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let text = if args.len() > 1 {
        fs::read_to_string(&args[1]).unwrap_or_else(|e| { eprintln!("error: {}", e); std::process::exit(2); })
    } else {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).ok();
        s
    };
    println!("{}", audit_json(&text));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("2.31.0"), vec![2, 31, 0]);
        assert_eq!(parse_version("v1.2.3-beta"), vec![1, 2, 3]);
        assert_eq!(parse_version("0"), vec![0]);
    }

    #[test]
    fn test_version_compare() {
        assert_eq!(version_compare("1.2.3", "1.2.10"), -1);
        assert_eq!(version_compare("2.0", "2.0.0"), 0);
        assert_eq!(version_compare("9.0.0", "8.4.0"), 1);
    }

    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein("colorama", "colourama"), 1);
        assert_eq!(levenshtein("same", "same"), 0);
    }

    #[test]
    fn test_typosquat() {
        assert_eq!(typosquat_match("reqests"), Some("requests"));
        assert_eq!(typosquat_match("requests"), None);
    }

    #[test]
    fn test_in_range_vulnerable() {
        let a = &ADVISORIES[0]; // requests
        assert!(in_range("2.28.0", a));
        assert!(!in_range("2.31.0", a));
    }

    #[test]
    fn test_pillow_critical_scores_f() {
        let deps = parse_requirements("pillow==8.4.0\n");
        let (_, grade, vulns, _) = score_dep(&deps[0]);
        assert_eq!(grade, 'F');
        assert_eq!(vulns, 1);
    }

    #[test]
    fn test_audit_json_shape() {
        let j = audit_json("requests==2.28.0\nnumpy\n");
        assert!(j.contains("\"tool\":\"depgraph\""));
        assert!(j.contains("\"vuln_count\":1"));
        assert!(j.contains("\"project_grade\""));
    }

    #[test]
    fn test_clean_pkg_grades_a() {
        let deps = parse_requirements("cryptography==42.0.0\n");
        let (score, grade, _, findings) = score_dep(&deps[0]);
        assert_eq!(grade, 'A');
        assert_eq!(findings, 0);
        assert!((score - 10.0).abs() < 1e-9);
    }
}
