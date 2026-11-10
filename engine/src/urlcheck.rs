//! ARGENT NETWORK — URL / domain analysis: phishing heuristics, typosquatting,
//! IDN homograph detection, intel & judol correlation, optional redirect tracing.

use crate::model::*;
use anyhow::Result;
use rusqlite::Connection;
use serde::Serialize;

/// Brands frequently impersonated in Indonesia and globally (registrable domains).
pub const PROTECTED: &[&str] = &[
    "bca.co.id", "klikbca.com", "bri.co.id", "bankmandiri.co.id", "bni.co.id", "btn.co.id", "bsi.co.id", "cimbniaga.co.id",
    "danamon.co.id", "permatabank.com", "ocbc.id", "jenius.com", "dana.id", "ovo.id", "gojek.com", "gopay.co.id", "linkaja.id",
    "shopee.co.id", "tokopedia.com", "bukalapak.com", "lazada.co.id", "pajak.go.id", "djponline.pajak.go.id", "bpjs-kesehatan.go.id",
    "apple.com", "icloud.com", "google.com", "gmail.com", "microsoft.com", "outlook.com", "paypal.com", "facebook.com",
    "instagram.com", "whatsapp.com", "telegram.org", "netflix.com", "binance.com", "indodax.com",
];

const SUSPICIOUS_TLDS: &[&str] = &["xyz", "top", "click", "icu", "buzz", "monster", "rest", "cfd", "sbs", "lol", "cyou", "zip", "mov", "tk", "ml", "ga", "cf", "gq", "live", "shop", "vip", "win", "bet", "casino"];
const SHORTENERS: &[&str] = &["bit.ly", "s.id", "tinyurl.com", "t.co", "cutt.ly", "shorturl.at", "rb.gy", "is.gd", "ow.ly", "linktr.ee", "lynk.id", "heylink.me"];
const LURE_WORDS: &[&str] = &["login", "signin", "verify", "verifikasi", "secure", "update", "akun", "account", "blokir", "suspend", "hadiah", "undian", "claim", "klaim", "bonus", "konfirmasi", "reset", "password", "otp", "wallet", "kyc"];

pub fn extract_urls(text: &str) -> Vec<String> {
    let mut v = vec![];
    for tok in text.split(|c: char| c.is_whitespace() || c == '<' || c == '>' || c == '"' || c == '\'') {
        let t = tok.trim_end_matches(['.', ',', ')', ']', ';', '!']);
        if t.starts_with("http://") || t.starts_with("https://") {
            v.push(t.to_string());
        } else if t.starts_with("www.") && t.len() > 6 {
            v.push(format!("http://{t}"));
        }
    }
    v
}

/// Damerau-Levenshtein (optimal string alignment) distance.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in 0..=a.len() { d[i][0] = i; }
    for j in 0..=b.len() { d[0][j] = j; }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = (a[i - 1] != b[j - 1]) as usize;
            d[i][j] = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

/// Map confusable characters (Cyrillic/Greek look-alikes, digit substitutions) to a Latin skeleton.
pub fn skeleton(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'х' => 'x', 'у' => 'y', 'і' => 'i', 'ј' => 'j', 'ѕ' => 's', 'һ' => 'h', 'ԁ' => 'd', 'ɡ' => 'g', 'ո' => 'n', 'ս' => 'u',
            'α' => 'a', 'ο' => 'o', 'ν' => 'v', 'τ' => 't', 'ι' => 'i', 'κ' => 'k', 'ρ' => 'p',
            '0' => 'o', '1' => 'l', '3' => 'e', '5' => 's', '@' => 'a',
            c => c,
        })
        .collect::<String>()
        .replace("rn", "m")
        .replace("vv", "w")
}

#[derive(Debug, Serialize)]
pub struct UrlAnalysis {
    pub url: String,
    pub host: Option<String>,
    pub unicode_host: Option<String>,
    pub registrable_domain: Option<String>,
    pub score: u32,
    pub verdict: String,
    pub findings: Vec<Finding>,
    pub redirects: Vec<String>,
}

fn registrable(host: &str) -> Option<String> {
    psl::domain(host.as_bytes()).and_then(|d| std::str::from_utf8(d.as_bytes()).ok()).map(|s| s.to_string())
}

pub fn check_url(url: &str, db: &Connection) -> Result<Vec<Finding>> {
    Ok(analyze(url, db, false)?.findings)
}

pub fn analyze(url_in: &str, db: &Connection, follow_redirects: bool) -> Result<UrlAnalysis> {
    let url = if url_in.contains("://") { url_in.to_string() } else { format!("http://{url_in}") };
    let host = crate::intel::host_of(&url);
    let mut f: Vec<Finding> = vec![];
    let s = || Subject { kind: "url".into(), name: url.clone(), path: None, sha256: None };
    let mut score = 0u32;
    let add = |f: &mut Vec<Finding>, score: &mut u32, pts: u32, rule: &str, title: &str, ev: String| {
        *score += pts;
        f.push(Finding::new("url-heuristics", rule, title, Category::Phishing, Severity::Low, Confidence::Low, s()).evidence(ev));
    };
    let mut unicode_host = None;
    let mut reg = None;
    if let Some(h) = &host {
        let (uni, _) = idna::domain_to_unicode(h);
        if h.contains("xn--") {
            unicode_host = Some(uni.clone());
            let skel = skeleton(&uni);
            let mixed = uni.chars().any(|c| c.is_ascii_alphabetic()) && uni.chars().any(|c| !c.is_ascii() && c.is_alphabetic());
            if let Some(b) = PROTECTED.iter().find(|b| skeleton(b) == skel || registrable(&skel).as_deref() == Some(**b)) {
                score += 60;
                f.push(Finding::new("url-heuristics", "AD-NET-HOMOGRAPH", format!("IDN homograph impersonating {b}"), Category::Phishing, Severity::High, Confidence::High, s())
                    .evidence(format!("{h} renders as '{uni}', visually identical to {b}")));
            } else if mixed {
                add(&mut f, &mut score, 25, "AD-NET-MIXSCRIPT", "Mixed-script internationalised domain", format!("{h} → {uni}"));
            }
        }
        if h.parse::<std::net::IpAddr>().is_ok() {
            add(&mut f, &mut score, 20, "AD-NET-IPHOST", "URL uses a raw IP address instead of a domain", h.clone());
        }
        reg = registrable(h);
        if let Some(r) = &reg {
            let label = r.split('.').next().unwrap_or("");
            let is_protected = PROTECTED.iter().any(|p| r == p || h.ends_with(&format!(".{p}")) || h == p);
            if !is_protected {
                // Brand embedded in subdomain/path of another domain: bca.co.id.verify-xyz.top
                for b in PROTECTED {
                    let bl = b.split('.').next().unwrap_or("");
                    if h.contains(&format!("{b}.")) || (bl.len() >= 4 && h.split(['.', '-']).any(|p| p == bl) && !r.starts_with(bl)) {
                        score += 45;
                        f.push(Finding::new("url-heuristics", "AD-NET-BRANDSUB", format!("Brand '{b}' used inside an unrelated domain"), Category::Phishing, Severity::High, Confidence::Medium, s())
                            .evidence(format!("host {h} has registrable domain {r}, not {b}")));
                        break;
                    }
                }
                for b in PROTECTED {
                    let bl = b.split('.').next().unwrap_or("");
                    let d = edit_distance(&skeleton(label), bl);
                    if bl.len() >= 4 && label != bl && (d == 1 || (d == 2 && bl.len() >= 7)) {
                        score += 40;
                        f.push(Finding::new("url-heuristics", "AD-NET-TYPOSQUAT", format!("Possible typosquat of {b}"), Category::Phishing, Severity::High, Confidence::Medium, s())
                            .evidence(format!("'{label}' is {d} edit(s) from '{bl}'")));
                        break;
                    }
                }
            }
            let tld = r.rsplit('.').next().unwrap_or("");
            if SUSPICIOUS_TLDS.contains(&tld) {
                add(&mut f, &mut score, 10, "AD-NET-TLD", "Domain uses a TLD frequently abused for phishing/gambling", format!(".{tld}"));
            }
            if SHORTENERS.contains(&r.as_str()) {
                add(&mut f, &mut score, 10, "AD-NET-SHORT", "Link shortener hides the real destination", r.clone());
            }
        }
        if h.matches('.').count() >= 4 {
            add(&mut f, &mut score, 10, "AD-NET-DEEPSUB", "Unusually deep subdomain chain", h.clone());
        }
        if h.matches('-').count() >= 3 {
            add(&mut f, &mut score, 5, "AD-NET-HYPHEN", "Many hyphens in hostname", h.clone());
        }
    }
    let lower = url.to_lowercase();
    if lower.split("://").nth(1).map(|r| r.split('/').next().unwrap_or("").contains('@')).unwrap_or(false) {
        add(&mut f, &mut score, 25, "AD-NET-USERINFO", "URL contains '@' credentials trick", url.clone());
    }
    let lures: Vec<_> = LURE_WORDS.iter().filter(|w| lower.contains(*w)).collect();
    if !lures.is_empty() && score > 0 {
        add(&mut f, &mut score, 5 * lures.len().min(4) as u32, "AD-NET-LURE", "Credential/prize lure keywords", format!("{lures:?}"));
    }
    if lower.starts_with("http://") && !lures.is_empty() {
        add(&mut f, &mut score, 10, "AD-NET-NOTLS", "Credential-style page without HTTPS", url.clone());
    }

    // Intel correlation (exact URL, host, parent domains, IP)
    for hit in crate::intel::lookup(db, "url", &url)? {
        score += 100;
        f.push(hit.to_finding(s()));
    }
    if let Some(h) = &host {
        for hit in crate::intel::lookup_any(db, h)? {
            score += 100;
            f.push(hit.to_finding(s()));
        }
    }
    // Gambling (judol) correlation
    let judol = crate::judol::check_url(db, &url)?;
    for j in &judol {
        score += match j.severity { Severity::Critical | Severity::High => 60, Severity::Medium => 25, _ => 5 };
    }
    f.extend(judol);

    let redirects = if follow_redirects { trace_redirects(&url, 10).unwrap_or_default() } else { vec![] };
    if redirects.len() > 1 {
        let last = redirects.last().unwrap().clone();
        if crate::intel::host_of(&last).and_then(|h| registrable(&h)) != reg {
            f.push(Finding::new("url-heuristics", "AD-NET-REDIRECT", "Redirects to a different domain", Category::NetworkThreat, Severity::Low, Confidence::Confirmed, s())
                .evidence(redirects.join(" → ")));
            if let Ok(sub) = analyze(&last, db, false) {
                score += sub.score / 2;
                f.extend(sub.findings);
            }
        }
    }

    // Promote heuristic severity based on aggregate score (severity ≠ confidence).
    let verdict = match score {
        s if s >= 100 => "MALICIOUS",
        s if s >= 60 => "HIGH_RISK",
        s if s >= 25 => "SUSPICIOUS",
        _ => "NO_KNOWN_INDICATOR",
    };
    for x in f.iter_mut().filter(|x| x.engine == "url-heuristics" && x.severity == Severity::Low) {
        if score >= 60 {
            x.severity = Severity::Medium;
        }
    }
    for x in f.iter_mut() {
        if x.recommendation.is_empty() {
            x.recommendation = "Do not enter credentials, OTPs or payment data. Navigate to the official site by typing its address yourself.".into();
        }
    }
    Ok(UrlAnalysis { url, host, unicode_host, registrable_domain: reg, score, verdict: verdict.into(), findings: f, redirects })
}

/// Follows HTTP redirects manually (HEAD→GET fallback), max `hops`. User-triggered only.
pub fn trace_redirects(url: &str, hops: usize) -> Result<Vec<String>> {
    let agent: ureq::Agent = ureq::Agent::config_builder().max_redirects(0).http_status_as_error(false).timeout_global(Some(std::time::Duration::from_secs(10))).build().into();
    let mut chain = vec![url.to_string()];
    let mut cur = url.to_string();
    for _ in 0..hops {
        let r = agent.get(&cur).header("User-Agent", "Mozilla/5.0 (ARGENT DEFENDER URL analysis)").call()?;
        if !(300..400).contains(&r.status().as_u16()) {
            break;
        }
        let Some(loc) = r.headers().get("location").and_then(|v| v.to_str().ok()) else { break };
        let next = if loc.starts_with("http") {
            loc.to_string()
        } else {
            let base = cur.split('/').take(3).collect::<Vec<_>>().join("/");
            format!("{base}/{}", loc.trim_start_matches('/'))
        };
        chain.push(next.clone());
        cur = next;
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn db() -> Connection { crate::db::open_memory().unwrap() }
    #[test]
    fn legit_domains_clean() {
        for u in ["https://www.klikbca.com/", "https://www.google.com/search?q=x", "https://shopee.co.id/"] {
            let a = analyze(u, &db(), false).unwrap();
            assert_eq!(a.verdict, "NO_KNOWN_INDICATOR", "{u}: {:?}", a.findings);
        }
    }
    #[test]
    fn typosquat_and_brand_sub() {
        assert!(analyze("https://klikbcca.com/login", &db(), false).unwrap().findings.iter().any(|f| f.rule == "AD-NET-TYPOSQUAT"));
        let a = analyze("http://bca.co.id.verify-akun.xyz/login", &db(), false).unwrap();
        assert!(a.findings.iter().any(|f| f.rule == "AD-NET-BRANDSUB"));
        assert!(a.score >= 60, "{}", a.score);
    }
    #[test]
    fn homograph() {
        // "аpple.com" with Cyrillic а
        let a = analyze("https://xn--pple-43d.com/", &db(), false).unwrap();
        assert!(a.findings.iter().any(|f| f.rule == "AD-NET-HOMOGRAPH"), "{:?}", a.findings);
    }
    #[test]
    fn extract() {
        assert_eq!(extract_urls("Klik http://a.b/c, atau www.x.id."), vec!["http://a.b/c", "http://www.x.id"]);
    }
}
