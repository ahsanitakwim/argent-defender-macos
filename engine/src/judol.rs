//! ARGENT GAMING WATCH — Indonesia illegal online gambling (judi online / "judol")
//! threat intelligence. CONFIRMED classifications come only from verified database
//! indicators; lexical heuristics can at most yield SUSPECTED / HIGH_RISK with an
//! explicit confidence, so ordinary games are never labelled gambling without evidence.

use crate::model::*;
use anyhow::{bail, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Strong terms: specific to gambling promotion in Indonesia.
const STRONG: &[&str] = &[
    "judi", "judol", "togel", "toto4d", "toto88", "slotgacor", "slot-gacor", "gacor", "maxwin", "sbobet", "casino", "kasino",
    "rtplive", "rtp-live", "scatter", "pragmaticplay", "pgsoft", "mahjongways", "sweetbonanza", "gatesofolympus", "zeus138",
    "sabung", "sv388", "bandarq", "dominoqq", "poker88", "idnpoker", "idnslot", "jackpot", "taruhan", "bet88", "bandar",
];
/// Weak terms: appear in gambling promotion but also in legitimate contexts.
const WEAK: &[&str] = &["slot", "toto", "bet", "depo", "deposit", "wd", "bonus", "spin", "hoki", "cuan", "jp", "win", "88", "777", "303", "138", "4d"];

/// Legitimate game publishers / stores — never flagged by heuristics alone.
const ALLOW_PREFIXES: &[&str] = &["com.supercell.", "com.mobile.legends", "com.tencent.", "com.garena.", "com.miHoYo.", "com.activision.", "com.ea.", "com.king.", "com.roblox.", "com.android.", "com.google.", "com.apple."];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub indicator_id: String,
    pub domain: Option<String>,
    pub url: Option<String>,
    pub package_name: Option<String>,
    pub apk_hash: Option<String>,
    pub brand_alias: Option<String>,
    pub indicator_type: String,
    pub classification: String,
    pub evidence: Option<String>,
    pub source: String,
    pub confidence: i64,
    pub verified: bool,
    pub verified_by: Option<String>,
    pub verification_date: Option<String>,
    pub last_updated: Option<String>,
}

pub fn add(c: &Connection, ind: &Indicator) -> Result<String> {
    if !matches!(ind.classification.as_str(), "CONFIRMED_INDICATOR" | "HIGH_RISK" | "SUSPECTED") {
        bail!("classification must be CONFIRMED_INDICATOR, HIGH_RISK or SUSPECTED");
    }
    if ind.classification == "CONFIRMED_INDICATOR" && (ind.evidence.as_deref().unwrap_or("").trim().is_empty()) {
        bail!("CONFIRMED_INDICATOR requires evidence (source document, screenshot hash, government list reference)");
    }
    let id = if ind.indicator_id.is_empty() {
        let key = format!("{:?}{:?}{:?}{:?}{:?}", ind.domain, ind.url, ind.package_name, ind.apk_hash, ind.brand_alias);
        format!("JDL-{}", &crate::hashing::sha256_hex(key.as_bytes())[..12])
    } else {
        ind.indicator_id.clone()
    };
    c.execute(
        "INSERT INTO indonesia_gambling_threat_intelligence (indicator_id,domain,url,package_name,apk_hash,brand_alias,indicator_type,classification,evidence,source,confidence,verified,verified_by,verification_date,last_updated)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
         ON CONFLICT(indicator_id) DO UPDATE SET domain=excluded.domain,url=excluded.url,package_name=excluded.package_name,apk_hash=excluded.apk_hash,
         brand_alias=excluded.brand_alias,indicator_type=excluded.indicator_type,classification=excluded.classification,evidence=excluded.evidence,
         source=excluded.source,confidence=excluded.confidence,last_updated=excluded.last_updated",
        params![id, ind.domain.as_ref().map(|d| d.to_ascii_lowercase()), ind.url, ind.package_name, ind.apk_hash.as_ref().map(|h| h.to_ascii_lowercase()),
            ind.brand_alias, ind.indicator_type, ind.classification, ind.evidence, ind.source, ind.confidence.clamp(0, 100), ind.verified as i64,
            ind.verified_by, ind.verification_date, crate::db::now()],
    )?;
    crate::db::audit(c, "admin", "judol.add", &id)?;
    Ok(id)
}

pub fn verify(c: &Connection, id: &str, analyst: &str) -> Result<()> {
    let n = c.execute(
        "UPDATE indonesia_gambling_threat_intelligence SET verified=1, verified_by=?2, verification_date=?3, last_updated=?3 WHERE indicator_id=?1",
        params![id, analyst, crate::db::now()],
    )?;
    if n == 0 { bail!("indicator {id} not found"); }
    crate::db::audit(c, analyst, "judol.verify", id)
}

pub fn delete(c: &Connection, id: &str, analyst: &str) -> Result<()> {
    let n = c.execute("DELETE FROM indonesia_gambling_threat_intelligence WHERE indicator_id=?1", [id])?;
    if n == 0 { bail!("indicator {id} not found"); }
    crate::db::audit(c, analyst, "judol.delete", id)
}

fn row(r: &rusqlite::Row) -> rusqlite::Result<Indicator> {
    Ok(Indicator {
        indicator_id: r.get(0)?, domain: r.get(1)?, url: r.get(2)?, package_name: r.get(3)?, apk_hash: r.get(4)?, brand_alias: r.get(5)?,
        indicator_type: r.get(6)?, classification: r.get(7)?, evidence: r.get(8)?, source: r.get(9)?, confidence: r.get(10)?,
        verified: r.get::<_, i64>(11)? != 0, verified_by: r.get(12)?, verification_date: r.get(13)?, last_updated: r.get(14)?,
    })
}
const COLS: &str = "indicator_id,domain,url,package_name,apk_hash,brand_alias,indicator_type,classification,evidence,source,confidence,verified,verified_by,verification_date,last_updated";

pub fn list(c: &Connection, q: Option<&str>) -> Result<Vec<Indicator>> {
    let like = format!("%{}%", q.unwrap_or(""));
    let mut st = c.prepare(&format!(
        "SELECT {COLS} FROM indonesia_gambling_threat_intelligence WHERE ?1='%%' OR domain LIKE ?1 OR package_name LIKE ?1 OR brand_alias LIKE ?1 OR url LIKE ?1 ORDER BY last_updated DESC LIMIT 5000"
    ))?;
    let r = st.query_map([like], row)?.collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(r)
}

/// CSV import: domain,url,package_name,apk_hash,brand_alias,indicator_type,classification,evidence,source,confidence
pub fn import_csv(c: &Connection, text: &str) -> Result<usize> {
    let mut n = 0;
    for l in text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#') && !l.starts_with("domain,")) {
        let f = crate::intel::csv_split(l);
        if f.len() < 10 { continue; }
        let o = |s: &String| (!s.is_empty()).then(|| s.clone());
        add(c, &Indicator {
            indicator_id: String::new(), domain: o(&f[0]), url: o(&f[1]), package_name: o(&f[2]), apk_hash: o(&f[3]), brand_alias: o(&f[4]),
            indicator_type: f[5].clone(), classification: f[6].clone(), evidence: o(&f[7]), source: f[8].clone(), confidence: f[9].parse().unwrap_or(50),
            verified: false, verified_by: None, verification_date: None, last_updated: None,
        })?;
        n += 1;
    }
    Ok(n)
}

fn sev_of(class: &str) -> Severity {
    match class { "CONFIRMED_INDICATOR" => Severity::High, "HIGH_RISK" => Severity::Medium, _ => Severity::Low }
}

fn db_finding(i: &Indicator, subj: Subject, matched: &str) -> Finding {
    let class = if i.classification == "CONFIRMED_INDICATOR" && !i.verified { "HIGH_RISK" } else { i.classification.as_str() };
    let conf = if i.verified { Confidence::Confirmed } else { Confidence::from_percent(i.confidence) };
    Finding::new("gaming-watch", &format!("JUDOL:{}", i.indicator_id), format!("Illegal online gambling indicator — {class}"), Category::Gambling, sev_of(class), conf, subj)
        .evidence(format!("{matched} matches {} indicator {} ({})", i.indicator_type, i.indicator_id, i.brand_alias.clone().unwrap_or_default()))
        .evidence(format!("source: {}{}", i.source, if i.verified { format!(", verified by {} on {}", i.verified_by.clone().unwrap_or_default(), i.verification_date.clone().unwrap_or_default()) } else { ", not yet verified".into() }))
        .evidence(i.evidence.clone().unwrap_or_default())
        .recommend("Online gambling is illegal in Indonesia. Uninstall the app / avoid the site, never deposit funds, and report it via aduankonten.id (Kominfo/Komdigi).")
}

/// Lexical scoring of a name (domain label, package name or app label).
pub fn lexical(name: &str) -> (u32, Vec<String>) {
    let n = name.to_lowercase().replace(['_', ' '], "");
    let mut hits = vec![];
    let mut score = 0;
    for t in STRONG {
        if n.contains(t) { score += 40; hits.push(t.to_string()); }
    }
    let lower = name.to_lowercase();
    let toks: Vec<&str> = lower.split(|c: char| !c.is_ascii_alphanumeric()).filter(|s| !s.is_empty()).collect();
    for t in WEAK {
        if toks.iter().any(|x| x == t || (x.starts_with(t) && x[t.len()..].chars().all(|c| c.is_ascii_digit()) && t.chars().all(|c| c.is_alphabetic()))) {
            score += 10; hits.push(t.to_string());
        }
    }
    // brand+number pattern typical of gambling mirrors: "slot88", "toto4d", "jp303"
    if toks.iter().any(|x| {
        let alpha: String = x.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
        let rest = &x[alpha.len()..];
        alpha.len() >= 2 && (rest.len() >= 2 && rest.chars().all(|c| c.is_ascii_digit()) || rest == "4d") && WEAK.iter().chain(STRONG).any(|w| alpha.contains(w))
    }) {
        score += 25; hits.push("brand+number mirror pattern".into());
    }
    (score, hits)
}

fn heuristic_finding(name: &str, subj: Subject, score: u32, hits: &[String]) -> Option<Finding> {
    let (class, sev, conf) = match score {
        s if s >= 80 => ("HIGH_RISK", Severity::Medium, Confidence::Medium),
        s if s >= 40 => ("SUSPECTED", Severity::Low, Confidence::Low),
        _ => return None,
    };
    Some(Finding::new("gaming-watch", "JUDOL-HEURISTIC", format!("Possible online gambling indicator — {class}"), Category::Gambling, sev, conf, subj)
        .evidence(format!("'{name}' matched gambling lexicon: {}", hits.join(", ")))
        .evidence("Heuristic only — not present in the verified indicator database")
        .recommend("Review manually. If confirmed, an administrator can add it to the verified database with evidence."))
}

pub fn check_package(c: &Connection, pkg: &str, label: Option<&str>) -> Result<Vec<Finding>> {
    let mut f = vec![];
    let mut st = c.prepare(&format!("SELECT {COLS} FROM indonesia_gambling_threat_intelligence WHERE package_name=?1"))?;
    for i in st.query_map([pkg], row)? {
        f.push(db_finding(&i?, subject("package", pkg), pkg));
    }
    if f.is_empty() && !ALLOW_PREFIXES.iter().any(|p| pkg.starts_with(p)) {
        let (s1, mut h1) = lexical(pkg);
        let (s2, h2) = label.map(lexical).unwrap_or((0, vec![]));
        h1.extend(h2);
        if let Some(x) = heuristic_finding(pkg, subject("package", pkg), s1.max(s2) + s1.min(s2) / 2, &h1) {
            f.push(x);
        }
    }
    Ok(f)
}

pub fn check_hash(c: &Connection, sha256: &str, subj: Subject) -> Result<Vec<Finding>> {
    let mut st = c.prepare(&format!("SELECT {COLS} FROM indonesia_gambling_threat_intelligence WHERE apk_hash=?1"))?;
    let r = st.query_map([sha256.to_ascii_lowercase()], row)?.map(|i| i.map(|i| db_finding(&i, subj.clone(), sha256))).collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(r)
}

pub fn check_url(c: &Connection, url: &str) -> Result<Vec<Finding>> {
    let mut f = vec![];
    let subj = subject("url", url);
    let host = crate::intel::host_of(url).unwrap_or_else(|| url.to_ascii_lowercase());
    let mut st = c.prepare(&format!("SELECT {COLS} FROM indonesia_gambling_threat_intelligence WHERE url=?1 OR domain=?2 OR (?2 LIKE '%.' || domain)"))?;
    for i in st.query_map(params![url, host], row)? {
        f.push(db_finding(&i?, subj.clone(), &host));
    }
    if f.is_empty() {
        // Mirror identification: same brand with different digits/TLD as a verified domain
        let reg = psl::domain(host.as_bytes()).and_then(|d| std::str::from_utf8(d.as_bytes()).ok().map(String::from)).unwrap_or(host.clone());
        let stem: String = reg.split('.').next().unwrap_or("").chars().filter(|c| c.is_ascii_alphabetic()).collect();
        if stem.len() >= 4 {
            let mirror: Option<Indicator> = c
                .query_row(&format!("SELECT {COLS} FROM indonesia_gambling_threat_intelligence WHERE domain IS NOT NULL AND classification='CONFIRMED_INDICATOR' AND verified=1 AND domain != ?1 AND replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(substr(domain,1,instr(domain,'.')-1),'0',''),'1',''),'2',''),'3',''),'4',''),'5',''),'6',''),'7',''),'8',''),'9','') = ?2 LIMIT 1"), params![reg, stem], row)
                .optional()?;
            if let Some(m) = mirror {
                f.push(Finding::new("gaming-watch", "JUDOL-MIRROR", "Probable mirror of a confirmed gambling domain — HIGH_RISK", Category::Gambling, Severity::Medium, Confidence::Medium, subj.clone())
                    .evidence(format!("{reg} shares brand stem '{stem}' with confirmed {} ({})", m.domain.unwrap_or_default(), m.indicator_id))
                    .recommend("Avoid the site; administrators may verify and add it as a confirmed indicator."));
            }
        }
        let label = reg.split('.').next().unwrap_or("");
        let path = url.split(&host).nth(1).unwrap_or("");
        let (s, h) = lexical(&format!("{label} {}", path.replace('/', " ")));
        let tld = reg.rsplit('.').next().unwrap_or("");
        let bonus = if ["bet", "casino", "poker", "games"].contains(&tld) { 30 } else { 0 };
        if let Some(x) = heuristic_finding(&host, subj, s + bonus, &h) {
            f.push(x);
        }
    }
    Ok(f)
}

/// Five-level classification summary for a set of findings.
pub fn classify(findings: &[Finding]) -> &'static str {
    let g: Vec<_> = findings.iter().filter(|f| f.category == Category::Gambling).collect();
    if g.iter().any(|f| f.title.contains("CONFIRMED") ) { "CONFIRMED_INDICATOR" }
    else if g.iter().any(|f| f.title.contains("HIGH_RISK")) { "HIGH_RISK" }
    else if g.iter().any(|f| f.title.contains("SUSPECTED")) { "SUSPECTED" }
    else if findings.iter().any(|f| f.category == Category::Limitation) { "UNKNOWN" }
    else { "NO_KNOWN_INDICATOR" }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ind(domain: &str, class: &str, verified: bool) -> Indicator {
        Indicator { indicator_id: String::new(), domain: Some(domain.into()), url: None, package_name: None, apk_hash: None, brand_alias: Some("TESTBRAND".into()),
            indicator_type: "domain".into(), classification: class.into(), evidence: Some("TEST FIXTURE — not a real indicator".into()), source: "unit-test".into(),
            confidence: 90, verified, verified_by: None, verification_date: None, last_updated: None }
    }
    #[test]
    fn ordinary_games_not_flagged() {
        let c = crate::db::open_memory().unwrap();
        for p in ["com.mobile.legends", "com.supercell.clashofclans", "com.kiloo.subwaysurf", "com.whatsapp", "id.dana", "com.gojek.app"] {
            assert!(check_package(&c, p, None).unwrap().is_empty(), "{p}");
        }
    }
    #[test]
    fn heuristics_and_db() {
        let c = crate::db::open_memory().unwrap();
        let h = check_package(&c, "com.slotgacor.maxwin88", Some("Slot Gacor Maxwin")).unwrap();
        assert_eq!(classify(&h), "HIGH_RISK", "{h:?}");
        let id = add(&c, &ind("judi-test.invalid", "CONFIRMED_INDICATOR", false)).unwrap();
        // unverified CONFIRMED is downgraded to HIGH_RISK
        assert_eq!(classify(&check_url(&c, "https://www.judi-test.invalid/").unwrap()), "HIGH_RISK");
        verify(&c, &id, "analyst").unwrap();
        assert_eq!(classify(&check_url(&c, "https://judi-test.invalid/").unwrap()), "CONFIRMED_INDICATOR");
        // mirror with different digits
        add(&c, &ind("hoki88test.invalid", "CONFIRMED_INDICATOR", true)).unwrap();
        let m = check_url(&c, "https://hoki77test.invalid/").unwrap();
        assert!(m.iter().any(|f| f.rule == "JUDOL-MIRROR"), "{m:?}");
        assert!(add(&c, &Indicator { evidence: None, ..ind("x.invalid", "CONFIRMED_INDICATOR", false) }).is_err());
    }
}
