//! ARGENT INTEL — offline threat-intelligence store with importers for URLhaus,
//! ThreatFox, MalwareBazaar, STIX 2.1 (incl. Amnesty MVT indicator bundles), MISP
//! events and plain lists. Every dataset records source, time, licence and SHA-256.

use crate::model::*;
use anyhow::{anyhow, bail, Result};
use rusqlite::{params, Connection};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct IocHit {
    pub ioc_type: String,
    pub value: String,
    pub threat: Option<String>,
    pub category: Option<String>,
    pub source: String,
    pub confidence: i64,
    pub reference: Option<String>,
    pub reliability: i64,
}

impl IocHit {
    pub fn to_finding(&self, subj: Subject) -> Finding {
        let cat = match self.category.as_deref().unwrap_or("") {
            c if c.contains("phish") => Category::Phishing,
            c if c.contains("spy") || c.contains("stalker") => Category::Spyware,
            c if c.contains("gambl") => Category::Gambling,
            c if c.contains("c2") || c.contains("botnet") => Category::NetworkThreat,
            c if c.contains("ransom") => Category::Ransomware,
            _ => Category::Malware,
        };
        // Effective confidence = indicator confidence weighted by source reliability.
        let eff = (self.confidence * self.reliability.max(1)) / 100;
        let sev = match cat {
            Category::Spyware | Category::Ransomware => Severity::Critical,
            Category::Malware | Category::NetworkThreat => Severity::High,
            _ => Severity::High,
        };
        Finding::new("intel", &format!("IOC:{}:{}", self.source, self.ioc_type), format!("Matches threat-intelligence indicator ({})", self.threat.clone().unwrap_or_else(|| self.source.clone())),
            cat, sev, Confidence::from_percent(eff.max(self.confidence.min(60))), subj)
            .evidence(format!("{} {} listed by {} (confidence {}%, source reliability {}%)", self.ioc_type, self.value, self.source, self.confidence, self.reliability))
            .evidence(self.reference.clone().map(|r| format!("reference: {r}")).unwrap_or_default())
            .recommend("Treat as compromised: isolate the item, do not open/visit it, and follow the incident-response guidance in the report.")
    }
}

pub fn normalize(ioc_type: &str, v: &str) -> String {
    let v = v.trim();
    match ioc_type {
        "domain" => v.trim_end_matches('.').to_ascii_lowercase(),
        "sha256" | "sha1" | "md5" | "cert_sha256" => v.to_ascii_lowercase(),
        "url" => v.to_string(),
        _ => v.to_string(),
    }
}

pub fn upsert(c: &Connection, ioc_type: &str, value: &str, threat: Option<&str>, category: Option<&str>, source: &str, confidence: i64, reference: Option<&str>, tags: Option<&str>, first_seen: Option<&str>) -> Result<()> {
    c.execute(
        "INSERT INTO ioc(ioc_type,value,threat,category,source,confidence,reference,tags,first_seen,last_updated) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
         ON CONFLICT(ioc_type,value,source) DO UPDATE SET threat=excluded.threat, category=excluded.category, confidence=excluded.confidence,
         reference=excluded.reference, tags=excluded.tags, last_updated=excluded.last_updated",
        params![ioc_type, normalize(ioc_type, value), threat, category, source, confidence.clamp(0, 100), reference, tags, first_seen, crate::db::now()],
    )?;
    Ok(())
}

pub fn lookup(c: &Connection, ioc_type: &str, value: &str) -> Result<Vec<IocHit>> {
    let v = normalize(ioc_type, value);
    let mut st = c.prepare(
        "SELECT i.ioc_type,i.value,i.threat,i.category,i.source,i.confidence,i.reference,COALESCE(f.reliability,50)
         FROM ioc i LEFT JOIN intel_feed f ON f.source=i.source WHERE i.ioc_type=?1 AND i.value=?2",
    )?;
    let r = st
        .query_map(params![ioc_type, v], |r| {
            Ok(IocHit { ioc_type: r.get(0)?, value: r.get(1)?, threat: r.get(2)?, category: r.get(3)?, source: r.get(4)?, confidence: r.get(5)?, reference: r.get(6)?, reliability: r.get(7)? })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(r)
}

/// Look up any observable; domains also match parent domains (sub.evil.com → evil.com).
pub fn lookup_any(c: &Connection, value: &str) -> Result<Vec<IocHit>> {
    let v = value.trim();
    let mut hits = vec![];
    let ty = classify(v);
    hits.extend(lookup(c, ty, v)?);
    if ty == "domain" {
        let parts: Vec<&str> = v.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            hits.extend(lookup(c, "domain", &parts[i..].join("."))?);
        }
    }
    if ty == "package" {
        hits.extend(lookup(c, "process", v)?);
    }
    Ok(hits)
}

pub fn classify(v: &str) -> &'static str {
    let is_hex = v.chars().all(|c| c.is_ascii_hexdigit());
    match v.len() {
        64 if is_hex => "sha256",
        40 if is_hex => "sha1",
        32 if is_hex => "md5",
        _ if v.contains("://") => "url",
        _ if v.parse::<std::net::IpAddr>().is_ok() => "ip",
        _ if v.contains('@') => "email",
        _ if v.contains('.') && !v.contains('/') && !v.contains(' ') && looks_like_domain(v) => "domain",
        _ => "package",
    }
}

fn looks_like_domain(v: &str) -> bool {
    // com.example.app style reverse-DNS identifiers are packages, not domains.
    let first = v.split('.').next().unwrap_or("");
    let n = v.split('.').count();
    let reverse_dns = matches!(first, "com" | "org" | "net" | "io" | "id" | "co" | "app" | "me" | "xyz" | "de" | "uk" | "ru" | "cn" | "jp" | "kr" | "in" | "br");
    let known = psl::suffix(v.as_bytes()).map(|s| s.is_known()).unwrap_or(false);
    let tld_alpha = v.rsplit('.').next().map(|t| t.len() >= 2 && t.chars().all(|c| c.is_ascii_alphabetic())).unwrap_or(false);
    n <= 6 && tld_alpha && !reverse_dns && (known || n <= 4)
}

// ------------------------------------------------------------------ CSV helper

pub fn csv_split(line: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut q = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if q && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => q = !q,
            ',' if !q => out.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    out.push(cur);
    out.into_iter().map(|s| s.trim().to_string()).collect()
}

fn data_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
}

#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub source: String,
    pub format: String,
    pub records: usize,
    pub skipped: usize,
    pub payload_sha256: String,
}

pub fn import(c: &mut Connection, format: &str, text: &str, source: &str, license: Option<&str>, url: Option<&str>, reliability: i64) -> Result<ImportResult> {
    let tx = c.transaction()?;
    let (mut n, mut skipped) = (0usize, 0usize);
    match format {
        // URLhaus CSV: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        "urlhaus" => {
            for l in data_lines(text) {
                let f = csv_split(l);
                if f.len() < 8 { skipped += 1; continue; }
                upsert(&tx, "url", &f[2], Some(&f[5]), Some("malware_distribution"), source, if f[3] == "online" { 90 } else { 75 }, Some(&f[7]), Some(&f[6]), Some(&f[1]))?;
                if let Some(h) = host_of(&f[2]) {
                    if h.parse::<std::net::IpAddr>().is_ok() {
                        upsert(&tx, "ip", &h, Some(&f[5]), Some("malware_distribution"), source, 60, Some(&f[7]), None, Some(&f[1]))?;
                    }
                }
                n += 1;
            }
        }
        // ThreatFox CSV: first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type,fk_malware,malware_alias,malware_printable,last_seen_utc,confidence_level,reference,tags,...
        "threatfox" => {
            for l in data_lines(text) {
                let f = csv_split(l);
                if f.len() < 10 { skipped += 1; continue; }
                let (ty, val) = match f[3].as_str() {
                    "domain" => ("domain", f[2].clone()),
                    "url" => ("url", f[2].clone()),
                    "ip:port" => ("ip", f[2].split(':').next().unwrap_or("").to_string()),
                    "sha256_hash" => ("sha256", f[2].clone()),
                    "md5_hash" => ("md5", f[2].clone()),
                    "sha1_hash" => ("sha1", f[2].clone()),
                    _ => { skipped += 1; continue; }
                };
                let cat = if f[4].contains("botnet_cc") { "c2" } else { f[4].as_str() };
                upsert(&tx, ty, &val, Some(&f[7]), Some(cat), source, f[9].parse().unwrap_or(50), Some(&f[10]), Some(&f[11]), Some(&f[0]))?;
                n += 1;
            }
        }
        // MalwareBazaar CSV: first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,mime_type,signature,...
        "bazaar" => {
            for l in data_lines(text) {
                let f = csv_split(l);
                if f.len() < 9 || f[1].len() != 64 { skipped += 1; continue; }
                let sig = (f[8] != "n/a").then(|| f[8].as_str());
                upsert(&tx, "sha256", &f[1], sig, Some("malware"), source, 95, Some(&format!("https://bazaar.abuse.ch/sample/{}/", f[1])), Some(&f[6]), Some(&f[0]))?;
                upsert(&tx, "md5", &f[2], sig, Some("malware"), source, 95, None, None, Some(&f[0]))?;
                upsert(&tx, "sha1", &f[3], sig, Some("malware"), source, 95, None, None, Some(&f[0]))?;
                n += 1;
            }
        }
        // STIX 2.x bundle (e.g. AmnestyTech investigations / MVT .stix2 files)
        "stix2" => {
            let v: serde_json::Value = serde_json::from_str(text)?;
            let objs = v["objects"].as_array().ok_or_else(|| anyhow!("STIX bundle has no objects"))?;
            let malware_name = objs.iter().find(|o| o["type"] == "malware").and_then(|o| o["name"].as_str()).map(String::from);
            for o in objs.iter().filter(|o| o["type"] == "indicator") {
                let pat = o["pattern"].as_str().unwrap_or("");
                match parse_stix_pattern(pat) {
                    Some((ty, val)) => {
                        upsert(&tx, ty, &val, malware_name.as_deref().or(o["name"].as_str()), Some("spyware"), source, 85, None, None, o["created"].as_str())?;
                        n += 1;
                    }
                    None => skipped += 1,
                }
            }
        }
        // MISP event JSON
        "misp" => {
            let v: serde_json::Value = serde_json::from_str(text)?;
            let ev = if v.get("Event").is_some() { &v["Event"] } else { &v };
            let info = ev["info"].as_str().map(String::from);
            let mut attrs: Vec<&serde_json::Value> = ev["Attribute"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
            if let Some(objs) = ev["Object"].as_array() {
                for o in objs {
                    if let Some(a) = o["Attribute"].as_array() {
                        attrs.extend(a.iter());
                    }
                }
            }
            for a in attrs {
                let ty = match a["type"].as_str().unwrap_or("") {
                    "domain" | "hostname" => "domain",
                    "url" | "link" => "url",
                    "ip-dst" | "ip-src" => "ip",
                    "sha256" => "sha256",
                    "md5" => "md5",
                    "sha1" => "sha1",
                    "email-src" => "email",
                    _ => { skipped += 1; continue; }
                };
                upsert(&tx, ty, a["value"].as_str().unwrap_or(""), info.as_deref(), a["category"].as_str(), source, 70, None, None, None)?;
                n += 1;
            }
        }
        // One indicator per line; type auto-detected. Optional ",category" suffix.
        "list" => {
            for l in data_lines(text) {
                let mut it = l.splitn(2, ',');
                let val = it.next().unwrap_or("").trim();
                let cat = it.next().map(|s| s.trim());
                if val.is_empty() { skipped += 1; continue; }
                upsert(&tx, classify(val), val, None, cat, source, 70, None, None, None)?;
                n += 1;
            }
        }
        other => bail!("unknown intel format '{other}' (use urlhaus|threatfox|bazaar|stix2|misp|list)"),
    }
    let sha = crate::hashing::sha256_hex(text.as_bytes());
    tx.execute(
        "INSERT INTO intel_feed(source,url,license,reliability,last_update,payload_sha256,records) VALUES (?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(source) DO UPDATE SET url=COALESCE(excluded.url,url), license=COALESCE(excluded.license,license), reliability=excluded.reliability,
         last_update=excluded.last_update, payload_sha256=excluded.payload_sha256, records=(SELECT count(*) FROM ioc WHERE source=?1)",
        params![source, url, license, reliability, crate::db::now(), sha, n as i64],
    )?;
    tx.commit()?;
    crate::db::audit(c, "engine", "intel.import", &format!("{source} {format} {n} records sha256={sha}"))?;
    Ok(ImportResult { source: source.into(), format: format.into(), records: n, skipped, payload_sha256: sha })
}

pub fn parse_stix_pattern(p: &str) -> Option<(&'static str, String)> {
    let p = p.trim().trim_start_matches('[').trim_end_matches(']');
    let (lhs, rhs) = p.split_once('=')?;
    let val = rhs.trim().trim_matches('\'').to_string();
    let ty = match lhs.trim() {
        "domain-name:value" => "domain",
        "url:value" => "url",
        "ipv4-addr:value" | "ipv6-addr:value" => "ip",
        "process:name" => "process",
        "app:id" => "package",
        "email-addr:value" => "email",
        "file:hashes.sha256" | "file:hashes.'SHA-256'" => "sha256",
        "file:hashes.md5" | "file:hashes.MD5" => "md5",
        "file:hashes.sha1" | "file:hashes.'SHA-1'" => "sha1",
        "x509-certificate:hashes.sha256" => "cert_sha256",
        _ => return None,
    };
    Some((ty, val))
}

pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let hostport = rest.split(['/', '?', '#']).next()?;
    let host = hostport.rsplit('@').next()?;
    let host = if host.starts_with('[') { host.split(']').next()?.trim_start_matches('[') } else { host.split(':').next()? };
    Some(host.to_ascii_lowercase())
}

/// Official abuse.ch export endpoints. abuse.ch may require a free Auth-Key; it is
/// read from the macOS Keychain by the app and passed to the engine via stdin.
pub fn feed_url(feed: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match feed {
        "urlhaus" => Some(("https://urlhaus.abuse.ch/downloads/csv_recent/", "urlhaus", "CC0 (abuse.ch terms of use)")),
        "threatfox" => Some(("https://threatfox.abuse.ch/export/csv/recent/", "threatfox", "CC0 (abuse.ch terms of use)")),
        "bazaar" => Some(("https://bazaar.abuse.ch/export/csv/recent/", "bazaar", "CC0 (abuse.ch terms of use)")),
        _ => None,
    }
}

pub fn update_online(c: &mut Connection, feed: &str, auth_key: Option<&str>) -> Result<ImportResult> {
    let (url, fmt, lic) = feed_url(feed).ok_or_else(|| anyhow!("unknown feed {feed}"))?;
    let mut req = ureq::get(url).header("User-Agent", concat!("ARGENT-DEFENDER/", env!("CARGO_PKG_VERSION")));
    if let Some(k) = auth_key {
        req = req.header("Auth-Key", k);
    }
    let mut resp = req.call().map_err(|e| anyhow!("download failed: {e}"))?;
    let body = resp.body_mut().with_config().limit(512 << 20).read_to_vec()?;
    let text = if body.starts_with(b"PK") {
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(body))?;
        let mut s = String::new();
        std::io::Read::read_to_string(&mut z.by_index(0)?, &mut s)?;
        s
    } else {
        String::from_utf8_lossy(&body).to_string()
    };
    import(c, fmt, &text, fmt, Some(lic), Some(url), 85)
}

#[derive(Serialize)]
pub struct IntelStats {
    pub total: i64,
    pub by_type: Vec<(String, i64)>,
    pub feeds: Vec<serde_json::Value>,
}

pub fn stats(c: &Connection) -> Result<IntelStats> {
    let total = c.query_row("SELECT count(*) FROM ioc", [], |r| r.get(0))?;
    let mut st = c.prepare("SELECT ioc_type, count(*) FROM ioc GROUP BY ioc_type ORDER BY 2 DESC")?;
    let by_type = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<std::result::Result<_, _>>()?;
    let mut st = c.prepare("SELECT source,url,license,reliability,last_update,payload_sha256,records FROM intel_feed ORDER BY source")?;
    let feeds = st
        .query_map([], |r| {
            Ok(serde_json::json!({"source": r.get::<_,String>(0)?, "url": r.get::<_,Option<String>>(1)?, "license": r.get::<_,Option<String>>(2)?,
              "reliability": r.get::<_,i64>(3)?, "last_update": r.get::<_,Option<String>>(4)?, "payload_sha256": r.get::<_,Option<String>>(5)?, "records": r.get::<_,i64>(6)?}))
        })?
        .collect::<std::result::Result<_, _>>()?;
    Ok(IntelStats { total, by_type, feeds })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn imports_and_matches() {
        let mut c = crate::db::open_memory().unwrap();
        let uh = "# URLhaus\n\"3001\",\"2026-11-01 10:00:00\",\"http://203.0.113.5/bins/x.apk\",\"online\",\"2026-11-01\",\"malware_download\",\"apk,android\",\"https://urlhaus.abuse.ch/url/3001/\",\"r\"\n";
        assert_eq!(import(&mut c, "urlhaus", uh, "urlhaus", None, None, 85).unwrap().records, 1);
        assert_eq!(lookup_any(&c, "http://203.0.113.5/bins/x.apk").unwrap().len(), 1);
        assert_eq!(lookup_any(&c, "203.0.113.5").unwrap().len(), 1);
        let tf = "\"2026-11-01 00:00:00\",\"1\",\"evil-c2.example\",\"domain\",\"botnet_cc\",\"x\",\"\",\"SpyNote\",\"\",\"100\",\"\",\"rat\",\"0\",\"r\"\n";
        import(&mut c, "threatfox", tf, "threatfox", None, None, 85).unwrap();
        let h = lookup_any(&c, "api.evil-c2.example").unwrap();
        assert_eq!(h[0].threat.as_deref(), Some("SpyNote"));
        let stix = r#"{"type":"bundle","objects":[{"type":"malware","name":"Pegasus"},{"type":"indicator","pattern":"[process:name = 'bh']"},{"type":"indicator","pattern":"[domain-name:value = 'bad.example']"}]}"#;
        assert_eq!(import(&mut c, "stix2", stix, "mvt-pegasus", None, None, 90).unwrap().records, 2);
        assert_eq!(lookup(&c, "process", "bh").unwrap()[0].threat.as_deref(), Some("Pegasus"));
        let f = lookup(&c, "domain", "bad.example").unwrap()[0].to_finding(subject("domain", "bad.example"));
        assert_eq!(f.category, Category::Spyware);
        assert_eq!(stats(&c).unwrap().feeds.len(), 3);
    }
    #[test]
    fn classifies() {
        assert_eq!(classify("com.whatsapp"), "package");
        assert_eq!(classify("example.com"), "domain");
        assert_eq!(classify(&"a".repeat(64)), "sha256");
        assert_eq!(classify("10.0.0.1"), "ip");
    }
}
