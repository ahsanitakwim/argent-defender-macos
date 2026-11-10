//! ARGENT REPORT — risk scoring, scan history and branded HTML/JSON reports.

use crate::model::*;
use anyhow::Result;
use rusqlite::{params, Connection};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct RiskScore {
    /// 100 = no known risk; 0 = critical compromise indicators.
    pub score: i64,
    pub rating: String,
    pub by_severity: BTreeMap<String, usize>,
    pub formula: &'static str,
}

/// score = 100 − Σ weight(severity) × factor(confidence), with diminishing returns
/// per rule (repeated hits of the same rule count 1, ½, ⅓ …), floored at 0. Any
/// CONFIRMED critical finding caps the score at 20.
pub fn risk_score(f: &[Finding]) -> RiskScore {
    let mut by: BTreeMap<String, usize> = BTreeMap::new();
    let mut per_rule: BTreeMap<&str, usize> = BTreeMap::new();
    let mut penalty = 0.0;
    for x in f {
        *by.entry(format!("{:?}", x.severity).to_uppercase()).or_default() += 1;
        let k = per_rule.entry(x.rule.as_str()).or_default();
        *k += 1;
        penalty += x.severity.weight() * x.confidence.factor() / *k as f64;
    }
    let mut score = (100.0 - penalty).round().max(0.0) as i64;
    if f.iter().any(|x| x.severity == Severity::Critical && x.confidence >= Confidence::High) {
        score = score.min(20);
    }
    let rating = match score { 90..=100 => "SECURE", 70..=89 => "LOW RISK", 50..=69 => "MODERATE RISK", 25..=49 => "HIGH RISK", _ => "CRITICAL" }.to_string();
    RiskScore { score, rating, by_severity: by, formula: "100 − Σ severity_weight × confidence_factor ÷ repeat_index; CRITICAL+HIGH-confidence caps at 20" }
}

pub fn new_scan_id(kind: &str) -> String {
    let mut r = [0u8; 4];
    let _ = getrandom::fill(&mut r);
    format!("{}-{}-{}", kind.to_uppercase(), chrono::Utc::now().format("%Y%m%dT%H%M%S"), hex::encode(r))
}

pub fn record_scan(c: &Connection, kind: &str, target: &str, device: Option<&str>, started: &str, findings: &[Finding], result: &serde_json::Value, bench: Option<&serde_json::Value>) -> Result<String> {
    let id = new_scan_id(kind);
    let score = risk_score(findings);
    c.execute("INSERT INTO scan(scan_id,kind,target,device_id,started_at,finished_at,score,findings,result_json,bench_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![id, kind, target, device, started, crate::db::now(), score.score, findings.iter().filter(|f| f.category != Category::Limitation).count() as i64,
            serde_json::to_string(result)?, bench.map(|b| b.to_string())])?;
    if let Some(d) = device {
        c.execute("UPDATE device SET last_score=?2, last_seen=?3 WHERE device_id=?1", params![d, score.score, crate::db::now()])?;
    }
    crate::db::audit(c, "engine", &format!("scan.{kind}"), &format!("{id} target={target} score={}", score.score))?;
    Ok(id)
}

pub fn history(c: &Connection, limit: i64) -> Result<Vec<serde_json::Value>> {
    let mut st = c.prepare("SELECT scan_id,kind,target,device_id,started_at,finished_at,score,findings FROM scan ORDER BY started_at DESC LIMIT ?1")?;
    let r = st.query_map([limit], |r| Ok(serde_json::json!({"scan_id": r.get::<_,String>(0)?, "kind": r.get::<_,String>(1)?, "target": r.get::<_,String>(2)?,
        "device_id": r.get::<_,Option<String>>(3)?, "started_at": r.get::<_,String>(4)?, "finished_at": r.get::<_,Option<String>>(5)?, "score": r.get::<_,Option<i64>>(6)?, "findings": r.get::<_,i64>(7)?})))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(r)
}

pub fn get_scan(c: &Connection, id: &str) -> Result<serde_json::Value> {
    let (kind, target, started, res, bench): (String, String, String, Option<String>, Option<String>) =
        c.query_row("SELECT kind,target,started_at,result_json,bench_json FROM scan WHERE scan_id=?1", [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
    Ok(serde_json::json!({"scan_id": id, "kind": kind, "target": target, "started_at": started,
        "result": res.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()), "bench": bench.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())}))
}

pub fn upsert_device(c: &Connection, id: &str, platform: &str, name: Option<&str>, manufacturer: Option<&str>, model: Option<&str>, os: Option<&str>) -> Result<()> {
    let now = crate::db::now();
    c.execute("INSERT INTO device(device_id,platform,name,manufacturer,model,os_version,first_seen,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7,?7)
               ON CONFLICT(device_id) DO UPDATE SET name=COALESCE(excluded.name,name), manufacturer=COALESCE(excluded.manufacturer,manufacturer),
               model=COALESCE(excluded.model,model), os_version=COALESCE(excluded.os_version,os_version), last_seen=excluded.last_seen",
        params![id, platform, name, manufacturer, model, os, now])?;
    Ok(())
}

pub fn devices(c: &Connection) -> Result<Vec<serde_json::Value>> {
    let mut st = c.prepare("SELECT d.device_id,d.platform,d.name,d.manufacturer,d.model,d.os_version,d.first_seen,d.last_seen,d.last_score,
        (SELECT max(started_at) FROM scan s WHERE s.device_id=d.device_id) FROM device d ORDER BY d.last_seen DESC")?;
    let r = st.query_map([], |r| Ok(serde_json::json!({"device_id": r.get::<_,String>(0)?, "platform": r.get::<_,String>(1)?, "name": r.get::<_,Option<String>>(2)?,
        "manufacturer": r.get::<_,Option<String>>(3)?, "model": r.get::<_,Option<String>>(4)?, "os_version": r.get::<_,Option<String>>(5)?, "first_seen": r.get::<_,String>(6)?,
        "last_seen": r.get::<_,String>(7)?, "last_score": r.get::<_,Option<i64>>(8)?, "last_scan": r.get::<_,Option<String>>(9)?})))?.collect::<std::result::Result<_, _>>()?;
    Ok(r)
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

const LOGO_PNG: &[u8] = include_bytes!("../../branding/argent_logo_128.png");

/// Self-contained, printable HTML report (macOS app prints it to PDF via WebKit).
pub fn html_report(title: &str, target: &str, findings: &[Finding], extra: &serde_json::Value, signature: Option<&serde_json::Value>) -> String {
    use base64::Engine;
    let score = risk_score(findings);
    let logo = base64::engine::general_purpose::STANDARD.encode(LOGO_PNG);
    let color = |s: Severity| match s {
        Severity::Critical => "#D94A52", Severity::High => "#E9A23B", Severity::Medium => "#3584D7", Severity::Low => "#48B8CF", Severity::Informational => "#36A879", Severity::NotAccessible => "#8A96A3",
    };
    let score_col = match score.score { 90..=100 => "#36A879", 70..=89 => "#48B8CF", 50..=69 => "#E9A23B", _ => "#D94A52" };
    let mut rows = String::new();
    for f in findings {
        rows += &format!(
            "<tr><td><span class=sev style='background:{}'>{:?}</span></td><td>{:?}</td><td><b>{}</b><div class=muted>{} · {} · <code>{}</code></div><ul>{}</ul>{}</td><td>{}<div class=muted>{}</div></td></tr>",
            color(f.severity), f.severity, f.confidence, esc(&f.title), esc(&f.engine), esc(&f.rule), esc(&f.id),
            f.evidence.iter().filter(|e| !e.is_empty()).map(|e| format!("<li>{}</li>", esc(e))).collect::<String>(),
            if f.recommendation.is_empty() { String::new() } else { format!("<div class=rec>➜ {}</div>", esc(&f.recommendation)) },
            esc(&f.subject.name), esc(f.subject.sha256.as_deref().unwrap_or("")),
        );
    }
    let summary = crate::ai::summarize(findings, &score);
    let sig = signature.map(|s| format!("<h2>Report integrity</h2><p class=muted>Hybrid signature (Ed25519 + ML-DSA-65) over the canonical JSON report.</p><pre>{}</pre>", esc(&serde_json::to_string_pretty(s).unwrap_or_default()))).unwrap_or_default();
    format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>{t} — ARGENT DEFENDER</title>
<style>
:root{{--bg:#101722;--navy:#17243A;--silver:#C5CED8;--plat:#E5EAF0;--blue:#3584D7;--cyan:#48B8CF}}
body{{font:14px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue",sans-serif;color:#1b2533;margin:0;background:#fff}}
header{{background:linear-gradient(135deg,var(--bg),var(--navy));color:var(--plat);padding:28px 40px;display:flex;gap:20px;align-items:center}}
header img{{width:64px;height:64px;border-radius:14px}} header h1{{margin:0;font-size:22px;letter-spacing:.12em}} header .tag{{color:var(--cyan);font-size:11px;letter-spacing:.2em}}
main{{padding:24px 40px}} .cards{{display:flex;gap:16px;flex-wrap:wrap}} .card{{border:1px solid #dfe5ec;border-radius:12px;padding:14px 18px;min-width:150px}}
.big{{font-size:34px;font-weight:700}} .muted{{color:#5b6878;font-size:12px}} table{{width:100%;border-collapse:collapse;margin-top:12px}}
td,th{{border-bottom:1px solid #e6ebf0;padding:10px 8px;vertical-align:top;text-align:left}} th{{font-size:11px;letter-spacing:.08em;color:#5b6878;text-transform:uppercase}}
.sev{{color:#fff;border-radius:6px;padding:2px 8px;font-size:11px;font-weight:600;white-space:nowrap}} ul{{margin:6px 0 0 18px;padding:0}} .rec{{margin-top:6px;color:#17243A}}
code,pre{{font:11px ui-monospace,Menlo,monospace}} pre{{background:#f4f6f9;padding:12px;border-radius:8px;white-space:pre-wrap;word-break:break-all}}
footer{{padding:20px 40px;color:#5b6878;font-size:11px;border-top:1px solid #e6ebf0}} @media print{{header{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}}}
</style></head><body>
<header><img src="data:image/png;base64,{logo}" alt=""><div><div class=tag>ADVANCED CYBER INTELLIGENCE &amp; DIGITAL FORENSICS</div><h1>ARGENT DEFENDER</h1><div>{t}</div></div></header>
<main>
<div class=cards>
<div class=card><div class=muted>Security score</div><div class=big style="color:{sc}">{s}</div><div>{rating}</div></div>
<div class=card><div class=muted>Target</div><div><b>{target}</b></div><div class=muted>Generated {now}</div></div>
<div class=card><div class=muted>Findings by severity</div><div>{sev}</div></div>
</div>
<h2>Summary</h2><p>{summary}</p>
<p class=muted>Severity (impact) and confidence (certainty of detection) are reported independently. Heuristic findings are indicators, not verdicts. Items marked NOT_ACCESSIBLE could not be examined and are not reported as clean.</p>
<h2>Findings ({n})</h2>
<table><tr><th>Severity</th><th>Confidence</th><th>Finding &amp; evidence</th><th>Subject</th></tr>{rows}</table>
<h2>Technical appendix</h2><pre>{extra}</pre>{sig}
<p class=muted>Scoring: {formula}</p>
</main><footer>ARGENT DEFENDER · DEFEND THE DIGITAL. REVEAL THE TRUTH. · Generated locally; no data was uploaded.</footer></body></html>"#,
        t = esc(title), logo = logo, sc = score_col, s = score.score, rating = score.rating, target = esc(target), now = crate::db::now(),
        sev = score.by_severity.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join(" · "), summary = esc(&summary), n = findings.len(), rows = rows,
        extra = esc(&serde_json::to_string_pretty(extra).unwrap_or_default()), sig = sig, formula = score.formula)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn f(sev: Severity, conf: Confidence, rule: &str) -> Finding { Finding::new("t", rule, "x", Category::Other, sev, conf, subject("x", "y")) }
    #[test]
    fn scoring() {
        assert_eq!(risk_score(&[]).score, 100);
        assert_eq!(risk_score(&[f(Severity::Informational, Confidence::Confirmed, "a")]).score, 100);
        assert_eq!(risk_score(&[f(Severity::High, Confidence::Confirmed, "a")]).score, 80);
        assert_eq!(risk_score(&[f(Severity::High, Confidence::Low, "a")]).score, 95);
        assert!(risk_score(&[f(Severity::Critical, Confidence::High, "a")]).score <= 20);
        // repeated same rule has diminishing weight
        let many: Vec<_> = (0..10).map(|_| f(Severity::Low, Confidence::Confirmed, "r")).collect();
        assert!(risk_score(&many).score > 80);
    }
    #[test]
    fn html_escapes() {
        let mut x = f(Severity::High, Confidence::High, "a");
        x.title = "<script>alert(1)</script>".into();
        let h = html_report("T", "tgt", &[x], &serde_json::json!({}), None);
        assert!(!h.contains("<script>alert"));
        assert!(h.contains("ARGENT DEFENDER"));
    }
}
