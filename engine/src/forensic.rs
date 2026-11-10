//! ARGENT FORENSIC — case & evidence management with integrity guarantees:
//! originals are never modified; analysis uses read-only working copies whose
//! SHA-256 is verified at acquisition and on demand; every action is recorded in a
//! per-evidence hash-chained chain of custody.

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct TimelineEvent {
    pub at: String,
    pub source: String,
    pub kind: String,
    pub description: String,
}

pub fn create_case(c: &Connection, title: &str, examiner: &str, description: Option<&str>) -> Result<String> {
    let id = format!("CASE-{}-{}", chrono::Utc::now().format("%Y%m%d"), &crate::hashing::sha256_hex(format!("{title}{}", crate::db::now()).as_bytes())[..6].to_uppercase());
    c.execute("INSERT INTO forensic_case(case_id,title,examiner,created_at,description) VALUES (?1,?2,?3,?4,?5)", params![id, title, examiner, crate::db::now(), description])?;
    crate::db::audit(c, examiner, "case.create", &id)?;
    Ok(id)
}

#[derive(Serialize)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub case_id: String,
    pub source_device: Option<String>,
    pub acquisition_method: String,
    pub acquired_at: String,
    pub original_path: String,
    pub working_copy_path: String,
    pub sha256: String,
    pub size: i64,
    pub item_count: i64,
}

/// Directory digest: SHA-256 over sorted (relative path, file SHA-256) pairs.
pub fn tree_digest(root: &Path) -> Result<(String, u64, i64)> {
    if root.is_file() {
        let h = crate::hashing::hash_file(root)?;
        return Ok((h.sha256, h.size, 1));
    }
    let mut entries: Vec<(String, PathBuf)> = walkdir::WalkDir::new(root).into_iter().flatten().filter(|e| e.file_type().is_file())
        .map(|e| (e.path().strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"), e.into_path())).collect();
    entries.sort();
    let mut h = Sha256::new();
    let mut size = 0;
    for (rel, p) in &entries {
        let fh = crate::hashing::hash_file(p)?;
        size += fh.size;
        h.update(rel.as_bytes());
        h.update([0]);
        h.update(fh.sha256.as_bytes());
        h.update([b'\n']);
    }
    Ok((hex::encode(h.finalize()), size, entries.len() as i64))
}

fn copy_ro(src: &Path, dst: &Path) -> Result<()> {
    if src.is_file() {
        if let Some(p) = dst.parent() { std::fs::create_dir_all(p)?; }
        std::fs::copy(src, dst)?;
        set_ro(dst)?;
        return Ok(());
    }
    for e in walkdir::WalkDir::new(src).into_iter().flatten() {
        let rel = e.path().strip_prefix(src)?;
        let t = dst.join(rel);
        if e.file_type().is_dir() {
            std::fs::create_dir_all(&t)?;
        } else if e.file_type().is_file() {
            std::fs::copy(e.path(), &t)?;
            set_ro(&t)?;
        }
    }
    Ok(())
}

fn set_ro(p: &Path) -> Result<()> {
    let mut perm = std::fs::metadata(p)?.permissions();
    perm.set_readonly(true);
    std::fs::set_permissions(p, perm)?;
    Ok(())
}

/// Acquire evidence: hash original → copy to case store (read-only) → re-hash copy → compare.
pub fn add_evidence(c: &Connection, store: &Path, case_id: &str, src: &Path, source_device: Option<&str>, method: &str, examiner: &str) -> Result<EvidenceRecord> {
    let exists: i64 = c.query_row("SELECT count(*) FROM forensic_case WHERE case_id=?1", [case_id], |r| r.get(0))?;
    if exists == 0 { bail!("case {case_id} not found"); }
    let src = src.canonicalize().with_context(|| format!("evidence source {} not found", src.display()))?;
    let acquired_at = crate::db::now();
    let (orig_hash, size, items) = tree_digest(&src)?;
    let n: i64 = c.query_row("SELECT count(*) FROM evidence WHERE case_id=?1", [case_id], |r| r.get(0))?;
    let id = format!("{case_id}-E{:03}", n + 1);
    let name = src.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "evidence".into());
    let work = store.join(case_id).join(&id).join(&name);
    copy_ro(&src, &work)?;
    let (copy_hash, _, _) = tree_digest(&work)?;
    if copy_hash != orig_hash {
        bail!("integrity failure: working copy hash {copy_hash} != original {orig_hash}");
    }
    c.execute("INSERT INTO evidence(evidence_id,case_id,source_device,acquisition_method,acquired_at,original_path,working_copy_path,sha256,size,item_count) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![id, case_id, source_device, method, acquired_at, src.display().to_string(), work.display().to_string(), orig_hash, size as i64, items])?;
    crate::db::custody(c, &id, examiner, "acquired", &format!("method={method}; source={}; sha256={orig_hash}; items={items}", src.display()))?;
    crate::db::custody(c, &id, "engine", "working_copy_verified", &format!("{} sha256={copy_hash}", work.display()))?;
    crate::db::audit(c, examiner, "evidence.add", &id)?;
    Ok(EvidenceRecord { evidence_id: id, case_id: case_id.into(), source_device: source_device.map(String::from), acquisition_method: method.into(), acquired_at,
        original_path: src.display().to_string(), working_copy_path: work.display().to_string(), sha256: orig_hash, size: size as i64, item_count: items })
}

#[derive(Serialize)]
pub struct VerifyResult {
    pub evidence_id: String,
    pub expected_sha256: String,
    pub working_copy_sha256: String,
    pub working_copy_intact: bool,
    pub custody_chain: crate::db::ChainReport,
}

pub fn verify_evidence(c: &Connection, id: &str, examiner: &str) -> Result<VerifyResult> {
    let (expected, work): (String, String) = c.query_row("SELECT sha256, working_copy_path FROM evidence WHERE evidence_id=?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))
        .with_context(|| format!("evidence {id} not found"))?;
    let (actual, _, _) = tree_digest(Path::new(&work))?;
    let ok = actual == expected;
    crate::db::custody(c, id, examiner, "verified", &format!("sha256={actual} intact={ok}"))?;
    Ok(VerifyResult { evidence_id: id.into(), expected_sha256: expected, working_copy_sha256: actual, working_copy_intact: ok, custody_chain: crate::db::verify_custody(c, id)? })
}

pub fn log_analysis(c: &Connection, id: &str, actor: &str, what: &str) -> Result<()> {
    crate::db::custody(c, id, actor, "analysed", what)
}

pub fn add_note(c: &Connection, case_id: &str, evidence_id: Option<&str>, author: &str, body: &str) -> Result<i64> {
    c.execute("INSERT INTO analyst_note(case_id,evidence_id,at,author,body) VALUES (?1,?2,?3,?4,?5)", params![case_id, evidence_id, crate::db::now(), author, body])?;
    if let Some(e) = evidence_id { crate::db::custody(c, e, author, "note_added", &crate::hashing::sha256_hex(body.as_bytes()))?; }
    Ok(c.last_insert_rowid())
}

pub fn case_json(c: &Connection, case_id: &str) -> Result<serde_json::Value> {
    let case: serde_json::Value = c.query_row("SELECT case_id,title,examiner,created_at,description FROM forensic_case WHERE case_id=?1", [case_id], |r| {
        Ok(serde_json::json!({"case_id": r.get::<_,String>(0)?, "title": r.get::<_,String>(1)?, "examiner": r.get::<_,String>(2)?, "created_at": r.get::<_,String>(3)?, "description": r.get::<_,Option<String>>(4)?}))
    })?;
    let mut st = c.prepare("SELECT evidence_id,source_device,acquisition_method,acquired_at,original_path,working_copy_path,sha256,size,item_count FROM evidence WHERE case_id=?1 ORDER BY evidence_id")?;
    let ev: Vec<serde_json::Value> = st.query_map([case_id], |r| Ok(serde_json::json!({"evidence_id": r.get::<_,String>(0)?, "source_device": r.get::<_,Option<String>>(1)?,
        "acquisition_method": r.get::<_,String>(2)?, "acquired_at": r.get::<_,String>(3)?, "original_path": r.get::<_,String>(4)?, "working_copy_path": r.get::<_,String>(5)?,
        "sha256": r.get::<_,String>(6)?, "size": r.get::<_,i64>(7)?, "item_count": r.get::<_,i64>(8)?})))?.collect::<std::result::Result<_, _>>()?;
    let mut st = c.prepare("SELECT l.seq,l.evidence_id,l.at,l.actor,l.action,l.detail,l.entry_hash FROM custody_log l JOIN evidence e ON e.evidence_id=l.evidence_id WHERE e.case_id=?1 ORDER BY l.seq")?;
    let custody: Vec<serde_json::Value> = st.query_map([case_id], |r| Ok(serde_json::json!({"seq": r.get::<_,i64>(0)?, "evidence_id": r.get::<_,String>(1)?, "at": r.get::<_,String>(2)?,
        "actor": r.get::<_,String>(3)?, "action": r.get::<_,String>(4)?, "detail": r.get::<_,Option<String>>(5)?, "entry_hash": r.get::<_,String>(6)?})))?.collect::<std::result::Result<_, _>>()?;
    let mut st = c.prepare("SELECT note_id,evidence_id,at,author,body FROM analyst_note WHERE case_id=?1 ORDER BY note_id")?;
    let notes: Vec<serde_json::Value> = st.query_map([case_id], |r| Ok(serde_json::json!({"note_id": r.get::<_,i64>(0)?, "evidence_id": r.get::<_,Option<String>>(1)?, "at": r.get::<_,String>(2)?,
        "author": r.get::<_,String>(3)?, "body": r.get::<_,String>(4)?})))?.collect::<std::result::Result<_, _>>()?;
    Ok(serde_json::json!({"case": case, "evidence": ev, "custody": custody, "notes": notes}))
}

pub fn list_cases(c: &Connection) -> Result<Vec<serde_json::Value>> {
    let mut st = c.prepare("SELECT c.case_id,c.title,c.examiner,c.created_at,(SELECT count(*) FROM evidence e WHERE e.case_id=c.case_id) FROM forensic_case c ORDER BY c.created_at DESC")?;
    let r = st.query_map([], |r| Ok(serde_json::json!({"case_id": r.get::<_,String>(0)?, "title": r.get::<_,String>(1)?, "examiner": r.get::<_,String>(2)?,
        "created_at": r.get::<_,String>(3)?, "evidence_count": r.get::<_,i64>(4)?})))?.collect::<std::result::Result<_, _>>()?;
    Ok(r)
}

/// Normalise mixed timestamps (RFC3339, "YYYY-MM-DD HH:MM:SS", unix seconds) to UTC RFC3339.
pub fn normalize_ts(s: &str) -> Option<String> {
    use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
    if let Ok(d) = DateTime::parse_from_rfc3339(s) { return Some(d.with_timezone(&Utc).to_rfc3339()); }
    if let Ok(n) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") { return Some(Utc.from_utc_datetime(&n).to_rfc3339()); }
    if let Ok(x) = s.parse::<i64>() { return DateTime::from_timestamp(if x > 100_000_000_000 { x / 1000 } else { x }, 0).map(|d| d.to_rfc3339()); }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_lifecycle_and_tamper_detection() {
        let c = crate::db::open_memory().unwrap();
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), "alpha").unwrap();
        std::fs::write(src.join("sub/b.bin"), [1u8, 2, 3]).unwrap();
        let case = create_case(&c, "Test", "examiner", None).unwrap();
        let ev = add_evidence(&c, &d.path().join("store"), &case, &src, Some("TEST-DEVICE"), "logical_copy", "examiner").unwrap();
        assert_eq!(ev.item_count, 2);
        // original unchanged
        assert_eq!(std::fs::read_to_string(src.join("a.txt")).unwrap(), "alpha");
        let v = verify_evidence(&c, &ev.evidence_id, "examiner").unwrap();
        assert!(v.working_copy_intact && v.custody_chain.intact);
        // tamper with working copy
        let wc = Path::new(&ev.working_copy_path).join("a.txt");
        let mut p = std::fs::metadata(&wc).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        p.set_readonly(false);
        std::fs::set_permissions(&wc, p).unwrap();
        std::fs::write(&wc, "tampered").unwrap();
        assert!(!verify_evidence(&c, &ev.evidence_id, "examiner").unwrap().working_copy_intact);
        // tamper with custody log
        c.execute("UPDATE custody_log SET actor='mallory' WHERE seq=1", []).unwrap();
        assert!(!crate::db::verify_custody(&c, &ev.evidence_id).unwrap().intact);
    }
    #[test]
    fn ts_norm() {
        assert_eq!(normalize_ts("2025-01-02 03:04:05").unwrap(), "2025-01-02T03:04:05+00:00");
        assert_eq!(normalize_ts("2025-01-02T10:04:05+07:00").unwrap(), "2025-01-02T03:04:05+00:00");
    }
}
