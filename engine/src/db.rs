//! SQLite storage + tamper-evident hash-chained logs.

use anyhow::{bail, Result};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::Path;

pub const SCHEMA_VERSION: i64 = 1;

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn open(path: &Path) -> Result<Connection> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let c = Connection::open(path)?;
    c.busy_timeout(std::time::Duration::from_secs(10))?;
    c.execute_batch(include_str!("schema.sql"))?;
    let v: Option<i64> = c.query_row("SELECT max(version) FROM schema_version", [], |r| r.get(0)).unwrap_or(None);
    if v.is_none() {
        c.execute("INSERT INTO schema_version(version) VALUES (?1)", [SCHEMA_VERSION])?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(c)
}

pub fn open_memory() -> Result<Connection> {
    let c = Connection::open_in_memory()?;
    c.execute_batch(include_str!("schema.sql"))?;
    Ok(c)
}

fn chain_hash(prev: &str, at: &str, actor: &str, action: &str, detail: &str) -> String {
    crate::hashing::sha256_hex(format!("{prev}\u{1f}{at}\u{1f}{actor}\u{1f}{action}\u{1f}{detail}").as_bytes())
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Append to the application audit log.
pub fn audit(c: &Connection, actor: &str, action: &str, detail: &str) -> Result<()> {
    let prev: String = c
        .query_row("SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
        .unwrap_or_else(|_| GENESIS.to_string());
    let at = now();
    let h = chain_hash(&prev, &at, actor, action, detail);
    c.execute(
        "INSERT INTO audit_log(at,actor,action,detail,prev_hash,entry_hash) VALUES (?1,?2,?3,?4,?5,?6)",
        params![at, actor, action, detail, prev, h],
    )?;
    Ok(())
}

#[derive(Serialize)]
pub struct ChainReport {
    pub entries: usize,
    pub intact: bool,
    pub first_broken_seq: Option<i64>,
}

fn verify_chain(c: &Connection, sql: &str) -> Result<ChainReport> {
    let mut st = c.prepare(sql)?;
    let rows = st.query_map([], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, Option<String>>(4)?, r.get::<_, String>(5)?, r.get::<_, String>(6)?))
    })?;
    let mut prev_expected: Option<String> = None;
    let mut n = 0;
    for row in rows {
        let (seq, at, actor, action, detail, prev, h) = row?;
        n += 1;
        let expected_prev = prev_expected.clone().unwrap_or_else(|| prev.clone());
        if prev != expected_prev || chain_hash(&prev, &at, &actor, &action, &detail.unwrap_or_default()) != h {
            return Ok(ChainReport { entries: n, intact: false, first_broken_seq: Some(seq) });
        }
        prev_expected = Some(h);
    }
    Ok(ChainReport { entries: n, intact: true, first_broken_seq: None })
}

pub fn verify_audit(c: &Connection) -> Result<ChainReport> {
    verify_chain(c, "SELECT seq,at,actor,action,detail,prev_hash,entry_hash FROM audit_log ORDER BY seq")
}

/// Append a chain-of-custody entry. Each evidence item has its own chain.
pub fn custody(c: &Connection, evidence_id: &str, actor: &str, action: &str, detail: &str) -> Result<()> {
    let prev: String = c
        .query_row(
            "SELECT entry_hash FROM custody_log WHERE evidence_id=?1 ORDER BY seq DESC LIMIT 1",
            [evidence_id],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| GENESIS.to_string());
    let at = now();
    let h = chain_hash(&prev, &at, actor, &format!("{evidence_id}:{action}"), detail);
    c.execute(
        "INSERT INTO custody_log(evidence_id,at,actor,action,detail,prev_hash,entry_hash) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![evidence_id, at, actor, action, detail, prev, h],
    )?;
    Ok(())
}

pub fn verify_custody(c: &Connection, evidence_id: &str) -> Result<ChainReport> {
    let mut st = c.prepare(
        "SELECT seq,at,actor,evidence_id||':'||action,detail,prev_hash,entry_hash FROM custody_log WHERE evidence_id=?1 ORDER BY seq",
    )?;
    let rows: Vec<_> = st
        .query_map([evidence_id], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, Option<String>>(4)?, r.get::<_, String>(5)?, r.get::<_, String>(6)?))
        })?
        .collect::<std::result::Result<_, _>>()?;
    let mut prev_expected = GENESIS.to_string();
    for (i, (seq, at, actor, action, detail, prev, h)) in rows.iter().enumerate() {
        if *prev != prev_expected || chain_hash(prev, at, actor, action, &detail.clone().unwrap_or_default()) != *h {
            return Ok(ChainReport { entries: i + 1, intact: false, first_broken_seq: Some(*seq) });
        }
        prev_expected = h.clone();
    }
    if rows.is_empty() {
        bail!("no custody entries for {evidence_id}");
    }
    Ok(ChainReport { entries: rows.len(), intact: true, first_broken_seq: None })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_chain_detects_tamper() {
        let c = open_memory().unwrap();
        for i in 0..5 {
            audit(&c, "tester", "act", &format!("d{i}")).unwrap();
        }
        assert!(verify_audit(&c).unwrap().intact);
        c.execute("UPDATE audit_log SET detail='evil' WHERE seq=3", []).unwrap();
        let r = verify_audit(&c).unwrap();
        assert!(!r.intact);
        assert_eq!(r.first_broken_seq, Some(3));
    }
}
