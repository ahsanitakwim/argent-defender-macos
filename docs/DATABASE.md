# ARGENT DEFENDER — Database Schema

SQLite 3 (bundled), WAL mode, foreign keys on, file mode 0600, at
`~/Library/Application Support/ArgentDefender/argent.db`. Created/migrated automatically by the engine (`schema_version`).

| Table | Purpose |
|---|---|
| `ioc` | Unified threat-intelligence indicators. Unique on (type, value, source). Indexed by value and (type, value). |
| `intel_feed` | Provenance per dataset: source, URL, **licence**, reliability 0–100, last update, **SHA-256 of the imported payload**, record count. |
| `indonesia_gambling_threat_intelligence` | ARGENT GAMING WATCH database (spec structure + `classification`, `verified`, `verified_by`). |
| `device` | Devices examined (id = adb serial / iOS UDID), model, OS, first/last seen, last score. |
| `scan` | Scan history: kind, target, device, timestamps, score, finding count, full result JSON, benchmark JSON. |
| `file_cache` | Incremental-scan cache keyed by path with size+mtime and SHA-256/SHA-1/MD5. |
| `forensic_case`, `evidence`, `analyst_note` | Cases, evidence items (acquisition method, UTC time, original & working-copy path, SHA-256, size, item count), notes. |
| `custody_log` | Per-evidence hash chain: `entry_hash = SHA-256(prev ‖ at ‖ actor ‖ evidence:action ‖ detail)`. |
| `audit_log` | Application-wide hash-chained audit log (imports, scans, admin changes, exports). |

Full DDL (authoritative copy: `engine/src/schema.sql`):

```sql
-- ARGENT DEFENDER local database schema (SQLite). Documented in docs/DATABASE.md.
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

-- Unified threat intelligence (URLhaus, ThreatFox, MalwareBazaar, STIX2/MVT, MISP, manual)
CREATE TABLE IF NOT EXISTS ioc (
    id            INTEGER PRIMARY KEY,
    ioc_type      TEXT NOT NULL CHECK (ioc_type IN ('domain','url','ip','sha256','sha1','md5','package','process','cert_sha256','email')),
    value         TEXT NOT NULL,
    threat        TEXT,            -- malware family / campaign
    category      TEXT,            -- malware|phishing|spyware|c2|gambling|...
    source        TEXT NOT NULL,
    confidence    INTEGER NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    reference     TEXT,
    tags          TEXT,
    first_seen    TEXT,
    last_updated  TEXT NOT NULL,
    UNIQUE (ioc_type, value, source)
);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc (value);
CREATE INDEX IF NOT EXISTS idx_ioc_type_value ON ioc (ioc_type, value);

-- Feed/dataset provenance: source, update time, license, integrity hash
CREATE TABLE IF NOT EXISTS intel_feed (
    source        TEXT PRIMARY KEY,
    url           TEXT,
    license       TEXT,
    reliability   INTEGER NOT NULL DEFAULT 50 CHECK (reliability BETWEEN 0 AND 100),
    last_update   TEXT,
    payload_sha256 TEXT,
    records       INTEGER NOT NULL DEFAULT 0
);

-- INDONESIA_GAMBLING_THREAT_INTELLIGENCE (ARGENT GAMING WATCH)
CREATE TABLE IF NOT EXISTS indonesia_gambling_threat_intelligence (
    indicator_id      TEXT PRIMARY KEY,
    domain            TEXT,
    url               TEXT,
    package_name      TEXT,
    apk_hash          TEXT,
    brand_alias       TEXT,
    indicator_type    TEXT NOT NULL CHECK (indicator_type IN ('domain','url','package','apk_hash','brand')),
    classification    TEXT NOT NULL CHECK (classification IN ('CONFIRMED_INDICATOR','HIGH_RISK','SUSPECTED')),
    evidence          TEXT,
    source            TEXT NOT NULL,
    confidence        INTEGER NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    verified          INTEGER NOT NULL DEFAULT 0,
    verified_by       TEXT,
    verification_date TEXT,
    last_updated      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_judol_domain ON indonesia_gambling_threat_intelligence (domain);
CREATE INDEX IF NOT EXISTS idx_judol_pkg ON indonesia_gambling_threat_intelligence (package_name);
CREATE INDEX IF NOT EXISTS idx_judol_hash ON indonesia_gambling_threat_intelligence (apk_hash);

-- Devices and scan history
CREATE TABLE IF NOT EXISTS device (
    device_id     TEXT PRIMARY KEY,   -- adb serial or iOS UDID (only if lawfully accessible)
    platform      TEXT NOT NULL CHECK (platform IN ('android','ios')),
    name          TEXT,
    manufacturer  TEXT,
    model         TEXT,
    os_version    TEXT,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    last_score    INTEGER
);

CREATE TABLE IF NOT EXISTS scan (
    scan_id       TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,      -- quick|full|deep|custom|incremental|android_audit|ios_backup|apk|url
    target        TEXT NOT NULL,
    device_id     TEXT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    score         INTEGER,
    findings      INTEGER NOT NULL DEFAULT 0,
    result_json   TEXT,
    bench_json    TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_started ON scan (started_at DESC);

-- Incremental-scan hash cache
CREATE TABLE IF NOT EXISTS file_cache (
    path          TEXT PRIMARY KEY,
    size          INTEGER NOT NULL,
    mtime         INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    sha1          TEXT NOT NULL,
    md5           TEXT NOT NULL,
    last_result   TEXT
);

-- Digital forensics: cases, evidence, chain of custody, notes
CREATE TABLE IF NOT EXISTS forensic_case (
    case_id       TEXT PRIMARY KEY,
    title         TEXT NOT NULL,
    examiner      TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    description   TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id         TEXT PRIMARY KEY,
    case_id             TEXT NOT NULL REFERENCES forensic_case(case_id),
    source_device       TEXT,
    acquisition_method  TEXT NOT NULL,
    acquired_at         TEXT NOT NULL,   -- UTC ISO-8601
    original_path       TEXT NOT NULL,
    working_copy_path   TEXT NOT NULL,
    sha256              TEXT NOT NULL,
    size                INTEGER NOT NULL,
    item_count          INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS custody_log (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id   TEXT NOT NULL,
    at            TEXT NOT NULL,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    detail        TEXT,
    prev_hash     TEXT NOT NULL,
    entry_hash    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analyst_note (
    note_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       TEXT NOT NULL,
    evidence_id   TEXT,
    at            TEXT NOT NULL,
    author        TEXT NOT NULL,
    body          TEXT NOT NULL
);

-- Tamper-evident, hash-chained application audit log
CREATE TABLE IF NOT EXISTS audit_log (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    at            TEXT NOT NULL,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    detail        TEXT,
    prev_hash     TEXT NOT NULL,
    entry_hash    TEXT NOT NULL
);
```
