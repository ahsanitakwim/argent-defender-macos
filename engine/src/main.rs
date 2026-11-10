//! `argent-engine` — JSON command-line interface used by the ARGENT DEFENDER macOS app.
//! Every command prints one JSON envelope: {"ok":bool,"command":..,"data":..,"error":..,"duration_ms":..}
//! Secrets (backup passwords, PQC master seed, API keys) are read from stdin only.

use anyhow::{anyhow, Context, Result};
use argent::*;
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "argent-engine", version, about = "ARGENT DEFENDER engine — DEFEND THE DIGITAL. REVEAL THE TRUTH.")]
struct Cli {
    /// SQLite database path (default: ~/Library/Application Support/ArgentDefender/argent.db)
    #[arg(long, global = true, env = "ARGENT_DB")]
    db: Option<PathBuf>,
    /// Pretty-print JSON
    #[arg(long, global = true)]
    pretty: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Host capability & external tool detection (adaptive compatibility)
    Env,
    /// Detect connected Android (ADB) and iPhone (libimobiledevice) devices
    Devices,
    /// Known devices and last scores
    DeviceHistory,
    #[command(subcommand)]
    Android(AndroidCmd),
    #[command(subcommand)]
    Ios(IosCmd),
    /// Static analysis of one APK file
    Apk { file: PathBuf, #[arg(long)] no_record: bool },
    /// File/folder scan (YARA-X, hash intel, APK/IPA, Gaming Watch, optional ClamAV)
    Scan {
        path: PathBuf,
        #[arg(long, default_value = "quick")] mode: String,
        #[arg(long)] rules_dir: Option<PathBuf>,
        #[arg(long, value_delimiter = ',')] ext: Vec<String>,
        #[arg(long, default_value_t = 0)] max_size: u64,
        #[arg(long)] clamav: bool,
        #[arg(long, default_value_t = 0)] threads: usize,
    },
    /// URL / domain analysis (phishing, typosquatting, homograph, intel, judol)
    Url { urls: Vec<String>, #[arg(long)] follow_redirects: bool },
    #[command(subcommand)]
    Intel(IntelCmd),
    #[command(subcommand)]
    Judol(JudolCmd),
    #[command(subcommand)]
    Case(CaseCmd),
    #[command(subcommand)]
    Evidence(EvidenceCmd),
    /// Scan history
    History { #[arg(long, default_value_t = 100)] limit: i64 },
    /// Full stored result of a scan
    ScanGet { id: String },
    /// Export a report for a stored scan (html|json). --sign reads PQC master seed (hex) from stdin.
    Report { #[arg(long)] scan: String, #[arg(long, default_value = "html")] format: String, #[arg(long)] out: PathBuf, #[arg(long)] sign: bool },
    #[command(subcommand)]
    Pqc(PqcCmd),
    /// Verify the tamper-evident audit log
    AuditVerify,
    /// Recent audit log entries
    AuditLog { #[arg(long, default_value_t = 200)] limit: i64 },
    /// List compiled YARA rules (bundled + admin rules dir)
    Rules { #[arg(long)] rules_dir: Option<PathBuf> },
}

#[derive(Subcommand)]
enum AndroidCmd {
    Info { #[arg(long)] serial: String },
    /// Security audit. --pull-apks enables Advanced Forensic Mode (copies user-installed APKs for static analysis).
    Audit { #[arg(long)] serial: String, #[arg(long)] pull_apks: Option<PathBuf>, #[arg(long)] third_party_only: bool },
}

#[derive(Subcommand)]
enum IosCmd {
    Info { #[arg(long)] udid: String },
    Audit { #[arg(long)] udid: String, #[arg(long, default_value_t = 17)] min_ios: u32 },
    /// Create a local backup via idevicebackup2 (device must be unlocked and trusted)
    BackupCreate { #[arg(long)] udid: String, #[arg(long)] out: PathBuf },
    /// Discover local Finder backups
    Backups { #[arg(long)] root: Option<PathBuf> },
    /// Analyse a backup. Encrypted backups: password on stdin (never stored).
    Analyze { #[arg(long)] backup: PathBuf, #[arg(long)] password_stdin: bool, #[arg(long)] include_messages: bool, #[arg(long, default_value_t = 17)] min_ios: u32 },
}

#[derive(Subcommand)]
enum IntelCmd {
    Import { #[arg(long)] format: String, #[arg(long)] file: PathBuf, #[arg(long)] source: String, #[arg(long)] license: Option<String>, #[arg(long, default_value_t = 70)] reliability: i64 },
    /// Download urlhaus|threatfox|bazaar. Optional abuse.ch Auth-Key on stdin with --auth-key-stdin.
    Update { #[arg(long)] feed: String, #[arg(long)] auth_key_stdin: bool },
    Lookup { value: String },
    Add { #[arg(long = "type")] ioc_type: String, #[arg(long)] value: String, #[arg(long)] category: Option<String>, #[arg(long)] threat: Option<String>, #[arg(long, default_value = "manual")] source: String, #[arg(long, default_value_t = 70)] confidence: i64 },
    Delete { #[arg(long)] id: i64 },
    List { #[arg(long)] q: Option<String>, #[arg(long, default_value_t = 500)] limit: i64 },
    Stats,
}

#[derive(Subcommand)]
enum JudolCmd {
    /// Add/update an indicator from JSON on stdin
    Add,
    List { #[arg(long)] q: Option<String> },
    Verify { #[arg(long)] id: String, #[arg(long)] analyst: String },
    Delete { #[arg(long)] id: String, #[arg(long)] analyst: String },
    Import { #[arg(long)] file: PathBuf },
    /// Check a domain/URL/package/hash
    Check { value: String },
}

#[derive(Subcommand)]
enum CaseCmd {
    Create { #[arg(long)] title: String, #[arg(long)] examiner: String, #[arg(long)] description: Option<String> },
    List,
    Show { id: String },
    Note { #[arg(long)] case: String, #[arg(long)] evidence: Option<String>, #[arg(long)] author: String, #[arg(long)] body: String },
    Timeline { id: String },
}

#[derive(Subcommand)]
enum EvidenceCmd {
    Add { #[arg(long)] case: String, #[arg(long)] path: PathBuf, #[arg(long)] device: Option<String>, #[arg(long, default_value = "logical_copy")] method: String, #[arg(long)] examiner: String },
    Verify { #[arg(long)] id: String, #[arg(long)] examiner: String },
    /// Run a deep scan on the read-only working copy and log it to chain of custody
    Analyze { #[arg(long)] id: String, #[arg(long)] examiner: String },
}

#[derive(Subcommand)]
enum PqcCmd {
    /// Generate a new random master seed (hex) — the app stores it in the Keychain
    NewSeed,
    /// Public key bundle for the seed on stdin
    Pubkey,
    Sign { #[arg(long)] file: PathBuf, #[arg(long)] out: PathBuf },
    Verify { #[arg(long)] file: PathBuf, #[arg(long)] sig: PathBuf, #[arg(long)] pubkey: PathBuf },
    Encrypt { #[arg(long)] file: PathBuf, #[arg(long)] pubkey: PathBuf, #[arg(long)] out: PathBuf },
    Decrypt { #[arg(long)] file: PathBuf, #[arg(long)] out: PathBuf },
}

fn default_db() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    if cfg!(target_os = "macos") { home.join("Library/Application Support/ArgentDefender/argent.db") } else { home.join(".local/share/argent-defender/argent.db") }
}

fn data_dir(db: &std::path::Path) -> PathBuf { db.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from(".")) }

fn stdin_line() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim_end_matches(['\n', '\r']).to_string())
}

fn findings_of(v: &Value) -> Vec<model::Finding> {
    v.get("findings").and_then(|f| serde_json::from_value(f.clone()).ok()).unwrap_or_default()
}

fn run(cli: &Cli) -> Result<Value> {
    let dbp = cli.db.clone().unwrap_or_else(default_db);
    let mut c = db::open(&dbp)?;
    let started = db::now();
    Ok(match &cli.cmd {
        Cmd::Env => json!({"host": tools::host(), "tools": tools::status(), "database": dbp, "intel": intel::stats(&c)?, "rules": scan::compile_rules(Some(&data_dir(&dbp).join("rules"))).map(|(r, e)| json!({"count": r.count, "files": r.files, "errors": e})).unwrap_or(json!(null))}),
        Cmd::Devices => {
            let android = match android::list_devices() {
                Ok(v) => { for d in &v { if d.state == "device" { report::upsert_device(&c, &d.serial, "android", d.model.as_deref(), None, d.model.as_deref(), None)?; } } json!({"available": true, "devices": v}) }
                Err(e) => json!({"available": false, "error": e.to_string(), "devices": []}),
            };
            let ios = match tools::which("idevice_id") {
                Some(_) => { let v = ios::list_devices()?; for d in &v { report::upsert_device(&c, &d.udid, "ios", d.name.as_deref(), Some("Apple"), d.product_type.as_deref(), d.ios_version.as_deref())?; } json!({"available": true, "devices": v}) }
                None => json!({"available": false, "error": "libimobiledevice not installed (brew install libimobiledevice)", "devices": []}),
            };
            json!({"android": android, "ios": ios})
        }
        Cmd::DeviceHistory => json!(report::devices(&c)?),
        Cmd::Android(AndroidCmd::Info { serial }) => {
            let i = android::info(&android::Adb { serial: serial.clone() })?;
            report::upsert_device(&c, serial, "android", i.device_name.as_deref(), i.manufacturer.as_deref(), i.model.as_deref(), i.android_version.as_deref())?;
            json!(i)
        }
        Cmd::Android(AndroidCmd::Audit { serial, pull_apks, third_party_only }) => {
            db::audit(&c, "user", "android.audit.start", &format!("{serial} advanced={}", pull_apks.is_some()))?;
            let a = android::audit_device(&c, serial, pull_apks.as_deref(), *third_party_only)?;
            report::upsert_device(&c, serial, "android", a.info.device_name.as_deref(), a.info.manufacturer.as_deref(), a.info.model.as_deref(), a.info.android_version.as_deref())?;
            let mut v = json!(a);
            v["risk"] = json!(report::risk_score(&a.findings));
            v["scan_id"] = json!(report::record_scan(&c, "android_audit", serial, Some(serial), &started, &a.findings, &v, None)?);
            v
        }
        Cmd::Ios(IosCmd::Info { udid }) => json!(ios::device_info(udid, "usb")?),
        Cmd::Ios(IosCmd::Audit { udid, min_ios }) => {
            let (info, f) = ios::device_audit(udid, *min_ios)?;
            let mut v = json!({"info": info, "findings": f, "risk": report::risk_score(&f)});
            v["scan_id"] = json!(report::record_scan(&c, "ios_audit", udid, Some(udid), &started, &f, &v, None)?);
            v
        }
        Cmd::Ios(IosCmd::BackupCreate { udid, out }) => { db::audit(&c, "user", "ios.backup.create", udid)?; json!({"output": ios::create_backup(udid, out)?, "path": out}) }
        Cmd::Ios(IosCmd::Backups { root }) => {
            let r = root.clone().unwrap_or_else(ios::default_backup_root);
            json!({"root": r, "readable": std::fs::read_dir(&r).is_ok(), "backups": ios::discover(&r),
                   "note": "If the folder is not readable, grant ARGENT DEFENDER Full Disk Access in System Settings › Privacy & Security."})
        }
        Cmd::Ios(IosCmd::Analyze { backup, password_stdin, include_messages, min_ios }) => {
            let pw = if *password_stdin { Some(stdin_line()?) } else { None };
            db::audit(&c, "user", "ios.backup.analyze", &format!("{} encrypted_password_supplied={}", backup.display(), pw.is_some()))?;
            let r = ios::analyze_backup(backup, pw.as_deref().map(|s| s.as_bytes()), &c, &ios::AnalyzeOptions { include_messages: *include_messages, min_ios_major: *min_ios })?;
            drop(pw);
            let mut v = json!(r);
            v["risk"] = json!(report::risk_score(&r.findings));
            v["gambling_classification"] = json!(judol::classify(&r.findings));
            v["scan_id"] = json!(report::record_scan(&c, "ios_backup", &backup.display().to_string(), Some(&r.summary.udid), &started, &r.findings, &v, None)?);
            v
        }
        Cmd::Apk { file, no_record } => {
            let mut r = apk::analyze_apk(file)?;
            apk::apksigner_verify(file, &mut r.signing);
            let prof = permissions::profile_from_apk(&r);
            let mut f = permissions::audit(&prof);
            let (rs, _) = scan::compile_rules(Some(&data_dir(&dbp).join("rules")))?;
            let bytes = std::fs::read(file)?;
            let mut scanner = yara_x::Scanner::new(&rs.rules);
            let subj = model::Subject { kind: "file".into(), name: file.file_name().unwrap().to_string_lossy().to_string(), path: Some(file.display().to_string()), sha256: Some(r.hashes.sha256.clone()) };
            f.extend(scan::yara_scan(&mut scanner, &bytes, &subj, None));
            for (n, d) in zip_entries(&bytes) { f.extend(scan::yara_scan(&mut scanner, &d, &subj, Some(&n))); }
            for (t, h) in [("sha256", &r.hashes.sha256), ("sha1", &r.hashes.sha1), ("md5", &r.hashes.md5)] { for hit in intel::lookup(&c, t, h)? { f.push(hit.to_finding(subj.clone())); } }
            for cert in &r.signing.certificates_sha256 { for hit in intel::lookup(&c, "cert_sha256", cert)? { f.push(hit.to_finding(subj.clone())); } }
            for hit in intel::lookup(&c, "package", &r.manifest.package)? { f.push(hit.to_finding(subj.clone())); }
            f.extend(judol::check_hash(&c, &r.hashes.sha256, subj.clone())?);
            f.extend(judol::check_package(&c, &r.manifest.package, r.manifest.label.as_deref())?);
            scan::dedup(&mut f);
            let mut v = json!({"apk": r, "profile": prof, "findings": f, "risk": report::risk_score(&f), "gambling_classification": judol::classify(&f)});
            if !no_record { v["scan_id"] = json!(report::record_scan(&c, "apk", &file.display().to_string(), None, &started, &f, &v, None)?); }
            v
        }
        Cmd::Scan { path, mode, rules_dir, ext, max_size, clamav, threads } => {
            let opt = scan::ScanOptions { mode: mode.parse()?, rules_dir: Some(rules_dir.clone().unwrap_or_else(|| data_dir(&dbp).join("rules"))), extensions: ext.clone(), max_size: *max_size, clamav: *clamav, threads: *threads };
            let r = scan::scan_path(&c, path, &opt)?;
            let mut v = json!(r);
            v["risk"] = json!(report::risk_score(&r.findings));
            v["gambling_classification"] = json!(judol::classify(&r.findings));
            let bench = json!(r.bench);
            v["scan_id"] = json!(report::record_scan(&c, mode, &path.display().to_string(), None, &started, &r.findings, &v, Some(&bench))?);
            v
        }
        Cmd::Url { urls, follow_redirects } => {
            let mut out = vec![];
            let mut all = vec![];
            for u in urls {
                let a = urlcheck::analyze(u, &c, *follow_redirects)?;
                all.extend(a.findings.clone());
                out.push(a);
            }
            let mut v = json!({"results": out, "findings": all, "risk": report::risk_score(&all), "gambling_classification": judol::classify(&all)});
            v["scan_id"] = json!(report::record_scan(&c, "url", &urls.join(" "), None, &started, &all, &v, None)?);
            v
        }
        Cmd::Intel(IntelCmd::Import { format, file, source, license, reliability }) => {
            let text = std::fs::read_to_string(file).with_context(|| format!("read {}", file.display()))?;
            json!(intel::import(&mut c, format, &text, source, license.as_deref(), None, *reliability)?)
        }
        Cmd::Intel(IntelCmd::Update { feed, auth_key_stdin }) => {
            let key = if *auth_key_stdin { Some(stdin_line()?) } else { None };
            json!(intel::update_online(&mut c, feed, key.as_deref().filter(|k| !k.is_empty()))?)
        }
        Cmd::Intel(IntelCmd::Lookup { value }) => json!({"type": intel::classify(value), "hits": intel::lookup_any(&c, value)?, "judol": judol::check_url(&c, value).ok()}),
        Cmd::Intel(IntelCmd::Add { ioc_type, value, category, threat, source, confidence }) => {
            intel::upsert(&c, ioc_type, value, threat.as_deref(), category.as_deref(), source, *confidence, None, None, None)?;
            c.execute("INSERT OR IGNORE INTO intel_feed(source,license,reliability,last_update,records) VALUES (?1,'local',70,?2,0)", rusqlite::params![source, db::now()])?;
            db::audit(&c, "admin", "intel.add", &format!("{ioc_type}:{value}"))?;
            json!({"added": value})
        }
        Cmd::Intel(IntelCmd::Delete { id }) => { c.execute("DELETE FROM ioc WHERE id=?1", [id])?; db::audit(&c, "admin", "intel.delete", &id.to_string())?; json!({"deleted": id}) }
        Cmd::Intel(IntelCmd::List { q, limit }) => {
            let like = format!("%{}%", q.clone().unwrap_or_default());
            let mut st = c.prepare("SELECT id,ioc_type,value,threat,category,source,confidence,last_updated FROM ioc WHERE value LIKE ?1 OR threat LIKE ?1 ORDER BY last_updated DESC LIMIT ?2")?;
            let rows: Vec<Value> = st.query_map(rusqlite::params![like, limit], |r| Ok(json!({"id": r.get::<_,i64>(0)?, "type": r.get::<_,String>(1)?, "value": r.get::<_,String>(2)?, "threat": r.get::<_,Option<String>>(3)?,
                "category": r.get::<_,Option<String>>(4)?, "source": r.get::<_,String>(5)?, "confidence": r.get::<_,i64>(6)?, "last_updated": r.get::<_,String>(7)?})))?.collect::<std::result::Result<_, _>>()?;
            json!(rows)
        }
        Cmd::Intel(IntelCmd::Stats) => json!(intel::stats(&c)?),
        Cmd::Judol(JudolCmd::Add) => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            let ind: judol::Indicator = serde_json::from_str(&s).context("indicator JSON")?;
            json!({"indicator_id": judol::add(&c, &ind)?})
        }
        Cmd::Judol(JudolCmd::List { q }) => json!(judol::list(&c, q.as_deref())?),
        Cmd::Judol(JudolCmd::Verify { id, analyst }) => { judol::verify(&c, id, analyst)?; json!({"verified": id}) }
        Cmd::Judol(JudolCmd::Delete { id, analyst }) => { judol::delete(&c, id, analyst)?; json!({"deleted": id}) }
        Cmd::Judol(JudolCmd::Import { file }) => json!({"imported": judol::import_csv(&c, &std::fs::read_to_string(file)?)?}),
        Cmd::Judol(JudolCmd::Check { value }) => {
            let f = match intel::classify(value) {
                "sha256" => judol::check_hash(&c, value, model::subject("file", value))?,
                "package" if !value.contains('/') => judol::check_package(&c, value, None)?,
                _ => judol::check_url(&c, value)?,
            };
            json!({"classification": judol::classify(&f), "findings": f})
        }
        Cmd::Case(CaseCmd::Create { title, examiner, description }) => json!({"case_id": forensic::create_case(&c, title, examiner, description.as_deref())?}),
        Cmd::Case(CaseCmd::List) => json!(forensic::list_cases(&c)?),
        Cmd::Case(CaseCmd::Show { id }) => forensic::case_json(&c, id)?,
        Cmd::Case(CaseCmd::Note { case, evidence, author, body }) => json!({"note_id": forensic::add_note(&c, case, evidence.as_deref(), author, body)?}),
        Cmd::Case(CaseCmd::Timeline { id }) => {
            let cj = forensic::case_json(&c, id)?;
            let mut ev: Vec<forensic::TimelineEvent> = vec![];
            for e in cj["evidence"].as_array().unwrap_or(&vec![]) {
                ev.push(forensic::TimelineEvent { at: e["acquired_at"].as_str().unwrap_or("").into(), source: "evidence".into(), kind: "acquired".into(), description: format!("{} {}", e["evidence_id"].as_str().unwrap_or(""), e["original_path"].as_str().unwrap_or("")) });
            }
            for l in cj["custody"].as_array().unwrap_or(&vec![]) {
                ev.push(forensic::TimelineEvent { at: l["at"].as_str().unwrap_or("").into(), source: "custody".into(), kind: l["action"].as_str().unwrap_or("").into(), description: format!("{} by {}", l["evidence_id"].as_str().unwrap_or(""), l["actor"].as_str().unwrap_or("")) });
            }
            for n in cj["notes"].as_array().unwrap_or(&vec![]) {
                ev.push(forensic::TimelineEvent { at: n["at"].as_str().unwrap_or("").into(), source: "note".into(), kind: "note".into(), description: n["body"].as_str().unwrap_or("").chars().take(200).collect() });
            }
            ev.iter_mut().for_each(|e| if let Some(n) = forensic::normalize_ts(&e.at) { e.at = n });
            ev.sort_by(|a, b| a.at.cmp(&b.at));
            json!(ev)
        }
        Cmd::Evidence(EvidenceCmd::Add { case, path, device, method, examiner }) => json!(forensic::add_evidence(&c, &data_dir(&dbp).join("evidence"), case, path, device.as_deref(), method, examiner)?),
        Cmd::Evidence(EvidenceCmd::Verify { id, examiner }) => json!(forensic::verify_evidence(&c, id, examiner)?),
        Cmd::Evidence(EvidenceCmd::Analyze { id, examiner }) => {
            let v = forensic::verify_evidence(&c, id, examiner)?;
            if !v.working_copy_intact { return Err(anyhow!("working copy integrity check failed — analysis refused")); }
            let work: String = c.query_row("SELECT working_copy_path FROM evidence WHERE evidence_id=?1", [id], |r| r.get(0))?;
            let p = PathBuf::from(&work);
            let mut v = if ios::summarize(&p).encrypted == Some(false) && p.join("Manifest.db").exists() {
                let r = ios::analyze_backup(&p, None, &c, &ios::AnalyzeOptions { include_messages: false, min_ios_major: 17 })?;
                json!(r)
            } else {
                let opt = scan::ScanOptions { mode: scan::Mode::Deep, rules_dir: Some(data_dir(&dbp).join("rules")), extensions: vec![], max_size: 0, clamav: false, threads: 0 };
                json!(scan::scan_path(&c, &p, &opt)?)
            };
            let f = findings_of(&v);
            v["risk"] = json!(report::risk_score(&f));
            let sid = report::record_scan(&c, "evidence", id, None, &started, &f, &v, None)?;
            forensic::log_analysis(&c, id, examiner, &format!("scan {sid}: {} findings", f.len()))?;
            v["scan_id"] = json!(sid);
            v
        }
        Cmd::History { limit } => json!(report::history(&c, *limit)?),
        Cmd::ScanGet { id } => report::get_scan(&c, id)?,
        Cmd::Report { scan, format, out, sign } => {
            let s = report::get_scan(&c, scan)?;
            let f = findings_of(&s["result"]);
            let canonical = serde_json::to_vec(&s)?;
            let sig = if *sign { let m = pqc::read_master_stdin()?; Some(json!({"signature": pqc::sign(&m, &canonical), "public_key": pqc::public_bundle(&m)})) } else { None };
            match format.as_str() {
                "json" => std::fs::write(out, serde_json::to_vec_pretty(&json!({"report": s, "risk": report::risk_score(&f), "summary": ai::summarize(&f, &report::risk_score(&f)), "integrity": sig}))?)?,
                _ => {
                    let mut extra = s["result"].clone();
                    if let Some(o) = extra.as_object_mut() { o.remove("findings"); o.remove("apps"); o.remove("bench"); }
                    std::fs::write(out, report::html_report(&format!("{} report — {}", s["kind"].as_str().unwrap_or(""), scan), s["target"].as_str().unwrap_or(""), &f, &json!({"scan": scan, "bench": s["bench"], "details": extra}), sig.as_ref()))?
                }
            }
            if let Some(sv) = &sig { std::fs::write(out.with_extension("sig.json"), serde_json::to_vec_pretty(sv)?)?; }
            db::audit(&c, "user", "report.export", &format!("{scan} → {}", out.display()))?;
            json!({"path": out, "signed": sig.is_some()})
        }
        Cmd::Pqc(PqcCmd::NewSeed) => json!({"seed_hex": hex::encode(pqc::random32())}),
        Cmd::Pqc(PqcCmd::Pubkey) => json!(pqc::public_bundle(&pqc::read_master_stdin()?)),
        Cmd::Pqc(PqcCmd::Sign { file, out }) => { let m = pqc::read_master_stdin()?; let s = pqc::sign(&m, &std::fs::read(file)?); std::fs::write(out, serde_json::to_vec_pretty(&json!({"signature": s, "public_key": pqc::public_bundle(&m)}))?)?; json!(s) }
        Cmd::Pqc(PqcCmd::Verify { file, sig, pubkey }) => {
            let sv: Value = serde_json::from_slice(&std::fs::read(sig)?)?;
            let s: pqc::HybridSignature = serde_json::from_value(sv.get("signature").cloned().unwrap_or(sv.clone()))?;
            let p: pqc::PublicBundle = serde_json::from_slice(&std::fs::read(pubkey)?)?;
            pqc::verify(&p, &std::fs::read(file)?, &s)?;
            json!({"valid": true, "suite": s.suite, "signer": s.signer_fingerprint})
        }
        Cmd::Pqc(PqcCmd::Encrypt { file, pubkey, out }) => { let p: pqc::PublicBundle = serde_json::from_slice(&std::fs::read(pubkey)?)?; std::fs::write(out, serde_json::to_vec(&pqc::encrypt(&p, &std::fs::read(file)?)?)?)?; json!({"path": out}) }
        Cmd::Pqc(PqcCmd::Decrypt { file, out }) => { let m = pqc::read_master_stdin()?; let e: pqc::Envelope = serde_json::from_slice(&std::fs::read(file)?)?; std::fs::write(out, pqc::decrypt(&m, &e)?)?; json!({"path": out}) }
        Cmd::AuditVerify => json!(db::verify_audit(&c)?),
        Cmd::AuditLog { limit } => {
            let mut st = c.prepare("SELECT seq,at,actor,action,detail FROM audit_log ORDER BY seq DESC LIMIT ?1")?;
            let rows: Vec<Value> = st.query_map([limit], |r| Ok(json!({"seq": r.get::<_,i64>(0)?, "at": r.get::<_,String>(1)?, "actor": r.get::<_,String>(2)?, "action": r.get::<_,String>(3)?, "detail": r.get::<_,Option<String>>(4)?})))?.collect::<std::result::Result<_, _>>()?;
            json!(rows)
        }
        Cmd::Rules { rules_dir } => {
            let (rs, errs) = scan::compile_rules(Some(&rules_dir.clone().unwrap_or_else(|| data_dir(&dbp).join("rules"))))?;
            let names: Vec<String> = rs.rules.iter().map(|r| format!("{}:{}", r.namespace(), r.identifier())).collect();
            json!({"count": rs.count, "files": rs.files, "rules": names, "errors": errs})
        }
    })
}

fn zip_entries(b: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut v = vec![];
    if let Ok(mut z) = zip::ZipArchive::new(std::io::Cursor::new(b)) {
        for i in 0..z.len() {
            if let Ok(e) = z.by_index(i) {
                let n = e.name().map(|n| n.to_string()).unwrap_or_default();
                if (n.ends_with(".dex") || n.ends_with(".so") || n.starts_with("assets/")) && e.size() < (64 << 20) {
                    let mut d = vec![];
                    if e.take(64 << 20).read_to_end(&mut d).is_ok() { v.push((n, d)); }
                }
            }
        }
    }
    v
}

fn main() {
    let cli = Cli::parse();
    let t = std::time::Instant::now();
    let cmd = std::env::args().skip(1).filter(|a| !a.starts_with("--")).take(2).collect::<Vec<_>>().join(" ");
    let (ok, data, err) = match run(&cli) {
        Ok(v) => (true, v, None),
        Err(e) => (false, Value::Null, Some(format!("{e:#}"))),
    };
    let env = json!({"ok": ok, "command": cmd, "data": data, "error": err, "duration_ms": t.elapsed().as_millis() as u64, "engine_version": env!("CARGO_PKG_VERSION")});
    let s = if cli.pretty { serde_json::to_string_pretty(&env) } else { serde_json::to_string(&env) };
    println!("{}", s.unwrap_or_else(|_| "{\"ok\":false}".into()));
    std::process::exit(if ok { 0 } else { 1 });
}
