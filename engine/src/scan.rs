//! ARGENT SCAN — unified, parallel file scanning engine (Quick / Full / Deep /
//! Custom / Incremental) combining YARA-X, hash intelligence, APK/IPA analysis,
//! Gaming Watch, optional ClamAV, with measured benchmarks.

use crate::model::*;
use anyhow::{bail, Context, Result};
use rayon::prelude::*;
use rusqlite::{params, Connection};
use serde::Serialize;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

// ------------------------------------------------------------------ YARA-X adapter

pub struct RuleSet {
    pub rules: yara_x::Rules,
    pub files: Vec<String>,
    pub count: usize,
}

pub const BUNDLED_RULES: &[(&str, &str)] = &[
    ("00_test_eicar.yar", include_str!("../rules/00_test_eicar.yar")),
    ("10_android_behaviour.yar", include_str!("../rules/10_android_behaviour.yar")),
    ("20_judol.yar", include_str!("../rules/20_judol.yar")),
];

/// Compile bundled rules plus every *.yar / *.yara in `extra_dir` (admin-managed).
/// A broken user rule file is skipped and reported, never fatal.
pub fn compile_rules(extra_dir: Option<&Path>) -> Result<(RuleSet, Vec<String>)> {
    let mut comp = yara_x::Compiler::new();
    let mut files = vec![];
    let mut errors = vec![];
    for (name, src) in BUNDLED_RULES {
        comp.new_namespace(name.trim_end_matches(".yar"));
        comp.add_source(*src).map_err(|e| anyhow::anyhow!("bundled rule {name}: {e}"))?;
        files.push(format!("bundled:{name}"));
    }
    if let Some(d) = extra_dir {
        if d.is_dir() {
            let mut paths: Vec<_> = walkdir::WalkDir::new(d).into_iter().flatten().filter(|e| {
                let p = e.path().extension().and_then(|x| x.to_str()).unwrap_or("");
                p == "yar" || p == "yara"
            }).map(|e| e.into_path()).collect();
            paths.sort();
            for p in paths {
                let src = std::fs::read_to_string(&p)?;
                // validate in isolation first so one bad file doesn't poison the compiler
                let mut probe = yara_x::Compiler::new();
                if let Err(e) = probe.add_source(src.as_str()) {
                    errors.push(format!("{}: {e}", p.display()));
                    continue;
                }
                comp.new_namespace(&format!("user_{}", p.file_stem().unwrap().to_string_lossy()));
                if let Err(e) = comp.add_source(src.as_str()) {
                    errors.push(format!("{}: {e}", p.display()));
                    continue;
                }
                files.push(p.display().to_string());
            }
        }
    }
    let rules = comp.build();
    let count = rules.iter().count();
    Ok((RuleSet { rules, files, count }, errors))
}

fn parse_sev(s: &str) -> Severity {
    match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical, "HIGH" => Severity::High, "MEDIUM" => Severity::Medium, "LOW" => Severity::Low, _ => Severity::Informational,
    }
}
fn parse_conf(s: &str) -> Confidence {
    match s.to_ascii_uppercase().as_str() { "CONFIRMED" => Confidence::Confirmed, "HIGH" => Confidence::High, "MEDIUM" => Confidence::Medium, _ => Confidence::Low }
}
fn parse_cat(s: &str) -> Category {
    serde_json::from_value(serde_json::Value::String(s.to_ascii_lowercase())).unwrap_or(Category::Malware)
}

pub fn yara_scan(scanner: &mut yara_x::Scanner, data: &[u8], subj: &Subject, inner: Option<&str>) -> Vec<Finding> {
    let mut out = vec![];
    let Ok(res) = scanner.scan(data) else { return out };
    for r in res.matching_rules() {
        let mut meta: HashMap<String, String> = HashMap::new();
        for (k, v) in r.metadata() {
            if let yara_x::MetaValue::String(s) = v { meta.insert(k.to_string(), s.to_string()); }
        }
        let g = |k: &str| meta.get(k).cloned().unwrap_or_default();
        let mut f = Finding::new("yara-x", &format!("{}:{}", r.namespace(), r.identifier()), if g("description").is_empty() { r.identifier().to_string() } else { g("description") },
            parse_cat(&g("category")), parse_sev(&g("severity")), parse_conf(&g("confidence")), subj.clone())
            .recommend(g("recommendation"));
        if let Some(i) = inner { f = f.evidence(format!("matched inside archive entry {i}")); }
        let pats: Vec<String> = r.patterns().filter(|p| p.matches().len() > 0).map(|p| format!("{} ×{}", p.identifier(), p.matches().len())).collect();
        if !pats.is_empty() { f = f.evidence(format!("patterns: {}", pats.join(", "))); }
        out.push(f);
    }
    out
}

// ------------------------------------------------------------------ scanning

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode { Quick, Full, Deep, Custom, Incremental }

impl std::str::FromStr for Mode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s { "quick" => Mode::Quick, "full" => Mode::Full, "deep" => Mode::Deep, "custom" => Mode::Custom, "incremental" => Mode::Incremental, _ => bail!("mode must be quick|full|deep|custom|incremental") })
    }
}

const QUICK_EXT: &[&str] = &["apk", "xapk", "apks", "ipa", "dex", "so", "dylib", "jar", "zip", "js", "html", "htm", "sh", "py", "mobileconfig", "plist", "exe", "dll", "elf", "bin", "pdf", "doc", "docx", "xls", "xlsx", "lnk", "com"];

#[derive(Serialize, Default, Clone)]
pub struct Bench {
    pub mode: String,
    pub threads: usize,
    pub files_discovered: usize,
    pub files_scanned: usize,
    pub files_skipped_cached: usize,
    pub files_skipped_size: usize,
    pub archive_entries_scanned: usize,
    pub applications_inspected: usize,
    pub bytes_scanned: u64,
    pub duration_ms: u128,
    pub throughput_mib_s: f64,
    pub rule_compile_ms: u128,
    pub rules_loaded: usize,
    pub cpu_user_ms: u64,
    pub cpu_system_ms: u64,
    pub cpu_utilization_pct: f64,
    pub peak_rss_mib: f64,
}

#[derive(Serialize)]
pub struct ScanResult {
    pub target: String,
    pub findings: Vec<Finding>,
    pub apps: Vec<crate::permissions::AppProfile>,
    pub rule_errors: Vec<String>,
    pub clamav: Option<String>,
    pub bench: Bench,
}

pub struct ScanOptions {
    pub mode: Mode,
    pub rules_dir: Option<PathBuf>,
    pub extensions: Vec<String>,
    pub max_size: u64,
    pub clamav: bool,
    pub threads: usize,
}

struct FileOut {
    path: String,
    size: u64,
    mtime: i64,
    hashes: Option<crate::hashing::Hashes>,
    findings: Vec<Finding>,
    app: Option<crate::permissions::AppProfile>,
    archive_entries: usize,
    cached: bool,
    ipa_bundle: Option<String>,
}

fn mtime(m: &std::fs::Metadata) -> i64 {
    m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn scan_archive(scanner: &mut yara_x::Scanner, data: &[u8], subj: &Subject, depth: usize, cap: u64) -> (Vec<Finding>, usize) {
    let mut f = vec![];
    let mut n = 0;
    let Ok(mut z) = zip::ZipArchive::new(std::io::Cursor::new(data)) else { return (f, 0) };
    for i in 0..z.len().min(20_000) {
        let Ok(e) = z.by_index(i) else { continue };
        if e.is_dir() || e.size() > cap { continue; }
        let name = e.name().map(|n| n.to_string()).unwrap_or_default();
        let lname = name.to_ascii_lowercase();
        let interesting = lname.ends_with(".dex") || lname.ends_with(".so") || lname.ends_with(".js") || lname.ends_with(".html") || lname.ends_with(".jar")
            || lname.ends_with(".zip") || lname.ends_with(".apk") || lname.ends_with(".dylib") || lname.starts_with("assets/") || lname.ends_with("resources.arsc")
            || (lname.starts_with("payload/") && !lname.ends_with(".png") && !lname.ends_with(".car") && !lname.ends_with(".nib"));
        if !interesting { continue; }
        let mut buf = Vec::with_capacity(e.size() as usize);
        if e.take(cap).read_to_end(&mut buf).is_err() { continue; }
        n += 1;
        f.extend(yara_scan(scanner, &buf, subj, Some(&name)));
        if depth > 0 && (lname.ends_with(".zip") || lname.ends_with(".apk") || lname.ends_with(".jar")) {
            let (ff, nn) = scan_archive(scanner, &buf, subj, depth - 1, cap);
            f.extend(ff);
            n += nn;
        }
    }
    (f, n)
}

fn ipa_bundle_id(data: &[u8]) -> Option<String> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(data)).ok()?;
    let name = (0..z.len()).filter_map(|i| z.by_index_raw(i).ok().map(|e| e.name().map(|n| n.to_string()).unwrap_or_default()))
        .find(|n| n.starts_with("Payload/") && n.ends_with(".app/Info.plist") && n.matches('/').count() == 2)?;
    let mut buf = vec![];
    z.by_name(&name).ok()?.read_to_end(&mut buf).ok()?;
    plist::Value::from_reader(std::io::Cursor::new(buf)).ok()?.as_dictionary()?.get("CFBundleIdentifier")?.as_string().map(String::from)
}

#[cfg(unix)]
fn rusage() -> (u64, u64, f64) {
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) };
    let ms = |t: libc::timeval| (t.tv_sec as u64) * 1000 + (t.tv_usec as u64) / 1000;
    let rss = if cfg!(target_os = "macos") { u.ru_maxrss as f64 / 1048576.0 } else { u.ru_maxrss as f64 / 1024.0 };
    (ms(u.ru_utime), ms(u.ru_stime), rss)
}
#[cfg(not(unix))]
fn rusage() -> (u64, u64, f64) { (0, 0, 0.0) }

pub fn scan_path(db: &Connection, target: &Path, opt: &ScanOptions) -> Result<ScanResult> {
    let t0 = Instant::now();
    let (u0, s0, _) = rusage();
    let tc = Instant::now();
    let (rs, rule_errors) = compile_rules(opt.rules_dir.as_deref())?;
    let rule_compile_ms = tc.elapsed().as_millis();
    let threads = if opt.threads == 0 { std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2) } else { opt.threads };
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build()?;

    // discover
    let meta = std::fs::metadata(target).with_context(|| format!("cannot access {}", target.display()))?;
    let mut files: Vec<(PathBuf, u64, i64)> = vec![];
    if meta.is_file() {
        files.push((target.to_path_buf(), meta.len(), mtime(&meta)));
    } else {
        for e in walkdir::WalkDir::new(target).follow_links(false).into_iter().flatten() {
            if !e.file_type().is_file() { continue; }
            if let Ok(m) = e.metadata() { files.push((e.into_path(), m.len(), mtime(&m))); }
        }
    }
    let discovered = files.len();
    let ext_ok = |p: &Path| -> bool {
        let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("").to_ascii_lowercase();
        match opt.mode {
            Mode::Quick => QUICK_EXT.contains(&ext.as_str()) || ext.is_empty(),
            Mode::Custom if !opt.extensions.is_empty() => opt.extensions.iter().any(|e| e.eq_ignore_ascii_case(&ext)),
            _ => true,
        }
    };
    let max_size = if opt.max_size > 0 { opt.max_size } else { match opt.mode { Mode::Quick => 64 << 20, Mode::Deep => 2 << 30, _ => 512 << 20 } };
    let mut skipped_size = 0;
    files.retain(|(p, sz, _)| {
        if *sz > max_size { skipped_size += 1; return false; }
        ext_ok(p) || meta.is_file()
    });

    // incremental cache
    let mut cache: HashMap<String, (u64, i64, String, String, String)> = HashMap::new();
    if opt.mode == Mode::Incremental {
        let mut st = db.prepare("SELECT path,size,mtime,sha256,sha1,md5 FROM file_cache")?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?)))? {
            let (p, a, b, c, d, e) = r?;
            cache.insert(p, (a, b, c, d, e));
        }
    }
    let depth = if opt.mode == Mode::Deep { 2 } else { 1 };
    let inner_cap: u64 = if opt.mode == Mode::Deep { 256 << 20 } else { 64 << 20 };

    let outs: Vec<FileOut> = pool.install(|| {
        files.par_iter().map_init(|| yara_x::Scanner::new(&rs.rules), |scanner, (p, size, mt)| {
            let ps = p.display().to_string();
            if let Some((cs, cm, _, _, _)) = cache.get(&ps) {
                if cs == size && cm == mt {
                    return FileOut { path: ps, size: *size, mtime: *mt, hashes: None, findings: vec![], app: None, archive_entries: 0, cached: true, ipa_bundle: None };
                }
            }
            scanner.set_timeout(std::time::Duration::from_secs(60));
            let mut out = FileOut { path: ps.clone(), size: *size, mtime: *mt, hashes: None, findings: vec![], app: None, archive_entries: 0, cached: false, ipa_bundle: None };
            let Ok(data) = std::fs::read(p) else {
                out.findings.push(limitation("scan", "AD-LIM-READ", "File could not be read (permission denied or locked)", Subject { kind: "file".into(), name: ps.clone(), path: Some(ps), sha256: None }));
                return out;
            };
            let h = crate::hashing::hash_reader(&data[..]).ok();
            let subj = Subject { kind: "file".into(), name: p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(), path: Some(ps.clone()), sha256: h.as_ref().map(|h| h.sha256.clone()) };
            out.findings.extend(yara_scan(scanner, &data, &subj, None));
            let is_zip = data.starts_with(b"PK\x03\x04");
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("").to_ascii_lowercase();
            if is_zip {
                let (f, n) = scan_archive(scanner, &data, &subj, depth, inner_cap);
                out.findings.extend(f);
                out.archive_entries = n;
                if ext == "apk" || (opt.mode == Mode::Deep && zip_has(&data, "AndroidManifest.xml")) {
                    match crate::apk::analyze_apk_bytes(&data, &ps) {
                        Ok(r) => {
                            let mut prof = crate::permissions::profile_from_apk(&r);
                            prof.label = prof.label.or(Some(subj.name.clone()));
                            out.findings.extend(crate::permissions::audit(&prof).into_iter().map(|mut f| { f.subject.path = Some(ps.clone()); f }));
                            out.app = Some(prof);
                        }
                        Err(e) => out.findings.push(Finding::new("apk", "AD-APK-PARSE", "APK could not be parsed (malformed or anti-analysis manifest)", Category::Integrity, Severity::Low, Confidence::Medium, subj.clone()).evidence(e.to_string())),
                    }
                }
                if ext == "ipa" {
                    out.ipa_bundle = ipa_bundle_id(&data);
                }
            }
            out.hashes = h;
            out
        }).collect()
    });

    // correlation (single-threaded, DB access)
    let mut findings = vec![];
    let mut apps = vec![];
    let mut bench = Bench { mode: format!("{:?}", opt.mode).to_lowercase(), threads, files_discovered: discovered, files_skipped_size: skipped_size, rule_compile_ms, rules_loaded: rs.count, ..Default::default() };
    let tx = db.unchecked_transaction()?;
    for o in outs {
        if o.cached { bench.files_skipped_cached += 1; continue; }
        bench.files_scanned += 1;
        bench.bytes_scanned += o.size;
        bench.archive_entries_scanned += o.archive_entries;
        let mut f = o.findings;
        if let Some(h) = &o.hashes {
            let subj = Subject { kind: "file".into(), name: Path::new(&o.path).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(), path: Some(o.path.clone()), sha256: Some(h.sha256.clone()) };
            for (t, v) in [("sha256", &h.sha256), ("sha1", &h.sha1), ("md5", &h.md5)] {
                for hit in crate::intel::lookup(db, t, v)? { f.push(hit.to_finding(subj.clone())); }
            }
            f.extend(crate::judol::check_hash(db, &h.sha256, subj.clone())?);
            if let Some(b) = &o.ipa_bundle {
                for hit in crate::intel::lookup(db, "package", b)? { f.push(hit.to_finding(subject("app", b))); }
                f.extend(crate::judol::check_package(db, b, None)?);
                bench.applications_inspected += 1;
            }
            tx.execute("INSERT INTO file_cache(path,size,mtime,sha256,sha1,md5,last_result) VALUES (?1,?2,?3,?4,?5,?6,?7)
                        ON CONFLICT(path) DO UPDATE SET size=excluded.size,mtime=excluded.mtime,sha256=excluded.sha256,sha1=excluded.sha1,md5=excluded.md5,last_result=excluded.last_result",
                params![o.path, o.size as i64, o.mtime, h.sha256, h.sha1, h.md5, f.len() as i64])?;
        }
        if let Some(a) = o.app {
            bench.applications_inspected += 1;
            for hit in crate::intel::lookup(db, "package", &a.package)? { f.push(hit.to_finding(subject("package", &a.package))); }
            f.extend(crate::judol::check_package(db, &a.package, a.label.as_deref())?);
            apps.push(a);
        }
        findings.extend(f);
    }
    tx.commit()?;

    let clamav = if opt.clamav { Some(run_clamav(target, &mut findings)) } else { None };
    let el = t0.elapsed();
    let (u1, s1, rss) = rusage();
    bench.duration_ms = el.as_millis();
    bench.throughput_mib_s = if el.as_secs_f64() > 0.0 { bench.bytes_scanned as f64 / 1048576.0 / el.as_secs_f64() } else { 0.0 };
    bench.cpu_user_ms = u1 - u0;
    bench.cpu_system_ms = s1 - s0;
    bench.cpu_utilization_pct = if el.as_millis() > 0 { ((u1 - u0 + s1 - s0) as f64 / el.as_millis() as f64) * 100.0 } else { 0.0 };
    bench.peak_rss_mib = rss;
    dedup(&mut findings);
    Ok(ScanResult { target: target.display().to_string(), findings, apps, rule_errors, clamav, bench })
}

fn zip_has(data: &[u8], name: &str) -> bool {
    zip::ZipArchive::new(std::io::Cursor::new(data)).map(|mut z| z.by_name(name).is_ok()).unwrap_or(false)
}

pub fn dedup(f: &mut Vec<Finding>) {
    let mut seen = std::collections::HashSet::new();
    f.retain(|x| seen.insert((x.id.clone(), x.evidence.join("|"))));
    f.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.confidence.cmp(&a.confidence)));
}

/// ClamAV secondary engine adapter (only when installed and enabled by the user).
pub fn run_clamav(target: &Path, findings: &mut Vec<Finding>) -> String {
    let Some(bin) = crate::tools::which("clamscan") else { return "not_installed".into() };
    let out = match std::process::Command::new(bin).args(["-r", "--infected", "--no-summary"]).arg(target).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(e) => return format!("error: {e}"),
    };
    let mut n = 0;
    for l in out.lines() {
        if let Some((path, rest)) = l.rsplit_once(": ") {
            if let Some(sig) = rest.strip_suffix(" FOUND") {
                n += 1;
                let subj = Subject { kind: "file".into(), name: Path::new(path).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(), path: Some(path.to_string()), sha256: None };
                findings.push(Finding::new("clamav", sig, format!("ClamAV signature: {sig}"), Category::Malware, Severity::High, Confidence::High, subj)
                    .evidence(l.to_string()).recommend("Quarantine the file and verify with a second engine."));
            }
        }
    }
    format!("ok ({n} detections)")
}

#[cfg(test)]
mod tests {
    use super::*;
    const EICAR: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    fn opts(mode: Mode) -> ScanOptions {
        ScanOptions { mode, rules_dir: None, extensions: vec![], max_size: 0, clamav: false, threads: 2 }
    }

    #[test]
    fn bundled_rules_compile() {
        let (rs, errs) = compile_rules(None).unwrap();
        assert!(errs.is_empty());
        assert!(rs.count >= 9, "{}", rs.count);
    }

    #[test]
    fn eicar_detected_and_clean_file_clean() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("eicar.com"), EICAR).unwrap();
        std::fs::write(d.path().join("readme.txt"), "hello world, nothing to see").unwrap();
        let db = crate::db::open_memory().unwrap();
        let r = scan_path(&db, d.path(), &opts(Mode::Full)).unwrap();
        assert_eq!(r.bench.files_scanned, 2);
        let hits: Vec<_> = r.findings.iter().filter(|f| f.engine == "yara-x").collect();
        assert_eq!(hits.len(), 1, "{:?}", r.findings);
        assert!(hits[0].rule.ends_with("AD_TEST_EICAR"));
        assert_eq!(hits[0].subject.name, "eicar.com");
    }

    #[test]
    fn eicar_inside_apk_and_intel_hash_and_incremental() {
        use crate::apk::testutil::*;
        let d = tempfile::tempdir().unwrap();
        let m = sample_manifest("com.test.stealer", &["android.permission.RECEIVE_SMS", "android.permission.READ_SMS", "android.permission.INTERNET"], false, true);
        let dex = b"dex\n035\0....android.provider.Telephony.SMS_RECEIVED....createFromPdu....https://api.telegram.org/bot123:abc/sendMessage?chat_id=1".to_vec();
        let apk = make_apk(&m, &[("classes.dex", &dex), ("assets/t.txt", EICAR.as_bytes())]);
        std::fs::write(d.path().join("undangan.apk"), &apk).unwrap();
        let mut db = crate::db::open_memory().unwrap();
        let sha = crate::hashing::sha256_hex(&apk);
        crate::intel::import(&mut db, "list", &format!("{sha},malware"), "unit-test", None, None, 90).unwrap();
        let r = scan_path(&db, d.path(), &opts(Mode::Incremental)).unwrap();
        let rules: Vec<_> = r.findings.iter().map(|f| f.rule.as_str()).collect();
        assert!(rules.iter().any(|r| r.ends_with("AD_AND_SMS_Telegram_Exfil")), "{rules:?}");
        assert!(rules.iter().any(|r| r.ends_with("AD_TEST_EICAR")), "{rules:?}");
        assert!(rules.iter().any(|r| r.starts_with("IOC:unit-test")), "{rules:?}");
        assert!(rules.contains(&"AD-PERM-020"), "{rules:?}");
        assert_eq!(r.apps.len(), 1);
        let r2 = scan_path(&db, d.path(), &opts(Mode::Incremental)).unwrap();
        assert_eq!(r2.bench.files_skipped_cached, 1);
        assert_eq!(r2.bench.files_scanned, 0);
    }

    #[test]
    fn bad_user_rule_is_reported_not_fatal() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("bad.yar"), "rule broken { condition: nope }").unwrap();
        std::fs::write(d.path().join("good.yar"), "rule user_ok { strings: $a = \"ARGENT\" condition: $a }").unwrap();
        let (rs, errs) = compile_rules(Some(d.path())).unwrap();
        assert_eq!(errs.len(), 1);
        assert!(rs.files.iter().any(|f| f.ends_with("good.yar")));
    }
}
