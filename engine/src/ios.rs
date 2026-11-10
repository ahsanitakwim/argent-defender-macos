//! iPhone support: device audit via libimobiledevice (lockdown pairing) and
//! local/encrypted backup forensics. Respects the iOS sandbox: only what Apple's
//! pairing and backup mechanisms expose is examined, and every gap is reported.

use crate::model::*;
use anyhow::{anyhow, bail, Context, Result};
use plist::Value;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ------------------------------------------------------------------ device (lockdown)

pub fn parse_kv(out: &str) -> BTreeMap<String, String> {
    out.lines()
        .filter_map(|l| l.split_once(": ").map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect()
}

#[derive(Debug, Serialize, Clone)]
pub struct IosDevice {
    pub udid: String,
    pub connection: String,
    pub name: Option<String>,
    pub product_type: Option<String>,
    pub ios_version: Option<String>,
    pub build: Option<String>,
    pub paired: Option<bool>,
}

pub fn list_devices() -> Result<Vec<IosDevice>> {
    let mut v = vec![];
    for (flag, conn) in [("-l", "usb"), ("-n", "wifi")] {
        if let Ok(out) = crate::tools::run("idevice_id", &[flag]) {
            for udid in out.lines().map(|l| l.split_whitespace().next().unwrap_or("").to_string()).filter(|s| !s.is_empty()) {
                if v.iter().any(|d: &IosDevice| d.udid == udid) {
                    continue;
                }
                v.push(device_info(&udid, conn).unwrap_or(IosDevice {
                    udid,
                    connection: conn.into(),
                    name: None,
                    product_type: None,
                    ios_version: None,
                    build: None,
                    paired: Some(false),
                }));
            }
        }
    }
    Ok(v)
}

pub fn device_info(udid: &str, conn: &str) -> Result<IosDevice> {
    let mut args = vec!["-u", udid];
    if conn == "wifi" {
        args.push("-n");
    }
    let kv = parse_kv(&crate::tools::run("ideviceinfo", &args)?);
    let paired = crate::tools::run("idevicepair", &["-u", udid, "validate"]).map(|s| s.contains("SUCCESS")).ok();
    Ok(IosDevice {
        udid: udid.into(),
        connection: conn.into(),
        name: kv.get("DeviceName").cloned(),
        product_type: kv.get("ProductType").cloned(),
        ios_version: kv.get("ProductVersion").cloned(),
        build: kv.get("BuildVersion").cloned(),
        paired,
    })
}

pub fn device_audit(udid: &str, min_ios_major: u32) -> Result<(BTreeMap<String, String>, Vec<Finding>)> {
    let kv = parse_kv(&crate::tools::run("ideviceinfo", &["-u", udid])?);
    let name = kv.get("DeviceName").cloned().unwrap_or_else(|| udid.to_string());
    let mut f = vec![];
    if let Some(v) = kv.get("ProductVersion") {
        f.extend(ios_version_findings(v, min_ios_major, &name));
    }
    if kv.get("PasswordProtected").map(|v| v == "false").unwrap_or(false) {
        f.push(Finding::new("shield", "AD-IOS-PASSCODE", "No passcode set on the device", Category::Configuration, Severity::High, Confidence::Confirmed, subject("device", &name))
            .evidence("lockdown PasswordProtected=false").recommend("Set a 6-digit or alphanumeric passcode (Settings › Face ID & Passcode)."));
    }
    f.push(limitation("ios", "AD-LIM-IOS-1",
        "Pairing exposes device metadata only; app data, processes and network traffic of other apps are sandboxed. Use Backup Forensics for deeper (still partial) analysis.",
        subject("device", &name)));
    // Keep only non-sensitive identifiers; do not surface IMEI/phone number.
    let keep = ["DeviceName", "DeviceClass", "ProductType", "ProductVersion", "BuildVersion", "HardwareModel", "PasswordProtected", "ActivationState", "TimeZone", "CPUArchitecture", "SerialNumber"];
    let info = kv.into_iter().filter(|(k, _)| keep.contains(&k.as_str())).collect();
    Ok((info, f))
}

fn ios_version_findings(v: &str, min_major: u32, name: &str) -> Vec<Finding> {
    let major: u32 = v.split('.').next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let sev = if major < min_major { Severity::High } else { Severity::Informational };
    let title = if major < min_major { "iOS version is older than the configured supported baseline" } else { "iOS version recorded" };
    vec![Finding::new("shield", "AD-IOS-VERSION", title, Category::Configuration, sev, Confidence::Confirmed, subject("device", name))
        .evidence(format!("ProductVersion={v}; baseline major={min_major} (configurable in Settings)"))
        .recommend("Check Settings › General › Software Update and install the latest iOS. Enable Lockdown Mode if you are at elevated risk of targeted spyware.")]
}

/// Create a local backup with Apple's backup protocol (idevicebackup2). Requires the
/// user to unlock/trust the device; encryption state follows the device setting.
pub fn create_backup(udid: &str, out_dir: &Path) -> Result<String> {
    std::fs::create_dir_all(out_dir)?;
    crate::tools::run("idevicebackup2", &["-u", udid, "backup", "--full", &out_dir.display().to_string()])
}

// ------------------------------------------------------------------ backup discovery

#[derive(Debug, Serialize, Clone)]
pub struct BackupSummary {
    pub path: String,
    pub udid: String,
    pub device_name: Option<String>,
    pub product_type: Option<String>,
    pub ios_version: Option<String>,
    pub last_backup: Option<String>,
    pub encrypted: Option<bool>,
}

pub fn default_backup_root() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    home.join("Library/Application Support/MobileSync/Backup")
}

pub fn discover(root: &Path) -> Vec<BackupSummary> {
    let mut v = vec![];
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let p = e.path();
            if p.join("Manifest.plist").is_file() {
                v.push(summarize(&p));
            }
        }
    }
    v
}

fn pstr(d: &plist::Dictionary, k: &str) -> Option<String> {
    d.get(k).and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Date(dt) => Some(chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::from(*dt)).to_rfc3339()),
        Value::Boolean(b) => Some(b.to_string()),
        Value::Integer(i) => Some(i.to_string()),
        _ => None,
    })
}

pub fn summarize(p: &Path) -> BackupSummary {
    let info = Value::from_file(p.join("Info.plist")).ok().and_then(|v| v.into_dictionary());
    let man = Value::from_file(p.join("Manifest.plist")).ok().and_then(|v| v.into_dictionary());
    let i = info.as_ref();
    BackupSummary {
        path: p.display().to_string(),
        udid: p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
        device_name: i.and_then(|d| pstr(d, "Device Name")),
        product_type: i.and_then(|d| pstr(d, "Product Type")),
        ios_version: i.and_then(|d| pstr(d, "Product Version")),
        last_backup: i.and_then(|d| pstr(d, "Last Backup Date")),
        encrypted: man.as_ref().and_then(|d| d.get("IsEncrypted")).and_then(|v| v.as_boolean()),
    }
}

// ------------------------------------------------------------------ encrypted backups

#[derive(Default, Debug)]
struct ClassKey {
    wrap: u32,
    wpky: Vec<u8>,
    key: Option<Vec<u8>>,
}

#[derive(Default, Debug)]
pub struct Keybag {
    salt: Vec<u8>,
    iter: u32,
    dpsl: Vec<u8>,
    dpic: u32,
    classes: BTreeMap<u32, ClassKey>,
}

const WRAP_PASSCODE: u32 = 2;

pub fn parse_keybag(b: &[u8]) -> Result<Keybag> {
    let mut kb = Keybag::default();
    let mut cur: Option<(u32, ClassKey)> = None;
    let mut p = 0;
    while p + 8 <= b.len() {
        let tag = std::str::from_utf8(&b[p..p + 4]).unwrap_or("????").to_string();
        let len = u32::from_be_bytes(b[p + 4..p + 8].try_into()?) as usize;
        let val = b.get(p + 8..p + 8 + len).ok_or_else(|| anyhow!("keybag truncated"))?;
        let int = || if len == 4 { u32::from_be_bytes(val.try_into().unwrap()) } else { 0 };
        match tag.as_str() {
            "UUID" if kb.salt.is_empty() && cur.is_none() && kb.iter == 0 => {}
            "UUID" => {
                if let Some((c, k)) = cur.take() {
                    kb.classes.insert(c, k);
                }
                cur = Some((0, ClassKey::default()));
            }
            "CLAS" => if let Some(c) = cur.as_mut() { c.0 = int(); },
            "WRAP" => if let Some(c) = cur.as_mut() { c.1.wrap = int(); },
            "WPKY" => if let Some(c) = cur.as_mut() { c.1.wpky = val.to_vec(); },
            "SALT" => kb.salt = val.to_vec(),
            "ITER" => kb.iter = int(),
            "DPSL" => kb.dpsl = val.to_vec(),
            "DPIC" => kb.dpic = int(),
            _ => {}
        }
        p += 8 + len;
    }
    if let Some((c, k)) = cur.take() {
        kb.classes.insert(c, k);
    }
    if kb.salt.is_empty() || kb.iter == 0 {
        bail!("keybag missing SALT/ITER");
    }
    Ok(kb)
}

fn aes_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    use aes_kw::KeyInit;
    if kek.len() != 32 || wrapped.len() < 24 {
        bail!("invalid key-wrap input");
    }
    let kw = aes_kw::KwAes256::new_from_slice(kek).map_err(|_| anyhow!("kek"))?;
    let mut out = vec![0u8; wrapped.len() - 8];
    kw.unwrap_key(wrapped, &mut out).map_err(|_| anyhow!("key unwrap failed (wrong password?)"))?;
    Ok(out)
}

pub fn derive_passcode_key(kb: &Keybag, password: &[u8]) -> Vec<u8> {
    let mut k1 = [0u8; 32];
    if !kb.dpsl.is_empty() && kb.dpic > 0 {
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, &kb.dpsl, kb.dpic, &mut k1);
    } else {
        k1.copy_from_slice(&sha2_32(password));
    }
    let mut k2 = [0u8; 32];
    let src: &[u8] = if !kb.dpsl.is_empty() && kb.dpic > 0 { &k1 } else { password };
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(src, &kb.salt, kb.iter, &mut k2);
    k2.to_vec()
}

fn sha2_32(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

impl Keybag {
    pub fn unlock(&mut self, password: &[u8]) -> Result<()> {
        let pk = derive_passcode_key(self, password);
        let mut ok = 0;
        for ck in self.classes.values_mut() {
            if ck.wrap & WRAP_PASSCODE != 0 && !ck.wpky.is_empty() {
                ck.key = Some(aes_unwrap(&pk, &ck.wpky).context("incorrect backup password")?);
                ok += 1;
            }
        }
        if ok == 0 {
            bail!("no passcode-wrapped class keys in keybag");
        }
        Ok(())
    }
    pub fn unwrap_for_class(&self, class: u32, wrapped: &[u8]) -> Result<Vec<u8>> {
        let ck = self.classes.get(&class).and_then(|c| c.key.as_ref()).ok_or_else(|| anyhow!("class key {class} unavailable"))?;
        aes_unwrap(ck, wrapped)
    }
}

pub fn aes_cbc_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{BlockModeDecrypt, KeyIvInit};
    let n = data.len() - data.len() % 16;
    let mut buf = data[..n].to_vec();
    let dec = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, &[0u8; 16]).map_err(|_| anyhow!("bad key length"))?;
    dec.decrypt_padded::<aes::cipher::block_padding::NoPadding>(&mut buf).map_err(|_| anyhow!("decrypt"))?;
    Ok(buf)
}

fn strip_pkcs7(mut v: Vec<u8>) -> Vec<u8> {
    if let Some(&pad) = v.last() {
        let p = pad as usize;
        if (1..=16).contains(&p) && v.len() >= p && v[v.len() - p..].iter().all(|&b| b == pad) {
            v.truncate(v.len() - p);
        }
    }
    v
}

/// File metadata from Manifest.db `file` column (NSKeyedArchiver MBFile).
#[derive(Debug, Default)]
pub struct MbFile {
    pub protection_class: Option<u32>,
    pub encryption_key: Option<Vec<u8>>,
    pub size: Option<u64>,
    pub last_modified: Option<i64>,
}

pub fn parse_mbfile(blob: &[u8]) -> Result<MbFile> {
    let v = Value::from_reader(std::io::Cursor::new(blob))?;
    let d = v.as_dictionary().ok_or_else(|| anyhow!("archive"))?;
    let objects = d.get("$objects").and_then(|o| o.as_array()).ok_or_else(|| anyhow!("$objects"))?;
    let root_uid = d.get("$top").and_then(|t| t.as_dictionary()).and_then(|t| t.get("root")).and_then(|r| r.as_uid()).ok_or_else(|| anyhow!("$top"))?;
    let resolve = |v: &Value| -> Value {
        match v {
            Value::Uid(u) => objects.get(u.get() as usize).cloned().unwrap_or(Value::String(String::new())),
            o => o.clone(),
        }
    };
    let root = objects.get(root_uid.get() as usize).and_then(|r| r.as_dictionary()).ok_or_else(|| anyhow!("root"))?;
    let mut f = MbFile::default();
    f.protection_class = root.get("ProtectionClass").and_then(|v| v.as_unsigned_integer()).map(|x| x as u32);
    f.size = root.get("Size").and_then(|v| v.as_unsigned_integer());
    f.last_modified = root.get("LastModified").and_then(|v| v.as_signed_integer());
    if let Some(ek) = root.get("EncryptionKey") {
        let ek = resolve(ek);
        f.encryption_key = match ek {
            Value::Data(d) => Some(d),
            Value::Dictionary(dd) => dd.get("NS.data").and_then(|x| x.as_data()).map(|x| x.to_vec()),
            _ => None,
        };
    }
    Ok(f)
}

// ------------------------------------------------------------------ backup access layer

pub struct Backup {
    pub root: PathBuf,
    pub encrypted: bool,
    keybag: Option<Keybag>,
    pub manifest_db: PathBuf,
    _tmp: Option<tempfile_like::TempDir>,
}

mod tempfile_like {
    /// Minimal secure temp dir (0700) removed on drop, used for decrypted working copies.
    pub struct TempDir(pub std::path::PathBuf);
    impl TempDir {
        pub fn new() -> std::io::Result<Self> {
            let mut r = [0u8; 8];
            let _ = getrandom::fill(&mut r);
            let p = std::env::temp_dir().join(format!("argent-{}", hex::encode(r)));
            std::fs::create_dir_all(&p)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))?;
            }
            Ok(TempDir(p))
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

impl Backup {
    pub fn open(root: &Path, password: Option<&[u8]>) -> Result<Backup> {
        let man = Value::from_file(root.join("Manifest.plist")).context("Manifest.plist not found — is this an iPhone backup folder?")?;
        let d = man.as_dictionary().ok_or_else(|| anyhow!("Manifest.plist"))?;
        let encrypted = d.get("IsEncrypted").and_then(|v| v.as_boolean()).unwrap_or(false);
        if !encrypted {
            return Ok(Backup { root: root.into(), encrypted, keybag: None, manifest_db: root.join("Manifest.db"), _tmp: None });
        }
        let pw = password.ok_or_else(|| anyhow!("backup is encrypted: password required"))?;
        let mut kb = parse_keybag(d.get("BackupKeyBag").and_then(|v| v.as_data()).ok_or_else(|| anyhow!("BackupKeyBag missing"))?)?;
        kb.unlock(pw)?;
        let mk = d.get("ManifestKey").and_then(|v| v.as_data()).ok_or_else(|| anyhow!("ManifestKey missing"))?;
        if mk.len() < 4 + 24 {
            bail!("ManifestKey malformed");
        }
        let class = u32::from_le_bytes(mk[..4].try_into()?);
        let key = kb.unwrap_for_class(class, &mk[4..])?;
        let enc = std::fs::read(root.join("Manifest.db"))?;
        let plain = strip_pkcs7(aes_cbc_decrypt(&key, &enc)?);
        if !plain.starts_with(b"SQLite format 3\0") {
            bail!("Manifest.db decryption produced invalid data (wrong password?)");
        }
        let tmp = tempfile_like::TempDir::new()?;
        let mdb = tmp.0.join("Manifest.db");
        std::fs::write(&mdb, plain)?;
        Ok(Backup { root: root.into(), encrypted, keybag: Some(kb), manifest_db: mdb, _tmp: Some(tmp) })
    }

    fn conn(&self) -> Result<rusqlite::Connection> {
        Ok(rusqlite::Connection::open_with_flags(&self.manifest_db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?)
    }

    /// Lists (fileID, domain, relativePath).
    pub fn files(&self, domain_like: &str, path_like: &str) -> Result<Vec<(String, String, String)>> {
        let c = self.conn()?;
        let mut st = c.prepare("SELECT fileID, domain, relativePath FROM Files WHERE flags=1 AND domain LIKE ?1 AND relativePath LIKE ?2")?;
        let r = st.query_map([domain_like, path_like], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(r)
    }

    pub fn domains(&self) -> Result<Vec<(String, i64)>> {
        let c = self.conn()?;
        let mut st = c.prepare("SELECT domain, count(*) FROM Files GROUP BY domain ORDER BY domain")?;
        let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(r)
    }

    /// Read (and if needed decrypt) one file into memory. Original backup is never modified.
    pub fn read(&self, file_id: &str) -> Result<Vec<u8>> {
        let p = self.root.join(&file_id[..2]).join(file_id);
        let data = std::fs::read(&p).with_context(|| format!("backup file {file_id} missing"))?;
        if !self.encrypted {
            return Ok(data);
        }
        let c = self.conn()?;
        let blob: Vec<u8> = c.query_row("SELECT file FROM Files WHERE fileID=?1", [file_id], |r| r.get(0))?;
        let mb = parse_mbfile(&blob)?;
        let ek = mb.encryption_key.ok_or_else(|| anyhow!("no EncryptionKey for {file_id}"))?;
        let class = mb.protection_class.unwrap_or_else(|| u32::from_le_bytes(ek[..4].try_into().unwrap()));
        let key = self.keybag.as_ref().unwrap().unwrap_for_class(class, &ek[4..])?;
        let mut plain = aes_cbc_decrypt(&key, &data)?;
        if let Some(sz) = mb.size {
            plain.truncate(sz as usize);
        } else {
            plain = strip_pkcs7(plain);
        }
        Ok(plain)
    }

    /// Materialise a file (e.g. an SQLite DB) to the secure temp area for read-only querying.
    pub fn extract_tmp(&self, file_id: &str, dir: &Path) -> Result<PathBuf> {
        let out = dir.join(file_id);
        std::fs::write(&out, self.read(file_id)?)?;
        Ok(out)
    }
}

// ------------------------------------------------------------------ analysis

pub const JAILBREAK_BUNDLES: &[(&str, &str)] = &[
    ("com.saurik.Cydia", "Cydia"),
    ("org.coolstar.sileo", "Sileo"),
    ("xyz.willy.Zebra", "Zebra"),
    ("me.apptapp.installer", "Installer"),
    ("science.xnu.undecimus", "unc0ver"),
    ("com.tigisoftware.Filza", "Filza"),
    ("com.opa334.TrollStore", "TrollStore"),
    ("com.electrateam.chimera", "Chimera"),
    ("org.coolstar.electra", "Electra"),
    ("com.checkra1n.loader", "checkra1n"),
    ("com.palera1n.loader", "palera1n"),
    ("com.serena.SerenaJailbreak", "Dopamine"),
];

#[derive(Debug, Serialize)]
pub struct IosBackupReport {
    pub summary: BackupSummary,
    pub encrypted: bool,
    pub passcode_set: Option<bool>,
    pub installed_apps: Vec<String>,
    pub domains: usize,
    pub files_indexed: i64,
    pub urls_examined: usize,
    pub processes_examined: usize,
    pub configuration_profiles: usize,
    pub timeline: Vec<crate::forensic::TimelineEvent>,
    pub findings: Vec<Finding>,
}

const APPLE_EPOCH: i64 = 978_307_200;

fn mac_time(t: f64) -> String {
    chrono::DateTime::from_timestamp((t as i64) + APPLE_EPOCH, 0).map(|d| d.to_rfc3339()).unwrap_or_default()
}

pub struct AnalyzeOptions {
    pub include_messages: bool,
    pub min_ios_major: u32,
}

pub fn analyze_backup(root: &Path, password: Option<&[u8]>, intel: &rusqlite::Connection, opt: &AnalyzeOptions) -> Result<IosBackupReport> {
    let summary = summarize(root);
    let bk = Backup::open(root, password)?;
    let man = Value::from_file(root.join("Manifest.plist"))?;
    let md = man.as_dictionary().unwrap();
    let dev = summary.device_name.clone().unwrap_or_else(|| summary.udid.clone());
    let mut f = vec![];
    let mut timeline = vec![];

    let passcode_set = md.get("WasPasscodeSet").and_then(|v| v.as_boolean());
    if passcode_set == Some(false) {
        f.push(Finding::new("shield", "AD-IOS-PASSCODE", "No device passcode was set when the backup was made", Category::Configuration, Severity::High, Confidence::Confirmed, subject("device", &dev))
            .evidence("Manifest.plist WasPasscodeSet=false").recommend("Set a strong passcode."));
    }
    if !bk.encrypted {
        f.push(Finding::new("shield", "AD-IOS-BKENC", "Backup is not encrypted", Category::Configuration, Severity::Medium, Confidence::Confirmed, subject("backup", &summary.udid))
            .evidence("Manifest.plist IsEncrypted=false")
            .recommend("Enable 'Encrypt local backup' in Finder. Unencrypted backups expose personal data on this Mac and omit some forensic artefacts."));
        f.push(limitation("ios", "AD-LIM-IOS-2", "Unencrypted backups exclude keychain, Health and some network/history data; analysis coverage is reduced", subject("backup", &summary.udid)));
    }
    if let Some(v) = &summary.ios_version {
        f.extend(ios_version_findings(v, opt.min_ios_major, &dev));
    }
    if let Some(d) = &summary.last_backup {
        timeline.push(crate::forensic::TimelineEvent { at: d.clone(), source: "Info.plist".into(), kind: "backup_created".into(), description: format!("Backup of {dev}") });
    }

    // Installed applications
    let mut apps: Vec<String> = md.get("Applications").and_then(|a| a.as_dictionary()).map(|a| a.keys().cloned().collect()).unwrap_or_default();
    if let Ok(info) = Value::from_file(root.join("Info.plist")) {
        if let Some(arr) = info.as_dictionary().and_then(|d| d.get("Installed Applications")).and_then(|v| v.as_array()) {
            for a in arr.iter().filter_map(|x| x.as_string()) {
                if !apps.iter().any(|x| x == a) {
                    apps.push(a.to_string());
                }
            }
        }
    }
    apps.sort();
    for (bid, name) in JAILBREAK_BUNDLES {
        if apps.iter().any(|a| a == bid) {
            f.push(Finding::new("ios-jailbreak", "AD-IOS-JB", format!("Jailbreak tool present: {name}"), Category::Jailbreak, Severity::High, Confidence::High, subject("app", *bid))
                .evidence(format!("Bundle id {bid} listed in backup application inventory"))
                .recommend("A jailbroken device has iOS protections disabled. Restore iOS via Finder if you did not jailbreak it yourself."));
        }
    }
    for a in &apps {
        for hit in crate::intel::lookup(intel, "package", a)? {
            f.push(hit.to_finding(subject("app", a)));
        }
        f.extend(crate::judol::check_package(intel, a, None)?);
    }

    let domains = bk.domains()?;
    let files_indexed: i64 = domains.iter().map(|d| d.1).sum();
    for (d, _) in &domains {
        if let Some(bid) = d.strip_prefix("AppDomain-") {
            if let Some((_, name)) = JAILBREAK_BUNDLES.iter().find(|(b, _)| *b == bid) {
                f.push(Finding::new("ios-jailbreak", "AD-IOS-JB-DOM", format!("Jailbreak tool data domain present: {name}"), Category::Jailbreak, Severity::High, Confidence::High, subject("app", bid))
                    .evidence(format!("Manifest.db domain {d}")).recommend("See jailbreak guidance."));
            }
        }
    }

    // Configuration profiles (MDM, root CAs, VPN, proxies can be delivered via profiles)
    let profiles = bk.files("%configurationprofiles%", "%ConfigurationProfiles/%.stub")?.len()
        + bk.files("SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles", "Library/ConfigurationProfiles/profile-%")?.len();
    if profiles > 0 {
        f.push(Finding::new("shield", "AD-IOS-PROFILE", format!("{profiles} configuration profile file(s) present"), Category::Configuration, Severity::Medium, Confidence::Low, subject("device", &dev))
            .evidence("Library/ConfigurationProfiles entries in backup")
            .recommend("Review Settings › General › VPN & Device Management. Remove profiles you do not recognise (they can install root certificates, VPNs or proxies)."));
    }
    let vpn = bk.files("SystemPreferencesDomain", "%com.apple.networkextension%")?;
    if !vpn.is_empty() {
        f.push(Finding::new("shield", "AD-IOS-VPN", "VPN / network-extension configuration present", Category::NetworkThreat, Severity::Informational, Confidence::High, subject("device", &dev))
            .evidence(format!("{} networkextension preference file(s)", vpn.len()))
            .recommend("Confirm every VPN in Settings › VPN is one you installed."));
    }

    let tmp = tempfile_like::TempDir::new()?;
    // Browser history → URL / phishing / judol / intel analysis
    let mut urls: Vec<(String, Option<String>)> = vec![];
    for (fid, _, _) in bk.files("HomeDomain", "Library/Safari/History.db")? {
        if let Ok(p) = bk.extract_tmp(&fid, &tmp.0) {
            if let Ok(c) = rusqlite::Connection::open_with_flags(&p, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) {
                let mut st = c.prepare("SELECT i.url, max(v.visit_time) FROM history_items i LEFT JOIN history_visits v ON v.history_item=i.id GROUP BY i.id")?;
                let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<f64>>(1)?)))?;
                for (u, t) in rows.flatten() {
                    urls.push((u, t.map(mac_time)));
                }
            }
        }
    }
    if opt.include_messages {
        for (fid, _, _) in bk.files("HomeDomain", "Library/SMS/sms.db")? {
            if let Ok(p) = bk.extract_tmp(&fid, &tmp.0) {
                if let Ok(c) = rusqlite::Connection::open_with_flags(&p, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) {
                    let mut st = c.prepare("SELECT text, date FROM message WHERE text LIKE '%http%' OR text LIKE '%www.%'")?;
                    let rows = st.query_map([], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<i64>>(1)?)))?;
                    for (t, d) in rows.flatten() {
                        // Only URLs are retained — message bodies are never stored or reported.
                        for u in crate::urlcheck::extract_urls(&t.unwrap_or_default()) {
                            let ts = d.map(|d| if d > 10_000_000_000 { d as f64 / 1e9 } else { d as f64 }).map(mac_time);
                            urls.push((u, ts));
                        }
                    }
                }
            }
        }
    } else {
        f.push(limitation("ios", "AD-LIM-IOS-3", "Links inside SMS/iMessage were not analysed (opt-in setting disabled)", subject("backup", &summary.udid)));
    }
    urls.sort();
    urls.dedup_by(|a, b| a.0 == b.0);
    for (u, t) in &urls {
        let mut hits = crate::urlcheck::check_url(u, intel)?;
        hits.retain(|h| h.severity >= Severity::Medium);
        if !hits.is_empty() {
            if let Some(t) = t {
                timeline.push(crate::forensic::TimelineEvent { at: t.clone(), source: "browser/messages".into(), kind: "suspicious_url".into(), description: u.clone() });
            }
        }
        f.extend(hits);
    }

    // DataUsage process names vs. process IOCs (STIX2/MVT-style spyware indicators)
    let mut procs = 0;
    for (fid, _, _) in bk.files("WirelessDomain", "Library/Databases/DataUsage.sqlite")? {
        if let Ok(p) = bk.extract_tmp(&fid, &tmp.0) {
            if let Ok(c) = rusqlite::Connection::open_with_flags(&p, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) {
                let mut st = c.prepare("SELECT ZPROCNAME, ZBUNDLENAME, ZFIRSTTIMESTAMP FROM ZPROCESS")?;
                let rows = st.query_map([], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<f64>>(2)?)))?;
                for (pn, bn, ts) in rows.flatten() {
                    procs += 1;
                    for name in [pn.clone(), bn.clone()].into_iter().flatten() {
                        let base = name.split('/').next().unwrap_or(&name).to_string();
                        for hit in crate::intel::lookup(intel, "process", &base)? {
                            let mut x = hit.to_finding(subject("process", &base));
                            if let Some(t) = ts {
                                x = x.evidence(format!("first seen {}", mac_time(t)));
                                timeline.push(crate::forensic::TimelineEvent { at: mac_time(t), source: "DataUsage.sqlite".into(), kind: "ioc_process".into(), description: base.clone() });
                            }
                            f.push(x);
                        }
                    }
                }
            }
        }
    }
    if procs == 0 {
        f.push(limitation("ios", "AD-LIM-IOS-4", "DataUsage process records not available in this backup (typically requires an encrypted backup)", subject("backup", &summary.udid)));
    }
    f.push(limitation("ios", "AD-LIM-IOS-5",
        "Absence of indicators in a backup does NOT prove the device is malware-free: backups exclude many system areas, memory and other apps' sandboxes",
        subject("backup", &summary.udid)));
    timeline.sort_by(|a, b| a.at.cmp(&b.at));
    Ok(IosBackupReport {
        summary,
        encrypted: bk.encrypted,
        passcode_set,
        installed_apps: apps,
        domains: domains.len(),
        files_indexed,
        urls_examined: urls.len(),
        processes_examined: procs,
        configuration_profiles: profiles,
        timeline,
        findings: f,
    })
}

#[cfg(test)]
pub mod testutil {
    //! Builds a synthetic *encrypted* backup with the exact iOS keybag format, so the
    //! decryption path is tested end-to-end without real personal data.
    use super::*;
    use aes::cipher::{BlockModeEncrypt, KeyIvInit};
    use aes_kw::KeyInit;

    fn tlv(tag: &str, v: &[u8]) -> Vec<u8> {
        let mut o = tag.as_bytes().to_vec();
        o.extend((v.len() as u32).to_be_bytes());
        o.extend(v);
        o
    }
    pub fn wrap(kek: &[u8], key: &[u8]) -> Vec<u8> {
        let kw = aes_kw::KwAes256::new_from_slice(kek).unwrap();
        let mut out = vec![0u8; key.len() + 8];
        kw.wrap_key(key, &mut out).unwrap();
        out
    }
    pub fn cbc_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut buf = data.to_vec();
        let pad = 16 - buf.len() % 16;
        buf.extend(std::iter::repeat(pad as u8).take(pad));
        let n = buf.len();
        cbc::Encryptor::<aes::Aes256>::new_from_slices(key, &[0u8; 16]).unwrap()
            .encrypt_padded::<aes::cipher::block_padding::NoPadding>(&mut buf, n).unwrap();
        buf
    }

    pub fn mbfile_blob(class: u32, wrapped: &[u8], size: u64) -> Vec<u8> {
        let mut ek = class.to_le_bytes().to_vec();
        ek.extend(wrapped);
        let mut root = plist::Dictionary::new();
        root.insert("ProtectionClass".into(), Value::Integer(class.into()));
        root.insert("Size".into(), Value::Integer(size.into()));
        root.insert("EncryptionKey".into(), Value::Uid(plist::Uid::new(2)));
        let mut ekd = plist::Dictionary::new();
        ekd.insert("NS.data".into(), Value::Data(ek));
        let mut top = plist::Dictionary::new();
        top.insert("root".into(), Value::Uid(plist::Uid::new(1)));
        let mut d = plist::Dictionary::new();
        d.insert("$objects".into(), Value::Array(vec![Value::String("$null".into()), Value::Dictionary(root), Value::Dictionary(ekd)]));
        d.insert("$top".into(), Value::Dictionary(top));
        d.insert("$archiver".into(), Value::String("NSKeyedArchiver".into()));
        let mut out = vec![];
        Value::Dictionary(d).to_writer_binary(&mut out).unwrap();
        out
    }

    /// Returns (backup dir) for a backup encrypted with `password`, containing a
    /// Safari history DB with one URL.
    pub fn make_backup(dir: &Path, password: &str, encrypted: bool, url: &str) {
        let salt = b"saltsaltsaltsaltsalt".to_vec();
        let dpsl = b"dpsl-salt-dpsl-salt-".to_vec();
        let (iter, dpic) = (10u32, 10u32);
        let class_key = [7u8; 32];
        // Build source DBs
        let tmp = dir.join("_src");
        std::fs::create_dir_all(&tmp).unwrap();
        let hist = tmp.join("History.db");
        let c = rusqlite::Connection::open(&hist).unwrap();
        c.execute_batch("CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT); CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL);").unwrap();
        c.execute("INSERT INTO history_items(id,url) VALUES (1,?1)", [url]).unwrap();
        c.execute("INSERT INTO history_visits(history_item,visit_time) VALUES (1, 800000000.0)", []).unwrap();
        drop(c);
        let hist_bytes = std::fs::read(&hist).unwrap();
        let file_id = "ab".to_string() + &"0".repeat(38);
        let file_key = [9u8; 32];
        let mdb = tmp.join("Manifest.db");
        let c = rusqlite::Connection::open(&mdb).unwrap();
        c.execute_batch("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB);").unwrap();
        let blob = mbfile_blob(3, &wrap(&class_key, &file_key), hist_bytes.len() as u64);
        c.execute("INSERT INTO Files VALUES (?1,'HomeDomain','Library/Safari/History.db',1,?2)", rusqlite::params![file_id, blob]).unwrap();
        drop(c);
        let mdb_bytes = std::fs::read(&mdb).unwrap();
        std::fs::create_dir_all(dir.join("ab")).unwrap();

        let mut man = plist::Dictionary::new();
        man.insert("IsEncrypted".into(), Value::Boolean(encrypted));
        man.insert("WasPasscodeSet".into(), Value::Boolean(true));
        let mut apps = plist::Dictionary::new();
        apps.insert("com.saurik.Cydia".into(), Value::Dictionary(Default::default()));
        man.insert("Applications".into(), Value::Dictionary(apps));
        if encrypted {
            let kb_tmp = Keybag { salt: salt.clone(), iter, dpsl: dpsl.clone(), dpic, classes: Default::default() };
            let pk = derive_passcode_key(&kb_tmp, password.as_bytes());
            let mut kb = vec![];
            kb.extend(tlv("VERS", &4u32.to_be_bytes()));
            kb.extend(tlv("TYPE", &1u32.to_be_bytes()));
            kb.extend(tlv("UUID", &[1u8; 16]));
            kb.extend(tlv("WRAP", &0u32.to_be_bytes()));
            kb.extend(tlv("SALT", &salt));
            kb.extend(tlv("ITER", &iter.to_be_bytes()));
            kb.extend(tlv("DPWT", &1u32.to_be_bytes()));
            kb.extend(tlv("DPIC", &dpic.to_be_bytes()));
            kb.extend(tlv("DPSL", &dpsl));
            kb.extend(tlv("UUID", &[2u8; 16]));
            kb.extend(tlv("CLAS", &3u32.to_be_bytes()));
            kb.extend(tlv("WRAP", &3u32.to_be_bytes()));
            kb.extend(tlv("KTYP", &0u32.to_be_bytes()));
            kb.extend(tlv("WPKY", &wrap(&pk, &class_key)));
            man.insert("BackupKeyBag".into(), Value::Data(kb));
            let manifest_key = [5u8; 32];
            let mut mk = 3u32.to_le_bytes().to_vec();
            mk.extend(wrap(&class_key, &manifest_key));
            man.insert("ManifestKey".into(), Value::Data(mk));
            std::fs::write(dir.join("Manifest.db"), cbc_encrypt(&manifest_key, &mdb_bytes)).unwrap();
            std::fs::write(dir.join("ab").join(&file_id), cbc_encrypt(&file_key, &hist_bytes)).unwrap();
        } else {
            std::fs::write(dir.join("Manifest.db"), &mdb_bytes).unwrap();
            std::fs::write(dir.join("ab").join(&file_id), &hist_bytes).unwrap();
        }
        Value::Dictionary(man).to_file_xml(dir.join("Manifest.plist")).unwrap();
        let mut info = plist::Dictionary::new();
        info.insert("Device Name".into(), Value::String("Test iPhone".into()));
        info.insert("Product Version".into(), Value::String("17.5".into()));
        Value::Dictionary(info).to_file_xml(dir.join("Info.plist")).unwrap();
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn kv_parse() {
        let kv = parse_kv("DeviceName: Budi's iPhone\nProductVersion: 17.5.1\n");
        assert_eq!(kv["DeviceName"], "Budi's iPhone");
    }

    #[test]
    fn encrypted_backup_roundtrip_and_wrong_password() {
        let d = tempfile::tempdir().unwrap();
        make_backup(d.path(), "correct horse", true, "https://example.org/");
        assert!(Backup::open(d.path(), Some(b"wrong")).is_err());
        let b = Backup::open(d.path(), Some(b"correct horse")).unwrap();
        let files = b.files("HomeDomain", "Library/Safari/History.db").unwrap();
        assert_eq!(files.len(), 1);
        let data = b.read(&files[0].0).unwrap();
        assert!(data.starts_with(b"SQLite format 3\0"));
    }

    #[test]
    fn backup_analysis_flags_jailbreak_and_url() {
        let d = tempfile::tempdir().unwrap();
        make_backup(d.path(), "pw", true, "http://bca.co.id.secure-verify-login.xyz/akun");
        let db = crate::db::open_memory().unwrap();
        let r = analyze_backup(d.path(), Some(b"pw"), &db, &AnalyzeOptions { include_messages: false, min_ios_major: 17 }).unwrap();
        assert!(r.encrypted);
        assert_eq!(r.urls_examined, 1);
        assert!(r.findings.iter().any(|f| f.rule == "AD-IOS-JB"));
        assert!(r.findings.iter().any(|f| f.category == Category::Phishing), "{:#?}", r.findings);
        assert!(r.findings.iter().any(|f| f.rule == "AD-LIM-IOS-5"));
    }

    #[test]
    fn unencrypted_backup_flags_missing_encryption() {
        let d = tempfile::tempdir().unwrap();
        make_backup(d.path(), "", false, "https://example.org/");
        let db = crate::db::open_memory().unwrap();
        let r = analyze_backup(d.path(), None, &db, &AnalyzeOptions { include_messages: false, min_ios_major: 17 }).unwrap();
        assert!(r.findings.iter().any(|f| f.rule == "AD-IOS-BKENC"));
    }
}
