//! Android device inspection over ADB (USB or authorised wireless debugging).
//! Standard mode is non-root and read-only. No security protection is bypassed;
//! anything not reachable without root is reported as NOT_ACCESSIBLE.

use crate::model::*;
use crate::permissions::AppProfile;
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AdbDevice {
    pub serial: String,
    pub state: String,
    pub model: Option<String>,
    pub product: Option<String>,
    pub transport: String,
}

pub fn parse_adb_devices(out: &str) -> Vec<AdbDevice> {
    out.lines()
        .skip_while(|l| !l.starts_with("List of devices"))
        .skip(1)
        .filter(|l| !l.trim().is_empty() && !l.starts_with('*'))
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let serial = it.next()?.to_string();
            let state = it.next()?.to_string();
            let kv: BTreeMap<_, _> = it.filter_map(|t| t.split_once(':')).collect();
            let transport = if serial.contains(':') || serial.contains("._adb-tls-") { "wifi" } else { "usb" }.to_string();
            Some(AdbDevice {
                serial,
                state,
                model: kv.get("model").map(|s| s.replace('_', " ")),
                product: kv.get("product").map(|s| s.to_string()),
                transport,
            })
        })
        .collect()
}

pub fn parse_getprop(out: &str) -> BTreeMap<String, String> {
    out.lines()
        .filter_map(|l| {
            let l = l.trim();
            let (k, v) = l.strip_prefix('[')?.split_once("]: [")?;
            Some((k.to_string(), v.trim_end_matches(']').to_string()))
        })
        .collect()
}

/// Parses `pm list packages -f -i -U` lines:
/// package:/data/app/~~x/com.foo-1/base.apk=com.foo  installer=com.android.vending uid:10123
#[derive(Debug, Clone, Serialize)]
pub struct PmPackage {
    pub package: String,
    pub apk_path: Option<String>,
    pub installer: Option<String>,
    pub uid: Option<u32>,
}

pub fn parse_pm_list(out: &str) -> Vec<PmPackage> {
    out.lines()
        .filter_map(|l| {
            let l = l.trim().strip_prefix("package:")?;
            let mut parts = l.split_whitespace();
            let first = parts.next()?;
            let (apk_path, package) = match first.rsplit_once('=') {
                Some((p, n)) if p.starts_with('/') => (Some(p.to_string()), n.to_string()),
                _ => (None, first.to_string()),
            };
            let mut installer = None;
            let mut uid = None;
            for t in parts {
                if let Some(v) = t.strip_prefix("installer=") {
                    installer = (v != "null").then(|| v.to_string());
                } else if let Some(v) = t.strip_prefix("uid:") {
                    uid = v.parse().ok();
                }
            }
            Some(PmPackage { package, apk_path, installer, uid })
        })
        .collect()
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct DumpsysPkg {
    pub version_name: Option<String>,
    pub target_sdk: Option<i64>,
    pub first_install: Option<String>,
    pub last_update: Option<String>,
    pub installer: Option<String>,
    pub system: bool,
    pub requested: BTreeSet<String>,
    pub granted: BTreeSet<String>,
}

/// Parses the relevant parts of `dumpsys package <pkg>`.
pub fn parse_dumpsys_package(out: &str) -> DumpsysPkg {
    let mut d = DumpsysPkg::default();
    #[derive(PartialEq)]
    enum S { None, Req, Install, Runtime }
    let mut s = S::None;
    for raw in out.lines() {
        let l = raw.trim();
        if l.starts_with("requested permissions:") { s = S::Req; continue; }
        if l.starts_with("install permissions:") { s = S::Install; continue; }
        if l.starts_with("runtime permissions:") { s = S::Runtime; continue; }
        if l.ends_with(':') && !l.starts_with("android.") { s = S::None; }
        if let Some(v) = l.strip_prefix("versionName=") { d.version_name = Some(v.to_string()); }
        if let Some(v) = l.strip_prefix("firstInstallTime=") { d.first_install = Some(v.to_string()); }
        if let Some(v) = l.strip_prefix("lastUpdateTime=") { d.last_update = Some(v.to_string()); }
        if let Some(v) = l.strip_prefix("installerPackageName=") { d.installer = (v != "null").then(|| v.to_string()); }
        if l.contains("targetSdk=") {
            if let Some(v) = l.split("targetSdk=").nth(1) { d.target_sdk = v.split_whitespace().next().and_then(|x| x.parse().ok()); }
        }
        if l.starts_with("pkgFlags=[") && l.contains(" SYSTEM ") { d.system = true; }
        match s {
            S::Req if l.contains('.') && !l.contains(' ') => { d.requested.insert(l.trim_end_matches(':').to_string()); }
            S::Install | S::Runtime => {
                if let Some((p, rest)) = l.split_once(": granted=") {
                    if rest.starts_with("true") { d.granted.insert(p.to_string()); }
                }
            }
            _ => {}
        }
    }
    d
}

/// `settings get secure enabled_accessibility_services` → set of package names
pub fn parse_accessibility(out: &str) -> BTreeSet<String> {
    out.trim()
        .split(':')
        .filter(|s| !s.is_empty() && *s != "null")
        .filter_map(|c| c.split('/').next().map(|p| p.to_string()))
        .collect()
}

/// `dumpsys device_policy` → packages of active admins
pub fn parse_device_admins(out: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for l in out.lines() {
        let l = l.trim();
        // e.g. "admin=ComponentInfo{com.foo/com.foo.AdminReceiver}"  or "ComponentInfo{...}:"
        if let Some(i) = l.find("ComponentInfo{") {
            if let Some(pkg) = l[i + 14..].split('/').next() {
                set.insert(pkg.to_string());
            }
        }
    }
    set
}

// ------------------------------------------------------------------ live device

pub struct Adb {
    pub serial: String,
}

impl Adb {
    pub fn shell(&self, cmd: &str) -> Result<String> {
        crate::tools::run("adb", &["-s", &self.serial, "shell", cmd])
    }
}

pub fn list_devices() -> Result<Vec<AdbDevice>> {
    Ok(parse_adb_devices(&crate::tools::run("adb", &["devices", "-l"])?))
}

#[derive(Debug, Clone, Serialize)]
pub struct AndroidInfo {
    pub serial: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub device_name: Option<String>,
    pub android_version: Option<String>,
    pub sdk: Option<String>,
    pub security_patch: Option<String>,
    pub build_fingerprint: Option<String>,
    pub build_tags: Option<String>,
    pub encryption_state: Option<String>,
    pub verified_boot_state: Option<String>,
    pub debuggable: Option<String>,
    pub bootloader_locked: Option<String>,
}

pub fn info(adb: &Adb) -> Result<AndroidInfo> {
    let p = parse_getprop(&adb.shell("getprop")?);
    let g = |k: &str| p.get(k).cloned().filter(|s| !s.is_empty());
    Ok(AndroidInfo {
        serial: adb.serial.clone(),
        manufacturer: g("ro.product.manufacturer"),
        model: g("ro.product.model"),
        device_name: g("ro.product.device"),
        android_version: g("ro.build.version.release"),
        sdk: g("ro.build.version.sdk"),
        security_patch: g("ro.build.version.security_patch"),
        build_fingerprint: g("ro.build.fingerprint"),
        build_tags: g("ro.build.tags"),
        encryption_state: g("ro.crypto.state"),
        verified_boot_state: g("ro.boot.verifiedbootstate"),
        debuggable: g("ro.debuggable"),
        bootloader_locked: g("ro.boot.flash.locked"),
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct AndroidAudit {
    pub info: AndroidInfo,
    pub apps: Vec<AppProfile>,
    pub findings: Vec<Finding>,
    pub anomalies: Vec<crate::ai::AnomalyResult>,
    pub pulled_apks: Vec<String>,
}

/// Device configuration assessment (ARGENT SHIELD for Android).
pub fn assess_config(i: &AndroidInfo, settings: &BTreeMap<String, String>, su_present: bool, today: chrono::NaiveDate) -> Vec<Finding> {
    let mut f = vec![];
    let d = || subject("device", i.model.clone().unwrap_or_else(|| i.serial.clone()));
    if let Some(sp) = &i.security_patch {
        if let Ok(date) = chrono::NaiveDate::parse_from_str(sp, "%Y-%m-%d") {
            let age = (today - date).num_days();
            let (sev, t) = if age > 365 { (Severity::High, "Security patch level is more than 12 months old") }
                else if age > 180 { (Severity::Medium, "Security patch level is more than 6 months old") }
                else if age > 90 { (Severity::Low, "Security patch level is more than 3 months old") }
                else { (Severity::Informational, "Security patch level is recent") };
            f.push(Finding::new("shield", "AD-AND-PATCH", t, Category::Configuration, sev, Confidence::Confirmed, d())
                .evidence(format!("ro.build.version.security_patch={sp} ({age} days old)"))
                .recommend("Install the latest system update (Settings › System › Software update). Devices that no longer receive updates should be replaced for sensitive use."));
        }
    }
    if su_present || i.build_tags.as_deref() == Some("test-keys") || i.debuggable.as_deref() == Some("1") {
        let mut x = Finding::new("shield", "AD-AND-ROOT", "Root / modified-firmware indicators", Category::Root, Severity::High,
            if su_present { Confidence::High } else { Confidence::Medium }, d())
            .recommend("A rooted or test-key build disables core Android protections. Restore stock firmware if you did not root the device yourself.");
        if su_present { x = x.evidence("'su' binary resolvable in PATH"); }
        if i.build_tags.as_deref() == Some("test-keys") { x = x.evidence("ro.build.tags=test-keys"); }
        if i.debuggable.as_deref() == Some("1") { x = x.evidence("ro.debuggable=1"); }
        f.push(x);
    }
    if i.verified_boot_state.as_deref().map(|v| v != "green").unwrap_or(false) || i.bootloader_locked.as_deref() == Some("0") {
        f.push(Finding::new("shield", "AD-AND-BOOT", "Bootloader unlocked or verified boot not green", Category::Configuration, Severity::High, Confidence::High, d())
            .evidence(format!("verifiedbootstate={:?} flash.locked={:?}", i.verified_boot_state, i.bootloader_locked))
            .recommend("Relock the bootloader with stock firmware unless you knowingly run a custom OS."));
    }
    if let Some(enc) = &i.encryption_state {
        if enc != "encrypted" {
            f.push(Finding::new("shield", "AD-AND-ENC", "Storage encryption not reported as enabled", Category::Configuration, Severity::High, Confidence::Medium, d())
                .evidence(format!("ro.crypto.state={enc}")).recommend("Enable a screen lock and device encryption."));
        }
    }
    let s = |k: &str| settings.get(k).map(|v| v.trim().to_string()).filter(|v| v != "null" && !v.is_empty());
    if let Some(p) = s("global:http_proxy") {
        if p != ":0" {
            f.push(Finding::new("shield", "AD-AND-PROXY", "Global HTTP proxy configured", Category::NetworkThreat, Severity::Medium, Confidence::High, d())
                .evidence(format!("settings global http_proxy={p}")).recommend("Remove the proxy unless set by your organisation; proxies can intercept traffic."));
        }
    }
    if s("secure:install_non_market_apps").as_deref() == Some("1") {
        f.push(Finding::new("shield", "AD-AND-UNKNOWN", "Installation from unknown sources is enabled (legacy global toggle)", Category::Configuration, Severity::Low, Confidence::High, d())
            .evidence("install_non_market_apps=1").recommend("Disable unknown sources when not needed."));
    }
    if s("global:adb_enabled").as_deref() == Some("1") {
        f.push(Finding::new("shield", "AD-AND-ADB", "USB debugging is enabled", Category::Configuration, Severity::Low, Confidence::Confirmed, d())
            .evidence("adb_enabled=1 (required for this scan)").recommend("Turn off USB/Wireless debugging after the assessment."));
    }
    if s("global:private_dns_mode").as_deref() == Some("off") {
        f.push(Finding::new("shield", "AD-AND-DNS", "Private DNS (DNS-over-TLS) is off", Category::NetworkThreat, Severity::Informational, Confidence::Confirmed, d())
            .evidence("private_dns_mode=off").recommend("Consider enabling Private DNS with a trusted provider."));
    }
    if s("secure:lockscreen.disabled").as_deref() == Some("1") {
        f.push(Finding::new("shield", "AD-AND-LOCK", "Lock screen disabled", Category::Configuration, Severity::High, Confidence::Medium, d())
            .evidence("lockscreen.disabled=1").recommend("Set a PIN, pattern or password."));
    }
    f
}

pub fn audit_device(intel: &rusqlite::Connection, serial: &str, pull_dir: Option<&std::path::Path>, third_party_only: bool) -> Result<AndroidAudit> {
    let adb = Adb { serial: serial.to_string() };
    let info = info(&adb)?;
    let mut settings = BTreeMap::new();
    for (ns, k) in [("global", "http_proxy"), ("secure", "install_non_market_apps"), ("global", "adb_enabled"), ("global", "private_dns_mode"), ("secure", "lockscreen.disabled")] {
        if let Ok(v) = adb.shell(&format!("settings get {ns} {k}")) {
            settings.insert(format!("{ns}:{k}"), v.trim().to_string());
        }
    }
    let su = adb.shell("command -v su || which su").map(|s| !s.trim().is_empty()).unwrap_or(false);
    let mut findings = assess_config(&info, &settings, su, chrono::Utc::now().date_naive());

    let acc = adb.shell("settings get secure enabled_accessibility_services").map(|s| parse_accessibility(&s)).unwrap_or_default();
    let admins = adb.shell("dumpsys device_policy").map(|s| parse_device_admins(&s)).unwrap_or_default();
    let listeners = adb.shell("settings get secure enabled_notification_listeners").map(|s| parse_accessibility(&s)).unwrap_or_default();
    let flag = if third_party_only { "-3" } else { "" };
    let pkgs = parse_pm_list(&adb.shell(&format!("pm list packages -f -i -U {flag}"))?);
    let third: BTreeSet<String> = parse_pm_list(&adb.shell("pm list packages -3").unwrap_or_default()).into_iter().map(|p| p.package).collect();

    let mut apps = vec![];
    let mut pulled = vec![];
    for p in &pkgs {
        let d = adb.shell(&format!("dumpsys package {}", p.package)).map(|s| parse_dumpsys_package(&s)).unwrap_or_default();
        let mut a = AppProfile {
            package: p.package.clone(),
            version: d.version_name.clone(),
            installer: p.installer.clone().or(d.installer.clone()),
            system_app: !third.contains(&p.package),
            permissions: d.requested.clone(),
            granted: d.granted.clone(),
            accessibility_enabled: acc.contains(&p.package),
            device_admin_active: admins.contains(&p.package),
            declares_notification_listener: listeners.contains(&p.package),
            target_sdk: d.target_sdk,
            first_install: d.first_install.clone(),
            ..Default::default()
        };
        // Advanced forensic mode: pull the APK (user-installed apps only, readable without root).
        if let (Some(dir), Some(remote)) = (pull_dir, p.apk_path.as_ref()) {
            if !a.system_app {
                std::fs::create_dir_all(dir)?;
                let local = dir.join(format!("{}.apk", p.package));
                if crate::tools::run("adb", &["-s", serial, "pull", remote, &local.display().to_string()]).is_ok() {
                    if let Ok(r) = crate::apk::analyze_apk(&local) {
                        let sp = crate::permissions::profile_from_apk(&r);
                        a.sha256 = sp.sha256;
                        a.label = sp.label;
                        a.declares_accessibility = sp.declares_accessibility;
                        a.declares_device_admin = sp.declares_device_admin;
                        a.declares_notification_listener |= sp.declares_notification_listener;
                        a.declares_vpn_service = sp.declares_vpn_service;
                        a.has_launcher = sp.has_launcher;
                        a.debuggable = sp.debuggable;
                        a.debug_certificate = sp.debug_certificate;
                        a.signed = sp.signed;
                        a.cleartext_traffic = sp.cleartext_traffic;
                    }
                    pulled.push(local.display().to_string());
                }
            }
        }
        findings.extend(crate::permissions::audit(&a));
        apps.push(a);
    }
    if pull_dir.is_none() {
        findings.push(limitation("android", "AD-LIM-AND-1",
            "APK contents not extracted (Standard Mode): manifest components, signatures and malware signatures inside APKs were not examined",
            subject("device", serial)));
    }
    findings.push(limitation("android", "AD-LIM-AND-2",
        "Private app data (/data/data) and system partitions are not readable without root; ARGENT DEFENDER does not root or bypass Android protections",
        subject("device", serial)));
    let anomalies = crate::ai::app_anomalies(&apps);
    findings.extend(crate::ai::anomaly_findings(&anomalies));
    for a in &apps {
        for hit in crate::intel::lookup(intel, "package", &a.package)? {
            findings.push(hit.to_finding(subject("package", &a.package)));
        }
        if let Some(h) = &a.sha256 {
            for hit in crate::intel::lookup(intel, "sha256", h)? {
                findings.push(hit.to_finding(subject("package", &a.package)));
            }
            findings.extend(crate::judol::check_hash(intel, h, subject("package", &a.package))?);
        }
        if !a.system_app {
            findings.extend(crate::judol::check_package(intel, &a.package, a.label.as_deref())?);
        }
    }
    crate::scan::dedup(&mut findings);
    Ok(AndroidAudit { info, apps, findings, anomalies, pulled_apks: pulled })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_adb_devices() {
        let out = "List of devices attached\nR58N12345AB            device usb:1-1 product:a52qnsxx model:SM_A525F device:a52q transport_id:1\n192.168.1.20:5555 unauthorized transport_id:2\n\n";
        let d = parse_adb_devices(out);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].model.as_deref(), Some("SM A525F"));
        assert_eq!(d[0].transport, "usb");
        assert_eq!(d[1].state, "unauthorized");
        assert_eq!(d[1].transport, "wifi");
    }
    #[test]
    fn parses_pm_and_dumpsys() {
        let pm = parse_pm_list("package:/data/app/~~ab==/com.foo-x==/base.apk=com.foo  installer=com.android.vending uid:10201\npackage:/system/app/Bar/Bar.apk=com.bar  installer=null uid:1000\n");
        assert_eq!(pm[0].package, "com.foo");
        assert_eq!(pm[0].installer.as_deref(), Some("com.android.vending"));
        assert_eq!(pm[1].installer, None);
        let ds = "    versionName=2.3.1\n    targetSdk=33\n    firstInstallTime=2025-01-02 10:11:12\n    requested permissions:\n      android.permission.INTERNET\n      android.permission.READ_SMS\n    install permissions:\n      android.permission.INTERNET: granted=true\n    runtime permissions:\n      android.permission.READ_SMS: granted=false, flags=[ USER_SET ]\n";
        let d = parse_dumpsys_package(ds);
        assert_eq!(d.version_name.as_deref(), Some("2.3.1"));
        assert_eq!(d.target_sdk, Some(33));
        assert!(d.requested.contains("android.permission.READ_SMS"));
        assert!(d.granted.contains("android.permission.INTERNET"));
        assert!(!d.granted.contains("android.permission.READ_SMS"));
    }
    #[test]
    fn parses_settings_and_admins() {
        assert!(parse_accessibility("com.a/com.a.Svc:com.b/.X\n").contains("com.b"));
        assert!(parse_accessibility("null\n").is_empty());
        let a = parse_device_admins("Enabled Device Admins (User 0, provisioningState: 0):\n  com.evil/.Adm:\n    uid=10123\n  admin=ComponentInfo{com.evil/com.evil.Adm}\n");
        assert!(a.contains("com.evil"));
    }
    #[test]
    fn patch_age_and_root() {
        let i = AndroidInfo { serial: "s".into(), manufacturer: None, model: Some("M".into()), device_name: None, android_version: None, sdk: None,
            security_patch: Some("2024-01-01".into()), build_fingerprint: None, build_tags: Some("test-keys".into()), encryption_state: Some("encrypted".into()),
            verified_boot_state: Some("green".into()), debuggable: Some("0".into()), bootloader_locked: Some("1".into()) };
        let f = assess_config(&i, &BTreeMap::new(), false, chrono::NaiveDate::from_ymd_opt(2026, 11, 10).unwrap());
        assert!(f.iter().any(|x| x.rule == "AD-AND-PATCH" && x.severity == Severity::High));
        assert!(f.iter().any(|x| x.rule == "AD-AND-ROOT"));
    }
}
