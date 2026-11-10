//! Permission & capability audit. A sensitive permission alone is never treated as
//! malicious: single permissions are informational; only documented *combinations*
//! that match known abuse patterns (banking overlay, stalkerware, locker ransomware,
//! SMS/OTP theft) raise risk, always with an explicit confidence.

use crate::model::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppProfile {
    pub package: String,
    pub label: Option<String>,
    pub version: Option<String>,
    pub installer: Option<String>,
    pub system_app: bool,
    pub sha256: Option<String>,
    pub permissions: BTreeSet<String>,
    /// Runtime-granted permissions (device inventory only)
    pub granted: BTreeSet<String>,
    pub declares_accessibility: bool,
    pub accessibility_enabled: bool,
    pub declares_device_admin: bool,
    pub device_admin_active: bool,
    pub declares_notification_listener: bool,
    pub declares_vpn_service: bool,
    pub has_launcher: Option<bool>,
    pub debuggable: bool,
    pub cleartext_traffic: Option<bool>,
    pub debug_certificate: bool,
    pub signed: Option<bool>,
    pub target_sdk: Option<i64>,
    pub first_install: Option<String>,
}

pub fn profile_from_apk(r: &crate::apk::ApkReport) -> AppProfile {
    let m = &r.manifest;
    AppProfile {
        package: m.package.clone(),
        label: m.label.clone(),
        version: m.version_name.clone(),
        sha256: Some(r.hashes.sha256.clone()),
        permissions: m.permissions.clone(),
        declares_accessibility: !m.services_with_permission("android.permission.BIND_ACCESSIBILITY_SERVICE").is_empty(),
        declares_device_admin: !m.services_with_permission("android.permission.BIND_DEVICE_ADMIN").is_empty()
            || !m.receivers_with_action("android.app.action.DEVICE_ADMIN_ENABLED").is_empty(),
        declares_notification_listener: !m.services_with_permission("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE").is_empty(),
        declares_vpn_service: !m.services_with_permission("android.permission.BIND_VPN_SERVICE").is_empty(),
        has_launcher: Some(m.has_launcher()),
        debuggable: m.debuggable,
        cleartext_traffic: m.cleartext_traffic,
        debug_certificate: r.signing.debug_certificate,
        signed: Some(r.signing.v1_jar_signature || r.signing.v2 || r.signing.v3 || r.signing.v31),
        target_sdk: m.target_sdk.as_deref().and_then(|s| s.parse().ok()),
        ..Default::default()
    }
}

const P: &str = "android.permission.";

fn has(a: &AppProfile, p: &str) -> bool {
    a.permissions.contains(&format!("{P}{p}")) || a.granted.contains(&format!("{P}{p}"))
}

/// Sensitive permissions surfaced as informational context.
pub const SENSITIVE: &[(&str, &str)] = &[
    ("READ_SMS", "Read SMS messages (incl. OTP codes)"),
    ("RECEIVE_SMS", "Intercept incoming SMS"),
    ("SEND_SMS", "Send SMS (premium-rate fraud risk)"),
    ("READ_CALL_LOG", "Read call history"),
    ("READ_CONTACTS", "Read contacts"),
    ("RECORD_AUDIO", "Use microphone"),
    ("CAMERA", "Use camera"),
    ("ACCESS_FINE_LOCATION", "Precise location"),
    ("ACCESS_BACKGROUND_LOCATION", "Location while in background"),
    ("SYSTEM_ALERT_WINDOW", "Draw over other apps (overlay)"),
    ("REQUEST_INSTALL_PACKAGES", "Install other APKs"),
    ("QUERY_ALL_PACKAGES", "Enumerate installed apps"),
    ("READ_PHONE_STATE", "Phone identifiers / call state"),
    ("MANAGE_EXTERNAL_STORAGE", "Full shared-storage access"),
    ("BIND_ACCESSIBILITY_SERVICE", "Accessibility service"),
    ("PACKAGE_USAGE_STATS", "App usage tracking"),
];

pub fn audit(a: &AppProfile) -> Vec<Finding> {
    let mut f = vec![];
    let subj = Subject { kind: "package".into(), name: a.package.clone(), path: None, sha256: a.sha256.clone() };
    let mk = |rule: &str, title: &str, cat: Category, sev: Severity, conf: Confidence| {
        Finding::new("permission-audit", rule, title, cat, sev, conf, subj.clone())
    };
    let acc = a.declares_accessibility || a.accessibility_enabled;
    let overlay = has(a, "SYSTEM_ALERT_WINDOW");
    let sms = has(a, "RECEIVE_SMS") || has(a, "READ_SMS");
    let net = has(a, "INTERNET");
    let sideloaded = !a.system_app
        && a.installer.as_deref().map(|i| !matches!(i, "com.android.vending" | "com.google.android.feedback" | "com.sec.android.app.samsungapps" | "com.huawei.appmarket" | "com.xiaomi.market" | "com.oppo.market" | "com.heytap.market" | "com.vivo.appstore")).unwrap_or(false);

    // --- Pattern: accessibility + overlay (banking trojan / credential overlay)
    if acc && overlay {
        f.push(
            mk("AD-PERM-001", "Accessibility service combined with screen overlay", Category::BankingTrojan, Severity::High,
               if a.accessibility_enabled { Confidence::High } else { Confidence::Medium })
                .evidence(format!("accessibility service {}", if a.accessibility_enabled { "ENABLED on device" } else { "declared in manifest" }))
                .evidence("android.permission.SYSTEM_ALERT_WINDOW requested")
                .recommend("Verify the app's purpose. If it is not an assistive/automation tool you installed knowingly, disable its accessibility access (Settings › Accessibility) and uninstall it."),
        );
    } else if a.accessibility_enabled && !a.system_app {
        f.push(
            mk("AD-PERM-002", "Third-party accessibility service is enabled", Category::Spyware, Severity::Medium, Confidence::Medium)
                .evidence("Enabled accessibility services can read screen content and perform actions")
                .recommend("Keep only accessibility services you deliberately enabled."),
        );
    } else if a.declares_accessibility && !a.system_app {
        f.push(mk("AD-PERM-003", "App declares an accessibility service", Category::Permission, Severity::Low, Confidence::Low)
            .evidence("BIND_ACCESSIBILITY_SERVICE service in manifest (not necessarily enabled)")
            .recommend("No action needed unless the service is enabled without your knowledge."));
    }

    // --- Pattern: device admin (+ accessibility) → locker ransomware / anti-removal
    if a.device_admin_active || a.declares_device_admin {
        let (sev, conf, title) = if acc {
            (Severity::High, Confidence::Medium, "Device-administrator capability combined with accessibility (locker/anti-removal pattern)")
        } else if a.device_admin_active && !a.system_app {
            (Severity::Medium, Confidence::Medium, "Third-party device administrator is ACTIVE")
        } else {
            (Severity::Low, Confidence::Low, "App can request device-administrator rights")
        };
        f.push(mk("AD-PERM-010", title, Category::Ransomware, sev, conf)
            .evidence(if a.device_admin_active { "Active device admin (dumpsys device_policy)" } else { "DEVICE_ADMIN receiver declared" })
            .recommend("Remove device-admin rights in Settings › Security › Device admin apps if not required (e.g. MDM)."));
    }

    // --- Pattern: SMS/OTP interception
    if sms && net && !a.system_app {
        f.push(mk("AD-PERM-020", "Can read/intercept SMS and access the internet (OTP theft pattern)", Category::Spyware,
                  Severity::Medium, if sideloaded { Confidence::Medium } else { Confidence::Low })
            .evidence("RECEIVE_SMS/READ_SMS + INTERNET")
            .recommend("Only messaging apps normally need SMS access. Revoke SMS permission if unexpected."));
    }

    // --- Pattern: stalkerware (surveillance capability set)
    let surveil = [has(a, "ACCESS_FINE_LOCATION") || has(a, "ACCESS_COARSE_LOCATION"), has(a, "ACCESS_BACKGROUND_LOCATION"), has(a, "RECORD_AUDIO"), has(a, "READ_SMS"), has(a, "READ_CALL_LOG"), has(a, "READ_CONTACTS"), a.declares_notification_listener, acc]
        .iter()
        .filter(|x| **x)
        .count();
    if surveil >= 5 && !a.system_app {
        let hidden = a.has_launcher == Some(false);
        f.push(mk("AD-PERM-030", "Broad surveillance capability set (stalkerware pattern)", Category::Stalkerware,
                  if hidden { Severity::Critical } else { Severity::High },
                  if hidden || sideloaded { Confidence::High } else { Confidence::Medium })
            .evidence(format!("{surveil} of 8 surveillance capabilities present (location, background location, microphone, SMS, call log, contacts, notification access, accessibility)"))
            .evidence(if hidden { "No launcher icon — app is hidden from the home screen" } else { "App has a launcher icon" })
            .recommend("If you did not install this app yourself, your device may be monitored. Seek help before removing it if your safety may be at risk (removal can alert the installer)."));
    } else if a.has_launcher == Some(false) && !a.system_app && net && surveil >= 2 {
        f.push(mk("AD-PERM-031", "Hidden app (no launcher icon) with sensitive capabilities", Category::Spyware, Severity::Medium, Confidence::Low)
            .evidence("No MAIN/LAUNCHER activity").evidence(format!("{surveil} surveillance capabilities"))
            .recommend("Identify where this app came from; legitimate plugins/services can also lack an icon."));
    }

    if a.declares_notification_listener && !a.system_app {
        f.push(mk("AD-PERM-040", "Can read all notifications (incl. OTPs, chats)", Category::Permission, Severity::Low, Confidence::Low)
            .evidence("NotificationListenerService declared").recommend("Grant notification access only to trusted apps."));
    }
    if has(a, "REQUEST_INSTALL_PACKAGES") && !a.system_app {
        f.push(mk("AD-PERM-050", "Can install other applications (dropper capability)", Category::Pua, Severity::Low,
                  if sideloaded { Confidence::Medium } else { Confidence::Low })
            .evidence("REQUEST_INSTALL_PACKAGES").recommend("Disable 'Install unknown apps' for this app unless it is an app store or browser you trust."));
    }
    if a.declares_vpn_service && !a.system_app {
        f.push(mk("AD-PERM-060", "Provides a VPN service (can route all device traffic)", Category::NetworkThreat, Severity::Informational, Confidence::Medium)
            .evidence("BIND_VPN_SERVICE").recommend("Use only VPN apps from providers you trust."));
    }
    if has(a, "SEND_SMS") && !a.system_app && sideloaded {
        f.push(mk("AD-PERM-070", "Sideloaded app can send SMS (premium-SMS fraud risk)", Category::Malware, Severity::Medium, Confidence::Low)
            .evidence("SEND_SMS + non-store installer").recommend("Check your phone bill for unexpected premium SMS charges."));
    }

    // --- Build / signing configuration
    if a.debuggable {
        f.push(mk("AD-CONF-001", "Application is debuggable", Category::Configuration, Severity::Medium, Confidence::Confirmed)
            .evidence("android:debuggable=true").recommend("Production apps should never be debuggable; treat unknown debuggable apps with suspicion."));
    }
    if a.debug_certificate {
        f.push(mk("AD-CONF-002", "Signed with an Android debug certificate", Category::Integrity, Severity::Medium, Confidence::Confirmed)
            .evidence("Certificate subject contains 'Android Debug'").recommend("Store-distributed apps are never debug-signed. Verify the source."));
    }
    if a.signed == Some(false) {
        f.push(mk("AD-CONF-003", "APK has no signature", Category::Integrity, Severity::High, Confidence::Confirmed)
            .evidence("No v1/v2/v3 signature found").recommend("Unsigned APKs cannot be installed normally; do not install."));
    }
    if a.cleartext_traffic == Some(true) {
        f.push(mk("AD-CONF-004", "Allows cleartext (non-TLS) network traffic", Category::Configuration, Severity::Low, Confidence::Confirmed)
            .evidence("usesCleartextTraffic=true").recommend("Avoid entering credentials in apps that permit unencrypted traffic."));
    }
    if let Some(t) = a.target_sdk {
        if t < 26 && !a.system_app {
            f.push(mk("AD-CONF-005", "Targets an outdated Android API level", Category::Configuration, Severity::Low, Confidence::Confirmed)
                .evidence(format!("targetSdkVersion={t} (<26 bypasses modern runtime-permission & background limits)"))
                .recommend("Prefer apps that are kept up to date."));
        }
    }
    if sideloaded {
        f.push(mk("AD-SRC-001", "Installed from outside a recognised app store", Category::Configuration, Severity::Informational, Confidence::Confirmed)
            .evidence(format!("installer={}", a.installer.clone().unwrap_or_default()))
            .recommend("Sideloaded apps are not reviewed by an app store; verify the source."));
    }

    let sens: Vec<_> = SENSITIVE.iter().filter(|(p, _)| has(a, p)).map(|(p, d)| format!("{P}{p} — {d}")).collect();
    if !sens.is_empty() {
        let mut x = mk("AD-PERM-INFO", "Sensitive permissions requested", Category::Permission, Severity::Informational, Confidence::Confirmed)
            .recommend("Informational only — sensitive permissions are common in legitimate apps.");
        x.evidence = sens;
        f.push(x);
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    fn app(perms: &[&str]) -> AppProfile {
        AppProfile { package: "x.y".into(), permissions: perms.iter().map(|p| format!("{P}{p}")).collect(), has_launcher: Some(true), ..Default::default() }
    }
    #[test]
    fn single_sensitive_permission_is_informational() {
        let f = audit(&app(&["CAMERA", "INTERNET"]));
        assert!(f.iter().all(|x| x.severity <= Severity::Informational), "{f:?}");
    }
    #[test]
    fn overlay_plus_accessibility_is_high() {
        let mut a = app(&["SYSTEM_ALERT_WINDOW", "INTERNET"]);
        a.declares_accessibility = true;
        assert!(audit(&a).iter().any(|x| x.rule == "AD-PERM-001" && x.severity == Severity::High));
    }
    #[test]
    fn hidden_stalkerware_is_critical() {
        let mut a = app(&["ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "READ_SMS", "READ_CALL_LOG", "INTERNET"]);
        a.has_launcher = Some(false);
        let f = audit(&a);
        assert!(f.iter().any(|x| x.rule == "AD-PERM-030" && x.severity == Severity::Critical));
    }
}
