//! ARGENT AI — local, explainable machine learning.
//! * Isolation Forest anomaly detection over per-app capability vectors (unsupervised,
//!   runs fully on-device, deterministic seed, per-feature explanations).
//! * Evidence-grounded summarisation: every sentence references finding IDs.
//! LLMs (llama.cpp, optional cloud) are used only by the app for narrative help and
//! are never the basis of a detection.

use crate::model::*;
use crate::permissions::AppProfile;
use serde::Serialize;

pub const FEATURES: &[&str] = &[
    "permissions", "sensitive_permissions", "sms", "location_bg", "microphone", "camera", "overlay", "accessibility",
    "device_admin", "notification_listener", "install_packages", "sideloaded", "no_launcher", "debuggable", "old_target_sdk",
];

pub fn features(a: &AppProfile) -> Vec<f64> {
    let has = |p: &str| a.permissions.contains(&format!("android.permission.{p}")) as u8 as f64;
    let sens = crate::permissions::SENSITIVE.iter().filter(|(p, _)| a.permissions.contains(&format!("android.permission.{p}"))).count() as f64;
    let sideloaded = a.installer.as_deref().map(|i| i != "com.android.vending").unwrap_or(false) && !a.system_app;
    vec![
        (a.permissions.len() as f64).ln_1p(),
        sens,
        (has("READ_SMS") + has("RECEIVE_SMS") + has("SEND_SMS")).min(1.0),
        has("ACCESS_BACKGROUND_LOCATION"),
        has("RECORD_AUDIO"),
        has("CAMERA"),
        has("SYSTEM_ALERT_WINDOW"),
        (a.declares_accessibility || a.accessibility_enabled) as u8 as f64 * if a.accessibility_enabled { 2.0 } else { 1.0 },
        (a.declares_device_admin || a.device_admin_active) as u8 as f64 * if a.device_admin_active { 2.0 } else { 1.0 },
        a.declares_notification_listener as u8 as f64,
        has("REQUEST_INSTALL_PACKAGES"),
        sideloaded as u8 as f64,
        (a.has_launcher == Some(false)) as u8 as f64,
        a.debuggable as u8 as f64,
        a.target_sdk.map(|t| (t < 26) as u8 as f64).unwrap_or(0.0),
    ]
}

/// Small deterministic PRNG (SplitMix64) so results are reproducible across runs.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn f(&mut self) -> f64 { (self.next() >> 11) as f64 / (1u64 << 53) as f64 }
    fn below(&mut self, n: usize) -> usize { (self.next() % n as u64) as usize }
}

enum Node { Leaf(usize), Split { f: usize, v: f64, l: Box<Node>, r: Box<Node> } }

fn c_factor(n: usize) -> f64 {
    if n <= 1 { return 0.0; }
    let n = n as f64;
    2.0 * ((n - 1.0).ln() + 0.577_215_664_9) - 2.0 * (n - 1.0) / n
}

fn build(data: &[Vec<f64>], idx: Vec<usize>, depth: usize, max: usize, rng: &mut Rng) -> Node {
    if depth >= max || idx.len() <= 1 { return Node::Leaf(idx.len()); }
    let dims = data[0].len();
    // pick a feature with spread among this subset
    for _ in 0..dims * 2 {
        let f = rng.below(dims);
        let (lo, hi) = idx.iter().fold((f64::MAX, f64::MIN), |(a, b), &i| (a.min(data[i][f]), b.max(data[i][f])));
        if hi > lo {
            let v = lo + rng.f() * (hi - lo);
            let (l, r): (Vec<usize>, Vec<usize>) = idx.iter().partition(|&&i| data[i][f] < v);
            return Node::Split { f, v, l: Box::new(build(data, l, depth + 1, max, rng)), r: Box::new(build(data, r, depth + 1, max, rng)) };
        }
    }
    Node::Leaf(idx.len())
}

fn path_len(n: &Node, x: &[f64], d: f64) -> f64 {
    match n {
        Node::Leaf(s) => d + c_factor(*s),
        Node::Split { f, v, l, r } => if x[*f] < *v { path_len(l, x, d + 1.0) } else { path_len(r, x, d + 1.0) },
    }
}

/// Returns anomaly scores in (0,1]; > ~0.6 is anomalous relative to the population.
pub fn isolation_forest(data: &[Vec<f64>], trees: usize, sample: usize, seed: u64) -> Vec<f64> {
    let n = data.len();
    if n < 4 { return vec![0.5; n]; }
    let psi = sample.min(n);
    let max_depth = (psi as f64).log2().ceil() as usize;
    let mut rng = Rng(seed);
    let forest: Vec<Node> = (0..trees).map(|_| {
        let mut idx: Vec<usize> = (0..n).collect();
        for i in 0..psi { let j = i + rng.below(n - i); idx.swap(i, j); }
        idx.truncate(psi);
        build(data, idx, 0, max_depth, &mut rng)
    }).collect();
    let c = c_factor(psi);
    data.iter().map(|x| {
        let e = forest.iter().map(|t| path_len(t, x, 0.0)).sum::<f64>() / trees as f64;
        2f64.powf(-e / c)
    }).collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct AnomalyResult {
    pub package: String,
    pub score: f64,
    pub anomalous: bool,
    /// Features where this app deviates most from the device population (z-score).
    pub drivers: Vec<(String, f64)>,
}

pub fn app_anomalies(apps: &[AppProfile]) -> Vec<AnomalyResult> {
    let pop: Vec<&AppProfile> = apps.iter().filter(|a| !a.system_app).collect();
    if pop.len() < 8 { return vec![]; }
    let data: Vec<Vec<f64>> = pop.iter().map(|a| features(a)).collect();
    let scores = isolation_forest(&data, 200, 256, 0xA26E_17D3);
    let dims = FEATURES.len();
    let mean: Vec<f64> = (0..dims).map(|f| data.iter().map(|x| x[f]).sum::<f64>() / data.len() as f64).collect();
    let sd: Vec<f64> = (0..dims).map(|f| (data.iter().map(|x| (x[f] - mean[f]).powi(2)).sum::<f64>() / data.len() as f64).sqrt().max(1e-6)).collect();
    let mut out: Vec<AnomalyResult> = pop.iter().zip(&data).zip(&scores).map(|((a, x), s)| {
        let mut d: Vec<(String, f64)> = (0..dims).map(|f| (FEATURES[f].to_string(), (x[f] - mean[f]) / sd[f])).filter(|(_, z)| *z > 1.5).collect();
        d.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        d.truncate(4);
        AnomalyResult { package: a.package.clone(), score: (*s * 1000.0).round() / 1000.0, anomalous: *s > 0.62 && !d.is_empty(), drivers: d }
    }).collect();
    out.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    out
}

pub fn anomaly_findings(r: &[AnomalyResult]) -> Vec<Finding> {
    r.iter().filter(|a| a.anomalous).map(|a| {
        Finding::new("argent-ai", "AD-AI-ANOMALY", "Capability profile is a statistical outlier on this device", Category::Anomaly, Severity::Low, Confidence::Low, subject("package", &a.package))
            .evidence(format!("Isolation-Forest score {:.3} (threshold 0.62)", a.score))
            .evidence(format!("top deviating features: {}", a.drivers.iter().map(|(f, z)| format!("{f} (z={z:.1})")).collect::<Vec<_>>().join(", ")))
            .recommend("Anomaly ≠ malware. Review this app alongside its other findings.")
    }).collect()
}

/// Deterministic, evidence-grounded summary (no LLM). Each claim cites finding IDs.
pub fn summarize(findings: &[Finding], score: &crate::report::RiskScore) -> String {
    let mut s = format!("Security score {}/100 ({}). ", score.score, score.rating);
    let crit: Vec<&Finding> = findings.iter().filter(|f| f.severity >= Severity::High && f.category != Category::Limitation).collect();
    if crit.is_empty() {
        s += "No high or critical findings were produced by the available checks. ";
    } else {
        s += &format!("{} high/critical finding(s): ", crit.len());
        s += &crit.iter().take(6).map(|f| format!("{} on {} [{}; confidence {:?}]", f.title, f.subject.name, f.id, f.confidence)).collect::<Vec<_>>().join("; ");
        s += ". ";
    }
    let lim = findings.iter().filter(|f| f.category == Category::Limitation).count();
    if lim > 0 { s += &format!("{lim} limitation(s) apply — areas that could not be examined are listed in the report and are not reported as clean."); }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn isolation_forest_finds_outlier() {
        let mut apps: Vec<AppProfile> = (0..30).map(|i| AppProfile { package: format!("app{i}"), installer: Some("com.android.vending".into()), has_launcher: Some(true),
            permissions: ["INTERNET", "ACCESS_NETWORK_STATE"].iter().map(|p| format!("android.permission.{p}")).collect(), ..Default::default() }).collect();
        apps.push(AppProfile { package: "evil".into(), installer: Some("com.android.chrome".into()), has_launcher: Some(false), accessibility_enabled: true, device_admin_active: true,
            permissions: ["INTERNET", "READ_SMS", "RECORD_AUDIO", "SYSTEM_ALERT_WINDOW", "ACCESS_BACKGROUND_LOCATION", "REQUEST_INSTALL_PACKAGES"].iter().map(|p| format!("android.permission.{p}")).collect(), ..Default::default() });
        let r = app_anomalies(&apps);
        assert_eq!(r[0].package, "evil");
        assert!(r[0].anomalous);
        assert!(!r.iter().filter(|a| a.package != "evil").any(|a| a.anomalous));
        // deterministic
        assert_eq!(app_anomalies(&apps)[0].score, r[0].score);
    }
}
