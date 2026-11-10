//! External tool discovery and adaptive environment detection.
//! Missing tools never crash the engine: the feature reports "not_installed".

use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;

/// Search PATH plus the usual Homebrew / Android SDK locations on macOS.
pub fn which(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
    for d in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/opt/local/bin"] {
        dirs.push(d.into());
    }
    if let Some(home) = std::env::var_os("HOME") {
        let h = PathBuf::from(home);
        dirs.push(h.join("Library/Android/sdk/platform-tools"));
        dirs.push(h.join(".local/bin"));
        if let Ok(rd) = std::fs::read_dir(h.join("Library/Android/sdk/build-tools")) {
            let mut v: Vec<_> = rd.flatten().map(|e| e.path()).collect();
            v.sort();
            if let Some(last) = v.pop() {
                dirs.push(last);
            }
        }
    }
    if let Some(extra) = std::env::var_os("ARGENT_TOOLS_DIR") {
        dirs.insert(0, extra.into());
    }
    dirs.into_iter().map(|d| d.join(name)).find(|p| p.is_file())
}

#[derive(Serialize)]
pub struct ToolStatus {
    pub name: &'static str,
    pub purpose: &'static str,
    pub path: Option<String>,
    pub version: Option<String>,
    pub install_hint: &'static str,
}

const TOOLS: &[(&str, &str, &[&str], &str)] = &[
    ("adb", "Android device access (USB / Wi-Fi debugging)", &["version"], "brew install --cask android-platform-tools"),
    ("idevice_id", "iPhone discovery (libimobiledevice)", &["--version"], "brew install libimobiledevice"),
    ("ideviceinfo", "iPhone device information", &["--version"], "brew install libimobiledevice"),
    ("idevicepair", "iPhone pairing validation", &["--version"], "brew install libimobiledevice"),
    ("idevicebackup2", "iPhone local backup creation", &["--version"], "brew install libimobiledevice"),
    ("apksigner", "Cryptographic APK signature verification", &["--version"], "Android SDK build-tools"),
    ("clamscan", "ClamAV secondary malware engine", &["--version"], "brew install clamav"),
    ("quark", "Quark-Engine Android behaviour rules", &["--version"], "pipx install quark-engine"),
    ("jadx", "Decompiler for analyst review", &["--version"], "brew install jadx"),
    ("apktool", "Resource decoding for analyst review", &["--version"], "brew install apktool"),
    ("ipsw", "IPSW / iOS firmware analysis", &["version"], "brew install blacktop/tap/ipsw"),
    ("tshark", "Wireshark CLI for PCAP analysis", &["--version"], "brew install --cask wireshark"),
    ("zeek", "Zeek network log generation", &["--version"], "brew install zeek"),
];

pub fn status() -> Vec<ToolStatus> {
    TOOLS
        .iter()
        .map(|(name, purpose, vargs, hint)| {
            let path = which(name);
            let version = path.as_ref().and_then(|p| {
                Command::new(p).args(*vargs).output().ok().map(|o| {
                    let s = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
                    s.lines().next().unwrap_or("").trim().chars().take(120).collect()
                })
            });
            ToolStatus { name, purpose, path: path.map(|p| p.display().to_string()), version, install_hint: hint }
        })
        .collect()
}

#[derive(Serialize)]
pub struct HostInfo {
    pub os: &'static str,
    pub arch: &'static str,
    pub os_version: Option<String>,
    pub cpu_model: Option<String>,
    pub logical_cpus: usize,
    pub memory_bytes: Option<u64>,
    pub apple_silicon: bool,
    pub engine_version: &'static str,
    pub yara_x: &'static str,
}

fn sysctl(key: &str) -> Option<String> {
    let o = Command::new("sysctl").args(["-n", key]).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

pub fn host() -> HostInfo {
    let os_version = if cfg!(target_os = "macos") {
        Command::new("sw_vers").arg("-productVersion").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        std::fs::read_to_string("/etc/os-release").ok().and_then(|s| {
            s.lines().find(|l| l.starts_with("PRETTY_NAME=")).map(|l| l[12..].trim_matches('"').to_string())
        })
    };
    let memory_bytes = if cfg!(target_os = "macos") {
        sysctl("hw.memsize").and_then(|s| s.parse().ok())
    } else {
        std::fs::read_to_string("/proc/meminfo").ok().and_then(|s| {
            s.lines().find(|l| l.starts_with("MemTotal:")).and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok()).map(|k| k * 1024)
        })
    };
    HostInfo {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        os_version,
        cpu_model: sysctl("machdep.cpu.brand_string"),
        logical_cpus: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        memory_bytes,
        apple_silicon: cfg!(all(target_os = "macos", target_arch = "aarch64")),
        engine_version: env!("CARGO_PKG_VERSION"),
        yara_x: "yara-x (embedded library)",
    }
}

/// Run a command with a timeout-free, captured output. Errors are returned as text.
pub fn run(bin: &str, args: &[&str]) -> anyhow::Result<String> {
    let path = which(bin).ok_or_else(|| anyhow::anyhow!("{bin} not installed"))?;
    let o = Command::new(path).args(args).output()?;
    if !o.status.success() {
        anyhow::bail!("{bin} {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).to_string())
}
