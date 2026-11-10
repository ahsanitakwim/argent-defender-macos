# ARGENT DEFENDER — Architecture

```
┌──────────────────────────── macOS (Intel / Apple Silicon) ─────────────────────────────┐
│  ARGENT DEFENDER.app  (SwiftUI · MVVM · Swift Concurrency · macOS 13+)                  │
│  ┌──────────────┐  ┌────────────────────────────────────────────────────────────────┐  │
│  │ AppState     │  │ Views: Overview · Device Center · Quick/Full/Deep Scan ·        │  │
│  │ (@MainActor  │◀▶│ Android · iPhone · Malware · Gaming Watch · Network ·           │  │
│  │  view-model) │  │ Forensics · Threat Intel · AI · Reports · History · Settings    │  │
│  └──────┬───────┘  └────────────────────────────────────────────────────────────────┘  │
│         │ Engine.swift: Process + JSON envelope; secrets via stdin; Keychain.swift      │
│         ▼                                                                              │
│  Contents/MacOS/argent-engine  (Rust, universal)                                       │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │ scan      YARA-X · multi-hash · archive descent · APK/IPA · rayon thread pool    │  │
│  │ apk       AXML decoder · v1/v2/v3/v3.1 signing block · cert SHA-256 · components  │  │
│  │ permissions  capability audit (combination rules, severity ≠ confidence)          │  │
│  │ android   adb inventory · dumpsys · settings · patch/root/boot/proxy (SHIELD)     │  │
│  │ ios       lockdown info · backup discovery · keybag + AES-KW + AES-CBC decrypt ·  │  │
│  │           Manifest.db · Safari/SMS URLs · DataUsage processes · profiles · JB     │  │
│  │ intel     IOC store · URLhaus/ThreatFox/Bazaar/STIX2/MISP/list · provenance       │  │
│  │ judol     INDONESIA_GAMBLING_THREAT_INTELLIGENCE · lexicon · mirrors · admin      │  │
│  │ urlcheck  PSL · IDN homograph · typosquat · brand-in-subdomain · redirects        │  │
│  │ forensic  cases · evidence (RO working copies) · custody hash-chain · timeline    │  │
│  │ ai        Isolation Forest (on-device) · evidence-grounded summary               │  │
│  │ pqc       Ed25519+ML-DSA-65 signatures · X25519+ML-KEM-768 → AES-256-GCM          │  │
│  │ report    risk score · history · HTML (→PDF in app) / JSON                        │  │
│  │ db        SQLite (WAL, 0600) · hash-chained audit log                             │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
│         │ external, optional (detected at runtime)                                     │
│         ▼                                                                              │
│  adb · idevice_id/ideviceinfo/idevicepair/idevicebackup2 · clamscan · apksigner ·      │
│  llama-server (localhost) · abuse.ch (user-triggered HTTPS)                            │
└────────────────────────────────────────────────────────────────────────────────────────┘
        USB / local Wi-Fi (official pairing only)
   ┌───────────────┐      ┌───────────────┐
   │ Android (ADB) │      │ iPhone (lockdown, Finder backup) │
   └───────────────┘      └───────────────┘
```

## Design decisions

1. **Swift UI + Rust engine over a process boundary.** Crash isolation (a malformed sample cannot take down the UI), easy universal builds (`lipo`), the engine is independently testable on CI without Xcode, and GPL/LGPL tools stay at arm's length.
2. **JSON envelope contract** `{ok, command, data, error, duration_ms, engine_version}` — see `API.md`. Contract tests in `app/Tests` decode envelopes captured from the real binary.
3. **Secrets never on argv or disk.** Backup passwords, PQC seed and API keys are written to the engine's stdin; the PQC seed and API keys live in the Keychain (`WhenUnlockedThisDeviceOnly`); backup passwords are not stored at all. Decrypted backup material is written only to a 0700 temp directory deleted after analysis.
4. **Severity and confidence are independent fields** on every finding. Single sensitive permissions are informational; only documented combinations raise risk. Gambling "CONFIRMED" requires a *verified* database indicator with evidence; heuristics top out at HIGH_RISK.
5. **Limitations are first-class findings** (`category=limitation`, `severity=NOT_ACCESSIBLE`) shown in a "Transparency — not examined" panel and excluded from the score, never reported as "clean".
6. **Forensic integrity:** original → SHA-256 → read-only working copy → re-hash → compare; directory digests are order-independent; every action appends to a per-evidence hash chain; app-wide actions append to a separate hash-chained audit log; both are verifiable.
7. **Crypto agility:** suite identifiers (`AD-SIG-1`, `AD-KEM-1`) are embedded in every signature/envelope so algorithms can be rotated without breaking old artefacts.
8. **No sandbox, Hardened Runtime.** The App Sandbox would forbid launching adb/libimobiledevice and reading `~/Library/Application Support/MobileSync`; reading Finder backups additionally requires the user to grant Full Disk Access.
9. **Performance:** rayon pool sized to logical CPUs (or user-set), per-thread YARA-X scanners, single read per file feeding hashing + YARA + ZIP parsing, SQLite file cache keyed by (path, size, mtime) for incremental scans, size caps per mode, measured benchmarks returned with every scan.

## Risk score

`score = 100 − Σ weight(severity) × factor(confidence) ÷ repeat_index(rule)`, floor 0; any CRITICAL finding with ≥HIGH confidence caps the score at 20.
Weights: CRITICAL 40 · HIGH 20 · MEDIUM 8 · LOW 3 · INFO/NOT_ACCESSIBLE 0. Factors: CONFIRMED 1.0 · HIGH 0.8 · MEDIUM 0.5 · LOW 0.25.
Ratings: ≥90 SECURE · 70–89 LOW RISK · 50–69 MODERATE · 25–49 HIGH · <25 CRITICAL.
