# Testing & Quality Assurance

## How to run

```bash
cd engine && cargo test --release          # Rust engine (runs on macOS and Linux)
cd app && swift test                        # Swift contract tests (macOS, Xcode 15+)
scripts/build_macos.sh                      # full pipeline: tests → universal build → sign → DMG
```

CI: `.github/workflows/build.yml` runs both suites and builds the DMG on a GitHub-hosted macOS runner.

## Evidence — engine test run (10 Nov 2026, Linux x86_64 build host)

```
test ai::tests::isolation_forest_finds_outlier ... ok
test android::tests::parses_adb_devices ... ok
test android::tests::parses_pm_and_dumpsys ... ok
test android::tests::parses_settings_and_admins ... ok
test android::tests::patch_age_and_root ... ok
test apk::tests::decodes_manifest_components ... ok
test apk::tests::rejects_non_apk ... ok
test db::tests::audit_chain_detects_tamper ... ok
test forensic::tests::ts_norm ... ok
test hashing::tests::known_vectors ... ok
test intel::tests::classifies ... ok
test intel::tests::imports_and_matches ... ok
test forensic::tests::evidence_lifecycle_and_tamper_detection ... ok
test ios::tests::encrypted_backup_roundtrip_and_wrong_password ... ok
test ios::tests::kv_parse ... ok
test ios::tests::backup_analysis_flags_jailbreak_and_url ... ok
test judol::tests::heuristics_and_db ... ok
test judol::tests::ordinary_games_not_flagged ... ok
test permissions::tests::hidden_stalkerware_is_critical ... ok
test permissions::tests::overlay_plus_accessibility_is_high ... ok
test permissions::tests::single_sensitive_permission_is_informational ... ok
test pqc::tests::hybrid_kem_roundtrip ... ok
test pqc::tests::hybrid_sign_verify_and_tamper ... ok
test report::tests::html_escapes ... ok
test report::tests::scoring ... ok
test ios::tests::unencrypted_backup_flags_missing_encryption ... ok
test scan::tests::bundled_rules_compile ... ok
test scan::tests::bad_user_rule_is_reported_not_fatal ... ok
test scan::tests::eicar_detected_and_clean_file_clean ... ok
test urlcheck::tests::extract ... ok
test urlcheck::tests::homograph ... ok
test urlcheck::tests::legit_domains_clean ... ok
test urlcheck::tests::typosquat_and_brand_sub ... ok
test scan::tests::eicar_inside_apk_and_intel_hash_and_incremental ... ok
test result: ok. 34 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

| Area | Tests | What is proven |
|---|---|---|
| Hashing | `known_vectors` | SHA-256/SHA-1/MD5 against published "abc" vectors |
| YARA-X / EICAR | `bundled_rules_compile`, `eicar_detected_and_clean_file_clean`, `eicar_inside_apk_and_intel_hash_and_incremental`, `bad_user_rule_is_reported_not_fatal` | EICAR detected as file and inside an APK; clean file produces no alert; Telegram-bot SMS-stealer pattern fires on DEX; intel hash correlation; incremental cache skips unchanged files; a broken admin rule is isolated |
| APK | `decodes_manifest_components`, `rejects_non_apk` | AXML decoding, launcher/accessibility detection, DEX/native-lib inventory |
| Real-world APK (manual) | PCAPdroid 1.8.4 from GitHub releases | Package/version/SDKs, v1+v2 signing, certificate SHA-256 `ac701125…c9fe` and 29 components **match androguard**; zero false positives (score 100) |
| Permission audit (false-positive control) | `single_sensitive_permission_is_informational`, `overlay_plus_accessibility_is_high`, `hidden_stalkerware_is_critical` | Sensitive permissions alone are never treated as malicious |
| Android ADB parsing | 4 tests | `adb devices -l`, `pm list`, `dumpsys package`, accessibility/device-admin settings, patch-age & root indicators |
| iPhone backups | `encrypted_backup_roundtrip_and_wrong_password`, `backup_analysis_flags_jailbreak_and_url`, `unencrypted_backup_flags_missing_encryption`, `kv_parse` | Keybag (PBKDF2-SHA256→PBKDF2-SHA1), RFC 3394 unwrap, Manifest.db + per-file AES-CBC decryption, wrong password rejected, jailbreak & phishing URL found, limitation always reported |
| Threat intel | `imports_and_matches`, `classifies` | URLhaus/ThreatFox/STIX2(MVT) import, parent-domain & IP matching, provenance |
| Gaming Watch | `ordinary_games_not_flagged`, `heuristics_and_db` | Mobile Legends, Clash of Clans, Subway Surfers, WhatsApp, DANA, Gojek not flagged; unverified CONFIRMED is downgraded; mirror-domain detection; evidence required |
| URL / phishing | 4 tests | Legit sites clean; typosquat (`klikbcca.com`), brand-in-subdomain, IDN homograph (`аpple.com`), URL extraction |
| Forensics | `evidence_lifecycle_and_tamper_detection`, `ts_norm` | Original untouched, working copy verified, tampering of copy **and** of custody log detected, timestamp normalisation |
| Audit log | `audit_chain_detects_tamper` | Hash chain detects modified entry and locates it |
| AI | `isolation_forest_finds_outlier` | Planted stalkerware-like profile ranked #1, no false outliers, deterministic |
| PQC | `hybrid_sign_verify_and_tamper`, `hybrid_kem_roundtrip` | Ed25519+ML-DSA-65 verify; content/sig/key tampering rejected; X25519+ML-KEM-768 round-trip; wrong key rejected |
| Risk & report | `scoring`, `html_escapes` | Score formula, diminishing repeats, CRITICAL cap; HTML injection escaped |

## End-to-end CLI run (same host)

`env`, `scan` (EICAR + real APK + text), `url` (4 URLs), `judol add/verify/check`, `intel import/lookup`, `case create`, `evidence add/analyze/verify`, `case timeline`, `report --sign` (HTML), `pqc pubkey/sign/verify` (+ tamper → rejected), `pqc encrypt/decrypt` (byte-identical), `audit-verify` (intact) — all succeeded.

## NOT yet tested (requires a Mac and devices)

| Item | Why not tested here | How to test |
|---|---|---|
| Compiling/running the SwiftUI app, UI tests | No Xcode/macOS on build host | `swift test`, then `scripts/build_macos.sh`, manual UI walkthrough |
| Intel vs Apple Silicon binaries | Linux host | Run DMG on both; `lipo -info` is printed by the build script |
| Live Android (USB / Wi-Fi ADB) | No device | Test phone with USB debugging; compare `android audit` with Settings |
| Live iPhone pairing / backup creation | No device | Trusted iPhone + libimobiledevice |
| Real Finder backups (encrypted) | Synthetic only | Make an encrypted backup of a test iPhone |
| ClamAV, apksigner adapters | Not installed | `brew install clamav`; Android SDK build-tools |
| Online abuse.ch update, redirect tracing, llama-server | Network policy | Run on a normal network |
| PDF export (WebKit) | Needs macOS | Export from Security Reports |
| Memory profiling with Instruments | Needs macOS | Instruments › Allocations during Deep Scan |

Malware testing policy: only the EICAR test string and synthetic pattern fixtures were used; no live malware was executed. Further detection validation should use an isolated lab VM with samples from MalwareBazaar under its terms.
