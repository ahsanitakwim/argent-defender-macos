# Release Notes

## 1.0.0 — 10 November 2026 (Phase 1 foundation release candidate)

### Delivered
- Native SwiftUI macOS app (16 sections, dark/light mode, splash, notification centre, search/filter, charts, export) using the user-supplied AD shield logo as app icon, splash, sidebar and report branding.
- Rust engine `argent-engine` 1.0.0 (universal-build ready): YARA-X scanning (Quick/Full/Deep/Custom/Incremental), native APK analysis (AXML, v1–v3.1 signing, certificates), permission/capability audit, Android ADB audit (Standard & Advanced Forensic modes), iPhone device audit, local & **encrypted** backup forensics, threat-intel store with 6 importers + online updater, Gaming Watch database & heuristics, URL/phishing analysis, digital forensics with chain of custody, on-device Isolation-Forest anomaly detection, hybrid post-quantum signatures/encryption, risk scoring, history, signed HTML/JSON reports (PDF via WebKit in the app), tamper-evident audit log.
- 34 automated engine tests (all passing), Swift contract tests against real engine output, CI workflow, build/sign/notarize/DMG script, full documentation.

### Known limitations (transparent)
- The macOS app has **not yet been compiled** — it was authored on a Linux host without Xcode. Expect a short fix-up pass on first `swift build`.
- Not yet validated on real Android/iPhone hardware, real encrypted Finder backups, ClamAV, apksigner, abuse.ch online endpoints, or llama.cpp.
- Not integrated: MobSF, Quark-Engine, capa, Hypatia, MITRE ATT&CK mapping, ONNX/Core ML classifier, PCAP parsing (nDPI/Zeek). See `docs/AUDIT.md`.
- Gaming Watch and intel databases ship **empty** by design (no fabricated indicators).
- APK labels that are resource references (`@0x7f…`) are not resolved (resources.arsc parsing pending).
