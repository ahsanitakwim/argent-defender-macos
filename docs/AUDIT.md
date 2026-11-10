# ARGENT DEFENDER — Audit Report & Integration Architecture (Phase 1)

Date: 10 November 2026 · Engine 1.0.0

## 1. Source-code & repository audit

| Item | Finding |
|---|---|
| Existing source code | None supplied. No legacy code, no SPECTRE remnants to migrate. Project created from scratch under the ARGENT DEFENDER name only. |
| Brand assets | User-supplied logo (shield + eagle + "AD" monogram + circuit lines, 344×338 px PNG). Converted to a macOS icon set (16–1024 px), `.icns`, splash/report logo and DMG background (`branding/`). **Recommendation:** supply a ≥1024 px vector/PNG master — the current icon is upscaled ~2.4× from the screenshot and is slightly soft at 512 pt @2x. |

## 2. Development-environment audit (this build session)

| Check | Result | Consequence |
|---|---|---|
| Host OS | Linux x86_64 (Ubuntu 24.04), 2 vCPU, 8 GB RAM | **Not a Mac.** |
| Xcode / Swift toolchain | Not available; download.swift.org blocked by network policy | SwiftUI app **was written but could not be compiled or run here**. Syntax was validated with tree-sitter-swift (all 19 files parse cleanly); type-checking happens on first `swift build` on a Mac. |
| Rust 1.97 / Cargo | Available; crates.io reachable | Engine built, all tests run here. |
| Android device / ADB | No device, no adb | ADB parsers tested with captured-format fixtures only; live device path untested. |
| iPhone / libimobiledevice | No device, no tools | Pairing/backup-creation path untested; backup *analysis* (incl. encryption) tested with synthetic backups built in Apple's exact keybag format. |
| ClamAV, apksigner, Quark, JADX, Apktool, ipsw, tshark, Zeek | Not installed | Adapters detect absence and degrade gracefully (verified). |
| Internet beyond package registries | Blocked (except GitHub release downloads) | Online abuse.ch update and redirect tracing are implemented but **not exercised**. |

Adaptive compatibility implemented in the engine (`argent-engine env`): CPU architecture, OS version, CPU model, logical CPUs, RAM, Apple-Silicon flag, presence/version of every external tool. Missing tools disable only their feature.

## 3. Upstream repository audit & selection

Licence facts are from the projects' published licences as known at audit time; re-verify before redistribution. "Integrated" means implemented **and** exercised by tests in this session.

| Repository | Licence | Decision | Status |
|---|---|---|---|
| VirusTotal/yara-x | BSD-3-Clause | **Embedded** as the signature engine (Rust crate, in-process, per-thread scanners, 60 s timeout). | ✅ Integrated & tested (EICAR, DEX rules, user rules, broken-rule isolation) |
| VirusTotal/yara | BSD-3-Clause | Not linked; YARA-X compiles the same rule language. | Not needed |
| libimobiledevice | LGPL-2.1 | Invoked as external CLIs (`idevice_id`, `ideviceinfo`, `idevicepair`, `idevicebackup2`) — process boundary keeps LGPL obligations simple. | ⚠️ Implemented, untested on hardware |
| Android platform-tools (ADB) | Apache-2.0 | External CLI. | ⚠️ Implemented; parsers unit-tested; untested on hardware |
| androguard | Apache-2.0 | Used as an **independent oracle** to validate the native Rust APK parser on a real APK (PCAPdroid 1.8.4): package, versions, signing schemes, certificate SHA-256 and component counts match; our parser additionally captures `uses-permission-sdk-23` entries androguard's `get_permissions()` omitted. Not shipped (avoids bundling Python). | ✅ Validation |
| Cisco-Talos ClamAV (link given: clamwin/clamav fork) | GPL-2.0 | Optional external `clamscan` adapter; never linked. | ⚠️ Implemented, untested (not installed here) |
| MobSF | GPL-3.0 | Not integrated in v1. Heavy server (Django + JADX + Java). Candidate: optional REST adapter to a user-run local MobSF instance. | ❌ Not integrated |
| Quark-Engine | GPL-3.0 | Detected only (`env`). Candidate: external adapter consuming `quark -s -o json`. | ❌ Not integrated |
| JADX, Apktool | Apache-2.0 | Detected only; analyst tools, not detection engines. | ❌ Not integrated |
| Hypatia | GPL-3.0 | Not integrated: it is an on-device Android scanner whose signature databases are served by its own infrastructure; equivalent coverage via MalwareBazaar/ClamAV hashes. | ❌ Not applicable |
| mandiant/capa | Apache-2.0 | Not integrated: targets PE/ELF/.NET; could later analyse native `.so` inside APKs. | ❌ Not integrated |
| blacktop/ipsw | MIT | Detected only. | ❌ Not integrated |
| OWASP MASTG | CC-BY-SA-4.0 | Methodology reference for checks (debuggable, cleartext, signing, exported components, permissions). | Reference |
| abuse.ch URLhaus / ThreatFox / MalwareBazaar | Data under abuse.ch terms (CC0) | Native CSV importers + online updater with SHA-256 provenance. | ✅ Importers tested · ⚠️ online fetch untested |
| MISP | AGPL-3.0 | MISP **event JSON format** importer (no live MISP API). | ✅ Format importer |
| OpenCTI | Apache-2.0 | Covered through STIX 2.x import (OpenCTI exports STIX). No live API. | ✅ Format importer |
| mitre/cti (ATT&CK) | ATT&CK terms of use | Not imported in v1. | ❌ Not integrated |
| PCAPdroid, Wireshark, Zeek, nDPI | GPL-3.0 / GPL-2.0 / BSD-3 / LGPL-3.0 | Workflow integration only: captures are acquired as forensic evidence and hashed/scanned; no PCAP protocol parsing in v1. `tshark`/`zeek` are detected. | ❌ Not integrated (parsing) |
| microsoft/onnxruntime, Core ML | MIT / Apple | Not used: no validated trained model exists yet, and shipping an unvalidated classifier would violate "no fabricated detections". | ❌ Not integrated |
| pyod, scikit-learn | BSD-2 / BSD-3 | Their Isolation Forest algorithm is **re-implemented natively in Rust** (deterministic seed, explanations) — no Python runtime. | ✅ Algorithm implemented & tested |
| ggml-org/llama.cpp | MIT | Client for the local `llama-server` OpenAI-compatible endpoint (narrative only). | ⚠️ Implemented, untested |
| open-quantum-safe/liboqs, oqs-provider | MIT | Evaluated; not chosen (C toolchain + universal-binary complexity). | Evaluated |
| bcgit/bc-java | MIT | Not applicable (JVM). | Evaluated |
| RustCrypto `ml-kem`, `ml-dsa` | Apache-2.0 / MIT | **Chosen**: pure Rust, FIPS 203/204 final; hybridised with X25519/Ed25519 so a PQ implementation flaw cannot lower classical security. Not independently audited — disclosed. | ✅ Integrated & tested |
| Apple CryptoKit | Apple | Recommended future backend for PQ primitives on macOS versions that provide them, behind the same suite IDs (crypto agility). | Planned |

## 4. Resulting integration architecture

See `ARCHITECTURE.md`. Summary: native SwiftUI app ⇄ (JSON over stdio, secrets over stdin) ⇄ Rust engine (YARA-X, APK/AXML, iOS backup + keybag crypto, intel, Gaming Watch, URL analysis, forensics, Isolation Forest, hybrid PQC, SQLite) ⇄ optional external tools (adb, libimobiledevice, ClamAV, apksigner, llama-server).
