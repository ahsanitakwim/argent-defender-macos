# ARGENT DEFENDER
### ADVANCED CYBER INTELLIGENCE & DIGITAL FORENSICS
**DEFEND THE DIGITAL. REVEAL THE TRUTH.**

<img src="branding/argent_icon_1024.png" width="160" alt="ARGENT DEFENDER">

Aplikasi native macOS (Intel & Apple Silicon) yang menjadikan MacBook pusat pemeriksaan keamanan, analisis malware, dan forensik digital untuk perangkat **iPhone** dan **Android** — local-first, transparan terhadap batasan iOS/Android, dan berbasis bukti.

## Struktur proyek

```
ArgentDefender/
├── app/                 SwiftUI macOS app (Package.swift — buka di Xcode)
│   ├── Sources/ArgentDefender/{App,Core,Views,Resources}
│   └── Tests/ArgentDefenderTests (kontrak JSON vs output engine asli)
├── engine/              Rust engine `argent-engine` (YARA-X, APK, iOS backup, intel, forensik, PQC, SQLite)
│   ├── src/*.rs         16 modul + schema.sql
│   └── rules/*.yar      Rule YARA-X bawaan (EICAR, perilaku Android, judol)
├── branding/            Ikon .icns / AppIcon.appiconset / logo / latar DMG (dari logo Anda)
├── packaging/           Info.plist, entitlements (Hardened Runtime)
├── scripts/             build_macos.sh (test → universal → sign → notarize → DMG), install_dependencies.sh
├── docs/                AUDIT · ARCHITECTURE · API · DATABASE · INSTALL · TESTING · BENCHMARK ·
│                        THIRD_PARTY_LICENSES · PRIVACY_POLICY · RELEASE_NOTES · sample-report.html
└── .github/workflows/   CI (Linux engine tests + macOS build/DMG)
```

## Mulai cepat

```bash
scripts/install_dependencies.sh     # adb, libimobiledevice, ClamAV (opsional)
scripts/build_macos.sh              # menghasilkan dist/ARGENT-DEFENDER-1.0.0.dmg
```
Engine juga dapat dipakai langsung: `engine/target/release/argent-engine --help`.

## Modul

| Modul | Isi | Status |
|---|---|---|
| ARGENT SCAN | Quick / Full / Deep / Custom / Incremental, YARA-X paralel, hash intel, benchmark terukur | ✅ Teruji |
| ARGENT DEVICE MANAGER | Deteksi Android (ADB USB/Wi-Fi) & iPhone (lockdown), status pairing, riwayat perangkat | ⚠️ Belum diuji di perangkat nyata |
| Android Scanner | Inventaris aplikasi, audit izin, accessibility/overlay/device-admin, patch, root, boot, proxy; mode Standard & Advanced Forensic (tarik APK) | ⚠️ Parser teruji; perangkat nyata belum |
| iPhone Scanner | A. Device Audit · B. Backup Forensics (termasuk **backup terenkripsi**) · C. Analisis IPA | ✅ Backup (sintetis) teruji · ⚠️ perangkat nyata belum |
| ARGENT MALWARE ENGINE | YARA-X, heuristik, statik APK, sertifikat, hash intel, ClamAV opsional | ✅ (ClamAV ⚠️) |
| ARGENT GAMING WATCH | Basis data INDONESIA_GAMBLING_THREAT_INTELLIGENCE, admin, mirror, heuristik leksikon | ✅ Teruji (database dikirim kosong — tanpa indikator karangan) |
| ARGENT NETWORK | Phishing, typosquatting, homograph IDN, brand-in-subdomain, redirect, korelasi intel | ✅ (redirect online ⚠️) |
| ARGENT FORENSIC | Kasus, evidence read-only, SHA-256, chain of custody berantai-hash, catatan, timeline | ✅ Teruji |
| ARGENT INTEL | URLhaus, ThreatFox, MalwareBazaar, STIX2/MVT, MISP JSON, daftar; provenance & lisensi | ✅ Importer · ⚠️ update online |
| ARGENT AI | Isolation Forest on-device, korelasi multi-engine, ringkasan berbasis bukti, llama.cpp lokal / cloud opt-in | ✅ Anomali · ⚠️ LLM |
| ARGENT SHIELD | Penilaian konfigurasi; severity & confidence terpisah; NOT ACCESSIBLE eksplisit | ✅ |
| QUANTUM-READY | Ed25519 + ML-DSA-65 (FIPS 204), X25519 + ML-KEM-768 (FIPS 203) → AES-256-GCM, suite agility | ✅ Teruji |
| ARGENT REPORT | Skor risiko, HTML/JSON bertanda tangan, PDF via WebKit | ✅ HTML/JSON · ⚠️ PDF (macOS) |
| ARGENT ADMIN | Rule YARA, indikator intel/judol, integrasi, kunci, log audit | ✅ |

**Penting — status kejujuran:** aplikasi SwiftUI ditulis di host Linux tanpa Xcode, sehingga **belum pernah dikompilasi**; sintaks tervalidasi (tree-sitter), tetapi kompilasi pertama di Mac kemungkinan memerlukan sedikit perbaikan. Detail lengkap di `docs/TESTING.md` dan `docs/AUDIT.md`.

## Batasan yang ditampilkan transparan di aplikasi
- iOS: pairing/backup **tidak** membuka seluruh filesystem, semua aplikasi, proses, atau lalu lintas jaringan. Tidak ada jailbreak/bypass sandbox. Tidak ditemukan indikator ≠ bebas malware.
- Android: tanpa root, data privat aplikasi dan partisi sistem tidak dapat dibaca; ARGENT DEFENDER tidak me-root dan tidak mem-bypass proteksi.
- Izin sensitif tunggal tidak pernah dianggap berbahaya; game biasa tidak pernah diklasifikasikan judi tanpa bukti.


## macOS compatibility (1.0.1)

This source targets macOS 12.0 and later. Navigation and row-grid presentation include macOS 12-compatible layouts. Universal Intel and Apple Silicon packaging is configured by `scripts/build_macos.sh`. Build and runtime compatibility must be verified through CI and testing on supported macOS versions.


## macOS 12 SwiftUI compatibility update (1.0.2)

The Overview dashboard uses native SwiftUI progress indicators instead of the macOS 13 Charts framework APIs. The AI question field uses the macOS 12-compatible TextField initializer. This removes the specific macOS 13-only APIs identified in the previous CI compiler log. Full build and runtime compatibility still require CI and device verification.
