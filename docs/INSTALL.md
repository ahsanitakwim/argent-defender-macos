# Instalasi ARGENT DEFENDER

## A. Pengguna (DMG)
1. Buka `ARGENT-DEFENDER-<versi>.dmg`, seret **ARGENT DEFENDER** ke **Applications**.
2. Jika aplikasi ditandatangani ad-hoc (tanpa Developer ID): klik kanan › **Open**, atau System Settings › Privacy & Security › **Open Anyway**.
3. Untuk membaca backup iPhone dari Finder: System Settings › Privacy & Security › **Full Disk Access** › tambahkan ARGENT DEFENDER.
4. Pasang alat perangkat (opsional, per fitur):
   ```bash
   scripts/install_dependencies.sh      # libimobiledevice, adb, ClamAV, jadx, apktool
   ```
   Alat yang tidak terpasang hanya menonaktifkan fitur terkait — aplikasi tetap berjalan.

**Kebutuhan sistem:** macOS 13 Ventura atau lebih baru (SwiftUI Charts/NavigationSplitView), Intel atau Apple Silicon (Universal Binary). Engine CLI sendiri berjalan di macOS 11+.

## B. Android
1. Settings › About phone › ketuk *Build number* 7× → Developer options.
2. Aktifkan **USB debugging**, sambungkan USB, ketuk **Allow** pada dialog RSA.
3. Wi-Fi (Android 11+): Developer options › *Wireless debugging* › *Pair device with pairing code*, lalu `adb pair IP:PORT` dan `adb connect IP:PORT`.
4. Setelah pemeriksaan, matikan kembali USB/Wireless debugging.

## C. iPhone
1. Sambungkan USB, buka kunci iPhone, ketuk **Trust This Computer**.
2. Untuk analisis terlengkap, aktifkan **Encrypt local backup** di Finder lalu buat backup (atau gunakan tombol *Create Local Backup* di aplikasi). Simpan kata sandinya — Apple tidak dapat memulihkannya.
3. Opsi Wi-Fi: di Finder centang *Show this iPhone when on Wi-Fi*.

## D. Developer (build dari source)
```bash
xcode-select --install                      # atau Xcode 15+
curl https://sh.rustup.rs -sSf | sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
scripts/build_macos.sh                      # test → universal build → sign → DMG di dist/
# Opsional: CODESIGN_IDENTITY="Developer ID Application: …" NOTARY_PROFILE=<profil> scripts/build_macos.sh
```
Pengembangan UI: buka folder `app/` di Xcode (Package.swift). Saat dijalankan dari Xcode, aplikasi otomatis menemukan `engine/target/release/argent-engine` (jalankan `cargo build --release` di `engine/` terlebih dahulu) atau gunakan variabel `ARGENT_ENGINE`.

## E. AI lokal (opsional)
```bash
brew install llama.cpp
llama-server -m <model.gguf> --port 8080     # endpoint default di Settings
```
