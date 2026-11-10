#!/usr/bin/env bash
# Optional device & analysis tools used by ARGENT DEFENDER (Homebrew). All are optional:
# a missing tool disables only its feature.
set -euo pipefail
command -v brew >/dev/null || { echo "Install Homebrew first: https://brew.sh"; exit 1; }
brew install libimobiledevice ideviceinstaller          # iPhone pairing, info, backups
brew install --cask android-platform-tools               # adb
brew install clamav || true                              # secondary malware engine
[ -f "$(brew --prefix)/etc/clamav/freshclam.conf" ] || cp "$(brew --prefix)/etc/clamav/freshclam.conf.sample" "$(brew --prefix)/etc/clamav/freshclam.conf" && sed -i '' 's/^Example/#Example/' "$(brew --prefix)/etc/clamav/freshclam.conf" || true
freshclam || true
brew install jadx apktool || true                        # analyst review tools
echo "Optional: Android SDK build-tools (apksigner) via Android Studio; llama.cpp: brew install llama.cpp"
