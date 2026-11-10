#!/usr/bin/env bash
# ARGENT DEFENDER — build, test, sign and package for macOS (Intel + Apple Silicon).
#
# Usage:  scripts/build_macos.sh [--skip-tests]
# Env:    CODESIGN_IDENTITY="Developer ID Application: Name (TEAMID)"   (optional; ad-hoc otherwise)
#         NOTARY_PROFILE=<notarytool keychain profile>                  (optional; notarize + staple)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' engine/Cargo.toml | head -1)
OUT="$ROOT/dist"; APP="$OUT/ARGENT DEFENDER.app"
SKIP_TESTS=0; [[ "${1:-}" == "--skip-tests" ]] && SKIP_TESTS=1

say() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
need() { command -v "$1" >/dev/null || { echo "Missing $1. $2"; exit 1; }; }

say "Environment audit"
[[ "$(uname)" == "Darwin" ]] || { echo "This script must run on macOS."; exit 1; }
sw_vers; uname -m; sysctl -n machdep.cpu.brand_string || true
need xcrun "Install Xcode or the Command Line Tools: xcode-select --install"
need swift "Install Xcode 15+ (Swift 5.9+)"
need cargo "Install Rust: https://rustup.rs"
swift --version
rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null

say "Rust engine (universal)"
export MACOSX_DEPLOYMENT_TARGET=11.0
( cd engine
  [[ $SKIP_TESTS == 1 ]] || cargo test --release
  cargo build --release --target aarch64-apple-darwin
  cargo build --release --target x86_64-apple-darwin )
mkdir -p "$OUT"
lipo -create -output "$OUT/argent-engine" \
  engine/target/aarch64-apple-darwin/release/argent-engine \
  engine/target/x86_64-apple-darwin/release/argent-engine
lipo -info "$OUT/argent-engine"

say "SwiftUI application (universal)"
( cd app
  if [[ $SKIP_TESTS == 0 ]]; then ARGENT_ENGINE="$OUT/argent-engine" swift test; fi
  if swift build -c release --arch arm64 --arch x86_64 2>/dev/null; then
     BIN="$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)/ArgentDefender"
  else
     echo "Universal swift build unavailable (needs full Xcode) — building per-arch and merging"
     swift build -c release --triple arm64-apple-macosx12.0
     swift build -c release --triple x86_64-apple-macosx12.0
     lipo -create -output .build/ArgentDefender-universal \
        "$(swift build -c release --triple arm64-apple-macosx12.0 --show-bin-path)/ArgentDefender" \
        "$(swift build -c release --triple x86_64-apple-macosx12.0 --show-bin-path)/ArgentDefender"
     BIN="$PWD/.build/ArgentDefender-universal"
  fi
  cp "$BIN" "$OUT/ArgentDefender.bin" )

say "Assemble .app bundle"
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/licenses"
cp "$OUT/ArgentDefender.bin" "$APP/Contents/MacOS/ArgentDefender"
cp "$OUT/argent-engine" "$APP/Contents/MacOS/argent-engine"
cp packaging/Info.plist "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP/Contents/Info.plist"
cp branding/ArgentDefender.icns "$APP/Contents/Resources/ArgentDefender.icns"
cp app/Sources/ArgentDefender/Resources/ArgentLogo.png "$APP/Contents/Resources/ArgentLogo.png"
cp docs/THIRD_PARTY_LICENSES.md docs/PRIVACY_POLICY.md "$APP/Contents/Resources/licenses/"
chmod +x "$APP/Contents/MacOS/"*

say "Code signing"
ID="${CODESIGN_IDENTITY:--}"
SIGN=(codesign --force --options runtime --timestamp --entitlements packaging/ArgentDefender.entitlements -s "$ID")
[[ "$ID" == "-" ]] && SIGN=(codesign --force --options runtime --entitlements packaging/ArgentDefender.entitlements -s -)
"${SIGN[@]}" "$APP/Contents/MacOS/argent-engine"
"${SIGN[@]}" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
[[ "$ID" == "-" ]] && echo "NOTE: ad-hoc signature (no Developer ID). First launch: right-click › Open, or System Settings › Privacy & Security › Open Anyway."

say "Smoke test"
"$APP/Contents/MacOS/argent-engine" --db "$OUT/smoke.db" env >/dev/null && echo "engine OK"
rm -f "$OUT/smoke.db"*

say "DMG"
STAGE="$OUT/dmg"; rm -rf "$STAGE"; mkdir -p "$STAGE/.background"
cp -R "$APP" "$STAGE/"; ln -s /Applications "$STAGE/Applications"
cp branding/dmg_background.png "$STAGE/.background/background.png"
DMG="$OUT/ARGENT-DEFENDER-$VERSION.dmg"; rm -f "$DMG"
if command -v create-dmg >/dev/null; then
  rm -rf "$STAGE/Applications" "$STAGE/.background"
  create-dmg --volname "ARGENT DEFENDER" --volicon branding/ArgentDefender.icns --background branding/dmg_background.png \
    --window-size 660 400 --icon-size 110 --icon "ARGENT DEFENDER.app" 170 230 --app-drop-link 490 230 "$DMG" "$STAGE"
else
  hdiutil create -volname "ARGENT DEFENDER" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
fi
[[ "$ID" != "-" ]] && codesign -s "$ID" --timestamp "$DMG"
if [[ -n "${NOTARY_PROFILE:-}" && "$ID" != "-" ]]; then
  say "Notarization"
  xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$DMG"
fi
shasum -a 256 "$DMG" | tee "$DMG.sha256"
say "Done → $DMG"
