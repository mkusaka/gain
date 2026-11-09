#!/usr/bin/env bash
# Assemble OUT_DIR/Gain.app: the universal menu bar app (app/Gain.swift) with the given, already
# signed, gain binary as Contents/Helpers/gain (Helpers, not MacOS: "Gain" and "gain" collide on a
# case-insensitive volume). The app itself is left unsigned: sign it after, without --deep.
# Usage: scripts/build-app.sh path/to/gain OUT_DIR [VERSION]
set -euo pipefail
GAIN=$1 OUT=$2 VERSION=${3:-0.0.0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
APP=$OUT/Gain.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Helpers"
for arch in arm64 x86_64; do
  swiftc -O -parse-as-library -target "$arch-apple-macos13" "$ROOT/app/Gain.swift" -o "$OUT/Gain-$arch"
done
lipo -create "$OUT/Gain-arm64" "$OUT/Gain-x86_64" -output "$APP/Contents/MacOS/Gain"
rm "$OUT/Gain-arm64" "$OUT/Gain-x86_64"
cp "$GAIN" "$APP/Contents/Helpers/gain"
cat >"$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.github.mkusaka.gain</string>
  <key>CFBundleName</key><string>Gain</string>
  <key>CFBundleExecutable</key><string>Gain</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
</dict></plist>
EOF
