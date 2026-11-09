#!/bin/bash
# Builds dist/Wazuh.app from the Swift package and the bundled official wazuh-docker stack.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-4.14.10}"
APP="dist/Wazuh.app"
# The newest Command Line Tools SDK requires SwiftUI macro plugins only shipped with Xcode;
# fall back to the newest SDK that builds without them when Xcode is absent.
if [ -z "${SDKROOT:-}" ] && ! xcode-select -p | grep -q Xcode.app; then
  for sdk in /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk /Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk; do
    [ -d "$sdk" ] && export SDKROOT="$sdk" && break
  done
fi

swift build -c release --arch arm64
BIN="$(swift build -c release --arch arm64 --show-bin-path)/WazuhMac"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Wazuh"
cp -R Resources/stack "$APP/Contents/Resources/stack"
rm -rf "$APP/Contents/Resources/stack/config/wazuh_indexer_ssl_certs"

# Icon
ICONSET="$(mktemp -d)/AppIcon.iconset"; mkdir -p "$ICONSET"
swift scripts/make_icon.swift scripts/assets/logo.json "$ICONSET/icon_512x512@2x.png"
for s in 16 32 128 256 512; do
  sips -z $s $s "$ICONSET/icon_512x512@2x.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  d=$((s*2)); sips -z $d $d "$ICONSET/icon_512x512@2x.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Wazuh</string>
  <key>CFBundleDisplayName</key><string>Wazuh</string>
  <key>CFBundleExecutable</key><string>Wazuh</string>
  <key>CFBundleIdentifier</key><string>io.github.aadhaar-debug.wazuhmac</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>Wazuh © Wazuh, Inc. (GPLv2). Unofficial macOS packaging.</string>
</dict>
</plist>
PLIST

codesign --force --deep --sign - "$APP"
echo "Built $APP"
