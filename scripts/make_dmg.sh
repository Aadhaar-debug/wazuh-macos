#!/bin/bash
# Packages dist/Wazuh.app into dist/Wazuh-<version>-arm64.dmg (drag-to-Applications layout).
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:-4.14.10}"
DMG="dist/Wazuh-${VERSION}-macOS-arm64.dmg"
STAGE="$(mktemp -d)/Wazuh"
mkdir -p "$STAGE"
cp -R dist/Wazuh.app "$STAGE/"
ln -s /Applications "$STAGE/Applications"
rm -f "$DMG"
hdiutil create -volname "Wazuh ${VERSION}" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
shasum -a 256 "$DMG" | tee "$DMG.sha256"
