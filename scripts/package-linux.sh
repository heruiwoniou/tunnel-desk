#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
npm run build
npm run tauri build -- --bundles deb
echo "Debian package is under src-tauri/target/release/bundle/deb"
