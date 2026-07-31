#!/usr/bin/env bash
# Builds a native macOS installer: SENTRYX.pkg — double-click, Apple's own
# installer chrome (Introduction / Destination / Installation Type /
# Summary), shows up in Finder as a proper installer, no Terminal needed.
#
# Usage (run on a Mac, or in CI with macOS runners):
#   ./build_pkg.sh
#
# Requires: sentryxd-darwin-<arch>, sxctl-darwin-<arch>,
# sentryx-setup-darwin-<arch>, sentryx-dashboard-darwin-<arch> already
# built (e.g. via `make dist` from the repo root) and sitting in ../../dist/

set -euo pipefail

ARCH="${1:-arm64}"   # pass amd64 for Intel Macs
# VERSION is the git tag (e.g. "v1.0.2") passed in by release.yml; macOS
# CFBundleVersion/pkgbuild --version both expect a bare numeric-ish string,
# so strip the leading "v". Falls back to "1.0" for a manual local run
# where VERSION isn't set at all (checked first so `set -u` doesn't choke
# on an unset var before the fallback kicks in).
RAW_VERSION="${VERSION:-1.0}"
PKG_VERSION="${RAW_VERSION#v}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST="$REPO_ROOT/dist"
WORK="$(mktemp -d)"
PKG_ROOT="$WORK/root/usr/local/sentryx"
SCRIPTS_DIR="$WORK/scripts"

mkdir -p "$PKG_ROOT" "$SCRIPTS_DIR"

cp "$DIST/sentryxd-darwin-$ARCH"       "$PKG_ROOT/sentryxd"
cp "$DIST/sxctl-darwin-$ARCH"          "$PKG_ROOT/sxctl"
cp "$DIST/sentryx-setup-darwin-$ARCH"  "$PKG_ROOT/sentryx-setup"
chmod +x "$PKG_ROOT"/*

# --- SENTRYX Dashboard.app -------------------------------------------
# A real, minimal .app bundle wrapping sentryx-dashboard, so the operator
# has a normal Finder/Launchpad/Dock icon to click *after* setup — the
# "like Blender" ask: an installed app, not a bookmark to
# http://localhost:9090.
DASH_APP="$WORK/root/Applications/SENTRYX Dashboard.app"
mkdir -p "$DASH_APP/Contents/MacOS" "$DASH_APP/Contents/Resources"
cp "$DIST/sentryx-dashboard-darwin-$ARCH" "$DASH_APP/Contents/MacOS/sentryx-dashboard"
chmod +x "$DASH_APP/Contents/MacOS/sentryx-dashboard"

# Branded icon: AppIcon.iconset (checked into this folder, pre-rendered
# from the logo) gets compiled into a real .icns with the same tool
# Xcode itself uses — no design app needed, this always runs on a Mac.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
iconutil -c icns "$SCRIPT_DIR/AppIcon.iconset" -o "$DASH_APP/Contents/Resources/AppIcon.icns"

cat > "$DASH_APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>SENTRYX Dashboard</string>
  <key>CFBundleIdentifier</key><string>com.sentryx.dashboard</string>
  <key>CFBundleVersion</key><string>$PKG_VERSION</string>
  <key>CFBundleExecutable</key><string>sentryx-dashboard</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSUIElement</key><false/>
</dict>
</plist>
EOF

# postinstall runs after the Apple installer UI finishes, but it runs as
# **root** with no attached GUI session — `open`/Terminal from here either
# silently fails or (worse) pops a Terminal window, which is exactly what
# we don't want. The fix: find the actual logged-in console user and hand
# the launch off to *their* session via `launchctl asuser`, so it appears
# as a normal window on their desktop, never root, never a terminal.
cat > "$SCRIPTS_DIR/postinstall" <<'EOF'
#!/bin/bash
set -euo pipefail

CONSOLE_UID="$(stat -f%u /dev/console)"
CONSOLE_USER="$(/usr/bin/stat -f%Su /dev/console)"

# No one's logged in at a GUI (e.g. installed via remote/headless session,
# or at the login screen) — nothing to attach a window to. Leave a unit
# the operator can launch by hand later instead of failing loudly.
if [ -z "$CONSOLE_USER" ] || [ "$CONSOLE_USER" = "root" ] || [ "$CONSOLE_USER" = "loginwindow" ]; then
  exit 0
fi

launchctl asuser "$CONSOLE_UID" sudo -u "$CONSOLE_USER" \
  /usr/local/sentryx/sentryx-setup >/tmp/sentryx-setup.postinstall.log 2>&1 &

exit 0
EOF
chmod +x "$SCRIPTS_DIR/postinstall"

pkgbuild \
  --root "$WORK/root" \
  --scripts "$SCRIPTS_DIR" \
  --identifier com.sentryx.installer \
  --version "$PKG_VERSION" \
  --install-location "/" \
  "$REPO_ROOT/SENTRYX-$ARCH.pkg"

echo "==> built $REPO_ROOT/SENTRYX-$ARCH.pkg — double-click to install"
echo "    postinstall opens the setup wizard in your own session (no Terminal)."
echo "    afterwards, launch the dashboard any time from /Applications/SENTRYX Dashboard.app"
rm -rf "$WORK"
