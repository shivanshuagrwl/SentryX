#!/usr/bin/env bash
# Builds a native Linux installer: sentryx_1.0_amd64.deb — double-click in
# a GUI file manager (or `sudo apt install ./sentryx_1.0_amd64.deb`), shows
# up in the system package manager, clean uninstall via `apt remove sentryx`.
#
# Usage: ./build_deb.sh
# Requires: sentryxd-linux-amd64, sxctl-linux-amd64, sentryx-setup-linux-amd64,
# sentryx-dashboard-linux-amd64 already built (`make dist`) in ../../dist/
# Also requires `policykit-1` on the target system for pkexec (near-universal
# on desktop distros already; declared as a Depends: below).

set -euo pipefail

ARCH="${1:-amd64}"
# VERSION is the git tag (e.g. "v1.0.2") passed in by release.yml; Debian's
# Version: field convention omits the leading "v", so strip it. Falls back
# to "1.0" for a manual local run with no VERSION set.
RAW_VERSION="${VERSION:-1.0}"
DEB_VERSION="${RAW_VERSION#v}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST="$REPO_ROOT/dist"
WORK="$(mktemp -d)"
PKG="$WORK/sentryx_${DEB_VERSION}_${ARCH}"

mkdir -p "$PKG/DEBIAN" "$PKG/usr/local/bin" "$PKG/lib/systemd/system" \
         "$PKG/usr/share/applications" "$PKG/usr/share/pixmaps"

cp "$DIST/sentryxd-linux-$ARCH"          "$PKG/usr/local/bin/sentryxd"
cp "$DIST/sxctl-linux-$ARCH"             "$PKG/usr/local/bin/sxctl"
cp "$DIST/sentryx-setup-linux-$ARCH"     "$PKG/usr/local/bin/sentryx-setup"
cp "$DIST/sentryx-dashboard-linux-$ARCH" "$PKG/usr/local/bin/sentryx-dashboard"
chmod 755 "$PKG"/usr/local/bin/*

cat > "$PKG/DEBIAN/control" <<EOF
Package: sentryx
Version: $DEB_VERSION
Section: net
Priority: optional
Architecture: $ARCH
Depends: policykit-1
Maintainer: SENTRYX
Description: Kernel-speed XDP packet interdiction daemon
 SENTRYX attaches an XDP program to a network interface for line-rate
 packet filtering, with a cross-platform control CLI and dashboard.
EOF

# --- Applications menu entries ----------------------------------------
# dpkg installs run as root with no attached desktop (no $DISPLAY, often
# no desktop session at all — think a headless `apt install` over SSH),
# so auto-launching a GUI wizard from postinst is exactly the "silently
# fails to open a browser" problem. Instead: install two menu icons and
# let the operator click them, same as installing any other .deb GUI app.
#
# "SENTRYX Setup" needs root (writes /etc/systemd/system, calls
# systemctl — see install_linux.go), so its launcher goes through
# `pkexec`: Linux's native graphical password prompt, PolicyKit's
# equivalent of Windows' UAC. This is the same mechanism GParted, Synaptic,
# and other privileged GUI tools use — never a terminal window.
cat > "$PKG/usr/share/applications/sentryx-setup.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=SENTRYX Setup
Comment=Run the SENTRYX setup wizard (interface, mode, and service install)
Exec=pkexec /usr/local/bin/sentryx-setup
Icon=sentryx
Terminal=false
Categories=Network;Security;System;
EOF

# "SENTRYX Dashboard" needs no privileges at all — it just opens the
# already-running daemon's dashboard in its own window — so it launches
# directly, no pkexec prompt, no terminal, exactly like opening any other
# installed app.
cat > "$PKG/usr/share/applications/sentryx-dashboard.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=SENTRYX Dashboard
Comment=Open the SENTRYX dashboard
Exec=/usr/local/bin/sentryx-dashboard
Icon=sentryx
Terminal=false
Categories=Network;Security;Monitor;
EOF

cp "$REPO_ROOT/installers/linux/sentryx.png" "$PKG/usr/share/pixmaps/sentryx.png"

cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/bash
set -e
# Nothing to launch here on purpose — see the .desktop files above. Just
# refresh the desktop database so the new menu entries show up immediately
# instead of needing a logout/login.
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi
echo "SENTRYX installed. Open 'SENTRYX Setup' from your Applications menu to finish configuring it."
exit 0
EOF
chmod 755 "$PKG/DEBIAN/postinst"

dpkg-deb --build --root-owner-group "$PKG" "$REPO_ROOT/sentryx_${DEB_VERSION}_${ARCH}.deb"

echo "==> built $REPO_ROOT/sentryx_${DEB_VERSION}_${ARCH}.deb"
echo "    install with: sudo apt install ./sentryx_${DEB_VERSION}_${ARCH}.deb"
echo "    then open 'SENTRYX Setup' from the Applications menu (pkexec will prompt for your password)"
rm -rf "$WORK"
