# Native installers (Windows / macOS / Linux)

These wrap the already-built `sentryxd` / `sxctl` / `sentryx-setup` /
`sentryx-dashboard` binaries in each OS's native installer chrome — the
"download one file, double-click, native OS prompt only (UAC / pkexec /
admin password), zero terminal" experience.

There are two apps the operator ever touches, and they're deliberately
separate:

- **SENTRYX Setup** — a one-time wizard (interface, mode, service install).
  Needs admin/root, since it registers a Windows Service / launchd agent /
  systemd unit.
- **SENTRYX Dashboard** — the icon the operator comes back to afterward,
  any time, like Blender or any other installed app. It opens the running
  daemon's dashboard as its own app-style window (no address bar, its own
  Dock/Taskbar/Alt-Tab entry) instead of a bare `localhost:9090` browser
  tab. Needs no privileges at all.

## What each platform does

| Platform | Elevation prompt | Setup launch | Dashboard launch |
|---|---|---|---|
| Windows | Native UAC (`PrivilegesRequired=admin` in the `.iss`) | Optional "launch after install" checkbox on the Finish page | Start Menu + optional desktop shortcut |
| macOS | Apple's own installer auth prompt (`pkgbuild`) | `postinstall` hands off to the wizard **in the logged-in user's own session** via `launchctl asuser` — never a Terminal window, never as root | `/Applications/SENTRYX Dashboard.app` — a real `.app` bundle |
| Linux | `pkexec` — PolicyKit's native graphical password prompt, Linux's equivalent of UAC | "SENTRYX Setup" entry in the Applications menu (`Exec=pkexec sentryx-setup`) — the `.deb`'s `postinst` deliberately does **not** auto-launch a GUI wizard as root during install, since that's unreliable with no attached desktop session | "SENTRYX Dashboard" entry in the Applications menu, no `pkexec` needed |

Windows didn't need a fix — `PrivilegesRequired=admin` already makes
double-clicking the compiled `.exe` trigger the native UAC popup with zero
extra scripting. macOS and Linux are what changed: macOS no longer opens a
Terminal, and Linux no longer tries to pop a GUI wizard from a root
post-install hook that has no desktop to draw on.

Nothing about `cmd/sentryx-setup`'s wizard logic changes. This is purely a
packaging layer on top of it, per the roadmap's own note that you can
always add "a proper native-feeling installer later... you don't lose any
of this work by upgrading."

## Build order

1. From the repo root: `make dist` — produces every OS/arch binary in
   `dist/`, including `sentryx-dashboard-<os>-<arch>`.
2. Then, per platform:

| Platform | Script | Output | Requires |
|---|---|---|---|
| Windows | `installers/windows/sentryx.iss` | `SentryxSetup.exe` | [Inno Setup](https://jrsoftware.org/isdl.php) (free), compile the `.iss` |
| macOS | `installers/macos/build_pkg.sh` | `SENTRYX-<arch>.pkg` | run on a Mac (uses `pkgbuild`, built in) |
| Linux | `installers/linux/build_deb.sh` | `sentryx_1.0_<arch>.deb` | `dpkg-deb` + `policykit-1` (both standard on Debian/Ubuntu desktops) |

Each one is a starting point, not a finished product — tweak branding,
icons, and the license/readme text to taste. All three now ship the
SENTRYX mark as a proper platform-native icon: `installers/macos/AppIcon.iconset`
(macOS `.icns` source), `installers/linux/sentryx.png` (Applications-menu
icon), and `installers/windows/sentryx.ico` (installer + shortcut icon,
wired into `sentryx.iss`'s `SetupIconFile` and `[Icons]` entries). The
Dashboard and Setup Wizard web UIs also carry the mark and a favicon —
see `internal/api/webui/` and `cmd/sentryx-setup/wizard/`.

---

<div align="right"><sub>SENTRYX — developed by Shivanshu</sub></div>
