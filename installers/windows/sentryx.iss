; SENTRYX — native Windows installer (Inno Setup)
;
; This gives you the exact experience in the screenshot: a black/white
; wizard with Back/Next/Finish, a license page, a progress bar, a Start
; Menu entry, and a proper "Add or Remove Programs" listing — instead of
; the browser-based wizard cmd/sentryx-setup opens on its own.
;
; What it actually does under the hood:
;   1. Copies sentryxd.exe, sxctl.exe, sentryx-setup.exe into
;      C:\Program Files\SENTRYX
;   2. Adds that folder to PATH so `sxctl` works from any terminal
;   3. Creates Start Menu shortcuts — the SENTRYX Dashboard (opens as its
;      own app-style window, not a bare localhost tab), the setup wizard,
;      and an uninstaller — plus an optional desktop icon for the dashboard
;   4. On the Finish page, offers to launch sentryx-setup.exe — which is
;      what actually picks your interface/mode and installs the Windows
;      Service. Native chrome for the install step, the existing browser
;      wizard for the configuration step — same binaries, same install.go
;      logic, just wrapped.
;
; ---------------------------------------------------------------------
; HOW TO BUILD THIS INTO SentryxSetup.exe:
;   1. Install Inno Setup (free): https://jrsoftware.org/isdl.php
;   2. Build the four Windows binaries first (from the repo root):
;        go build -o dist/sentryxd.exe          ./cmd/sentryxd
;        go build -o dist/sxctl.exe              ./cmd/sxctl
;        go build -o dist/sentryx-setup.exe      ./cmd/sentryx-setup
;        go build -o dist/sentryx-dashboard.exe  ./cmd/sentryx-dashboard
;      (or `make dist` builds every OS/arch at once — grab the four
;      windows-amd64 ones and rename them to match the names above, or
;      just adjust the [Files] Source paths below to point at the exact
;      dist/ filenames.)
;   3. Open this .iss file in Inno Setup's compiler (or right-click →
;      "Compile"). Output lands in installers\windows\Output\SentryxSetup.exe
; ---------------------------------------------------------------------

#define MyAppName "SENTRYX"
#define MyAppVersion "1.0"
#define MyAppPublisher "SENTRYX"
#define MyAppURL "https://github.com/shivanshuagrwl/SentryX"
#define MyAppExeName "sentryx-setup.exe"

[Setup]
AppId={{B6E7A6B4-6C1E-4E9A-9C1A-5E1F2B7D9A11}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\SENTRYX
DefaultGroupName=SENTRYX
DisableProgramGroupPage=yes
; Requires admin — sentryxd needs elevated rights on Windows to register
; a service and add firewall rules (see cmd/sentryx-setup/install_windows.go)
PrivilegesRequired=admin
OutputDir=Output
OutputBaseFilename=SentryxSetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=sentryx.ico
UninstallDisplayIcon={app}\sentryx.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addpath"; Description: "Add SENTRYX to PATH (so 'sxctl' works from any terminal)"; GroupDescription: "Additional options:"
Name: "launchwizard"; Description: "Launch the SENTRYX setup wizard after install"; GroupDescription: "Additional options:"; Flags: checkedonce
Name: "desktopicon"; Description: "Create a desktop shortcut for the SENTRYX Dashboard"; GroupDescription: "Additional options:"; Flags: unchecked

[Files]
; Adjust these Source paths to wherever your Windows build output actually
; lives — see the build instructions in the header comment above.
Source: "..\..\dist\sentryxd-windows-amd64.exe";           DestDir: "{app}"; DestName: "sentryxd.exe";           Flags: ignoreversion
Source: "..\..\dist\sxctl-windows-amd64.exe";               DestDir: "{app}"; DestName: "sxctl.exe";               Flags: ignoreversion
Source: "..\..\dist\sentryx-setup-windows-amd64.exe";       DestDir: "{app}"; DestName: "sentryx-setup.exe";       Flags: ignoreversion
Source: "..\..\dist\sentryx-dashboard-windows-amd64.exe";   DestDir: "{app}"; DestName: "sentryx-dashboard.exe";   Flags: ignoreversion
Source: "sentryx.ico";                                       DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md";                              DestDir: "{app}"; Flags: ignoreversion
; --- No redistributable needed today, on purpose ---------------------
; Game installers bundle a silent VC++ Redist/DirectX .exe because their
; game itself is C/C++ and needs that runtime present. sentryxd/sxctl/
; sentryx-setup/sentryx-dashboard are statically-linked Go binaries with
; zero cgo — nothing to redistribute, nothing that can be "missing" on a
; clean Windows box. If that ever changes (e.g. a future cgo dependency),
; the pattern is exactly what games use — drop the prerequisite's silent
; installer next to this .iss and add:
;   Source: "prereqs\vc_redist.x64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall
;   [Run] section: Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/quiet /norestart"; \
;       StatusMsg: "Installing prerequisites..."; Check: NeedsVCRedist
; and a Check: function that detects whether it's already present, same
; idea as NeedsAddPath below.

[Icons]
; The wizard is a one-time "configure it" step; the dashboard is the icon
; the operator actually keeps coming back to afterward (double-click, like
; opening any other installed app — Blender, Steam, whatever), so it gets
; top billing plus an optional desktop shortcut.
Name: "{group}\SENTRYX Dashboard";     Filename: "{app}\sentryx-dashboard.exe"; IconFilename: "{app}\sentryx.ico"
Name: "{autodesktop}\SENTRYX Dashboard"; Filename: "{app}\sentryx-dashboard.exe"; Tasks: desktopicon; IconFilename: "{app}\sentryx.ico"
Name: "{group}\SENTRYX Setup Wizard";  Filename: "{app}\sentryx-setup.exe"; IconFilename: "{app}\sentryx.ico"
Name: "{group}\SENTRYX CLI (sxctl)";   Filename: "{cmd}"; Parameters: "/k ""cd /d ""{app}"" && sxctl --help"""; WorkingDir: "{app}"; IconFilename: "{app}\sentryx.ico"
Name: "{group}\Uninstall SENTRYX";     Filename: "{uninstallexe}"

[Registry]
; Adds {app} to the *system* PATH so `sxctl` and `sentryxd` work from any
; terminal without the user hunting for the install folder. Only applied
; if the "addpath" task above is checked.
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
    Tasks: addpath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
; Mirrors the Finish page in the screenshot: an optional "launch the app
; now" checkbox. Here that's the setup wizard (interface/mode picker +
; service install), not the app itself, since there's a real
; configuration step left to do — same idea, one extra click.
Filename: "{app}\sentryx-setup.exe"; Description: "Launch the SENTRYX setup wizard"; Flags: postinstall skipifsilent nowait; Tasks: launchwizard

[Code]
// Only adds {app} to PATH if it isn't already there — re-running the
// installer (an upgrade) shouldn't pile up duplicate PATH entries.
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;
