# SENTRYX — Install & Use Guide

## Ye hai kya

SENTRYX ek network security tool hai jo kernel-level (XDP) packet filtering
karta hai — matlab ek firewall/intrusion-detection daemon (`sentryxd`) jo
background me chalta hai, ek CLI (`sxctl`) usko control karne ke liye, aur
ab do GUI pieces:

- **SENTRYX Setup** — ek baar chalane wala wizard (interface choose karo,
  mode choose karo, service install ho jaati hai).
- **SENTRYX Dashboard** — jab bhi dekhna ho status, tab double-click karne
  wala icon (jaise Blender ya koi bhi normal app) — apni khud ki window me
  khulta hai, browser tab jaisa nahi lagta.

Teeno OS (Windows/macOS/Linux) ke liye native installer hai: ek file
download karo, double-click karo, sirf OS ka apna security prompt
(UAC / macOS password / Linux ka pkexec) aayega — terminal kahin nahi
chahiye.

---

## Step 0 — Build karna (ek baar, kisi bhi machine se jahan Go ho)

Repo root me:

```bash
make dist
```

Ye `dist/` folder me har OS/arch ke liye 4 binaries bana dega:
`sentryxd`, `sxctl`, `sentryx-setup`, `sentryx-dashboard` — Linux, Windows,
macOS sab ke liye.

Agar `go` install nahi hai:
```bash
sudo apt-get install golang-go     # Debian/Ubuntu
```

---

## Step 1 — Har OS ke liye native installer banao

Ye step OS-specific hai — jis OS ka installer chahiye, us OS pe (ya us OS
ke CI runner pe) chalao.

### Windows → `SentryxSetup.exe`
1. [Inno Setup](https://jrsoftware.org/isdl.php) install karo (free).
2. `installers/windows/sentryx.iss` ko Inno Setup me kholo.
3. **Compile** pe click karo.
4. Output: `installers/windows/Output/SentryxSetup.exe`

### macOS → `SENTRYX-<arch>.pkg`
Ek Mac pe:
```bash
cd installers/macos
./build_pkg.sh arm64      # ya amd64 Intel Mac ke liye
```
Output: `SENTRYX-arm64.pkg` (repo root me)

### Linux → `sentryx_1.0_<arch>.deb`
```bash
cd installers/linux
./build_deb.sh amd64
```
Output: `sentryx_1.0_amd64.deb` (repo root me)

---

## Step 2 — Install karna (end-user ka experience)

### Windows
1. `SentryxSetup.exe` double-click karo.
2. Windows ka **UAC popup** aayega (admin permission) — Yes karo.
3. Normal installer wizard: Next → Next → Install → Finish.
4. Finish page pe "Launch the SENTRYX setup wizard" checkbox checked
   milega — usse setup wizard khul jayega browser me (interface + mode
   choose karne ke liye).
5. Baad me jab bhi dashboard dekhna ho: Start Menu → **SENTRYX Dashboard**
   (ya desktop icon, agar install ke time checkbox tick kiya tha).

### macOS
1. `.pkg` file double-click karo.
2. Apple ka apna installer UI khulega — Continue → Install.
3. macOS password maangega (installer ka apna prompt, koi Terminal nahi).
4. Install finish hote hi, setup wizard **automatically** aapki apni
   session me khul jayega (browser tab) — koi Terminal window nahi
   dikhegi.
5. Baad me dashboard chahiye ho to: **Launchpad → SENTRYX Dashboard**
   (ya `/Applications/SENTRYX Dashboard.app`).

### Linux
1. File manager me `.deb` double-click karo (ya
   `sudo apt install ./sentryx_1.0_amd64.deb`).
2. Install ho jayega — koi wizard automatically nahi khulega (ye jaan-bujh
   kar hai, kyunki install ke time GUI session available nahi hota).
3. **Applications menu** kholo → **"SENTRYX Setup"** pe click karo.
4. Ek native graphical password prompt aayega (pkexec — Linux ka UAC jaisa
   equivalent) — password daalo.
5. Setup wizard khulega (browser tab me) — interface + mode choose karo.
6. Baad me dashboard ke liye: Applications menu → **"SENTRYX Dashboard"**
   (password nahi maangega, seedha khul jayega).

---

## Step 3 — Setup wizard me kya karna hai

Wizard 3 cheeze poochta hai:
1. **Network interface** — kaunsa interface monitor karna hai
   (auto-detect ho jata hai).
2. **Mode** — `strict` (auto-block) ya `learning` (sirf detect/log karo,
   block mat karo — pehli baar ke liye recommended).
3. Confirm → daemon service install ho jaati hai (Windows Service /
   launchd agent / systemd unit) aur turant start ho jaati hai.

Last screen pe ek generated **API token** aur dashboard URL dikhega —
config file me save ho jata hai (aage manually kahin daalne ki zaroorat
nahi).

---

## Step 4 — Roz ka use

- Status/traffic dekhna ho → **SENTRYX Dashboard** icon double-click.
- Command line se control karna ho → `sxctl` (PATH me add ho jata hai,
  Windows pe "addpath" task check karo installer me).
- Service manage karna ho:
  - Windows: `services.msc` ya `sc query SENTRYXD`
  - macOS: `launchctl list | grep sentryx`
  - Linux: `systemctl status sentryxd`

---

## GitHub pe push karna (auto-build + auto-release)

Repo me ab ye add ho gaya hai:

- `.github/workflows/ci.yml` — har push/PR pe build check karta hai.
- `.github/workflows/release.yml` — jab bhi aap ek version **tag** push
  karoge (`v1.0.0` jaisa), ye automatically:
  1. Linux runner pe `make dist` chala kar saare binaries banata hai.
  2. Teeno OS ke native runners (ubuntu/macos/windows) pe teeno installer
     banata hai (`.deb`, `.pkg`, `.exe`).
  3. Ek **GitHub Release** bana kar teeno files usme attach kar deta hai.

Matlab: aap sirf ek baar tag push karo, baaki sab automatic ho jata hai —
log bas `Releases` page se apne OS ki file download karke double-click
karenge.

```bash
git init
git add .
git commit -m "SENTRYX v1.0"
git remote add origin https://github.com/<your-username>/sentryx.git
git push -u origin main

git tag v1.0.0
git push origin v1.0.0     # <-- ye release workflow trigger karega
```

Kuch minutes baad `github.com/<you>/sentryx/releases/latest` pe teeno
installer files ready milenge.

**Ek zaroori one-time step:** repo me abhi `go.sum` file commit nahi hai
(is sandbox ka network kuch Go module domains — `gopkg.in` — block karta
hai, isliye main yahan se generate nahi kar saka). CI/release workflow
khud `go mod tidy` chala kar isse GitHub ke runner pe (jahan full internet
hai) resolve kar lega, to pehla push/tag automatically kaam karega. Lekin
better practice ke liye, apni machine pe ek baar ye chala kar `go.sum` ko
commit kar dena recommended hai:

```bash
go mod tidy
git add go.sum
git commit -m "add go.sum"
```

### "Auto-install prerequisites" (VC++ Redist jaisa)

Games apne installer me DirectX/VC++ Redist silently install karte hain
kyunki wo C/C++ me bane hote hain aur us runtime ke bina chalte nahi.
SENTRYX ke saare binaries (`sentryxd`, `sxctl`, `sentryx-setup`,
`sentryx-dashboard`) pure Go se statically-linked hain — **koi runtime
dependency hai hi nahi**, to VC++ Redist jaisi cheez ki zaroorat nahi hai.
Ye ek real advantage hai (kabhi "missing DLL" error nahi aayega).

Jo real prerequisites hain, wo already automatic hain:
- **Linux**: `.deb` ka `Depends: policykit-1` — `apt install` khud
  `pkexec` (agar missing ho) install kar leta hai, exactly wahi tareeka
  jaise ek game installer DirectX install karta hai.
- **Windows/macOS**: kuch extra chahiye hi nahi — dono OS ka apna
  UAC/installer mechanism already built-in hai.

Agar kabhi future me koi real dependency add ho (jaise ek cgo library),
to `installers/windows/sentryx.iss` me already ek ready-to-use comment
block hai jo dikhata hai silent installer kaise bundle karte hain — bas
uncomment karke apni `.exe` daal dena.



| Problem | Fix |
|---|---|
| Linux: Applications menu me icon nahi dikh raha | Logout/login karo, ya `update-desktop-database` khud chala lo — normally automatic hota hai |
| macOS: setup wizard nahi khula | Aap login screen pe install kar rahe the (headless) — `/usr/local/sentryx/sentryx-setup` manually chala lo |
| Dashboard "can't connect" bol raha hai | Pehle Setup wizard complete karo — daemon chalu hone ke baad hi dashboard kaam karega |
| Koi bhi branded icon generic dikh raha | Ab teeno installers me SENTRYX ka apna icon already wired hai (`installers/{macos,linux,windows}`) — agar phir bhi generic dikhe, cache clear karo (Windows: icon cache rebuild; macOS: `killall Finder`; Linux: `update-desktop-database`) |

---

<div align="right"><sub>SENTRYX — developed by Shivanshu</sub></div>
