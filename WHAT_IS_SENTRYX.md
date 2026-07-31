# SENTRYX

**Kernel-level network protection — install it like any normal app, no terminal required.**

---

## What this actually is

SENTRYX is a firewall — but instead of running as a regular background
program, it works inside the operating system's own network layer (the
"kernel"), so it can inspect and block bad traffic before your computer
even fully processes it. That's what "kernel-level" means: it's not slower
security software watching traffic *after* the fact, it's positioned as
early as software is allowed to be.

In plain terms: it watches every packet of network traffic hitting your
machine, decides in real time whether it's safe, and drops the bad stuff —
all with almost no performance cost, because it never leaves the fastest
part of the system.

You get three pieces, but only ever look at one:

- **SENTRYX Setup** — a one-time wizard you run once, right after
  installing. It asks which network connection to protect and how, then
  configures everything.
- **SENTRYX Dashboard** — the app you actually open day to day. A real
  desktop window (Start Menu / Applications / Dock icon), not a browser
  tab, showing live traffic and blocked threats.
- **sxctl** — a power-user command-line tool. You will never need this
  unless you want it; everything it can do, the Dashboard can also do.

---

## What it can do

| Feature | In plain English |
|---|---|
| **Line-rate blocking** | Blocks malicious IPs at the network card level, before your machine's normal software even sees the traffic. |
| **Live dashboard** | A real-time view of traffic, blocked threats, and a "war-room" map showing where attacks are coming from. |
| **Anomaly detection** | Learns what "normal" traffic looks like for your machine, and automatically blocks anything that suddenly spikes far past normal — no rules to write. |
| **Threat intelligence feed** | Automatically pulls in a live list of known-malicious IPs from a public threat database and keeps it updated on its own. |
| **Explainable blocks** | You can ask "why was this IP blocked?" and get a real, plain-English answer instead of a raw log line. |
| **GeoIP country blocking** | Block all traffic from entire countries with one switch, if that's relevant to you. |
| **ARP spoof detection** | Warns you if something on your local network is impersonating another device (a common attack technique). |
| **Packet capture** | Save a snapshot of raw traffic around an incident, for later inspection. |
| **Policy-as-code** | Advanced users can write their rules in one file and version it — not needed for normal use. |
| **Fleet mode** | Push the same protection settings to many machines at once — relevant if you're protecting more than one computer. |
| **Cross-platform** | Works on Windows, macOS, and Linux, with the same dashboard everywhere. |

Some of these (policy-as-code, fleet mode, live benchmarking) are aimed at
technical users managing several machines — a normal single-computer user
will never need to touch them. The Dashboard and Setup wizard cover
everything a regular user needs.

---

## Installing it — no terminal, ever

This is the important part: **you should never need to open a terminal,
Command Prompt, or PowerShell window to install or use SENTRYX.** If a
step ever seems to ask you to type commands, that's not the intended path
— use the steps below instead.

### 1. Go to the Releases page

Open this link in your browser:

```
https://github.com/shivanshu-agarwal/sentryx/releases/latest
```

You'll see three files. Download the one for your computer:

| Your computer | File to download |
|---|---|
| Windows | `SentryxSetup.exe` |
| Mac | `SENTRYX-arm64.pkg` |
| Linux | `sentryx_1.0_amd64.deb` |

### 2. Install it

**Windows**
1. Open the downloaded `SentryxSetup.exe` (double-click it, same as any installer).
2. Windows will show a security prompt asking to allow changes — click **Yes**.
3. Click through the wizard: **Next → Next → Install → Finish.**
4. Tick "Launch the SENTRYX setup wizard" on the last screen (it's checked by default).

**Mac**
1. Open the downloaded `SENTRYX-arm64.pkg` (double-click it).
2. macOS shows its normal installer screen — click **Continue → Continue → Install**.
3. Enter your Mac's login password when asked (that's your Mac unlocking, not a terminal).
4. Once it finishes, the setup wizard opens on its own.

**Linux**
1. Double-click the downloaded `sentryx_1.0_amd64.deb` file — most Linux
   desktops will open it automatically in a graphical installer (like the
   Software Center or GNOME Software).
2. Click **Install**, enter your password when the graphical prompt asks
   for it.
3. Open your Applications menu and click **"SENTRYX Setup"** — you'll get
   a graphical password prompt (this is the same kind of prompt as any
   other app asking for admin rights, not a terminal).

### 3. Run the setup wizard (one time only)

A window will open in your browser asking two simple questions: which
network connection to protect, and which mode to run in. Answer them and
click through — it installs itself as a background service and starts
protecting your machine automatically from then on, even after a restart.

### 4. Day-to-day use

From now on, just open **SENTRYX Dashboard** from your Start Menu /
Applications / Dock whenever you want to check on things. It runs
protection in the background all the time, whether the Dashboard is open
or not.

---

<div align="right"><sub>SENTRYX — developed by Shivanshu</sub></div>
