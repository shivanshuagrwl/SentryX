# SENTRYX

**Kernel-speed packet interdiction.**

SENTRYX is a programmable firewall built on eBPF and XDP. Filtering
decisions happen in kernel space, at the network driver, before the Linux
kernel has even allocated a socket buffer for the packet — which makes it
dramatically faster than a traditional iptables/nftables setup under high
traffic. Rules are pushed live from a Go control daemon through eBPF maps,
so nothing ever needs to be recompiled or reloaded to block an address,
change a rate limit, or read live traffic stats.

```
 __      __   ______   ______   _______   __     __   ______   __       __
/  \    /  | /      \ /      \ /       \ /  |   /  | /      \ /  |     /  |
$$  \  /$$ |/$$$$$$  |/$$$$$$  |$$$$$$$  |$$ |   $$ |/$$$$$$  |$$ |     $$ |
$$$  \/$$$ |$$ |  $$ |$$ |  $$/ $$ |  $$ |$$ |   $$ |$$ |__$$ |$$ |     $$ |
$$$$  $$$$ |$$ |  $$ |$$ |      $$ |  $$ |$$  \ /$$/ $$    $$ |$$ |     $$ |
$$ $$ $$/$$ |$$ |  $$ |$$ |   __ $$ |  $$ | $$  /$$/  $$$$$$$$ |$$ |     $$ |
$$ |$$$/ $$ |$$ \__$$ |$$ \__/  |$$ |__$$ |  $$ $$/   $$ |  $$ |$$ |_____$$ |
$$ | $/  $$ |$$    $$/ $$    $$/ $$    $$/    $$$/    $$ |  $$ |$$       |
$$/      $$/  $$$$$$/   $$$$$$/  $$$$$$$/      $/     $$/   $$/ $$$$$$$$/
```

Built by **Shivanshu Agarwal** and **Shaaz Aryan Rehman**.

---

## Download

[![Release installers](https://github.com/shivanshu-agarwal/sentryx/actions/workflows/release.yml/badge.svg)](https://github.com/shivanshu-agarwal/sentryx/actions/workflows/release.yml)
[![CI](https://github.com/shivanshu-agarwal/sentryx/actions/workflows/ci.yml/badge.svg)](https://github.com/shivanshu-agarwal/sentryx/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Grab the installer for your OS from the **[Latest Release](https://github.com/shivanshu-agarwal/sentryx/releases/latest)** — download one file, double-click, done:

| OS | File | What you'll see |
|---|---|---|
| Windows | `SentryxSetup.exe` | Native UAC prompt, then a normal Back/Next/Finish wizard |
| macOS | `SENTRYX-arm64.pkg` | Apple's own installer UI + your Mac login password |
| Linux | `sentryx_1.0_amd64.deb` | `sudo apt install ./sentryx_1.0_amd64.deb`, then click **"SENTRYX Setup"** in your Applications menu (pkexec password prompt) |

No terminal required on any of the three. Every tagged release
(`.github/workflows/release.yml`) rebuilds and re-attaches all three
automatically — see [`INSTALL_GUIDE.md`](INSTALL_GUIDE.md) for the full
walkthrough, or [`installers/README.md`](installers/README.md) for how the
packaging itself works under the hood.

---

## Architecture

```
[ INCOMING PACKETS ]
        │
        ▼
┌──────────────────────────────────────┐
│  KERNEL SPACE                        │
│  bpf/xdp_sentryx.c                  │
│  → parses Eth/IP, checks blocklist    │
│    + per-IP rate limit, XDP_DROP or  │
│    XDP_PASS at line rate              │
└───────────────▲───────────────────────┘
                │  eBPF maps: blocklist, rate_limits, stats
┌───────────────▼───────────────────────┐
│  USER SPACE — sentryxd (Go)         │
│  loads/attaches the XDP program,      │
│  owns every map read & write,         │
│  persists rules, serves the API       │
└───────────────▲───────────────────────┘
                │  REST + Server-Sent Events, :9090
        ┌───────┴────────┐
        ▼                ▼
   sxctl (CLI)     web/dashboard (UI)
```

## Repo layout

```
sentryx/
├── bpf/xdp_sentryx.c        kernel-space filter
├── cmd/
│   ├── sentryxd/            control daemon entrypoint
│   └── sxctl/                CLI entrypoint + subcommands
├── internal/
│   ├── firewall/             eBPF map loading & access (the only code that touches maps)
│   ├── api/                  REST + SSE server, auth middleware
│   │   └── webui/            control-room UI, embedded into the sentryxd binary via go:embed
│   └── store/                JSON-backed rule persistence
├── web/dashboard/index.html  same UI, kept standalone for demo mode (see below) — not what a running daemon serves
├── Makefile
└── go.mod
```

## Building

Requires a Linux host (XDP is Linux-only), Go 1.22+, and `clang`/`libbpf`
for the kernel object.

```bash
make deps     # installs clang, libbpf, bpftool (Debian/Ubuntu)
make all      # compiles bpf/xdp_sentryx.o, bin/sentryxd, bin/sxctl
```

## Running

```bash
export SENTRYX_TOKEN=$(openssl rand -hex 32)
sudo ./bin/sentryxd -iface eth0 -obj bpf/xdp_sentryx.o

# in another shell
export SENTRYX_TOKEN=<same token>
./bin/sxctl block 203.0.113.7 --label "known scanner"
./bin/sxctl list
./bin/sxctl stats
```

No native XDP support on your test interface (common in VMs)? Add
`-generic` to the daemon flags to fall back to SKB-mode XDP — slower, but
works everywhere.

Open **http://localhost:9090** for the dashboard once the daemon is
running. The dashboard also runs standalone straight from
`web/dashboard/index.html` in **demo mode** (simulated traffic) if you just
want to look at the UI without a Linux box handy.

## API reference

| Method | Path | Description |
|---|---|---|
| `GET`  | `/api/health` | Daemon status, no auth required |
| `GET`  | `/api/rules` | List active blocklist rules |
| `POST` | `/api/rules` | `{ "ip", "label", "rate_limit_pps" }` — add a rule |
| `DELETE` | `/api/rules/{ip}` | Remove a rule |
| `POST` | `/api/rules/{ip}/rate-limit` | `{ "limit_pps" }` — set/clear a rate limit |
| `GET`  | `/api/stats` | Current packet/byte counters |
| `GET`  | `/api/stream` | Server-Sent Events, one stats snapshot/sec |
| `GET`  | `/api/geoip` | Phase 20 — currently-blocked country CIDR ranges |
| `GET`  | `/api/arp` | Phase 21 — ARP spoof-suspected alerts |
| `POST` | `/api/capture/start` / `stop` | Phase 22 — start/stop a bounded pcap capture |
| `GET`  | `/api/capture/status` / `download` | Phase 22 — progress + the pcap file itself |
| `GET`  | `/api/topology` | Phase 26 — recent geo-tagged block events (backfill) |
| `GET`  | `/api/topology/stream` | Phase 26 — SSE feed of new block events for the war-room map |

All routes except `/api/health` require `Authorization: Bearer <SENTRYX_TOKEN>`
unless the daemon was started with `-insecure`.

## Everything added since the first prototype

The sections above describe the original single-daemon MVP. Since then the
following shipped on top of it — this section is the map of what's where.

| Feature | Where it lives | CLI |
|---|---|---|
| Behavioral anomaly detection (EWMA baseline + threshold, auto-block) | `internal/anomaly` | `sxctl anomalies`, `sxctl baselines` |
| Explainable drops ("why was this dropped") | `internal/firewall.DropReason`, `GET /api/why/{ip}` | `sxctl why <ip>` |
| Live per-IP traffic window (top talkers, SYN ratio) | `internal/firewall.ActivitySnapshot`, `GET /api/activity` | `sxctl activity` |
| Threat-intel auto-feed (abuse.ch Feodo Tracker) | `internal/threatintel` | daemon flag `-threat-intel` |
| Policy-as-code (`policy.yaml`, git-diffable) | `internal/policy` | `sxctl policy init`, `sxctl policy apply <file>`, daemon flag `-policy` |
| Live benchmark (SENTRYX's own kernel counters, before/after a synthetic load) | `cmd/sxctl/benchmark.go` | `sxctl benchmark --target host:port` |
| Distributed / fleet mode — push one policy to many daemons | `cmd/sxctl/controller.go` | `sxctl controller push/status --nodes nodes.yaml` |
| Colored CLI output + spinners | `cmd/sxctl/color.go` | automatic (honors `NO_COLOR`) |
| Dashboard: war-room particle view, sparklines, working Settings panel | `web/dashboard/index.html` | — |
| GeoIP country blocking (ipdeny.com CIDR feed) | `internal/geoip` | `sxctl geoip status` |
| ARP spoofing detection (detect-only) | `bpf/xdp_sentryx.c`, `internal/anomaly` | `sxctl arp` |
| Packet capture / pcap export (Linux/XDP only; honest no-op elsewhere) | `internal/capture` | `sxctl capture start/stop/status` |
| **Phase 26** — live topology / war-room map, geo-tagged block events over SSE | `internal/topology`, `web/dashboard/index.html` | — |
| **Phase 27.1** — pre-flight environment check (kernel, toolchain, iface/XDP mode, capabilities, container/WSL2) | `internal/firewall/doctor.go` | `sxctl doctor [--iface eth0]` |
| **Phase 27.2** — cross-platform control plane (Linux/XDP, Windows/netsh, macOS/pfctl backends behind one `Backend` interface) | `internal/firewall/firewall_{linux,windows,darwin}.go` | same `sxctl`/API surface everywhere |
| **Phase 27.3** — cross-compiled release binaries for every supported OS/arch | `Makefile`'s `dist` target | `make dist` |
| **Phase 27.4** — one-line source installer, now with a `sxctl doctor` sanity check baked in | `scripts/install.sh` | `curl -sSL .../install.sh \| sudo bash` |
| **Phase 28** — GUI installer: local wizard server, auto-opens the browser, downloads/wires up binaries, installs the native service (systemd/Windows Service/launchd) | `cmd/sentryx-setup` | `./sentryx-setup` (no terminal needed after that) |
| One-command install + systemd service | `scripts/install.sh`, `scripts/sentryxd.service` | `sudo ./scripts/install.sh -i eth0` |

### Anomaly detection

Enabled by default. The daemon polls the kernel's per-IP activity window
every 5s, keeps an EWMA baseline packet rate per source IP, and auto-blocks
anything that spikes far past its own normal (default: 8x baseline, or a
SYN ratio ≥ 90%, sustained for 2 consecutive polls). Tune it or watch it
without it acting:

```bash
sudo ./bin/sentryxd -iface eth0 -anomaly-dry-run              # log only, never block
sudo ./bin/sentryxd -iface eth0 -anomaly-rate-multiplier 12    # less sensitive
sxctl anomalies      # what's been flagged, and why, in one sentence per entry
sxctl baselines      # what "normal" currently looks like, per IP
```

### Threat intelligence

```bash
sudo ./bin/sentryxd -iface eth0 -threat-intel -threat-intel-interval 15m
```

Seeds the blocklist from abuse.ch's Feodo Tracker on boot and re-syncs on a
timer; every entry it adds is tagged `reason=threat-intel` so it's never
confused with a manual or anomaly-based block, and anything that rolls off
the upstream feed gets unblocked automatically.

### Policy-as-code

```bash
sxctl policy init                       # writes a starter policy.yaml
sudo ./bin/sentryxd -policy policy.yaml   # applied on daemon boot
sxctl policy apply policy.yaml          # push the same file to a *running* daemon, no restart
```

Commit `policy.yaml` — it's meant to live in git next to everything else.

### Live benchmark

```bash
sxctl benchmark --target 10.0.0.5:9999 --duration 10s --rate 5000 --report bench.json
```

Fires synthetic UDP load at `--target` and diffs `/api/stats` (the daemon's
own kernel counters) from before to after, printed as a terminal bar chart.
To compare against iptables, run it a second time with `--target` pointed at
a host/port protected by iptables instead, and compare the two reports —
`sxctl` only measures, it never reconfigures either side.

### Distributed / fleet mode

For running more than one SENTRYX instance (e.g. one per edge PoP) without
building a second control plane: every node is still just an ordinary
sentryxd with its own REST API, and `sxctl controller` fans the same
requests out to all of them from one place.

```bash
cp nodes.example.yaml nodes.yaml   # fill in real hosts + token env-var names
sxctl controller status --nodes nodes.yaml
sxctl controller push   --nodes nodes.yaml --policy policy.yaml
```

Each node's token is resolved from an environment variable at run time
(`token: env:SENTRYX_TOKEN_EDGE1` in `nodes.yaml`), so no secret has to sit
in the file itself. This is intentionally the "partial implementation" tier
of a distributed design, not a rewrite into a gossip protocol or a
Raft-backed control plane — pushing policy to N REST endpoints concurrently
already covers "one operator manages a fleet," and it reuses infrastructure
that already exists (the daemon's own `/api/rules`) instead of inventing new
infrastructure just to look more distributed.

### Dashboard: Settings panel

Click **Settings** in the sidebar to point the dashboard at a non-default
daemon address and/or supply an API token — both are saved to
`localStorage` in that browser only. Useful for opening the dashboard from
a laptop against a daemon on a remote box, or against a daemon that isn't
running `-insecure`.

### One-command install

```bash
git clone <this repo> && cd sentryx
sudo ./scripts/install.sh -i eth0
```

Builds everything, installs `sentryxd`/`sxctl` to `/usr/local/bin`,
generates an API token into `/etc/sentryx/sentryx.env` (root-only, 600)
if one doesn't already exist, writes a starter `/etc/sentryx/policy.yaml`,
and installs + enables a `sentryxd.service` systemd unit. Re-running it is
safe — it only touches files it manages and never overwrites an existing
token or policy file.

## Why XDP instead of iptables?

iptables/nftables hook into Netfilter, which sits after the kernel has
already parsed the packet and allocated an `sk_buff` for it. XDP runs
directly in the NIC driver's receive path, before any of that happens —
so a dropped packet costs almost nothing. This matters most under high
packet rates or when mitigating volumetric attacks, where every cycle spent
per-packet adds up fast.

## License

MIT — see `LICENSE`.

---

<div align="right"><sub>SENTRYX — developed by Shivanshu</sub></div>
