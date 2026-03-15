<p align="center">
  <img src="static/logo.svg" alt="ZFS NAS Logo" width="700"/>
</p>
<p align="center">
  <strong>A ZFS NAS management portal that gets out of your way.</strong><br/>
  Single binary. Secure. No database. No bloat.
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go" alt="Go 1.22+"/>
  <img src="https://img.shields.io/badge/Platform-Ubuntu%2022.04%2B-E95420?style=flat-square&logo=ubuntu" alt="Ubuntu 22.04+"/>
  <img src="https://img.shields.io/badge/License-GPLv3-8a2cff?style=flat-square" alt="GPLv3 License"/>
  <img src="https://img.shields.io/badge/Version-4.0.0-00eaff?style=flat-square" alt="Version 4.0.0"/>
</p>

## Why ZFS NAS Chezmoi?
Most NAS management software are slow to install, slow to load, and buried under layers of configuration. ZFS NAS Chezmoi is different:

- **One binary, zero dependencies** — compile once, copy anywhere, run. No Docker. No Node. No Python runtime.
- **Instant startup** — the portal is live in under a second. All static assets are embedded directly in the binary.
- **No database** — configuration lives in plain JSON files next to the binary. Back up with `cp`. Inspect with any text editor.
- **HTTPS on first launch** — a self-signed certificate is generated automatically. No manual certificate setup required.
- **Guided setup wizard** — first-run installs missing system packages, registers a systemd service, detects existing ZFS pools, and creates your admin account. Start to finish in under five minutes.

![Demo](assets/zfsnas-v310-demo.gif)

---

## Features

### Storage Management
- **Multi-Pool Support** — manage any number of ZFS pools side by side; switch between pools with a dropdown in the top bar and the Pool tab; last selection remembered per user across sessions
- **ZFS Pools** — create (Stripe / Mirror / RAIDZ1 / RAIDZ2) with configurable ashift, compression, and dedup; import existing pools; expand with new devices; upgrade pool feature flags; destroy
- **Pool Cache Devices** — add and remove ZFS L2ARC cache devices per pool via the ⚡ Cache Config modal
- **Pool Fixer Wizard** — guided recovery for degraded, faulted, or suspended pools; automatically clears error state and brings offline disks back online in two steps
- **Disk Online / Offline** — manually take individual pool member disks offline or bring them back online without leaving the portal
- **Datasets** — full nested hierarchy with quota, refquota, reservation, record size, compression, sync, dedup, case sensitivity, and a free-text comment stored as a ZFS user property (`zfsnas:comment`)
- **Snapshots** — create, restore, clone, and delete; visual tree per dataset; snapshot list spans all pools
- **Scheduled Snapshots** — automated policies (hourly / daily / weekly / monthly) with configurable retention counts
- **ZFS Scrub** — trigger, monitor progress, stop, and schedule auto-scrubs (weekly / bi-weekly / monthly / every 2 or 4 months) at a configurable hour
- **ZFS Native Encryption** — create AES-256-GCM encrypted pools and datasets; keys are loaded automatically at startup so encrypted volumes mount without manual intervention
- **Encryption Key Management** — generate, import, export, and delete encryption keys from the Settings tab; export format is compatible with TrueNAS key exports, making migration between platforms straightforward; lock icons throughout the UI identify which pools and datasets are encrypted

### File Sharing
- **SMB Shares** — create and manage Samba shares with per-user read/write or read-only permissions
- **NFS Shares** — Linux/macOS NFS exports with per-client CIDR and options (ro/rw, sync/async)

### Monitoring & Alerts
- **Physical Disks** — list all non-system disks with vendor, model, serial number, type, temperature, and SMART wearout (ATA + NVMe), color-coded by health
- **Pool Member Status** — per-disk health state (ONLINE / FAULTED / OFFLINE / etc.) shown inline in the pool view; presence detection for disks that have been physically removed
- **Pool Capacity Bar** — persistent capacity visualization at the top of every page with a pool selector when multiple pools are configured; per-dataset segments with hover tooltips
- **System Dashboard** — 24-hour RRD charts for CPU, memory (app + cache stacked), network (per interface), and disk I/O; live sparklines updated every few seconds
- **Hardware Info** — CPU core count and total RAM exposed via `/api/sysinfo/hardware`
- **Email Alerts** — SMTP-based notifications for pool degradation, disk wearout, SMART errors, and failed logins; all pools monitored (not just the first)
- **Audit Health Events** — pool problem / recovery and disk problem / recovery transitions are written to the audit log automatically by the background health poller

### Administration
- **User Management** — three roles: `admin`, `read-only`, `smb-only`; active session listing and remote kill; per-user UI preferences (pool selection, sidebar state) persisted across sessions
- **Audit Log** — append-only activity log with live sidebar widget and full log page (filterable by user, action, date); covers storage, sharing, auth, OS, and health events
- **Web Terminal** — browser-based PTY terminal (admin only), powered by xterm.js over WebSocket
- **OS Updates** — check for and stream-apply `apt` security updates from the portal
- **Binary Self-Update** — check for a newer release and apply it in-place over WebSocket with live progress output
- **Timezone Management** — set system timezone from the portal; falls back to `/usr/share/zoneinfo/` on minimal installs without `timedatectl`
- **Settings** — configure port, storage units (GB / GiB), SMTP, alert subscriptions, and read-only API key

---

## Requirements

| Requirement | Version |
|---|---|
| Debian | **13 (Bookworm) or later — recommended** |
| Ubuntu | 26.04 LTS or later (also supported) |
| Go (if you build from source) | 1.22 or later |
| `sudo` access without password | Required for ZFS, Samba/NFS management, and SMART commands (or [sudo hardening](SECURITY.md)) |

The following system packages are required. If any are missing, the **Prerequisites** tab will detect them and offer a guided installation:

| Package | Purpose |
|---|---|
| `zfsutils-linux` | `zpool` / `zfs` commands |
| `samba` | SMB file sharing |
| `nfs-kernel-server` | NFS file sharing |
| `smartmontools` | SSD wearout via `smartctl` |
| `nvme-cli` | NVMe wearout via `nvme smart-log` |
| `util-linux` | Disk listing via `lsblk` |
| `sudo` | Required to run privileged ZFS, Samba, NFS, and SMART commands |

---

## Installation

### Option A — Quick installer (recommended)

One command installs ZFS (if needed), creates a dedicated service account, downloads the latest binary, and registers a systemd service:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/macgaver/zfsnas-chezmoi/main/zfsnas-quickinstall-for-debian.sh)
```

> Run as root or with `sudo`. Supports Debian 13+ and Ubuntu 26.04+.

Once the installer completes, open your browser at the URL it prints (e.g. `https://<your-server-ip>:8443/setup`) and follow the setup wizard.

---

### Option B — Build from source

```bash
# 1. Clone the repository
git clone https://github.com/macgaver/zfsnas-chezmoi.git
cd zfsnas-chezmoi

# 2. Build the binary (all static assets are embedded at compile time)
go build -o zfsnas .

# 3. Run
./zfsnas
```

### Option C — Download a release binary

```bash
# Download the latest release for Linux amd64
curl -Lo zfsnas https://github.com/macgaver/zfsnas-chezmoi/releases/latest/download/zfsnas-chezmoi
chmod +x zfsnas-chezmoi.ca
./zfsnas
```

### First-run setup (Options B and C)

Place the binary in a folder owned by a user with passwordless sudo access (you can restrict sudo to specific commands — see [SECURITY.md](SECURITY.md)). Then launch and open your browser at:

```
https://<your-server-ip>:8443/setup
```

> Accept the self-signed certificate warning — the cert is generated locally on your server and is used only to encrypt traffic between your browser and the portal.

The setup wizard will guide you through:

1. **Prerequisites** — detect and install missing system packages
2. **Systemd service** — optionally register `zfsnas.service` so the portal starts on boot
3. **ZFS pool** — detect and import existing pools, or create a new one
4. **Admin account** — create your first administrator

After setup, the portal is available at:

```
https://<your-server-ip>:8443
```

---

## Configuration

All configuration is stored in `./config/` relative to the binary (or override with `--config`):

```
config/
├── config.json            # port, first-run flag
├── users.json             # all portal users
├── shares.json            # SMB share definitions
├── nfs-shares.json        # NFS export definitions
├── alerts.json            # SMTP config + event subscriptions
├── snapshot-schedules.json
├── audit.log              # append-only, one JSON line per event
└── certs/
    ├── server.crt
    └── server.key
```

### CLI flags

| Flag | Default | Description |
|---|---|---|
| `--config` | `./config` | Path to the config directory |
| `--dev` | off | Serve static files from disk (development mode) |
| `--debug` | off | Enable verbose logging |

---

## Architecture

ZFS NAS Chezmoi is built to stay fast and simple as it grows:

- **Go 1.22+** — single statically-linked binary, cold start in milliseconds
- **Embedded frontend** — HTML, CSS, and JS compiled into the binary via `go:embed`; zero CDN calls in production
- **Alpine.js** — lightweight reactive UI with no build step, no npm, no bundler
- **gorilla/mux** — minimal HTTP routing
- **JSON file storage** — no database process to manage or back up
- **WebSocket streaming** — real-time terminal, package installation output, and system metrics without polling hacks
- **Background goroutines** — SMART refresh, health alerts, snapshot scheduling, and session cleanup run as lightweight goroutines inside the single process

---

## Security

For the full security model, sudo hardening guide, TLS configuration, and authentication details see **[SECURITY.md](SECURITY.md)**.

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.
