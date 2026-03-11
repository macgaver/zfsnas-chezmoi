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
  <img src="https://img.shields.io/badge/License-MIT-8a2cff?style=flat-square" alt="MIT License"/>
  <img src="https://img.shields.io/badge/Version-2.0.0-00eaff?style=flat-square" alt="Version 2.0.0"/>
</p>

---

## Why ZFS NAS Chezmoi?

Most NAS management software is slow to install, slow to load, and buried under layers of configuration. ZFS NAS Chezmoi is different:

- **One binary, zero dependencies** — compile once, copy anywhere, run. No Docker. No Node. No Python runtime.
- **Instant startup** — the portal is live in under a second. All static assets are embedded directly in the binary.
- **No database** — configuration lives in plain JSON files next to the binary. Back up with `cp`. Inspect with any text editor.
- **HTTPS on first launch** — a self-signed certificate is generated automatically. No manual certificate setup required.
- **Guided setup wizard** — first-run installs missing system packages, registers a systemd service, detects existing ZFS pools, and creates your admin account. Start to finish in under five minutes.

---

## Features

### Storage Management
- **ZFS Pools** — create (Stripe / RAIDZ1 / RAIDZ2), import existing pools, expand, and destroy
- **Datasets** — full nested hierarchy with quota, compression, and refquota options
- **Snapshots** — create, restore, clone, and delete; visual tree per dataset
- **Scheduled Snapshots** — automated policies (hourly / daily / weekly / monthly) with configurable retention counts
- **ZFS Scrub** — trigger, monitor progress, stop, and optionally schedule weekly scrubs

### File Sharing
- **SMB Shares** — create and manage Samba shares with per-user read/write or read-only permissions
- **NFS Shares** — Linux/macOS NFS exports with per-client CIDR and options (ro/rw, sync/async)

### Monitoring & Alerts
- **Physical Disks** — list all non-system disks with vendor, model, type, and SMART wearout (ATA + NVMe), color-coded by health
- **Pool Capacity Bar** — persistent capacity visualization at the top of every page, with per-dataset segments and hover tooltips
- **System Dashboard** — live CPU, RAM, network (per interface), and ZFS disk I/O sparklines updated every 2 seconds
- **Email Alerts** — SMTP-based notifications for pool degradation, SMART errors, disk wearout, failed logins, and more

### Administration
- **User Management** — three roles: `admin`, `read-only`, `smb-only`; active session listing and remote kill
- **Audit Log** — append-only activity log with live sidebar widget and full log page (filterable by user, action, date)
- **Web Terminal** — browser-based PTY terminal (admin only), powered by xterm.js over WebSocket
- **Ubuntu Updates** — check for and stream-apply `apt` security updates from the portal
- **Settings** — configure port, storage units (GB / GiB), SMTP, and alert subscriptions

---

## Requirements

| Requirement | Version |
|---|---|
| Ubuntu | 22.04 LTS or later (24.04 LTS recommended) |
| Go (build from source) | 1.22 or later |
| `sudo` access | Required for ZFS, Samba, and SMART commands |

The following system packages are **installed automatically** by the setup wizard if missing:

| Package | Purpose |
|---|---|
| `zfsutils-linux` | `zpool` / `zfs` commands |
| `samba` | SMB file sharing |
| `nfs-kernel-server` | NFS file sharing |
| `smartmontools` | SSD wearout via `smartctl` |
| `nvme-cli` | NVMe wearout via `nvme smart-log` |
| `util-linux` | Disk listing via `lsblk` |

---

## Installation

### Option A — Build from source

```bash
# 1. Clone the repository
git clone https://github.com/macgaver/zfsnas-chezmoi.git
cd zfsnas-chezmoi

# 2. Build the binary (all static assets are embedded at compile time)
go build -o zfsnas .

# 3. Run
sudo ./zfsnas
```

### Option B — Download a release binary

```bash
# Download the latest release for Linux amd64
curl -Lo zfsnas https://github.com/macgaver/zfsnas-chezmoi/releases/latest/download/zfsnas-chezmoi
chmod +x zfsnas-chezmoi.ca
./zfsnas
```

### First-run setup

On first launch, open your browser and navigate to:

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

## License

MIT — see [LICENSE](LICENSE) for details.
