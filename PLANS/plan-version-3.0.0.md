# ZFS NAS Management Portal — Version 3.0.0 Plan

Version 3.0.0 adds a version badge with GitHub release navigation, binary self-update,
a fully populated Dashboard with 24-hour RRD-backed charts, and disk temperature display.
No breaking changes to the existing API or data formats.

---

## What Shipped in 2.0.0

- Email alerts (SMTP config, health poller, HTML email templates)
- NFS shares (`/etc/exports` management, UI)
- Scheduled snapshots (cron-like scheduler, policy CRUD, retention pruning)
- ZFS scrub management (trigger, monitor, scheduled weekly scrub)
- Disk I/O bar charts (live read/write/busy sparklines in the top bar, from `/proc/diskstats`)
- System resource API (`GET /api/sysinfo/diskio`) polled every 5 s

---

## Version 3.0.0 Feature Set

---

### Phase 1 — Version Badge & GitHub Releases Link

**Goal:** users can always see which version is running and jump to the changelog.

**UI — sidebar header, below the logo:**
```html
<a id="app-version" href="..." target="_blank" rel="noopener">v3.0.0</a>
```
- Styled as a small, muted pill/badge (e.g. `v3.0.0`, monospace, rounded, subtle border)
- Clicking opens `https://github.com/macgaver/zfsnas-chezmoi/releases` in a new browser tab
- Text and link rendered from a Go-embedded constant so they never go stale

**Backend (`internal/version/version.go`):**
```go
package version

const Version = "3.0.0"
const ReleasesURL = "https://github.com/macgaver/zfsnas-chezmoi/releases"
```

**API — new endpoint:**
```
GET /api/version   → { "version": "3.0.0", "releases_url": "https://github.com/macgaver/zfsnas-chezmoi/releases" }
```

- Frontend fetches once on load; injects into the badge anchor
- No auth required (called before login would be odd, so still behind RequireAuth for consistency)

---

### Phase 2 — Live Binary Self-Update

**Goal:** admins can keep the portal current by pulling the latest released binary from
GitHub with one click, without SSH access.

**UI — Settings page, new "Updates" section (below existing storage-unit setting):**
- Toggle: **Enable live binary updates** (default off, persisted in `config.json`)
- When enabled, a **"Check for Update"** button appears
- Status line: current version vs latest available (e.g. `v3.0.0  →  v3.1.0 available`)
- **"Download & Apply"** button (shown when a newer version is found):
  - Streams progress via WebSocket (same pattern as apt-get streaming)
  - Steps shown: fetching release info → downloading binary → verifying → replacing → restarting
- After applying, the process self-restarts using `syscall.Exec` (same PID slot — systemd keeps the service alive automatically)

**Backend:**

`internal/updater/updater.go`:
- `CheckLatest() (tag, downloadURL string, err error)` — calls GitHub Releases API:
  `GET https://api.github.com/repos/macgaver/zfsnas-chezmoi/releases/latest`
  Parses `tag_name` and finds the asset whose name matches `zfsnas-linux-amd64`
  (or `zfsnas` — the binary name is `zfsnas`, arch detected at runtime via `runtime.GOARCH`)
- `Download(url, destPath string) error` — streams the binary to a temp file in the same
  directory as `os.Executable()`, verifying it is non-empty
- `Replace(tempPath, exePath string) error` — `os.Rename(tempPath, exePath)` (atomic on
  same filesystem)
- `Restart(exePath string, args []string, env []string) error` — `syscall.Exec(exePath, args, env)`

`handlers/updates.go` (new `HandleBinaryUpdate*` handlers, separate from `HandleApplyUpdates` which is OS apt):
- `GET /api/binary-update/check` — calls `updater.CheckLatest()`, returns `{ current, latest, download_url, update_available }`
- `WebSocket /ws/binary-update-apply` — runs download + replace + restart, streams progress lines

`AppConfig` additions:
```go
LiveUpdateEnabled bool `json:"live_update_enabled,omitempty"`
```

**Security considerations:**
- Feature disabled by default
- Only admin role can toggle or trigger
- Binary downloaded over HTTPS only; process replaced only if download succeeds and file is non-empty
- No signature verification in v3.0.0 (noted as future improvement — v3.1.0 can add SHA256 checksum from release notes)

---

### Phase 3 — Dashboard: 24-Hour RRD Charts

**Goal:** the Dashboard tab becomes the primary at-a-glance health view with historical
CPU, memory, network, and disk I/O graphs for the last 24 hours.

#### 3a — RRD Metrics Collector (Go, no external dependencies)

A lightweight circular-buffer RRD implementation in `internal/rrd/`.
No `rrdtool` binary required — all in Go, persisted as a compact JSON file.

**Design:**
- **Resolution:** 5-minute samples → 288 data points per 24 hours
- **Storage:** `config/metrics.rrd.json` — one JSON object per series, each a fixed-length
  ring buffer of `{ ts: unix_epoch, v: float64 }` pairs
- **Series collected:**
  | Series key | Source | Unit |
  |---|---|---|
  | `cpu_pct` | `/proc/stat` (delta between samples) | % |
  | `mem_used_pct` | `/proc/meminfo` | % |
  | `net_rx_kbps` | `/proc/net/dev` (sum across non-loopback interfaces) | KB/s |
  | `net_tx_kbps` | `/proc/net/dev` (sum across non-loopback interfaces) | KB/s |
  | `disk_read_kbps` | `/proc/diskstats` (pool members, reuse existing `sysinfo.go` logic) | KB/s |
  | `disk_write_kbps` | `/proc/diskstats` | KB/s |
  | `disk_busy_pct` | `/proc/diskstats` | % |

**`internal/rrd/rrd.go`:**
```go
// RingBuffer — 288-slot circular buffer, JSON-serializable
type Sample struct { TS int64; V float64 }
type Series struct { Samples [288]Sample; Head int }
type DB struct { Series map[string]*Series }

func Open(path string) (*DB, error)   // load from disk or create new
func (db *DB) Record(key string, v float64, now time.Time)  // write one sample
func (db *DB) Query(key string) []Sample                    // returns sorted 288-slot slice
func (db *DB) Flush(path string) error                      // persist to disk
```

**`system/metrics_collector.go`:**
- `StartMetricsCollector(configDir string)` — goroutine that ticks every 5 minutes,
  samples all 7 series, calls `rrd.Record()`, then `rrd.Flush()`
- Reuses `readDiskstats()` already in `sysinfo.go` for disk metrics
- Samples `/proc/stat` for CPU (two readings 500 ms apart for accuracy at the 5-min mark)

**API — new endpoint:**
```
GET /api/dashboard/metrics
```
Returns all 7 series as 288-point arrays (or fewer if collector has not run 288 times yet):
```json
{
  "cpu_pct":         [ { "ts": 1710000000, "v": 12.3 }, ... ],
  "mem_used_pct":    [ ... ],
  "net_rx_kbps":     [ ... ],
  "net_tx_kbps":     [ ... ],
  "disk_read_kbps":  [ ... ],
  "disk_write_kbps": [ ... ],
  "disk_busy_pct":   [ ... ]
}
```

Optional query param `?series=cpu_pct,mem_used_pct` to fetch a subset.

#### 3b — Dashboard UI (Chart.js 4, already on CDN)

**Layout — `page-dashboard` replaces the current stub:**

Row 1 — 4 summary stat cards (keep existing: Pool Status, Datasets, SMB Shares, Users)

Row 2 — 2 full-width or 50/50 charts:
- **CPU Usage (24h)** — area chart, blue, y-axis 0–100%
- **Memory Usage (24h)** — area chart, purple, y-axis 0–100%

Row 3 — 2 charts:
- **Network I/O (24h)** — line chart, RX green / TX orange, y-axis KB/s auto-scaled
- **Disk I/O (24h)** — line chart, Read teal / Write amber, y-axis KB/s auto-scaled

Row 4 — 1 chart (full width):
- **Disk Busy % (24h)** — area chart, red at >80%, y-axis 0–100%

**Behaviour:**
- Charts populated once on `showPage('dashboard')` via `GET /api/dashboard/metrics`
- X-axis labels: time of day (`HH:MM`) derived from timestamps
- Auto-refresh every 5 minutes (matching RRD precision) while Dashboard is the active page
- Empty / insufficient-data state: show "Collecting data — charts will fill in over 24h" message with a progress indicator showing how many samples have been collected
- All charts use the same dark theme palette already established (background `var(--surface)`, grid `var(--border)`, text `var(--text-2)`)

---

### Phase 4 — Disk Temperature

**Goal:** add a temperature column to the Physical Disks table.

**Backend — `system/disks.go`:**

Add `TempC *int` field to `DiskInfo`:
```go
TempC *int `json:"temp_c"` // nil = not available
```

Parse temperature from SMART data:

*ATA/SATA (`querySMARTATA`):*
- Look for smartctl JSON field `temperature.current` (available in smartctl 7+)
- Fallback: scan `ata_smart_attributes.table` for attribute ID 194
  (`Temperature_Celsius`) or ID 190 (`Airflow_Temperature_Cel`), use `raw.value`
  (the integer degrees field)

*NVMe (`querySMARTNVMe`):*
- The `nvme smart-log -o json` output includes `"temperature"` (in Kelvin) —
  convert: `tempC = temperature - 273`

Add `TempC` to the `smartctlOutput` struct:
```go
Temperature struct {
    Current int `json:"current"`
} `json:"temperature"`
```

Add to `nvmeSmartLog` struct:
```go
Temperature int `json:"temperature"` // Kelvin
```

Populate in both `querySMARTATA` and `querySMARTNVMe`.

**UI — `page-disks` table:**

Add a **Temp** column after **Wearout**:
- Display `°C` value (e.g. `38 °C`) or `—` if nil
- Color coding: ≤ 45°C → default text; 46–59°C → `var(--accent-warn)` orange; ≥ 60°C → `var(--accent-danger)` red

No additional API changes — `TempC` is returned as part of the existing `GET /api/disks` response.

---

## API Additions (v3.0.0)

```
Version
  GET    /api/version                         current version + releases URL

Binary Self-Update
  GET    /api/binary-update/check             { current, latest, update_available, download_url }
  WS     /ws/binary-update-apply              streams update progress, restarts on success

Dashboard Metrics
  GET    /api/dashboard/metrics               7 series × 288 data points (24h RRD)
  GET    /api/dashboard/metrics?series=...    subset of series
```

---

## New Internal Packages

| Package | Purpose |
|---|---|
| `internal/version/` | `Version` constant + `ReleasesURL` constant |
| `internal/rrd/` | lightweight circular-buffer RRD (288 slots × 7 series, JSON-persisted) |
| `internal/updater/` | GitHub Releases API check + binary download + `syscall.Exec` restart |

**New system file:**

| File | Purpose |
|---|---|
| `system/metrics_collector.go` | 5-minute goroutine that samples `/proc` and writes to RRD |

---

## Modified Files

| File | Change |
|---|---|
| `internal/config/config.go` | Add `LiveUpdateEnabled bool` to `AppConfig` |
| `system/disks.go` | Add `TempC *int` to `DiskInfo`; parse from smartctl/nvme JSON |
| `handlers/settings.go` | Handle `live_update_enabled` toggle |
| `handlers/router.go` | Register 4 new routes |
| `main.go` | Start `system.StartMetricsCollector()` goroutine; import `version` package |
| `static/index.html` | Version badge in sidebar; Dashboard charts; Temp column; Update section in Settings |

---

## Implementation Order

| Phase | Scope | Effort |
|---|---|---|
| 1 | Version badge + `/api/version` | Tiny |
| 2 | RRD collector + `/api/dashboard/metrics` (backend) | Medium |
| 3 | Dashboard charts UI | Medium |
| 4 | Disk temperature (SMART parse + table column) | Small |
| 5 | Live update (updater package + WebSocket handler + settings UI) | Medium |

Phase order rationale: RRD data starts accumulating immediately after merge, so the
collector should land first. The dashboard UI and temperature display are independent.
Live update is last because it requires the most careful testing (self-restart path).

---

## Notes & Constraints

- **No new Go module dependencies.** All features use Go stdlib (`net/http`, `os/exec`,
  `syscall`, `encoding/json`, `sync`) and existing third-party modules already in `go.mod`.
- **No `rrdtool` binary required.** The RRD subsystem is pure Go.
- **Binary self-update disabled by default.** Operator must explicitly opt in via Settings.
- **RRD file is lossy by design.** 24h of data at 5-min precision; older data is overwritten.
  This is intentional — use Prometheus/Grafana for long-term retention if needed.
- **`syscall.Exec` restart** replaces the process image in-place. Under systemd, the
  `Restart=on-failure` (or `always`) directive ensures the service comes back if exec fails.
  Admins should confirm their unit file has `Restart=` set before enabling live updates.
