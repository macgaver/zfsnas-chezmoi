# ZFS NAS Portal — REST API Reference

All API endpoints are served over HTTPS. The portal runs on port `8443` by default.

---

## Authentication

Two authentication methods are supported:

### 1. Session cookie
Log in via `POST /api/auth/login`. The server sets a `zfsnas_session` HttpOnly cookie that is sent automatically by browsers.

### 2. Bearer token (API key)
Generate a key in **Users → API Keys** (admin only). Pass it in every request:

```
Authorization: Bearer <your-api-key>
```

Bearer tokens work on all `/api/v2.0/` integration endpoints. They provide read-only access and do not grant access to the internal `/api/` endpoints.

---

## Response format

All responses are JSON. Successful responses return HTTP `200` with a body of the requested data (object or array). Errors return a non-2xx status with:

```json
{ "error": "description" }
```

---

## Internal API (`/api/…`)

Requires a valid session cookie. Admin-only endpoints are marked **[admin]**.

### Auth

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Log in — body: `{"username":"…","password":"…"}` |
| `POST` | `/api/auth/logout` | Invalidate current session |
| `GET` | `/api/auth/me` | Current session info (username, role) |
| `GET` | `/api/auth/sessions` | **[admin]** List all active sessions |
| `DELETE` | `/api/auth/sessions/{token}` | **[admin]** Revoke a session |
| `POST` | `/api/auth/setup` | First-run admin account creation |
| `PUT` | `/api/prefs` | Save UI preferences for current user |

### Users

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/users` | List all users |
| `POST` | `/api/users` | **[admin]** Create a user |
| `PUT` | `/api/users/{id}` | **[admin]** Update user (email, role, password) |
| `DELETE` | `/api/users/{id}` | **[admin]** Delete a user |

### API Keys

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/settings/api-keys` | **[admin]** List API keys (key values are masked) |
| `POST` | `/api/settings/api-keys` | **[admin]** Generate a new key — body: `{"name":"…"}`. The full key is returned once. |
| `DELETE` | `/api/settings/api-keys/{id}` | **[admin]** Delete a key |

### ZFS Pool

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/pool` | Pool info (name, size, health, members) |
| `POST` | `/api/pool` | **[admin]** Create a new pool |
| `GET` | `/api/pool/detect` | **[admin]** Detect importable pools |
| `POST` | `/api/pool/import` | **[admin]** Import a pool |
| `GET` | `/api/pool/status` | `zpool status` output |
| `GET` | `/api/pool/zfs-version` | ZFS kernel module version |
| `POST` | `/api/pool/grow` | **[admin]** Add a device to the pool |
| `POST` | `/api/pool/destroy` | **[admin]** Destroy the pool |
| `POST` | `/api/pool/upgrade` | **[admin]** Upgrade pool feature flags |

### Scrub

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/pool/scrub/status` | Scrub progress and history |
| `POST` | `/api/pool/scrub/start` | **[admin]** Start a scrub |
| `POST` | `/api/pool/scrub/stop` | **[admin]** Stop a running scrub |
| `GET` | `/api/pool/scrub/schedule` | Auto-scrub schedule config |
| `PUT` | `/api/pool/scrub/schedule` | **[admin]** Update auto-scrub schedule |

### Datasets

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/datasets` | List all datasets (recursive, pool root first) |
| `POST` | `/api/datasets` | **[admin]** Create a dataset |
| `PUT` | `/api/datasets/{path}` | **[admin]** Update dataset properties |
| `DELETE` | `/api/datasets/{path}` | **[admin]** Destroy a dataset |

### Snapshots

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/snapshots` | List all snapshots |
| `POST` | `/api/snapshots` | **[admin]** Create a snapshot |
| `POST` | `/api/snapshots/restore` | **[admin]** Roll back a dataset to a snapshot |
| `POST` | `/api/snapshots/clone` | **[admin]** Clone a snapshot to a new dataset |
| `POST` | `/api/snapshots/delete` | **[admin]** Delete a snapshot |

### Snapshot Schedules

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/snapshot-schedules` | List all snapshot policies |
| `POST` | `/api/snapshot-schedules` | **[admin]** Create a policy |
| `PUT` | `/api/snapshot-schedules/{id}` | **[admin]** Update a policy |
| `DELETE` | `/api/snapshot-schedules/{id}` | **[admin]** Delete a policy |
| `POST` | `/api/snapshot-schedules/{id}/run-now` | **[admin]** Trigger a policy immediately |

### Disks

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/disks` | List all physical disks with SMART data |
| `POST` | `/api/disks/scan` | **[admin]** Run `smartctl` scan on all disks |
| `POST` | `/api/disks/refresh` | **[admin]** Re-read disk SMART data |

### SMB Shares

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/shares` | List SMB shares |
| `POST` | `/api/shares` | **[admin]** Create a share |
| `PUT` | `/api/shares/{name}` | **[admin]** Update a share |
| `DELETE` | `/api/shares/{name}` | **[admin]** Delete a share |
| `GET` | `/api/shares/status` | Samba service status |
| `POST` | `/api/shares/service` | **[admin]** Start/stop Samba |
| `POST` | `/api/shares/set-password` | **[admin]** Set an SMB user password |

### NFS Shares

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/nfs/shares` | List NFS exports |
| `POST` | `/api/nfs/shares` | **[admin]** Create an export |
| `PUT` | `/api/nfs/shares/{id}` | **[admin]** Update an export |
| `DELETE` | `/api/nfs/shares/{id}` | **[admin]** Delete an export |
| `GET` | `/api/nfs/status` | NFS service status |
| `POST` | `/api/nfs/service` | **[admin]** Start/stop NFS |

### Alerts (SMTP)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/alerts` | Get alert configuration |
| `PUT` | `/api/alerts` | **[admin]** Update alert configuration |
| `POST` | `/api/alerts/test` | **[admin]** Send a test alert email |

### Settings

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/settings` | Get app settings (port, storage unit, etc.) |
| `PUT` | `/api/settings` | **[admin]** Update app settings |
| `GET` | `/api/settings/timezone` | Get current timezone and available list |
| `PUT` | `/api/settings/timezone` | **[admin]** Set system timezone |

### System

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/version` | App version, server IP, releases URL |
| `GET` | `/api/net/ifaces` | Network interfaces with IPv4 addresses |
| `GET` | `/api/sysinfo/diskio` | Live disk I/O snapshot (5 s rolling) |
| `GET` | `/api/dashboard/metrics` | 24 h RRD time-series (CPU, RAM, net, disk I/O) |
| `POST` | `/api/system/reboot` | **[admin]** Reboot the host |
| `POST` | `/api/system/shutdown` | **[admin]** Shut down the host |
| `GET` | `/api/audit` | Append-only activity log |

### Prerequisites & Binary Updates

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/prereqs` | Check required package install status |
| `POST` | `/api/prereqs/install-service` | **[admin]** Register and enable the systemd service |
| `GET` | `/api/updates/check` | **[admin]** Check for available apt updates |
| `GET` | `/api/binary-update/check` | **[admin]** Check for a new binary release on GitHub |

### WebSocket endpoints

| Path | Description |
|---|---|
| `GET /ws/prereqs-install` | **[admin]** Stream `apt-get install` output |
| `GET /ws/updates-apply` | **[admin]** Stream `apt-get upgrade` output |
| `GET /ws/binary-update-apply` | **[admin]** Stream in-place binary self-update |
| `GET /ws/terminal` | **[admin]** Interactive PTY terminal (xterm.js) |

---

## Integration API (`/api/v2.0/…`)

Read-only endpoints for use by external integrations and dashboard tools.

Authentication: session cookie **or** `Authorization: Bearer <api-key>`.

### System

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/v2.0/system/info` | `{"loadavg":[1m,5m,15m], "uptime_seconds":N}` |
| `GET` | `/api/v2.0/system/version` | Version string, e.g. `"ZFS-NAS-3.2.0"` |

### Pool & Datasets

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/v2.0/pool` | Array of pools with `name`, `healthy`, `status`, `size`, `allocated`, `free` |
| `GET` | `/api/v2.0/pool/dataset` | All datasets with `pool`, `name`, `used.parsed`, `available.parsed`, `quota.parsed`, `compression`, `mountpoint` |
| `GET` | `/api/v2.0/pool/snapshottask` | Snapshot policies with schedule and retention info |

### Snapshots

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/v2.0/snapshot` | All snapshots with `id`, `dataset`, `snapshot_name`, `properties.used`, `properties.creation` |

### Disks

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/v2.0/disk` | Physical disks with `name`, `serial`, `model`, `size`, `type`, `rotational`, `temperature`, `in_use` |

### Shares

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/v2.0/sharing/smb` | SMB shares with `id`, `name`, `path`, `ro`, `browsable`, `guestok`, `timemachine` |
| `GET` | `/api/v2.0/sharing/nfs` | NFS exports with `id`, `paths`, `hosts`, `ro`, `maproot_squash` |

### Services

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/v2.0/service` | `[{service:"cifs",state:"RUNNING"},{service:"nfs",state:"STOPPED"}]` |

### Alerts

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/v2.0/alert/list` | Empty array (no persistent alert log) |

### homepage.dev widget

This API is compatible with the **TrueNAS** widget on [homepage.dev](https://gethomepage.dev/widgets/services/truenas/). Add the following to your `services.yaml`:

```yaml
- My NAS:
    href: https://192.168.1.10:8443
    widget:
      type: truenas
      url: https://192.168.1.10:8443
      key: <your-api-key>
      version: 1        # required — forces HTTP REST mode
      enablePools: true
```

> `version: 1` is required. The WebSocket transport (v2 default) is not implemented.
