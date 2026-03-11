# Version 3.1.0 — Plan & Changelog

## Overview
Version 3.1.0 is a quality-of-life and feature-completeness release built on top of 3.0.0.
It covers UI polish, better mobile/iPad support, richer SMB share options, and improved
usability across the portal.

---

## Features & Changes

### 1. Pool Capacity Percentage in Top Bar
- The top-bar pool summary now shows used and free space with a color-coded percentage.
- Color thresholds: green < 70 %, yellow < 85 %, red ≥ 85 %.

### 2. Favicon & iOS PWA Icon
- Browser tab now shows the ZFS NAS rack logo as an SVG favicon (`static/favicon.svg`).
- iOS/iPadOS home-screen web app icon: a 180×180 PNG generated on-the-fly by
  `handlers/icon.go` (served at `/apple-touch-icon.png`, no auth required so iOS can
  fetch it before login).
- `static/login.html` and `static/setup.html` also reference the favicon and PWA meta tags.

### 3. iOS PWA Zoom Fix
- Inputs now use `font-size: 16px` minimum (prevents iOS auto-zoom on focus).
- A `visibilitychange` listener snaps the viewport to `maximum-scale=1` for 300 ms when
  returning to the app from another app, then restores the original viewport, eliminating
  the stuck-zoom issue on iPadOS.

### 4. Slim Icon-Only Sidebar on Small Screens
- On screens ≤ 600 px the sidebar collapses to 52 px wide: only icons visible, header and
  labels hidden, icons centered.
- Implemented with a `@media (max-width: 600px)` block in `static/style.css`.

### 5. Import ZFS Pool — Rename & Force-Import Modal
- "Detect Existing Pool" button renamed to **Import ZFS Pool**.
- When the import fails with a "use -f to force" error the browser `alert()` is replaced
  by a proper confirmation modal (`modal-force-import`) explaining the risk and letting
  the user confirm before retrying with `zpool import -f`.
- New backend function: `system.ImportPoolForce(name string) error`.
- `HandleImportPool` in `handlers/pools.go` accepts a `force bool` JSON field.

### 6. Recursive Dataset Delete Modal
- When deleting a dataset that has children, the "use -r" Samba error is caught and
  presented in a confirmation modal (`modal-recursive-delete`) instead of a raw
  `alert()`.
- New backend function: `system.DestroyDatasetRecursive(name string) error`.
- `HandleDeleteDataset` accepts `?recursive=true` query parameter.

### 7. ZFS Pool Upgrade Button
- `_fetchPoolStatus()` parses `zpool status` output; if it contains "zpool upgrade" a blue
  **Upgrade Pool** button appears beside the Import button.
- New modal `modal-pool-upgrade` with confirmation before running `zpool upgrade <name>`.
- New backend function: `system.UpgradePool(name string) error`.
- New handler: `HandleUpgradePool` in `handlers/pools.go`.
- New route: `POST /api/pool/upgrade`.
- New audit action: `ActionUpgradePool`.

### 8. Power Button (Reboot / Shutdown)
- The Updates tab header now has a **Power** button with a dropdown to Reboot or Shutdown.
- Confirmation modal (`modal-power`) before executing.
- New file: `system/power.go` — `Reboot()` and `Shutdown()` via `sudo shutdown`.
- New file: `handlers/power.go` — `HandleReboot`, `HandleShutdown` (admin-only,
  audit-logged).
- New routes: `POST /api/system/reboot`, `POST /api/system/shutdown`.
- New audit actions: `ActionSystemReboot`, `ActionSystemShutdown`.

### 9. ZFS Disk Path Resolution (by-id → /dev/sdX)
- Pool member disk paths shown in the ZFS Pool tab are now resolved from
  `/dev/disk/by-id/…` or `/dev/disk/by-uuid/…` symlinks to their canonical
  `/dev/sdX` (or `/dev/nvmeX`) paths via `filepath.EvalSymlinks`.
- Implemented in `system/zfs.go` as `resolveDevPath()`, called inside `poolMembers()`.
- Fallback to the original path if resolution fails or result is outside `/dev/`.

### 10. Server Timezone Configuration
- New **Server Timezone** card in the Settings tab.
- Dropdown lists all timezones from `timedatectl list-timezones`; current timezone
  pre-selected.
- Saving calls `sudo timedatectl set-timezone`; takes effect immediately.
- Info tooltip explains impact on snapshot schedules, scrub schedule, and audit log.
- New file: `system/timezone.go` — `GetTimezone()`, `SetTimezone()`, `ListTimezones()`.
- New handlers in `handlers/settings.go`: `HandleGetTimezone`, `HandleSetTimezone`.
- New routes: `GET /api/settings/timezone`, `PUT /api/settings/timezone`.

### 11. Dataset Detail — Proper HTML Modal
- Clicking a dataset in the top-bar chart previously showed a raw `alert()` popup.
- Replaced with a styled modal (`modal-dataset-detail`) showing the same information
  (name, used, available, compression, mountpoint, creation date) in a clean layout.

### 12. User Creation — SMB-Only Role Improvements
- When **SMB-Only** role is selected in the Create User form, the password field is
  hidden (SMB-only users cannot log into the portal).
- The form resets completely (all fields cleared, role back to default) each time the
  modal is reopened.
- Backend: `HandleCreateUser` skips bcrypt entirely for SMB-only users (empty
  `PasswordHash`).

### 13. User List — Edit, Delete & SMB Password Improvements
- Edit button is now a small pencil icon (✏️) that opens the Edit User modal
  (`modal-edit-user`) allowing changes to email, password, and role.
- Delete button is now a red trash icon (🗑️).
- **Set SMB Password** button is now available for users of all roles (not just
  SMB-only), so admin and read-only users can also be given Samba credentials.

### 14. Persist Activity Bar Collapsed State
- The collapsed/expanded state of the bottom activity bar is saved per user in
  `config/users.json` under a `preferences` object.
- On login, the saved preference is read from `/api/auth/me` and applied immediately.
- Toggle fires `PUT /api/prefs` to persist the change.
- New struct: `UserPreferences { ActivityBarCollapsed bool }` in
  `internal/config/config.go`.
- New handler: `HandleUpdatePrefs` in `handlers/auth.go`.
- New route: `PUT /api/prefs`.

### 15. SMB Share — Advanced Options
Six new per-share settings added to the Create/Edit Share modal and `smb.conf` output:

| Setting | Description |
|---|---|
| **Time Machine** | Advertises the share as a macOS Time Machine target (`fruit` VFS). Optional quota in GB (0 = unlimited). |
| **Recycle Bin** | Moves deleted files to `.recycle/` instead of deleting. Optional retention in days (0 = keep forever). A nightly 2 AM goroutine cleans files older than the retention period. |
| **Durable Handles** | Enables SMB2/3 durable handles (`posix locking = no`) for seamless client reconnection. Checked by default. |
| **Apple Encoding** | Enables `catia` VFS module with the standard macOS character mapping so special filename characters work correctly from Mac clients. |
| **Allowed Hosts** | `hosts allow` — space-separated IPs/subnets permitted to access the share. |
| **Hosts Deny** | `hosts deny` — space-separated IPs/subnets explicitly denied. |

- `SMBShare` struct in `system/smb.go` extended with 8 new fields.
- `applySMBConf` updated to emit all VFS object combinations, catia mappings, recycle
  parameters (including `directory_mode`, `subdir_mode`, `maxsize`), and Time Machine
  fruit settings.
- New function: `system.StartRecycleCleaner(configDir string)` — goroutine started in
  `main.go`.

### 16. Close Modals by Clicking Outside
- All modal dialogs can now be dismissed by clicking the darkened backdrop area outside
  the dialog box, without needing the ✕ button.
- Implemented with a single `document.addEventListener('click', …)` listener that maps
  each backdrop element ID to its close function.

### 17. Settings Tab — Multi-Column Grid Layout
- The four settings cards (General, Samba, Timezone, Email Alerts) are now arranged in a
  responsive CSS grid: `repeat(auto-fill, minmax(420px, 1fr))`.
- On wide screens: cards sit side by side in two columns.
- On narrow screens: falls back to single-column stacking.
- `max-width: 520px` constraint removed from each card.

---

## Files Changed / Added

| File | Status | Notes |
|---|---|---|
| `static/index.html` | Modified | All UI changes (modals, settings grid, SMB modal, user list, etc.) |
| `static/style.css` | Modified | 16px input font-size, slim mobile sidebar media query |
| `static/favicon.svg` | New | Rack icon crop for browser tab favicon |
| `static/login.html` | Modified | Favicon + PWA meta tags |
| `static/setup.html` | Modified | Favicon + PWA meta tags |
| `system/smb.go` | Modified | New SMBShare fields, updated applySMBConf, StartRecycleCleaner |
| `system/zfs.go` | Modified | UpgradePool, ImportPoolForce, DestroyDatasetRecursive, resolveDevPath |
| `system/power.go` | New | Reboot, Shutdown |
| `system/timezone.go` | New | GetTimezone, SetTimezone, ListTimezones |
| `handlers/icon.go` | New | HandleAppleTouchIcon (180×180 PNG generator) |
| `handlers/power.go` | New | HandleReboot, HandleShutdown |
| `handlers/pools.go` | Modified | HandleUpgradePool, HandleImportPool (force support) |
| `handlers/datasets.go` | Modified | HandleDeleteDataset (recursive support) |
| `handlers/auth.go` | Modified | HandleMe returns preferences, HandleUpdatePrefs |
| `handlers/settings.go` | Modified | HandleGetTimezone, HandleSetTimezone |
| `handlers/users.go` | Modified | HandleCreateUser skips bcrypt for smb-only |
| `handlers/router.go` | Modified | All new routes registered |
| `internal/config/config.go` | Modified | UserPreferences struct, Preferences field on User |
| `internal/audit/audit.go` | Modified | ActionUpgradePool, ActionSystemReboot, ActionSystemShutdown |
| `main.go` | Modified | system.StartRecycleCleaner(absConfig) |
