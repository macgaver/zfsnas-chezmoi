# Security

> **Scope:** This document covers a **storage-only ZNAS deployment** — the
> optional **VMs & Containers** (Incus virtualization) feature is *not*
> enabled. If you run virtualization, see **[`SECURITY+.md`](SECURITY+.md)**,
> which documents the additional sudo entries that feature requires
> (`ZFSNAS_INCUSNET`, `ZFSNAS_INCUS`, `ZFSNAS_VMSETUP`, `ZFSNAS_SYNCOID`,
> and Incus InterLink trust).

## Service capabilities

The `zfsnas.service` systemd unit grants the non-root service account one Linux
capability: **`CAP_NET_BIND_SERVICE`** (`AmbientCapabilities=`). This is the
single capability needed to bind privileged ports (below 1024) and is used only
when the optional **Settings → Server Port → "Also bind port 443"** option is
enabled, so the portal can listen on the standard HTTPS port without running as
root. It grants no other elevated rights; leaving it set when the option is off
is harmless.

## Sudo access model

ZFS NAS Portal requires `sudo` privileges because most ZFS, Samba, NFS, SMART, and system operations must run as root. Three configurations are supported — the portal's **Prerequisites** tab reports which one is active.

| Mode | How it works | Recommended? |
|---|---|---|
| **Running as root** | Process UID is 0; no sudo needed | No — high blast radius |
| **NOPASSWD: ALL** | Blanket root delegation | Acceptable for home / lab use |
| **Hardened sudoers** | Whitelist of specific commands only | Yes — production deployments |

---

## Restricting sudo (recommended for production)

### 1 — Create a dedicated service account

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin zfsnas
```

Place the binary and the `config/` directory somewhere the new user owns (e.g. `/opt/zfsnas/`):

```bash
sudo mkdir -p /opt/zfsnas
sudo chown zfsnas:zfsnas /opt/zfsnas
sudo cp zfsnas /opt/zfsnas/
```

### 2 — Add the sudoers entry

Run `sudo visudo -f /etc/sudoers.d/zfsnas` and paste the block below.

> **Note:** Paths are correct for Ubuntu 22.04 / 24.04 LTS. Verify with `which <command>` if you are on a different distribution.
>
> **sudo-rs (Ubuntu 26.04+):** Ubuntu 26.04 ships **sudo-rs** (the Rust rewrite of sudo) as the default. sudo-rs is stricter about wildcards in command arguments — `*` may only appear as the **entire trailing argument** (e.g. `cmd *` is allowed; `cmd /path/*`, `cmd /a*/b`, and `cmd * literal` are rejected with "wildcards are not allowed in command arguments"). When sudo-rs rejects an entry, every line that follows it in the file is silently dropped, which manifests as "missing" entries in the **Prerequisites → Sudoers Hardening** view. The template below is written to satisfy sudo-rs; path scoping that previously lived in the sudoers file (e.g. `/mnt/*`) has moved into the portal itself, which validates every File Browser target against known dataset mountpoints and share roots before invoking the underlying command.

```sudoers
# ── ZFS pool & dataset management ────────────────────────────────────────────
# since v1.0.0 — pool creation, import, status, dataset CRUD, snapshots
# since v2.0.0 — zpool scrub (Scrub Management page)
# since v4.0.0 — zpool offline/online/clear (Pool Fixer Wizard)
# since v5.0.0 — zfs load-key / unload-key (native encryption)
# since v6.1.0 — zfs send / zfs recv (remote & local dataset replication)
# since v6.3.21 — zpool replace (Pool Fixer Wizard: disk replacement for DEGRADED pools)
# since v6.3.26 — zfs allow (InterLink push & schedule replication: ZFS delegation to service user)
Cmnd_Alias ZFSNAS_ZFS = \
    /usr/sbin/zpool *, \
    /usr/sbin/zfs *

# ── Samba (SMB shares) ────────────────────────────────────────────────────────
# since v1.0.0 — Samba service control, user provisioning, share config write
# since v3.0.0 — useradd with optional --uid/--gid/--no-user-group (custom UID/GID feature);
#                groupadd -g <gid> for primary group pre-creation;
#                userdel -f / groupdel / gpasswd -d for user deletion
# since v6.1.0 — smbstatus -S (active session listing on the SMB shares page)
# since v6.3.27 — chgrp/chmod 0770 replace chmod 777 for share path setup;
#                 groupadd --system sambashare ensures the group exists
#                 chmod / chown / mkdir / rmdir / find moved to ZFSNAS_FILES (path-scoped to /mnt/* etc.)
Cmnd_Alias ZFSNAS_SMB = \
    /usr/bin/systemctl reload smbd, \
    /usr/bin/systemctl restart smbd, \
    /usr/bin/systemctl start smbd, \
    /usr/bin/systemctl stop smbd, \
    /usr/bin/systemctl start nmbd, \
    /usr/bin/systemctl stop nmbd, \
    /usr/sbin/useradd *, \
    /usr/sbin/usermod -aG sambashare *, \
    /usr/sbin/userdel -f *, \
    /usr/sbin/groupadd *, \
    /usr/sbin/groupdel *, \
    /usr/bin/gpasswd *, \
    /usr/bin/smbpasswd *, \
    /usr/bin/chgrp sambashare *, \
    /usr/bin/tee /etc/samba/smb.conf, \
    /usr/bin/smbstatus -S

# ── NFS shares ────────────────────────────────────────────────────────────────
# since v2.0.0 — NFS share management and export config write
# since v6.3.22 — chmod 0777 on dataset path moved to ZFSNAS_FILES (path-scoped to /mnt/* etc.)
Cmnd_Alias ZFSNAS_NFS = \
    /usr/sbin/exportfs -ra, \
    /usr/bin/systemctl start nfs-server, \
    /usr/bin/systemctl stop nfs-server, \
    /usr/bin/tee /etc/exports

# ── SMART & hardware monitoring ───────────────────────────────────────────────
# since v1.0.0 — SMART disk health data (SAS/SATA)
# since v3.0.0 — NVMe health and temperature monitoring
# since v6.5.3 — DMI/SMBIOS reads for motherboard, BIOS, and per-DIMM memory
#   inventory shown in the SysInfo popup
# NOTE: on sudo-rs hosts (Ubuntu 26.04+) the trailing
#   /usr/bin/cat /proc/*/smaps_rollup line is widened to /usr/bin/cat *
#   because sudo-rs only accepts `*` as the entire trailing argument and
#   refuses any wildcard with a literal prefix or suffix. The portal-side
#   PID filter in system/memprocs.go remains the boundary.
Cmnd_Alias ZFSNAS_SMART = \
    /usr/sbin/smartctl *, \
    /usr/bin/nvme smart-log -o json *, \
    /usr/sbin/dmidecode *, \
    /usr/bin/cat /proc/*/smaps_rollup    # or `cat *` on sudo-rs hosts

# ── Disk preparation & wipe ───────────────────────────────────────────────────
# since v1.0.0 — wipe and partition a disk before adding it to a pool;
#   wipefs clears signatures, sgdisk creates GPT layout, dd zero-fills,
#   partprobe + udevadm settle kernel/udev state, blkid reads UUIDs
# NOTE: sgdisk lives at /usr/sbin/sgdisk on Debian 12 and at /usr/bin/sgdisk on
#   some Ubuntu releases. Verify the correct path with `which sgdisk` and adjust
#   the two sgdisk lines below if needed.
Cmnd_Alias ZFSNAS_DISK = \
    /usr/sbin/wipefs -a *, \
    /usr/sbin/sgdisk *, \
    /usr/bin/dd if=/dev/zero *, \
    /usr/sbin/partprobe *, \
    /usr/bin/udevadm settle *, \
    /usr/sbin/blkid -o export

# ── iSCSI sharing ─────────────────────────────────────────────────────────────
# since v6.1.0 — iSCSI target management via targetcli-fb; service control for
#   rtslib-fb-targetctl / targetclid / tgt (whichever is installed)
Cmnd_Alias ZFSNAS_ISCSI = \
    /usr/bin/targetcli, \
    /usr/bin/systemctl start rtslib-fb-targetctl, \
    /usr/bin/systemctl stop rtslib-fb-targetctl, \
    /usr/bin/systemctl restart rtslib-fb-targetctl, \
    /usr/bin/systemctl start targetclid, \
    /usr/bin/systemctl stop targetclid, \
    /usr/bin/systemctl restart targetclid, \
    /usr/bin/systemctl start tgt, \
    /usr/bin/systemctl stop tgt, \
    /usr/bin/systemctl restart tgt

# ── S3 Object Server (MinIO) ──────────────────────────────────────────────────
# since v6.3.20 — optional MinIO S3 server; binary download, system account
#   setup, service unit, env file, data directory, TLS certs, and service control
Cmnd_Alias ZFSNAS_MINIO = \
    /usr/bin/wget -q -O /usr/local/bin/minio *, \
    /usr/bin/wget -q -O /usr/local/bin/mc *, \
    /usr/bin/chmod +x /usr/local/bin/minio, \
    /usr/bin/chmod +x /usr/local/bin/mc, \
    /usr/sbin/useradd --system --home-dir /var/lib/minio --shell /usr/sbin/nologin minio-user, \
    /usr/bin/mkdir -p /var/lib/minio, \
    /usr/bin/mkdir -p /var/lib/minio/.minio/certs, \
    /usr/bin/mkdir -p *, \
    /usr/bin/chown minio-user\:minio-user /var/lib/minio, \
    /usr/bin/chown -R minio-user\:minio-user /var/lib/minio/.minio/certs, \
    /usr/bin/chown -R minio-user\:minio-user *, \
    /usr/bin/chown root\:minio-user /etc/default/minio, \
    /usr/bin/chmod 640 /etc/default/minio, \
    /usr/bin/chmod 640 /var/lib/minio/.minio/certs/private.key, \
    /usr/bin/tee /var/lib/minio/.minio/certs/public.crt, \
    /usr/bin/tee /var/lib/minio/.minio/certs/private.key, \
    /usr/bin/rm -f /var/lib/minio/.minio/certs/public.crt, \
    /usr/bin/rm -f /var/lib/minio/.minio/certs/private.key, \
    /usr/bin/tee /etc/systemd/system/minio.service, \
    /usr/bin/tee /etc/default/minio, \
    /usr/bin/systemctl enable minio, \
    /usr/bin/systemctl disable minio, \
    /usr/bin/systemctl start minio, \
    /usr/bin/systemctl stop minio, \
    /usr/bin/systemctl restart minio

# ── UPS Management (NUT) ──────────────────────────────────────────────────────
# since v6.3.22 — optional NUT daemon; install, auto-detect UPS, write /etc/nut/
#   config files, service control; uninstall purges packages and removes /etc/nut;
#   udevadm control/trigger used after writing USB udev rules for UPS detection
Cmnd_Alias ZFSNAS_UPS = \
    /usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get purge -y nut nut-client nut-server, \
    /usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get remove -y nut nut-client, \
    /usr/bin/udevadm control --reload-rules, \
    /usr/bin/udevadm trigger --subsystem-match=usb, \
    /usr/bin/systemctl enable nut-server, \
    /usr/bin/systemctl disable nut-server, \
    /usr/bin/systemctl start nut-server, \
    /usr/bin/systemctl stop nut-server, \
    /usr/bin/systemctl restart nut-server, \
    /usr/bin/systemctl enable nut-client, \
    /usr/bin/systemctl disable nut-client, \
    /usr/bin/systemctl start nut-client, \
    /usr/bin/systemctl stop nut-client, \
    /usr/bin/systemctl enable nut-monitor, \
    /usr/bin/systemctl disable nut-monitor, \
    /usr/bin/systemctl start nut-monitor, \
    /usr/bin/systemctl stop nut-monitor, \
    /usr/bin/systemctl reset-failed, \
    /usr/sbin/nut-scanner *, \
    /usr/bin/nut-scanner, \
    /usr/bin/chown root\:nut /etc/nut, \
    /usr/bin/chmod 750 /etc/nut, \
    /usr/bin/chown root\:nut /etc/nut/nut.conf, \
    /usr/bin/chown root\:nut /etc/nut/ups.conf, \
    /usr/bin/chown root\:nut /etc/nut/upsd.conf, \
    /usr/bin/chown root\:nut /etc/nut/upsd.users, \
    /usr/bin/chown root\:nut /etc/nut/upsmon.conf, \
    /usr/bin/chmod 640 /etc/nut/nut.conf, \
    /usr/bin/chmod 640 /etc/nut/ups.conf, \
    /usr/bin/chmod 640 /etc/nut/upsd.conf, \
    /usr/bin/chmod 640 /etc/nut/upsd.users, \
    /usr/bin/chmod 640 /etc/nut/upsmon.conf, \
    /usr/bin/tee /etc/nut/nut.conf, \
    /usr/bin/tee /etc/nut/upsd.conf, \
    /usr/bin/tee /etc/nut/upsd.users, \
    /usr/bin/tee /etc/nut/upsmon.conf, \
    /usr/bin/tee /etc/nut/ups.conf, \
    /usr/bin/rm -rf /etc/nut, \
    /usr/bin/rm -rf /etc/systemd/system/nut-driver.target.wants, \
    /usr/bin/rm -rf /etc/systemd/system/nut-driver@.service.d

# ── Folder usage scanning ─────────────────────────────────────────────────────
# since v6.0.0 — Folder TreeMap feature; scans dataset mount points for per-folder sizes
Cmnd_Alias ZFSNAS_SCAN = \
    /usr/bin/du -b -d 6 *

# ── File Browser (v6.4.3+) ────────────────────────────────────────────────────
# since v6.4.3 — chown/chmod on files and folders within dataset mountpoints via File Browser.
# since v6.4.4 — find used for directory listing.
# since v6.4.25 — path scoping moved from sudoers into the portal because sudo-rs
#   (Ubuntu 26.04+) does not allow wildcards in non-trailing argument positions.
#   The portal validates every target path against known dataset mountpoints
#   and share roots before invoking these commands; arbitrary paths cannot be
#   targeted from the UI.
# since v6.5.29 — Browse Files promoted to a full file browser. mkdir / rm / mv /
#   cp -a entries added so the new + Folder, Delete, Move, Copy buttons can
#   mutate inside dataset mountpoints + share roots (each path is SafeJoin'd
#   against a knownRoot server-side before any sudo call runs, regardless of
#   how permissive the alias entry looks).
Cmnd_Alias ZFSNAS_FILES = \
    /usr/bin/find *, \
    /usr/bin/chown *, \
    /usr/bin/chown -R *, \
    /usr/bin/chmod *, \
    /usr/bin/chmod -R *, \
    /usr/bin/mkdir -p *, \
    /usr/bin/rm -rf *, \
    /usr/bin/rm -f *, \
    /usr/bin/mv -f *, \
    /usr/bin/mv -n *, \
    /usr/bin/cp -a -f *, \
    /usr/bin/cp -a -n *, \
    /usr/bin/cp -a *, \
    /usr/bin/stat -c *, \
    /usr/bin/head -c *, \
    /usr/bin/cat *

# ── System management ─────────────────────────────────────────────────────────
# since v1.0.0 — timezone setting, shutdown/reboot from power menu, ZFS kernel module load
# since v3.0.0 — systemctl restart zfsnas ("Restart Portal" in the power menu)
# since v6.3.22 — tee entries for ARC Level 1 tuning (modprobe.d + sysfs parameters)
Cmnd_Alias ZFSNAS_SYSTEM = \
    /usr/bin/timedatectl set-timezone *, \
    /usr/sbin/shutdown *, \
    /usr/sbin/modprobe zfs, \
    /usr/bin/systemctl restart zfsnas, \
    /usr/bin/tee /etc/modprobe.d/zfs.conf, \
    /usr/bin/tee /sys/module/zfs/parameters/zfs_arc_max, \
    /usr/bin/tee /sys/module/zfs/parameters/zfs_arc_min

# ── Network Time (chrony NTP) ─────────────────────────────────────────────────
# since v6.4.18 — NTP server configuration via Settings > General > Network Time card
#   (only visible when chrony is installed and running)
Cmnd_Alias ZFSNAS_NTP = \
    /usr/bin/tee /etc/chrony/chrony.conf, \
    /usr/bin/systemctl restart chronyd

# ── OS updates & service installation ────────────────────────────────────────
# since v1.0.0 — prerequisite package install (apt-get install) and
#   systemd service setup (tee + daemon-reload + enable)
# since v3.0.0 — OS package updates (apt-get upgrade) from the Settings page
# since v6.1.0 — apt-get remove / autoremove for optional feature uninstall
#   (e.g. targetcli-fb removal when iSCSI feature is disabled)
# since v6.6.27 — tee /etc/apt/apt.conf.d/20auto-upgrades toggles the OS
#   automatic-background-upgrade service (unattended-upgrades) on/off from the
#   OS Packages card
Cmnd_Alias ZFSNAS_APT = \
    /usr/bin/apt-get *, \
    /usr/bin/tee /etc/apt/apt.conf.d/20auto-upgrades, \
    /usr/bin/tee /etc/systemd/system/zfsnas.service, \
    /usr/bin/systemctl daemon-reload, \
    /usr/bin/systemctl enable zfsnas

# ── Disk Power Management (hdparm) ────────────────────────────────────────────
# since v6.4.6 — APM level, spindown timeout, write cache, acoustic management
#   applied immediately to all physical disks; persisted in /etc/hdparm.conf
Cmnd_Alias ZFSNAS_DISKPOWER = \
    /usr/sbin/hdparm *, \
    /usr/bin/tee /etc/hdparm.conf

# ── System/Platform Power Management ─────────────────────────────────────────
# since v6.4.6 — CPU governor via sysfs (no extra package required); PCIe ASPM
#   and USB autosuspend applied immediately via sysfs; all settings persist
#   across reboots via /etc/rc.local (managed block written by the portal)
Cmnd_Alias ZFSNAS_SYSPOWER = \
    /usr/bin/tee *, \
    /usr/bin/chmod +x /etc/rc.local, \
    /usr/bin/systemctl enable rc-local, \
    /usr/bin/systemctl start rc-local

# ── Sudoers self-management (Sudoers Hardening UI feature - optional) ───────────────────────
# since v6.3.31 — lets the portal overwrite its own sudoers file when the
#   Sudoers Hardening feature is enabled in the Prerequisites tab.
# since v6.3.32 — cat /etc/sudoers.d/zfsnas lets the portal read its own file
#   so the Sudoers Review diff is always accurate (detects manual edits).
# since v6.4.25 — chmod 0440 /etc/sudoers.d/zfsnas corrects the file
#   permissions after each write; sudo tee creates new files with umask-derived
#   permissions (typically 0644) and this restores the recommended 0440.
#Cmnd_Alias ZFSNAS_SECURITY = \
#    /usr/bin/tee /etc/sudoers.d/zfsnas, \
#    /usr/bin/cat /etc/sudoers.d/zfsnas, \
#    /usr/bin/chmod 0440 /etc/sudoers.d/zfsnas

# ── Grant all of the above, passwordless, to the service account ──────────────
#
# To enable the optional Sudoers Hardening UI feature, also add `ZFSNAS_SECURITY`.
zfsnas ALL=(ALL) NOPASSWD: \
    ZFSNAS_ZFS, ZFSNAS_SMB, ZFSNAS_NFS, ZFSNAS_ISCSI, ZFSNAS_MINIO, ZFSNAS_UPS, ZFSNAS_DISKPOWER, ZFSNAS_SYSPOWER, ZFSNAS_SMART, ZFSNAS_DISK, ZFSNAS_SCAN, ZFSNAS_FILES, ZFSNAS_SYSTEM, ZFSNAS_NTP, ZFSNAS_APT
```

### 3 — Run the portal as the service account

Update `/etc/systemd/system/zfsnas.service` to use the new user:

```ini
[Service]
User=zfsnas
WorkingDirectory=/opt/zfsnas
ExecStart=/opt/zfsnas/zfsnas
```

### Notes

- **Web terminal** — the browser terminal runs a shell as the `zfsnas` user. With the restricted sudoers entry above, any `sudo` command typed in that terminal is still limited to the whitelist. If you do not use the web terminal feature you can remove the `/ws/terminal` route or simply accept that a logged-in admin can run a shell with the same restrictions.
- **`chgrp sambashare *`** (in `ZFSNAS_SMB`) — sets group ownership of every newly created SMB share directory to `sambashare`. The path wildcard is required because share directories can live at any path within your ZFS mount hierarchy.
- **`chmod *` / `chmod -R *`** (in `ZFSNAS_FILES`) — covers all permission changes: 0777 for NFS share paths, 0770 for SMB share directories, and 0700 for user home directories. The portal itself enforces path scoping (every target is validated against known dataset mountpoints and share roots before the command runs) because sudo-rs (Ubuntu 26.04+) does not allow wildcards in non-trailing argument positions. The previous `chmod * /mnt/*` form is no longer expressible.
- **`tee` for config files** — `tee` is granted as `tee *` in `ZFSNAS_SYSPOWER` (where the target paths are dynamic — per-CPU scaling governor, per-USB-device autosuspend). Specific tee paths (`smb.conf`, `exports`, `zfsnas.service`, `zfs.conf`, ARC sysfs paths, `/etc/hdparm.conf`, `/etc/chrony/chrony.conf`) remain in their feature-specific aliases for clarity, even though `tee *` would cover them.
- **`dd` / `wipefs` / `sgdisk`** — used by the "Wipe Disk" feature before adding a disk to a pool. These are destructive by design; ensure only trusted admins have access to the portal.
- **`zfs load-key` / `zfs unload-key`** — used for ZFS native encryption (v5.0.0+). Key files are stored in `config/keystore/` and are only readable by the `zfsnas` user.
- **Force-disconnect & Lock (v6.4.13+)** — when a user clicks "Force Disconnect & Lock" on an encrypted dataset, the portal checks the SMB share config for any shares backed by that dataset's mountpoint. If found, `systemctl stop smbd` is issued (already in `ZFSNAS_SMB`), the dataset is unmounted and its key unloaded, then `systemctl start smbd` restarts the service. The stop/start is brief (typically under a second) and only occurs when needed. Other SMB shares are briefly unavailable during this window.
- **`systemctl restart zfsnas`** — used by the "Restart Portal" option in the power menu (v3.0.0+). Only available to admin-role users.
- **`smbstatus -S`** — used to list active SMB sessions per share (v6.1.0+). On Debian/Ubuntu the `smbstatus` binary only exposes session data to root, so sudo is required. NFS session data comes from `showmount -a` and `/proc/fs/nfsd/clients/`, which are readable without sudo.
- **`find *`** (in `ZFSNAS_FILES`) — used for File Browser directory listings (v6.4.4+) and to delete files in SMB `.recycle/` folders (v6.0.0+). Path scoping moved from sudoers to Go (sudo-rs does not allow `find /mnt/*`); the portal validates targets against known dataset mountpoints and share roots.
- **`targetcli`** — used by the iSCSI sharing feature (v6.1.0+) to configure LIO targets, backstores, ACLs, and CHAP credentials via a piped script. The portal generates the full targetcli command sequence internally; no user-supplied input is passed directly to the shell. If you do not use iSCSI, you can omit `ZFSNAS_ISCSI` from the grant line and remove the `targetcli-fb` package.
- **iSCSI service names** — three possible service names are listed (`rtslib-fb-targetctl`, `targetclid`, `tgt`) to cover different `targetcli-fb` package versions and distributions. Only the service actually installed on your system will be used; the unused entries are harmless.
- **`wget` for MinIO binaries** — the portal downloads `minio` and `mc` directly from `dl.min.io` via `sudo wget`. The destination paths are fixed (`/usr/local/bin/minio` and `/usr/local/bin/mc`); only the source URL is a wildcard. If you prefer not to allow `wget` with sudo, pre-install the binaries manually and omit the `wget` lines from the sudoers entry.
- **`mkdir -p *` and `chown -R minio-user:minio-user *`** — the MinIO data directory is user-configured and can be any path, so these entries use wildcards. Scope is limited in practice to the path you set in the MinIO configuration. If your data directory is always under a fixed parent (e.g. `/data`), you can tighten these to `/usr/bin/mkdir -p /data/*` and `/usr/bin/chown -R minio-user\:minio-user /data/*`.
- **`nut-scanner *` / `/usr/bin/nut-scanner`** — the NUT USB/HID scanner runs under sudo because it requires raw USB device access. The portal always invokes it with either `-C -N` (fast USB-only scan) or `-a -t 2` (full scan with 2 s timeout). Two entries cover different installation paths: `/usr/sbin/nut-scanner` (Debian/Ubuntu default) and `/usr/bin/nut-scanner` (some distros). If you do not use the UPS feature you can omit `ZFSNAS_UPS` from the grant line entirely.
- **`systemctl enable/disable/start/stop nut-monitor`** — the `nut-monitor` service is an alias used by some NUT packages (alongside `nut-client`). Both service names are included to cover package version differences across distributions.
- **`/sbin/shutdown -h +0` (UPS watcher)** — the UPS shutdown watcher calls `/sbin/shutdown -h +0` directly (no `sudo` wrapper) to halt the system when battery thresholds are breached. This command does not appear in the sudoers whitelist; it relies on the process having shutdown permission via polkit (standard on Ubuntu 22.04+) or on the portal running as root. If you observe shutdown failures, add a polkit rule granting the `zfsnas` user shutdown permission, or add `/sbin/shutdown -h +0` to `ZFSNAS_SYSTEM` and update the code to use `sudo`.
- **`env DEBIAN_FRONTEND=noninteractive apt-get purge/remove`** — NUT uninstall wraps `apt-get` with the `env` command to suppress interactive prompts. The sudoers entry therefore targets `/usr/bin/env` (not `/usr/bin/apt-get` directly) and must match the exact argument sequence shown in `ZFSNAS_UPS`. The NUT *install* path (`apt-get install -y nut nut-client`) is already covered by the wildcard entry in `ZFSNAS_APT`.
- **`tee /etc/sudoers.d/zfsnas`** — used by the Sudoers Hardening feature (v6.3.31+) to apply in-portal sudoers changes. Only the portal's own drop-in file is writable; the main `/etc/sudoers` file is never touched.
- **`cat /etc/sudoers.d/zfsnas`** — used by the Sudoers Review diff (v6.3.32+) to read the portal's own sudoers file so the review always shows the accurate current state, including manual edits. Without this, the portal can only compare against the last content it wrote.
- **`chmod 0440 /etc/sudoers.d/zfsnas`** — corrects file permissions after each write (v6.4.25+). `sudo tee` creates new files with umask-derived permissions (typically 0644); this restores the recommended 0440 so the file has no write bits beyond the owner. If you do not use the Sudoers Hardening feature you can omit the entire `ZFSNAS_SECURITY` alias.
- **`find *`, `chown *`, `chown -R *`, `chmod *`, `chmod -R *`** (in `ZFSNAS_FILES`) — used by the File Browser (v6.4.3+/v6.4.4+) for directory listing, ownership changes, and permission changes. sudo-rs (Ubuntu 26.04+) does not allow wildcards in non-trailing argument positions, so the previous `chown * /mnt/*` style is no longer expressible. The portal now enforces path scoping itself: every File Browser request is validated against known dataset mountpoints and share roots before any of these commands run; arbitrary paths cannot be targeted from the UI.
- **`tee /etc/apt/apt.conf.d/20auto-upgrades`** — used by the Automatic OS Updates toggle on the OS Packages card (v6.6.27+) to enable or disable the distribution's `unattended-upgrades` background service. The portal writes only this fixed apt periodic config (the same file `dpkg-reconfigure unattended-upgrades` manages), setting `APT::Periodic::Update-Package-Lists` and `APT::Periodic::Unattended-Upgrade` to `"0"` or `"1"`. Reading the current state needs no sudo (`apt-config dump`). A NAS is best served with this **disabled** so updates install only during a chosen maintenance window, since an unattended upgrade can restart Samba/NFS/iSCSI and other services without warning.
- **`tee /etc/modprobe.d/zfs.conf` and sysfs tee entries** — used by the ARC Level 1 tuning feature (v6.3.22+) to persist ZFS ARC size limits across reboots and to apply them immediately via kernel sysfs. These are write-only paths; the portal only ever pipes well-formed `options zfs ...` lines or numeric byte values through `tee`.
- **`zfs send *` / `zfs recv *` / `zfs receive *`** — used by the remote replication feature (snapshot policies and standalone replication tasks) and the local dataset-to-dataset replication feature. `zfs send` streams a snapshot to stdout; `zfs recv`/`zfs receive` reads a stream from stdin. Both are required locally for local replication (`zfs send | zfs recv` piped on the same host). For remote replication and InterLink push, only `zfs send` is run locally — the remote side runs `zfs recv` via SSH under its own service account (no local sudo required for that side). Including both forms (`recv` and `receive`) is necessary because OpenZFS accepts either spelling.
- **`zfs allow *`** — used by the InterLink push feature and scheduled replication via InterLink servers to delegate ZFS permissions (`snapshot,send,receive,create,mount`) to the service account on every pool. This is required so that `zfs send` / `zfs recv` can be invoked without sudo when the remote side accepts the SSH connection as the non-root service user. The portal always restricts delegation to the service account's own username and to the specific permission set shown above.
- **`useradd *` / `groupadd *`** — broad wildcards are required because user creation accepts optional `--uid`, `--gid`, and `--no-user-group` flags (v3.0.0+ custom UID/GID feature). The original narrower forms (`useradd -M -s /usr/sbin/nologin *`, `groupadd --system sambashare`) are replaced to cover all combinations the portal may generate.
- **`userdel -f *` / `groupdel *` / `gpasswd *`** — used when deleting a portal user: Samba password entry is removed, the user is removed from the `sambashare` group, the Linux account is deleted, and the primary group is cleaned up. `gpasswd` is granted with a single trailing wildcard (broadened from `gpasswd -d * sambashare`) because sudo-rs (Ubuntu 26.04+) does not allow wildcards in non-trailing argument positions.
- **`smbpasswd -x *`** — deletes the Samba password database entry for a user. The existing `smbpasswd -s -a *` entry covers creation/update; `-x` is needed for deletion.
- **`udevadm control --reload-rules` / `udevadm trigger --subsystem-match=usb`** — run after writing a udev rule for UPS USB detection (v6.3.22+). These are distinct from `udevadm settle` (used in disk prep) and require their own sudoers entries.
- **Command paths** — `sgdisk` lives at `/usr/sbin/sgdisk` on Debian 12 and at `/usr/bin/sgdisk` on some Ubuntu releases. The entries above use `/usr/sbin/sgdisk` (the Debian default). Verify the correct path with `which sgdisk` and adjust if needed. Other tools listed under `/usr/bin/` or `/usr/sbin/` follow the same rule — check with `which <command>` on your system.

---

## TLS / HTTPS

The portal generates a self-signed certificate on first run (`config/certs/`). Connections are HTTPS-only; there is no HTTP fallback. For production use you can replace the auto-generated certificate with one signed by a trusted CA — place your `cert.pem` and `key.pem` in the same directory.

---

## Authentication

- Session-based auth with server-side session store; cookies are `HttpOnly` and `Secure`.
- Four roles: **admin** (full access), **read-only** (no mutations), **smb-only** (SMB share access only), **standard** (v6.4.4+, 11 granular permission flags configurable per user).
- All login attempts are written to the audit log, including the client IP.

---

## Reporting vulnerabilities

Please open a [GitHub issue](https://github.com/macgaver/zfsnas-chezmoi/issues) or contact the maintainer directly via GitHub.
