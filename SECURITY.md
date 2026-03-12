# Security

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

```sudoers
# ── ZFS ──────────────────────────────────────────────────────────────────────
Cmnd_Alias ZFSNAS_ZFS = \
    /usr/sbin/zpool list *, \
    /usr/sbin/zpool status *, \
    /usr/sbin/zpool status, \
    /usr/sbin/zpool create *, \
    /usr/sbin/zpool import *, \
    /usr/sbin/zpool import -f *, \
    /usr/sbin/zpool add *, \
    /usr/sbin/zpool attach *, \
    /usr/sbin/zpool scrub *, \
    /usr/sbin/zpool scrub -s *, \
    /usr/sbin/zpool destroy *, \
    /usr/sbin/zpool upgrade *, \
    /usr/sbin/zfs list *, \
    /usr/sbin/zfs set *, \
    /usr/sbin/zfs create *, \
    /usr/sbin/zfs destroy *, \
    /usr/sbin/zfs destroy -r *, \
    /usr/sbin/zfs snapshot *, \
    /usr/sbin/zfs rollback -r *, \
    /usr/sbin/zfs clone *

# ── Samba ─────────────────────────────────────────────────────────────────────
Cmnd_Alias ZFSNAS_SMB = \
    /usr/bin/systemctl reload smbd, \
    /usr/bin/systemctl restart smbd, \
    /usr/bin/systemctl start smbd, \
    /usr/bin/systemctl stop smbd, \
    /usr/bin/systemctl start nmbd, \
    /usr/bin/systemctl stop nmbd, \
    /usr/sbin/useradd -M -s /usr/sbin/nologin *, \
    /usr/sbin/usermod -aG sambashare *, \
    /usr/bin/smbpasswd -s -a *, \
    /usr/bin/chmod 777 *, \
    /usr/bin/tee /etc/samba/smb.conf

# ── NFS ───────────────────────────────────────────────────────────────────────
Cmnd_Alias ZFSNAS_NFS = \
    /usr/sbin/exportfs -ra, \
    /usr/bin/systemctl start nfs-server, \
    /usr/bin/systemctl stop nfs-server, \
    /usr/bin/tee /etc/exports

# ── SMART / disks ─────────────────────────────────────────────────────────────
Cmnd_Alias ZFSNAS_SMART = \
    /usr/sbin/smartctl -j -a *, \
    /usr/sbin/smartctl -j -i *, \
    /usr/sbin/nvme smart-log -o json *

# ── System ────────────────────────────────────────────────────────────────────
Cmnd_Alias ZFSNAS_SYSTEM = \
    /usr/bin/timedatectl set-timezone *, \
    /usr/sbin/shutdown -r now, \
    /usr/sbin/shutdown -h now, \
    /usr/sbin/modprobe zfs

# ── OS updates & service install ──────────────────────────────────────────────
Cmnd_Alias ZFSNAS_APT = \
    /usr/bin/apt-get update -qq, \
    /usr/bin/apt-get install -y *, \
    /usr/bin/apt-get upgrade -y, \
    /usr/bin/tee /etc/systemd/system/zfsnas.service, \
    /usr/bin/systemctl daemon-reload, \
    /usr/bin/systemctl enable zfsnas

# ── Grant all of the above, passwordless, to the service account ──────────────
zfsnas ALL=(ALL) NOPASSWD: \
    ZFSNAS_ZFS, ZFSNAS_SMB, ZFSNAS_NFS, ZFSNAS_SMART, ZFSNAS_SYSTEM, ZFSNAS_APT
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
- **`chmod 777`** — the portal applies this to newly created SMB share paths. If your shares always live under a fixed parent (e.g. `/data`), you can tighten this to `/usr/bin/chmod 777 /data/*`.
- **`tee` for config files** — write access is limited to the three specific paths listed (`smb.conf`, `exports`, `zfsnas.service`). The wildcard form `tee *` is intentionally avoided.

---

## TLS / HTTPS

The portal generates a self-signed certificate on first run (`config/certs/`). Connections are HTTPS-only; there is no HTTP fallback. For production use you can replace the auto-generated certificate with one signed by a trusted CA — place your `cert.pem` and `key.pem` in the same directory.

---

## Authentication

- Session-based auth with server-side session store; cookies are `HttpOnly` and `Secure`.
- Three roles: **admin** (full access), **read-only** (no mutations), **smb-only** (SMB share access only).
- All login attempts are written to the audit log, including the client IP.

---

## Reporting vulnerabilities

Please open a [GitHub issue](https://github.com/macgaver/zfsnas-chezmoi/issues) or contact the maintainer directly via GitHub.
