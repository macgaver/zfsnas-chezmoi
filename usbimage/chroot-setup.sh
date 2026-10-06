#!/bin/bash
# chroot-setup.sh — runs INSIDE the target rootfs chroot. Installs the
# kernel, casper, the signed boot chain, and every feature package the
# portal can enable (spec: everything baked, user only configures), then
# applies appliance hygiene. Args: $1 = Ubuntu codename, $2 = mirror,
# $3 = Incus version to install from Zabbly (empty: Ubuntu's own package).
set -euo pipefail
CODENAME="$1"; MIRROR="$2"; INCUS_VERSION="${3:-}"
export DEBIAN_FRONTEND=noninteractive
# The caller's HOME means nothing inside the chroot. CI runs build.sh with
# `sudo -E`, which keeps HOME=/home/ghrunner — a path that does not exist in
# the rootfs, so any tool that writes under ~ (gpg did) aborts the build.
export HOME=/root

cat > /etc/apt/sources.list <<EOF
deb $MIRROR $CODENAME main universe
deb $MIRROR ${CODENAME}-updates main universe
deb $MIRROR ${CODENAME}-security main universe
EOF
apt-get update

# Bring the whole rootfs up to the archive's current state before anything
# else. `apt-get install` alone is not enough: it installs the newest version
# of the packages it NAMES, but leaves everything debootstrap laid down (and
# every transitive dependency already present) at whatever version it had when
# the rootfs was first created. Re-running this stage on a rootfs built weeks
# ago would otherwise ship a stale base system with a fresh package list.
echo "== upgrading the base rootfs to the current archive =="
# (plain dist-upgrade: it already pulls in new dependencies — --with-new-pkgs
# is an `upgrade`-only flag and apt rejects the combination)
apt-get -y dist-upgrade
apt-get -s dist-upgrade | tail -n1   # prints "0 upgraded…" so the build log records the state

# Base system + live-boot machinery + signed boot chain
apt-get install -y --no-install-recommends \
    systemd-sysv systemd-resolved dbus udev kmod ca-certificates curl wget sudo \
    linux-generic casper \
    shim-signed grub-efi-amd64-signed grub-efi-amd64-bin grub-pc-bin grub2-common \
    openssh-server \
    vim-tiny    # a console editor (vi / vim.tiny); minbase ships none at all

# Every portal feature, pre-baked (spec: user configures, never installs)
#
# genisoimage: Incus builds a small config/agent ISO for every VM it starts and
# shells out to genisoimage for it. Nothing in the archive drags it in — the
# incus package declares no Depends, Recommends or Suggests on any ISO tool —
# so leaving it out makes every VM on the appliance fail to start, with the
# missing binary named nowhere the user can see. Do not drop it as "unused":
# no reverse dependency protects it.
#
# zram-tools: backs Memory Compression in Settings > Virtualization. Off the
# appliance the portal installs it on demand (handlers/memcomp.go), but the
# appliance root is read-only and that install would not survive a reboot, so
# the package has to be in the image for the feature to be configurable at all.
# The portal drives the zramswap unit and /etc/default/zramswap from here.
#
# The rest of this line is the same lesson learned three times over: the portal
# shells out to these binaries, and on a read-only appliance an on-demand
# apt-get is not an option. Each was verified missing from the image.
#   pciutils     -> lspci. PCI passthrough config AND the GPU/storage-controller
#                   inventory in System Hardware. Its absence surfaces raw:
#                   {"error":"lspci: exec: \"lspci\": executable file not found"}.
#   usbutils     -> lsusb, the same story for USB device passthrough
#                   (system/lxd.go ListUSBDevices).
#   targetcli-fb -> targetcli. ISCSIPrereqsInstalled() gates the whole iSCSI
#                   feature on this binary; the image shipped `tgt`, which the
#                   code only ever uses as a service-NAME fallback, so iSCSI
#                   reported "not installed" on the appliance.
#   sshpass      -> required for InterLink push and the Proxmox import flow
#                   (the virt enable flow installs it off-appliance).
#   ntfs-3g      -> ntfsfix, used by Proxmox import to clear the dirty bit on
#                   NTFS guest disks.
#   chrony       -> chronyc, behind the Network Time panel; the virt enable
#                   flow installs it off-appliance for guest time sync.
# Incus. Ubuntu's archive keeps one Incus for the life of the release (26.04:
# 6.0.5, frozen), so official images take it from the Incus project's own
# packages (Zabbly) at exactly the version the CI workflow declares
# (APPLIANCE_INCUS_VERSION). Pinned at 1001 so it wins over the archive and
# can replace an archive build left in a reused rootfs; the archive's incus*
# are pinned away so a later apt run can never swap it back.
# Note: Zabbly's Incus ships its own QEMU, OVMF and LXC under /opt/incus.
INCUS_PKGS=(incus incus-base incus-client incus-extra)
if [ -n "$INCUS_VERSION" ]; then
    echo "== Incus $INCUS_VERSION from Zabbly =="
    apt-get install -y --no-install-recommends gnupg
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL --retry 3 https://pkgs.zabbly.com/key.asc -o /etc/apt/keyrings/zabbly.asc
    # The fingerprint the Incus documentation publishes for this key.
    # Throwaway keyring dir: reading a key file must not create ~/.gnupg in the image.
    gnupg_tmp=$(mktemp -d)
    fp=$(GNUPGHOME="$gnupg_tmp" gpg --batch --show-keys --with-colons /etc/apt/keyrings/zabbly.asc | awk -F: '/^fpr/{print $10; exit}')
    rm -rf "$gnupg_tmp"
    [ "$fp" = "4EFC590696CB15B87C73A3AD82CC8797C838DCFD" ] \
        || { echo "ERROR: unexpected Zabbly key fingerprint $fp" >&2; exit 1; }
    printf '%s\n' "Enabled: yes" "Types: deb" "URIs: https://pkgs.zabbly.com/incus/stable" \
        "Suites: $CODENAME" "Components: main" "Architectures: amd64" \
        "Signed-By: /etc/apt/keyrings/zabbly.asc" \
        > /etc/apt/sources.list.d/zabbly-incus-stable.sources
    # incus-agent is the exception: Ubuntu's package is the GUEST side (unit +
    # udev rule that start the agent when this appliance itself runs as an
    # Incus/LXD VM) and Zabbly ships no equivalent; without it `incus exec`
    # into an appliance VM stops working. apt applies the first matching
    # record, so it comes before the incus* block.
    printf '%s\n' "Package: incus-agent" "Pin: release o=Ubuntu" "Pin-Priority: 500" "" \
        "Package: ${INCUS_PKGS[*]}" "Pin: version 1:${INCUS_VERSION}-*" "Pin-Priority: 1001" "" \
        "Package: incus*" "Pin: release o=Ubuntu" "Pin-Priority: -1" \
        > /etc/apt/preferences.d/zabbly-incus
    apt-get update
    apt-get install -y --allow-downgrades "${INCUS_PKGS[@]}" incus-agent
    got=$(dpkg-query -W -f='${Version}' incus)
    case "$got" in
        1:"$INCUS_VERSION"-*) echo "incus $got installed" ;;
        *) echo "ERROR: incus $got installed, expected $INCUS_VERSION" >&2; exit 1 ;;
    esac
    # VMs created under Ubuntu's Incus keep their UEFI variables in a file
    # named after Ubuntu's firmware (qemu.nvram -> OVMF_VARS_4M.fd). Zabbly's
    # Incus only searches its own folder, under its own names, so without
    # these aliases every existing UEFI VM fails after the upgrade with
    # "Unable to locate matching firmware" (seen on the 26.04.1-4 test).
    q=/opt/incus/share/qemu
    for pair in OVMF_CODE.4MB.fd:OVMF_CODE_4M.fd OVMF_CODE.4MB.fd:OVMF_CODE_4M.secboot.fd \
                OVMF_VARS.4MB.fd:OVMF_VARS_4M.fd OVMF_VARS.4MB.ms.fd:OVMF_VARS_4M.ms.fd; do
        src=${pair%%:*} alias=${pair#*:}
        [ -e "$q/$src" ] || { echo "ERROR: $q/$src missing from Zabbly's Incus" >&2; exit 1; }
        [ -e "$q/$alias" ] || ln -s "$src" "$q/$alias"
    done
else
    apt-get install -y incus
fi

apt-get install -y \
    zfsutils-linux genisoimage samba nfs-kernel-server nut mergerfs tgt \
    zram-tools \
    pciutils usbutils targetcli-fb sshpass ntfs-3g chrony \
    smartmontools hdparm rsync sanoid pv \
    ifupdown bridge-utils \
    gdisk parted dosfstools e2fsprogs zstd \
    python3 jq net-tools ethtool lsof nvme-cli lsscsi

# Realtek vendor NIC drivers (r8168: RTL8111/8168 family, r8125: RTL8125
# 2.5G). The in-kernel r8169 already drives every Realtek chip and stays the
# default; these are the opt-in fallback for older RTL8111 revisions that drop
# their link or time out under r8169 — common on second-hand desktops. See
# /usr/lib/zfsnas/realtek-vendor.sh for how they are switched on.
# Built here against the image kernel, then only the .ko files are kept and
# DKMS + the compiler are purged: the image kernel never changes in place, and
# gcc/dkms would cost ~200 MB of squashfs. Best-effort per driver: a vendor
# source that does not compile against a new kernel must not sink the image.
echo "== Realtek vendor NIC drivers =="
KVER=$(ls -1 /lib/modules | sort -V | tail -n1)
printf '%s\n' "deb $MIRROR $CODENAME multiverse" > /etc/apt/sources.list.d/znas-build-multiverse.list
apt-get update
HAD_HEADERS=0
dpkg -s "linux-headers-$KVER" >/dev/null 2>&1 && HAD_HEADERS=1
VENDOR_DIR=/lib/modules/$KVER/updates/znas-realtek
mkdir -p "$VENDOR_DIR"
for drv in r8168 r8125; do
    if apt-get install -y --no-install-recommends "linux-headers-$KVER" dkms "${drv}-dkms" \
        && ko=$(find "/lib/modules/$KVER" -name "${drv}.ko*" -path '*dkms*' -o -name "${drv}.ko*" -path '*updates*' | grep -v znas-realtek | head -n1) \
        && [ -n "$ko" ]; then
        cp "$ko" "$VENDOR_DIR/"
        echo "realtek: built $drv for $KVER"
    else
        echo "WARNING: realtek: $drv did not build for $KVER — the image ships without it" >&2
    fi
    apt-get purge -y "${drv}-dkms" 2>/dev/null || true
done
apt-get purge -y dkms 2>/dev/null || true
[ "$HAD_HEADERS" = 1 ] || apt-get purge -y "linux-headers-$KVER" 2>/dev/null || true
apt-get autoremove -y --purge
rm -f /etc/apt/sources.list.d/znas-build-multiverse.list
apt-get update
# The DKMS packages ship a "blacklist r8169" of their own; the purge removes
# it, and must have: r8169 stays the default.
rm -f /etc/modprobe.d/r8168-dkms.conf /etc/modprobe.d/r8125-dkms.conf
# Never auto-load the vendor drivers (udev would race them against r8169);
# realtek-vendor.sh loads them explicitly, which a blacklist does not stop.
printf '%s\n' "# ZNAS appliance: opt-in only, see /usr/lib/zfsnas/realtek-vendor.sh" \
    "blacklist r8168" "blacklist r8125" > /etc/modprobe.d/zfsnas-realtek-vendor.conf
depmod "$KVER"
systemctl enable zfsnas-realtek.service
ls -l "$VENDOR_DIR"

# MinIO is not in the archive — bake the same binaries the portal's
# install flow downloads (system/minio.go).
# Retries matter here: a single dropped connection to dl.min.io aborts the
# whole chroot stage under `set -e`, costing a full rebuild (seen once).
#
# 2026-09: MinIO archived the open-source server/client and dl.min.io now
# answers 410 Gone. Download to a temp file and keep the binary the rootfs
# already has (from an earlier build) when that fails — `wget -O` straight
# onto the target truncated it to 0 bytes and, under -q, aborted the build
# with no message at all. A fresh rootfs with no binary still fails, loudly.
fetch_bin() {
    local dest="$1" url="$2" tmp="$1.new"
    if wget -q --tries=3 --timeout=30 -O "$tmp" "$url" && [ -s "$tmp" ]; then
        mv "$tmp" "$dest"
    else
        rm -f "$tmp"
        if [ -s "$dest" ]; then
            echo "WARNING: could not download $url — keeping the existing $(basename "$dest")" >&2
        elif [ "${ZNAS_ALLOW_NO_MINIO:-0}" = 1 ]; then
            # Fresh rootfs, no binary to keep: build without it on request.
            # The image then has no S3 (MinIO) feature.
            echo "WARNING: could not download $url — building WITHOUT $(basename "$dest") (ZNAS_ALLOW_NO_MINIO=1)" >&2
            return 0
        else
            echo "ERROR: could not download $url and the rootfs has no $(basename "$dest")." >&2
            echo "       Set ZNAS_ALLOW_NO_MINIO=1 to build an image without S3 (see HOW-TO-BUILD-ISO.md)." >&2
            return 1
        fi
    fi
    chmod +x "$dest"
}
fetch_bin /usr/local/bin/minio https://dl.min.io/server/minio/release/linux-amd64/minio
fetch_bin /usr/local/bin/mc    https://dl.min.io/client/mc/release/linux-amd64/mc

# ---- appliance hygiene (spec §3 stage 2) -----------------------------------
# Login banner (appliance + Ubuntu + kernel + portal version) for every
# interactive bash — SSH, console, the portal's host terminal, incus exec —
# via /etc/bash.bashrc, since the last two are not login shells. Ubuntu's own
# SSH motd ("Welcome to Ubuntu…" + doc links) is switched off so it does not
# repeat half of it.
grep -q zfsnas/login-banner.sh /etc/bash.bashrc || cat >> /etc/bash.bashrc <<'BANNER'

# ZNAS appliance identity banner (once per session)
[ -r /usr/lib/zfsnas/login-banner.sh ] && . /usr/lib/zfsnas/login-banner.sh
BANNER
chmod -x /etc/update-motd.d/00-header /etc/update-motd.d/10-help-text 2>/dev/null || true
apt-get purge -y snapd unattended-upgrades update-notifier-common 2>/dev/null || true
apt-get autoremove -y
systemctl mask apt-daily.timer apt-daily-upgrade.timer motd-news.timer 2>/dev/null || true
rm -f /etc/update-motd.d/50-motd-news
# netplan wait-online boot hang (feedback_netplan_migration_waitonline_apipa)
systemctl mask systemd-networkd-wait-online.service 2>/dev/null || true
# zram-tools enables zramswap in its postinst, which would hand every appliance
# a 50%-of-RAM compressed swap nobody asked for. Memory Compression is an opt-in
# the user turns on in Settings > Virtualization (the portal runs `systemctl
# enable zramswap` itself), so ship the package present but the unit off.
# systemctl may refuse to run in the chroot, hence the direct symlink fallback.
systemctl disable zramswap 2>/dev/null \
    || rm -f /etc/systemd/system/multi-user.target.wants/zramswap.service

# journald in RAM; /tmp + /var/tmp tmpfs via the DEFAULT fstab (this fstab
# is what the persist hook seeds into the store on first boot)
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=volatile\n' > /etc/systemd/journald.conf.d/volatile.conf
cat > /etc/fstab <<'EOF'
# ZFS NAS USB appliance — OS is read-only; only /persist takes writes.
tmpfs /tmp     tmpfs nosuid,nodev 0 0
tmpfs /var/tmp tmpfs nosuid,nodev 0 0
EOF

# Identity: blank machine-id (systemd generates through the persist bind on
# first boot); no baked hostid (hook generates a random one into the store).
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -sf /etc/machine-id /var/lib/dbus/machine-id
rm -f /etc/hostid
# Default hostname. casper's own 18hostname script is REMOVED below: it forces
# `ubuntu` on every boot and writes through the persisted /etc/hostname bind,
# so it would silently reset a hostname the user had chosen.
echo znas > /etc/hostname
printf '127.0.0.1\tlocalhost\n127.0.1.1\tznas\n\n::1\t\tlocalhost ip6-localhost ip6-loopback\nff02::1\t\tip6-allnodes\nff02::2\t\tip6-allrouters\n' > /etc/hosts

# SSH ships enabled but root LOCKED (portal SSH-access card unlocks).
passwd -l root
mkdir -p /etc/ssh/sshd_config.d
printf 'PermitRootLogin yes\n' > /etc/ssh/sshd_config.d/10-zfsnas.conf

# ---- networking: ifupdown, not netplan -------------------------------------
# The appliance ships the SAME shape the portal's netplan→ifupdown migration
# produces, so it is already in its final state on first boot: ifupdown +
# dhcpcd, systemd-networkd out of the way, and DNS written by the dhcpcd
# exit-hook (NOT via resolvectl — that call blocks ~90s at boot before
# resolved is on D-Bus and hangs networking.service).
# The interfaces file itself is generated on first boot from the hardware —
# see gen-net-config.sh — because which ports get bridged depends on which
# ones have a cable in them.
apt-get purge -y netplan.io 2>/dev/null || true
apt-get install -y --no-install-recommends dhcpcd-base ifupdown bridge-utils

for u in systemd-networkd.service systemd-networkd.socket \
         systemd-networkd-wait-online.service; do
    systemctl disable "$u" 2>/dev/null || true
    systemctl mask "$u" 2>/dev/null || true
done
systemctl enable networking.service 2>/dev/null || true
systemctl enable zfsnas-netgen.service zfsnas-netfallback.service
systemctl enable zfsnas-authsync.path
systemctl enable zfsnas-hostnat.service

# dhcpcd: no 169.254 link-local fallback (a bridge is slow to forward right
# after boot, so early DHCP attempts can fail and APIPA would stick), and no
# built-in resolv.conf hook — our exit-hook writes a plain file instead.
cat > /etc/dhcpcd.conf <<'DHCPCD'
# Managed by the ZFS NAS appliance image.
hostname
persistent
option rapid_commit, domain_name_servers, domain_name, domain_search, host_name
option classless_static_routes, interface_mtu
require dhcp_server_identifier
slaac private
noipv4ll
nohook resolv.conf
DHCPCD

# /etc/resolv.conf must be a REAL file for the exit-hook to write; the stub
# symlink to systemd-resolved would make the hook's redirect fail.
rm -f /etc/resolv.conf
printf '# Written by the dhcpcd exit-hook on each lease.\n' > /etc/resolv.conf
chmod 0644 /etc/resolv.conf

# ---- strip casper's live-DESKTOP session scripts -------------------------
# casper ships a live-CD session zoo (creates an "ubuntu" live user, runs
# apt-get at boot, configures X/GNOME/KDE/jackd, pollinate…). On a headless
# appliance those are useless and actively harmful: with no DNS the apt and
# pollinate steps stall the boot for minutes. Keep only what a server boot
# needs (mountpoints, fstab, swap, locales, init, cdrom, the
# update-initramfs/unattended/snap disablers, server networking, OUR persist
# hook, and casperboot).
CB=/usr/share/initramfs-tools/scripts/casper-bottom
for s in 15autologin 18hostname 19keyboard 20xconfig 22desktop_settings 22sslcert \
         24preseed 25adduser 30accessibility 31disable_update_notifier \
         33enable_apport_crashes 34disable_kde_services \
         37disable_screensaver_lubuntu 40install_driver_updates \
         41apt_build_cache_cdrom 44pk_allow_ubuntu 45jackd2 \
         52gnome_initial_setup 56override_nvidia_udev_rule 57pollinate \
         59disable_mozc_autosetup 60_create_intaller_logdir \
         61desktop_canary_tweaks; do
    rm -f "$CB/$s"
done

systemctl enable ssh zfsnas zfsnas-firstboot

update-initramfs -u -k all
apt-get clean
rm -rf /var/lib/apt/lists/*
