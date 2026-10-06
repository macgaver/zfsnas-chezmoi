#!/bin/sh
# realtek-vendor.sh — swap the in-kernel Realtek driver (r8169) for Realtek's
# own r8168 / r8125 drivers, before any network is configured.
#
# The image carries both, but the vendor modules are blacklisted
# (/etc/modprobe.d/zfsnas-realtek-vendor.conf) so they never auto-load: they
# claim the same PCI IDs as r8169, and with both present the winner is
# whichever udev loads first. r8169 stays the default — it covers every
# Realtek chip, including ones the vendor drivers do not know.
#
# Opt in when an older RTL8111/8168 (or a 2.5G RTL8125) drops its link, never
# gets one, or logs "rtl_rxtx_empty_cond == 1 (loop: 42, delay: 100)":
#   - once:   boot the "Realtek vendor NIC driver" GRUB entry
#             (kernel parameter znas.realtek=vendor);
#   - always: touch /persist/.zfsnas-persist/realtek-vendor and reboot
#             (delete it and reboot to go back).
# Needs Secure Boot OFF (or legacy BIOS): the modules are built with the image
# and signed by a throwaway key no firmware trusts. Whatever happens, r8169 is
# loaded again at the end, so the machine never ends up with less than before.
set -u
FLAG=/persist/.zfsnas-persist/realtek-vendor

grep -qw 'znas.realtek=vendor' /proc/cmdline || [ -e "$FLAG" ] || exit 0

# Let udev's coldplug finish first, or r8169 could load after the swap.
udevadm settle --timeout=30 || true

loaded=""
for m in r8168 r8125; do
    modinfo "$m" >/dev/null 2>&1 || continue
    loaded="$loaded $m"
done
if [ -z "$loaded" ]; then
    echo "realtek-vendor: no vendor module in this image — keeping r8169"
    exit 0
fi

# Unbind r8169 first so the vendor driver can claim the device. Explicit
# modprobe ignores the blacklist that keeps udev from loading these.
modprobe -r r8169 2>/dev/null || true
for m in $loaded; do
    if modprobe "$m"; then
        echo "realtek-vendor: loaded $m"
    elif [ "$(od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | tr -d ' ')" = 1 ]; then
        # The modules are signed with a key made at image build time, which no
        # firmware trusts: Secure Boot refuses them.
        echo "realtek-vendor: $m refused — Secure Boot is on; disable it in the firmware setup to use the vendor driver"
    else
        echo "realtek-vendor: $m failed to load"
    fi
done
# Back in for every chip the vendor drivers did not claim (a newer chip they
# do not know, or a second NIC): r8169 only binds devices that are still free.
modprobe r8169 2>/dev/null || true
exit 0
