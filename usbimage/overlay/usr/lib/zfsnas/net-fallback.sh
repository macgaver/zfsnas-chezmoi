#!/bin/sh
# Safety net for the generated bridge config.
#
# A bridge that never gets a DHCP lease would leave a headless appliance
# unreachable — and the portal is the only way in. If no interface holds a
# global IPv4 shortly after boot, fall back to plain DHCP on every physical
# NIC and re-apply, so the box comes back even if bridging failed on this
# hardware.
set -u
log() { echo "<4>zfsnas-netfallback: $*" > /dev/kmsg 2>/dev/null || echo "zfsnas-netfallback: $*"; }
MARKER=/etc/network/.zfsnas-fallback-applied
IF_FILE=/etc/network/interfaces

[ -e "$MARKER" ] && exit 0
grep -q "bridge_ports" "$IF_FILE" 2>/dev/null || exit 0   # nothing bridged; nothing to undo

i=0
while [ "$i" -lt 12 ]; do
    if ip -4 -o addr show scope global 2>/dev/null | grep -q .; then
        exit 0                                             # we have an address: all good
    fi
    i=$((i + 1)); sleep 5
done

log "no IPv4 address 60s after boot — reverting to plain DHCP so the portal stays reachable"
{
    echo "# Fallback written by zfsnas-netfallback: bridging did not obtain a"
    echo "# lease on this hardware. Re-create bridges from the portal once the"
    echo "# network is understood."
    echo ""
    echo "auto lo"
    echo "iface lo inet loopback"
    echo ""
    for d in /sys/class/net/*; do
        n=$(basename "$d")
        [ -e "$d/device" ] || continue
        case "$n" in lo|vmbr*|lxdbr*|br-*|virbr*|docker*|veth*|tap*|tun*|bond*|team*) continue ;; esac
        printf 'auto %s\niface %s inet dhcp\n\n' "$n" "$n"
    done
} > "$IF_FILE"
: > "$MARKER"
# Tear the bridges down before re-running ifup, or the NICs stay enslaved.
for b in /sys/class/net/vmbr*; do
    [ -e "$b" ] || continue
    ifdown "$(basename "$b")" 2>/dev/null
    ip link set "$(basename "$b")" down 2>/dev/null
    ip link delete "$(basename "$b")" 2>/dev/null
done
systemctl restart networking 2>/dev/null || ifup -a 2>/dev/null
log "fallback applied"
exit 0
