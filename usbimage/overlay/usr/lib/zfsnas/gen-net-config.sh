#!/bin/sh
# Generate the appliance's first-boot network configuration.
#
# The image ships ifupdown — NOT netplan — because that is the state the rest
# of ZNAS expects: the portal's bridge, VLAN and static-IP code all edit
# /etc/network/interfaces, and enabling virtualization on a netplan host would
# otherwise force a netplan→ifupdown migration first. Shipping the migrated
# shape means the appliance is already in its final state on first boot.
#
# Every physical NIC that has LINK gets a `vmbrN` bridge which owns the DHCP
# lease, with the NIC enslaved and address-less — a guest attached to vmbr0
# then sits directly on the LAN with no further setup. A NIC without link gets
# a plain DHCP stanza so plugging a cable in later still works.
#
# Runs once. /etc/network is bind-mounted from the persist store, so the marker
# and the generated file survive reboots and a static IP configured later from
# the portal is never overwritten.
set -u
IF_FILE=/etc/network/interfaces
MARKER=/etc/network/.zfsnas-generated
log() { echo "<4>zfsnas-netgen: $*" > /dev/kmsg 2>/dev/null || echo "zfsnas-netgen: $*"; }

[ -e "$MARKER" ] && { log "already generated — leaving $IF_FILE alone"; exit 0; }
mkdir -p /etc/network/interfaces.d

nics=""
for d in /sys/class/net/*; do
    n=$(basename "$d")
    [ -e "$d/device" ] || continue
    case "$n" in lo|vmbr*|lxdbr*|br-*|virbr*|docker*|veth*|tap*|tun*|bond*|team*) continue ;; esac
    nics="$nics $n"
done
[ -n "$nics" ] || { log "no physical NICs found"; exit 0; }

# Bring links up, then let the PHY negotiate before reading carrier.
for n in $nics; do ip link set "$n" up 2>/dev/null; done
i=0
while [ "$i" -lt 8 ]; do
    for n in $nics; do
        [ "$(cat "/sys/class/net/$n/carrier" 2>/dev/null || echo 0)" = "1" ] && { i=99; break; }
    done
    [ "$i" = 99 ] && break
    i=$((i + 1)); sleep 1
done
sleep 2   # let the remaining ports settle so a second NIC is not missed

{
    echo "# /etc/network/interfaces — generated on first boot by zfsnas-netgen."
    echo "# Managed by the ZFS NAS Portal: change network settings from the"
    echo "# portal, not by hand. Delete $(basename "$MARKER") and reboot to"
    echo "# regenerate this file from the hardware."
    echo ""
    echo "auto lo"
    echo "iface lo inet loopback"
    echo ""
} > "$IF_FILE"

idx=0
for n in $nics; do
    if [ "$(cat "/sys/class/net/$n/carrier" 2>/dev/null || echo 0)" = "1" ]; then
        br="vmbr$idx"; idx=$((idx + 1))
        # `auto`, not allow-hotplug: networking.service brings everything up
        # through a single `ifup -a` path, which the bridge stanzas require.
        # The member NIC is `inet manual` — it must NOT take an address of its
        # own, or the host ends up with two DHCP clients on one link.
        printf 'auto %s\niface %s inet manual\n\n' "$n" "$n" >> "$IF_FILE"
        # No `hwaddress ether` and no `bridge-vlan-aware`: on kernel >= 7 both
        # break bridge bring-up on Ubuntu 26.04 (see bridgeKernelStanzaTail —
        # the appliance always ships a 7.x kernel, so the safe shape is the
        # only one emitted here).
        printf 'auto %s\niface %s inet dhcp\n    bridge_ports %s\n    bridge_stp off\n    bridge_fd 0\n\n' \
            "$br" "$br" "$n" >> "$IF_FILE"
        log "$n has link — bridged as $br (bridge holds the DHCP lease)"
    else
        printf 'auto %s\niface %s inet dhcp\n\n' "$n" "$n" >> "$IF_FILE"
        log "$n has no link — plain DHCP, no bridge"
    fi
done

: > "$MARKER"
log "wrote $IF_FILE"
exit 0
