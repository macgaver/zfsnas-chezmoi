#!/bin/sh
# Ensure the NAT networks exist — one per physical link-up NIC, named
# host-nat, host-nat2, host-nat3, … (the first keeps the bare name).
#
# These used to be created only by the portal's enable-virtualization flow, so
# a user who created a datastore directly from the Datastores page never got
# one. On the appliance they should simply BE there: a guest that should sit
# behind NAT rather than on the LAN needs no setup at all.
#
# Incus creates its database on first daemon start, and a network needs no
# storage pool, so this works on a box where nothing else has been configured
# yet. Idempotent: existing networks are never touched.
set -u
log() { echo "<4>zfsnas-hostnat: $*" > /dev/kmsg 2>/dev/null || echo "zfsnas-hostnat: $*"; }
command -v incus >/dev/null || exit 0

# Wait for the daemon to accept commands (it is starting in parallel with us).
i=0
while [ "$i" -lt 30 ]; do
    incus network list >/dev/null 2>&1 && break
    i=$((i + 1)); sleep 2
done
incus network list >/dev/null 2>&1 || { log "incus not responding — skipping"; exit 0; }

# A port counts when it is cabled AND addressed. The address usually sits on
# the bridge the port was enslaved to at first boot, not on the port itself, so
# both are checked. Which NAT belongs to which port is recorded on the network
# (user.zfsnas.uplink) — a NAT bridge has no physical port, so the pairing
# cannot be recovered later.
has_ipv4() {
    ip -4 -o addr show dev "$1" 2>/dev/null | grep -q "inet "
}

scan_nics() {
    found=""
    for d in /sys/class/net/*; do
        n=$(basename "$d")
        [ -e "$d/device" ] || continue
        case "$n" in lo|vmbr*|lxdbr*|br-*|virbr*|docker*|veth*|tap*|tun*|bond*|team*) continue ;; esac
        [ "$(cat "$d/carrier" 2>/dev/null || echo 0)" = "1" ] || continue
        master=""
        [ -e "$d/master" ] && master=$(basename "$(readlink "$d/master")")
        if has_ipv4 "$n" || { [ -n "$master" ] && has_ipv4 "$master"; }; then
            found="$found $n"
        fi
    done
    echo "$found" | tr ' ' '\n' | grep -v '^$' | sort | tr '\n' ' '
}

# Wait for the DHCP leases before deciding how many NAT networks to make:
# network-online.target is not a reliable gate under ifupdown, and a port
# scanned one second too early looks address-less, which would collapse every
# port down to a single unpaired host-nat for the life of the install.
i=0
nics=$(scan_nics)
while [ -z "$(echo "$nics" | tr -d ' ')" ] && [ "$i" -lt 30 ]; do
    sleep 2
    i=$((i + 1))
    nics=$(scan_nics)
done
# With no addressed port there is still a host-nat, just no port to pair it
# with — "-" is the sentinel for that, since an empty list would iterate zero
# times and create nothing at all.
[ -n "$(echo "$nics" | tr -d ' ')" ] || nics="-"

i=0
for nic in $nics; do
    if [ "$i" -eq 0 ]; then name="host-nat"; else name="host-nat$((i + 1))"; fi
    if incus network show "$name" >/dev/null 2>&1; then
        log "$name already exists"
        if [ "$nic" != "-" ] && [ -z "$(incus network get "$name" user.zfsnas.uplink 2>/dev/null)" ]; then
            incus network set "$name" user.zfsnas.uplink "$nic" >/dev/null 2>&1 \
                && log "$name paired with $nic"
        fi
    elif [ "$nic" = "-" ]; then
        if incus network create "$name" ipv4.address=auto ipv4.nat=true ipv6.address=none >/dev/null 2>&1; then
            log "created $name (no addressed port to pair it with)"
        else
            log "could not create $name (continuing)"
        fi
    elif incus network create "$name" ipv4.address=auto ipv4.nat=true ipv6.address=none \
            user.zfsnas.uplink="$nic" >/dev/null 2>&1; then
        log "created $name for $nic"
    else
        log "could not create $name (continuing)"
    fi
    i=$((i + 1))
done
exit 0
