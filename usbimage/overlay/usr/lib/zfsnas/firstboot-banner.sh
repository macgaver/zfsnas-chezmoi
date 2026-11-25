#!/bin/sh
# Writes the TTY login banner with the portal URL(s). Runs once network is up.
PORT=$(python3 -c 'import json,sys;print(json.load(open("/opt/zfsnas/config/config.json")).get("port",""))' 2>/dev/null)
[ -n "$PORT" ] || PORT=8443
VER=$(sed -n 's/^appliance_version=//p' /etc/zfsnas-release 2>/dev/null)
[ -n "$VER" ] || VER=$(sed -n 's/^version=//p' /etc/zfsnas-release 2>/dev/null)
# Before the first admin exists the portal only serves the setup wizard, so
# point the console straight at /setup — otherwise the first thing a new user
# sees is a login form they have no account for. Once users.json exists the
# plain URL is the right one.
PATHPART="/setup"
FIRSTRUN=1
if [ -s /opt/zfsnas/config/users.json ]; then
    case "$(tr -d ' \n\t' < /opt/zfsnas/config/users.json)" in
        ""|"[]"|"{}") ;;                 # present but empty: still first run
        *) PATHPART=""; FIRSTRUN=0 ;;
    esac
fi
# IPv4 only: an IPv6 URL (SLAAC/link-local, printed without brackets) is not
# something a user can type into a browser, and it often shows up before the
# DHCP lease — which used to leave the console with an IPv6-only URL.
ipv4s() {
    hostname -I 2>/dev/null | tr ' ' '\n' \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.'
}
# At boot, give DHCP up to 90 s to hand out an IPv4 address.
if [ "$1" = "--boot" ]; then
    i=0
    while [ -z "$(ipv4s)" ] && [ $i -lt 45 ]; do sleep 2; i=$((i+1)); done
fi
IPS=$(ipv4s | sed "s|^|      https://|; s|\$|:${PORT}${PATHPART}|")
mkdir -p /etc/issue.d
NEW=$(mktemp)
{
    echo ""
    echo "  ZNAS Appliance ${VER}"
    if [ "$FIRSTRUN" = "1" ]; then
        echo "  First run — create your admin account at:"
    else
        echo "  Open the portal in a browser:"
    fi
    if [ -n "$IPS" ]; then echo "$IPS"; else
        echo "      (no IPv4 address yet — check cabling / DHCP)"
    fi
    echo "  SSH is locked until you set a root password in Portal Settings."
    echo ""
} > "$NEW"
# Rewritten by the timer too: only touch the file (and redraw the consoles)
# when the address or first-run state actually changed.
if cmp -s "$NEW" /etc/issue.d/zfsnas.issue; then
    rm -f "$NEW"
else
    mv "$NEW" /etc/issue.d/zfsnas.issue
    chmod 644 /etc/issue.d/zfsnas.issue
    agetty --reload 2>/dev/null || true
fi
