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
IPS=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' \
      | sed "s|^|      https://|; s|\$|:${PORT}${PATHPART}|")
mkdir -p /etc/issue.d
{
    echo ""
    echo "  ZNAS Appliance ${VER} — ZFS NAS Portal"
    if [ "$FIRSTRUN" = "1" ]; then
        echo "  First run — create your admin account at:"
    else
        echo "  Open the portal in a browser:"
    fi
    if [ -n "$IPS" ]; then echo "$IPS"; else
        echo "      (no network address yet — check cabling / DHCP)"
    fi
    echo "  SSH is locked until you set a root password in Portal Settings."
    echo ""
} > /etc/issue.d/zfsnas.issue
