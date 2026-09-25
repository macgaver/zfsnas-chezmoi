# shellcheck shell=sh
# login-banner.sh — SOURCED (not executed) by /etc/bash.bashrc
# and /etc/profile.d/zz-zfsnas-banner.sh. Prints the appliance identity once
# per session for every interactive shell: SSH, the console, the portal's
# host terminal and `incus exec … bash` (the last two are NOT login shells,
# which is why this hangs off bash.bashrc and not only /etc/profile).
# Read-only: it never changes the files the portal's version checks use.

case "$-" in *i*) ;; *) return 0 2>/dev/null || exit 0 ;; esac
[ -t 1 ] || return 0 2>/dev/null || exit 0
# Once per session: /etc/profile sources bash.bashrc AND profile.d, and a
# nested shell (sudo -s, bash inside bash) would repeat it otherwise.
[ -z "$ZNAS_BANNER_SHOWN" ] || return 0 2>/dev/null || exit 0
export ZNAS_BANNER_SHOWN=1

_znas_appl=$(sed -n 's/^appliance_version=//p' /etc/zfsnas-release 2>/dev/null)
_znas_ubuntu=$(. /etc/os-release 2>/dev/null && echo "${VERSION%% (*}")
_znas_kernel=$(uname -r)
# The portal version that is actually RUNNING (it may be a persisted update
# newer than the one baked into the image); falls back to the baked one when
# the process is not readable (non-root) or not running.
_znas_pid=$(systemctl show -p MainPID --value zfsnas.service 2>/dev/null)
_znas_portal=""
[ -n "$_znas_pid" ] && [ "$_znas_pid" != 0 ] && \
    _znas_portal=$("/proc/$_znas_pid/exe" --version 2>/dev/null | head -n1)
[ -n "$_znas_portal" ] || _znas_portal=$(sed -n 's/^version=//p' /etc/zfsnas-release 2>/dev/null)
_znas_port=$(sed -n 's/.*"port"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' /opt/zfsnas/config/config.json 2>/dev/null | head -n1)
_znas_ip=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -m1 -E '^[0-9]+\.')

printf '\n  \033[1;36mZNAS Appliance %s\033[0m  ·  Ubuntu %s  ·  kernel %s\n' \
    "${_znas_appl:-unknown}" "${_znas_ubuntu:-?}" "$_znas_kernel"
printf '  Portal %s' "${_znas_portal:-?}"
[ -n "$_znas_ip" ] && printf '  ·  https://%s:%s' "$_znas_ip" "${_znas_port:-8443}"
printf '\n  \033[2mRead-only OS image: changes outside the portal are lost at reboot.\033[0m\n\n'

unset _znas_appl _znas_ubuntu _znas_kernel _znas_pid _znas_portal _znas_port _znas_ip
