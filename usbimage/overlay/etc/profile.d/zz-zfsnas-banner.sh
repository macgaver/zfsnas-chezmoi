# shellcheck shell=sh
# ZNAS appliance banner for login shells that are not bash (bash gets it from
# /etc/bash.bashrc; the once-per-session guard keeps it from printing twice).
[ -r /usr/lib/zfsnas/login-banner.sh ] && . /usr/lib/zfsnas/login-banner.sh
