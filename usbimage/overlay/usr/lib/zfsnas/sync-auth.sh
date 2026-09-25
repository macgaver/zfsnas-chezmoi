#!/bin/sh
# Copy the system account files into the persist store.
#
# These files are `copy` type in the manifest — restored INTO the running
# system at boot, not bind-mounted (shadow-utils rewrite them via rename,
# which EBUSYs on a bind mount). That means anything that creates a user at
# runtime — the portal's SMB user flow runs `useradd`, or an admin on the
# shell — is LOST at the next boot unless it is copied back out. Losing an
# account this way is not even a clean loss: Samba's passdb IS persisted, so
# the SMB entry survives while its Unix account does not, leaving a broken
# user with UID 4294967295 that cannot log in.
#
# Triggered by zfsnas-authsync.path whenever one of the files changes.
set -u
STORE=/persist/.zfsnas-persist/system/etc-auth
[ -d /persist/.zfsnas-persist ] || exit 0     # no persistence this boot
mkdir -p "$STORE"
for f in passwd shadow group gshadow subuid subgid; do
    [ -f "/etc/$f" ] || continue
    if ! cmp -s "/etc/$f" "$STORE/$f" 2>/dev/null; then
        cp -a "/etc/$f" "$STORE/$f.tmp" 2>/dev/null || continue
        mv -f "$STORE/$f.tmp" "$STORE/$f" 2>/dev/null
    fi
done
sync
exit 0
