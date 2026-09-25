#!/bin/sh
# run-zfsnas.sh — picks the persisted binary override iff its --version is
# >= the baked one (spec §2 adoption rule): a stale override never shadows
# a freshly reflashed newer image; a broken/truncated override fails the
# --version probe and the baked binary runs. ExecStart of zfsnas.service.
BAKED="${ZFSNAS_BAKED:-/opt/zfsnas/zfsnas}"
OVERRIDE="${ZFSNAS_OVERRIDE:-/persist/.zfsnas-persist/bin/zfsnas}"
BIN="$BAKED"
if [ -x "$OVERRIDE" ]; then
    OV=$("$OVERRIDE" --version 2>/dev/null | head -n1)
    BV=$("$BAKED" --version 2>/dev/null | head -n1)
    if [ -n "$OV" ] && [ -n "$BV" ] && dpkg --compare-versions "$OV" ge "$BV" 2>/dev/null; then
        BIN="$OVERRIDE"
    fi
fi
if [ -n "$ZFSNAS_LAUNCH_DRYRUN" ]; then
    echo "$BIN"
    exit 0
fi
echo "zfsnas launcher: starting $BIN"
exec "$BIN" "$@"
