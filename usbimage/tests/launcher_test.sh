#!/bin/bash
# Unit test for run-zfsnas.sh version-adoption logic. No root needed.
set -euo pipefail
cd "$(dirname "$0")"
L=../overlay/usr/lib/zfsnas/run-zfsnas.sh
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
mkbin() { printf '#!/bin/sh\necho %s\n' "$2" > "$1"; chmod +x "$1"; }
run() { ZFSNAS_BAKED="$T/baked" ZFSNAS_OVERRIDE="$T/override" \
        ZFSNAS_LAUNCH_DRYRUN=1 sh "$L"; }
fail() { echo "FAIL: $1"; exit 1; }

mkbin "$T/baked" 6.8.28
# 1. no override -> baked
[ "$(run)" = "$T/baked" ] || fail "no override should pick baked"
# 2. newer override wins
mkbin "$T/override" 6.8.30
[ "$(run)" = "$T/override" ] || fail "newer override should win"
# 3. equal version -> override (ge)
mkbin "$T/override" 6.8.28
[ "$(run)" = "$T/override" ] || fail "equal override should win"
# 4. older override loses (fresh reflash beats stale override)
mkbin "$T/override" 6.8.27
[ "$(run)" = "$T/baked" ] || fail "older override must lose"
# 5. broken override (no --version output) -> baked
printf '#!/bin/sh\nexit 1\n' > "$T/override"; chmod +x "$T/override"
[ "$(run)" = "$T/baked" ] || fail "broken override must lose"
echo "launcher_test: ALL PASS"
