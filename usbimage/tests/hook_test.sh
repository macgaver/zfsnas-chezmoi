#!/bin/bash
# Logic test for 60zfsnas_persist: superblock scan, seed, bind. Root only.
set -euo pipefail
cd "$(dirname "$0")"
[ "$EUID" -eq 0 ] || { echo "run as root (build VM)"; exit 1; }
H=../hooks/60zfsnas_persist
T=$(mktemp -d)
LOOP=""
ZLOOP=""
cleanup() {
    umount -R "$T/root" 2>/dev/null || true    # any leftover binds
    mountpoint -q "$T/store-mnt" 2>/dev/null && umount "$T/store-mnt"
    [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null
    [ -n "$ZLOOP" ] && losetup -d "$ZLOOP" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT
fail() { echo "FAIL: $1"; exit 1; }

# ---- 1. superblock scan finds a labeled ext4 at a GiB boundary -------------
truncate -s 3G "$T/stick.img"
LOOP=$(losetup -f --show "$T/stick.img")
# put an ext4 labeled ZFSNAS-PERSIST at exactly 1 GiB, 512 MiB long
truncate -s 512M "$T/fs.img"
mke2fs -t ext4 -q -L ZFSNAS-PERSIST "$T/fs.img"
dd if="$T/fs.img" of="$LOOP" bs=1M seek=1024 conv=notrunc status=none
export ZFSNAS_HOOK_SOURCED=1
. "$H"
ZP_DISK="$LOOP"
off=$(zp_scan_for_store) || fail "scan found nothing"
[ "$off" = "1073741824" ] || fail "scan offset $off != 1GiB"
echo "PASS: scan"

# ---- 2. seed + bind against a fake root ------------------------------------
mkdir -p "$T/store-mnt" "$T/root/etc-target" "$T/root/etc"
mount -t ext4 -o loop "$T/fs.img" "$T/store-mnt" 2>/dev/null || \
    mount -t ext4 "$T/fs.img" "$T/store-mnt"
echo "version=6.8.28" > "$T/root/etc/zfsnas-release"
mkdir -p "$T/root/opt/zfsnas/config"
echo '{"seeded":"yes"}' > "$T/root/opt/zfsnas/config/settings.json"
echo "test-shadow-content" > "$T/root/etc/shadow-t"
MANIFEST="$T/manifest"
cat > "$MANIFEST" <<EOF
dir config /opt/zfsnas/config
file system/hostid /etc/hostid
copy system/shadow /etc/shadow-t
EOF
zp_seed_and_bind "$T/store-mnt/.zfsnas-persist" "$T/root"
[ -f "$T/store-mnt/.zfsnas-persist/config/settings.json" ] || fail "dir seed"
grep -q seeded "$T/root/opt/zfsnas/config/settings.json" || fail "dir bind"
mountpoint -q "$T/root/opt/zfsnas/config" || fail "config not a bind mount"
[ -s "$T/store-mnt/.zfsnas-persist/system/hostid" ] || fail "hostid not generated"
[ "$(stat -c %s "$T/store-mnt/.zfsnas-persist/system/hostid")" = 4 ] || fail "hostid size"
[ -f "$T/store-mnt/.zfsnas-persist/persist.json" ] || fail "persist.json"
grep -q '"created_by_image":"6.8.28"' "$T/store-mnt/.zfsnas-persist/persist.json" || fail "persist.json content"
mountpoint -q "$T/root/etc/hostid" || fail "hostid not bound"
umount "$T/root/opt/zfsnas/config" "$T/root/etc/hostid"
echo "PASS: seed+bind"

# ---- 3. copy-type: seeded into the store, copied to target, NOT bound -----
[ -f "$T/store-mnt/.zfsnas-persist/system/shadow" ] || fail "copy-type not seeded into store"
grep -q "test-shadow-content" "$T/store-mnt/.zfsnas-persist/system/shadow" || fail "copy-type store content wrong"
grep -q "test-shadow-content" "$T/root/etc/shadow-t" || fail "copy-type not copied to target"
mountpoint -q "$T/root/etc/shadow-t" 2>/dev/null && fail "copy-type target must NOT be a bind mount"
echo "PASS: copy-type (seed, copy, no-bind)"

# ---- 4. zp_part_at_sector resolves a GPT entry by its start sector --------
# This is the building block both zp_register_partition's retry loop and
# the zp_main fresh-create path's zombie self-heal (round-2 fix) depend on.
# A full end-to-end "zombie entry survives a reboot and gets re-adopted"
# scenario is NOT exercised here: it lives inline in zp_main's fresh-create
# branch (not factored into a standalone function, per the round-2 ruling —
# only zp_part_at_sector was), and reaching it means going through
# zp_find_disk, which requires a real casper iso9660 mount in /proc/mounts.
# Faking that here would mean either mounting a real ISO image just for
# this unit test, or re-implementing zp_main's fresh-create branch inline
# in the test — the latter tests a copy of the logic, not the hook itself.
# Both are the kind of contortion this test is meant to avoid; the full
# zombie-adoption scenario is exercised by Phase C's QEMU scenario runner
# instead (reflash matrix), which boots the real hook end to end.
truncate -s 2G "$T/zombie.img"
ZLOOP=$(losetup -f --partscan --show "$T/zombie.img")
sgdisk -n "0:2048:+64MiB" -t 0:8300 -c "0:testpart" "$ZLOOP" >/dev/null 2>&1 || fail "sgdisk setup for zombie test failed"
partx -a "$ZLOOP" >/dev/null 2>&1 || partx -u "$ZLOOP" >/dev/null 2>&1
ZP_DISK="$ZLOOP"
part=$(zp_part_at_sector 2048) || fail "zp_part_at_sector found nothing for sector 2048"
[ -b "$part" ] || fail "zp_part_at_sector returned non-block-device: $part"
[ "$(cat "/sys/class/block/$(basename "$part")/start")" = "2048" ] || fail "resolved wrong partition"
if zp_part_at_sector 999999 >/dev/null 2>&1; then
    fail "zp_part_at_sector should find nothing for a sector with no partition"
fi
losetup -d "$ZLOOP"
ZLOOP=""
echo "PASS: zp_part_at_sector"
echo "hook_test: ALL PASS"
