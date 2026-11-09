#!/bin/bash
# Logic test for 60zfsnas_persist: superblock scan, seed, bind. Root only.
set -euo pipefail
cd "$(dirname "$0")"
[ "$EUID" -eq 0 ] || { echo "run as root (build VM)"; exit 1; }
H=../hooks/60zfsnas_persist
T=$(mktemp -d)
LOOP=""
ZLOOP=""
DLOOP=""
cleanup() {
    mountpoint -q "$T/dstore" 2>/dev/null && umount "$T/dstore"
    [ -n "$DLOOP" ] && losetup -d "$DLOOP" 2>/dev/null
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

# ---- 5. internal disk: store re-registered at its exact size, pool back ---
# A 4 GiB "disk": store at 1 GiB (512 MiB) + a pool partition after it,
# then the image dd is simulated by dropping both entries (power cut before
# the upgrade could put them back).
truncate -s 4G "$T/disk.img"
DLOOP=$(losetup -f --partscan --show "$T/disk.img")
SS=2097152; SE=3145727; PS=3145728; PE=$(( 8388608 - 34 - 1 ))
sgdisk -n "4:$SS:$SE" -t 4:8300 -c 4:ZFSNAS-PERSIST -n "5:$PS:$PE" -t 5:BF01 -c 5:zpool-1 "$DLOOP" >/dev/null
partx -a "$DLOOP" >/dev/null 2>&1 || partx -u "$DLOOP" >/dev/null 2>&1
mke2fs -t ext4 -q -L ZFSNAS-PERSIST "${DLOOP}p4"
mkdir -p "$T/byid" "$T/dstore"
ln -s "$DLOOP" "$T/byid/nvme-TEST_DISK_1"
ln -s "${DLOOP}p4" "$T/byid/nvme-TEST_DISK_1-part4"
ZP_BYID_DIR="$T/byid"
[ "$(zp_disk_id "$DLOOP")" = "nvme-TEST_DISK_1" ] || fail "zp_disk_id"
mount "${DLOOP}p4" "$T/dstore"
mkdir -p "$T/dstore/.zfsnas-persist"
cat > "$T/dstore/.zfsnas-persist/disk-layout.conf" <<EOF
VERSION=1
DISK_ID=nvme-TEST_DISK_1
SECTOR_SIZE=512
PART=4:$SS:$SE:8300:ZFSNAS-PERSIST
PART=5:$PS:$PE:BF01:zpool-1
POOL_NAME=zpool-1
EOF
umount "$T/dstore"
ZP_DISK="$DLOOP"
[ "$(zp_fs_bytes "$DLOOP" $((SS * 512)))" = $(( (SE - SS + 1) * 512 )) ] || fail "zp_fs_bytes $(zp_fs_bytes "$DLOOP" $((SS * 512)))"
echo "PASS: zp_disk_id + zp_fs_bytes"
sgdisk -d 4 -d 5 "$DLOOP" >/dev/null; partx -d "$DLOOP" >/dev/null 2>&1 || true
off=$(zp_scan_for_store) || fail "scan found no store on the disk"
[ "$off" = $((SS * 512)) ] || fail "scan offset $off"
fsb=$(zp_fs_bytes "$DLOOP" "$off"); last=$(( (off + fsb) / 512 - 1 ))
zp_register_partition "$off" "$last" || fail "register store"
[ "$(cat "/sys/class/block/$(basename "$ZP_PART")/size")" = $((SE - SS + 1)) ] || fail "store not registered at its exact size"
mount "$ZP_PART" "$T/dstore"
zp_restore_layout "$T/dstore"
umount "$T/dstore"
pool=$(zp_part_at_sector "$PS") || fail "pool partition not re-registered"
[ "$(cat "/sys/class/block/$(basename "$pool")/size")" = $((PE - PS + 1)) ] || fail "pool partition wrong size"
sgdisk -i 5 "$DLOOP" 2>/dev/null | grep -q "zpool-1" || sgdisk -p "$DLOOP" | grep -q zpool-1 || fail "pool label"
echo "PASS: store exact size + pool re-registered from the layout"

# ---- 6. a layout naming ANOTHER disk is ignored ---------------------------
sgdisk -d "$(basename "$pool" | sed 's/.*p//')" "$DLOOP" >/dev/null; partx -d "$pool" >/dev/null 2>&1 || partx -u "$DLOOP" >/dev/null 2>&1
mount "$ZP_PART" "$T/dstore"
sed -i 's/^DISK_ID=.*/DISK_ID=nvme-SOME_OTHER_DISK/' "$T/dstore/.zfsnas-persist/disk-layout.conf"
zp_restore_layout "$T/dstore"
umount "$T/dstore"
if zp_part_at_sector "$PS" >/dev/null; then fail "layout of another disk was applied"; fi
echo "PASS: foreign layout ignored"
losetup -d "$DLOOP"; DLOOP=""
echo "hook_test: ALL PASS"
