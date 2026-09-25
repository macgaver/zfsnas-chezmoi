#!/bin/bash
# test.sh — QEMU scenario runner for the USB appliance image (spec §6).
# Run as root in the build VM. Usage: ./test.sh <scenario> [iso]
#   boot-matrix : UEFI+SecureBoot / UEFI / BIOS boots -> portal answers
#   firstboot   : first boot creates + seeds the persist partition
#   reflash     : dd a 2nd ISO over the stick -> store re-adopted
#   overlap     : store too close to ISO end -> overlap-lost + fresh store
#   degraded    : stick with no free space -> boots, degraded status
#   wear        : 30 min idle write-volume check
#   manual      : boot UEFI with display for hands-on portal testing
set -euo pipefail
cd "$(dirname "$0")"
. ./conf.sh
ISO="${2:-$(newest_appliance_iso)}"
[ -n "$ISO" ] || { echo "no znas-usb-appliance-v*.iso here — build one or pass its path"; exit 1; }
WORK="${WORK:-$PWD/work}"
mkdir -p "$WORK"
STICK="$WORK/stick.img"
STICK_SIZE=8G
PORT=18443
MON="$WORK/qemu-mon.sock"

OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.ms.fd    # MS keys -> Secure Boot on
OVMF_VARS=/usr/share/OVMF/OVMF_VARS_4M.ms.fd
OVMF_CODE_NOSB=/usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS_NOSB=/usr/share/OVMF/OVMF_VARS_4M.fd

fail() { echo "FAIL: $*"; exit 1; }
note() { echo -e "\n--- $* ---"; }

make_stick() {
    rm -f "$STICK"
    truncate -s "$STICK_SIZE" "$STICK"
    dd if="$ISO" of="$STICK" bs=4M conv=notrunc status=none
}

# Byte offset where GPT partition 1 (the iso9660 region written by xorriso's
# -partition_offset 16 / -append_partition 2 ESP) ends. This is what the
# persist hook's zp_iso_end actually measures — NOT the raw ISO file size,
# which also includes the appended 16 MiB ESP partition.
stick_iso_end() {   # echoes the ISO9660 partition's end byte on $STICK
    command -v parted >/dev/null || {
        echo "stick_iso_end: parted not installed (see README build-VM deps)" >&2
        return 1
    }
    e=$(parted -sm "$STICK" unit B print 2>/dev/null \
        | awk -F: '$1=="1"{gsub("B","",$3); print $3}')
    [ -n "$e" ] || { echo "stick_iso_end: could not read partition 1 end" >&2; return 1; }
    echo "$e"
}

# NOTE: the serial chardev keeps BOTH a socket (so grub_pick_toram can drive the
# GRUB menu) and a logfile QEMU writes itself. A bare `-serial unix:...` with no
# reader attached starves the guest: with console=ttyS0 on the cmdline the boot
# blocks once the socket buffer fills, which silently failed whole scenarios.
qemu_up() {   # $1 = firmware: sb | uefi | bios ; extra args pass through
    fw="$1"; shift
    local fwargs=()
    case "$fw" in
        sb)   cp "$OVMF_VARS" "$WORK/vars.fd"
              # Ubuntu's MS-keys firmware is built SMM_REQUIRE: without q35 +
              # smm=on (and the secure pflash property) it cannot manage
              # authenticated variables and never boots. Real hardware needs
              # none of this — it is purely how you enable Secure Boot in QEMU.
              fwargs=(-machine q35,smm=on
                      -global driver=cfi.pflash01,property=secure,value=on
                      -global ICH9-LPC.disable_s3=1
                      -drive "if=pflash,format=raw,unit=0,readonly=on,file=$OVMF_CODE"
                      -drive "if=pflash,format=raw,unit=1,file=$WORK/vars.fd") ;;
        uefi) cp "$OVMF_VARS_NOSB" "$WORK/vars.fd"
              fwargs=(-drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE_NOSB"
                      -drive "if=pflash,format=raw,file=$WORK/vars.fd") ;;
        bios) fwargs=() ;;
    esac
    # The serial LOG must go too, not just the sockets: grub_pick_toram waits
    # for the GRUB countdown to appear in it, and a leftover log from the
    # previous leg matches instantly — the keystrokes then fire before QEMU
    # has even created its monitor socket (~2s), GRUB never sees them, and the
    # leg fails as if the image could not boot to RAM. Cost me three runs.
    rm -f "$MON" "$WORK/serial.sock" "$WORK/serial.log"
    qemu-system-x86_64 -enable-kvm -m 4096 -smp 2 -display "${QDISPLAY:-none}" \
        "${fwargs[@]}" \
        -drive "file=$STICK,if=none,id=stick,format=raw" \
        -device qemu-xhci -device usb-storage,drive=stick \
        -netdev "user,id=n0,hostfwd=tcp::${PORT}-:8443,hostfwd=tcp::10022-:22" \
        -device virtio-net-pci,netdev=n0 \
        -monitor "unix:$MON,server,nowait" \
        -chardev "socket,id=zser,path=$WORK/serial.sock,server=on,wait=off,logfile=$WORK/serial.log" \
        -serial chardev:zser \
        "$@" &
    QPID=$!
}

qemu_down() {
    echo quit | socat - "UNIX-CONNECT:$MON" >/dev/null 2>&1 || kill "$QPID" 2>/dev/null || true
    for _ in $(seq 1 10); do
        kill -0 "$QPID" 2>/dev/null || break
        sleep 1
    done
    if kill -0 "$QPID" 2>/dev/null; then
        kill -9 "$QPID" 2>/dev/null || true
    fi
    wait "$QPID" 2>/dev/null || true
}
monkey() {   # send one key through the QEMU monitor
    # Wait for the monitor socket: QEMU takes a second or two to create it, and
    # a key sent into a missing socket is lost with only a socat message on
    # stderr — which reads later like the guest ignored the key.
    for _ in $(seq 1 20); do
        [ -S "$MON" ] && break
        sleep 1
    done
    [ -S "$MON" ] || { echo "monkey: QEMU monitor socket never appeared — key '$1' NOT sent" >&2; return 1; }
    printf 'sendkey %s\n' "$1" | socat - "UNIX-CONNECT:$MON" >/dev/null
}

wait_portal() {
    for _ in $(seq 1 90); do
        if curl -skm 5 "https://127.0.0.1:$PORT/" >/dev/null 2>&1; then
            return 0
        fi
        # Fail fast (and say why) if QEMU is gone — a hostfwd bind clash or a
        # bad drive kills it in the first second, and waiting out the full
        # 7.5-minute budget for a dead process just hides the real error.
        if ! kill -0 "$QPID" 2>/dev/null; then
            echo "wait_portal: QEMU exited early (pid $QPID)" >&2
            tail -5 "$WORK/serial.log" 2>/dev/null >&2
            return 1
        fi
        sleep 5
    done
    {   echo "wait_portal: timed out after 450s — diagnostics:"
        echo "  qemu alive: $(kill -0 "$QPID" 2>/dev/null && echo yes || echo no)"
        echo "  host ports: $(ss -ltn 2>/dev/null | grep -c ":$PORT")"
        echo "  serial tail:"; tail -6 "$WORK/serial.log" 2>/dev/null | tr -cd '[:print:]\n'
    } >&2
    return 1
}


# Drive the GRUB menu over the serial console (deterministic — no sleep-guessing
# a video-console keystroke timing) and have GRUB itself confirm the RAM entry
# was actually selected before we move on. Requires build.sh's grub.cfg to
# enable `serial`/`terminal_input|output ... serial` (Task 16 amendment).
grub_pick_toram() {
    # Drive the GRUB menu with the QEMU monitor (sendkey), not by reading the
    # serial socket: the menu is only on screen for `timeout=5`, so a reader
    # that attaches late never sees it and the whole leg stalls. Verification
    # does not need GRUB's echo either — the kernel prints its own command
    # line, so "toram" appearing there is proof the right entry booted.
    # WAIT for the menu to actually be on screen before typing. A fixed sleep
    # was wrong: plain OVMF reaches GRUB noticeably later than the MS-keys
    # build, so the keystrokes landed before the menu existed, GRUB timed out
    # and booted the DEFAULT entry — the leg then failed with "kernel never
    # reported toram" while the image was perfectly fine.
    # Wait for the COUNTDOWN line, not merely for the menu text. The menu is
    # drawn once at the firmware's initial resolution and then AGAIN after the
    # mode switch, and that redraw puts the highlight back on the default
    # entry — so keys sent between the two renders are undone, which is how
    # plain UEFI kept booting the default entry while Secure Boot (whose
    # redraw lands earlier) passed. The countdown only prints once the menu
    # has settled, and leaves `timeout=5` to act in.
    for _ in $(seq 1 90); do
        grep -aq "executed automatically" "$WORK/serial.log" 2>/dev/null && break
        sleep 1
    done
    # No arrow key: "load OS to RAM" is the FIRST entry and the default, so the
    # highlight already sits on it. (It used to be second, and this pressed
    # down once.) Enter just skips the countdown.
    monkey ret
    for _ in $(seq 1 24); do
        if grep -aq "Command line:.*toram" "$WORK/serial.log" 2>/dev/null; then
            echo "  toram entry confirmed on the kernel command line"
            return 0
        fi
        kill -0 "$QPID" 2>/dev/null || { echo "grub_pick_toram: QEMU exited" >&2; return 1; }
        # Nothing has booted yet: the menu may still be up because a keystroke
        # was swallowed by a redraw. Press enter again — the highlight is
        # already on the toram entry, so this can only confirm it.
        grep -aq "Command line:" "$WORK/serial.log" 2>/dev/null || monkey ret
        sleep 5
    done
    echo "grub_pick_toram: kernel never reported toram" >&2
    grep -a "Command line:" "$WORK/serial.log" 2>/dev/null | head -2 >&2
    return 1
}


# Mount the stick's persist partition on the HOST (VM must be off).
inspect_stick() {   # sets INSPECT_DIR; caller must call uninspect_stick
    LOOPDEV=$(losetup -Pf --show "$STICK")
    for _ in 1 2 3; do
        compgen -G "${LOOPDEV}p*" >/dev/null 2>&1 && break
        sleep 1
    done
    PPART=$(blkid -o device -t "LABEL=$PERSIST_LABEL" "$LOOPDEV"p* 2>/dev/null | head -n1)
    [ -n "$PPART" ] || { losetup -d "$LOOPDEV" 2>/dev/null || true; return 1; }
    INSPECT_DIR=$(mktemp -d)
    mount "$PPART" "$INSPECT_DIR" || {
        rmdir "$INSPECT_DIR" 2>/dev/null || true
        losetup -d "$LOOPDEV" 2>/dev/null || true
        return 1
    }
}
uninspect_stick() {
    # `losetup -d` is asynchronous: the device can linger with dirty pages for
    # $STICK. If we dd a new ISO over the file while that is still true, the
    # loop device's stale pages get written back afterwards and silently
    # clobber what we just wrote. Unmount, flush, then WAIT for the device to
    # actually go away before returning.
    umount "$INSPECT_DIR" 2>/dev/null || true
    sync
    rmdir "$INSPECT_DIR" 2>/dev/null || true
    losetup -d "$LOOPDEV" 2>/dev/null || true
    for _ in $(seq 1 10); do
        losetup -a 2>/dev/null | grep -q "^$LOOPDEV:" || break
        sleep 1
    done
    sync
}

sc_boot_matrix() {
    # Driving a 5-second GRUB menu through a serial console is inherently racy;
    # one retry keeps a swallowed keystroke from being reported as an image
    # failure. A leg that fails TWICE is a real finding. Both entries are
    # verified against the kernel command line, so a missed keystroke shows up
    # as a failed leg rather than as a leg that silently retested the default.

    # Entry 1 (the DEFAULT): load OS to RAM.
    for fw in sb uefi bios; do
        note "boot-matrix: $fw + toram (default entry)"
        for attempt in 1 2; do
            make_stick
            qemu_up "$fw"
            if grub_pick_toram && wait_portal; then
                qemu_down
                echo "PASS: $fw + toram"
                break
            fi
            qemu_down
            [ "$attempt" = 2 ] && fail "toram entry never booted ($fw) — failed twice"
            echo "  retrying $fw + toram (attempt 2)"
        done
    done

    # Entry 2: run from the stick (no toram).
    for fw in sb uefi bios; do
        note "boot-matrix: $fw + run-from-stick"
        for attempt in 1 2; do
            make_stick
            qemu_up "$fw"
            if grub_pick_from_stick && wait_portal; then
                qemu_down
                echo "PASS: $fw + run-from-stick"
                break
            fi
            qemu_down
            [ "$attempt" = 2 ] && fail "run-from-stick entry never booted ($fw) — failed twice"
            echo "  retrying $fw + run-from-stick (attempt 2)"
        done
    done
}

# Pick the SECOND entry, "run from stick" — the non-toram boot. Mirrors
# grub_pick_toram, but asserts the opposite: the kernel command line must NOT
# carry toram, which is what proves the arrow key landed and we are really
# exercising the read-from-stick path rather than silently retesting the
# default.
grub_pick_from_stick() {
    for _ in $(seq 1 90); do
        grep -aq "executed automatically" "$WORK/serial.log" 2>/dev/null && break
        sleep 1
    done
    monkey down          # exactly one: a second would move on to "safe graphics"
    sleep 1
    monkey ret
    for _ in $(seq 1 24); do
        if grep -aq "Command line:" "$WORK/serial.log" 2>/dev/null; then
            if grep -aq "Command line:.*toram" "$WORK/serial.log" 2>/dev/null; then
                # The down keystroke was swallowed by a menu redraw and GRUB
                # booted the default. Caller retries the whole leg.
                echo "grub_pick_from_stick: booted the toram entry instead" >&2
                return 1
            fi
            echo "  run-from-stick entry confirmed (no toram on the kernel command line)"
            return 0
        fi
        kill -0 "$QPID" 2>/dev/null || { echo "grub_pick_from_stick: QEMU exited" >&2; return 1; }
        sleep 5
    done
    echo "grub_pick_from_stick: kernel never reported a command line" >&2
    grep -a "Command line:" "$WORK/serial.log" 2>/dev/null | head -2 >&2
    return 1
}

sc_firstboot() {
    make_stick
    qemu_up uefi
    wait_portal || { qemu_down; fail "portal never answered"; }
    qemu_down
    inspect_stick || fail "no persist partition created"
    [ -d "$INSPECT_DIR/.zfsnas-persist/config" ]  || { uninspect_stick; fail "store not seeded (config)"; }
    [ -f "$INSPECT_DIR/.zfsnas-persist/persist.json" ] || { uninspect_stick; fail "no persist.json"; }
    [ -s "$INSPECT_DIR/.zfsnas-persist/system/etc-identity/hostid" ] || { uninspect_stick; fail "no hostid"; }
    uninspect_stick
    echo "PASS: firstboot"
}

sc_reflash() {
    sc_firstboot
    inspect_stick || fail "inspect"
    echo "reflash-canary" > "$INSPECT_DIR/.zfsnas-persist/config/canary.txt"
    uninspect_stick
    note "reflashing (dd new ISO over the stick, persist blocks untouched)"
    dd if="$ISO" of="$STICK" bs=4M conv=notrunc status=none   # wipes GPT, not the store
    qemu_up uefi
    wait_portal || { qemu_down; fail "portal never answered after reflash"; }
    qemu_down
    inspect_stick || fail "store not re-adopted after reflash"
    [ -f "$INSPECT_DIR/.zfsnas-persist/config/canary.txt" ] || { uninspect_stick; fail "canary lost"; }
    uninspect_stick
    echo "PASS: reflash"
}

sc_overlap() {
    # Plant a labeled ext4 at the first GiB boundary AT/PAST the ISO's
    # iso9660-partition end (planting below that would corrupt the ISO
    # itself). Whether that boundary falls inside the 512 MiB headroom is
    # fixed by the ISO's size, so compute which behavior the hook MUST show
    # and assert exactly that:
    #   boundary <  isoend+512MiB -> overlap-lost + fresh store
    #   boundary >= isoend+512MiB -> clean re-adoption
    GIB=1073741824; HEADROOM=536870912
    make_stick
    ISOEND=$(stick_iso_end) || fail "cannot determine ISO end on the stick"
    B=$(( ((ISOEND + GIB - 1) / GIB) * GIB ))
    truncate -s 256M "$WORK/oldfs.img"
    mke2fs -t ext4 -q -L "$PERSIST_LABEL" "$WORK/oldfs.img"
    # drop a canary into the planted store to detect adoption vs recreation
    LOOPTMP=$(losetup -f --show "$WORK/oldfs.img"); MT=$(mktemp -d)
    mount "$LOOPTMP" "$MT"; mkdir -p "$MT/.zfsnas-persist/config"
    echo overlap-canary > "$MT/.zfsnas-persist/config/canary.txt"
    umount "$MT"; losetup -d "$LOOPTMP"; rmdir "$MT"
    dd if="$WORK/oldfs.img" of="$STICK" bs=4M seek=$((B / 4194304)) \
        conv=notrunc status=none
    qemu_up uefi
    wait_portal || { qemu_down; fail "portal never answered"; }
    qemu_down
    inspect_stick || fail "no persist store present after boot"
    if [ "$B" -lt $((ISOEND + HEADROOM)) ]; then
        [ ! -f "$INSPECT_DIR/.zfsnas-persist/config/canary.txt" ] \
            || { uninspect_stick; fail "overlap store adopted but must be declared lost"; }
        uninspect_stick
        echo "PASS: overlap (geometry forced overlap-lost; fresh store created)"
        echo "      (amber portal banner verified by eye in scenario 3)"
    else
        [ -f "$INSPECT_DIR/.zfsnas-persist/config/canary.txt" ] \
            || { uninspect_stick; fail "store past headroom must be re-adopted"; }
        uninspect_stick
        echo "PASS: overlap (geometry outside headroom -> clean re-adoption)"
        echo "      NOTE: to exercise the overlap-lost path too, rebuild with a"
        echo "      padded squashfs or shrink HEADROOM in a scratch hook build."
    fi
}

sc_degraded() {
    # Stick barely larger than the ISO -> no room -> degraded, still boots.
    ISOB=$(stat -c %s "$ISO")
    rm -f "$STICK"
    truncate -s $((ISOB + 64 * 1024 * 1024)) "$STICK"
    dd if="$ISO" of="$STICK" bs=4M conv=notrunc status=none
    qemu_up uefi
    wait_portal || { qemu_down; fail "degraded image must still boot + serve"; }
    qemu_down
    echo "PASS: degraded (portal red banner verified manually in scenario 3)"
}

sc_wear() {
    make_stick
    qemu_up uefi
    wait_portal || { qemu_down; fail "portal never answered"; }
    # Sample a PROFILE, not a single delta. The first minutes after boot are a
    # one-off burst (the portal creating its config, certs and RRD files); what
    # actually wears a stick out is the steady state after that. Measuring only
    # start-to-end conflates the two and fails on a perfectly healthy image.
    read_wr() {
        echo 'info blockstats' | socat - "UNIX-CONNECT:$MON" 2>/dev/null \
            | sed -n 's/^stick:.*wr_bytes=\([0-9]*\).*/\1/p'
    }
    note "settling for 5 min after boot, then sampling for 30 min"
    prev=$(read_wr); settle=$prev
    sleep 300
    settle=$(read_wr)
    echo "  post-boot burst (boot + first 5 min): $(( (settle - prev) / 1048576 )) MiB"
    prev=$settle
    for i in 1 2 3 4 5 6; do
        sleep 300
        cur=$(read_wr)
        echo "  minute $((i*5)): $(( (cur - prev) / 1024 )) KiB written"
        prev=$cur
    done
    qemu_down
    total_kib=$(( (prev - settle) / 1024 ))
    echo "steady-state writes over 30 idle minutes: ${total_kib} KiB"
    # 30 MiB/30 min steady state would be ~0.5 TB/year — the real red line.
    [ "$total_kib" -lt 30720 ] || fail "wear: ${total_kib} KiB in 30 steady-state minutes is too much — find the writer"
    echo "PASS: wear"
}


sc_manual() {
    make_stick
    # two blank disks so the operator can create a mirrored ZFS pool
    qemu-img create -f qcow2 "$WORK/pool1.qcow2" 4G >/dev/null
    qemu-img create -f qcow2 "$WORK/pool2.qcow2" 4G >/dev/null
    QDISPLAY=gtk qemu_up uefi \
        -drive "file=$WORK/pool1.qcow2,if=virtio,format=qcow2" \
        -drive "file=$WORK/pool2.qcow2,if=virtio,format=qcow2"
    echo "Manual session: portal https://127.0.0.1:$PORT — ssh root@127.0.0.1 -p 10022"
    echo "Ctrl-C here when done."
    wait "$QPID"
}

case "${1:-}" in
    boot-matrix) sc_boot_matrix ;;
    firstboot)   sc_firstboot ;;
    reflash)     sc_reflash ;;
    overlap)     sc_overlap ;;
    degraded)    sc_degraded ;;
    wear)        sc_wear ;;
    manual)      sc_manual ;;
    *) grep '^#   ' "$0"; exit 1 ;;
esac
