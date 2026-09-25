#!/bin/bash
# build.sh — builds znas-usb-appliance-v<ubuntu x-y-z>-<build>.iso. Run as root
# in the build VM.
# Usage: ./build.sh [--binary /path/to/zfsnas] [--from STAGE] [--test]
# Stages: debootstrap chroot binary squashfs iso smoke
#
# OS package freshness: the `chroot` stage refreshes the archive and
# dist-upgrades the rootfs, so any build that runs it ships current Ubuntu
# packages. `--from binary` (and later) deliberately reuses the rootfs as-is
# and touches no packages — it is the fast path for a new portal binary only.
# Ship an image after a chroot-stage build when OS updates matter.
set -euo pipefail
cd "$(dirname "$0")"
. ./conf.sh

WORK="${WORK:-$PWD/work}"
ROOTFS="$WORK/rootfs"
ISOROOT="$WORK/isoroot"
OUT=""   # set by set_out once the rootfs (and so the Ubuntu release) exists
BINARY="../zfsnas"
FROM=""
SMOKE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --binary) BINARY="$2"; shift 2 ;;
        --from)   FROM="$2";   shift 2 ;;
        --test)   SMOKE=1;     shift ;;
        *) echo "unknown arg $1"; exit 1 ;;
    esac
done
[ "$EUID" -eq 0 ] || { echo "run as root"; exit 1; }
for t in debootstrap mksquashfs xorriso sgdisk mkfs.vfat mcopy mmd grub-mkimage; do
    command -v "$t" >/dev/null || { echo "missing tool: $t (see README)"; exit 1; }
done

log() { echo -e "\n=== $* ==="; }

# appliance_version: <Ubuntu point release>-<APPLIANCE_BUILD> from the built
# rootfs. VERSION is "26.04.1 LTS (Resolute Raccoon)"; the .0 release has no
# point digit ("26.04 LTS"), so it becomes 26.04.0.
appliance_version() {
    local v
    v=$(. "$ROOTFS/etc/os-release" && echo "${VERSION%% *}")
    [ -n "$v" ] || { echo "cannot read the Ubuntu version from $ROOTFS/etc/os-release" >&2; exit 1; }
    case "$v" in *.*.*) ;; *) v="$v.0" ;; esac
    # The CI workflow declares the Ubuntu release it expects. The archive only
    # serves the current point release, so a mismatch means the declaration is
    # stale (or early) — refuse rather than publish a mislabelled image.
    if [ -n "${UBUNTU_VERSION:-}" ] && [ "$v" != "$UBUNTU_VERSION" ]; then
        echo "the rootfs is Ubuntu $v but UBUNTU_VERSION declares $UBUNTU_VERSION — update APPLIANCE_UBUNTU_VERSION in .github/workflows/appliance-image.yml" >&2
        exit 1
    fi
    echo "${v}-${APPLIANCE_BUILD}"
}
set_out() { [ -n "$OUT" ] || OUT="$PWD/$(appliance_iso_name "$(appliance_version)")"; }

stage_debootstrap() {
    log "stage: debootstrap ($UBUNTU_CODENAME)"
    curl -sfIo /dev/null "$MIRROR/dists/$UBUNTU_CODENAME/Release" \
        || { echo "codename '$UBUNTU_CODENAME' not on mirror — fix conf.sh"; exit 1; }
    # a previous hard-killed run may have left proc/sys/dev bind-mounted
    # under ROOTFS — rm -rf through a live /dev bind would delete host
    # device nodes
    umount_chroot
    rm -rf "$ROOTFS"; mkdir -p "$ROOTFS"
    debootstrap --arch=amd64 --variant=minbase \
        --components=main,universe "$UBUNTU_CODENAME" "$ROOTFS" "$MIRROR"
}

mount_chroot()  { for m in proc sys dev dev/pts; do mount --bind "/$m" "$ROOTFS/$m"; done; }
umount_chroot() { for m in dev/pts dev sys proc; do umount -l "$ROOTFS/$m" 2>/dev/null || true; done; }

stage_chroot() {
    log "stage: chroot customization"
    # overlay files, manifest, hooks — BEFORE chroot-setup so
    # update-initramfs picks the persist hook up
    cp -a overlay/. "$ROOTFS/"
    # Every path the overlay touches must end up root-owned and not group/
    # world-writable. The checkout belongs to the build user (uid 1000) with a
    # 002 umask, and cp -a carried that over — onto the files AND onto the
    # image's /, /etc, /usr (cp -a overlay/. copies the top dir's attributes
    # too). The appliance's first shell user also gets uid 1000, so it could
    # have rewritten root-run scripts or dropped files into /etc. Fix-up rather
    # than cp --no-preserve, because a reused rootfs keeps the old owners.
    (cd overlay && find . -print0) | while IFS= read -r -d '' p; do
        chown -h root:root "$ROOTFS/$p"
        [ -L "$ROOTFS/$p" ] || chmod go-w "$ROOTFS/$p"
    done
    chmod 0755 "$ROOTFS"/usr/lib/zfsnas/*.sh
    mkdir -p "$ROOTFS/usr/share/zfsnas"
    cp persist-manifest.txt "$ROOTFS/usr/share/zfsnas/persist-manifest.txt"
    # initramfs-tools/casper aren't installed into ROOTFS yet at this point
    # (that happens inside chroot-setup.sh below via linux-generic/casper) —
    # these target dirs don't exist on a bare debootstrap minbase rootfs, so
    # create them before installing our hook files into them.
    mkdir -p "$ROOTFS/usr/share/initramfs-tools/hooks" \
        "$ROOTFS/usr/share/initramfs-tools/scripts/casper-bottom"
    install -m 0755 hooks/zfsnas-persist.hook \
        "$ROOTFS/usr/share/initramfs-tools/hooks/zfsnas-persist"
    install -m 0755 hooks/60zfsnas_persist \
        "$ROOTFS/usr/share/initramfs-tools/scripts/casper-bottom/60zfsnas_persist"
    install -m 0755 chroot-setup.sh "$ROOTFS/chroot-setup.sh"
    # Give the chroot a working resolver for the duration of the stage.
    # chroot-setup.sh ends by replacing /etc/resolv.conf with the stub the
    # dhcpcd exit-hook writes into at runtime — which means re-entering this
    # stage (--from chroot) would otherwise start with a nameserver-less file
    # and every download in it would fail. apt hides that (its packages are
    # already cached), so the failure lands on the first wget and takes the
    # whole build down with no obvious cause. Seen twice; hence this.
    if grep -q '^nameserver' /etc/resolv.conf 2>/dev/null; then
        cp -L /etc/resolv.conf "$ROOTFS/etc/resolv.conf"
    else
        printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' > "$ROOTFS/etc/resolv.conf"
    fi
    mount_chroot
    trap umount_chroot EXIT
    chroot "$ROOTFS" /chroot-setup.sh "$UBUNTU_CODENAME" "$MIRROR"
    umount_chroot
    trap - EXIT
    rm -f "$ROOTFS/chroot-setup.sh"
    # Fail now, not an hour later at squashfs, if the declared Ubuntu release
    # is not what dist-upgrade just installed.
    echo "appliance version: $(appliance_version)"
}

stage_binary() {
    log "stage: zfsnas binary"
    [ -f "$BINARY" ] || { echo "binary not found: $BINARY (use --binary)"; exit 1; }
    install -D -m 0755 "$BINARY" "$ROOTFS/opt/zfsnas/zfsnas"
    v=$("$ROOTFS/opt/zfsnas/zfsnas" --version || true)
    echo "binary reports version: $v (image: $IMAGE_VERSION)"
    [ "$v" = "$IMAGE_VERSION" ] || echo "WARNING: version mismatch"
}

stage_squashfs() {
    log "stage: squashfs"
    # Stamped here, the last step before the rootfs is frozen, so the Ubuntu
    # release it names is the one actually shipped whatever stage we resumed
    # from. appliance_version is what the portal compares against GitHub.
    printf 'version=%s\nappliance_version=%s\nbuild_date=%s\n' \
        "$IMAGE_VERSION" "$(appliance_version)" "$(date -u +%F)" \
        > "$ROOTFS/etc/zfsnas-release"
    # Console pre-login line (agetty): name the appliance, not just Ubuntu.
    # Display only — version checks read os-release / zfsnas-release, never this.
    printf 'ZNAS Appliance %s (Ubuntu %s) \\n \\l\n\n' "$(appliance_version)" \
        "$(. "$ROOTFS/etc/os-release" && echo "${VERSION%% (*}")" > "$ROOTFS/etc/issue"
    mkdir -p "$ISOROOT/casper"
    cp "$(ls -1v "$ROOTFS"/boot/vmlinuz-* | tail -n1)" "$ISOROOT/casper/vmlinuz"
    cp "$(ls -1v "$ROOTFS"/boot/initrd.img-* | tail -n1)" "$ISOROOT/casper/initrd"
    # NOTE: do NOT exclude /tmp /proc /sys /dev /run — mksquashfs -e drops the
    # DIRECTORY, not just its contents, and a live root with no /tmp breaks
    # debconf and leaves tmp.mount without a mountpoint (init dies on boot).
    # They are empty in the rootfs (chroot binds are unmounted by stage_chroot);
    # Ubuntu's own live squashfs ships them the same way.
    rm -f "$ISOROOT/casper/filesystem.squashfs"
    mksquashfs "$ROOTFS" "$ISOROOT/casper/filesystem.squashfs" \
        -comp zstd -Xcompression-level 19 -noappend -wildcards \
        -e 'boot/vmlinuz*' -e 'boot/initrd.img*'
    printf '%s' "$(du -sx --block-size=1 "$ROOTFS" | cut -f1)" \
        > "$ISOROOT/casper/filesystem.size"
}

stage_iso() {
    log "stage: ISO assembly (hybrid BIOS+UEFI, Secure Boot chain)"
    set_out
    rm -f "$OUT" "$OUT.sha256" "$OUT.sig"

    # ---- GRUB menu (read by BOTH boot paths) -------------------------------
    # Entry ORDER is load-bearing, not cosmetic. "load OS to RAM" (toram) is
    # first and therefore the default because zfsnas-upgrade-image REFUSES to
    # run on any other entry: overwriting the image while the running system
    # reads its squashfs from that same region corrupts the live OS. Booting
    # from the stick instead means the only way to update the image is from
    # another machine, so the second entry says so in its title.
    # test.sh drives this menu by position (grub_pick_toram / the from-stick
    # leg) — reordering these entries means updating that harness too.
    # Titles stay pure ASCII and under ~76 chars: GRUB's built-in terminal font
    # has no unicode.pf2 loaded, and an 80-col text console truncates the rest.
    #
    # IOMMU is on by DEFAULT so PCI passthrough works out of the box: without
    # it the kernel builds no IOMMU groups and vfio-pci cannot claim a device,
    # which is a silent dead end in the passthrough UI. Both vendor flags ride
    # together (each is ignored by the other vendor's code, so one image serves
    # Intel and AMD), and iommu=pt keeps host-owned devices on identity mapping
    # so nothing pays for the DMA remap it does not use. The vfio modules
    # themselves are already in the stock generic kernel.
    # "safe graphics" deliberately does NOT get these flags: on hardware with a
    # broken IOMMU implementation it is the way back in.
    # noprompt: casper-stop otherwise ends every shutdown/reboot with "Please
    # remove the installation medium, then press ENTER" and waits forever for
    # a keypress — a headless appliance never reboots. (The portal also drops
    # /run/casper-no-prompt at startup, which covers images built before this.)
    # nopersistent: casper's own auto-persistence (casper-helpers) appends a
    # "writable" partition across the stick's free space before our hook runs,
    # which both steals the region our aligned store needs and is the wrong
    # model for this appliance (we do selective persistence, not a whole-root
    # overlay).
    mkdir -p "$ISOROOT/boot/grub"
    cat > "$ISOROOT/boot/grub/grub.cfg" <<EOF
# serial console: headless debugging on real hardware + deterministic menu driving in the QEMU test rig
serial --unit=0 --speed=115200
terminal_input console serial
terminal_output console serial
set default=0
set timeout=5
menuentry "ZNAS System (USB appliance) - load OS to RAM [default, keep stick in]" {
    linux  /casper/vmlinuz boot=casper noprompt toram nopersistent intel_iommu=on amd_iommu=on iommu=pt console=tty0 console=ttyS0,115200n8 ---
    initrd /casper/initrd
}
menuentry "ZNAS System (USB appliance) - run from stick, upgrade from another PC" {
    linux  /casper/vmlinuz boot=casper noprompt nopersistent intel_iommu=on amd_iommu=on iommu=pt console=tty0 console=ttyS0,115200n8 ---
    initrd /casper/initrd
}
menuentry "ZNAS System (safe graphics)" {
    linux  /casper/vmlinuz boot=casper noprompt nomodeset nopersistent console=tty0 console=ttyS0,115200n8 ---
    initrd /casper/initrd
}
EOF

    # ---- ESP: Canonical-signed shim -> signed GRUB (Secure Boot) -----------
    ESP="$WORK/esp.img"
    rm -f "$ESP"
    truncate -s 16M "$ESP"
    mkfs.vfat -n ESP "$ESP" >/dev/null
    mmd -i "$ESP" ::/EFI ::/EFI/BOOT ::/EFI/ubuntu
    SHIM="$ROOTFS/usr/lib/shim/shimx64.efi.signed.latest"
    [ -f "$SHIM" ] || SHIM="$ROOTFS/usr/lib/shim/shimx64.efi.signed"
    MOKM="$ROOTFS/usr/lib/shim/mmx64.efi.signed"
    [ -f "$MOKM" ] || MOKM="$ROOTFS/usr/lib/shim/mmx64.efi"
    GRUBEFI="$ROOTFS/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed"
    GRUBLIB="$ROOTFS/usr/lib/grub/i386-pc"
    for f in "$SHIM" "$GRUBEFI" "$GRUBLIB/cdboot.img" "$GRUBLIB/boot_hybrid.img"; do
        [ -f "$f" ] || { echo "signed boot chain file missing: $f"; exit 1; }
    done
    mcopy -i "$ESP" "$SHIM"    ::/EFI/BOOT/BOOTX64.EFI
    mcopy -i "$ESP" "$MOKM"    ::/EFI/BOOT/mmx64.efi
    mcopy -i "$ESP" "$GRUBEFI" ::/EFI/BOOT/grubx64.efi
    # Signed GRUB's embedded prefix is /EFI/ubuntu — hand off to the ISO cfg.
    cat > "$WORK/esp-grub.cfg" <<EOF
search --no-floppy --set=root --label $ISO_LABEL
set prefix=(\$root)/boot/grub
configfile \$prefix/grub.cfg
EOF
    mcopy -i "$ESP" "$WORK/esp-grub.cfg" ::/EFI/ubuntu/grub.cfg

    # ---- BIOS: our own grub-pc El Torito image (SB doesn't exist there) ----
    cat > "$WORK/bios-embed.cfg" <<EOF
search --no-floppy --set=root --label $ISO_LABEL
set prefix=(\$root)/boot/grub
configfile \$prefix/grub.cfg
EOF
    # `serial` + `terminal` are REQUIRED here, not optional: grub.cfg opens a
    # serial console for headless machines, and without these modules baked
    # into the BIOS core image those commands fail silently — the menu is
    # drawn on VGA only, so a headless BIOS box on a serial line sees nothing
    # and cannot pick "load OS to RAM". UEFI is unaffected because Canonical's
    # signed grubx64.efi already carries them.
    grub-mkimage -O i386-pc -d "$GRUBLIB" -p /boot/grub \
        -c "$WORK/bios-embed.cfg" -o "$WORK/core.img" \
        biosdisk iso9660 part_gpt part_msdos search search_label \
        normal configfile linux ls cat echo test gzio serial terminal
    cat "$GRUBLIB/cdboot.img" "$WORK/core.img" > "$ISOROOT/boot/grub/eltorito.img"
    mkdir -p "$ISOROOT/boot/grub/i386-pc"
    cp "$GRUBLIB"/*.mod "$GRUBLIB"/*.lst "$ISOROOT/boot/grub/i386-pc/" 2>/dev/null || true

    # ---- hybrid ISO --------------------------------------------------------
    # grub-mkrescue parity: -partition_offset 16 gives the ISO9660 region a
    # real partition-table entry on dd'd sticks — the persist hook's sgdisk
    # logic needs a sane GPT.
    xorriso -as mkisofs \
        -V "$ISO_LABEL" -iso-level 3 -full-iso9660-filenames \
        -rational-rock -joliet -joliet-long \
        -partition_offset 16 \
        --grub2-mbr "$GRUBLIB/boot_hybrid.img" \
        --mbr-force-bootable \
        -append_partition 2 0xEF "$ESP" \
        -appended_part_as_gpt \
        -eltorito-catalog boot/grub/boot.cat \
        -b boot/grub/eltorito.img -no-emul-boot -boot-load-size 4 \
        -boot-info-table --grub2-boot-info \
        -eltorito-alt-boot -e '--interval:appended_partition_2:all::' \
        -no-emul-boot \
        -o "$OUT" "$ISOROOT"
    (cd "$(dirname "$OUT")" && sha256sum "$(basename "$OUT")" > "$OUT.sha256")
    ls -lh "$OUT"
}

stage_smoke() {
    log "stage: QEMU smoke test"
    set_out
    ./test.sh boot-matrix "$OUT"
}

run_stage() {
    case "$1" in
        debootstrap) stage_debootstrap ;;
        chroot)      stage_chroot ;;
        binary)      stage_binary ;;
        squashfs)    stage_squashfs ;;
        iso)         stage_iso ;;
        smoke)       stage_smoke ;;
    esac
}

ALL_STAGES="debootstrap chroot binary squashfs iso"
[ "$SMOKE" = 1 ] && ALL_STAGES="$ALL_STAGES smoke"
case " $ALL_STAGES " in
    *" $FROM "*) ;;
    *) [ -z "$FROM" ] || { echo "unknown stage '$FROM' (valid: $ALL_STAGES)"; exit 1; } ;;
esac
started=0
for s in $ALL_STAGES; do
    if [ -z "$FROM" ] || [ "$s" = "$FROM" ]; then started=1; fi
    [ "$started" = 1 ] && run_stage "$s"
done
set_out
log "done: $(basename "$OUT")"
