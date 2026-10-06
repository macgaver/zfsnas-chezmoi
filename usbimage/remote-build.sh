#!/bin/bash
# remote-build.sh — build the appliance ISO on a separate build machine and
# copy the result back here, in one command. Machine details come from
# local.conf (git-ignored; start from local.conf.example).
#
# Steps: build the portal binary from this checkout (Go) → push this usbimage/
# tree and the binary to the build machine → run build.sh there → check the
# ISO's checksum there → copy .iso + .sha256 back → check it again here →
# delete it on the build machine.
#
# Usage:
#   ./remote-build.sh --build N [--from STAGE] [--binary FILE] [--test]
#
#   --build N      appliance build number: 26.04.1-N (required, so a rebuild
#                  never silently reuses a published number)
#   --from STAGE   resume there: debootstrap chroot binary squashfs iso
#                  (default: chroot — fresh Ubuntu packages, reuses debootstrap)
#   --binary FILE  bake this portal binary instead of building one from source
#   --test         run the QEMU boot matrix after the build (needs KVM there)
#
# Building directly on the build machine needs none of this: ./build.sh.
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
REPO_ROOT="$(cd .. && pwd)"

[ -f local.conf ] || { echo "no local.conf — copy local.conf.example to local.conf and fill it in"; exit 1; }
# shellcheck source=local.conf.example
. ./local.conf
: "${BUILD_SSH:?set BUILD_SSH in local.conf}" "${BUILD_DIR:?}" "${BUILD_BINARY:?}"
LOCAL_ISO_DIR="${LOCAL_ISO_DIR:-$HERE}"

BUILD_NO="" FROM="chroot" BINARY="" TEST=""
while [ $# -gt 0 ]; do
    case "$1" in
        --build)  BUILD_NO="$2"; shift 2 ;;
        --from)   FROM="$2";     shift 2 ;;
        --binary) BINARY="$2";   shift 2 ;;
        --test)   TEST="--test"; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1"; exit 1 ;;
    esac
done
[[ "$BUILD_NO" =~ ^[1-9][0-9]*$ ]] || { echo "--build N is required (the last digit of 26.04.1-N)"; exit 1; }

note() { echo -e "\n==> $*"; }
SSH=(ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=10 "$BUILD_SSH")

# remote CMD — run a bash command as root on the build machine (inside the
# Incus VM when BUILD_INCUS_VM is set).
remote() {
    local q; q=$(printf '%q' "$1")
    if [ -n "${BUILD_INCUS_VM:-}" ]; then
        "${SSH[@]}" "sudo incus exec $BUILD_INCUS_VM -- bash -c $q"
    else
        "${SSH[@]}" "sudo bash -c $q"
    fi
}
# push LOCAL REMOTE / pull REMOTE LOCAL — via /tmp on the SSH host.
push() {
    local tmp; tmp="/tmp/znas-rb-$$-$(basename "$2")"
    scp -q "$1" "$BUILD_SSH:$tmp"
    if [ -n "${BUILD_INCUS_VM:-}" ]; then
        "${SSH[@]}" "sudo incus file push '$tmp' '$BUILD_INCUS_VM$2' >/dev/null && rm -f '$tmp'"
    else
        "${SSH[@]}" "sudo install -m 0644 '$tmp' '$2' && rm -f '$tmp'"
    fi
}
pull() {
    local tmp; tmp="/tmp/znas-rb-$$-$(basename "$1")"
    if [ -n "${BUILD_INCUS_VM:-}" ]; then
        "${SSH[@]}" "sudo incus file pull '$BUILD_INCUS_VM$1' '$tmp' >/dev/null && sudo chown \$(id -u) '$tmp'"
    else
        "${SSH[@]}" "sudo cp '$1' '$tmp' && sudo chown \$(id -u) '$tmp'"
    fi
    scp -q "$BUILD_SSH:$tmp" "$2"
    "${SSH[@]}" "rm -f '$tmp'"
}

# Incus version: the one the CI workflow declares, unless local.conf or the
# environment says otherwise (INCUS_VERSION="" there = Ubuntu's own package).
WF="$REPO_ROOT/.github/workflows/appliance-image.yml"
INCUS_VERSION="${INCUS_VERSION-$(sed -n 's/^  APPLIANCE_INCUS_VERSION: "\(.*\)"/\1/p' "$WF")}"

WORKTMP=$(mktemp -d)
trap 'rm -rf "$WORKTMP"' EXIT

# ---- 1. portal binary ------------------------------------------------------
if [ -n "$BINARY" ]; then
    cp "$BINARY" "$WORKTMP/zfsnas"
else
    PORTAL_VERSION=$(sed -n 's/^var Version = "\(.*\)"/\1/p' "$REPO_ROOT/internal/version/version.go")
    note "building portal $PORTAL_VERSION from $REPO_ROOT"
    (cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
        -ldflags "-s -w -X zfsnas/internal/version.Version=$PORTAL_VERSION" -o "$WORKTMP/zfsnas" .)
fi
chmod 755 "$WORKTMP/zfsnas"
PORTAL_VERSION=$("$WORKTMP/zfsnas" --version)
note "portal binary: $PORTAL_VERSION ($(sha256sum "$WORKTMP/zfsnas" | cut -c1-16))"

# ---- 2. push the tree and the binary ----------------------------------------
note "pushing usbimage/ and the binary to ${BUILD_INCUS_VM:+$BUILD_INCUS_VM on }$BUILD_SSH:$BUILD_DIR"
tar -C "$HERE" --exclude=./work --exclude=./local.conf --exclude='*.iso' \
    --exclude='*.iso.sha256' --exclude='*.iso.sig' --exclude='*.log' -czf "$WORKTMP/tree.tgz" .
push "$WORKTMP/tree.tgz" /tmp/znas-usbimage.tgz
push "$WORKTMP/zfsnas" "$BUILD_BINARY"
# --no-same-owner: files land root-owned, whatever uid they have here.
remote "set -e; mkdir -p '$BUILD_DIR'; tar -C '$BUILD_DIR' --no-same-owner -xzf /tmp/znas-usbimage.tgz; rm -f /tmp/znas-usbimage.tgz; chmod 755 '$BUILD_BINARY' '$BUILD_DIR'/*.sh"

# ---- 3. build --------------------------------------------------------------
LOG="build-remote-$(date +%Y%m%d-%H%M%S).log"
note "building (from stage '$FROM', appliance build $BUILD_NO, Incus ${INCUS_VERSION:-from the Ubuntu archive}) — log: $BUILD_DIR/$LOG"
if ! remote "cd '$BUILD_DIR' && UBUNTU_VERSION='${UBUNTU_VERSION:-}' APPLIANCE_BUILD='$BUILD_NO' \
        IMAGE_VERSION='$PORTAL_VERSION' ZNAS_ALLOW_NO_MINIO='${ZNAS_ALLOW_NO_MINIO:-0}' \
        INCUS_VERSION='$INCUS_VERSION' \
        ${BUILD_WORK:+WORK='$BUILD_WORK'} ${ZNAS_MINIO_CACHE:+ZNAS_MINIO_CACHE='$ZNAS_MINIO_CACHE'} \
        ./build.sh --binary '$BUILD_BINARY' --from '$FROM' $TEST > '$LOG' 2>&1"; then
    echo; echo "BUILD FAILED — last lines of $LOG:"
    remote "tail -n 30 '$BUILD_DIR/$LOG'"
    exit 1
fi
remote "grep -E '^=== |WARNING' '$BUILD_DIR/$LOG'" || true

# ---- 4. verify there, copy back, verify here --------------------------------
ISO=$(remote "cd '$BUILD_DIR' && ls -1v znas-usb-appliance-v*-$BUILD_NO.iso | tail -n1")
[ -n "$ISO" ] || { echo "no ISO for build $BUILD_NO found in $BUILD_DIR"; exit 1; }
note "verifying $ISO on the build machine"
remote "cd '$BUILD_DIR' && sha256sum -c '$ISO.sha256'"
note "copying $ISO to $LOCAL_ISO_DIR"
mkdir -p "$LOCAL_ISO_DIR"
rm -f "$LOCAL_ISO_DIR/$ISO.sig"          # a signature of an older build is now wrong
pull "$BUILD_DIR/$ISO.sha256" "$LOCAL_ISO_DIR/$ISO.sha256"
pull "$BUILD_DIR/$ISO" "$LOCAL_ISO_DIR/$ISO"
(cd "$LOCAL_ISO_DIR" && sha256sum -c "$ISO.sha256")
# The copy here is verified: don't let images pile up on the build machine.
remote "rm -f '$BUILD_DIR/$ISO' '$BUILD_DIR/$ISO.sha256'"

note "done: $LOCAL_ISO_DIR/$ISO (portal $PORTAL_VERSION)"
