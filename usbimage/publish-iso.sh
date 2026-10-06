#!/bin/bash
# Publish a built appliance image as a GitHub release on the appliance repo
# (macgaver/znas-usb-appliance), where the portal's "USB Appliance Upgrades"
# card looks for it.
#
# GitHub release assets are the right home for this: they do NOT count against
# the repository's size, and the limit is 2 GiB per file (the image is ~1.5 GB).
# The ISO must never be committed to a repo — git would keep every revision.
#
# What the portal needs on each release (asset names are the contract — the
# version is parsed from the ISO name, not from the tag):
#   znas-usb-appliance-v26-04-1-1.iso          the image
#   znas-usb-appliance-v26-04-1-1.iso.sha256   `sha256sum` line (zfsnas-upgrade-image checks it)
#   znas-usb-appliance-v26-04-1-1.iso.sig      cosign sign-blob signature, same key as the
#                                              portal binary — the portal REFUSES unsigned images
# Tag: v26.04.1-1. Drafts and pre-releases are ignored by the portal, so
# --prerelease is a safe way to stage an image for testing.
#
# Usage:  ./publish-iso.sh [--iso <file>] [--repo <owner/name>] [--notes <text>] [--prerelease]
# Default ISO: the highest-versioned znas-usb-appliance-v*.iso in this directory.
# Needs the GitHub CLI, authenticated (gh auth login) or GH_TOKEN in the env.
set -euo pipefail
cd "$(dirname "$0")"
. ./conf.sh

ISO=""
REPO="macgaver/znas-usb-appliance"
NOTES=""
PRERELEASE=()
while [ $# -gt 0 ]; do
    case "$1" in
        --iso)        ISO="$2";   shift 2 ;;
        --repo)       REPO="$2";  shift 2 ;;
        --notes)      NOTES="$2"; shift 2 ;;
        --prerelease) PRERELEASE=(--prerelease); shift ;;
        *) echo "unknown argument: $1"; exit 1 ;;
    esac
done

[ -n "$ISO" ] || ISO=$(newest_appliance_iso)
[ -n "$ISO" ] || { echo "no znas-usb-appliance-v*.iso here — run ./build.sh first"; exit 1; }
base=$(basename "$ISO")
[[ "$base" =~ ^znas-usb-appliance-v([0-9]+)-([0-9]+)-([0-9]+)-([0-9]+)\.iso$ ]] \
    || { echo "$base is not named znas-usb-appliance-vX-Y-Z-N.iso — the portal would not see it"; exit 1; }
VERSION="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}-${BASH_REMATCH[4]}"
UBUNTU="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
TAG="v${VERSION}"

[ -f "$ISO" ]         || { echo "missing $ISO"; exit 1; }
[ -f "$ISO.sha256" ]  || { echo "missing $ISO.sha256"; exit 1; }
[ -f "$ISO.sig" ]     || { echo "missing $ISO.sig — sign it first:  cosign sign-blob --key cosign.key --tlog-upload=false --output-signature $ISO.sig $ISO"; exit 1; }
command -v gh >/dev/null || { echo "gh (GitHub CLI) is not installed"; exit 1; }

# Verify before uploading: a corrupt 1.5 GB asset is expensive to discover later.
echo "Verifying checksum…"
(cd "$(dirname "$ISO")" && sha256sum -c "$base.sha256")

size=$(stat -c %s "$ISO")
if [ "$size" -gt $((2 * 1024 * 1024 * 1024)) ]; then
    echo "ISO is $((size / 1024 / 1024)) MB — over GitHub's 2 GiB per-asset limit."
    exit 1
fi

default_notes() {
    cat <<NOTES
ZNAS USB appliance image **${VERSION}**: Ubuntu ${UBUNTU} LTS with the ZNAS portal ${IMAGE_VERSION}${INCUS_VERSION:+ and Incus **${INCUS_VERSION}**}.

**Upgrading an appliance:** Platform → USB Appliance Upgrades. Your settings are kept.

**New stick:** flash \`${base}\` with balenaEtcher, Rufus (dd mode) or \`dd\`, then boot it and open the address shown on screen.
- USB stick: **8 GB minimum**, **32 GB or more on USB 3 (or faster) recommended**.
- Target machine: x86-64, 4 GB RAM or more (more with ZFS). UEFI with Secure Boot, or legacy BIOS.

Verify the download with the \`.sha256\`; the portal also checks the \`.sig\` signature before installing an upgrade.
NOTES
}

if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
    echo "Uploading to existing release $TAG (replacing any previous image)…"
    gh release upload "$TAG" "$ISO" "$ISO.sha256" "$ISO.sig" --repo "$REPO" --clobber
else
    echo "Creating release $TAG…"
    gh release create "$TAG" "$ISO" "$ISO.sha256" "$ISO.sig" --repo "$REPO" "${PRERELEASE[@]}" \
        --title "ZNAS Appliance ${VERSION}" \
        --notes "${NOTES:-$(default_notes)}"
fi

echo
echo "Download URL:"
echo "  https://github.com/$REPO/releases/download/$TAG/$base"
