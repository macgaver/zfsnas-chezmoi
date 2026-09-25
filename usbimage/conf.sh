# usbimage/conf.sh — build configuration. Sourced by build.sh and test.sh.
# shellcheck shell=bash
# shellcheck disable=SC2034  # every var here is consumed by the sourcing script
UBUNTU_CODENAME="resolute"          # Ubuntu 26.04 LTS. Stage 1 verifies this
                                    # exists on the mirror and aborts if not.
MIRROR="http://archive.ubuntu.com/ubuntu"
IMAGE_VERSION="${IMAGE_VERSION:-6.9.25}"  # portal binary baked into the image
# Appliance image version = <Ubuntu point release>-<APPLIANCE_BUILD>, e.g.
# 26.04.1-1. The Ubuntu part is read from the built rootfs (base-files bumps
# /etc/os-release at each point release); APPLIANCE_BUILD is ours: bump it to
# ship a new image while Ubuntu has no new point release, reset it to 1 when
# Ubuntu moves (26.04.1-3 -> 26.04.2-1). Official images are driven from
# .github/workflows/appliance-image.yml, which passes APPLIANCE_BUILD and
# UBUNTU_VERSION (checked against the built rootfs) in the env.
APPLIANCE_BUILD="${APPLIANCE_BUILD:-1}"
ISO_LABEL="ZFSNAS-USB"              # ISO9660 volume label; GRUB + hook search it
PERSIST_LABEL="ZFSNAS-PERSIST"      # ext4 label of the persist partition

# appliance_iso_name 26.04.1-1  ->  znas-usb-appliance-v26-04-1-1.iso
# The portal parses exactly this shape back out of the GitHub asset name.
appliance_iso_name() { local v="${1//./-}"; echo "znas-usb-appliance-v${v}.iso"; }

# newest_appliance_iso: the highest-versioned image in the current directory.
newest_appliance_iso() { ls -1v znas-usb-appliance-v*.iso 2>/dev/null | tail -n1; }
