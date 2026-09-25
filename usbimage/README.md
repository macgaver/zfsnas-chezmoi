# ZFS NAS Portal — USB appliance image build

Builds `znas-usb-appliance-v<x-y-z>-<build>.iso`: Ubuntu 26.04 live (casper) +
zfsnas as root + selective persistence.

**New here? Start with [HOW-TO-BUILD-ISO.md](HOW-TO-BUILD-ISO.md)** — it takes you from
an empty machine to a bootable stick. From a workstation with a separate build
machine, `./remote-build.sh --build N` does the round trip (set up `local.conf`
from `local.conf.example` first).

## Build VM (once)

Any Ubuntu 24.04+ x86-64 machine or VM with ≥4 CPU / 8 GB RAM / 30 GB disk
(details and alternatives in HOW-TO-BUILD-ISO.md). With Incus, for example:

```
incus launch images:ubuntu/24.04 znas-usbbuild --vm \
  -c limits.cpu=4 -c limits.memory=8GiB -d root,size=30GiB
incus exec znas-usbbuild -- apt-get update
incus exec znas-usbbuild -- apt-get install -y \
  debootstrap squashfs-tools xorriso gdisk dosfstools mtools \
  grub-pc-bin grub-efi-amd64-bin grub2-common \
  qemu-system-x86 ovmf qemu-utils curl ca-certificates shellcheck rsync socat parted
```

Copy the `usbimage/` tree and the release `zfsnas` binary into the VM
(`incus file push -r`), then inside the VM, as root:

```
./build.sh --binary /root/zfsnas          # full build
./build.sh --from squashfs                # resume from a stage
./build.sh --binary /root/zfsnas --test   # build + QEMU smoke test
./test.sh boot-matrix                     # full scenario runner (see test.sh)
```

Stages: `debootstrap` → `chroot` → `binary` → `squashfs` → `iso` → (`smoke`).
Work dir: `./work/` (safe to delete; `--from` needs earlier stages present).

## Outputs

`znas-usb-appliance-v26-04-1-1.iso` + `.sha256` in `usbimage/`. Flash with dd /
Etcher / Rufus (dd mode). Secure Boot: supported (Canonical shim chain).
Minimums: 8 GB stick (32 GB+ on USB 3 or faster recommended), 4 GB RAM (more for toram + ZFS).

## Versioning

The image is versioned `<Ubuntu point release>-<build>`, e.g. `26.04.1-1`:

- the Ubuntu part comes from the built rootfs's `/etc/os-release` (26.04 →
  `26.04.0`), so a rebuild after Ubuntu ships 26.04.2 is automatically `26.04.2-N`;
- `APPLIANCE_BUILD` (conf.sh, or the env) is ours: bump it to ship a new image
  while Ubuntu has no new point release, reset it to 1 when Ubuntu moves.

`build.sh` stamps it as `appliance_version=` in `/etc/zfsnas-release` (next to
`version=`, the baked portal binary) and names the ISO
`znas-usb-appliance-v26-04-1-1.iso`. The portal parses the version back out
of that exact name, so do not rename published files.

## Publishing the image

Images are published on **github.com/macgaver/znas-usb-appliance**, where the
portal's Platform → USB Appliance Upgrades card looks for them. Each release
carries three assets: the `.iso`, its `.sha256`, and a cosign `.sig` made with
the same key as the portal binary. **The portal refuses an image without a
valid signature.** Drafts and pre-releases are ignored by the portal.

**To ship an image, edit `APPLIANCE_UBUNTU_VERSION` and/or `APPLIANCE_BUILD`
at the top of `.github/workflows/appliance-image.yml` and push.** The workflow
builds only when release `v<ubuntu>-<build>` does not exist yet on the
appliance repo, then boot-tests, signs and publishes it. The build fails if the
Ubuntu mirror delivers a different point release than the one declared.

By hand:

```
cosign sign-blob --key cosign.key --tlog-upload=false \
  --output-signature znas-usb-appliance-v26-04-1-1.iso.sig znas-usb-appliance-v26-04-1-1.iso
./publish-iso.sh                    # newest ISO here -> release v26.04.1-1
./publish-iso.sh --prerelease       # stage it without appliances seeing it
```

The ISO must never be committed to a repo; release assets do not count
against repository size (2 GiB per-file limit).

## In-place upgrade on a running appliance

`/usr/local/sbin/zfsnas-upgrade-image` rewrites only the image region of the
stick; the settings partition is re-adopted on the next boot. It refuses
unless the appliance booted "load OS to RAM" (the default entry). The portal
drives it: download to the persist store → cosign verify → the script runs in
a transient `zfsnas-image-upgrade` unit (so a portal restart cannot kill a
half-finished write) → reboot. Reboot/shutdown from the portal are blocked
while the write runs.
