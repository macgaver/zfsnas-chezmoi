# How to build the ZNAS USB appliance ISO

This folder turns Ubuntu 26.04 LTS plus the ZNAS portal binary into a bootable
USB image: `znas-usb-appliance-v26-04-1-1.iso`. The OS runs read-only from the
stick (loaded to RAM by default); settings live on a separate partition that
the image creates on first boot and keeps across upgrades.

Nothing here is tied to a particular network or machine. You need one Linux
build machine, about 30 minutes, and internet access.

---

## 1. What you need

| | Minimum | Notes |
|---|---|---|
| Build machine | x86-64, **Ubuntu 24.04 or newer** | Physical box, VM, or cloud instance. Builds run as **root** and mount/chroot a rootfs, so use a machine or VM you don't mind dedicating (not a container). |
| CPU / RAM / disk | 4 cores, 8 GB, **30 GB free** | The rootfs, squashfs and ISO take ~10 GB; 30 GB leaves room for a second build. |
| Network | `archive.ubuntu.com`, `dl.min.io` | Ubuntu packages, plus MinIO for the S3 feature (see *Troubleshooting* — MinIO stopped publishing binaries in 2026). |
| KVM (`/dev/kvm`) | only for the boot tests | In a VM this means **nested virtualization** must be on. Building works without it. |
| Go 1.22+ | only to build the portal from source | Any machine; the binary is copied over. |
| A USB stick | 8 GB minimum | 32 GB or more on USB 3 (or faster) recommended. Plus 4 GB RAM on the target machine (more with ZFS). |

The build does **not** create its build machine for you. Set one up once
(step 2); after that every build is a single command.

---

## 2. Set up the build machine (once)

Pick any way to get an Ubuntu 24.04+ x86-64 system. Examples:

**Incus / LXD VM**
```bash
incus launch images:ubuntu/24.04 znas-build --vm \
  -c limits.cpu=4 -c limits.memory=8GiB -c security.nesting=true -d root,size=40GiB
incus exec znas-build -- bash          # then continue inside
```

**Multipass**
```bash
multipass launch 24.04 --name znas-build --cpus 4 --memory 8G --disk 40G
multipass shell znas-build
```

**Existing Ubuntu machine**: just use it.

For boot tests inside a VM, enable nested virtualization on the host (for
example `options kvm_intel nested=1` / `kvm_amd nested=1`) and check that
`/dev/kvm` exists in the guest.

Then install the tools, as root:

```bash
apt-get update
apt-get install -y \
  debootstrap squashfs-tools xorriso gdisk dosfstools mtools \
  grub-pc-bin grub-efi-amd64-bin grub2-common \
  qemu-system-x86 ovmf qemu-utils curl ca-certificates shellcheck rsync socat parted \
  git
```

Ubuntu 24.04's `debootstrap` has no script named after 26.04 (`resolute`); it
falls back to its generic Ubuntu script, which works. Nothing to do.

---

## 3. Get the source and the portal binary

On the build machine:

```bash
git clone https://github.com/macgaver/zfsnas-chezmoi.git
cd zfsnas-chezmoi
```

`build.sh` bakes `../zfsnas` (the repository root) into the image by default.
Put a portal binary there, either way:

**Build it from source** (Go 1.22+, any machine; copy the result to the
repository root on the build machine):
```bash
VERSION=6.10.5                     # what the portal will report
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X zfsnas/internal/version.Version=${VERSION}" -o zfsnas .
./zfsnas --version
```

**Or use a published release**:
```bash
curl -fLo zfsnas https://github.com/macgaver/zfsnas-chezmoi/releases/latest/download/zfsnas-chezmoi
chmod +x zfsnas
```

---

## 4. Build

```bash
cd usbimage
sudo IMAGE_VERSION="$(../zfsnas --version)" APPLIANCE_BUILD=1 ./build.sh
```

The first build takes 15–30 minutes (most of it is downloading and upgrading
packages). The result lands in this folder:

```
znas-usb-appliance-v26-04-1-1.iso
znas-usb-appliance-v26-04-1-1.iso.sha256
```

### Stages

`debootstrap` → `chroot` → `binary` → `squashfs` → `iso` (→ `smoke` with `--test`)

Everything is kept in `./work/`, so you can resume from any stage:

| Command | Use it when |
|---|---|
| `./build.sh` | First build, or to start clean. |
| `./build.sh --from chroot` | To pick up Ubuntu updates or changes to `chroot-setup.sh` / `overlay/`. |
| `./build.sh --from binary --binary /path/to/zfsnas` | Only the portal changed (a few minutes, no package changes). |
| `./build.sh --test` | Build, then boot it in QEMU under UEFI + Secure Boot, UEFI and BIOS (needs `/dev/kvm`). |

`./work/` is safe to delete; the next build then starts from `debootstrap`.

### Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `APPLIANCE_BUILD` | `1` | The last digit of the version (`26.04.1-N`). Bump it to ship a new image on the same Ubuntu release; go back to 1 when Ubuntu moves. |
| `UBUNTU_VERSION` | unset | If set (e.g. `26.04.1`), the build fails unless the rootfs really is that Ubuntu point release. Official builds set it. |
| `INCUS_VERSION` | unset | If set (e.g. `7.5.1`), Incus is installed at exactly that version from the Incus project's own packages (Zabbly, `stable`) instead of Ubuntu's archive (frozen at 6.0.5 on 26.04). `remote-build.sh` defaults it to `APPLIANCE_INCUS_VERSION` from the workflow. Only ever move it forward: Incus upgrades its database on first start and an older Incus cannot read it back. |
| `IMAGE_VERSION` | see `conf.sh` | The portal version you are baking in; only used for labels and a mismatch warning. |
| `WORK` | `./work` | Where the rootfs and intermediate files live. |
| `ZNAS_MINIO_CACHE` | unset | A folder holding `minio` and `mc` to seed a fresh rootfs with (MinIO no longer publishes them). |
| `ZNAS_ALLOW_NO_MINIO` | `0` | `1` = build without MinIO when it cannot be downloaded (the image then has no S3 feature). |

**Where the version comes from**: the Ubuntu part is read from the built
rootfs (`/etc/os-release`), so it follows whatever point release the Ubuntu
archive serves that day. You cannot build an older point release; the archive
only has the current one.

`conf.sh` holds the rest: the Ubuntu codename (`resolute` = 26.04), the
mirror, and the partition labels.

### Building from your workstation instead

If the build machine is a separate box or VM, `remote-build.sh` does the
whole round trip from your checkout. It builds the portal with Go, pushes this
folder and the binary over SSH, runs `build.sh` there, and copies the checked
ISO back:

```bash
cp local.conf.example local.conf     # once: describe your build machine
./remote-build.sh --build 1          # → znas-usb-appliance-v26-04-1-1.iso here
./remote-build.sh --build 2 --from binary   # portal-only rebuild, a few minutes
```

`local.conf` is git-ignored because it names your own machines. It supports a
plain SSH build machine or an Incus VM behind an SSH host (`BUILD_INCUS_VM`).
Your SSH user needs passwordless `sudo` there.

---

## 5. Test (optional, needs KVM)

```bash
sudo ./test.sh boot-matrix   # UEFI+Secure Boot, UEFI and BIOS boots; the portal must answer
sudo ./test.sh firstboot     # first boot creates and seeds the settings partition
sudo ./test.sh reflash       # writing a new image over the stick keeps the settings
sudo ./test.sh overlap       # a bigger image that would overlap the settings is handled
sudo ./test.sh degraded      # a stick with no free space still boots (no persistence)
sudo ./test.sh wear          # 30 min idle: how much the appliance writes to the stick
sudo ./test.sh manual        # opens a QEMU window (needs a desktop) to click through by hand
```

Each scenario uses a throw-away 8 GB stick image in `./work/`. Unit tests for
the scripts, no KVM needed, are in `tests/`: `bash tests/launcher_test.sh`
(no root) and `sudo bash tests/hook_test.sh`.

---

## 6. Flash and boot

Write the ISO to the whole stick, not to a partition:

```bash
sudo dd if=znas-usb-appliance-v26-04-1-1.iso of=/dev/sdX bs=4M conv=fsync status=progress
```

Etcher and Rufus (in **dd mode**) work too. Boot the target machine from the
stick and let the default **"load OS to RAM"** entry start. The console then
prints the portal address. Open it in a browser and create the first admin at
`/setup`. SSH stays locked until you set a root password or key in the portal.

---

## 7. Upgrades, signing and publishing

Appliances upgrade themselves from **Platform → USB Appliance Upgrades**. The
portal looks for releases on `github.com/macgaver/znas-usb-appliance` and
**installs only images signed with the project's key**. Its public key is
built into the portal, in `internal/updater/pubkey.go`.

- **Your own builds**: flash them directly (step 6). An appliance will not
  offer them as an in-place upgrade, because they are not signed with the
  project key. That is the point of the signature.
- **Testing in-place upgrades with your own images**: change the key in
  `internal/updater/pubkey.go` and the repository in
  `internal/updater/appliance.go` (`applianceReleasesAPI`) to your own, build
  that portal into both images, then sign your ISOs with your key
  (`cosign sign-blob --key your.key --tlog-upload=false --output-signature X.iso.sig X.iso`)
  and publish them with `./publish-iso.sh --repo you/your-repo`.
- **Official images** are built by `.github/workflows/appliance-image.yml`.
  Maintainers change `APPLIANCE_UBUNTU_VERSION` / `APPLIANCE_BUILD` /
  `APPLIANCE_INCUS_VERSION` at the top of that file and push; the workflow
  builds, boot-tests, signs and publishes. A new `APPLIANCE_INCUS_VERSION`
  alone is enough: the workflow compares it with the Incus version recorded in
  the newest release's notes and builds the next free build number.

Each release carries three assets whose **names must not change**: the portal
reads the version from the ISO's file name.

```
znas-usb-appliance-v26-04-1-1.iso
znas-usb-appliance-v26-04-1-1.iso.sha256
znas-usb-appliance-v26-04-1-1.iso.sig
```

---

## 8. Troubleshooting

**`ERROR: could not download https://dl.min.io/...`**
MinIO archived its open-source server and client in 2026, and `dl.min.io` now
answers *410 Gone*. A rootfs that already has the binaries keeps them (with a
warning); a fresh one cannot get them. Build with `ZNAS_ALLOW_NO_MINIO=1` to
produce an image without the S3 feature.

**`the rootfs is Ubuntu 26.04.2 but UBUNTU_VERSION declares 26.04.1`**
Ubuntu shipped a new point release. Update `UBUNTU_VERSION` (or
`APPLIANCE_UBUNTU_VERSION` in the workflow), and reset `APPLIANCE_BUILD` to 1.

**`codename 'resolute' not on mirror`**
Wrong codename or mirror in `conf.sh`, or no network.

**`WARNING: version mismatch`** after the `binary` stage
The binary reports a different version than `IMAGE_VERSION`. Harmless, but
set `IMAGE_VERSION` to the binary's version so labels and banners are right.

**Boot tests fail immediately / `Could not access KVM kernel module`**
No `/dev/kvm`. Enable nested virtualization for the build VM, or skip `--test`.

**A build was interrupted**
Re-run from the stage that failed (`./build.sh --from chroot`, for example).
The chroot stage unmounts its `proc/sys/dev` binds on exit, and a full build
clears leftovers before it deletes the old rootfs. After a hard kill, check
`mount | grep work/rootfs` and unmount anything listed before rebuilding.

**Out of disk space**
Delete `./work/` and old ISOs. A build needs about 10 GB free.

## Realtek NICs

The in-kernel `r8169` driver (with `linux-firmware-realtek`) handles every
Realtek Ethernet chip and is always the default. The image also carries
Realtek's own `r8168` (RTL8111/8168) and `r8125` (RTL8125 2.5G) drivers, built
against the image kernel, for older RTL8111 revisions whose link drops or never
comes up under `r8169`. They are blacklisted and only used on request:

- once: boot **"ZNAS System - load OS to RAM, Realtek vendor NIC driver"** (last GRUB entry);
- always: `touch /persist/.zfsnas-persist/realtek-vendor` and reboot (remove it to go back).

They need Secure Boot off (or legacy BIOS): they are signed with a key made at
build time that no firmware trusts. `r8169` is always reloaded afterwards for
any chip the vendor drivers did not claim. Logic: `overlay/usr/lib/zfsnas/realtek-vendor.sh`.
