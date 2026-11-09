#!/usr/bin/python3 -I
"""Disks the appliance OS can be moved to (PLANS/plan-appliance-internal-disk.md).

  disk-targets.py              JSON: machine facts + every disk with its eligibility
  disk-targets.py --check NAME exit 0 if NAME may be erased now, else print why, exit 1

The installer re-runs --check right before it erases anything: the web page's
list alone is never trusted.
"""
import json
import os
import re
import subprocess
import sys

MIN_BYTES = 32 * 1000 ** 3          # "32 GB" as disks are sold
ISO_LABEL = "ZFSNAS-USB"
BYID = "/dev/disk/by-id"


def run(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def parent_disk(dev):
    """/dev/sdc1 -> sdc, /dev/nvme0n1p4 -> nvme0n1, sdc -> sdc."""
    name = os.path.basename(os.path.realpath(dev))
    link = os.path.realpath(f"/sys/class/block/{name}")
    if os.path.exists(os.path.join(link, "partition")):
        return os.path.basename(os.path.dirname(link))
    return name


def disk_id(name):
    """Same rule as the boot hook's zp_disk_id: first by-id name, sorted,
    skipping partitions and the wwn/eui aliases."""
    target = os.path.realpath(f"/dev/{name}")
    try:
        entries = sorted(os.listdir(BYID))
    except OSError:
        return ""
    for e in entries:
        if "-part" in e or e.startswith(("wwn-", "nvme-eui.", "nvme-nvme.")):
            continue
        if os.path.realpath(os.path.join(BYID, e)) == target:
            return e
    return ""


def nvme_formats(name):
    """[(index, data_bytes, metadata_bytes, in_use)] of an NVMe namespace."""
    out = run("nvme", "id-ns", "-H", f"/dev/{name}")
    fmts = []
    for m in re.finditer(r"LBA Format\s+(\d+)\s*:\s*Metadata Size:\s*(\d+)\s*bytes\s*-\s*Data Size:\s*(\d+)\s*bytes.*?(\(in use\))?\s*$", out, re.M):
        fmts.append((int(m.group(1)), int(m.group(3)), int(m.group(2)), bool(m.group(4))))
    return fmts


def nvme_512_index(name):
    for idx, data, meta, _ in nvme_formats(name):
        if data == 512 and meta == 0:
            return idx
    return None


def nvme_format_all_namespaces(name):
    """True when a format on this controller erases every namespace (FNA bit 0)."""
    ctrl = re.sub(r"n\d+$", "", name)
    out = run("nvme", "id-ctrl", "-H", f"/dev/{ctrl}")
    m = re.search(r"\[0:0\]\s*:\s*0x1\s*Format Applies to All", out)
    return bool(m)


def facts():
    persist = run("findmnt", "-n", "-o", "SOURCE", "/persist").strip()
    system = parent_disk(persist) if persist.startswith("/dev/") else ""
    layout = os.path.exists("/persist/.zfsnas-persist/disk-layout.conf")
    image_disks = set()
    for line in run("blkid", "-o", "device", "-t", f"LABEL={ISO_LABEL}").split():
        image_disks.add(parent_disk(line))
    pools = {}
    cur = ""
    for line in run("zpool", "status", "-P").splitlines():
        m = re.match(r"\s*pool:\s*(\S+)", line)
        if m:
            cur = m.group(1)
            continue
        m = re.match(r"\s+(/dev/\S+)", line)
        if m and cur:
            pools.setdefault(parent_disk(m.group(1)), set()).add(cur)
    mounts = {}
    with open("/proc/mounts") as f:
        for line in f:
            src, mnt = line.split()[:2]
            if src.startswith("/dev/"):
                mounts.setdefault(parent_disk(src), []).append(mnt)
    with open("/proc/swaps") as f:
        for line in list(f)[1:]:
            src = line.split()[0]
            if src.startswith("/dev/"):
                mounts.setdefault(parent_disk(src), []).append("swap")
    cmdline = open("/proc/cmdline").read().split()
    return {
        "uefi": os.path.isdir("/sys/firmware/efi"),
        "toram": "toram" in cmdline,
        "system_disk": system,
        "system_medium": "disk" if layout else ("stick" if system else ""),
        "image_disks": sorted(image_disks),
        "_pools": pools,
        "_mounts": mounts,
    }


def describe(dev, f):
    name = dev["name"]
    size = int(dev.get("size") or 0)
    tran = (dev.get("tran") or "").lower()
    lsec = int(dev.get("log-sec") or 512)
    contents = []
    exported = []
    for ch in dev.get("children") or []:
        what = ch.get("fstype") or "partition"
        if ch.get("label"):
            what += f" “{ch['label']}”"
        if ch.get("fstype") == "zfs_member" and ch.get("label"):
            exported.append(ch["label"])
        contents.append(f"{ch['name']}: {what}")
    if not dev.get("children") and dev.get("fstype"):
        contents.append(dev["fstype"])
    t = {
        "name": name, "path": f"/dev/{name}", "size": size,
        "model": (dev.get("model") or "").strip(), "serial": (dev.get("serial") or "").strip(),
        "tran": tran, "rotational": bool(dev.get("rota")), "logical_sector": lsec,
        "by_id": disk_id(name), "contents": contents, "notes": [],
        "eligible": True, "reason": "", "nvme_format": None,
    }

    def no(reason):
        if t["eligible"]:
            t["eligible"], t["reason"] = False, reason

    if name == f["system_disk"]:
        no("the disk ZNAS runs from")
    elif name in f["image_disks"]:
        # Refused only while it holds ZNAS settings (a working stick). An
        # unfinished install (image, no settings) or a retired stick can be
        # reused — otherwise a failed move could never be retried.
        labels = {(ch.get("label") or "") for ch in dev.get("children") or []}
        if "ZFSNAS-PERSIST" in labels:
            no("a ZNAS USB stick with its own settings")
        elif "ZFSNAS-MOVED" in labels:
            t["notes"].append("an old ZNAS stick whose settings were moved")
        else:
            t["notes"].append("holds an unfinished ZNAS install")
    if name in f["_pools"]:
        no("in pool " + ", ".join(sorted(f["_pools"][name])))
    if name in f["_mounts"]:
        no("in use (" + ", ".join(sorted(set(f["_mounts"][name]))[:3]) + ")")
    for ch in dev.get("children") or []:
        if ch.get("fstype") in ("linux_raid_member", "LVM2_member"):
            no("part of a RAID or LVM volume")
    if tran == "usb":
        t["notes"].append("USB disk: works, but an internal disk is more reliable")
    if size < MIN_BYTES:
        no("too small (needs 32 GB or more)")
    if tran == "nvme" and not f["uefi"]:
        no("this machine started in legacy BIOS mode, which usually can't start from NVMe: switch the firmware to UEFI first")
    if lsec != 512:
        if tran == "nvme" and name.startswith("nvme"):
            idx = nvme_512_index(name)
            if idx is None:
                no("this NVMe drive only supports 4K sectors")
            else:
                t["nvme_format"] = idx
                t["notes"].append("will be switched to 512-byte sectors")
                if nvme_format_all_namespaces(name):
                    others = [n for n in os.listdir("/sys/block")
                              if n != name and n.startswith(re.sub(r"n\d+$", "", name) + "n")]
                    if others:
                        no("switching its sector size would also erase " + ", ".join(sorted(others)))
        else:
            no("4K-sector disks are not supported")
    exported = [p for p in exported if p not in f["_pools"].get(name, set())]
    if exported:
        t["notes"].append("holds an exported pool: " + ", ".join(sorted(set(exported))))
    return t


def targets():
    f = facts()
    data = json.loads(run("lsblk", "-J", "-b", "-o",
                          "NAME,SIZE,TYPE,TRAN,MODEL,SERIAL,ROTA,LOG-SEC,FSTYPE,LABEL") or '{"blockdevices":[]}')
    out = []
    for dev in data.get("blockdevices", []):
        if dev.get("type") != "disk" or dev["name"].startswith(("zd", "nbd", "ram", "loop", "zram")):
            continue
        out.append(describe(dev, f))
    pub = {k: v for k, v in f.items() if not k.startswith("_")}
    pub["targets"] = out
    return pub


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        name = os.path.basename(sys.argv[2])
        for t in targets()["targets"]:
            if t["name"] == name:
                if t["eligible"]:
                    print(json.dumps(t))
                    return 0
                print(t["reason"])
                return 1
        print(f"no such disk: {name}")
        return 1
    json.dump(targets(), sys.stdout)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
