// Where the appliance runs from: its USB stick or an internal disk it was
// moved to (PLANS/plan-appliance-internal-disk.md).
package system

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Paths are vars so tests can point them into a temp dir.
var (
	procMountsPath       = "/proc/mounts"
	sysClassBlockPath    = "/sys/class/block"
	persistMovedToPath   = "/var/lib/zfsnas/persist-moved-to"
	bootedFromPath       = "/run/zfsnas-install/booted-from" // zfsnas-disk-heal.service
	diskLayoutPath       = "/persist/.zfsnas-persist/disk-layout.conf"
	applianceImageLabels = []string{"ZFSNAS-USB"}
	applianceBlkid       = func(args ...string) (string, error) {
		out, err := exec.Command("blkid", args...).Output()
		return string(out), err
	}
)

// ApplianceMedium describes the disk holding the settings store in use.
type ApplianceMedium struct {
	Kind          string `json:"kind"` // "stick" | "disk" | "" (no store: degraded/moved)
	Disk          string `json:"disk,omitempty"`
	Model         string `json:"model,omitempty"`
	SizeBytes     int64  `json:"size_bytes,omitempty"`
	Transport     string `json:"transport,omitempty"` // usb | nvme | sata
	PoolName      string `json:"pool_name,omitempty"` // internal disk: the pool created with it
	PersistStatus string `json:"persist_status"`
	MovedTo       string `json:"moved_to,omitempty"` // this stick's settings were moved
	// OtherImageDisk: another disk carries the appliance image (the old
	// stick still plugged in after a move).
	OtherImageDisk string `json:"other_image_disk,omitempty"`
	UEFI           bool   `json:"uefi"`
	// BootedFromOther: an internal-disk install that the firmware started
	// from another disk's boot partition (the old stick first in the boot
	// order) — upgrades written to the internal disk wouldn't take effect.
	BootedFromOther bool `json:"booted_from_other"`
}

// mountSource returns the device mounted at mnt, from /proc/mounts.
func mountSource(mountsPath, mnt string) string {
	f, err := os.Open(mountsPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) >= 2 && fs[1] == mnt {
			return fs[0]
		}
	}
	return ""
}

// blockParentDisk maps a partition name to its disk ("nvme0n1p4" ->
// "nvme0n1"); a whole disk maps to itself.
func blockParentDisk(sysClassBlock, name string) string {
	real, err := filepath.EvalSymlinks(filepath.Join(sysClassBlock, name))
	if err != nil {
		return ""
	}
	if _, err := os.Stat(filepath.Join(real, "partition")); err != nil {
		return name
	}
	return filepath.Base(filepath.Dir(real))
}

func diskTransport(sysClassBlock, disk string) string {
	real, _ := filepath.EvalSymlinks(filepath.Join(sysClassBlock, disk))
	switch {
	case strings.Contains(real, "/usb"):
		return "usb"
	case strings.HasPrefix(disk, "nvme"):
		return "nvme"
	}
	return "sata"
}

// readDiskLayoutPool returns POOL_NAME from disk-layout.conf, "" if none.
func readDiskLayoutPool(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "POOL_NAME="); ok {
			return v, true
		}
	}
	return "", true
}

// ApplianceMediumInfo reports what ZNAS runs from right now.
func ApplianceMediumInfo() ApplianceMedium {
	m := ApplianceMedium{PersistStatus: PersistStatus(), UEFI: dirExists("/sys/firmware/efi")}
	if b, err := os.ReadFile(persistMovedToPath); err == nil {
		m.MovedTo = strings.TrimSpace(string(b))
	}
	src := mountSource(procMountsPath, "/persist")
	if strings.HasPrefix(src, "/dev/") {
		m.Disk = blockParentDisk(sysClassBlockPath, filepath.Base(src))
	}
	if m.Disk != "" {
		m.Kind = "stick"
		if pool, ok := readDiskLayoutPool(diskLayoutPath); ok {
			m.Kind, m.PoolName = "disk", pool
			m.BootedFromOther = readFileTrim(bootedFromPath) == "other"
		}
		m.Model = strings.TrimSpace(readFileTrim(filepath.Join("/sys/block", m.Disk, "device/model")))
		if n, err := strconv.ParseInt(readFileTrim(filepath.Join("/sys/block", m.Disk, "size")), 10, 64); err == nil {
			m.SizeBytes = n * 512
		}
		m.Transport = diskTransport(sysClassBlockPath, m.Disk)
	}
	// blkid, not /dev/disk/by-label: udev keeps ONE link per label, and the
	// stick and the disk carry the same one.
	for _, label := range applianceImageLabels {
		out, _ := applianceBlkid("-o", "device", "-t", "LABEL="+label)
		for _, dev := range strings.Fields(out) {
			if d := blockParentDisk(sysClassBlockPath, filepath.Base(dev)); d != "" && d != m.Disk {
				m.OtherImageDisk = d
			}
		}
	}
	return m
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// SetApplianceModeForTest forces ApplianceMode for another package's tests
// and returns the function restoring it.
func SetApplianceModeForTest(v bool) func() {
	applianceOnce.Do(func() {})
	old := applianceCached
	applianceCached = v
	return func() { applianceCached = old }
}
