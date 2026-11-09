package system

import (
	"os"
	"path/filepath"
	"testing"
)

// A fake sysfs: nvme0n1 with partition nvme0n1p4, sda (a USB stick) with sda1.
func fakeBlockTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	devs := filepath.Join(root, "devices")
	mk := func(rel string, part bool) {
		d := filepath.Join(devs, rel)
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
		if part {
			os.WriteFile(filepath.Join(d, "partition"), []byte("4\n"), 0644)
		}
	}
	mk("pci0000:00/nvme/nvme0n1", false)
	mk("pci0000:00/nvme/nvme0n1/nvme0n1p4", true)
	mk("pci0000:00/usb2/2-1/host6/sda", false)
	mk("pci0000:00/usb2/2-1/host6/sda/sda1", true)
	cls := filepath.Join(root, "class")
	os.MkdirAll(cls, 0755)
	for name, rel := range map[string]string{
		"nvme0n1": "pci0000:00/nvme/nvme0n1", "nvme0n1p4": "pci0000:00/nvme/nvme0n1/nvme0n1p4",
		"sda": "pci0000:00/usb2/2-1/host6/sda", "sda1": "pci0000:00/usb2/2-1/host6/sda/sda1",
	} {
		if err := os.Symlink(filepath.Join(devs, rel), filepath.Join(cls, name)); err != nil {
			t.Fatal(err)
		}
	}
	return cls
}

func TestApplianceMediumInternalDisk(t *testing.T) {
	cls := fakeBlockTree(t)
	dir := t.TempDir()
	mounts := filepath.Join(dir, "mounts")
	os.WriteFile(mounts, []byte("/dev/nvme0n1p4 /persist ext4 rw 0 0\n"), 0644)
	layout := filepath.Join(dir, "disk-layout.conf")
	os.WriteFile(layout, []byte("VERSION=1\nDISK_ID=nvme-X\nPOOL_NAME=zpool-1\n"), 0644)
	oldM, oldC, oldL, oldB := procMountsPath, sysClassBlockPath, diskLayoutPath, applianceBlkid
	t.Cleanup(func() { procMountsPath, sysClassBlockPath, diskLayoutPath, applianceBlkid = oldM, oldC, oldL, oldB })
	procMountsPath, sysClassBlockPath, diskLayoutPath = mounts, cls, layout
	applianceBlkid = func(...string) (string, error) { return "/dev/sda1\n/dev/nvme0n1p1\n", nil }

	m := ApplianceMediumInfo()
	if m.Kind != "disk" || m.Disk != "nvme0n1" || m.PoolName != "zpool-1" || m.Transport != "nvme" {
		t.Fatalf("internal disk: %+v", m)
	}
	if m.OtherImageDisk != "sda" {
		t.Fatalf("old stick still plugged in not reported: %+v", m)
	}

	// The stick itself: no layout file, transport usb.
	os.WriteFile(mounts, []byte("/dev/sda1 /persist ext4 rw 0 0\n"), 0644)
	os.Remove(layout)
	applianceBlkid = func(...string) (string, error) { return "/dev/sda1\n", nil }
	m = ApplianceMediumInfo()
	if m.Kind != "stick" || m.Disk != "sda" || m.Transport != "usb" || m.OtherImageDisk != "" {
		t.Fatalf("stick: %+v", m)
	}

	// No store mounted (degraded, or settings moved away).
	os.WriteFile(mounts, []byte("tmpfs /run tmpfs rw 0 0\n"), 0644)
	if m = ApplianceMediumInfo(); m.Kind != "" || m.Disk != "" {
		t.Fatalf("no store: %+v", m)
	}
}
