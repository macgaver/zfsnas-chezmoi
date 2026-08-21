package system

// vm.swappiness management (v6.8.7).
//
// Why this exists: on a host running VMs, the kernel will page out IDLE guest
// memory long before RAM is scarce — at the stock swappiness of 60 it is happy
// to evict cold pages with tens of gigabytes free. Getting them back is a disk
// read, and if swap lives on a ZFS zvol that read traverses the ZFS stack. Under
// pool load the fault can take minutes.
//
// Observed on znas5, 2026-08-21: five qemu tasks blocked >122 s in
// shmem_swapin_folio, 12 GiB of guest RAM parked on NVMEPool/swap, 80 GiB free.
// The guests froze. Nothing was actively swapping — the pages had been evicted
// during an earlier pressure episode and Linux never brings them back on its
// own.
//
// The knob is read from /proc/sys/vm/swappiness, applied at runtime through
// sudo tee, and persisted to /etc/sysctl.d so it survives a reboot — the same
// runtime-plus-persistent shape the ARC max setting uses (see arc.go).

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// RecommendedSwappiness is what the slider's marker points at.
//
// 10, not 0: zero does NOT mean "never swap", it means "swap only to avoid an
// OOM kill", which trades VM stalls for killed processes. 10 keeps guest RAM
// resident under normal conditions while leaving the kernel an escape valve.
const RecommendedSwappiness = 10

const (
	swappinessProcPath   = "/proc/sys/vm/swappiness"
	swappinessSysctlPath = "/etc/sysctl.d/60-zfsnas-swappiness.conf"
	procSwapsPath        = "/proc/swaps"
)

// SwapDevice is one entry from /proc/swaps.
type SwapDevice struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"` // "zram" | "zvol" | "partition" | "file"
	SizeMB int64  `json:"size_mb"`
	UsedMB int64  `json:"used_mb"`
}

// SwappinessStatus is what GET /api/system/swappiness returns. It carries the
// live swap picture as well as the value, because the setting is meaningless
// without knowing what swap is backed by: at swappiness 60 with swap on a zvol
// the host is one pressure episode away from frozen guests, while the same
// value with zram is unremarkable.
type SwappinessStatus struct {
	Current     int          `json:"current"`
	Recommended int          `json:"recommended"`
	Devices     []SwapDevice `json:"devices"`
	TotalMB     int64        `json:"total_mb"`
	UsedMB      int64        `json:"used_mb"`
	// OnZvol is the condition worth warning about: a page-in has to go through
	// ZFS, so it can block behind pool I/O.
	OnZvol bool `json:"on_zvol"`
	// Persisted reports whether our sysctl drop-in exists, i.e. whether the
	// current value will survive a reboot.
	Persisted bool `json:"persisted"`
}

// classifySwapDevice names the backing store behind a swap entry.
// zram is compressed RAM (good), zd* is a ZFS zvol (the hazard), anything else
// under /dev is a block device, and a bare path is a swap file.
func classifySwapDevice(dev string) string {
	base := dev
	if i := strings.LastIndex(dev, "/"); i >= 0 {
		base = dev[i+1:]
	}
	switch {
	case strings.HasPrefix(base, "zram"):
		return "zram"
	case strings.HasPrefix(base, "zd"):
		return "zvol"
	case strings.HasPrefix(dev, "/dev/"):
		return "partition"
	default:
		return "file"
	}
}

// parseProcSwaps reads /proc/swaps content. Sizes there are in KiB.
func parseProcSwaps(content string) []SwapDevice {
	var out []SwapDevice
	for i, line := range strings.Split(content, "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // header / blank
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		sizeKB, err1 := strconv.ParseInt(f[2], 10, 64)
		usedKB, err2 := strconv.ParseInt(f[3], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, SwapDevice{
			Name:   f[0],
			Kind:   classifySwapDevice(f[0]),
			SizeMB: sizeKB / 1024,
			UsedMB: usedKB / 1024,
		})
	}
	return out
}

func validateSwappiness(v int) error {
	if v < 0 || v > 100 {
		return fmt.Errorf("swappiness must be between 0 and 100, got %d", v)
	}
	return nil
}

// swappinessSysctlFile renders the persistent drop-in. Regenerated whole on
// every write so the file can never accumulate a second, silently-winning
// directive.
func swappinessSysctlFile(v int) string {
	return fmt.Sprintf(`# Managed by ZNAS — Settings → Virtualization → Memory Swapping.
# Lower values keep VM guest memory resident; see the portal for the rationale.
vm.swappiness = %d
`, v)
}

// GetSwappinessStatus reads the current value plus the live swap picture.
func GetSwappinessStatus() SwappinessStatus {
	st := SwappinessStatus{Current: -1, Recommended: RecommendedSwappiness}
	if b, err := os.ReadFile(swappinessProcPath); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			st.Current = n
		}
	}
	if b, err := os.ReadFile(procSwapsPath); err == nil {
		st.Devices = parseProcSwaps(string(b))
	}
	for _, d := range st.Devices {
		st.TotalMB += d.SizeMB
		st.UsedMB += d.UsedMB
		if d.Kind == "zvol" {
			st.OnZvol = true
		}
	}
	if _, err := os.Stat(swappinessSysctlPath); err == nil {
		st.Persisted = true
	}
	return st
}

// SetSwappiness applies the value now and persists it for the next boot.
//
// Runtime first: if the persist step fails the admin still gets the behaviour
// they asked for and a clear error, rather than a file that promises something
// the running kernel is not doing.
func SetSwappiness(v int) error {
	if err := validateSwappiness(v); err != nil {
		return err
	}
	cmd := exec.Command("sudo", "tee", swappinessProcPath)
	cmd.Stdin = bytes.NewBufferString(strconv.Itoa(v) + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apply swappiness: %w: %s", err, strings.TrimSpace(string(out)))
	}
	persist := exec.Command("sudo", "tee", swappinessSysctlPath)
	persist.Stdin = bytes.NewBufferString(swappinessSysctlFile(v))
	if out, err := persist.CombinedOutput(); err != nil {
		return fmt.Errorf("applied for this boot, but could not persist to %s: %w: %s",
			swappinessSysctlPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}
