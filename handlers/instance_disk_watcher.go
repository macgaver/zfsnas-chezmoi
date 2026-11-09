// Space alert for VM/container disks: the "VM / Container disk usage
// exceeds N%" notification (vm_disk_full). Checked every 5 minutes; one
// notification when a disk crosses its threshold, re-armed once it drops
// 5 points below. The state survives restarts so a deploy doesn't repeat it.
package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"zfsnas/internal/alerts"
	"zfsnas/internal/config"
	"zfsnas/system"
)

const instanceDiskWatchInterval = 5 * time.Minute

func instanceDiskAlertStatePath() string {
	return filepath.Join(config.Dir(), "instance-disk-alerts.json")
}

// StartInstanceDiskWatcher launches the 5-minute disk-usage poller.
func StartInstanceDiskWatcher() {
	go func() {
		time.Sleep(2 * time.Minute)
		checkInstanceDisks()
		tick := time.NewTicker(instanceDiskWatchInterval)
		defer tick.Stop()
		for range tick.C {
			checkInstanceDisks()
		}
	}()
}

func checkInstanceDisks() {
	if !system.IncusInstalled() {
		return
	}
	cfg, err := alerts.Load()
	if err != nil {
		return
	}
	enabled, global := alerts.MinVMDiskFullThreshold(cfg)
	if !enabled {
		return
	}
	alerted := map[string]bool{}
	if b, err := os.ReadFile(instanceDiskAlertStatePath()); err == nil {
		_ = json.Unmarshal(b, &alerted)
	}
	next, sends := evalInstanceDiskAlerts(system.InstanceDiskUsages(global), alerted)
	for _, u := range sends {
		kind := "Container"
		what := "disk " + u.Disk
		if u.VM {
			kind, what = "VM", "filesystem "+u.Disk
		}
		if err := alerts.Send(alerts.EventVMDiskFull,
			fmt.Sprintf("%s %s: %s %.0f%% full", kind, u.Instance, what, u.Pct()),
			"VM / Container Disk Almost Full",
			fmt.Sprintf("%s '%s': %s is %.0f%% full (%s used of %s, alert threshold %d%%). Free some space or grow the disk (Edit → Disks). When a container's disk is completely full, Incus can no longer save its settings.",
				kind, u.Instance, what, u.Pct(), fmtBytesIEC(u.Used), fmtBytesIEC(u.Size), u.Threshold),
		); err != nil {
			log.Printf("[alerts] disk-full send for %s/%s: %v", u.Instance, u.Disk, err)
		}
	}
	if b, err := json.Marshal(next); err == nil {
		_ = os.WriteFile(instanceDiskAlertStatePath(), b, 0600)
	}
}

// evalInstanceDiskAlerts returns the new "already alerted" set and the
// disks to notify about now. A disk no longer measured (instance deleted,
// muted, threshold off) is forgotten.
func evalInstanceDiskAlerts(usages []system.InstanceDiskUsage, alerted map[string]bool) (map[string]bool, []system.InstanceDiskUsage) {
	next := map[string]bool{}
	var sends []system.InstanceDiskUsage
	for _, u := range usages {
		key := u.Instance + "|" + u.Disk
		pct := u.Pct()
		switch {
		case pct >= float64(u.Threshold):
			if !alerted[key] {
				sends = append(sends, u)
			}
			next[key] = true
		case alerted[key] && pct >= float64(u.Threshold-5):
			next[key] = true // hysteresis: not re-armed yet
		}
	}
	return next, sends
}

func fmtBytesIEC(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
