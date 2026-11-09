// Per-disk "space alert" for VMs and containers: the vm_disk_full
// notification (threshold set per notification target) with an optional
// per-disk override stored on the instance.
package system

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// instanceDiskAlertPrefix + device name holds the per-disk threshold:
// absent = the notification settings' threshold, "off" = never, "1".."99".
const instanceDiskAlertPrefix = "user.zfsnas.disk_alert_pct."

// DiskAlertKey is the instance config key holding a disk's alert threshold.
func DiskAlertKey(device string) string { return instanceDiskAlertPrefix + device }

// NormalizeDiskAlertPct validates a per-disk threshold from the editor:
// "" (use the notification settings), "off", or a whole percent 1–99.
func NormalizeDiskAlertPct(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%")))
	if s == "" || s == "default" {
		return "", nil
	}
	if s == "off" || s == "0" {
		return "off", nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 99 {
		return "", fmt.Errorf("disk alert threshold must be 1–99%% or off")
	}
	return strconv.Itoa(n), nil
}

// diskAlertThreshold resolves the threshold for one disk: 0 = no alert.
func diskAlertThreshold(conf map[string]string, device string, global int) int {
	v, _ := NormalizeDiskAlertPct(conf[DiskAlertKey(device)])
	switch v {
	case "":
		return global
	case "off":
		return 0
	}
	n, _ := strconv.Atoi(v)
	return n
}

// InstanceDiskUsage is one VM/container disk (container) or guest
// filesystem (VM) measured against its alert threshold.
type InstanceDiskUsage struct {
	Instance  string
	Disk      string // device name ("root") or, for a VM, the guest mount point
	VM        bool
	Used      uint64
	Size      uint64
	Threshold int
}

// Pct is the used share in percent.
func (u InstanceDiskUsage) Pct() float64 {
	if u.Size == 0 {
		return 0
	}
	return float64(u.Used) * 100 / float64(u.Size)
}

type diskAlertInstance struct {
	Name            string                       `json:"name"`
	Type            string                       `json:"type"`
	Status          string                       `json:"status"`
	Config          map[string]string            `json:"config"`
	ExpandedDevices map[string]map[string]string `json:"expanded_devices"`
}

// datasetLimit returns (used, limit) of a container dataset against its
// quota: refquota (snapshots excluded) when set, else quota. limit 0 = none.
func datasetLimit(ds string) (used, limit uint64) {
	out, err := exec.Command("zfs", "get", "-Hp", "-o", "property,value", "used,referenced,quota,refquota", ds).Output()
	if err != nil {
		return 0, 0
	}
	v := map[string]uint64{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			v[f[0]], _ = strconv.ParseUint(f[1], 10, 64)
		}
	}
	if v["refquota"] > 0 {
		return v["referenced"], v["refquota"]
	}
	return v["used"], v["quota"]
}

// InstanceDiskUsages measures every disk with an active threshold.
// Containers: each disk's ZFS dataset against its quota (what makes the
// container "full" — works stopped too). VMs: the guest's real filesystems
// as reported by the Incus agent (running VMs only), against the root
// disk's threshold. Instances with "No alerts" ticked are skipped.
func InstanceDiskUsages(global int) []InstanceDiskUsage {
	out, err := exec.Command("incus", "query", "/1.0/instances?recursion=1").Output()
	if err != nil {
		return nil
	}
	var insts []diskAlertInstance
	if json.Unmarshal(out, &insts) != nil {
		return nil
	}
	var res []InstanceDiskUsage
	zfsPools := map[string]string{}
	var vmFS map[string]map[string][2]float64 // instance → mountpoint → {size, avail}
	for _, in := range insts {
		if in.Config[instanceNoAlertsKey] == "true" {
			continue
		}
		if in.Type == "virtual-machine" {
			if in.Status != "Running" {
				continue
			}
			thr := diskAlertThreshold(in.Config, rootDeviceName(in.ExpandedDevices), global)
			if thr <= 0 {
				continue
			}
			if vmFS == nil {
				vmFS = guestFilesystems()
			}
			for mp, sa := range vmFS[in.Name] {
				if sa[0] <= 0 {
					continue
				}
				used := sa[0] - sa[1]
				if used < 0 {
					used = 0
				}
				res = append(res, InstanceDiskUsage{Instance: in.Name, Disk: mp, VM: true,
					Used: uint64(used), Size: uint64(sa[0]), Threshold: thr})
			}
			continue
		}
		for dev, d := range in.ExpandedDevices {
			if d["type"] != "disk" || d["pool"] == "" {
				continue
			}
			thr := diskAlertThreshold(in.Config, dev, global)
			if thr <= 0 {
				continue
			}
			zp, ok := zfsPools[d["pool"]]
			if !ok {
				zp = lxdZFSPoolForLXDPool(d["pool"])
				zfsPools[d["pool"]] = zp
			}
			if zp == "" {
				continue
			}
			ds := ""
			if d["path"] == "/" {
				ds = zp + "/containers/" + in.Name
			} else if d["source"] != "" {
				ds = lxdFindZFSDataset(d["source"])
			}
			if ds == "" {
				continue
			}
			used, limit := datasetLimit(ds)
			if limit == 0 {
				continue // no size limit: the pool's own alerts cover it
			}
			res = append(res, InstanceDiskUsage{Instance: in.Name, Disk: dev, Used: used, Size: limit, Threshold: thr})
		}
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].Instance != res[j].Instance {
			return res[i].Instance < res[j].Instance
		}
		return res[i].Disk < res[j].Disk
	})
	return res
}

func rootDeviceName(devs map[string]map[string]string) string {
	for n, d := range devs {
		if d["type"] == "disk" && d["path"] == "/" {
			return n
		}
	}
	return "root"
}

// guestFilesystems reads the agent-reported filesystems of running VMs.
func guestFilesystems() map[string]map[string][2]float64 {
	res := map[string]map[string][2]float64{}
	body, err := fetchLXDMetricsBody()
	if err != nil {
		return res
	}
	for _, s := range parsePromText(body) {
		var idx int
		switch s.metric {
		case "lxd_filesystem_size_bytes":
			idx = 0
		case "lxd_filesystem_avail_bytes":
			idx = 1
		default:
			continue
		}
		inst, mp := s.labels["name"], s.labels["mountpoint"]
		if inst == "" || mp == "" || !isRealGuestFilesystem(s.labels["device"], s.labels["fstype"], mp) {
			continue
		}
		if res[inst] == nil {
			res[inst] = map[string][2]float64{}
		}
		v := res[inst][mp]
		v[idx] = s.value
		res[inst][mp] = v
	}
	return res
}

// ContainerSnapsExcluded reports whether a container dataset's size limit
// leaves snapshots out (ZFS refquota) rather than counting them (quota).
func ContainerSnapsExcluded(ds string) bool {
	out, err := exec.Command("zfs", "get", "-Hp", "-o", "value", "refquota", ds).Output()
	if err != nil {
		return false
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	return n > 0
}

// setContainerSnapsExcluded switches a container disk between quota (the
// default: snapshots count against the disk's size) and refquota (they
// count against the pool only). Incus moves the ZFS property itself.
func setContainerSnapsExcluded(pool, volume string, on bool) error {
	out, err := exec.Command("incus", "storage", "volume", "set", pool, volume,
		"zfs.use_refquota="+strconv.FormatBool(on)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}
