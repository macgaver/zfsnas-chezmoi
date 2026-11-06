package system

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// diskstatSample holds one raw reading from /proc/diskstats for a device.
type diskstatSample struct {
	sectorsRead    uint64
	sectorsWritten uint64
	msIO           uint64 // ms spent doing I/O (field 12)
	ts             time.Time
}

// DiskIOSample is the computed per-device I/O metrics for one interval.
type DiskIOSample struct {
	ReadKBps  float64 `json:"read_kbps"`
	WriteKBps float64 `json:"write_kbps"`
	BusyPct   float64 `json:"busy_pct"`
}

// DiskIOSnapshot is the full snapshot returned by the API.
type DiskIOSnapshot struct {
	Devices map[string]DiskIOSample `json:"devices"` // key = kernel device name (e.g. "sda")
	At      time.Time               `json:"at"`
}

var (
	diskIOMu     sync.RWMutex
	diskIOLatest *DiskIOSnapshot
	diskIOPrev   map[string]diskstatSample
)

// StartDiskIOPoller samples /proc/diskstats every 2 s, keeping the latest
// computed snapshot for the pool's member disks.
func StartDiskIOPoller() {
	diskIOPrev = make(map[string]diskstatSample)
	go func() {
		tick := time.NewTicker(3 * time.Second)
		defer tick.Stop()
		for range tick.C {
			poolDevs := poolMemberBaseNames()
			if len(poolDevs) == 0 {
				continue
			}
			raw, err := readDiskstats(poolDevs)
			if err != nil {
				continue
			}
			now := time.Now()
			snap := &DiskIOSnapshot{
				Devices: make(map[string]DiskIOSample, len(poolDevs)),
				At:      now,
			}
			diskIOMu.Lock()
			for dev, cur := range raw {
				prev, hasPrev := diskIOPrev[dev]
				if hasPrev {
					dtSec := cur.ts.Sub(prev.ts).Seconds()
					if r, w, busy, ok := diskRates(cur, prev, dtSec); ok {
						snap.Devices[dev] = DiskIOSample{
							ReadKBps:  r * 1024,
							WriteKBps: w * 1024,
							BusyPct:   busy,
						}
					}
				}
				diskIOPrev[dev] = cur
			}
			diskIOLatest = snap
			diskIOMu.Unlock()
		}
	}()
}

// HardwareInfo holds static hardware properties of the host.
type HardwareInfo struct {
	CPUCores      int    `json:"cpu_cores"`
	TotalRAMBytes uint64 `json:"total_ram_bytes"`
}

// GetHardwareInfo reads CPU core count from /proc/cpuinfo and total RAM from /proc/meminfo.
func GetHardwareInfo() HardwareInfo {
	info := HardwareInfo{}

	// CPU cores: count "processor" lines in /proc/cpuinfo
	if f, err := os.Open("/proc/cpuinfo"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "processor") {
				info.CPUCores++
			}
		}
		f.Close()
	}

	// Total RAM from /proc/meminfo (value is in kB)
	if f, err := os.Open("/proc/meminfo"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 && fields[0] == "MemTotal:" {
				if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					info.TotalRAMBytes = val * 1024
				}
				break
			}
		}
		f.Close()
	}

	return info
}

// GetDiskIOSnapshot returns the most-recently computed I/O snapshot.
func GetDiskIOSnapshot() *DiskIOSnapshot {
	diskIOMu.RLock()
	defer diskIOMu.RUnlock()
	return diskIOLatest
}

var (
	poolMemberCacheMu   sync.Mutex
	poolMemberCache     []string
	poolMemberCachedAt  time.Time
	poolPerPoolCache    map[string][]string
	poolPerPoolCachedAt time.Time
)

// poolMemberBaseNames returns the kernel device names (e.g. "sda", "vdb") for ALL
// ZFS pools' member devices so the IO poller captures data for every pool.
// Uses `zpool status -P` for full paths, then resolves any by-partuuid/UUID
// paths to real device names via lsblk/blkid.
//
// Results are cached for 5 minutes — pool topology almost never changes and
// running `zpool status -P` every 3 s (the disk-IO poll interval) is wasteful.
func poolMemberBaseNames() []string {
	poolMemberCacheMu.Lock()
	defer poolMemberCacheMu.Unlock()
	if time.Since(poolMemberCachedAt) < 5*time.Minute && poolMemberCache != nil {
		return poolMemberCache
	}

	out, err := exec.Command("sudo", "zpool", "status", "-P").Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	validStates := map[string]bool{
		"ONLINE": true, "DEGRADED": true, "FAULTED": true,
		"OFFLINE": true, "REMOVED": true, "UNAVAIL": true,
	}
	vdevPrefixes := []string{"mirror-", "raidz2-", "raidz1-", "raidz-", "spare-", "log-", "cache-"}

	seen := make(map[string]bool)
	var names []string

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name, state := fields[0], fields[1]
		if !validStates[state] {
			continue
		}
		if name == "NAME" {
			continue
		}
		isVdev := false
		for _, pfx := range vdevPrefixes {
			if strings.HasPrefix(name, pfx) {
				isVdev = true
				break
			}
		}
		if isVdev {
			continue
		}
		real := resolveDevPath(name)
		base := diskBaseName(filepath.Base(real))
		// Skip anything that still looks like an unresolved UUID.
		if base == "" || strings.Contains(base, "-") || len(base) > 20 {
			continue
		}
		if !seen[base] {
			seen[base] = true
			names = append(names, base)
		}
	}
	poolMemberCache = names
	poolMemberCachedAt = time.Now()
	return names
}

// poolMemberBaseNamesPerPool returns a map from pool name to kernel device basenames
// (e.g. "sda") that belong to that pool. Results are cached for 5 minutes.
func poolMemberBaseNamesPerPool() map[string][]string {
	poolMemberCacheMu.Lock()
	defer poolMemberCacheMu.Unlock()
	if time.Since(poolPerPoolCachedAt) < 5*time.Minute && poolPerPoolCache != nil {
		return poolPerPoolCache
	}

	// Get pool names.
	listOut, err := exec.Command("sudo", "zpool", "list", "-H", "-o", "name").Output()
	if err != nil || len(listOut) == 0 {
		return nil
	}
	var pools []string
	for _, line := range strings.Split(strings.TrimSpace(string(listOut)), "\n") {
		if name := strings.TrimSpace(line); name != "" {
			pools = append(pools, name)
		}
	}

	validStates := map[string]bool{
		"ONLINE": true, "DEGRADED": true, "FAULTED": true,
		"OFFLINE": true, "REMOVED": true, "UNAVAIL": true,
	}
	vdevPrefixes := []string{"mirror-", "raidz2-", "raidz1-", "raidz-", "spare-", "log-", "cache-"}

	result := make(map[string][]string)
	for _, pool := range pools {
		statusOut, err := exec.Command("sudo", "zpool", "status", "-P", pool).Output()
		if err != nil || len(statusOut) == 0 {
			continue
		}
		seen := make(map[string]bool)
		var devices []string
		for _, line := range strings.Split(string(statusOut), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			name, state := fields[0], fields[1]
			if !validStates[state] || name == "NAME" || name == pool {
				continue
			}
			isVdev := false
			for _, pfx := range vdevPrefixes {
				if strings.HasPrefix(name, pfx) {
					isVdev = true
					break
				}
			}
			if isVdev {
				continue
			}
			real := resolveDevPath(name)
			base := diskBaseName(filepath.Base(real))
			if base == "" || strings.Contains(base, "-") || len(base) > 20 {
				continue
			}
			if !seen[base] {
				seen[base] = true
				devices = append(devices, base)
			}
		}
		if len(devices) > 0 {
			result[pool] = devices
		}
	}
	poolPerPoolCache = result
	poolPerPoolCachedAt = time.Now()
	return result
}

// readDiskstats reads /proc/diskstats and returns samples for the requested devices.
func readDiskstats(devs []string) (map[string]diskstatSample, error) {
	want := make(map[string]bool, len(devs))
	for _, d := range devs {
		want[d] = true
	}

	f, err := os.Open("/proc/diskstats")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	now := time.Now()
	result := make(map[string]diskstatSample, len(devs))
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 14 {
			continue
		}
		name := fields[2]
		if !want[name] {
			continue
		}
		sectorsRead, _ := strconv.ParseUint(fields[5], 10, 64)
		sectorsWritten, _ := strconv.ParseUint(fields[9], 10, 64)
		msIO, _ := strconv.ParseUint(fields[12], 10, 64)
		result[name] = diskstatSample{
			sectorsRead:    sectorsRead,
			sectorsWritten: sectorsWritten,
			msIO:           msIO,
			ts:             now,
		}
	}
	return result, scanner.Err()
}
