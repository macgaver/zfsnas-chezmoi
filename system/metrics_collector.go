package system

import (
	"bufio"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"zfsnas/internal/rrd"
)

var metricsDB *rrd.DB

// GetMetricsDB returns the shared RRD database used by the metrics collector.
func GetMetricsDB() *rrd.DB {
	return metricsDB
}

// StartMetricsCollector opens (or creates) the RRD file and starts a goroutine
// that samples all 7 system metrics every 5 minutes.
func StartMetricsCollector(configDir string) {
	dbPath := filepath.Join(configDir, "metrics.rrd.json")
	db, err := rrd.Open(dbPath)
	if err != nil {
		log.Printf("metrics: failed to open RRD at %s: %v", dbPath, err)
		return
	}
	metricsDB = db

	go func() {
		var prevNet map[string]netStat
		var prevNetTime time.Time
		var prevDiskIO map[string]diskstatSample
		var prevDiskTime time.Time

		tick := time.NewTicker(5 * time.Minute)
		defer tick.Stop()

		for now := range tick.C {
			// --- CPU first ---
			// Wait briefly so that other goroutines that woke up on the same
			// tick (health poller, disk I/O poller, etc.) have time to finish
			// their subprocess work before we sample CPU.
			time.Sleep(3 * time.Second)
			cpu1 := readCPUStat()
			time.Sleep(500 * time.Millisecond)
			cpu2 := readCPUStat()
			if cpu1 != nil && cpu2 != nil {
				total := float64(cpu2.total - cpu1.total)
				idle := float64(cpu2.idle - cpu1.idle)
				if total > 0 {
					db.Record("cpu_pct", (total-idle)/total*100, now)
				}
			}

			// --- Memory (and all other metrics after CPU is recorded) ---
			if used, cache, arc, app := readMemStats(); used >= 0 {
				db.Record("mem_used_pct", used, now)
				db.Record("mem_cache_pct", cache, now)
				db.Record("mem_arc_pct", arc, now)
				db.Record("mem_app_pct", app, now)
			}
			// --- Memory compression (zram-tools), v6.5.3+ ---
			// Recorded as % of physical RAM so the dashboard chart can stack
			// the compressed-pool layer above the 100 %-physical line. Three
			// series: configured pool size, uncompressed bytes held (= RAM
			// effectively gained), compressed bytes physically in RAM.
			// All zero when zram is disabled, which matches the chart's
			// "render the old way" behaviour for pre-zram historical samples.
			if zc := GetMemCompStatus(); zc.Enabled {
				memTotalKB, _, _ := readMemInfo()
				totalKB := float64(memTotalKB)
				if totalKB > 0 {
					db.Record("mem_zram_pool_pct", float64(zc.DiskSizeBytes)/1024/totalKB*100, now)
					db.Record("mem_zram_orig_pct", float64(zc.OrigDataBytes)/1024/totalKB*100, now)
					db.Record("mem_zram_compr_pct", float64(zc.ComprDataBytes)/1024/totalKB*100, now)
				}
			}

			// --- Network ---
			curNet := readNetStats()
			if prevNet != nil && curNet != nil {
				dtSec := now.Sub(prevNetTime).Seconds()
				if dtSec > 0 {
					for iface, cur := range curNet {
						if prev, ok := prevNet[iface]; ok {
							rx, ok1 := netRateMbps(cur.rxBytes, prev.rxBytes, dtSec)
							tx, ok2 := netRateMbps(cur.txBytes, prev.txBytes, dtSec)
							if ok1 && ok2 {
								db.Record("net_"+iface+"_rx", rx, now)
								db.Record("net_"+iface+"_tx", tx, now)
							}
						}
					}
				}
			}
			prevNet = curNet
			prevNetTime = now

			// --- Disk I/O (reuses readDiskstats from sysinfo.go) ---
			poolDevs := poolMemberBaseNames()
			if len(poolDevs) > 0 {
				curDisk, err := readDiskstats(poolDevs)
				if err == nil && prevDiskIO != nil {
					dtSec := now.Sub(prevDiskTime).Seconds()
					if dtSec > 0 {
						var readMBps, writeMBps, busyTotal float64
						count := 0
						for dev, cur := range curDisk {
							if prev, ok := prevDiskIO[dev]; ok {
								if r, w, busy, ok := diskRates(cur, prev, dtSec); ok {
									readMBps += r
									writeMBps += w
									busyTotal += busy
									count++
								}
							}
						}
						db.Record("disk_read_mbps", readMBps, now)
						db.Record("disk_write_mbps", writeMBps, now)
						if count > 0 {
							db.Record("disk_busy_pct", busyTotal/float64(count), now)
						}
					}
				}
				prevDiskIO = curDisk
				prevDiskTime = now
			}

			if err := db.Flush(); err != nil {
				log.Printf("metrics: flush error: %v", err)
			}
		}
	}()
}

// cpuStat holds the total and idle CPU jiffies from /proc/stat.
type cpuStat struct {
	total uint64
	idle  uint64
}

func readCPUStat() *cpuStat {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return nil
		}
		vals := make([]uint64, len(fields)-1)
		for i, fld := range fields[1:] {
			vals[i], _ = strconv.ParseUint(fld, 10, 64)
		}
		// Fields: user, nice, system, idle, iowait, irq, softirq, steal, …
		idle := vals[3] // idle
		if len(vals) > 4 {
			idle += vals[4] // iowait counts as idle for our purposes
		}
		var total uint64
		for _, v := range vals {
			total += v
		}
		return &cpuStat{total: total, idle: idle}
	}
	return nil
}

// readARCSize returns the ZFS ARC cache size in kilobytes by reading
// /proc/spl/kstat/zfs/arcstats. Returns 0 if unavailable.
func readARCSize() uint64 {
	f, err := os.Open("/proc/spl/kstat/zfs/arcstats")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Format: <name> <type> <value>
		if len(fields) == 3 && fields[0] == "size" {
			val, _ := strconv.ParseUint(fields[2], 10, 64)
			return val / 1024 // bytes → KB (matches /proc/meminfo units)
		}
	}
	return 0
}

// readMemStats returns (used%, cache%, arc%, app%) from /proc/meminfo and ZFS arcstats.
// cache = page cache + buffers; arc = ZFS ARC; app = used − cache − arc; used = total − available.
// Returns -1 for all four on error.
func readMemStats() (used, cache, arc, app float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return -1, -1, -1, -1
	}
	defer f.Close()

	var total, free, buffers, cached, shmem, available uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = val
		case "MemFree:":
			free = val
		case "Buffers:":
			buffers = val
		case "Cached:":
			cached = val
		case "Shmem:":
			shmem = val
		case "MemAvailable:":
			available = val
		}
	}
	if total == 0 {
		return -1, -1, -1, -1
	}

	// /proc/meminfo's "Cached" lumps in Shmem (tmpfs + qemu memfd/hugetlb guest
	// RAM), which makes VM memory look like reclaimable page cache. Subtract
	// Shmem so VMs land in "app" memory where they belong.
	pageCache := cached
	if pageCache > shmem {
		pageCache -= shmem
	} else {
		pageCache = 0
	}

	arcKB := readARCSize()
	// Cap ARC at the app memory headroom to avoid going negative.
	var appKB uint64
	if total > free+buffers+pageCache {
		appKB = total - free - buffers - pageCache
	}
	if arcKB > appKB {
		arcKB = appKB
	}

	used = float64(total-available) / float64(total) * 100
	cache = float64(buffers+pageCache) / float64(total) * 100
	arc = float64(arcKB) / float64(total) * 100
	app = float64(appKB-arcKB) / float64(total) * 100
	return used, cache, arc, app
}

type netStat struct {
	rxBytes uint64
	txBytes uint64
}

// GetIfaceIPv4s returns a map of external interface name → first IPv4 address.
func GetIfaceIPv4s() map[string]string {
	result := make(map[string]string)
	ifaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	for _, iface := range ifaces {
		if !isExternalInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil {
				result[iface.Name] = ip.String()
				break
			}
		}
	}
	return result
}

// isExternalInterface returns true for physical/bonded/wireless interfaces.
// It excludes loopback, container, and virtual interfaces by name prefix.
func isExternalInterface(name string) bool {
	for _, pfx := range []string{"lo", "docker", "veth", "virbr", "br-", "tun", "tap", "vxlan", "dummy"} {
		if strings.HasPrefix(name, pfx) {
			return false
		}
	}
	return true
}

func readNetStats() map[string]netStat {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil
	}
	defer f.Close()

	result := make(map[string]netStat)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum <= 2 {
			continue // skip two header lines
		}
		line := scanner.Text()
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if !isExternalInterface(iface) {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		result[iface] = netStat{rxBytes: rx, txBytes: tx}
	}
	return result
}
