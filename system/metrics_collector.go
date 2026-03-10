package system

import (
	"bufio"
	"log"
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
		var prevNet     map[string]netStat
		var prevNetTime time.Time
		var prevDiskIO  map[string]diskstatSample
		var prevDiskTime time.Time

		tick := time.NewTicker(5 * time.Minute)
		defer tick.Stop()

		for now := range tick.C {
			// --- CPU (two readings 500 ms apart for accuracy) ---
			cpu1 := readCPUStat()
			time.Sleep(500 * time.Millisecond)
			cpu2 := readCPUStat()
			if cpu1 != nil && cpu2 != nil {
				total := float64(cpu2.total - cpu1.total)
				idle  := float64(cpu2.idle  - cpu1.idle)
				if total > 0 {
					db.Record("cpu_pct", (total-idle)/total*100, now)
				}
			}

			// --- Memory ---
			if used, cache, app := readMemStats(); used >= 0 {
				db.Record("mem_used_pct",  used,  now)
				db.Record("mem_cache_pct", cache, now)
				db.Record("mem_app_pct",   app,   now)
			}

			// --- Network ---
			curNet := readNetStats()
			if prevNet != nil && curNet != nil {
				dtSec := now.Sub(prevNetTime).Seconds()
				if dtSec > 0 {
					var rxTotal, txTotal float64
					for iface, cur := range curNet {
						if prev, ok := prevNet[iface]; ok {
							rxTotal += float64(cur.rxBytes-prev.rxBytes) / 1024 / dtSec
							txTotal += float64(cur.txBytes-prev.txBytes) / 1024 / dtSec
						}
					}
					db.Record("net_rx_kbps", rxTotal, now)
					db.Record("net_tx_kbps", txTotal, now)
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
						var readKBps, writeKBps, busyTotal float64
						count := 0
						for dev, cur := range curDisk {
							if prev, ok := prevDiskIO[dev]; ok {
								readKBps  += float64(cur.sectorsRead-prev.sectorsRead)       * 512 / 1024 / dtSec
								writeKBps += float64(cur.sectorsWritten-prev.sectorsWritten) * 512 / 1024 / dtSec
								dtMS := dtSec * 1000
								busy := float64(cur.msIO-prev.msIO) / dtMS * 100
								if busy > 100 {
									busy = 100
								}
								busyTotal += busy
								count++
							}
						}
						db.Record("disk_read_kbps",  readKBps,  now)
						db.Record("disk_write_kbps", writeKBps, now)
						if count > 0 {
							db.Record("disk_busy_pct", busyTotal/float64(count), now)
						}
					}
				}
				prevDiskIO  = curDisk
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

// readMemStats returns (used%, cache%, app%) from /proc/meminfo.
// cache = page cache + buffers; app = used − cache; used = total − available.
// Returns -1 for all three on error.
func readMemStats() (used, cache, app float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return -1, -1, -1
	}
	defer f.Close()

	var total, free, buffers, cached, available uint64
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
		case "MemAvailable:":
			available = val
		}
	}
	if total == 0 {
		return -1, -1, -1
	}
	used  = float64(total-available) / float64(total) * 100
	cache = float64(buffers+cached)  / float64(total) * 100
	var appKB uint64
	if total > free+buffers+cached {
		appKB = total - free - buffers - cached
	}
	app = float64(appKB) / float64(total) * 100
	return used, cache, app
}

type netStat struct {
	rxBytes uint64
	txBytes uint64
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
		if iface == "lo" {
			continue // skip loopback
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
