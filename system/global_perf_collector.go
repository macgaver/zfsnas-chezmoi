package system

import (
	"log"
	"path/filepath"
	"time"
	"zfsnas/internal/capacityrrd"
)

var globalPerfDB *capacityrrd.DB

// GetGlobalPerfDB returns the shared global system performance RRD database.
func GetGlobalPerfDB() *capacityrrd.DB {
	return globalPerfDB
}

// StartGlobalPerfCollector opens (or creates) the global system performance RRD
// and starts a goroutine that samples CPU, memory, network, and disk I/O every 5 minutes.
// Series keys: cpu, mem_app, mem_cache, net_{iface}_rx, net_{iface}_tx,
// disk_read, disk_write, disk_busy, gwrtt_{gatewayID} (ms)
func StartGlobalPerfCollector(configDir string) {
	dbPath := filepath.Join(configDir, "global_perf.rrd.json")
	db, err := capacityrrd.Open(dbPath)
	if err != nil {
		log.Printf("global_perf: failed to open RRD at %s: %v", dbPath, err)
		return
	}
	globalPerfDB = db

	go func() {
		// Prime previous states before first tick so the first sample is available after 5 min.
		prevNet := readNetStats()
		prevNetTime := time.Now()
		poolDevs := poolMemberBaseNames()
		prevDiskIO, _ := readDiskstats(poolDevs)
		prevDiskTime := time.Now()

		tick := time.NewTicker(5 * time.Minute)
		defer tick.Stop()

		for now := range tick.C {
			// CPU: two readings 500 ms apart to compute delta.
			time.Sleep(3 * time.Second)
			cpu1 := readCPUStat()
			time.Sleep(500 * time.Millisecond)
			cpu2 := readCPUStat()
			if cpu1 != nil && cpu2 != nil {
				total := float64(cpu2.total - cpu1.total)
				idle := float64(cpu2.idle - cpu1.idle)
				if total > 0 {
					db.Record("cpu", (total-idle)/total*100, now)
				}
			}

			// Memory
			if _, cache, arc, app := readMemStats(); app >= 0 {
				vmPct, containerPct := 0.0, 0.0
				if snap := GetMemProcsSnapshot(); snap != nil {
					vmPct = snap.VMPct
					containerPct = snap.ContainerPct
					// Clamp so subtraction never pushes app below 0.
					if vmPct+containerPct > app {
						ratio := app / (vmPct + containerPct)
						vmPct *= ratio
						containerPct *= ratio
					}
				}
				appOnly := app - vmPct - containerPct
				if appOnly < 0 {
					appOnly = 0
				}
				db.Record("mem_app", appOnly, now)
				db.Record("mem_vm", vmPct, now)
				db.Record("mem_container", containerPct, now)
				db.Record("mem_arc", arc, now)
				db.Record("mem_cache", cache, now)
			}

			// Network (per interface)
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

			// Gateway latency (Firewall, monitored gateways only): the true
			// min/avg/max of the pings answered in the last 5 minutes.
			recordGatewayRTT(db, now)

			// Disk I/O (aggregate across all pool member disks)
			poolDevs = poolMemberBaseNames()
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
						db.Record("disk_read", readMBps, now)
						db.Record("disk_write", writeMBps, now)
						if count > 0 {
							db.Record("disk_busy", busyTotal/float64(count), now)
						}
					}
				}
				prevDiskIO = curDisk
				prevDiskTime = now
			}

			if err := db.Flush(); err != nil {
				log.Printf("global_perf: flush error: %v", err)
			}
		}
	}()
}

// recordGatewayRTT stores gwrtt_<gateway ID> from the gateway daemon's
// 15-minute rings; nothing when no ping was answered (an outage is not 0 ms).
func recordGatewayRTT(db *capacityrrd.DB, now time.Time) {
	for id, pts := range SDNGatewayRTT() {
		if mn, avg, mx, n := RTTWindow(pts, now.Unix()-300, now.Unix()); n > 0 {
			db.RecordAgg("gwrtt_"+id, mn, avg, mx, n, now)
		}
	}
}
