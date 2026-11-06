package system

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"zfsnas/internal/capacityrrd"
)

var poolPerfDB *capacityrrd.DB

// GetPoolPerfDB returns the shared per-pool disk performance RRD database.
func GetPoolPerfDB() *capacityrrd.DB {
	return poolPerfDB
}

// readDiskTempC returns the current temperature in °C for a disk basename
// (e.g. "sda", "nvme0n1") via the kernel's hwmon sysfs interface. Returns
// (0, false) when no hwmon temp1_input is exposed for this device — typical
// for SATA drives without the `drivetemp` kernel module loaded, in which
// case the caller falls back to the slower cached SMART value. Real-time:
// updates on every read, costs one read of a millicelsius integer file.
func readDiskTempC(dev string) (int, bool) {
	var candidates []string
	if strings.HasPrefix(dev, "nvme") {
		// /sys/class/nvme/nvme0/hwmon*/temp1_input — works on every
		// modern NVMe driver. The hwmon directory number isn't stable
		// across reboots so glob it.
		candidates = append(candidates, "/sys/class/nvme/"+dev+"/hwmon*/temp1_input")
		// nvme namespace device (e.g. nvme0n1) — try sibling lookup.
		if i := strings.IndexByte(dev, 'n'); i > 0 {
			parent := dev[:i] // "nvme0n1" → "nvme0"
			candidates = append(candidates, "/sys/class/nvme/"+parent+"/hwmon*/temp1_input")
		}
	}
	// SATA / SAS via `drivetemp` kernel module (CONFIG_SENSORS_DRIVETEMP).
	// Module is not loaded by default on most distros — present when the
	// admin has explicitly modprobed it.
	candidates = append(candidates, "/sys/block/"+dev+"/device/hwmon*/temp1_input")

	for _, pattern := range candidates {
		matches, _ := filepath.Glob(pattern)
		for _, p := range matches {
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			s := strings.TrimSpace(string(data))
			v, err := strconv.Atoi(s)
			if err != nil {
				continue
			}
			// hwmon reports millicelsius; round to nearest °C.
			c := (v + 500) / 1000
			// Sanity-check — bogus drivers sometimes report 0 / huge ints.
			if c < -40 || c > 150 {
				continue
			}
			return c, true
		}
	}
	return 0, false
}

// StartPoolPerfCollector opens (or creates) the per-pool disk performance RRD
// and starts a goroutine that samples disk I/O per pool every 5 minutes.
// Series keys:
//
//	read:{pool}:{dev}, write:{pool}:{dev}, busy:{pool}:{dev}
//	l2size:{pool}      — bytes currently held in L2ARC (system-wide arcstats)
//	l2hitpct:{pool}    — L2 hit % over the 5-minute window
//
// L2 series are emitted only for pools that have at least one cache device.
// Because arcstats expose system-wide L2 counters (no per-pool breakdown), the
// same numeric values are written for every pool that has L2ARC.
func StartPoolPerfCollector(configDir string) {
	dbPath := filepath.Join(configDir, "pool_perf.rrd.json")
	db, err := capacityrrd.Open(dbPath)
	if err != nil {
		log.Printf("pool_perf: failed to open RRD at %s: %v", dbPath, err)
		return
	}
	poolPerfDB = db

	go func() {
		// Prime prevDiskIO immediately so the first tick (5 min from now)
		// can compute a delta rather than requiring two full ticks.
		poolDevs := poolMemberBaseNamesPerPool()
		var allDevs []string
		if len(poolDevs) > 0 {
			seen := make(map[string]bool)
			for _, devs := range poolDevs {
				for _, d := range devs {
					if !seen[d] {
						seen[d] = true
						allDevs = append(allDevs, d)
					}
				}
			}
		}
		prevDiskIO, _ := readDiskstats(allDevs)
		prevDiskTime := time.Now()

		// Prime L2 hit/miss counters so the first tick can compute a delta.
		var prevL2Hits, prevL2Misses int64
		if arc, err := GetARCStats(); err == nil {
			prevL2Hits, prevL2Misses = arc.L2Hits, arc.L2Misses
		}

		tick := time.NewTicker(5 * time.Minute)
		defer tick.Stop()

		for now := range tick.C {
			poolDevs = poolMemberBaseNamesPerPool()
			if len(poolDevs) == 0 {
				continue
			}

			// Collect union of all devices for a single diskstats read.
			seen := make(map[string]bool)
			allDevs = nil
			for _, devs := range poolDevs {
				for _, d := range devs {
					if !seen[d] {
						seen[d] = true
						allDevs = append(allDevs, d)
					}
				}
			}

			curDisk, err := readDiskstats(allDevs)
			if err == nil && prevDiskIO != nil {
				dtSec := now.Sub(prevDiskTime).Seconds()
				if dtSec > 0 {
					for pool, devs := range poolDevs {
						for _, dev := range devs {
							cur, hasCur := curDisk[dev]
							prev, hasPrev := prevDiskIO[dev]
							if !hasCur || !hasPrev {
								continue
							}
							readMBps, writeMBps, busy, ok := diskRates(cur, prev, dtSec)
							if !ok {
								continue
							}
							db.Record("read:"+pool+":"+dev, readMBps, now)
							db.Record("write:"+pool+":"+dev, writeMBps, now)
							db.Record("busy:"+pool+":"+dev, busy, now)
						}
					}
				}
			}

			// L2ARC sampling — only when at least one pool has cache devices.
			// arcstats are system-wide, so the same values are recorded for every
			// pool that currently exposes L2ARC.
			if pools, perr := GetAllPools(); perr == nil {
				var l2Pools []string
				for _, p := range pools {
					if p != nil && len(p.CacheDevs) > 0 {
						l2Pools = append(l2Pools, p.Name)
					}
				}
				if len(l2Pools) > 0 {
					if arc, aerr := GetARCStats(); aerr == nil {
						dHits := arc.L2Hits - prevL2Hits
						dMiss := arc.L2Misses - prevL2Misses
						var hitPct float64
						if dHits < 0 || dMiss < 0 {
							// Counter reset (module reload) — skip this sample.
							hitPct = -1
						} else if total := dHits + dMiss; total > 0 {
							hitPct = float64(dHits) / float64(total) * 100
						}
						for _, pool := range l2Pools {
							db.Record("l2size:"+pool, float64(arc.L2Size), now)
							if hitPct >= 0 {
								db.Record("l2hitpct:"+pool, hitPct, now)
							}
						}
						prevL2Hits, prevL2Misses = arc.L2Hits, arc.L2Misses
					}
				}
			}

			// Per-disk temperature, sampled per pool. Source priority:
			//   1. sysfs hwmon (real-time, NVMe via /sys/class/nvme/<dev>/hwmon*,
			//      SATA via /sys/block/<dev>/device/hwmon* when the drivetemp
			//      module is loaded).
			//   2. cached SMART TempC from the periodic disks-list scan, for
			//      drives that don't expose hwmon (most SATA without drivetemp).
			// If neither is available the sample is SKIPPED (no record written),
			// so the frontend chart shows a gap for unknown periods and no line
			// at all for drives that have never had a value.
			var smartTemps map[string]int
			disks, derr := ListDisks(configDir)
			if derr == nil {
				smartTemps = make(map[string]int, len(disks))
				for _, d := range disks {
					if d.TempC != nil {
						smartTemps[d.Name] = *d.TempC
					}
				}
			}
			for pool, devs := range poolDevs {
				for _, dev := range devs {
					if t, ok := readDiskTempC(dev); ok {
						db.Record("temp:"+pool+":"+dev, float64(t), now)
					} else if t, ok := smartTemps[dev]; ok {
						db.Record("temp:"+pool+":"+dev, float64(t), now)
					}
					// else: no sample — leave a gap.
				}
			}

			// Disk power state per device, sampled per pool. 100 = active/idle,
			// 0 = standby; "unknown" / empty (NVMe, virtual, hdparm missing)
			// is skipped so the line shows a gap rather than a misleading
			// zero. Same diskPowerState() helper as the Physical Disks page,
			// so the value matches what hdparm -C reports. Cheap to sample —
			// hdparm -C is the SMART CHECK POWER MODE command, read-only and
			// safe to issue against sleeping drives.
			for pool, devs := range poolDevs {
				for _, dev := range devs {
					state := diskPowerState("/dev/" + dev)
					if state == "" || strings.HasPrefix(state, "unknown") {
						continue
					}
					var v float64
					switch {
					case state == "standby" || strings.HasPrefix(state, "standby"):
						v = 0
					case strings.Contains(state, "active") || strings.Contains(state, "idle"):
						v = 100
					default:
						// Sleeping / NVrcv / other rare states — treat as
						// "powered down". 0 reads the same as standby on the
						// chart so the line stays clean.
						v = 0
					}
					db.Record("pwr:"+pool+":"+dev, v, now)
				}
			}

			prevDiskIO = curDisk
			prevDiskTime = now

			if err := db.Flush(); err != nil {
				log.Printf("pool_perf: flush error: %v", err)
			}
		}
	}()
}
