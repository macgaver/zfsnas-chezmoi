package system

import (
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"zfsnas/internal/capacityrrd"
)

var capacityDB *capacityrrd.DB

// GetCapacityDB returns the shared capacity RRD database (nil until first collection).
func GetCapacityDB() *capacityrrd.DB {
	return capacityDB
}

// StartCapacityCollector opens (or creates) the capacity RRD and starts the
// 5-minute background poller that samples pool and dataset capacity.
func StartCapacityCollector(configDir string) {
	dbPath := filepath.Join(configDir, "capacity.rrd.json")
	db, err := capacityrrd.Open(dbPath)
	if err != nil {
		log.Printf("capacity: failed to open RRD at %s: %v", dbPath, err)
		return
	}
	capacityDB = db

	go func() {
		tick := time.NewTicker(5 * time.Minute)
		defer tick.Stop()
		var pruned time.Time
		for now := range tick.C {
			live := sampleCapacity(db, now)
			if live != nil && now.Sub(pruned) >= 24*time.Hour {
				pruned = now
				if n := pruneCapacitySeries(db, live, now); n > 0 {
					log.Printf("capacity: dropped %d series of datasets gone for 30 days", n)
				}
			}
			if err := db.Flush(); err != nil {
				log.Printf("capacity: flush error: %v", err)
			}
		}
	}()
}

// sampleCapacity records one sample of every pool, dataset and zvol, and
// returns the names seen ("ds:<name>", "zv:<name>"); nil when a listing
// failed (nothing may then be judged gone).
func sampleCapacity(db *capacityrrd.DB, now time.Time) map[string]bool {
	pools, err := GetAllPools()
	if err != nil {
		log.Printf("capacity: GetAllPools: %v", err)
		return nil
	}
	live := map[string]bool{}
	for _, p := range pools {
		pfx := "pool:" + p.Name + ":"
		db.Record(pfx+"used", float64(p.UsableUsed), now)
		db.Record(pfx+"avail", float64(p.UsableAvail), now)
		db.Record(pfx+"usable", float64(p.UsableSize), now)
		if cr := parseComprRatio(p.Compression); cr > 0 {
			db.Record(pfx+"compratio", cr, now)
		}
	}

	datasets, err := ListAllDatasets()
	if err != nil {
		log.Printf("capacity: ListAllDatasets: %v", err)
		return nil
	}
	for _, d := range datasets {
		live["ds:"+d.Name] = true
		pfx := "ds:" + d.Name + ":"
		db.Record(pfx+"used", float64(d.Used), now)
		db.Record(pfx+"avail", float64(d.Avail), now)
		if d.Quota > 0 {
			db.Record(pfx+"quota", float64(d.Quota), now)
		}
		if cr := parseComprRatio(d.CompRatio); cr > 0 {
			db.Record(pfx+"compratio", cr, now)
		}
	}

	zvols, err := ListAllZVols()
	if err != nil {
		log.Printf("capacity: ListAllZVols: %v", err)
		return nil
	}
	for _, z := range zvols {
		live["zv:"+z.Name] = true
		pfx := "zv:" + z.Name + ":"
		db.Record(pfx+"used", float64(z.Used), now)
		db.Record(pfx+"size", float64(z.Size), now)
		if cr := parseComprRatio(z.CompRatio); cr > 0 {
			db.Record(pfx+"compratio", cr, now)
		}
	}
	return live
}

// pruneCapacitySeries drops the series of datasets and zvols that no longer
// exist and have had no sample for 30 days (deleted containers, old clones,
// Incus' deleted images): each kept ~200 KB of memory and file for 5 years.
func pruneCapacitySeries(db *capacityrrd.DB, live map[string]bool, now time.Time) int {
	n := 0
	for _, key := range db.AllKeys() {
		i := strings.LastIndexByte(key, ':')
		if i < 0 || !(strings.HasPrefix(key, "ds:") || strings.HasPrefix(key, "zv:")) || live[key[:i]] {
			continue
		}
		var last int64
		for tier := 0; tier <= 2; tier++ {
			if q := db.Query(tier, key); len(q) > 0 && q[len(q)-1].TS > last {
				last = q[len(q)-1].TS
			}
		}
		if now.Unix()-last > 30*86400 {
			db.DeleteKey(key)
			n++
		}
	}
	return n
}

// parseComprRatio converts "1.24x" → 1.24; returns 0 on error or if value is ≤1.
func parseComprRatio(s string) float64 {
	s = strings.TrimSuffix(strings.TrimSpace(s), "x")
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v <= 1.0 {
		return 0
	}
	return v
}
