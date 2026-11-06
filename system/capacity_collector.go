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
		for now := range tick.C {
			sampleCapacity(db, now)
			if err := db.Flush(); err != nil {
				log.Printf("capacity: flush error: %v", err)
			}
		}
	}()
}

func sampleCapacity(db *capacityrrd.DB, now time.Time) {
	pools, err := GetAllPools()
	if err != nil {
		log.Printf("capacity: GetAllPools: %v", err)
		return
	}
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
		return
	}
	for _, d := range datasets {
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
		return
	}
	for _, z := range zvols {
		pfx := "zv:" + z.Name + ":"
		db.Record(pfx+"used", float64(z.Used), now)
		db.Record(pfx+"size", float64(z.Size), now)
		if cr := parseComprRatio(z.CompRatio); cr > 0 {
			db.Record(pfx+"compratio", cr, now)
		}
	}
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
