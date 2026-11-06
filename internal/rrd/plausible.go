package rrd

import (
	"math"
	"strings"
)

// Limits far above any real hardware: a value beyond them is an accident (an
// unsigned counter difference across a reset gives about 10^11 Mbit/s), never
// a real peak.
const (
	MaxNetMbps  = 1_000_000 // 1 Tbit/s
	maxNetBps   = MaxNetMbps * 1e6 / 8
	maxDiskMBps = 1_000_000 // 1 TB/s
	maxDiskBps  = maxDiskMBps * 1e6
)

// Plausible says whether a value may be stored for a series. Both round-robin
// databases refuse the others, and drop those an earlier version stored.
// Rate series have limits; every series refuses NaN and infinity.
func Plausible(key string, v float64) bool {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return false
	}
	limit := 0.0
	switch {
	case strings.HasPrefix(key, "net_rx:"), strings.HasPrefix(key, "net_tx:"): // VM NIC, bytes/s
		limit = maxNetBps
	case strings.HasPrefix(key, "net_") && (strings.HasSuffix(key, "_rx") || strings.HasSuffix(key, "_tx")): // Mbit/s
		limit = MaxNetMbps
	case strings.HasPrefix(key, "disk_r:"), strings.HasPrefix(key, "disk_w:"): // VM disk, bytes/s
		limit = maxDiskBps
	case key == "disk_read", key == "disk_write", key == "disk_read_mbps", key == "disk_write_mbps",
		strings.HasPrefix(key, "read:"), strings.HasPrefix(key, "write:"): // MB/s
		limit = maxDiskMBps
	case key == "disk_busy", key == "disk_busy_pct", strings.HasPrefix(key, "busy:"): // %
		return v >= 0 && v <= 100
	case strings.HasPrefix(key, "gwrtt_"): // gateway ping time, ms
		return v >= 0 && v <= 10000
	default:
		return true
	}
	return v >= 0 && v < limit
}
