package handlers

import (
	"net/http"
	"strings"
	"zfsnas/internal/rrd"
	"zfsnas/system"
)

var staticMetricSeries = []string{
	"cpu_pct",
	"mem_used_pct",
	"mem_cache_pct",
	"mem_app_pct",
	"disk_read_mbps",
	"disk_write_mbps",
	"disk_busy_pct",
}

// buildDashboardKeys returns the full set of metric series to query: static series
// plus any per-NIC net_{iface}_rx / net_{iface}_tx series present in the RRD.
func buildDashboardKeys(db *rrd.DB) []string {
	keys := make([]string, len(staticMetricSeries))
	copy(keys, staticMetricSeries)
	for _, k := range db.Keys() {
		if strings.HasPrefix(k, "net_") && (strings.HasSuffix(k, "_rx") || strings.HasSuffix(k, "_tx")) {
			keys = append(keys, k)
		}
	}
	return keys
}

// HandleGetNetIfaces returns a map of external interface name → IPv4 address.
func HandleGetNetIfaces(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, system.GetIfaceIPv4s())
}

// HandleGetDashboardMetrics returns RRD time-series data for the dashboard charts.
// Optional query param: ?series=cpu_pct,mem_used_pct  (comma-separated subset)
func HandleGetDashboardMetrics(w http.ResponseWriter, r *http.Request) {
	db := system.GetMetricsDB()
	if db == nil {
		jsonErr(w, http.StatusServiceUnavailable, "metrics collector not ready")
		return
	}

	keys := buildDashboardKeys(db)
	if q := r.URL.Query().Get("series"); q != "" {
		keys = strings.Split(q, ",")
	}

	result := make(map[string][]rrd.Sample, len(keys))
	for _, key := range keys {
		samples := db.Query(key)
		result[key] = samples
	}
	jsonOK(w, result)
}
