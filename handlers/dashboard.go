package handlers

import (
	"net/http"
	"strings"
	"zfsnas/internal/rrd"
	"zfsnas/system"
)

var allMetricSeries = []string{
	"cpu_pct",
	"mem_used_pct",
	"mem_cache_pct",
	"mem_app_pct",
	"net_rx_kbps",
	"net_tx_kbps",
	"disk_read_kbps",
	"disk_write_kbps",
	"disk_busy_pct",
}

// HandleGetDashboardMetrics returns RRD time-series data for the dashboard charts.
// Optional query param: ?series=cpu_pct,mem_used_pct  (comma-separated subset)
func HandleGetDashboardMetrics(w http.ResponseWriter, r *http.Request) {
	db := system.GetMetricsDB()
	if db == nil {
		jsonErr(w, http.StatusServiceUnavailable, "metrics collector not ready")
		return
	}

	keys := allMetricSeries
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
