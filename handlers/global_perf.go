package handlers

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"zfsnas/internal/capacityrrd"
	"zfsnas/system"
)

// HandleGetGlobalPerfData returns multi-tier global system performance RRD data.
// Query params: tier (0=5-min/week, 1=30-min/month, 2=daily/5yr), since (unix ts)
// Response: { series: { key: []CapSample }, ifaces: []string }
func HandleGetGlobalPerfData(w http.ResponseWriter, r *http.Request) {
	db := system.GetGlobalPerfDB()
	if db == nil {
		jsonErr(w, http.StatusServiceUnavailable, "global perf collector not ready")
		return
	}

	tier, _ := strconv.Atoi(r.URL.Query().Get("tier"))
	if tier < 0 || tier > 2 {
		tier = 0
	}

	var since int64
	if s := r.URL.Query().Get("since"); s != "" {
		since, _ = strconv.ParseInt(s, 10, 64)
	}

	// Discover NIC names from net_{iface}_rx keys.
	ifaceSet := make(map[string]bool)
	for _, k := range db.Keys() {
		if strings.HasPrefix(k, "net_") && strings.HasSuffix(k, "_rx") {
			iface := strings.TrimSuffix(strings.TrimPrefix(k, "net_"), "_rx")
			ifaceSet[iface] = true
		}
	}
	ifaces := make([]string, 0, len(ifaceSet))
	for iface := range ifaceSet {
		ifaces = append(ifaces, iface)
	}
	sort.Strings(ifaces)

	result := make(map[string][]capacityrrd.CapSample)
	for _, key := range db.Keys() {
		samples := db.Query(tier, key)
		if since > 0 {
			cut := len(samples)
			for i, s := range samples {
				if s.TS >= since {
					cut = i
					break
				}
			}
			samples = samples[cut:]
		}
		if samples == nil {
			samples = []capacityrrd.CapSample{}
		}
		result[key] = samples
	}

	// Gateway latency series (Firewall): gwrtt_<id> → the gateway's name.
	gateways := map[string]string{}
	names := system.SDNGatewayNames()
	for _, k := range db.Keys() {
		if id, ok := strings.CutPrefix(k, "gwrtt_"); ok {
			if n, known := names[id]; known {
				gateways[k] = n
			}
		}
	}

	jsonOK(w, map[string]interface{}{
		"series":   result,
		"ifaces":   ifaces,
		"gateways": gateways,
	})
}

// HandleGetGlobalPerfOldest returns the Unix timestamp of the oldest Tier0 sample
// across all global system performance series. Returns oldest_ts=0 if no data yet.
func HandleGetGlobalPerfOldest(w http.ResponseWriter, r *http.Request) {
	db := system.GetGlobalPerfDB()
	var oldest int64
	if db != nil {
		oldest = db.OldestTS()
	}
	jsonOK(w, map[string]int64{"oldest_ts": oldest})
}
