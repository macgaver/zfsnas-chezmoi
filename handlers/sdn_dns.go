package handlers

// DNS reports (Monitor → DNS) and blocklists.

import (
	"net/http"
	"strconv"
	"time"

	"zfsnas/internal/config"
	"zfsnas/system"
)

// sdnDNSSpan reads the report's range.
func sdnDNSSpan(r string) time.Duration {
	switch r {
	case "7d":
		return 7 * 24 * time.Hour
	case "30d":
		return 30 * 24 * time.Hour
	case "1y":
		return 365 * 24 * time.Hour
	}
	return 24 * time.Hour
}

// HandleSDNDNSReport — GET /api/sdn/dns/report?range=24h|7d|30d|1y → the
// dashboard, the clients' names, and the blocklists' size.
func HandleSDNDNSReport(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := sdnStoreFor(appCfg).LoadConfirmed()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		sum := system.SDNDNSReport(sdnDNSSpan(r.URL.Query().Get("range")))
		var ips []string
		for _, l := range [][]system.SDNDNSCount{sum.TopClients, sum.TopClientsBlocked} {
			for _, x := range l {
				ips = append(ips, x.Key)
			}
		}
		ips = append(ips, sum.ClientSeries.Clients...)
		bl := system.SDNBlocklistsState()
		jsonOK(w, map[string]any{
			"metrics":    c.DNS.Enabled && c.DNS.Metrics,
			"collecting": system.SDNDNSCollecting(),
			"report":     sum,
			"names":      system.SDNInsideNames(c, ips),
			"blocklist":  map[string]any{"domains": bl.Domains, "built": bl.Built, "blocking": c.DNS.Enabled && c.DNS.Blocking()},
		})
	}
}

// HandleSDNDNSQueries — GET /api/sdn/dns/queries?domain=&client=&status=
// &before=&limit= → the query log, newest first, with the clients' names.
func HandleSDNDNSQueries(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 || limit > 1000 {
			limit = 200
		}
		before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
		list := system.SDNDNSQueries(q.Get("domain"), q.Get("client"), q.Get("status"), before, limit)
		seen := map[string]bool{}
		var ips []string
		for _, x := range list {
			if !seen[x.Client] {
				seen[x.Client] = true
				ips = append(ips, x.Client)
			}
		}
		c, _ := sdnStoreFor(appCfg).LoadConfirmed()
		jsonOK(w, map[string]any{"queries": list, "names": system.SDNInsideNames(c, ips)})
	}
}

// HandleSDNBlocklists — GET /api/sdn/dns/blocklists → each list's last
// download and the domains blocked.
func HandleSDNBlocklists(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, system.SDNBlocklistsState())
}

// HandleSDNBlocklistsUpdate — POST /api/sdn/dns/blocklists/update: download
// every list now.
func HandleSDNBlocklistsUpdate(w http.ResponseWriter, r *http.Request) {
	system.SDNBlocklistsKick(true)
	jsonOK(w, map[string]bool{"ok": true})
}
