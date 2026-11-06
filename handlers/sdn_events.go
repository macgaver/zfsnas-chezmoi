package handlers

import (
	"net/http"
	"strconv"

	"zfsnas/internal/config"
	"zfsnas/system"
)

// HandleSDNEvents — GET /api/sdn/events?category=all|gateway|ddns|system&limit=N
// The firewall event history, newest first (default 200, at most 1000).
func HandleSDNEvents(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 {
			limit = 200
		}
		if limit > 1000 {
			limit = 1000
		}
		cat := q.Get("category")
		switch cat {
		case "", "all", "gateway", "ddns", "system":
		default:
			jsonErr(w, http.StatusBadRequest, "unknown category")
			return
		}
		jsonOK(w, map[string]any{"events": system.SDNReadEvents(sdnStoreFor(appCfg).Dir, cat, limit)})
	}
}

// HandleSDNGatewayRTT — GET /api/sdn/gateway-rtt[?id=<gateway ID>][&points=0]
// A gateway's latency over the last 15 minutes, from the gateway monitor's
// own checks (no extra pings): now, average, min, max, loss, and the points
// (left out with points=0). Without id: the gateway carrying the default
// route. Used by the header popup and the iOS app.
func HandleSDNGatewayRTT(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var isPPPoE func(string) bool
		if c, err := sdnStoreFor(appCfg).LoadConfirmed(); err == nil {
			isPPPoE = func(id string) bool {
				if g := c.GatewayByID(id); g != nil {
					in := c.InterfaceByID(g.Interface)
					return in != nil && in.Kind == "pppoe"
				}
				return false
			}
		}
		s, ok := system.SDNGatewayRTTSummary(q.Get("id"), q.Get("points") != "0", isPPPoE)
		if !ok {
			jsonErr(w, http.StatusNotFound, "no such gateway, or no gateway carries the default route")
			return
		}
		jsonOK(w, s)
	}
}
