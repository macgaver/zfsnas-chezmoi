package handlers

// Auto groups (6.11.27): lists the Firewall maintains itself (firewall
// reputation lists and the address lists of the active IDS rules) that
// rules can use as a source or destination. See system/sdn_autogroups.go.

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"zfsnas/internal/config"
	"zfsnas/internal/sdn"
	"zfsnas/system"
)

// HandleSDNAutoGroups — GET /api/sdn/autogroups
func HandleSDNAutoGroups(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, system.SDNAutoGroups(appCfg.ConfigDir))
	}
}

// HandleSDNAutoGroupEntries — GET /api/sdn/autogroups/{id} → {id, entries}
func HandleSDNAutoGroupEntries(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		v, err := system.SDNAutoGroupEntries(appCfg.ConfigDir, id)
		if err != nil {
			jsonErr(w, http.StatusNotFound, err.Error())
			return
		}
		jsonOK(w, map[string]interface{}{"id": id, "entries": v})
	}
}

// HandleSDNFirewallLog — GET /api/sdn/log?rule=<id>&limit=<n>
// Packets logged by rules with "Log matching connections" (last 24 h,
// newest first). The page joins them with the rules it already has.
func HandleSDNFirewallLog(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := system.SDNFirewallLog(r.URL.Query().Get("rule"), limit)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if entries == nil {
		entries = []system.SDNLogEntry{}
	}
	jsonOK(w, map[string]interface{}{"entries": entries, "rate_per_sec": sdn.LogRatePerSec, "burst": sdn.LogBurst})
}
