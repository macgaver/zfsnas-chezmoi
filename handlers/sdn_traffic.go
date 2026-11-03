package handlers

// Firewall traffic statistics, live connections and geo database endpoints
// (spec §12; plan PLANS/plan-sdn-phase2-traffic.md).

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/sdn"
	"zfsnas/internal/traffic"
	"zfsnas/system"
)

var sdnRanges = map[string]time.Duration{
	"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour,
	"1y": 365 * 24 * time.Hour, "5y": 5 * 365 * 24 * time.Hour,
}

// HandleSDNTraffic — GET /api/sdn/traffic?range=24h&dir=all&group=ip&q=&offset=&limit=
func HandleSDNTraffic(w http.ResponseWriter, r *http.Request) {
	qv := r.URL.Query()
	span, ok := sdnRanges[qv.Get("range")]
	if !ok {
		span = 24 * time.Hour
	}
	now := time.Now()
	q := traffic.Query{From: now.Add(-span), To: now.Add(time.Minute), Dir: qv.Get("dir"), Group: qv.Get("group"), Filter: qv.Get("q")}
	if q.Group == "" {
		q.Group = "ip"
	}
	q.Offset, _ = strconv.Atoi(qv.Get("offset"))
	limit, _ := strconv.Atoi(qv.Get("limit"))
	q.Limit = sdnTrafficLimit(limit)
	jsonOK(w, system.SDNTrafficQuery(q))
}

// sdnTrafficLimit: lines per answer; 100 when not asked, at most 2000.
func sdnTrafficLimit(n int) int {
	if n <= 0 {
		return 100
	}
	return min(n, 2000)
}

// HandleSDNTrafficStatus — GET /api/sdn/traffic/status
func HandleSDNTrafficStatus(w http.ResponseWriter, r *http.Request) {
	st := system.SDNTrafficStatusNow()
	att := "IP geolocation by DB-IP.com (CC BY 4.0)"
	if st.StatsDir != "" {
		att = system.SDNGeoAttribution(system.SDNGeoDir(st.StatsDir))
	}
	resp := map[string]any{"status": st, "attribution": att}
	if g := system.SDNGeo(); g != nil {
		if h := sdnHomeGuess(); h != nil {
			resp["home"] = h
		}
	}
	jsonOK(w, resp)
}

// sdnHomeGuess places "home" on the map from the WAN addresses' geo data.
func sdnHomeGuess() map[string]any {
	for _, a := range system.SDNPublicLocalAddrs() {
		if in := system.SDNGeo().Lookup(a); in.Lat != 0 || in.Lon != 0 {
			return map[string]any{"lat": in.Lat, "lon": in.Lon, "city": in.City, "cc": in.CountryCode}
		}
	}
	return nil
}

// HandleSDNConnections — GET /api/sdn/connections?limit=500
func HandleSDNConnections(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	list, err := system.SDNLiveConnections(limit)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, list)
}

// HandleSDNTopTalkers — GET /api/sdn/top-talkers?dir=down|up → the inside
// devices using the Internet most right now (the header's dial popups).
func HandleSDNTopTalkers(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := sdnStoreFor(appCfg)
		s, _ := st.LoadState()
		c, err := st.LoadConfirmed()
		if !s.Enabled || err != nil {
			jsonOK(w, system.SDNTalkersReport{})
			return
		}
		dir := r.URL.Query().Get("dir")
		if dir != "up" {
			dir = "down"
		}
		jsonOK(w, system.SDNTopTalkers(c, dir, 10))
	}
}

// HandleSDNKillConnection — POST /api/sdn/connections/kill {proto, src, dst, sport, dport}
func HandleSDNKillConnection(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Proto, Src, Dst string
		Sport, Dport    uint16
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Src == "" || b.Dst == "" {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	sess := MustSession(r)
	if err := system.SDNKillConnection(b.Proto, b.Src, b.Dst, b.Sport, b.Dport); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionSDNApply, Target: "connection",
		Result: audit.ResultOK, Details: "killed " + b.Proto + " " + b.Src + " → " + b.Dst})
	jsonOK(w, map[string]bool{"ok": true})
}

// HandleSDNGeoUpdate — POST /api/sdn/geodb/update (download now)
func HandleSDNGeoUpdate(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := system.SDNTrafficStatusNow()
		dir := system.SDNGeoDir(st.StatsDir)
		if st.StatsDir == "" {
			jsonErr(w, http.StatusConflict, "the traffic collector is not running")
			return
		}
		err := system.SDNUpdateGeoDB(dir, time.Now())
		system.SDNSetGeoDir(dir)
		if err != nil {
			jsonErr(w, http.StatusBadGateway, err.Error())
			return
		}
		jsonOK(w, system.SDNGeoDBStatus(dir))
	}
}

// sdnGeoProviderView is the location database choice without the key.
func sdnGeoProviderView() map[string]any {
	p := system.SDNGeoProviderLoad()
	st := system.SDNTrafficStatusNow()
	out := map[string]any{"provider": p.Provider, "account_id": p.AccountID, "key_set": p.LicenseKey != "",
		"configured": p.MaxMindConfigured(), "job": system.SDNGeoJobNow(), "in_use": "dbip"}
	if st.StatsDir != "" {
		dir := system.SDNGeoDir(st.StatsDir)
		out["in_use"], out["files"] = system.SDNGeoSource(dir), system.SDNGeoDBStatus(dir)
	}
	return out
}

// HandleSDNGeoProviderGet — GET /api/sdn/geodb/provider
func HandleSDNGeoProviderGet(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, sdnGeoProviderView())
}

type sdnGeoProviderBody struct {
	Provider   string `json:"provider"`
	AccountID  string `json:"account_id"`
	LicenseKey string `json:"license_key"` // empty: keep the saved one
}

// sdnGeoCreds merges what was typed with what is saved.
func sdnGeoCreds(b sdnGeoProviderBody) system.SDNGeoProvider {
	p := system.SDNGeoProviderLoad()
	p.AccountID = strings.TrimSpace(b.AccountID)
	if k := strings.TrimSpace(b.LicenseKey); k != "" {
		p.LicenseKey = k
	}
	return p
}

// HandleSDNGeoMaxMindTest — POST /api/sdn/geodb/maxmind/test {account_id, license_key}
func HandleSDNGeoMaxMindTest(w http.ResponseWriter, r *http.Request) {
	var b sdnGeoProviderBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := system.SDNMaxMindTest(sdnGeoCreds(b)); err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// HandleSDNGeoProviderSet — PUT /api/sdn/geodb/provider {provider, account_id?, license_key?}
// Choosing MaxMind checks the credentials first, then downloads GeoLite2 in
// the background; DB-IP answers until it is in place.
func HandleSDNGeoProviderSet(w http.ResponseWriter, r *http.Request) {
	var b sdnGeoProviderBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || (b.Provider != "dbip" && b.Provider != "maxmind") {
		jsonErr(w, http.StatusBadRequest, "choose dbip or maxmind")
		return
	}
	p := system.SDNGeoProviderLoad()
	if b.Provider == "maxmind" {
		if b.AccountID != "" || b.LicenseKey != "" {
			p = sdnGeoCreds(b)
		}
		if err := system.SDNMaxMindTest(p); err != nil {
			jsonErr(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	p.Provider = b.Provider
	if err := system.SDNGeoProviderSave(p); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if st := system.SDNTrafficStatusNow(); st.StatsDir != "" {
		dir := system.SDNGeoDir(st.StatsDir)
		system.SDNSetGeoDir(dir)      // back to DB-IP at once, or GeoLite2 if already there
		system.SDNGeoUpdateAsync(dir) // fetch what the choice lacks
	}
	sess := MustSession(r)
	name := map[string]string{"dbip": "DB-IP Lite", "maxmind": "MaxMind GeoLite2"}[b.Provider]
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionSDNGeoProvider, Target: "geolocation",
		Result: audit.ResultOK, Details: "location database: " + name})
	jsonOK(w, sdnGeoProviderView())
}

// HandleSDNStatsLocation — POST /api/sdn/traffic/location {pool}: keep the
// statistics on <pool>/znas-netstats. Not a router change: saved directly.
func HandleSDNStatsLocation(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Pool string `json:"pool"`
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Pool == "" {
			jsonErr(w, http.StatusBadRequest, "choose a pool")
			return
		}
		mp, err := system.SDNSetStatsPool(b.Pool)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Keep what was collected so far (and the geo databases).
		if old := system.SDNTrafficStatusNow().StatsDir; old != "" && old != mp {
			system.SDNTrafficFlush()
			if err := system.SDNMoveStats(old, mp); err != nil {
				jsonErr(w, http.StatusInternalServerError, "moving the statistics: "+err.Error())
				return
			}
		}
		st := sdnStoreFor(appCfg)
		var serr error
		_ = sdnLocked(st, func() {
			for _, load := range []func() (*sdn.Config, error){st.LoadConfirmed} {
				c, err := load()
				if err != nil {
					serr = err
					return
				}
				c.Settings.StatsDir = mp
				serr = st.SaveConfirmed(c)
			}
			if d, err := st.LoadDraft(); err == nil {
				d.Config.Settings.StatsDir = mp
				_, _ = st.SaveDraft(d.Config, d.Revision, MustSession(r).Username)
			}
		})
		if serr != nil {
			jsonErr(w, http.StatusInternalServerError, serr.Error())
			return
		}
		jsonOK(w, map[string]string{"stats_dir": mp})
	}
}

// HandleSDNCountries — GET /api/sdn/countries → [[code, name], …]
func HandleSDNCountries(w http.ResponseWriter, r *http.Request) { jsonOK(w, sdn.Countries) }
