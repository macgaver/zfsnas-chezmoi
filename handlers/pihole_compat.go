package handlers

// Pi-hole-compatible statistics for dashboards such as homepage.dev's
// "pihole" widget, answered from the Firewall's DNS report (last 24 h) and
// its blocklists. The widget's "key" is one of the portal's API keys (the
// same ones the TrueNAS-compatible /api/v2.0/ endpoints take).
//
//   v6: POST /api/auth {"password":"<key>"} → session.sid, then
//       GET /api/stats/summary with header X-FTL-SID: <sid> (or ?sid=)
//   v5: GET /admin/api.php?summaryRaw&auth=<key> (also ?summary)
//
// Read-only: a sid only opens /api/stats/summary.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/config"
	"zfsnas/system"
)

const piholeSIDValidity = 30 * time.Minute

var piholeSIDs = struct {
	sync.Mutex
	m map[string]time.Time // sid → expiry
}{m: map[string]time.Time{}}

// piholeKeyOK: whether s is one of the portal's API keys.
func piholeKeyOK(s string) bool {
	if s == "" {
		return false
	}
	keys, _ := config.LoadAPIKeys()
	ok := false
	for _, k := range keys {
		if subtle.ConstantTimeCompare([]byte(k.Key), []byte(s)) == 1 {
			ok = true
		}
	}
	return ok
}

func piholeNewSID(now time.Time) string {
	b := make([]byte, 18)
	rand.Read(b)
	sid := hex.EncodeToString(b)
	piholeSIDs.Lock()
	for k, exp := range piholeSIDs.m {
		if now.After(exp) {
			delete(piholeSIDs.m, k)
		}
	}
	piholeSIDs.m[sid] = now.Add(piholeSIDValidity)
	piholeSIDs.Unlock()
	return sid
}

func piholeSIDOK(sid string, now time.Time) bool {
	if sid == "" {
		return false
	}
	piholeSIDs.Lock()
	defer piholeSIDs.Unlock()
	exp, ok := piholeSIDs.m[sid]
	if !ok || now.After(exp) {
		delete(piholeSIDs.m, sid)
		return false
	}
	return true
}

// piholeDelay slows down guessing a key.
func piholeDelay() { time.Sleep(300 * time.Millisecond) }

func piholeUnauthorized(w http.ResponseWriter) {
	piholeDelay()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"key": "unauthorized", "message": "Unauthorized", "hint": nil},
		"took":  0,
	})
}

// HandlePiholeAuth — POST /api/auth (Pi-hole v6 login).
func HandlePiholeAuth(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	if !piholeKeyOK(body.Password) {
		piholeUnauthorized(w)
		return
	}
	jsonOK(w, map[string]any{
		"session": map[string]any{
			"valid": true, "totp": false, "sid": piholeNewSID(time.Now()), "csrf": "",
			"validity": int(piholeSIDValidity / time.Second), "message": "password correct",
		},
		"took": 0,
	})
}

// HandlePiholeLogout — DELETE /api/auth: ends the session.
func HandlePiholeLogout(w http.ResponseWriter, r *http.Request) {
	sid := piholeSID(r)
	piholeSIDs.Lock()
	delete(piholeSIDs.m, sid)
	piholeSIDs.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func piholeSID(r *http.Request) string {
	if s := r.Header.Get("X-FTL-SID"); s != "" {
		return s
	}
	if s := r.Header.Get("sid"); s != "" {
		return s
	}
	return r.URL.Query().Get("sid")
}

type piholeStats struct {
	total, blocked, cached, forwarded, clients, gravity int
	pct                                                 float64
	gravityAt                                           int64
	enabled                                             bool
}

func piholeCollect(appCfg *config.AppConfig) piholeStats {
	sum := system.SDNDNSReport(24 * time.Hour)
	bl := system.SDNBlocklistsState()
	st := piholeStats{gravity: bl.Domains}
	if !bl.Built.IsZero() {
		st.gravityAt = bl.Built.Unix()
	}
	if c, err := sdnStoreFor(appCfg).LoadConfirmed(); err == nil && c != nil {
		st.enabled = c.DNS.Enabled && c.DNS.Blocking()
	}
	if sum != nil {
		st.total, st.blocked, st.cached, st.forwarded, st.clients = sum.Total, sum.Blocked, sum.Cached, sum.Forwarded, sum.Clients
	}
	if st.total > 0 {
		st.pct = float64(st.blocked) * 100 / float64(st.total)
	}
	return st
}

// HandlePiholeSummary — GET /api/stats/summary (Pi-hole v6 shape).
func HandlePiholeSummary(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !piholeSIDOK(piholeSID(r), time.Now()) {
			piholeUnauthorized(w)
			return
		}
		st := piholeCollect(appCfg)
		jsonOK(w, map[string]any{
			"queries": map[string]any{
				"total": st.total, "blocked": st.blocked, "percent_blocked": st.pct,
				"forwarded": st.forwarded, "cached": st.cached,
			},
			"clients": map[string]any{"active": st.clients, "total": st.clients},
			"gravity": map[string]any{"domains_being_blocked": st.gravity, "last_update": st.gravityAt},
			"took":    0,
		})
	}
}

// HandlePiholeV5 — GET /admin/api.php?summaryRaw&auth=<key> (Pi-hole v5).
func HandlePiholeV5(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		auth := q.Get("auth")
		if auth == "" {
			if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
				auth = a[7:]
			}
		}
		if !piholeKeyOK(auth) {
			// Pi-hole v5 answers an empty array without a valid token
			piholeDelay()
			jsonOK(w, []any{})
			return
		}
		st := piholeCollect(appCfg)
		status := "disabled"
		if st.enabled {
			status = "enabled"
		}
		jsonOK(w, map[string]any{
			"domains_being_blocked": st.gravity,
			"dns_queries_today":     st.total,
			"ads_blocked_today":     st.blocked,
			"ads_percentage_today":  st.pct,
			"queries_forwarded":     st.forwarded,
			"queries_cached":        st.cached,
			"unique_clients":        st.clients,
			"clients_ever_seen":     st.clients,
			"status":                status,
			"gravity_last_updated":  map[string]any{"file_exists": st.gravityAt > 0, "absolute": st.gravityAt},
		})
	}
}
