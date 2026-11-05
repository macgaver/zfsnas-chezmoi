package handlers

// OPNsense-compatible endpoints for homepage.dev's "opnsense" widget (CPU,
// memory, WAN upload/download totals). The widget sends HTTP Basic auth; the
// username is ignored and the password must be one of the portal's API keys.
//
//   GET /api/diagnostics/activity/getActivity → {"headers":[top lines…]}
//   GET /api/diagnostics/traffic/interface    → {"interfaces":{"wan":{…}}}
//
// "wan" is the default-route interface; widget.wan may also name any Linux
// interface.

import (
	"net/http"
	"strings"

	"zfsnas/system"
)

func opnsenseAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, pw, ok := r.BasicAuth()
		if !ok {
			if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
				pw, ok = a[7:], true
			}
		}
		if !ok || !piholeKeyOK(pw) {
			if ok {
				piholeDelay()
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="api"`)
			jsonErr(w, http.StatusUnauthorized, "Authentication Failed")
			return
		}
		next(w, r)
	}
}

// HandleOPNsenseActivity — GET /api/diagnostics/activity/getActivity.
func HandleOPNsenseActivity(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{"headers": system.OPNsenseActivityHeaders(), "details": []any{}})
}

// HandleOPNsenseInterfaces — GET /api/diagnostics/traffic/interface.
func HandleOPNsenseInterfaces(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{"interfaces": system.OPNsenseInterfaces(), "time": 0})
}
