package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The Firewall GeoMap street map loads OpenStreetMap tiles from the browser:
// the CSP must allow them as images (and nothing else from that host).
func TestCSPAllowsOSMTilesAsImagesOnly(t *testing.T) {
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	csp := rec.Header().Get("Content-Security-Policy")
	for _, d := range strings.Split(csp, ";") {
		d = strings.TrimSpace(d)
		has := strings.Contains(d, "tile.openstreetmap.org")
		if strings.HasPrefix(d, "img-src ") && !has {
			t.Errorf("img-src must allow OSM tiles: %q", d)
		}
		if !strings.HasPrefix(d, "img-src ") && has {
			t.Errorf("OSM host must not be allowed outside img-src: %q", d)
		}
	}
}
