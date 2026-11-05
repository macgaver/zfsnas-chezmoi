package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"zfsnas/internal/config"
)

// The homepage.dev pihole widget's two flows, through the real router: v6
// (login with an API key, then the summary with the sid) and v5 (?auth=).
func TestPiholeCompat(t *testing.T) {
	if err := config.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveAPIKeys([]config.APIKeyEntry{{ID: "1", Name: "home", Key: "k123", CreatedAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	h := http.HandlerFunc(HandlePiholeAuth)
	do := func(hh http.Handler, method, url, body string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, url, strings.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		hh.ServeHTTP(w, req)
		return w
	}
	if w := do(h, "POST", "/api/auth", `{"password":"nope"}`, nil); w.Code != 401 {
		t.Fatalf("bad key: %d", w.Code)
	}
	w := do(h, "POST", "/api/auth", `{"password":"k123"}`, nil)
	var a struct {
		Session struct {
			Valid    bool   `json:"valid"`
			SID      string `json:"sid"`
			Validity int    `json:"validity"`
		} `json:"session"`
	}
	json.Unmarshal(w.Body.Bytes(), &a)
	if w.Code != 200 || !a.Session.Valid || a.Session.SID == "" || a.Session.Validity <= 0 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	cfg := &config.AppConfig{}
	sum := HandlePiholeSummary(cfg)
	if w := do(sum, "GET", "/api/stats/summary", "", map[string]string{"X-FTL-SID": "wrong"}); w.Code != 401 {
		t.Fatalf("bad sid: %d", w.Code)
	}
	w = do(sum, "GET", "/api/stats/summary", "", map[string]string{"X-FTL-SID": a.Session.SID})
	var s map[string]map[string]any
	json.Unmarshal(w.Body.Bytes(), &s)
	if w.Code != 200 || s["queries"]["total"] == nil || s["queries"]["percent_blocked"] == nil || s["gravity"]["domains_being_blocked"] == nil {
		t.Fatalf("summary: %d %s", w.Code, w.Body)
	}
	v5 := HandlePiholeV5(cfg)
	w = do(v5, "GET", "/admin/api.php?summaryRaw&auth=k123", "", nil)
	var m map[string]any
	json.Unmarshal(w.Body.Bytes(), &m)
	for _, k := range []string{"dns_queries_today", "ads_blocked_today", "ads_percentage_today", "domains_being_blocked"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("v5 missing %s: %s", k, w.Body)
		}
	}
	if w := do(v5, "GET", "/admin/api.php?summaryRaw&auth=bad", "", nil); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("v5 bad key: %s", w.Body)
	}
}
