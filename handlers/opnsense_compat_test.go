package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
	"time"

	"zfsnas/internal/config"
)

// What homepage.dev's opnsense widget does with the answers: Basic auth
// (any username, the password is an API key), then its own regexes on top's
// header lines and the "wan" byte counters.
func TestOPNsenseCompat(t *testing.T) {
	if err := config.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveAPIKeys([]config.APIKeyEntry{{ID: "1", Name: "home", Key: "k123", CreatedAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	get := func(h http.HandlerFunc, user, pw string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/x", nil)
		req.SetBasicAuth(user, pw)
		w := httptest.NewRecorder()
		h(w, req)
		return w
	}
	act := opnsenseAuth(HandleOPNsenseActivity)
	if w := get(act, "root", "bad"); w.Code != 401 {
		t.Fatalf("bad key: %d", w.Code)
	}
	w := get(act, "whatever-user", "k123")
	var a struct{ Headers []string }
	json.Unmarshal(w.Body.Bytes(), &a)
	if w.Code != 200 || len(a.Headers) < 4 {
		t.Fatalf("activity: %d %s", w.Code, w.Body)
	}
	m := regexp.MustCompile(` ([0-9.]+)% idle`).FindStringSubmatch(a.Headers[2])
	if m == nil {
		t.Fatalf("idle regex: %q", a.Headers[2])
	}
	if v, err := strconv.ParseFloat(m[1], 64); err != nil || v < 0 || v > 100 {
		t.Fatalf("idle %q", m[1])
	}
	if regexp.MustCompile(`Mem: (.+) Active,`).FindStringSubmatch(a.Headers[3]) == nil {
		t.Fatalf("mem regex: %q", a.Headers[3])
	}
	w = get(opnsenseAuth(HandleOPNsenseInterfaces), "x", "k123")
	var i struct {
		Interfaces map[string]map[string]any
	}
	json.Unmarshal(w.Body.Bytes(), &i)
	if w.Code != 200 || i.Interfaces["lo"] == nil {
		t.Fatalf("interfaces: %d %s", w.Code, w.Body)
	}
	for _, k := range []string{"bytes received", "bytes transmitted"} {
		if _, ok := i.Interfaces["lo"][k]; !ok {
			t.Fatalf("missing %q", k)
		}
	}
}
