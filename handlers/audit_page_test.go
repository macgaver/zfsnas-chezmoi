package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"zfsnas/internal/audit"
)

// The drawer's poll: only the newest rows, the full count, and 304 until the
// log changes. Without a limit (the Activity page) everything comes back.
func TestAuditLog_LimitAndNotModified(t *testing.T) {
	dir := t.TempDir()
	audit.Init(dir)
	path := filepath.Join(dir, "audit.log")
	line := func(a string) string {
		return `{"timestamp":"2026-01-01T00:00:00Z","user":"u","action":"` + a + `","result":"ok"}` + "\n"
	}
	if err := os.WriteFile(path, []byte(line("a")+line("b")+line("c")), 0o640); err != nil {
		t.Fatal(err)
	}
	get := func(url, etag string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", url, nil)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		rec := httptest.NewRecorder()
		HandleAuditLog(rec, req)
		return rec
	}
	actions := func(rec *httptest.ResponseRecorder) string {
		var es []audit.Entry
		if err := json.Unmarshal(rec.Body.Bytes(), &es); err != nil {
			t.Fatal(err)
		}
		s := ""
		for _, e := range es {
			s += e.Action
		}
		return s
	}
	r := get("/api/audit?limit=2", "")
	if r.Code != 200 || actions(r) != "bc" || r.Header().Get("X-Audit-Total") != "3" {
		t.Fatalf("limit: %d %q %v", r.Code, actions(r), r.Header())
	}
	tag := r.Header().Get("ETag")
	if r := get("/api/audit?limit=2", tag); r.Code != http.StatusNotModified || r.Body.Len() != 0 {
		t.Fatalf("unchanged: %d", r.Code)
	}
	if r := get("/api/audit?limit=3", tag); r.Code != 200 {
		t.Fatalf("a wider window is a different answer: %d", r.Code)
	}
	if r := get("/api/audit", ""); actions(r) != "abc" {
		t.Fatalf("no limit: %q", actions(r))
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o640)
	f.WriteString(line("d"))
	f.Close()
	if r := get("/api/audit?limit=2", tag); r.Code != 200 || actions(r) != "cd" {
		t.Fatalf("changed: %d %q", r.Code, actions(r))
	}
}

// A stylesheet from Google must never hold up the first paint: on a VPN with no
// Internet route it would wait for a timeout.
func TestExternalFontsDoNotBlockRender(t *testing.T) {
	css, err := os.ReadFile("../static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?m)^\s*@import\s+url\(['"]?https?:`).Match(css) {
		t.Error("style.css imports an external stylesheet")
	}
	link := regexp.MustCompile(`<link rel="stylesheet"[^>]*fonts\.googleapis\.com[^>]*>`)
	for _, p := range []string{"../static/index.html", "../static/login.html", "../static/setup.html", "terminal_multi.go"} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range link.FindAll(b, -1) {
			if !strings.Contains(string(m), `media="print"`) {
				t.Errorf("%s: blocking font link: %s", p, m)
			}
		}
	}
}
