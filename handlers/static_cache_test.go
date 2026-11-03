package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// A new binary must reach the browser without a hard refresh: script and style
// files revalidate on every load, and an unchanged one answers 304.
func TestStaticAssets_Revalidate(t *testing.T) {
	h := staticAssets(fstest.MapFS{"a.js": {Data: []byte("one")}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/a.js", nil))
	etag := rec.Header().Get("ETag")
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-cache" || etag == "" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	req := httptest.NewRequest("GET", "/a.js", nil)
	req.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("unchanged file: %d", rec.Code)
	}
	// the same name in a new build
	h = staticAssets(fstest.MapFS{"a.js": {Data: []byte("two")}})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "two" {
		t.Fatalf("changed file: %d %q", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/missing.js", nil))
	if rec.Code != 404 {
		t.Fatalf("missing: %d", rec.Code)
	}
}

// Asking for more than the cap gives the cap, not the small default.
func TestSDNTrafficLimit(t *testing.T) {
	for in, want := range map[int]int{0: 100, -1: 100, 50: 50, 2000: 2000, 9000: 2000} {
		if got := sdnTrafficLimit(in); got != want {
			t.Errorf("%d: got %d, want %d", in, got, want)
		}
	}
}
