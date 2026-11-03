package system

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"zfsnas/internal/geoip"
)

func gz(t *testing.T, b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func TestSDNUpdateGeoDB(t *testing.T) {
	mmdb, err := os.ReadFile("testdata/tiny-country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		if strings.Contains(r.URL.Path, "2026-10") { // current month not published yet → fall back
			http.NotFound(w, r)
			return
		}
		if strings.Contains(r.URL.Path, "city") {
			_, _ = w.Write(gz(t, []byte("not a database")))
			return
		}
		_, _ = w.Write(gz(t, mmdb))
	}))
	defer srv.Close()
	old := sdnGeoBaseURL
	sdnGeoBaseURL = srv.URL + "/free"
	t.Cleanup(func() { sdnGeoBaseURL = old })
	dir := t.TempDir()
	err = SDNUpdateGeoDB(dir, time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "city") {
		t.Fatalf("a corrupt download must be reported: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "dbip-country-lite.mmdb")); err != nil {
		t.Fatal("country DB not installed")
	}
	if _, err := os.Stat(filepath.Join(dir, "dbip-city-lite.mmdb")); err == nil {
		t.Fatal("a corrupt city DB must not be installed")
	}
	if !strings.Contains(strings.Join(asked, " "), "dbip-country-lite-2026-09.mmdb.gz") {
		t.Fatalf("no fallback to the previous month: %v", asked)
	}
	// Fresh files are not downloaded again.
	asked = nil
	_ = SDNUpdateGeoDB(dir, time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC))
	for _, a := range asked {
		if strings.Contains(a, "country") {
			t.Fatalf("fresh country DB downloaded again: %v", asked)
		}
	}
}

// Boot can run before the pool holding the geo database is available: the
// country networks of the last apply are cached in the config dir.
func TestSDNCountryCIDRs_CacheFallback(t *testing.T) {
	dir := t.TempDir()
	old := sdnGeo
	t.Cleanup(func() { sdnGeo = old })
	sdnGeo = nil
	_ = SDNSaveCountryCache(dir, map[string][]string{"SE": {"89.160.20.0/23"}})
	f := SDNCountryCIDRsFunc(dir)
	got, err := f("SE")
	if err != nil || len(got) != 1 || got[0] != "89.160.20.0/23" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := f("CA"); err == nil {
		t.Fatal("unknown country without a database must be an error")
	}
}

// A compile holding the resolver while another start-up path sets the geo
// dir again must keep working (was: "read …mmdb: file already closed").
func TestSDNSetGeoDir_HeldResolverStaysUsable(t *testing.T) {
	mmdb, err := os.ReadFile("testdata/tiny-country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, geoip.CountryFile), mmdb, 0644)
	t.Cleanup(func() { SDNSetGeoDir(t.TempDir()) })
	SDNSetGeoDir(dir)
	held := SDNGeo()
	if held == nil {
		t.Fatal("no resolver")
	}
	SDNSetGeoDir(dir) // same dir again: kept
	if SDNGeo() != held {
		t.Fatal("same dir reopened")
	}
	other := t.TempDir()
	_ = os.WriteFile(filepath.Join(other, geoip.CountryFile), mmdb, 0644)
	SDNSetGeoDir(other) // moved: the old one is replaced but not closed under the holder
	if _, err := held.CountryCIDRs("SE"); err != nil {
		t.Fatalf("held resolver closed: %v", err)
	}
}
