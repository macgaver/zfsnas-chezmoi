package system

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func mmTarGz(t *testing.T, edition string, mmdb []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	dir := edition + "_20261031/"
	for _, f := range []struct {
		name string
		body []byte
	}{{dir + "LICENSE.txt", []byte("license")}, {dir + edition + ".mmdb", mmdb}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write(f.body)
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

func TestSDNMaxMind(t *testing.T) {
	mmdb, err := os.ReadFile("testdata/tiny-country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var asked []string
	badSum := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path+"?"+r.URL.RawQuery)
		mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/storage/") { // the signed redirect target: no credentials sent there
			if r.Header.Get("Authorization") != "" {
				t.Errorf("credentials sent to the storage host")
			}
			ed := strings.TrimPrefix(r.URL.Path, "/storage/")
			_, _ = w.Write(mmTarGz(t, ed, mmdb))
			return
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "12345" || p != "goodkey" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ed := strings.Split(strings.TrimPrefix(r.URL.Path, "/geoip/databases/"), "/")[0]
		switch r.URL.Query().Get("suffix") {
		case "tar.gz.sha256":
			s := sha256.Sum256(mmTarGz(t, ed, mmdb))
			h := hex.EncodeToString(s[:])
			if badSum {
				h = strings.Repeat("0", 64)
			}
			_, _ = w.Write([]byte(h + "  " + ed + "_20261031.tar.gz\n"))
		case "tar.gz":
			http.Redirect(w, r, "/storage/"+ed, http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	oldBase, oldCfg := sdnMaxMindBase, sdnConfigDir
	sdnMaxMindBase = srv.URL + "/geoip/databases"
	sdnConfigDir = t.TempDir()
	t.Cleanup(func() { sdnMaxMindBase, sdnConfigDir = oldBase, oldCfg })

	if err := SDNMaxMindTest(SDNGeoProvider{AccountID: "12345", LicenseKey: "bad"}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("bad key must be refused: %v", err)
	}
	good := SDNGeoProvider{Provider: "maxmind", AccountID: "12345", LicenseKey: "goodkey"}
	if err := SDNMaxMindTest(good); err != nil {
		t.Fatal(err)
	}

	geo := t.TempDir()
	if SDNGeoSource(geo) != "dbip" {
		t.Fatal("DB-IP must be the default")
	}
	if err := SDNGeoProviderSave(good); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(sdnGeoProviderPath()); fi.Mode().Perm() != 0600 {
		t.Fatalf("geo.json holds the key: mode %v", fi.Mode().Perm())
	}
	if SDNGeoSource(geo) != "dbip" {
		t.Fatal("GeoLite2 chosen but not downloaded: DB-IP must still answer")
	}

	// a wrong checksum installs nothing
	badSum = true
	if err := SDNUpdateGeoDB(geo, time.Now()); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("checksum mismatch not reported: %v", err)
	}
	if _, err := os.Stat(sdnMaxMindFile(geo, "GeoLite2-Country")); err == nil {
		t.Fatal("a file failing the checksum was installed")
	}
	badSum = false
	if err := SDNUpdateGeoDB(geo, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, e := range sdnMaxMindEditions {
		if _, err := os.Stat(sdnMaxMindFile(geo, e.edition)); err != nil {
			t.Fatalf("%s not installed", e.edition)
		}
	}
	if SDNGeoSource(geo) != "maxmind" || !strings.Contains(SDNGeoAttribution(geo), "MaxMind") {
		t.Fatal("GeoLite2 downloaded but not in use")
	}
	st := SDNGeoDBStatus(geo)
	if len(st) != 3 || st[0].File != "GeoLite2-Country.mmdb" || !st[0].Present {
		t.Fatalf("status: %+v", st)
	}

	// fresh: nothing asked; old but unchanged: checksum only, no download
	mu.Lock()
	asked = nil
	mu.Unlock()
	_ = SDNUpdateGeoDB(geo, time.Now().Add(time.Hour))
	if len(asked) != 0 {
		t.Fatalf("fresh databases fetched again: %v", asked)
	}
	_ = SDNUpdateGeoDB(geo, time.Now().Add(4*24*time.Hour))
	for _, a := range asked {
		if strings.Contains(a, "suffix=tar.gz") && !strings.Contains(a, "sha256") {
			t.Fatalf("unchanged database downloaded again: %v", asked)
		}
	}

	// back to DB-IP keeps the credentials
	good.Provider = "dbip"
	_ = SDNGeoProviderSave(good)
	if p := SDNGeoProviderLoad(); p.UseMaxMind() || !p.MaxMindConfigured() || SDNGeoSource(geo) != "dbip" {
		t.Fatalf("switch back: %+v", p)
	}
}
