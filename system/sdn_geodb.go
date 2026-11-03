package system

// DB-IP Lite geolocation databases (country, city, ASN; CC BY 4.0) for the
// Firewall's traffic statistics and country rules. Downloaded monthly into
// the stats directory (a pool dataset — never the appliance's USB stick).

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"zfsnas/internal/geoip"
)

var sdnGeoBaseURL = "https://download.db-ip.com/free"

var sdnGeoFiles = []struct{ kind, file string }{
	{"country", geoip.CountryFile},
	{"city", geoip.CityFile},
	{"asn", geoip.ASNFile},
}

// SDNGeoDir is where the databases live inside the stats directory.
func SDNGeoDir(statsDir string) string { return filepath.Join(statsDir, "geo") }

// SDNUpdateGeoDB downloads any database older than 32 days (DB-IP publishes
// monthly; the current month may not be out yet early in the month, so the
// previous one is tried too). Each file is checked to open as a database
// before it replaces the old one. Returns the first error but keeps going.
func SDNUpdateGeoDB(dir string, now time.Time) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	var errs []error
	for _, f := range sdnGeoFiles {
		dst := filepath.Join(dir, f.file)
		if fi, err := os.Stat(dst); err == nil && now.Sub(fi.ModTime()) < 32*24*time.Hour {
			continue
		}
		var err error
		for _, m := range []time.Time{now, now.AddDate(0, -1, 0)} {
			url := fmt.Sprintf("%s/dbip-%s-lite-%s.mmdb.gz", sdnGeoBaseURL, f.kind, m.Format("2006-01"))
			if err = sdnGeoFetch(url, dst, now); err == nil || !errors.Is(err, errGeoNotFound) {
				break
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s database: %w", f.kind, err))
		}
	}
	return errors.Join(errs...)
}

var errGeoNotFound = errors.New("not published")

func sdnGeoFetch(url, dst string, now time.Time) error {
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errGeoNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, cerr := io.Copy(f, io.LimitReader(zr, 1<<30))
	if err := f.Close(); cerr == nil {
		cerr = err
	}
	if cerr != nil {
		os.Remove(tmp)
		return cerr
	}
	db, err := geoip.Open(tmp)
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("downloaded file is not a valid database: %w", err)
	}
	db.Close()
	_ = os.Chtimes(tmp, now, now)
	return os.Rename(tmp, dst)
}

// SDNGeoStatus describes the installed databases for the UI.
type SDNGeoStatus struct {
	File    string    `json:"file"`
	Present bool      `json:"present"`
	Updated time.Time `json:"updated,omitempty"`
}

func SDNGeoDBStatus(dir string) []SDNGeoStatus {
	var out []SDNGeoStatus
	for _, f := range sdnGeoFiles {
		s := SDNGeoStatus{File: f.file}
		if fi, err := os.Stat(filepath.Join(dir, f.file)); err == nil {
			s.Present, s.Updated = true, fi.ModTime()
		}
		out = append(out, s)
	}
	return out
}

// sdnGeo is the open resolver for the current stats directory (nil until
// the geo databases are present).
var (
	sdnGeo      *geoip.Resolver
	sdnGeoStamp string // dir + country file mtime of sdnGeo
	sdnGeoMu    sync.Mutex
)

// SDNSetGeoDir (re)opens the databases in dir.
func SDNSetGeoDir(dir string) {
	stamp := dir
	if fi, err := os.Stat(filepath.Join(dir, geoip.CountryFile)); err == nil {
		stamp += "@" + fi.ModTime().String()
	}
	sdnGeoMu.Lock()
	if sdnGeo != nil && stamp == sdnGeoStamp {
		sdnGeoMu.Unlock()
		return // same databases: callers may be using the open ones
	}
	sdnGeoMu.Unlock()
	r := geoip.NewResolver(dir)
	sdnGeoMu.Lock()
	old := sdnGeo
	if r.HasCountry() {
		sdnGeo, sdnGeoStamp = r, stamp
	} else {
		sdnGeo, sdnGeoStamp = nil, ""
		r.Close()
	}
	sdnGeoMu.Unlock()
	if old != nil {
		// A compile or a lookup may still hold the old resolver: close it
		// once they are surely done with it.
		time.AfterFunc(2*time.Minute, old.Close)
	}
}

// SDNGeo returns the current resolver (may be nil).
func SDNGeo() *geoip.Resolver {
	sdnGeoMu.Lock()
	defer sdnGeoMu.Unlock()
	return sdnGeo
}

func countryCachePath(configDir string) string {
	return filepath.Join(configDir, "sdn", "country-cache.json")
}

// SDNSaveCountryCache stores the country networks used by the last apply.
func SDNSaveCountryCache(configDir string, m map[string][]string) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_ = os.MkdirAll(filepath.Dir(countryCachePath(configDir)), 0700)
	return os.WriteFile(countryCachePath(configDir), b, 0600)
}

// SDNCountryCIDRsFunc gives the compiler a country lookup: the geo database
// when open, else the cache of the last apply.
func SDNCountryCIDRsFunc(configDir string) func(string) ([]string, error) {
	var cache map[string][]string
	return func(cc string) ([]string, error) {
		if r := SDNGeo(); r != nil {
			return r.CountryCIDRs(cc)
		}
		if cache == nil {
			cache = map[string][]string{}
			if b, err := os.ReadFile(countryCachePath(configDir)); err == nil {
				_ = json.Unmarshal(b, &cache)
			}
		}
		if v, ok := cache[cc]; ok {
			return v, nil
		}
		return nil, errors.New("country database not available — download it from Firewall → Traffic first")
	}
}
