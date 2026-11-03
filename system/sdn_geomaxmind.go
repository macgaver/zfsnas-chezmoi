package system

// MaxMind GeoLite2 as an alternative to the free DB-IP Lite databases: the
// admin brings a MaxMind account ID and license key (GeoLite2 needs a free
// account and its EULA accepted), the databases are fetched twice a week into
// <geo dir>/maxmind and checked against MaxMind's SHA-256 before use. DB-IP
// stays in place as the fallback while GeoLite2 is not downloaded yet.

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/geoip"
)

// SDNGeoProvider is the location database choice (config/sdn/geo.json).
// The MaxMind credentials are kept when going back to DB-IP, so switching
// back needs no retyping.
type SDNGeoProvider struct {
	Provider   string `json:"provider"` // "dbip" (default) | "maxmind"
	AccountID  string `json:"account_id,omitempty"`
	LicenseKey string `json:"license_key,omitempty"`
}

// MaxMindConfigured: credentials are saved.
func (p SDNGeoProvider) MaxMindConfigured() bool { return p.AccountID != "" && p.LicenseKey != "" }

// UseMaxMind: GeoLite2 is the chosen source.
func (p SDNGeoProvider) UseMaxMind() bool { return p.Provider == "maxmind" && p.MaxMindConfigured() }

var sdnMaxMindBase = "https://download.maxmind.com/geoip/databases"

var sdnMaxMindEditions = []struct{ kind, edition string }{
	{"country", "GeoLite2-Country"},
	{"city", "GeoLite2-City"},
	{"asn", "GeoLite2-ASN"},
}

// MaxMind publishes GeoLite2 on Tuesdays and Fridays.
const sdnMaxMindMaxAge = 3 * 24 * time.Hour

func sdnMaxMindDir(geoDir string) string { return filepath.Join(geoDir, "maxmind") }
func sdnMaxMindFile(geoDir, edition string) string {
	return filepath.Join(sdnMaxMindDir(geoDir), edition+".mmdb")
}

func sdnGeoProviderPath() string {
	if sdnConfigDir == "" {
		return ""
	}
	return filepath.Join(sdnConfigDir, "sdn", "geo.json")
}

// SDNGeoProviderLoad returns the saved choice (DB-IP when none).
func SDNGeoProviderLoad() SDNGeoProvider {
	p := SDNGeoProvider{Provider: "dbip"}
	if path := sdnGeoProviderPath(); path != "" {
		if b, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(b, &p)
		}
	}
	if p.Provider != "maxmind" {
		p.Provider = "dbip"
	}
	return p
}

// SDNGeoProviderSave stores the choice (0600: it holds the license key).
func SDNGeoProviderSave(p SDNGeoProvider) error {
	path := sdnGeoProviderPath()
	if path == "" {
		return errors.New("the configuration directory is not set")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// sdnGeoFiles returns the database paths in use in geoDir and the source
// they come from: GeoLite2 once chosen and downloaded, else DB-IP.
func sdnGeoActive(geoDir string) (country, city, asn, source string) {
	if SDNGeoProviderLoad().UseMaxMind() {
		c, ci := sdnMaxMindFile(geoDir, "GeoLite2-Country"), sdnMaxMindFile(geoDir, "GeoLite2-City")
		if fileExists(c) || fileExists(ci) {
			return c, ci, sdnMaxMindFile(geoDir, "GeoLite2-ASN"), "maxmind"
		}
	}
	return filepath.Join(geoDir, geoip.CountryFile), filepath.Join(geoDir, geoip.CityFile), filepath.Join(geoDir, geoip.ASNFile), "dbip"
}

// SDNGeoSource says which databases answer lookups now ("dbip" | "maxmind").
func SDNGeoSource(geoDir string) string { _, _, _, s := sdnGeoActive(geoDir); return s }

// SDNGeoAttribution is the credit line the licenses ask for.
func SDNGeoAttribution(geoDir string) string {
	if SDNGeoSource(geoDir) == "maxmind" {
		return "This product includes GeoLite Data created by MaxMind, available from https://www.maxmind.com"
	}
	return "IP geolocation by DB-IP.com (CC BY 4.0)"
}

// sdnMaxMindGet asks MaxMind for one file of an edition (suffix "tar.gz" or
// "tar.gz.sha256"). The download redirects to a signed storage URL, which
// gets no credentials.
func sdnMaxMindGet(p SDNGeoProvider, edition, suffix string, timeout time.Duration) (*http.Response, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s/download?suffix=%s", sdnMaxMindBase, edition, suffix), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(p.AccountID, p.LicenseKey)
	client := &http.Client{Timeout: timeout, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		r.Header.Del("Authorization") // the signed storage URL needs no credentials: never hand them on
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("MaxMind is not reachable: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, sdnMaxMindStatusErr(resp.StatusCode)
	}
	return resp, nil
}

func sdnMaxMindStatusErr(code int) error {
	switch code {
	case http.StatusUnauthorized:
		return errors.New("MaxMind refused the account ID or license key")
	case http.StatusForbidden:
		return errors.New("this MaxMind account may not download GeoLite2 (accept the GeoLite2 EULA in your MaxMind account)")
	case http.StatusTooManyRequests:
		return errors.New("MaxMind's daily download limit is reached for this account: try again tomorrow")
	case http.StatusNotFound:
		return errors.New("MaxMind has no such database")
	}
	return fmt.Errorf("MaxMind answered HTTP %d", code)
}

// sdnMaxMindSum fetches the published SHA-256 of an edition's archive.
func sdnMaxMindSum(p SDNGeoProvider, edition string) (string, error) {
	resp, err := sdnMaxMindGet(p, edition, "tar.gz.sha256", 30*time.Second)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 || len(f[0]) != 64 {
		return "", errors.New("MaxMind sent an unreadable checksum")
	}
	if _, err := hex.DecodeString(f[0]); err != nil {
		return "", errors.New("MaxMind sent an unreadable checksum")
	}
	return strings.ToLower(f[0]), nil
}

// SDNMaxMindTest checks the credentials without downloading a database.
func SDNMaxMindTest(p SDNGeoProvider) error {
	if strings.TrimSpace(p.AccountID) == "" || strings.TrimSpace(p.LicenseKey) == "" {
		return errors.New("enter the account ID and the license key")
	}
	_, err := sdnMaxMindSum(p, "GeoLite2-City")
	return err
}

// sdnUpdateMaxMind downloads the editions older than three days. An archive
// whose checksum matches the installed one is not downloaded again (MaxMind
// counts downloads per day).
func sdnUpdateMaxMind(geoDir string, p SDNGeoProvider, now time.Time, force bool) error {
	if err := os.MkdirAll(sdnMaxMindDir(geoDir), 0755); err != nil {
		return err
	}
	var errs []error
	for _, e := range sdnMaxMindEditions {
		dst := sdnMaxMindFile(geoDir, e.edition)
		if fi, err := os.Stat(dst); err == nil && !force && now.Sub(fi.ModTime()) < sdnMaxMindMaxAge {
			continue
		}
		if err := sdnMaxMindFetch(p, e.edition, dst, now); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.edition, err))
		}
	}
	return errors.Join(errs...)
}

func sdnMaxMindFetch(p SDNGeoProvider, edition, dst string, now time.Time) error {
	sum, err := sdnMaxMindSum(p, edition)
	if err != nil {
		return err
	}
	sumFile := dst + ".sha256"
	if old, _ := os.ReadFile(sumFile); strings.TrimSpace(string(old)) == sum && fileExists(dst) {
		return os.Chtimes(dst, now, now) // unchanged since the last download
	}
	resp, err := sdnMaxMindGet(p, edition, "tar.gz", 15*time.Minute)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	h := sha256.New()
	body := io.TeeReader(io.LimitReader(resp.Body, 1<<30), h)
	tmp := dst + ".tmp"
	found, err := sdnExtractMMDB(body, edition+".mmdb", tmp)
	if err == nil {
		_, err = io.Copy(io.Discard, body) // the checksum covers the whole archive
	}
	if err == nil && !found {
		err = fmt.Errorf("the archive has no %s.mmdb", edition)
	}
	if err == nil && hex.EncodeToString(h.Sum(nil)) != sum {
		err = errors.New("the download does not match MaxMind's checksum")
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	db, err := geoip.Open(tmp)
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("downloaded file is not a valid database: %w", err)
	}
	db.Close()
	_ = os.Chtimes(tmp, now, now)
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	return os.WriteFile(sumFile, []byte(sum+"\n"), 0644)
}

// sdnExtractMMDB writes the archive member named name (in its dated folder)
// to dst.
func sdnExtractMMDB(r io.Reader, name, dst string) (bool, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return false, err
	}
	tr := tar.NewReader(zr)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, err
		}
		if found || hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != name {
			continue
		}
		f, err := os.Create(dst)
		if err != nil {
			return false, err
		}
		_, cerr := io.Copy(f, io.LimitReader(tr, 1<<30))
		if err := f.Close(); cerr == nil {
			cerr = err
		}
		if cerr != nil {
			return false, cerr
		}
		found = true
	}
	_, _ = io.Copy(io.Discard, zr)
	return found, nil
}

// A download started from the settings runs in the background; the page
// asks how it went.
var (
	sdnGeoJobMu sync.Mutex
	sdnGeoJob   SDNGeoJob
	sdnGeoUpdMu sync.Mutex // one update at a time (daily loop, button, settings)
)

// SDNGeoJob is the state of the last background download.
type SDNGeoJob struct {
	Running  bool      `json:"running"`
	Error    string    `json:"error,omitempty"`
	Finished time.Time `json:"finished,omitempty"`
}

func SDNGeoJobNow() SDNGeoJob {
	sdnGeoJobMu.Lock()
	defer sdnGeoJobMu.Unlock()
	return sdnGeoJob
}

// SDNGeoUpdateAsync downloads what the chosen source lacks, then reopens
// the databases.
func SDNGeoUpdateAsync(geoDir string) {
	sdnGeoJobMu.Lock()
	if sdnGeoJob.Running {
		sdnGeoJobMu.Unlock()
		return
	}
	sdnGeoJob = SDNGeoJob{Running: true}
	sdnGeoJobMu.Unlock()
	go func() {
		err := SDNUpdateGeoDB(geoDir, time.Now())
		SDNSetGeoDir(geoDir)
		sdnGeoJobMu.Lock()
		sdnGeoJob = SDNGeoJob{Finished: time.Now()}
		if err != nil {
			sdnGeoJob.Error = err.Error()
		}
		sdnGeoJobMu.Unlock()
	}()
}
