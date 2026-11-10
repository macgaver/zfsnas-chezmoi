package system

// Public address card for the Firewall pages: what is known about an
// Internet address. Shown on hover, with no third party told about it:
//   - reverse DNS (PTR) and whether each name resolves back (forward-confirmed)
//   - location and network from the local geo databases
//   - RDAP (the registry's "whois"): address block, owner, abuse contact
//   - three downloaded lists, checked locally: Spamhaus DROP, FireHOL
//     level 1, Tor exit nodes (refreshed daily with the geo databases)
//
// On a click only (each sends the address to that service):
//   - GreyNoise Community: Internet-wide scanner or not, benign or malicious
//   - Shodan InternetDB: its open ports, host names, tags, known CVEs
//   - AbuseIPDB: abuse reports and confidence score (free account key)

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/geoip"
)

const sdnIPIntelUA = "ZNAS-firewall/1.0"

// ── reputation lists ────────────────────────────────────────────────────

type sdnRepList struct {
	ID, Name, URL, About string
}

var sdnRepLists = []sdnRepList{
	{"spamhaus-drop", "Spamhaus DROP", "https://www.spamhaus.org/drop/drop_v4.json",
		"Address blocks hijacked or leased by spammers and cyber-criminals: no legitimate traffic comes from them"},
	{"firehol-level1", "FireHOL level 1", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
		"Attacks, malware, botnet command servers and hijacked blocks seen in the last days (several lists merged)"},
	{"tor-exit", "Tor exit node", "https://check.torproject.org/torbulkexitlist",
		"A Tor exit node: the real sender is hidden behind the Tor network"},
}

// SDNRepDir is where the downloaded lists live (next to the geo databases).
func SDNRepDir(geoDir string) string { return filepath.Join(geoDir, "reputation") }

// sdnParseRepList reads one downloaded list: one address or block per line,
// "#"/";" comments, or Spamhaus's JSON lines ({"cidr": …}).
func sdnParseRepList(r io.Reader) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		if l[0] == '{' {
			var j struct {
				CIDR string `json:"cidr"`
			}
			if json.Unmarshal([]byte(l), &j) != nil || j.CIDR == "" {
				continue
			}
			l = j.CIDR
		}
		if i := strings.IndexAny(l, " \t;"); i > 0 {
			l = l[:i]
		}
		if p, err := netip.ParsePrefix(l); err == nil && p.Addr().Is4() {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(l); err == nil && a.Is4() {
			out = append(out, netip.PrefixFrom(a, 32))
		}
	}
	return out
}

type sdnRepLoaded struct {
	mod      time.Time
	prefixes []netip.Prefix
}

var sdnRepMu sync.Mutex
var sdnRepCache = map[string]sdnRepLoaded{} // file path → parsed list

func sdnRepLoad(path string) ([]netip.Prefix, time.Time) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}
	}
	sdnRepMu.Lock()
	defer sdnRepMu.Unlock()
	if c, ok := sdnRepCache[path]; ok && c.mod.Equal(fi.ModTime()) {
		return c.prefixes, c.mod
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}
	}
	defer f.Close()
	ps := sdnParseRepList(f)
	sdnRepCache[path] = sdnRepLoaded{fi.ModTime(), ps}
	return ps, fi.ModTime()
}

// SDNRepHit is one list the address is on.
type SDNRepHit struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Entry string `json:"entry"` // the listed block, or the address itself
	About string `json:"about"`
}

// SDNRepListState is one list's download state.
type SDNRepListState struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Entries int       `json:"entries"`
	Updated time.Time `json:"updated,omitempty"`
}

func sdnRepCheck(dir string, a netip.Addr) (hits []SDNRepHit, lists []SDNRepListState) {
	for _, l := range sdnRepLists {
		ps, mod := sdnRepLoad(filepath.Join(dir, l.ID+".txt"))
		lists = append(lists, SDNRepListState{ID: l.ID, Name: l.Name, Entries: len(ps), Updated: mod})
		for _, p := range ps {
			if p.Contains(a) {
				e := p.String()
				if p.Bits() == 32 {
					e = p.Addr().String()
				}
				hits = append(hits, SDNRepHit{ID: l.ID, Name: l.Name, Entry: e, About: l.About})
				break
			}
		}
	}
	return hits, lists
}

var sdnRepUpdMu sync.Mutex

// SDNUpdateRepLists downloads every list older than 20 hours. A download
// that does not parse to at least one entry keeps the previous copy.
func SDNUpdateRepLists(dir string, now time.Time) error {
	sdnRepUpdMu.Lock()
	defer sdnRepUpdMu.Unlock()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	var errs []error
	for _, l := range sdnRepLists {
		dst := filepath.Join(dir, l.ID+".txt")
		if fi, err := os.Stat(dst); err == nil && now.Sub(fi.ModTime()) < 20*time.Hour {
			continue
		}
		if err := sdnRepFetch(l.URL, dst, now); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", l.Name, err))
		}
	}
	return errors.Join(errs...)
}

func sdnRepFetch(url, dst string, now time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", sdnIPIntelUA)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if len(sdnParseRepList(strings.NewReader(string(b)))) == 0 {
		return errors.New("the download holds no address")
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	_ = os.Chtimes(tmp, now, now)
	return os.Rename(tmp, dst)
}

// ── RDAP ───────────────────────────────────────────────────────────────

// SDNRDAP is the registry record of the address block.
type SDNRDAP struct {
	Registry string `json:"registry,omitempty"` // ARIN, RIPE NCC…
	Name     string `json:"name,omitempty"`     // the block's name (NET-…)
	Handle   string `json:"handle,omitempty"`
	Range    string `json:"range,omitempty"` // first – last address
	CIDR     string `json:"cidr,omitempty"`
	Country  string `json:"country,omitempty"`
	Org      string `json:"org,omitempty"` // registrant
	Abuse    string `json:"abuse,omitempty"`
	Created  string `json:"created,omitempty"`
	Updated  string `json:"updated,omitempty"`
	Link     string `json:"link,omitempty"`
}

type rdapEntity struct {
	Roles      []string        `json:"roles"`
	VCardArray json.RawMessage `json:"vcardArray"`
	Entities   []rdapEntity    `json:"entities"`
}

// vcard extracts "fn" and the first "email" of an RDAP jCard.
func (e rdapEntity) vcard() (fn, email string) {
	var v []json.RawMessage
	if json.Unmarshal(e.VCardArray, &v) != nil || len(v) < 2 {
		return
	}
	var props [][]json.RawMessage
	if json.Unmarshal(v[1], &props) != nil {
		return
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var name, val string
		_ = json.Unmarshal(p[0], &name)
		if json.Unmarshal(p[3], &val) != nil {
			continue
		}
		switch name {
		case "fn":
			if fn == "" {
				fn = val
			}
		case "email":
			if email == "" {
				email = val
			}
		}
	}
	return
}

func (e rdapEntity) has(role string) bool {
	for _, r := range e.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// sdnRDAPParse reads an RDAP "ip network" answer.
func sdnRDAPParse(b []byte) (SDNRDAP, error) {
	var j struct {
		Handle   string       `json:"handle"`
		Name     string       `json:"name"`
		Start    string       `json:"startAddress"`
		End      string       `json:"endAddress"`
		Country  string       `json:"country"`
		Port43   string       `json:"port43"`
		Entities []rdapEntity `json:"entities"`
		CIDRs    []struct {
			Prefix string `json:"v4prefix"`
			Length int    `json:"length"`
		} `json:"cidr0_cidrs"`
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Links []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
			Type string `json:"type"`
		} `json:"links"`
	}
	if err := json.Unmarshal(b, &j); err != nil {
		return SDNRDAP{}, err
	}
	r := SDNRDAP{Name: j.Name, Handle: j.Handle, Country: j.Country}
	if j.Start != "" {
		r.Range = j.Start + " – " + j.End
	}
	var cidrs []string
	for _, c := range j.CIDRs {
		if c.Prefix != "" {
			cidrs = append(cidrs, fmt.Sprintf("%s/%d", c.Prefix, c.Length))
		}
	}
	r.CIDR = strings.Join(cidrs, ", ")
	for _, e := range j.Events {
		d := e.Date
		if len(d) >= 10 {
			d = d[:10]
		}
		switch e.Action {
		case "registration":
			r.Created = d
		case "last changed":
			r.Updated = d
		}
	}
	for _, l := range j.Links {
		if l.Rel == "self" {
			r.Link = l.Href
		}
	}
	reg := strings.ToLower(j.Port43 + " " + r.Link)
	for k, v := range map[string]string{"arin": "ARIN", "ripe": "RIPE NCC", "apnic": "APNIC", "lacnic": "LACNIC", "afrinic": "AFRINIC"} {
		if strings.Contains(reg, k) {
			r.Registry = v
		}
	}
	// the owner and the abuse contact, at any depth (RIPE nests them)
	var walk func([]rdapEntity)
	walk = func(es []rdapEntity) {
		for _, e := range es {
			fn, email := e.vcard()
			if r.Org == "" && e.has("registrant") && fn != "" {
				r.Org = fn
			}
			if r.Abuse == "" && e.has("abuse") && email != "" {
				r.Abuse = email
			}
			walk(e.Entities)
		}
	}
	walk(j.Entities)
	return r, nil
}

var sdnRDAPBase = "https://rdap.org/ip/"

func sdnRDAPLookup(a netip.Addr) (SDNRDAP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", sdnRDAPBase+a.String(), nil)
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", sdnIPIntelUA)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return SDNRDAP{}, fmt.Errorf("registry not reachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return SDNRDAP{}, fmt.Errorf("registry busy, try again in a minute")
	}
	if resp.StatusCode != http.StatusOK {
		return SDNRDAP{}, fmt.Errorf("registry answered HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return SDNRDAP{}, err
	}
	return sdnRDAPParse(b)
}

// ── the card ───────────────────────────────────────────────────────────

// SDNPTRName is one reverse DNS name and whether it resolves back.
type SDNPTRName struct {
	Name      string `json:"name"`
	Confirmed bool   `json:"confirmed"` // its A records include the address
}

// SDNIPInfo is the public address card.
type SDNIPInfo struct {
	IP        string            `json:"ip"`
	Geo       geoip.Info        `json:"geo"`
	PTR       []SDNPTRName      `json:"ptr"`
	PTRError  string            `json:"ptr_error,omitempty"`
	RDAP      *SDNRDAP          `json:"rdap,omitempty"`
	RDAPError string            `json:"rdap_error,omitempty"`
	Lists     []SDNRepHit       `json:"lists"`
	ListState []SDNRepListState `json:"list_state"`
	Services  map[string]bool   `json:"services"` // which on-click lookups are usable
}

type sdnTimed[T any] struct {
	at  time.Time
	val T
	err string
}

var (
	sdnIntelMu   sync.Mutex
	sdnRDAPCache = map[netip.Addr]sdnTimed[SDNRDAP]{}
	sdnRevCache  = map[netip.Addr]sdnTimed[[]SDNPTRName]{}
	sdnExtCache  = map[string]sdnTimed[map[string]any]{}
)

// sdnIntelPrune keeps a cache bounded: entries older than ttl go, and when
// still too big, everything goes.
func sdnIntelPrune[K comparable, T any](m map[K]sdnTimed[T], ttl time.Duration, now time.Time) {
	if len(m) < 2000 {
		return
	}
	for k, v := range m {
		if now.Sub(v.at) > ttl {
			delete(m, k)
		}
	}
	if len(m) >= 2000 {
		clear(m)
	}
}

func sdnPTR(a netip.Addr) ([]SDNPTRName, string) {
	now := time.Now()
	sdnIntelMu.Lock()
	if c, ok := sdnRevCache[a]; ok && now.Sub(c.at) < time.Hour {
		sdnIntelMu.Unlock()
		return c.val, c.err
	}
	sdnIntelMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, a.String())
	out, msg := []SDNPTRName{}, ""
	var dnsErr *net.DNSError
	switch {
	case err != nil && errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		// no reverse name: an answer, not an error
	case err != nil:
		msg = "reverse lookup failed"
	}
	for i, n := range names {
		if i == 4 {
			break
		}
		n = strings.TrimSuffix(n, ".")
		p := SDNPTRName{Name: n}
		if ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", n); err == nil {
			for _, ip := range ips {
				if ip.Unmap() == a {
					p.Confirmed = true
				}
			}
		}
		out = append(out, p)
	}
	sdnIntelMu.Lock()
	sdnIntelPrune(sdnRevCache, time.Hour, now)
	sdnRevCache[a] = sdnTimed[[]SDNPTRName]{now, out, msg}
	sdnIntelMu.Unlock()
	return out, msg
}

func sdnRDAP(a netip.Addr) (*SDNRDAP, string) {
	now := time.Now()
	sdnIntelMu.Lock()
	if c, ok := sdnRDAPCache[a]; ok && (now.Sub(c.at) < 24*time.Hour && c.err == "" || now.Sub(c.at) < 5*time.Minute) {
		sdnIntelMu.Unlock()
		if c.err != "" {
			return nil, c.err
		}
		v := c.val
		return &v, ""
	}
	sdnIntelMu.Unlock()
	r, err := sdnRDAPLookup(a)
	e := ""
	if err != nil {
		e = err.Error()
	}
	sdnIntelMu.Lock()
	sdnIntelPrune(sdnRDAPCache, 24*time.Hour, now)
	sdnRDAPCache[a] = sdnTimed[SDNRDAP]{now, r, e}
	sdnIntelMu.Unlock()
	if e != "" {
		return nil, e
	}
	return &r, ""
}

// SDNIPInfoFor builds the card of a public address. Reverse DNS and RDAP
// run side by side; each has its own deadline.
func SDNIPInfoFor(a netip.Addr) SDNIPInfo {
	info := SDNIPInfo{IP: a.String(), PTR: []SDNPTRName{}, Lists: []SDNRepHit{}}
	if r := SDNGeo(); r != nil {
		info.Geo = r.Lookup(a)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); info.PTR, info.PTRError = sdnPTR(a) }()
	go func() { defer wg.Done(); info.RDAP, info.RDAPError = sdnRDAP(a) }()
	if st := SDNTrafficStatusNow(); st.StatsDir != "" {
		hits, lists := sdnRepCheck(SDNRepDir(SDNGeoDir(st.StatsDir)), a)
		if hits != nil {
			info.Lists = hits
		}
		info.ListState = lists
	}
	wg.Wait()
	k := SDNIPIntelKeysLoad()
	info.Services = map[string]bool{"greynoise": true, "shodan": true, "abuseipdb": k.AbuseIPDB != ""}
	return info
}

// ── on-click services ──────────────────────────────────────────────────

// SDNIPIntelKeys are the optional service keys (config/sdn/ipintel.json, 0600).
type SDNIPIntelKeys struct {
	AbuseIPDB string `json:"abuseipdb_key,omitempty"`
	GreyNoise string `json:"greynoise_key,omitempty"`
}

func sdnIPIntelKeysPath() string {
	if sdnConfigDir == "" {
		return ""
	}
	return filepath.Join(sdnConfigDir, "sdn", "ipintel.json")
}

// SDNIPIntelKeysLoad returns the saved keys (none when the file is missing).
func SDNIPIntelKeysLoad() SDNIPIntelKeys {
	var k SDNIPIntelKeys
	if p := sdnIPIntelKeysPath(); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(b, &k)
		}
	}
	return k
}

// SDNIPIntelKeysSave stores the keys.
func SDNIPIntelKeysSave(k SDNIPIntelKeys) error {
	path := sdnIPIntelKeysPath()
	if path == "" {
		return errors.New("the configuration directory is not set")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(k, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var sdnExtURL = map[string]string{
	"greynoise": "https://api.greynoise.io/v3/community/",
	"shodan":    "https://internetdb.shodan.io/",
	"abuseipdb": "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=",
}

// SDNIPExternal asks one outside service about the address (cached 6 hours).
// "found": false means the service knows nothing about it.
func SDNIPExternal(service string, a netip.Addr, keys SDNIPIntelKeys) (map[string]any, error) {
	base, ok := sdnExtURL[service]
	if !ok {
		return nil, errors.New("unknown service")
	}
	if service == "abuseipdb" && keys.AbuseIPDB == "" {
		return nil, errors.New("AbuseIPDB needs a free API key: add it first")
	}
	ck := service + "|" + a.String()
	now := time.Now()
	sdnIntelMu.Lock()
	if c, ok := sdnExtCache[ck]; ok && now.Sub(c.at) < 6*time.Hour {
		sdnIntelMu.Unlock()
		return c.val, nil
	}
	sdnIntelMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", base+a.String(), nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", sdnIPIntelUA)
	switch service {
	case "abuseipdb":
		req.Header.Set("Key", keys.AbuseIPDB)
	case "greynoise":
		if keys.GreyNoise != "" {
			req.Header.Set("key", keys.GreyNoise)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s is not reachable", service)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var v map[string]any
	_ = json.Unmarshal(b, &v)
	switch {
	case resp.StatusCode == http.StatusNotFound:
		// GreyNoise and InternetDB: never seen
		v = map[string]any{"found": false}
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, errors.New("daily limit of this free service reached, try again later")
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, errors.New("the service refused the API key")
	case resp.StatusCode != http.StatusOK || v == nil:
		return nil, fmt.Errorf("the service answered HTTP %d", resp.StatusCode)
	default:
		if d, ok := v["data"].(map[string]any); ok && service == "abuseipdb" {
			v = d
		}
		v["found"] = true
	}
	sdnIntelMu.Lock()
	sdnIntelPrune(sdnExtCache, 6*time.Hour, now)
	sdnExtCache[ck] = sdnTimed[map[string]any]{now, v, ""}
	sdnIntelMu.Unlock()
	return v, nil
}
