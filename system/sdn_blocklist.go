package system

// DNS blocklists (Firewall → DHCP & DNS → Local DNS): lists of domains
// fetched from URLs every day, merged with the admin's blocked domains,
// minus the allowed ones, into one hosts file the DNS server reads
// (addn-hosts). Updating the file only tells the server to read it again
// (SIGHUP): no restart, no countdown.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/sdn"
)

const (
	sdnBlocklistMaxPerList = 2_000_000
	sdnBlocklistMaxBytes   = 128 << 20
	sdnBlocklistEvery      = 24 * time.Hour
)

var blocklistDomainRe = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// names a hosts file maps for the machine itself
var blocklistSkip = map[string]bool{"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true, "ip6-allnodes": true,
	"ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true}

// parseBlocklist reads hosts ("0.0.0.0 name"), plain ("name") and Adblock
// ("||name^") lines.
func parseBlocklist(r io.Reader, max int) []string {
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() && len(seen) < max {
		l := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if l == "" || l[0] == '!' || strings.HasPrefix(l, "@@") || l[0] == '[' {
			continue
		}
		var name string
		switch f := strings.Fields(l); {
		case strings.HasPrefix(l, "||"):
			name, _, _ = strings.Cut(l[2:], "^")
		case len(f) >= 2:
			if _, err := netip.ParseAddr(f[0]); err != nil {
				continue
			}
			name = f[1]
		case len(f) == 1:
			name = f[0]
		default:
			continue
		}
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if blocklistSkip[name] || !blocklistDomainRe.MatchString(name) {
			continue
		}
		if _, err := netip.ParseAddr(name); err == nil {
			continue
		}
		seen[name] = true
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// renderBlocklistHosts merges the lists and the blocked domains, minus the
// allowed ones. Every name twice: IPv4 and IPv6.
func renderBlocklistHosts(lists [][]string, allow, deny []string) (string, int) {
	set := map[string]bool{}
	for _, l := range lists {
		for _, d := range l {
			set[d] = true
		}
	}
	for _, d := range deny {
		set[d] = true
	}
	for _, d := range allow {
		delete(set, d)
	}
	names := make([]string, 0, len(set))
	for d := range set {
		names = append(names, d)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# Written by ZNAS (Firewall → Local DNS blocklists); rewritten at every update.\n")
	for _, d := range names {
		b.WriteString("0.0.0.0 " + d + "\n:: " + d + "\n")
	}
	return b.String(), len(names)
}

// SDNBlocklistState is shown on the DNS editor and the reports.
type SDNBlocklistState struct {
	Domains int                           `json:"domains"` // blocked names in the file
	Built   time.Time                     `json:"built"`
	Hash    string                        `json:"hash"` // of what the file was built from
	Lists   map[string]SDNBlocklistStatus `json:"lists"`
}

// SDNBlocklistStatus is one list's last download.
type SDNBlocklistStatus struct {
	URL     string    `json:"url"`
	Domains int       `json:"domains"`
	Updated time.Time `json:"updated"`         // last successful download
	Tried   time.Time `json:"tried"`           // last attempt
	Error   string    `json:"error,omitempty"` // of the last attempt
}

type sdnBlocklists struct {
	mu        sync.Mutex
	statePath string
	cacheDir  string              // lists' domains between runs ("" = memory)
	cache     map[string][]string // by list id
	fetch     func(url string) ([]string, error)
	state     SDNBlocklistState
	loaded    bool
}

func (m *sdnBlocklists) loadState() {
	if m.loaded {
		return
	}
	m.loaded = true
	if b, err := os.ReadFile(m.statePath); err == nil {
		_ = json.Unmarshal(b, &m.state)
	}
	if m.state.Lists == nil {
		m.state.Lists = map[string]SDNBlocklistStatus{}
	}
}

func (m *sdnBlocklists) cached(id string) ([]string, bool) {
	if d, ok := m.cache[id]; ok {
		return d, true
	}
	if m.cacheDir == "" {
		return nil, false
	}
	f, err := os.Open(filepath.Join(m.cacheDir, id+".txt"))
	if err != nil {
		return nil, false
	}
	defer f.Close()
	d := parseBlocklist(f, sdnBlocklistMaxPerList)
	m.cache[id] = d
	return d, true
}

func (m *sdnBlocklists) keep(id string, d []string) {
	m.cache[id] = d
	if m.cacheDir == "" {
		return
	}
	if err := os.MkdirAll(m.cacheDir, 0755); err == nil {
		_ = os.WriteFile(filepath.Join(m.cacheDir, id+".txt"), []byte(strings.Join(d, "\n")+"\n"), 0644)
	}
}

// update downloads the lists due (all of them with force) and rebuilds the
// DNS server's file when what it is built from changed.
func (m *sdnBlocklists) update(c *sdn.Config, now time.Time, force bool) SDNBlocklistState {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadState()
	var lists [][]string
	h := sha256.New()
	enabled := map[string]bool{}
	for _, l := range c.DNS.Blocklists {
		if !l.Enabled || !c.DNS.Enabled {
			continue
		}
		enabled[l.ID] = true
		st := m.state.Lists[l.ID]
		domains, have := m.cached(l.ID)
		if st.URL != l.URL { // a new address: what we had is another list
			have, domains, st = false, nil, SDNBlocklistStatus{URL: l.URL}
		}
		if force || !have || now.Sub(st.Updated) >= sdnBlocklistEvery && now.Sub(st.Tried) >= time.Hour {
			st.Tried = now
			if d, err := m.fetch(l.URL); err != nil {
				st.Error = err.Error()
			} else {
				domains, have = d, true
				m.keep(l.ID, d)
				st.Updated, st.Error, st.Domains = now, "", len(d)
			}
		}
		m.state.Lists[l.ID] = st
		if have {
			lists = append(lists, domains)
			fmt.Fprintf(h, "%s %d %d\n", l.ID, st.Updated.Unix(), len(domains))
		}
	}
	for id := range m.state.Lists {
		if !enabled[id] {
			delete(m.state.Lists, id)
			delete(m.cache, id)
		}
	}
	if !c.DNS.Enabled {
		c = &sdn.Config{} // DNS off: nothing to block
	}
	fmt.Fprintf(h, "allow %v\ndeny %v\n", c.DNS.Allow, c.DNS.Deny)
	hash := hex.EncodeToString(h.Sum(nil))
	_, statErr := os.Stat(sdnBlocklistFile)
	blocking := c.DNS.Blocking()
	changed := false
	switch {
	case !blocking:
		if statErr == nil {
			sdnRemoveFile(sdnBlocklistFile) //nolint:errcheck
			changed = true
		}
		m.state.Domains, m.state.Hash = 0, ""
	case hash != m.state.Hash || statErr != nil:
		text, n := renderBlocklistHosts(lists, c.DNS.Allow, c.DNS.Deny)
		if _, err := sdnSyncFile(sdnBlocklistFile, text); err == nil {
			m.state.Domains, m.state.Built, m.state.Hash = n, now, hash
			changed = true
		}
	}
	if changed {
		if active, _ := sdnRun.Run(nil, "systemctl", "is-active", sdnDNSUnitName); strings.TrimSpace(string(active)) == "active" {
			sdnRun.Run(nil, "systemctl", "reload", sdnDNSUnitName) //nolint:errcheck — read the file again
		}
	}
	if b, err := json.MarshalIndent(m.state, "", "  "); err == nil {
		_ = os.MkdirAll(filepath.Dir(m.statePath), 0755)
		_ = os.WriteFile(m.statePath, b, 0644)
	}
	return m.state
}

// sdnFetchBlocklist downloads one list.
func sdnFetchBlocklist(url string) ([]string, error) {
	cl := &http.Client{Timeout: 3 * time.Minute}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ZNAS-Firewall")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	d := parseBlocklist(io.LimitReader(resp.Body, sdnBlocklistMaxBytes), sdnBlocklistMaxPerList)
	if len(d) == 0 {
		return nil, fmt.Errorf("no domains in the list")
	}
	return d, nil
}

// ── the portal's blocklist keeper ──

var sdnBL = struct {
	sync.Mutex
	m    *sdnBlocklists
	kick chan bool // true = download all now
}{kick: make(chan bool, 1)}

// StartSDNBlocklists keeps the lists current: at start, every hour (lists
// due after a day), and when kicked (Apply, "Update now").
func StartSDNBlocklists(configDir string, confirmed func() *sdn.Config) {
	sdnBL.Lock()
	sdnBL.m = &sdnBlocklists{statePath: filepath.Join(configDir, "sdn", "blocklists.json"), cache: map[string][]string{}, fetch: sdnFetchBlocklist}
	sdnBL.Unlock()
	go func() {
		tick := time.NewTicker(time.Hour)
		force := false
		for {
			if c := confirmed(); c != nil {
				m := sdnBL.m
				dir, _ := sdnStatsDir(c)
				m.cacheDir = filepath.Join(dir, "dns", "lists")
				m.update(c, time.Now(), force)
			}
			select {
			case <-tick.C:
				force = false
			case force = <-sdnBL.kick:
			}
		}
	}()
}

// SDNBlocklistsKick asks for an update (all lists downloaded with force).
func SDNBlocklistsKick(force bool) {
	select {
	case sdnBL.kick <- force:
	default:
	}
}

// SDNBlocklistsState is the last update's outcome.
func SDNBlocklistsState() SDNBlocklistState {
	sdnBL.Lock()
	m := sdnBL.m
	sdnBL.Unlock()
	if m == nil {
		return SDNBlocklistState{Lists: map[string]SDNBlocklistStatus{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadState()
	return m.state
}
