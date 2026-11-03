package system

// DNS reports (Monitor → DNS): with "advanced metrics" on, the DNS server
// logs every query to a file in RAM (/run/znas-sdn-dns/queries.log, rotated
// by the DHCP supervisor). The portal reads it as it grows and keeps:
//   - the query log: the newest queries (a ring), with what happened to each;
//   - 10-minute totals for the last 24 h (the dashboard);
//   - hourly totals, saved per day in the statistics folder (dns/) for a
//     year (the long ranges). Top lists are trimmed when saved.
// Without a statistics folder everything stays in memory.

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"zfsnas/internal/sdn"
)

// SDNDNSQuery is one query and what happened to it.
type SDNDNSQuery struct {
	T        int64  `json:"t"` // unix seconds
	Client   string `json:"client"`
	Type     string `json:"type"`
	Domain   string `json:"domain"`
	Status   string `json:"status"`             // forwarded | cached | local | blocked | "" (no answer seen)
	Reply    string `json:"reply,omitempty"`    // first answer: an address, NXDOMAIN, NODATA…, a name
	Upstream string `json:"upstream,omitempty"` // server it was forwarded to
}

// dnsAgg counts one period (10 minutes or one hour).
type dnsAgg struct {
	T              int64          `json:"t"`
	Total          int            `json:"total"`
	Blocked        int            `json:"blocked"`
	Cached         int            `json:"cached"`
	Forwarded      int            `json:"forwarded"`
	Local          int            `json:"local"`
	Types          map[string]int `json:"types"`
	Upstreams      map[string]int `json:"upstreams"` // server, or cache / blocklist / local
	Domains        map[string]int `json:"domains"`   // answered (not blocked)
	BlockedDomains map[string]int `json:"blocked_domains"`
	Clients        map[string]int `json:"clients"`
	ClientsBlocked map[string]int `json:"clients_blocked"`
}

func newDNSAgg(t int64) *dnsAgg {
	return &dnsAgg{T: t, Types: map[string]int{}, Upstreams: map[string]int{}, Domains: map[string]int{},
		BlockedDomains: map[string]int{}, Clients: map[string]int{}, ClientsBlocked: map[string]int{}}
}

func (a *dnsAgg) maps() []map[string]int {
	return []map[string]int{a.Types, a.Upstreams, a.Domains, a.BlockedDomains, a.Clients, a.ClientsBlocked}
}

func (a *dnsAgg) add(b *dnsAgg) {
	a.Total += b.Total
	a.Blocked += b.Blocked
	a.Cached += b.Cached
	a.Forwarded += b.Forwarded
	a.Local += b.Local
	dst, src := a.maps(), b.maps()
	for i := range dst {
		for k, v := range src[i] {
			dst[i][k] += v
		}
	}
}

// trimmed keeps the n biggest entries of each top list (saved hours).
func (a *dnsAgg) trimmed(n int) *dnsAgg {
	c := *a
	trim := func(m map[string]int) map[string]int {
		if len(m) <= n {
			return m
		}
		out := map[string]int{}
		for _, kv := range topN(m, n) {
			out[kv.Key] = kv.N
		}
		return out
	}
	c.Domains, c.BlockedDomains, c.Clients, c.ClientsBlocked = trim(a.Domains), trim(a.BlockedDomains), trim(a.Clients), trim(a.ClientsBlocked)
	return &c
}

// SDNDNSCount is one entry of a top list.
type SDNDNSCount struct {
	Key string `json:"key"`
	N   int    `json:"n"`
}

func topN(m map[string]int, n int) []SDNDNSCount {
	out := make([]SDNDNSCount, 0, len(m))
	for k, v := range m {
		out = append(out, SDNDNSCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N > out[j].N || (out[i].N == out[j].N && out[i].Key < out[j].Key) })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

type sdnDNSLogPaths struct {
	blocklist string // the blocklist hosts file
	hostsDir  string // the networks' DHCP names
}

type dnsPending struct {
	seq     uint64 // ring slot owner
	slot    int
	t10, th int64 // buckets it was counted in
	done    bool  // outcome counted
}

type sdnDNSStats struct {
	mu       sync.Mutex
	paths    sdnDNSLogPaths
	ring     []SDNDNSQuery
	ringSeq  []uint64
	next     uint64 // queries seen
	pending  map[string]*dnsPending
	pendOrd  []string
	b10      map[int64]*dnsAgg // 10-minute periods, last 25 h
	hours    map[int64]*dnsAgg // hours, last 49 h (older ones are in the day files)
	lastT    int64             // newest line read
	resumeT  int64             // lines up to this second were counted before a restart
	dir      string            // where history is saved ("" = memory only)
	cacheKey string
	cacheVal *SDNDNSSummary
}

func newSDNDNSStats(p sdnDNSLogPaths, ringSize int) *sdnDNSStats {
	return &sdnDNSStats{paths: p, ring: make([]SDNDNSQuery, ringSize), ringSeq: make([]uint64, ringSize),
		pending: map[string]*dnsPending{}, b10: map[int64]*dnsAgg{}, hours: map[int64]*dnsAgg{}}
}

var dnsLineRe = regexp.MustCompile(`^(\w{3} [ \d]\d \d\d:\d\d:\d\d) dnsmasq\[\d+\]: (\d+) ([0-9a-fA-F.:]+)/\d+ (.*)$`)

var dnsTypeNames = map[string]string{"type=64": "SVCB", "type=65": "HTTPS"}

// lineTime: dnsmasq writes no year.
func lineTime(stamp string, now time.Time) (time.Time, bool) {
	t, err := time.ParseInLocation("Jan _2 15:04:05", stamp, now.Location())
	if err != nil {
		return t, false
	}
	t = t.AddDate(now.Year(), 0, 0)
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, true
}

// line reads one line of the query log.
func (s *sdnDNSStats) line(l string, now time.Time) {
	m := dnsLineRe.FindStringSubmatch(l)
	if m == nil {
		return
	}
	ts, ok := lineTime(m[1], now)
	if !ok {
		return
	}
	t := ts.Unix()
	if t <= s.resumeT {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if t > s.lastT {
		s.lastT = t
	}
	s.cacheKey = ""
	key, client, rest := m[2]+"/"+m[3], m[3], m[4]
	if strings.HasPrefix(rest, "query[") {
		typ, after, ok := strings.Cut(rest[len("query["):], "] ")
		if !ok {
			return
		}
		domain, _, _ := strings.Cut(after, " ")
		if n, ok := dnsTypeNames[typ]; ok {
			typ = n
		}
		s.addQuery(key, SDNDNSQuery{T: t, Client: client, Type: typ, Domain: strings.ToLower(domain)})
		return
	}
	p := s.pending[key]
	if p == nil || s.ringSeq[p.slot] != p.seq {
		return
	}
	q := &s.ring[p.slot]
	word, after, _ := strings.Cut(rest, " ")
	_, answer, hasAnswer := strings.Cut(after, " is ")
	status := ""
	switch {
	case word == "forwarded":
		if _, srv, ok := strings.Cut(after, " to "); ok && q.Upstream == "" {
			q.Upstream = srv
		}
		status = "forwarded"
	case word == "reply":
		status = "forwarded"
	case word == "cached" || word == "cached-stale":
		status = "cached"
	case word == "config":
		status = "local"
	case strings.HasPrefix(word, "/"):
		status = "local"
		if word == s.paths.blocklist {
			status = "blocked"
		}
	default:
		return
	}
	if hasAnswer && q.Reply == "" {
		q.Reply = answer
	}
	if p.done {
		return
	}
	p.done = true
	q.Status = status
	for _, a := range []*dnsAgg{s.b10[p.t10], s.hours[p.th]} {
		if a == nil {
			continue
		}
		switch status {
		case "blocked":
			a.Blocked++
			a.Upstreams["blocklist"]++
			a.BlockedDomains[q.Domain]++
			a.ClientsBlocked[q.Client]++
		case "cached":
			a.Cached++
			a.Upstreams["cache"]++
			a.Domains[q.Domain]++
		case "local":
			a.Local++
			a.Upstreams["local"]++
			a.Domains[q.Domain]++
		default:
			a.Forwarded++
			if q.Upstream != "" {
				a.Upstreams[q.Upstream]++
			}
			a.Domains[q.Domain]++
		}
	}
}

func (s *sdnDNSStats) addQuery(key string, q SDNDNSQuery) {
	slot := int(s.next % uint64(len(s.ring)))
	s.next++
	s.ring[slot], s.ringSeq[slot] = q, s.next
	t10, th := q.T-q.T%600, q.T-q.T%3600
	for _, x := range []struct {
		m map[int64]*dnsAgg
		t int64
	}{{s.b10, t10}, {s.hours, th}} {
		a := x.m[x.t]
		if a == nil {
			a = newDNSAgg(x.t)
			x.m[x.t] = a
		}
		a.Total++
		a.Types[q.Type]++
		a.Clients[q.Client]++
	}
	s.pending[key] = &dnsPending{seq: s.next, slot: slot, t10: t10, th: th}
	s.pendOrd = append(s.pendOrd, key)
	if len(s.pendOrd) > 4096 { // outcomes come within moments
		for _, k := range s.pendOrd[:2048] {
			delete(s.pending, k)
		}
		s.pendOrd = append([]string(nil), s.pendOrd[2048:]...)
	}
	// periods out of the windows: hours are in the day files once saved
	for k := range s.b10 {
		if k < q.T-25*3600 {
			delete(s.b10, k)
		}
	}
	if s.dir != "" {
		for k := range s.hours {
			if k < q.T-49*3600 {
				delete(s.hours, k)
			}
		}
	}
}

// sdnDNSFilter narrows the query log.
type sdnDNSFilter struct {
	Domain string // contains, any case
	Client string // exact address
	Status string // blocked | allowed | forwarded | cached | local
	Before int64  // only queries older than this (paging), 0 = none
}

func (s *sdnDNSStats) queries(f sdnDNSFilter, limit int) []SDNDNSQuery {
	s.mu.Lock()
	defer s.mu.Unlock()
	dom := strings.ToLower(f.Domain)
	out := []SDNDNSQuery{}
	n := uint64(len(s.ring))
	for i := uint64(0); i < n && i < s.next && len(out) < limit; i++ {
		slot := (s.next - 1 - i) % n
		q := s.ring[slot]
		switch {
		case f.Before != 0 && q.T >= f.Before:
			continue
		case dom != "" && !strings.Contains(q.Domain, dom):
			continue
		case f.Client != "" && q.Client != f.Client:
			continue
		case f.Status == "allowed" && q.Status == "blocked":
			continue
		case f.Status != "" && f.Status != "allowed" && q.Status != f.Status:
			continue
		}
		out = append(out, q)
	}
	return out
}

// SDNDNSPoint is one point of "queries over time".
type SDNDNSPoint struct {
	T       int64 `json:"t"`
	Allowed int   `json:"allowed"`
	Blocked int   `json:"blocked"`
}

// SDNDNSSummary is the dashboard for one range.
type SDNDNSSummary struct {
	From              int64          `json:"from"`
	Step              int64          `json:"step"` // seconds per point
	Total             int            `json:"total"`
	Blocked           int            `json:"blocked"`
	Cached            int            `json:"cached"`
	Forwarded         int            `json:"forwarded"`
	Local             int            `json:"local"`
	Clients           int            `json:"clients"` // distinct
	Types             map[string]int `json:"types"`
	Upstreams         map[string]int `json:"upstreams"`
	TopDomains        []SDNDNSCount  `json:"top_domains"`
	TopBlocked        []SDNDNSCount  `json:"top_blocked"`
	TopClients        []SDNDNSCount  `json:"top_clients"`
	TopClientsBlocked []SDNDNSCount  `json:"top_clients_blocked"`
	Series            []SDNDNSPoint  `json:"series"`
	ClientSeries      struct {
		Clients []string `json:"clients"`
		Points  [][]int  `json:"points"` // per point, per client
	} `json:"client_series"`
}

// summary: 24 h from the 10-minute periods; 7 and 30 days from hours; a
// year from days (hours summed).
func (s *sdnDNSStats) summary(now time.Time, span time.Duration, top int) *SDNDNSSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := span.String() + "/" + now.Truncate(time.Minute).String()
	if s.cacheKey == key && s.cacheVal != nil {
		return s.cacheVal
	}
	var periods []*dnsAgg
	var step int64
	end := now.Unix()
	switch {
	case span <= 24*time.Hour:
		step = 600
		for _, a := range s.b10 {
			periods = append(periods, a)
		}
	default:
		step = 3600
		if span > 31*24*time.Hour {
			step = 86400
		}
		periods = s.hoursFor(now.Add(-span), now)
	}
	// points: aligned to the step, the last one holding now
	last := end - end%step
	if step == 86400 {
		y, m, d := now.Date()
		last = time.Date(y, m, d, 0, 0, 0, 0, now.Location()).Unix()
	}
	nPts := int(span / (time.Duration(step) * time.Second))
	first := last - int64(nPts-1)*step
	if step == 86400 {
		first = time.Unix(last, 0).AddDate(0, 0, -(nPts - 1)).Unix()
	}
	idx := func(t int64) int {
		if step == 86400 {
			tt := time.Unix(t, 0)
			y, m, d := tt.Date()
			day := time.Date(y, m, d, 0, 0, 0, 0, now.Location())
			return int(day.Sub(time.Unix(first, 0)).Hours()/24 + 0.5)
		}
		return int((t - first) / step)
	}
	sum := &SDNDNSSummary{From: first, Step: step, Series: make([]SDNDNSPoint, nPts)}
	for i := range sum.Series {
		sum.Series[i].T = first + int64(i)*step
		if step == 86400 {
			sum.Series[i].T = time.Unix(first, 0).AddDate(0, 0, i).Unix()
		}
	}
	all := newDNSAgg(first)
	var used []*dnsAgg
	for _, a := range periods {
		i := idx(a.T)
		if i < 0 || i >= nPts {
			continue
		}
		used = append(used, a)
		all.add(a)
		sum.Series[i].Allowed += a.Total - a.Blocked
		sum.Series[i].Blocked += a.Blocked
	}
	sum.Total, sum.Blocked, sum.Cached, sum.Forwarded, sum.Local = all.Total, all.Blocked, all.Cached, all.Forwarded, all.Local
	sum.Clients, sum.Types, sum.Upstreams = len(all.Clients), all.Types, all.Upstreams
	sum.TopDomains, sum.TopBlocked = topN(all.Domains, top), topN(all.BlockedDomains, top)
	sum.TopClients, sum.TopClientsBlocked = topN(all.Clients, top), topN(all.ClientsBlocked, top)
	// client activity: the busiest clients, per point
	for _, c := range topN(all.Clients, 8) {
		sum.ClientSeries.Clients = append(sum.ClientSeries.Clients, c.Key)
	}
	sum.ClientSeries.Points = make([][]int, nPts)
	for i := range sum.ClientSeries.Points {
		sum.ClientSeries.Points[i] = make([]int, len(sum.ClientSeries.Clients))
	}
	for _, a := range used {
		i := idx(a.T)
		for j, c := range sum.ClientSeries.Clients {
			sum.ClientSeries.Points[i][j] += a.Clients[c]
		}
	}
	s.cacheKey, s.cacheVal = key, sum
	return sum
}

// hoursFor: the hours between from and to — in memory for the last ones,
// from the day files for the others.
func (s *sdnDNSStats) hoursFor(from, to time.Time) []*dnsAgg {
	byT := map[int64]*dnsAgg{}
	if s.dir != "" {
		for d := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, from.Location()); !d.After(to); d = d.AddDate(0, 0, 1) {
			for _, h := range readDNSDay(filepath.Join(s.dir, d.Format("2006-01-02")+".json.gz")) {
				byT[h.T] = h
			}
		}
	}
	for t, h := range s.hours {
		byT[t] = h // the live hours win over what was saved
	}
	out := make([]*dnsAgg, 0, len(byT))
	for _, h := range byT {
		if h.T >= from.Unix()-3600 && h.T <= to.Unix() {
			out = append(out, h)
		}
	}
	return out
}

func readDNSDay(path string) []*dnsAgg {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil
	}
	var hours []*dnsAgg
	if json.NewDecoder(zr).Decode(&hours) != nil {
		return nil
	}
	for _, h := range hours {
		for _, m := range []*map[string]int{&h.Types, &h.Upstreams, &h.Domains, &h.BlockedDomains, &h.Clients, &h.ClientsBlocked} {
			if *m == nil {
				*m = map[string]int{}
			}
		}
	}
	return hours
}

func writeGzJSON(path string, v any) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(f)
	if err := json.NewEncoder(zw).Encode(v); err != nil {
		f.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// dnsLive is what a restart needs to go on: the query log, the last 24 h
// and the hours not yet complete in the day files.
type dnsLive struct {
	LastT int64         `json:"last_t"`
	Ring  []SDNDNSQuery `json:"ring"` // oldest first
	B10   []*dnsAgg     `json:"b10"`
	Hours []*dnsAgg     `json:"hours"`
}

const dnsSaveTop = 200 // top-list entries kept per saved period

// save writes the day files of the hours in memory and the live state.
func (s *sdnDNSStats) save(dir string, now time.Time) error {
	s.mu.Lock()
	days := map[string][]*dnsAgg{}
	for _, h := range s.hours {
		d := time.Unix(h.T, 0).In(now.Location()).Format("2006-01-02")
		days[d] = append(days[d], h.trimmed(dnsSaveTop))
	}
	live := dnsLive{LastT: s.lastT}
	n := uint64(len(s.ring))
	start := uint64(0)
	if s.next > n {
		start = s.next - n
	}
	for i := start; i < s.next; i++ {
		live.Ring = append(live.Ring, s.ring[i%n])
	}
	for _, a := range s.b10 {
		live.B10 = append(live.B10, a.trimmed(dnsSaveTop))
	}
	for _, a := range s.hours {
		live.Hours = append(live.Hours, a.trimmed(dnsSaveTop))
	}
	s.mu.Unlock()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for d, hours := range days {
		// merge with what the day file has (hours no longer in memory)
		p := filepath.Join(dir, d+".json.gz")
		byT := map[int64]*dnsAgg{}
		for _, h := range readDNSDay(p) {
			byT[h.T] = h
		}
		for _, h := range hours {
			byT[h.T] = h
		}
		merged := make([]*dnsAgg, 0, len(byT))
		for _, h := range byT {
			merged = append(merged, h)
		}
		sort.Slice(merged, func(i, j int) bool { return merged[i].T < merged[j].T })
		if err := writeGzJSON(p, merged); err != nil {
			return err
		}
	}
	// a year of day files
	if ents, err := os.ReadDir(dir); err == nil {
		cut := now.AddDate(-1, 0, -1).Format("2006-01-02")
		for _, e := range ents {
			if name, ok := strings.CutSuffix(e.Name(), ".json.gz"); ok && len(name) == 10 && name < cut {
				os.Remove(filepath.Join(dir, e.Name())) //nolint:errcheck
			}
		}
	}
	return writeGzJSON(filepath.Join(dir, "live.json.gz"), live)
}

// load restores the live state saved by save.
func (s *sdnDNSStats) load(dir string, now time.Time) error {
	f, err := os.Open(filepath.Join(dir, "live.json.gz"))
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	var live dnsLive
	if err := json.NewDecoder(io.LimitReader(zr, 1<<30)).Decode(&live); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dir = dir
	s.lastT, s.resumeT = live.LastT, live.LastT
	for _, q := range live.Ring {
		slot := int(s.next % uint64(len(s.ring)))
		s.next++
		s.ring[slot], s.ringSeq[slot] = q, s.next
	}
	fix := func(list []*dnsAgg, into map[int64]*dnsAgg, keep time.Duration) {
		for _, a := range list {
			if a.T < now.Add(-keep).Unix() {
				continue
			}
			for _, m := range []*map[string]int{&a.Types, &a.Upstreams, &a.Domains, &a.BlockedDomains, &a.Clients, &a.ClientsBlocked} {
				if *m == nil {
					*m = map[string]int{}
				}
			}
			into[a.T] = a
		}
	}
	fix(live.B10, s.b10, 25*time.Hour)
	fix(live.Hours, s.hours, 49*time.Hour)
	return nil
}

// ── following the log file ──

// sdnTail reads a growing file, following it across rotations (renamed
// away, a new one created), and hands complete lines.
type sdnTail struct {
	path    string
	f       *os.File
	ino     uint64
	partial string
}

func (t *sdnTail) poll(fn func(string)) {
	if t.f == nil {
		f, err := os.Open(t.path)
		if err != nil {
			return
		}
		t.f, t.ino = f, fileIno(f)
	}
	t.drain(fn)
	// rotated: finish the old file (done above), then switch
	if st, err := os.Stat(t.path); err == nil && statIno(st) != t.ino {
		t.f.Close()
		t.f = nil
		t.partial = ""
		t.poll(fn)
	}
}

func (t *sdnTail) drain(fn func(string)) {
	buf := make([]byte, 64<<10)
	for {
		n, err := t.f.Read(buf)
		if n > 0 {
			data := t.partial + string(buf[:n])
			lines := strings.Split(data, "\n")
			t.partial = lines[len(lines)-1]
			for _, l := range lines[:len(lines)-1] {
				fn(l)
			}
		}
		if err != nil || n == 0 {
			return
		}
	}
}

func (t *sdnTail) close() {
	if t.f != nil {
		t.f.Close()
		t.f = nil
	}
}

func statIno(st os.FileInfo) uint64 {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return s.Ino
	}
	return 0
}

func fileIno(f *os.File) uint64 {
	if st, err := f.Stat(); err == nil {
		return statIno(st)
	}
	return 0
}

// ── the portal's collector ──

var sdnDNS = struct {
	sync.Mutex
	s       *sdnDNSStats
	tail    *sdnTail
	on      bool
	dir     string
	started time.Time
}{}

// StartSDNDNSStats reads the DNS query log while advanced metrics are on,
// and saves the history every 10 minutes.
func StartSDNDNSStats(confirmed func() *sdn.Config) {
	go func() {
		tick := time.NewTicker(time.Second)
		lastSave := time.Now()
		var c *sdn.Config
		for n := 0; ; n++ {
			<-tick.C
			if n%10 == 0 { // the settings change rarely: read them every 10 s
				c = confirmed()
			}
			on := c != nil && c.DNS.Enabled && c.DNS.Metrics
			now := time.Now()
			sdnDNS.Lock()
			if c != nil {
				base, _ := sdnStatsDir(c)
				dir := filepath.Join(base, "dns")
				if sdnDNS.s == nil || dir != sdnDNS.dir {
					if sdnDNS.s != nil && sdnDNS.dir != "" {
						sdnDNS.s.save(sdnDNS.dir, now) //nolint:errcheck — the old folder gets what it had
					}
					s := newSDNDNSStats(sdnDNSLogPaths{blocklist: sdnBlocklistFile, hostsDir: sdnHostsDir}, 100000)
					s.load(dir, now) //nolint:errcheck — nothing saved yet is fine
					s.dir = dir
					sdnDNS.s, sdnDNS.dir = s, dir
				}
			}
			if on && !sdnDNS.on {
				sdnDNS.tail, sdnDNS.started = &sdnTail{path: sdnQueryLog}, now
			}
			if !on && sdnDNS.tail != nil {
				sdnDNS.tail.close()
				sdnDNS.tail = nil
			}
			sdnDNS.on = on
			s, tl := sdnDNS.s, sdnDNS.tail
			sdnDNS.Unlock()
			if tl != nil && s != nil {
				tl.poll(func(l string) { s.line(l, now) })
			}
			if s != nil && now.Sub(lastSave) >= 10*time.Minute {
				lastSave = now
				if err := s.save(s.dir, now); err != nil {
					log.Printf("[sdn-dns] saving the DNS statistics: %v", err)
				}
			}
		}
	}()
}

// SDNDNSStatsSave saves the history now (portal shutdown).
func SDNDNSStatsSave() {
	sdnDNS.Lock()
	s := sdnDNS.s
	sdnDNS.Unlock()
	if s != nil {
		s.save(s.dir, time.Now()) //nolint:errcheck
	}
}

// SDNDNSReport is the dashboard for one range.
func SDNDNSReport(span time.Duration) *SDNDNSSummary {
	sdnDNS.Lock()
	s := sdnDNS.s
	sdnDNS.Unlock()
	if s == nil {
		s = newSDNDNSStats(sdnDNSLogPaths{}, 1)
	}
	return s.summary(time.Now(), span, 25)
}

// SDNDNSQueries is the query log, newest first.
func SDNDNSQueries(domain, client, status string, before int64, limit int) []SDNDNSQuery {
	sdnDNS.Lock()
	s := sdnDNS.s
	sdnDNS.Unlock()
	if s == nil {
		return []SDNDNSQuery{}
	}
	return s.queries(sdnDNSFilter{Domain: domain, Client: client, Status: status, Before: before}, limit)
}

// SDNDNSCollecting: whether queries are being read now.
func SDNDNSCollecting() bool {
	sdnDNS.Lock()
	defer sdnDNS.Unlock()
	return sdnDNS.on
}

// SDNInsideNames names inside addresses: this server, DHCP leases, Incus
// instances (no reverse-DNS lookups).
func SDNInsideNames(c *sdn.Config, ips []string) map[string]string {
	if c == nil {
		c = &sdn.Config{}
	}
	leases := map[string]string{}
	for _, l := range SDNDHCPLeases(c) {
		if l.Hostname != "" {
			leases[l.IP] = l.Hostname
		}
	}
	out := map[string]string{}
	for _, s := range ips {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		switch {
		case a.IsLoopback() || sdnIDSLocal(a):
			out[s] = "This ZNAS"
		case leases[s] != "":
			out[s] = leases[s]
		default:
			sdnTC.mu.Lock()
			if n := sdnTC.names[a]; n != "" {
				out[s] = n
			}
			sdnTC.mu.Unlock()
		}
	}
	return out
}
