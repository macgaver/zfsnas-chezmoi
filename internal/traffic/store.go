package traffic

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/geoip"
)

// Tiers and retention (owner): 5-minute precision for 2 weeks, hourly for
// 2 months, daily for 5 years.
const (
	Keep5m = 14 * 24 * time.Hour
	Keep1h = 60 * 24 * time.Hour
	Keep1d = 5 * 365 * 24 * time.Hour
)

// Store keeps closed buckets on disk: <dir>/5m/YYYYMMDD.jsonl.gz,
// <dir>/1h/YYYYMM.jsonl.gz, <dir>/1d/YYYY.jsonl.gz. Each Write appends one
// gzip member — one sequential write per flush (every 10 minutes).
type Store struct {
	Dir  string
	TopN map[string]int // per tier: "5m", "1h", "1d"
	mu   sync.Mutex
}

type storeState struct {
	Hour time.Time `json:"hour"` // hours before this are rolled into 1h
	Day  time.Time `json:"day"`  // days before this are rolled into 1d
}

func (s *Store) topN(tier string) int {
	if n, ok := s.TopN[tier]; ok {
		return n
	}
	return map[string]int{"5m": 2000, "1h": 1500, "1d": 1000}[tier]
}

func tierFile(dir, tier string, t time.Time) string {
	layout := map[string]string{"5m": "20060102", "1h": "200601", "1d": "2006"}[tier]
	return filepath.Join(dir, tier, t.UTC().Format(layout)+".jsonl.gz")
}

func (s *Store) appendBuckets(tier string, bs []Bucket) error {
	byFile := map[string][]Bucket{}
	var order []string
	for _, b := range bs {
		f := tierFile(s.Dir, tier, b.Start)
		if _, ok := byFile[f]; !ok {
			order = append(order, f)
		}
		byFile[f] = append(byFile[f], b)
	}
	for _, path := range order {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		zw := gzip.NewWriter(f)
		enc := json.NewEncoder(zw)
		for _, b := range byFile[path] {
			if err := enc.Encode(b); err != nil {
				zw.Close()
				f.Close()
				return err
			}
		}
		if err := zw.Close(); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Write stores closed 5-minute buckets (top-N applied).
func (s *Store) Write(bs []Bucket) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range bs {
		bs[i].Recs = topN(bs[i].Recs, s.topN("5m"))
	}
	return s.appendBuckets("5m", bs)
}

func readTier(path string, fn func(Bucket)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var b Bucket
		if json.Unmarshal(sc.Bytes(), &b) == nil {
			fn(b)
		}
	}
}

func (s *Store) loadState() storeState {
	var st storeState
	if b, err := os.ReadFile(filepath.Join(s.Dir, "state.json")); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func (s *Store) saveState(st storeState) error {
	b, _ := json.Marshal(st)
	tmp := filepath.Join(s.Dir, "state.json.tmp")
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.Dir, "state.json"))
}

func recKey(r Rec) string {
	return strings.Join([]string{r.Dir, r.Remote, r.Proto, strconv.Itoa(int(r.PubPort)), r.Inside, strconv.Itoa(int(r.Port)), r.Rule, r.CC, r.Iface}, "|")
}

func merge(dst *Rec, r Rec) {
	dst.BytesIn += r.BytesIn
	dst.BytesOut += r.BytesOut
	dst.Pkts += r.Pkts
	dst.Sessions += r.Sessions
	if dst.First.IsZero() || (!r.First.IsZero() && r.First.Before(dst.First)) {
		dst.First = r.First
	}
	if r.Last.After(dst.Last) {
		dst.Last = r.Last
	}
}

func volume(r Rec) uint64 {
	if r.Dir == "blk" {
		return r.Pkts
	}
	return r.BytesIn + r.BytesOut
}

// topN keeps, per direction, the n largest records (by volume) and the n/10
// busiest by sessions (scanners: 200 at the 5-minute tier); the rest is
// folded into exact per-country rows.
func topN(recs []Rec, n int) []Rec {
	if n <= 0 {
		return recs
	}
	byDir := map[string][]Rec{}
	for _, r := range recs {
		byDir[r.Dir] = append(byDir[r.Dir], r)
	}
	var out []Rec
	for _, dir := range []string{"in", "out", "blk"} {
		rs := byDir[dir]
		if len(rs) <= n {
			out = append(out, rs...)
			continue
		}
		sort.SliceStable(rs, func(i, j int) bool { return volume(rs[i]) > volume(rs[j]) })
		keep := map[int]bool{}
		for i := 0; i < n; i++ {
			keep[i] = true
		}
		idx := make([]int, len(rs))
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool { return rs[idx[a]].Sessions > rs[idx[b]].Sessions })
		for _, i := range idx[:min(n/10, len(idx))] {
			keep[i] = true
		}
		folded := map[string]*Rec{}
		var order []string
		for i, r := range rs {
			if keep[i] || r.Remote == "" {
				if r.Remote == "" {
					if f := folded[r.CC]; f != nil {
						merge(f, r)
						continue
					}
					cp := r
					folded[r.CC] = &cp
					order = append(order, r.CC)
					continue
				}
				out = append(out, r)
				continue
			}
			f := folded[r.CC]
			if f == nil {
				f = &Rec{Dir: dir, CC: r.CC, Country: r.Country, Lat: r.Lat, Lon: r.Lon}
				folded[r.CC] = f
				order = append(order, r.CC)
			}
			merge(f, Rec{BytesIn: r.BytesIn, BytesOut: r.BytesOut, Pkts: r.Pkts, Sessions: r.Sessions, First: r.First, Last: r.Last})
		}
		for _, cc := range order {
			out = append(out, *folded[cc])
		}
	}
	return out
}

func mergeBuckets(start time.Time, bs []Bucket, n int) Bucket {
	m := map[string]*Rec{}
	var order []string
	for _, b := range bs {
		for _, r := range b.Recs {
			k := recKey(r)
			if cur := m[k]; cur != nil {
				merge(cur, r)
				continue
			}
			cp := r
			m[k] = &cp
			order = append(order, k)
		}
	}
	out := Bucket{Start: start}
	for _, k := range order {
		out.Recs = append(out.Recs, *m[k])
	}
	out.Recs = topN(out.Recs, n)
	return out
}

// Rollup aggregates complete hours into the hourly tier and complete days
// into the daily tier. Runs hourly; idempotent thanks to state.json.
func (s *Store) Rollup(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.loadState()
	if st.Hour.IsZero() {
		files, _ := filepath.Glob(filepath.Join(s.Dir, "5m", "*.jsonl.gz"))
		sort.Strings(files)
		if len(files) == 0 {
			return nil
		}
		t, err := time.Parse("20060102", strings.TrimSuffix(filepath.Base(files[0]), ".jsonl.gz"))
		if err != nil {
			return err
		}
		st.Hour, st.Day = t, t
	}
	endHour := now.UTC().Truncate(time.Hour)
	cache := map[string][]Bucket{}
	read := func(path string) []Bucket {
		if bs, ok := cache[path]; ok {
			return bs
		}
		var bs []Bucket
		readTier(path, func(b Bucket) { bs = append(bs, b) })
		cache[path] = bs
		return bs
	}
	var hours []Bucket
	for h := st.Hour; h.Before(endHour); h = h.Add(time.Hour) {
		var in []Bucket
		for _, b := range read(tierFile(s.Dir, "5m", h)) {
			if !b.Start.Before(h) && b.Start.Before(h.Add(time.Hour)) {
				in = append(in, b)
			}
		}
		if len(in) > 0 {
			hours = append(hours, mergeBuckets(h, in, s.topN("1h")))
		}
		st.Hour = h.Add(time.Hour)
	}
	if err := s.appendBuckets("1h", hours); err != nil {
		return err
	}
	endDay := st.Hour.Truncate(24 * time.Hour)
	var days []Bucket
	for d := st.Day; d.Before(endDay); d = d.Add(24 * time.Hour) {
		var in []Bucket
		for _, b := range read(tierFile(s.Dir, "1h", d)) {
			if !b.Start.Before(d) && b.Start.Before(d.Add(24*time.Hour)) {
				in = append(in, b)
			}
		}
		if len(in) > 0 {
			days = append(days, mergeBuckets(d, in, s.topN("1d")))
		}
		st.Day = d.Add(24 * time.Hour)
	}
	if err := s.appendBuckets("1d", days); err != nil {
		return err
	}
	return s.saveState(st)
}

// Prune deletes data past each tier's retention.
func (s *Store) Prune(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range []struct {
		tier, layout string
		keep         time.Duration
		span         func(time.Time) time.Time
	}{
		{"5m", "20060102", Keep5m, func(t time.Time) time.Time { return t.AddDate(0, 0, 1) }},
		{"1h", "200601", Keep1h, func(t time.Time) time.Time { return t.AddDate(0, 1, 0) }},
		{"1d", "2006", Keep1d, func(t time.Time) time.Time { return t.AddDate(1, 0, 0) }},
	} {
		files, _ := filepath.Glob(filepath.Join(s.Dir, t.tier, "*.jsonl.gz"))
		for _, f := range files {
			start, err := time.Parse(t.layout, strings.TrimSuffix(filepath.Base(f), ".jsonl.gz"))
			if err == nil && now.Sub(t.span(start)) > t.keep {
				_ = os.Remove(f)
			}
		}
	}
}

// ── queries ───────────────────────────────────────────────────────────────

type Query struct {
	From, To time.Time
	Dir      string // in | out | blk | all
	Group    string // ip | country | city
	Filter   string
	Inside   string // only this inside host (exact address)
	Limit    int
	Offset   int
	// Locate, when set, places each remote again with the database in use
	// now: a line keeps the location found when it was recorded, so after a
	// database change (DB-IP → GeoLite2, a monthly update) old lines would
	// otherwise show the old answer. false: keep what was recorded.
	Locate func(remote string) (geoip.Info, bool)
}

type Row struct {
	Rec
	IPs   int      `json:"ips,omitempty"`   // distinct remotes (country/city rows)
	Ports []uint16 `json:"ports,omitempty"` // top targeted ports (blocked) / remote ports reached (outgoing)
	Hosts []string `json:"hosts,omitempty"` // top inside hosts (outgoing)
	Trend []uint64 `json:"trend,omitempty"` // 24 points over the range
}

type KPI struct {
	Bytes, Sessions, Pkts uint64
	Remotes, Countries    int
	TopCountries          []string `json:"top_countries,omitempty"`
}

type Result struct {
	Tier   string         `json:"tier"`
	KPI    map[string]KPI `json:"kpi"`
	Rows   []Row          `json:"rows"`
	Total  int            `json:"total"`
	Points []Row          `json:"points"`
}

func tierFor(q Query, now time.Time) string {
	span := q.To.Sub(q.From)
	switch {
	case span <= 48*time.Hour && now.Sub(q.From) <= Keep5m:
		return "5m"
	case span <= 61*24*time.Hour && now.Sub(q.From) <= Keep1h:
		return "1h"
	}
	return "1d"
}

// collect streams every bucket of the range to fn — stored tiers then the
// open (in-memory) buckets — without holding them all in memory.
func (s *Store) collect(q Query, open []Bucket, now time.Time, fn func(Bucket)) string {
	tier := tierFor(q, now)
	st := s.loadState()
	add := func(b Bucket) {
		if !b.Start.Before(q.From) && b.Start.Before(q.To) {
			fn(b)
		}
	}
	scan := func(tier string, from, to time.Time) {
		seen := map[string]bool{}
		step := map[string]func(time.Time) time.Time{
			"5m": func(t time.Time) time.Time { return t.AddDate(0, 0, 1) },
			"1h": func(t time.Time) time.Time { return t.AddDate(0, 1, 0) },
			"1d": func(t time.Time) time.Time { return t.AddDate(1, 0, 0) },
		}[tier]
		for t := from; t.Before(to); t = step(t) {
			f := tierFile(s.Dir, tier, t)
			if seen[f] {
				continue
			}
			seen[f] = true
			readTier(f, func(b Bucket) {
				if !b.Start.Before(from) && b.Start.Before(to) {
					add(b)
				}
			})
		}
		// the last partial period
		if f := tierFile(s.Dir, tier, to.Add(-time.Second)); !seen[f] {
			readTier(f, func(b Bucket) {
				if !b.Start.Before(from) && b.Start.Before(to) {
					add(b)
				}
			})
		}
	}
	from := q.From.UTC()
	switch tier {
	case "5m":
		scan("5m", from, q.To)
	case "1h":
		edge := maxTime(st.Hour, from)
		scan("1h", from.Truncate(time.Hour), minTime(st.Hour, q.To))
		scan("5m", edge, q.To) // not rolled yet
	default:
		dEdge, hEdge := maxTime(st.Day, from), maxTime(st.Hour, maxTime(st.Day, from))
		scan("1d", from.Truncate(24*time.Hour), minTime(st.Day, q.To))
		scan("1h", dEdge, minTime(st.Hour, q.To))
		scan("5m", hEdge, q.To)
	}
	for _, b := range open {
		add(b)
	}
	return tier
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.IsZero() || b.Before(a) {
		return b
	}
	return a
}

func groupKey(r Rec, group string) string {
	switch group {
	case "country":
		return r.Dir + "|" + r.CC
	case "city":
		return r.Dir + "|" + r.CC + "|" + r.City
	}
	if r.Dir == "blk" {
		return strings.Join([]string{r.Dir, r.Remote, r.CC, r.Rule}, "|")
	}
	if r.Dir == "out" {
		return strings.Join([]string{r.Dir, r.Remote, r.CC, r.Iface}, "|")
	}
	return strings.Join([]string{r.Dir, r.Remote, r.CC, strconv.Itoa(int(r.PubPort)), r.Inside, strconv.Itoa(int(r.Port))}, "|")
}

func matches(r Rec, f string) bool {
	if f == "" {
		return true
	}
	f = strings.ToLower(f)
	hay := strings.ToLower(strings.Join([]string{r.Remote, r.Country, r.CC, r.City, r.ASOrg, r.Name, r.Inside, r.Iface, r.Rule,
		strconv.Itoa(int(r.Port)), strconv.Itoa(int(r.PubPort)), "as" + strconv.Itoa(int(r.ASN))}, " "))
	return strings.Contains(hay, f)
}

// Query aggregates the stored and open buckets for one view.
func (s *Store) Query(q Query, open []Bucket, now time.Time) Result {
	res := Result{KPI: map[string]KPI{}}
	type acc struct {
		row   Row
		ips   map[string]bool
		ports map[uint16]uint64
		hosts map[string]uint64
	}
	rows := map[string]*acc{}
	remotes := map[string]map[string]bool{}
	countries := map[string]map[string]uint64{}
	span := q.To.Sub(q.From)
	located := map[string]*geoip.Info{} // remote → current answer (nil: keep the recorded one)
	relocate := func(r *Rec) {
		if q.Locate == nil || r.Remote == "" {
			return
		}
		g, seen := located[r.Remote]
		if !seen {
			if in, ok := q.Locate(r.Remote); ok && in.CountryCode != "" {
				g = &in
			}
			located[r.Remote] = g
		}
		if g != nil {
			r.geo(*g)
		}
	}
	res.Tier = s.collect(q, open, now, func(b Bucket) {
		slot := int(b.Start.Sub(q.From) * 24 / maxDur(span, time.Second))
		if slot > 23 {
			slot = 23
		}
		for _, r := range b.Recs {
			relocate(&r)
			k := res.KPI[r.Dir]
			k.Bytes += r.BytesIn + r.BytesOut
			k.Sessions += r.Sessions
			k.Pkts += r.Pkts
			res.KPI[r.Dir] = k
			if remotes[r.Dir] == nil {
				remotes[r.Dir], countries[r.Dir] = map[string]bool{}, map[string]uint64{}
			}
			if r.Remote != "" {
				remotes[r.Dir][r.Remote] = true
			}
			if r.CC != "" {
				countries[r.Dir][r.Country] += volume(r)
			}
			if (q.Dir != "" && q.Dir != "all" && r.Dir != q.Dir) || !matches(r, q.Filter) || (q.Inside != "" && r.Inside != q.Inside) {
				continue
			}
			gk := groupKey(r, q.Group)
			a := rows[gk]
			if a == nil {
				a = &acc{row: Row{Rec: r, Trend: make([]uint64, 24)}, ips: map[string]bool{}, ports: map[uint16]uint64{}, hosts: map[string]uint64{}}
				a.row.BytesIn, a.row.BytesOut, a.row.Pkts, a.row.Sessions = 0, 0, 0, 0
				if q.Group == "country" || q.Group == "city" {
					a.row.Remote, a.row.Inside, a.row.Name, a.row.ASN, a.row.ASOrg = "", "", "", 0, ""
				}
				rows[gk] = a
			}
			merge(&a.row.Rec, r)
			if slot >= 0 {
				a.row.Trend[slot] += volume(r)
			}
			if r.Remote != "" {
				a.ips[r.Remote] = true
			}
			if r.Dir == "blk" {
				a.ports[r.Port] += r.Pkts
			}
			if r.Dir == "out" {
				if r.Port != 0 { // 0: ICMP and other port-less protocols
					a.ports[r.Port] += r.BytesIn + r.BytesOut + r.Sessions // sessions: a port with no bytes yet still counts
				}
				h := r.Name
				if h == "" {
					h = r.Inside
				}
				a.hosts[h] += r.BytesIn + r.BytesOut
			}
		}
	})
	for dir, k := range res.KPI {
		k.Remotes, k.Countries = len(remotes[dir]), len(countries[dir])
		type cv struct {
			c string
			v uint64
		}
		var cs []cv
		for c, v := range countries[dir] {
			cs = append(cs, cv{c, v})
		}
		sort.Slice(cs, func(i, j int) bool { return cs[i].v > cs[j].v })
		for i := 0; i < len(cs) && i < 3; i++ {
			k.TopCountries = append(k.TopCountries, cs[i].c)
		}
		res.KPI[dir] = k
	}
	var all []Row
	for _, a := range rows {
		a.row.IPs = len(a.ips)
		nPorts := 3
		if a.row.Dir == "out" {
			nPorts = 5
		}
		a.row.Ports = topKeys(a.ports, nPorts)
		a.row.Hosts = topKeys(a.hosts, 3)
		all = append(all, a.row)
	}
	sort.Slice(all, func(i, j int) bool {
		if vi, vj := volume(all[i].Rec), volume(all[j].Rec); vi != vj {
			return vi > vj
		}
		return all[i].Remote < all[j].Remote
	})
	for _, r := range all {
		if (r.Lat != 0 || r.Lon != 0) && len(res.Points) < 150 {
			res.Points = append(res.Points, r)
		}
	}
	res.Total = len(all)
	lim := q.Limit
	if lim <= 0 {
		lim = 100
	}
	if q.Offset < len(all) {
		end := min(q.Offset+lim, len(all))
		res.Rows = all[q.Offset:end]
	}
	return res
}

func maxDur(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func topKeys[K comparable](m map[K]uint64, n int) []K {
	type kv struct {
		k K
		v uint64
	}
	var xs []kv
	for k, v := range m {
		xs = append(xs, kv{k, v})
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].v > xs[j].v })
	var out []K
	for i := 0; i < len(xs) && i < n; i++ {
		out = append(out, xs[i].k)
	}
	return out
}
