package traffic

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"zfsnas/internal/geoip"
)

func rec(dir, remote, cc string, bytes uint64, sessions uint64, at time.Time) Rec {
	return Rec{Dir: dir, Remote: remote, Inside: "10.97.8.10", Proto: "tcp", PubPort: 443, Port: 443, CC: cc, Country: cc, City: cc + "-city",
		BytesIn: bytes, Sessions: sessions, First: at, Last: at}
}

func bucket(at time.Time, recs ...Rec) Bucket {
	return Bucket{Start: at.Truncate(BucketSize), Recs: recs}
}

var day = time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)

func TestStore_WriteOncePerFlush(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	if err := s.Write([]Bucket{bucket(day.Add(10*time.Minute), rec("in", "1.1.1.1", "AU", 100, 1, day))}); err != nil {
		t.Fatal(err)
	}
	if err := s.Write([]Bucket{bucket(day.Add(20*time.Minute), rec("in", "1.1.1.1", "AU", 50, 1, day))}); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(s.Dir, "5m", "*"))
	if len(files) != 1 || filepath.Base(files[0]) != "20261028.jsonl.gz" {
		t.Fatalf("files %v", files)
	}
	res := s.Query(Query{From: day, To: day.Add(time.Hour), Dir: "in", Group: "ip"}, nil, day.Add(time.Hour))
	if len(res.Rows) != 1 || res.Rows[0].BytesIn != 150 || res.Rows[0].Sessions != 2 || res.KPI["in"].Bytes != 150 {
		t.Fatalf("%+v", res)
	}
}

// Review focus 5: totals across tiers agree.
func TestStore_RollupTotalsAgree(t *testing.T) {
	s := &Store{Dir: t.TempDir(), TopN: map[string]int{"1h": 1, "1d": 1}}
	var bs []Bucket
	for i := 0; i < 12; i++ { // one hour of 5-min buckets, two remotes each
		at := day.Add(time.Duration(i) * BucketSize)
		bs = append(bs, bucket(at, rec("in", "1.1.1.1", "AU", 100, 1, at), rec("in", "89.160.20.112", "SE", 10, 1, at)))
	}
	_ = s.Write(bs)
	if err := s.Rollup(day.Add(26 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	five := s.Query(Query{From: day, To: day.Add(time.Hour), Dir: "in", Group: "ip"}, nil, day.Add(time.Hour))
	hour := s.Query(Query{From: day, To: day.Add(5 * 24 * time.Hour), Dir: "in", Group: "country"}, nil, day.Add(26*time.Hour))
	dayq := s.Query(Query{From: day, To: day.Add(90 * 24 * time.Hour), Dir: "in", Group: "country"}, nil, day.Add(90*24*time.Hour))
	if five.KPI["in"].Bytes != 1320 || hour.KPI["in"].Bytes != 1320 || dayq.KPI["in"].Bytes != 1320 {
		t.Fatalf("totals differ: 5m %d, 1h %d, 1d %d", five.KPI["in"].Bytes, hour.KPI["in"].Bytes, dayq.KPI["in"].Bytes)
	}
	// top-1 in the hourly tier: SE folded into its exact country row
	h := s.Query(Query{From: day, To: day.Add(5 * 24 * time.Hour), Dir: "in", Group: "ip"}, nil, day.Add(26*time.Hour))
	var se uint64
	for _, r := range h.Rows {
		if r.CC == "SE" {
			se += r.BytesIn
			if r.Remote != "" {
				t.Fatalf("SE should have been folded: %+v", r)
			}
		}
	}
	if se != 120 {
		t.Fatalf("SE total %d", se)
	}
}

func TestStore_Prune(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	old := day.AddDate(0, 0, -20)
	_ = s.Write([]Bucket{bucket(old, rec("in", "1.1.1.1", "AU", 1, 1, old))})
	_ = s.Write([]Bucket{bucket(day, rec("in", "1.1.1.1", "AU", 1, 1, day))})
	s.Prune(day)
	files, _ := filepath.Glob(filepath.Join(s.Dir, "5m", "*"))
	if len(files) != 1 {
		t.Fatalf("5-min data older than 14 days must go: %v", files)
	}
}

func TestStore_QueryFilterGroupsAndOpenBuckets(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	_ = s.Write([]Bucket{bucket(day, rec("in", "1.1.1.1", "AU", 100, 1, day), rec("in", "89.160.20.112", "SE", 10, 1, day),
		Rec{Dir: "blk", Remote: "175.16.199.1", CC: "CN", Country: "China", Port: 22, Pkts: 7, Sessions: 7, Rule: "default deny", First: day, Last: day})})
	open := []Bucket{bucket(day.Add(BucketSize), rec("in", "89.160.20.112", "SE", 5, 1, day.Add(BucketSize)))}
	r := s.Query(Query{From: day, To: day.Add(time.Hour), Dir: "in", Group: "ip", Filter: "se-city"}, open, day.Add(time.Hour))
	if len(r.Rows) != 1 || r.Rows[0].BytesIn != 15 {
		t.Fatalf("%+v", r.Rows)
	}
	c := s.Query(Query{From: day, To: day.Add(time.Hour), Dir: "blk", Group: "country"}, open, day.Add(time.Hour))
	if len(c.Rows) != 1 || c.Rows[0].Pkts != 7 || c.KPI["blk"].Pkts != 7 || len(c.Rows[0].Ports) != 1 || c.Rows[0].Ports[0] != 22 {
		t.Fatalf("%+v %+v", c.Rows, c.KPI)
	}
	if _, err := os.Stat(s.Dir); err != nil {
		t.Fatal(err)
	}
}

// Outgoing lines to one address merge every port we reached there: the row
// lists them, busiest first (port 0 — ICMP — is not a port).
func TestStore_QueryOutgoingKeepsPorts(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	out := func(port uint16, bytes uint64) Rec {
		r := rec("out", "142.250.1.1", "US", bytes, 1, day)
		r.Port, r.PubPort, r.Lat, r.Lon = port, 0, 37.4, -122.1
		return r
	}
	_ = s.Write([]Bucket{bucket(day, out(443, 900), out(80, 50), out(853, 300), out(0, 999))})
	r := s.Query(Query{From: day, To: day.Add(time.Hour), Dir: "out", Group: "ip"}, nil, day.Add(time.Hour))
	if len(r.Rows) != 1 {
		t.Fatalf("rows %+v", r.Rows)
	}
	if got := r.Rows[0].Ports; len(got) != 3 || got[0] != 443 || got[1] != 853 || got[2] != 80 {
		t.Fatalf("ports %v, want [443 853 80]", got)
	}
	if len(r.Points) != 1 || len(r.Points[0].Ports) != 3 {
		t.Fatalf("map points must carry the ports too: %+v", r.Points)
	}
}

// After a location database change, old lines show the current database's
// answer (table and map); an address it does not know keeps the recorded one.
func TestStore_QueryLocatesAgain(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	old := rec("in", "24.50.76.243", "CA", 100, 1, day)
	old.City, old.Lat, old.Lon = "Trois-Rivières", 46.34, -72.62
	_ = s.Write([]Bucket{bucket(day, old, rec("in", "89.160.20.112", "SE", 10, 1, day))})
	asked := 0
	q := Query{From: day, To: day.Add(time.Hour), Dir: "in", Group: "ip", Locate: func(ip string) (geoip.Info, bool) {
		asked++
		if ip == "24.50.76.243" {
			return geoip.Info{CountryCode: "CA", Country: "Canada", City: "Roberval", Lat: 48.52, Lon: -72.24}, true
		}
		return geoip.Info{}, true // not in the new database
	}}
	r := s.Query(q, nil, day.Add(time.Hour))
	got := map[string]Row{}
	for _, row := range r.Rows {
		got[row.Remote] = row
	}
	if g := got["24.50.76.243"]; g.City != "Roberval" || g.Lat != 48.52 {
		t.Fatalf("not located again: %+v", g)
	}
	if g := got["89.160.20.112"]; g.City != "SE-city" {
		t.Fatalf("unknown address lost its recorded place: %+v", g)
	}
	c := s.Query(Query{From: q.From, To: q.To, Dir: "in", Group: "city", Locate: q.Locate}, nil, day.Add(time.Hour))
	for _, row := range c.Rows {
		if row.City == "Trois-Rivières" {
			t.Fatalf("city view still shows the old place: %+v", c.Rows)
		}
	}
}

func TestStore_HostIPsFollowHosts(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	a := rec("out", "1.1.1.1", "AU", 500, 1, day)
	a.Inside, a.Name = "10.0.0.5", "nas.lan"
	b := rec("out", "1.1.1.1", "AU", 100, 1, day)
	b.Inside = "10.0.0.9" // no name known: shown by its address
	_ = s.Write([]Bucket{bucket(day, a, b)})
	r := s.Query(Query{From: day, To: day.Add(time.Hour), Dir: "out", Group: "ip"}, nil, day.Add(time.Hour))
	if len(r.Rows) != 1 {
		t.Fatalf("rows: %+v", r.Rows)
	}
	row := r.Rows[0]
	if len(row.Hosts) != 2 || row.Hosts[0] != "nas.lan" || row.HostIPs[0] != "10.0.0.5" || row.Hosts[1] != "10.0.0.9" || row.HostIPs[1] != "10.0.0.9" {
		t.Fatalf("hosts %v / %v", row.Hosts, row.HostIPs)
	}
}
