package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Lines as dnsmasq 2.91 writes them with log-queries=extra (captured on the
// lab VM): every line of one query carries its serial and client.
const dnsLogSample = `Oct 30 20:29:27 dnsmasq[884197]: started, version 2.91 cachesize 1000
Oct 30 20:29:28 dnsmasq[884197]: 1 10.97.8.20/53208 query[A] example.com from 10.97.8.20
Oct 30 20:29:28 dnsmasq[884197]: 1 10.97.8.20/53208 forwarded example.com to 1.1.1.1
Oct 30 20:29:28 dnsmasq[884197]: 1 10.97.8.20/53208 reply example.com is 104.20.23.154
Oct 30 20:29:28 dnsmasq[884197]: 1 10.97.8.20/53208 reply example.com is 172.66.147.243
Oct 30 20:29:28 dnsmasq[884197]: 2 10.97.8.21/33697 query[A] example.com from 10.97.8.21
Oct 30 20:29:28 dnsmasq[884197]: 2 10.97.8.21/33697 cached example.com is 104.20.23.154
Oct 30 20:29:28 dnsmasq[884197]: 3 10.97.8.20/39944 query[AAAA] example.com from 10.97.8.20
Oct 30 20:29:28 dnsmasq[884197]: 3 10.97.8.20/39944 forwarded example.com to 9.9.9.9
Oct 30 20:29:28 dnsmasq[884197]: 3 10.97.8.20/39944 reply example.com is 2606:4700:10::6814:179a
Oct 30 20:29:28 dnsmasq[884197]: 4 10.97.8.20/57126 query[A] ads.example.com from 10.97.8.20
Oct 30 20:29:28 dnsmasq[884197]: 4 10.97.8.20/57126 /var/lib/znas-sdn/blocklist.hosts ads.example.com is 0.0.0.0
Oct 30 20:29:28 dnsmasq[884197]: 5 10.97.8.21/49339 query[AAAA] ads.example.com from 10.97.8.21
Oct 30 20:29:28 dnsmasq[884197]: 5 10.97.8.21/49339 /var/lib/znas-sdn/blocklist.hosts ads.example.com is ::
Oct 30 20:29:28 dnsmasq[884197]: 7 10.97.8.20/59430 query[A] cam.lab.lan from 10.97.8.20
Oct 30 20:29:28 dnsmasq[884197]: 7 10.97.8.20/59430 /run/znas-sdn-dns/hosts.d/net800 cam.lab.lan is 10.97.8.20
Oct 30 20:29:28 dnsmasq[884197]: 8 10.97.8.20/46085 query[A] nas.lab.lan from 10.97.8.20
Oct 30 20:29:28 dnsmasq[884197]: 8 10.97.8.20/46085 config nas.lab.lan is 10.97.8.5
Oct 30 20:29:29 dnsmasq[884197]: 9 10.97.8.20/37739 query[A] nothere.lab.lan from 10.97.8.20
Oct 30 20:29:29 dnsmasq[884197]: 9 10.97.8.20/37739 config nothere.lab.lan is NXDOMAIN
Oct 30 20:29:29 dnsmasq[884197]: 10 10.97.8.20/60632 query[A] nosuchdomain-zzzz.com from 10.97.8.20
Oct 30 20:29:29 dnsmasq[884197]: 10 10.97.8.20/60632 forwarded nosuchdomain-zzzz.com to 1.1.1.1
Oct 30 20:29:29 dnsmasq[884197]: 10 10.97.8.20/60632 reply nosuchdomain-zzzz.com is NXDOMAIN
Oct 30 20:29:29 dnsmasq[884197]: 11 10.97.8.20/55798 query[PTR] 20.8.97.10.in-addr.arpa from 10.97.8.20
Oct 30 20:29:29 dnsmasq[884197]: 11 10.97.8.20/55798 /run/znas-sdn-dns/hosts.d/net800 10.97.8.20 is cam.lab.lan
Oct 30 20:29:29 dnsmasq[884197]: 12 10.97.8.20/43273 query[MX] google.com from 10.97.8.20
Oct 30 20:29:29 dnsmasq[884197]: 12 10.97.8.20/43273 forwarded google.com to 1.1.1.1
Oct 30 20:29:29 dnsmasq[884197]: 12 10.97.8.20/43273 reply google.com is <MX>
`

var dnsTestPaths = sdnDNSLogPaths{blocklist: "/var/lib/znas-sdn/blocklist.hosts", hostsDir: "/run/znas-sdn-dns/hosts.d"}

func feedDNS(s *sdnDNSStats, text string, now time.Time) {
	for _, l := range strings.Split(text, "\n") {
		s.line(l, now)
	}
}

// Each query ends up with what happened to it: forwarded (and to which
// server), answered from the cache, answered here (names of this router and
// of the DHCP networks), or blocked by a list — and the answer.
func TestSDNDNSStats_ClassifiesQueries(t *testing.T) {
	now := time.Date(2026, 10, 30, 20, 30, 0, 0, time.Local)
	s := newSDNDNSStats(dnsTestPaths, 1000)
	feedDNS(s, dnsLogSample, now)
	got := s.queries(sdnDNSFilter{}, 100)
	if len(got) != 11 {
		t.Fatalf("%d queries: %+v", len(got), got)
	}
	// newest first
	want := []struct{ domain, typ, client, status, reply, upstream string }{
		{"google.com", "MX", "10.97.8.20", "forwarded", "<MX>", "1.1.1.1"},
		{"20.8.97.10.in-addr.arpa", "PTR", "10.97.8.20", "local", "cam.lab.lan", ""},
		{"nosuchdomain-zzzz.com", "A", "10.97.8.20", "forwarded", "NXDOMAIN", "1.1.1.1"},
		{"nothere.lab.lan", "A", "10.97.8.20", "local", "NXDOMAIN", ""},
		{"nas.lab.lan", "A", "10.97.8.20", "local", "10.97.8.5", ""},
		{"cam.lab.lan", "A", "10.97.8.20", "local", "10.97.8.20", ""},
		{"ads.example.com", "AAAA", "10.97.8.21", "blocked", "::", ""},
		{"ads.example.com", "A", "10.97.8.20", "blocked", "0.0.0.0", ""},
		{"example.com", "AAAA", "10.97.8.20", "forwarded", "2606:4700:10::6814:179a", "9.9.9.9"},
		{"example.com", "A", "10.97.8.21", "cached", "104.20.23.154", ""},
		{"example.com", "A", "10.97.8.20", "forwarded", "104.20.23.154", "1.1.1.1"},
	}
	for i, w := range want {
		q := got[i]
		if q.Domain != w.domain || q.Type != w.typ || q.Client != w.client || q.Status != w.status || q.Reply != w.reply || q.Upstream != w.upstream {
			t.Errorf("query %d: %+v, want %+v", i, q, w)
		}
	}
	if got[0].T != time.Date(2026, 10, 30, 20, 29, 29, 0, time.Local).Unix() {
		t.Errorf("time %v", time.Unix(got[0].T, 0))
	}
}

// The numbers behind the dashboard: totals, blocked share, query types, who
// answered, top domains (allowed and blocked), top clients.
func TestSDNDNSStats_Summary(t *testing.T) {
	now := time.Date(2026, 10, 30, 20, 30, 0, 0, time.Local)
	s := newSDNDNSStats(dnsTestPaths, 1000)
	feedDNS(s, dnsLogSample, now)
	sum := s.summary(now, 24*time.Hour, 10)
	if sum.Total != 11 || sum.Blocked != 2 || sum.Cached != 1 || sum.Forwarded != 4 || sum.Local != 4 || sum.Clients != 2 {
		t.Fatalf("totals %+v", sum)
	}
	if sum.Types["A"] != 7 || sum.Types["AAAA"] != 2 || sum.Types["PTR"] != 1 || sum.Types["MX"] != 1 {
		t.Fatalf("types %v", sum.Types)
	}
	if sum.Upstreams["1.1.1.1"] != 3 || sum.Upstreams["9.9.9.9"] != 1 || sum.Upstreams["cache"] != 1 || sum.Upstreams["blocklist"] != 2 || sum.Upstreams["local"] != 4 {
		t.Fatalf("answered by %v", sum.Upstreams)
	}
	if len(sum.TopDomains) == 0 || sum.TopDomains[0].Key != "example.com" || sum.TopDomains[0].N != 3 {
		t.Fatalf("top domains %+v", sum.TopDomains)
	}
	if len(sum.TopBlocked) != 1 || sum.TopBlocked[0].Key != "ads.example.com" || sum.TopBlocked[0].N != 2 {
		t.Fatalf("top blocked %+v", sum.TopBlocked)
	}
	if sum.TopClients[0].Key != "10.97.8.20" || sum.TopClients[0].N != 9 || len(sum.TopClientsBlocked) != 2 {
		t.Fatalf("clients %+v / %+v", sum.TopClients, sum.TopClientsBlocked)
	}
	// over time: one 10-minute point holds them all, split allowed/blocked
	var tot, blk int
	for _, p := range sum.Series {
		tot += p.Allowed + p.Blocked
		blk += p.Blocked
	}
	if tot != 11 || blk != 2 || len(sum.Series) != 144 {
		t.Fatalf("series %d points, %d queries, %d blocked", len(sum.Series), tot, blk)
	}
	if len(sum.ClientSeries.Clients) != 2 {
		t.Fatalf("client activity %+v", sum.ClientSeries.Clients)
	}
}

// The query log is filtered by domain text, client and outcome.
func TestSDNDNSStats_QueryFilters(t *testing.T) {
	now := time.Date(2026, 10, 30, 20, 30, 0, 0, time.Local)
	s := newSDNDNSStats(dnsTestPaths, 1000)
	feedDNS(s, dnsLogSample, now)
	if got := s.queries(sdnDNSFilter{Status: "blocked"}, 100); len(got) != 2 {
		t.Fatalf("blocked %+v", got)
	}
	if got := s.queries(sdnDNSFilter{Client: "10.97.8.21"}, 100); len(got) != 2 {
		t.Fatalf("client %+v", got)
	}
	if got := s.queries(sdnDNSFilter{Domain: "EXAMPLE"}, 100); len(got) != 5 {
		t.Fatalf("domain %+v", got)
	}
	if got := s.queries(sdnDNSFilter{Status: "allowed"}, 100); len(got) != 9 {
		t.Fatalf("allowed %+v", got)
	}
	if got := s.queries(sdnDNSFilter{}, 3); len(got) != 3 || got[0].Domain != "google.com" {
		t.Fatalf("limit %+v", got)
	}
}

// The query log keeps the newest queries only.
func TestSDNDNSStats_RingLimit(t *testing.T) {
	now := time.Date(2026, 10, 30, 20, 30, 0, 0, time.Local)
	s := newSDNDNSStats(dnsTestPaths, 4)
	feedDNS(s, dnsLogSample, now)
	got := s.queries(sdnDNSFilter{}, 100)
	if len(got) != 4 || got[0].Domain != "google.com" || got[3].Domain != "nothere.lab.lan" {
		t.Fatalf("%+v", got)
	}
	// the counts are not limited by the log's size
	if sum := s.summary(now, 24*time.Hour, 10); sum.Total != 11 {
		t.Fatalf("total %d", sum.Total)
	}
}

// History survives a portal restart (saved to the statistics folder), and
// the hourly records give the long ranges.
func TestSDNDNSStats_SaveLoadAndLongRange(t *testing.T) {
	dir := t.TempDir()
	day1 := time.Date(2026, 10, 29, 9, 15, 0, 0, time.Local)
	s := newSDNDNSStats(dnsTestPaths, 1000)
	feedDNS(s, strings.ReplaceAll(dnsLogSample, "Oct 30 20:29", "Oct 29 09:14"), day1)
	day2 := time.Date(2026, 10, 30, 20, 30, 0, 0, time.Local)
	feedDNS(s, dnsLogSample, day2)
	if err := s.save(dir, day2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "2026-10-29.json.gz")); err != nil {
		t.Fatalf("day file: %v", err)
	}
	r := newSDNDNSStats(dnsTestPaths, 1000)
	if err := r.load(dir, day2); err != nil {
		t.Fatal(err)
	}
	if got := r.queries(sdnDNSFilter{}, 100); len(got) != 22 {
		t.Fatalf("query log after restart: %d", len(got))
	}
	sum := r.summary(day2, 7*24*time.Hour, 10)
	if sum.Total != 22 || sum.Blocked != 4 {
		t.Fatalf("7 days after restart %+v", sum)
	}
	if len(sum.Series) != 168 {
		t.Fatalf("7 days: hourly points, got %d", len(sum.Series))
	}
	// lines already counted before the restart are not counted again
	feedDNS(r, dnsLogSample, day2)
	if sum := r.summary(day2, 24*time.Hour, 10); sum.Total != 11 {
		t.Fatalf("re-read log counted twice: %d", sum.Total)
	}
	if sum := r.summary(day2, 365*24*time.Hour, 10); len(sum.Series) != 365 || sum.Total != 22 {
		t.Fatalf("1 year: daily points %d, total %d", len(sum.Series), sum.Total)
	}
}

// The reader follows the log file across rotations and keeps partial lines.
func TestSDNDNSTail(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "queries.log")
	_ = os.WriteFile(p, []byte("line1\nlin"), 0644)
	var got []string
	tl := &sdnTail{path: p}
	tl.poll(func(l string) { got = append(got, l) })
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString("e2\nline3\n")
	f.Close()
	// rotated: the rest of the old file, then the new one
	_ = os.Rename(p, p+".1")
	f, _ = os.OpenFile(p+".1", os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString("line4\n")
	f.Close()
	_ = os.WriteFile(p, []byte("line5\n"), 0644)
	tl.poll(func(l string) { got = append(got, l) })
	tl.poll(func(l string) { got = append(got, l) })
	if strings.Join(got, ",") != "line1,line2,line3,line4,line5" {
		t.Fatalf("%v", got)
	}
}
