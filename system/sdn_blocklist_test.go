package system

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"zfsnas/internal/sdn"
)

// Lists come as hosts files, plain domain lists or Adblock filters; the
// names a hosts file maps for itself and anything that is not a domain are
// skipped.
func TestParseBlocklist(t *testing.T) {
	in := `# Title: test list
! adblock comment
127.0.0.1 localhost
0.0.0.0 0.0.0.0
0.0.0.0 Ads.Example.COM   # inline comment
127.0.0.1	tracker.test
::1 ip6-localhost
plain.example.org.
||adblock.example.net^
||path.example.net^$third-party
@@||exception.example.net^
not a domain line
10.0.0.1
http://example.com/page
broadcasthost
`
	got := parseBlocklist(strings.NewReader(in), 100)
	want := "adblock.example.net ads.example.com path.example.net plain.example.org tracker.test"
	if strings.Join(got, " ") != want {
		t.Fatalf("got  %v\nwant %s", got, want)
	}
	if got := parseBlocklist(strings.NewReader("a.com\nb.com\nc.com\n"), 2); len(got) != 2 {
		t.Fatalf("limit: %v", got)
	}
}

// Every name twice (IPv4 and IPv6: a name in the file only as 0.0.0.0 would
// still be looked up upstream for IPv6), the allowed ones out, the blocked
// ones in.
func TestRenderBlocklistHosts(t *testing.T) {
	got, n := renderBlocklistHosts([][]string{{"b.com", "a.com", "keep.org"}, {"a.com", "c.net"}}, []string{"keep.org"}, []string{"mine.example"})
	want := "0.0.0.0 a.com\n:: a.com\n0.0.0.0 b.com\n:: b.com\n0.0.0.0 c.net\n:: c.net\n0.0.0.0 mine.example\n:: mine.example\n"
	if !strings.HasSuffix(got, want) || n != 4 {
		t.Fatalf("%d domains:\n%s", n, got)
	}
}

func blocklistTestConfig() *sdn.Config {
	c := withServices(labBase())
	c.DNS.Blocklists = []sdn.DNSBlocklist{{ID: "bl01", URL: "https://lists.test/one", Enabled: true},
		{ID: "bl02", URL: "https://lists.test/two", Enabled: true}, {ID: "bl03", URL: "https://lists.test/off", Enabled: false}}
	c.Normalize()
	return c
}

// Lists are fetched, merged into the DNS server's file, and the server told
// to read it again (no restart). A list that cannot be fetched keeps what it
// had; changing only the allowed/blocked domains needs no download.
func TestSDNBlocklistUpdate(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	fetches := map[string]int{}
	fail := map[string]bool{}
	m := &sdnBlocklists{statePath: dir + "/blocklists.json", cache: map[string][]string{},
		fetch: func(url string) ([]string, error) {
			fetches[url]++
			if fail[url] {
				return nil, errors.New("HTTP 503")
			}
			return map[string][]string{"https://lists.test/one": {"ads.one.com", "x.com"}, "https://lists.test/two": {"x.com", "two.net"}}[url], nil
		}}
	rec.out = map[string]string{"systemctl is-active " + sdnDNSUnitName: "active\n"}
	c := blocklistTestConfig()
	now := time.Unix(1800000000, 0)
	st := m.update(c, now, false)
	b, _ := os.ReadFile(sdnBlocklistFile)
	if !strings.Contains(string(b), "0.0.0.0 two.net\n") || !strings.Contains(string(b), ":: ads.one.com\n") || st.Domains != 3 {
		t.Fatalf("file (%d domains):\n%s", st.Domains, b)
	}
	if fetches["https://lists.test/off"] != 0 {
		t.Fatal("disabled list fetched")
	}
	if st.Lists["bl01"].Domains != 2 || st.Lists["bl01"].Updated.IsZero() {
		t.Fatalf("list state %+v", st.Lists["bl01"])
	}
	if rec.index("systemctl reload "+sdnDNSUnitName) < 0 {
		t.Fatalf("DNS server not told: %v", rec.cmds)
	}

	// within a day: no download; only the allowed domains changed → rebuilt
	rec.cmds = nil
	c.DNS.Allow = []string{"x.com"}
	st = m.update(c, now.Add(time.Hour), false)
	if fetches["https://lists.test/one"] != 1 {
		t.Fatalf("downloaded again within the day: %v", fetches)
	}
	if b, _ := os.ReadFile(sdnBlocklistFile); strings.Contains(string(b), " x.com\n") || st.Domains != 2 {
		t.Fatalf("allowed domain still blocked:\n%s", b)
	}

	// a day later, one list fails: it keeps its domains and says why
	fail["https://lists.test/two"] = true
	st = m.update(c, now.Add(25*time.Hour), false)
	if st.Lists["bl02"].Error == "" || st.Lists["bl02"].Domains != 2 {
		t.Fatalf("failed list %+v", st.Lists["bl02"])
	}
	if b, _ := os.ReadFile(sdnBlocklistFile); !strings.Contains(string(b), " two.net\n") {
		t.Fatal("the failed list's domains were dropped")
	}

	// nothing to block any more: the file goes
	c.DNS.Blocklists, c.DNS.Deny = nil, nil
	m.update(c, now.Add(26*time.Hour), false)
	if _, err := os.Stat(sdnBlocklistFile); !os.IsNotExist(err) {
		t.Fatal("blocklist file kept with nothing to block")
	}
}
