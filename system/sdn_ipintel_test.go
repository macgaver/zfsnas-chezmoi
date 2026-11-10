package system

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSDNParseRepList(t *testing.T) {
	in := `# FireHOL
1.2.3.0/24
5.6.7.8
;comment
{"cidr":"9.9.0.0/16","sblid":"SBL1","rir":"ripencc"}
{"type":"metadata","timestamp":1}
10.0.0.1 ; trailing
bogus
`
	got := sdnParseRepList(strings.NewReader(in))
	want := []string{"1.2.3.0/24", "5.6.7.8/32", "9.9.0.0/16", "10.0.0.1/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i, p := range got {
		if p.String() != want[i] {
			t.Errorf("%d: got %s want %s", i, p, want[i])
		}
	}
}

func TestSDNRepCheck(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "firehol-level1.txt"), []byte("45.138.0.0/16\n"), 0644)
	os.WriteFile(filepath.Join(dir, "tor-exit.txt"), []byte("45.138.12.51\n"), 0644)
	hits, lists := sdnRepCheck(dir, netip.MustParseAddr("45.138.12.51"))
	if len(lists) != 3 || lists[0].Entries != 0 || lists[1].Entries != 1 {
		t.Fatalf("lists %+v", lists)
	}
	if len(hits) != 2 || hits[0].Entry != "45.138.0.0/16" || hits[1].Entry != "45.138.12.51" {
		t.Fatalf("hits %+v", hits)
	}
	if h, _ := sdnRepCheck(dir, netip.MustParseAddr("8.8.8.8")); len(h) != 0 {
		t.Fatalf("8.8.8.8 listed: %+v", h)
	}
}

func TestSDNUpdateRepListsKeepsOldOnEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "empty") {
			w.Write([]byte("# nothing\n"))
			return
		}
		w.Write([]byte("1.2.3.4\n"))
	}))
	defer srv.Close()
	old := sdnRepLists
	defer func() { sdnRepLists = old }()
	sdnRepLists = []sdnRepList{{ID: "a", URL: srv.URL + "/ok"}, {ID: "b", URL: srv.URL + "/empty"}}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("7.7.7.7\n"), 0644)
	os.Chtimes(filepath.Join(dir, "b.txt"), time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))
	if err := SDNUpdateRepLists(dir, time.Now()); err == nil {
		t.Fatal("empty download should report an error")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(b) != "1.2.3.4\n" {
		t.Fatalf("a = %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "b.txt")); string(b) != "7.7.7.7\n" {
		t.Fatalf("b replaced: %q", b)
	}
}

func TestSDNRDAPParse(t *testing.T) {
	// trimmed RIPE answer: owner and abuse contact nested
	j := `{"handle":"45.138.12.0 - 45.138.12.255","name":"EXAMPLE-NET","startAddress":"45.138.12.0","endAddress":"45.138.12.255","country":"NL","port43":"whois.ripe.net",
	"cidr0_cidrs":[{"v4prefix":"45.138.12.0","length":24}],
	"events":[{"eventAction":"registration","eventDate":"2020-01-02T00:00:00Z"},{"eventAction":"last changed","eventDate":"2024-05-06T10:00:00Z"}],
	"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Hosting BV"]]],
	  "entities":[{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse"],["email",{},"text","abuse@example.nl"]]]}]}],
	"links":[{"rel":"self","href":"https://rdap.db.ripe.net/ip/45.138.12.0"}]}`
	r, err := sdnRDAPParse([]byte(j))
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "EXAMPLE-NET" || r.CIDR != "45.138.12.0/24" || r.Org != "Example Hosting BV" || r.Abuse != "abuse@example.nl" ||
		r.Registry != "RIPE NCC" || r.Created != "2020-01-02" || r.Updated != "2024-05-06" || r.Range != "45.138.12.0 – 45.138.12.255" {
		t.Fatalf("%+v", r)
	}
}

func TestSDNIPExternal(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/gn/"):
			if strings.HasSuffix(r.URL.Path, "1.1.1.1") {
				w.WriteHeader(404)
				w.Write([]byte(`{"message":"IP not observed"}`))
				return
			}
			w.Write([]byte(`{"noise":true,"classification":"malicious","name":"unknown"}`))
		case strings.HasPrefix(r.URL.Path, "/ab"):
			gotKey = r.Header.Get("Key")
			w.Write([]byte(`{"data":{"abuseConfidenceScore":87,"totalReports":12}}`))
		case strings.HasPrefix(r.URL.Path, "/limit/"):
			w.WriteHeader(429)
		}
	}))
	defer srv.Close()
	old := sdnExtURL
	defer func() { sdnExtURL = old }()
	sdnExtURL = map[string]string{"greynoise": srv.URL + "/gn/", "abuseipdb": srv.URL + "/ab?ip=", "shodan": srv.URL + "/limit/"}
	clear(sdnExtCache)

	v, err := SDNIPExternal("greynoise", netip.MustParseAddr("45.138.12.51"), SDNIPIntelKeys{})
	if err != nil || v["found"] != true || v["classification"] != "malicious" {
		t.Fatalf("greynoise: %v %v", v, err)
	}
	v, err = SDNIPExternal("greynoise", netip.MustParseAddr("1.1.1.1"), SDNIPIntelKeys{})
	if err != nil || v["found"] != false {
		t.Fatalf("greynoise 404: %v %v", v, err)
	}
	if _, err = SDNIPExternal("abuseipdb", netip.MustParseAddr("45.138.12.51"), SDNIPIntelKeys{}); err == nil {
		t.Fatal("abuseipdb without key should fail")
	}
	v, err = SDNIPExternal("abuseipdb", netip.MustParseAddr("45.138.12.51"), SDNIPIntelKeys{AbuseIPDB: "k1"})
	if err != nil || gotKey != "k1" || v["abuseConfidenceScore"] != float64(87) {
		t.Fatalf("abuseipdb: %v %v key=%q", v, err, gotKey)
	}
	if _, err = SDNIPExternal("shodan", netip.MustParseAddr("45.138.12.51"), SDNIPIntelKeys{}); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("429: %v", err)
	}
	if _, err = SDNIPExternal("nope", netip.MustParseAddr("45.138.12.51"), SDNIPIntelKeys{}); err == nil {
		t.Fatal("unknown service accepted")
	}
}
