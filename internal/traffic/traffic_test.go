package traffic

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"zfsnas/internal/geoip"
)

const (
	listLine  = "ipv4     2 tcp      6 431999 ESTABLISHED src=89.160.20.112 dst=192.168.2.130 sport=51000 dport=52400 packets=10 bytes=1000 src=10.97.8.10 dst=89.160.20.112 sport=32400 dport=51000 packets=20 bytes=50000 [ASSURED] mark=0 use=1 id=4242"
	destroyEv = "[1761681234.123456]\t [DESTROY] ipv4     2 tcp      6 src=89.160.20.112 dst=192.168.2.130 sport=51000 dport=52400 packets=15 bytes=1500 src=10.97.8.10 dst=89.160.20.112 sport=32400 dport=51000 packets=30 bytes=80000 [ASSURED] mark=0 id=4242"
)

func TestParseConntrack(t *testing.T) {
	f, ok := ParseConntrack(listLine)
	if !ok {
		t.Fatal("not parsed")
	}
	if f.ID != 4242 || f.Proto != "tcp" || f.OrigSrc.String() != "89.160.20.112" || f.ReplySrc.String() != "10.97.8.10" ||
		f.OrigDport != 52400 || f.ReplySport != 32400 || f.BytesOrig != 1000 || f.BytesReply != 50000 || f.Destroy {
		t.Fatalf("%+v", f)
	}
	d, ok := ParseConntrack(destroyEv)
	if !ok || !d.Destroy || d.BytesReply != 80000 || d.At.Unix() != 1761681234 {
		t.Fatalf("%+v", d)
	}
	icmp, ok := ParseConntrack("ipv4     2 icmp     1 29 src=10.97.9.20 dst=8.8.8.8 type=8 code=0 id=17 packets=1 bytes=84 src=8.8.8.8 dst=192.168.2.130 type=0 code=0 id=17 packets=1 bytes=84 mark=0 use=1 id=99")
	if !ok || icmp.ID != 99 || icmp.Proto != "icmp" || icmp.ReplyDst.String() != "192.168.2.130" {
		t.Fatalf("icmp %+v", icmp)
	}
	if _, ok := ParseConntrack("conntrack v1.4.8 (conntrack-tools): 12 flow entries have been shown."); ok {
		t.Fatal("summary line parsed as a flow")
	}
}

func testEnv() Env {
	return Env{
		Local: func(a netip.Addr) bool {
			return a.String() == "192.168.2.130" || strings.HasPrefix(a.String(), "10.97.") && strings.HasSuffix(a.String(), ".1")
		},
		IfaceOf: func(a netip.Addr) string {
			if a.String() == "192.168.2.130" {
				return "enp5s0"
			}
			return ""
		},
		NameOf: func(a netip.Addr) string {
			if a.String() == "10.97.8.10" {
				return "plex"
			}
			return ""
		},
		Geo: func(a netip.Addr) geoip.Info {
			switch a.String() {
			case "89.160.20.112":
				return geoip.Info{CountryCode: "SE", Country: "Sweden", City: "Stockholm", Lat: 59.3, Lon: 18.1}
			case "140.82.112.4":
				return geoip.Info{CountryCode: "US", Country: "United States", City: "San Francisco"}
			}
			return geoip.Info{}
		},
	}
}

func TestClassify_IncomingDNAT(t *testing.T) {
	f, _ := ParseConntrack(listLine)
	_, r, ok := Classify(f, testEnv())
	if !ok || r.Dir != "in" || r.Remote != "89.160.20.112" || r.Inside != "10.97.8.10" || r.Port != 32400 || r.PubPort != 52400 ||
		r.PubIP != "192.168.2.130" || r.Iface != "enp5s0" || r.Name != "plex" || r.CC != "SE" || r.City != "Stockholm" {
		t.Fatalf("%+v", r)
	}
}

func TestClassify_IncomingToZNAS(t *testing.T) {
	f, _ := ParseConntrack("ipv4 2 udp 17 29 src=89.160.20.112 dst=192.168.2.130 sport=40000 dport=51820 packets=3 bytes=300 src=192.168.2.130 dst=89.160.20.112 sport=51820 dport=40000 packets=3 bytes=300 mark=0 use=1 id=7")
	_, r, ok := Classify(f, testEnv())
	if !ok || r.Dir != "in" || r.Inside != "192.168.2.130" || r.Name != "This ZNAS" {
		t.Fatalf("%+v", r)
	}
}

func TestClassify_OutgoingSNAT(t *testing.T) {
	f, _ := ParseConntrack("ipv4 2 tcp 6 100 ESTABLISHED src=10.97.9.20 dst=140.82.112.4 sport=40000 dport=443 packets=10 bytes=2000 src=140.82.112.4 dst=192.168.2.130 sport=443 dport=40000 packets=12 bytes=90000 [ASSURED] mark=0 use=1 id=8")
	_, r, ok := Classify(f, testEnv())
	if !ok || r.Dir != "out" || r.Remote != "140.82.112.4" || r.Inside != "10.97.9.20" || r.Port != 443 || r.Iface != "enp5s0" ||
		r.BytesOut != 2000 || r.BytesIn != 90000 || r.CC != "US" {
		t.Fatalf("%+v", r)
	}
}

func TestClassify_InternalIgnored(t *testing.T) {
	f, _ := ParseConntrack("ipv4 2 tcp 6 100 ESTABLISHED src=10.97.7.10 dst=10.97.8.10 sport=40000 dport=22 packets=1 bytes=60 src=10.97.8.10 dst=10.97.7.10 sport=22 dport=40000 packets=1 bytes=60 mark=0 use=1 id=9")
	if _, _, ok := Classify(f, testEnv()); ok {
		t.Fatal("private ↔ private traffic must not be in the outside tables")
	}
}

var t0 = time.Date(2026, 10, 28, 12, 1, 0, 0, time.UTC)

func flowAt(line string, at time.Time) Flow {
	f, _ := ParseConntrack(line)
	f.At = at
	return f
}

// A flow seen by the poll, then destroyed, is counted once with its final
// counters; a flow already open when the collector starts is not counted
// for the bytes it had before (they may already be on disk).
func TestAggregator_NoDoubleCount(t *testing.T) {
	a := NewAggregator(testEnv())
	a.Seeded = true
	a.AddFlow(flowAt(listLine, t0))
	a.AddFlow(flowAt(destroyEv, t0.Add(30*time.Second)))
	r := single(t, a.Snapshot(), "in")
	if r.BytesIn != 1500 || r.BytesOut != 80000 || r.Sessions != 1 {
		t.Fatalf("%+v", r)
	}

	b := NewAggregator(testEnv()) // fresh start: first poll seeds only
	b.AddFlow(flowAt(listLine, t0))
	b.Seeded = true
	b.AddFlow(flowAt(destroyEv, t0.Add(30*time.Second)))
	r = single(t, b.Snapshot(), "in")
	if r.BytesIn != 500 || r.BytesOut != 30000 {
		t.Fatalf("pre-start bytes counted: %+v", r)
	}
}

func single(t *testing.T, bs []Bucket, dir string) Rec {
	t.Helper()
	var out []Rec
	for _, b := range bs {
		for _, r := range b.Recs {
			if r.Dir == dir {
				out = append(out, r)
			}
		}
	}
	if len(out) != 1 {
		t.Fatalf("want 1 %s rec, got %+v", dir, out)
	}
	return out[0]
}

func TestAggregator_BucketsAndDrain(t *testing.T) {
	a := NewAggregator(testEnv())
	a.Seeded = true
	a.AddFlow(flowAt(destroyEv, t0))                    // 12:00 bucket
	a.AddFlow(flowAt(destroyEv, t0.Add(6*time.Minute))) // 12:05 bucket (same id, new flow)
	drained := a.Drain(t0.Add(5 * time.Minute))
	if len(drained) != 1 || !drained[0].Start.Equal(time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("drain %+v", drained)
	}
	if len(a.Snapshot()) != 1 {
		t.Fatal("open bucket must stay")
	}
}

func TestAggregator_Blocked(t *testing.T) {
	a := NewAggregator(testEnv())
	a.AddBlocked([]Blocked{{Src: "89.160.20.112", Proto: "tcp", Port: 22, Iface: "enp6s0", Rule: "default deny", Packets: 5}}, t0)
	a.AddBlocked([]Blocked{{Src: "89.160.20.112", Proto: "tcp", Port: 22, Iface: "enp6s0", Rule: "default deny", Packets: 8}}, t0.Add(time.Minute))
	a.AddBlocked([]Blocked{{Src: "89.160.20.112", Proto: "tcp", Port: 22, Iface: "enp6s0", Rule: "default deny", Packets: 2}}, t0.Add(2*time.Minute)) // element expired+recreated
	r := single(t, a.Snapshot(), "blk")
	if r.Pkts != 10 || r.CC != "SE" || r.Port != 22 {
		t.Fatalf("%+v", r)
	}
}

// Memory stays bounded: past the cap, records fold into per-country rows.
func TestAggregator_CapFoldsIntoCountry(t *testing.T) {
	a := NewAggregator(testEnv())
	a.Seeded = true
	a.Cap = 1
	a.AddFlow(flowAt(destroyEv, t0))
	other := strings.ReplaceAll(destroyEv, "sport=51000", "sport=51001")
	other = strings.ReplaceAll(other, "dport=52400", "dport=52401")
	other = strings.ReplaceAll(other, "id=4242", "id=5")
	a.AddFlow(flowAt(other, t0))
	recs := a.Snapshot()[0].Recs
	if len(recs) != 2 {
		t.Fatalf("%+v", recs)
	}
	var folded *Rec
	for i := range recs {
		if recs[i].Remote == "" {
			folded = &recs[i]
		}
	}
	if folded == nil || folded.CC != "SE" || folded.BytesOut != 80000 {
		t.Fatalf("overflow not folded into the country row: %+v", recs)
	}
}

// A record first classified before the facts were known (address just
// assigned, geo DB still downloading) gets them from later sightings.
func TestAggregator_FillsMissingFacts(t *testing.T) {
	env := testEnv()
	geo := env.Geo
	env.Geo = nil
	a := NewAggregator(env)
	a.Seeded = true
	a.AddFlow(flowAt(destroyEv, t0))
	a.Env.Geo = geo
	second := strings.ReplaceAll(destroyEv, "id=4242", "id=4243")
	a.AddFlow(flowAt(second, t0.Add(time.Minute)))
	r := single(t, a.Snapshot(), "in")
	if r.CC != "SE" || r.City != "Stockholm" || r.Name != "plex" {
		t.Fatalf("facts not filled: %+v", r)
	}
}

func TestAggregator_BlockedBaselinesPruned(t *testing.T) {
	a := NewAggregator(testEnv())
	a.AddBlocked([]Blocked{{Src: "1.1.1.1", Proto: "tcp", Port: 22, Packets: 1}, {Src: "1.1.1.2", Proto: "tcp", Port: 22, Packets: 1}}, t0)
	a.AddBlocked([]Blocked{{Src: "1.1.1.2", Proto: "tcp", Port: 22, Packets: 3}}, t0.Add(time.Minute))
	if n := a.BlockedTracked(); n != 1 {
		t.Fatalf("expired set elements must be forgotten: %d tracked", n)
	}
}

func TestClassify_RouterOwnPublicAddress(t *testing.T) {
	env := testEnv()
	env.Local = func(a netip.Addr) bool { return a.String() == "74.15.1.2" }
	f, _ := ParseConntrack("ipv4 2 tcp 6 100 ESTABLISHED src=74.15.1.2 dst=140.82.112.4 sport=40000 dport=443 packets=1 bytes=100 src=140.82.112.4 dst=74.15.1.2 sport=443 dport=40000 packets=1 bytes=900 mark=0 use=1 id=11")
	_, r, ok := Classify(f, env)
	if !ok || r.Dir != "out" || r.Name != "This ZNAS" {
		t.Fatalf("router-originated traffic from a public WAN address must count as outgoing: %+v %v", r, ok)
	}
}

func TestAggregator_SetSeeded(t *testing.T) {
	a := NewAggregator(testEnv())
	a.SetSeeded()
	a.AddFlow(flowAt(listLine, t0))
	if len(a.Snapshot()) != 1 {
		t.Fatal("seeded aggregator must count new flows")
	}
}
