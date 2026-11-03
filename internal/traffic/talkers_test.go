package traffic

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// A connection as `conntrack -L -o extended,id` prints it on a router (SNAT:
// the reply goes to the WAN address).
func ctLine(id int, in, remote string, up, down int) string {
	return fmt.Sprintf("ipv4     2 tcp      6 431954 ESTABLISHED src=%s dst=%s sport=57407 dport=443 packets=13 bytes=%d src=%s dst=69.156.169.77 sport=443 dport=57407 packets=18 bytes=%d [ASSURED] mark=256 use=1 id=%d", in, remote, up, remote, down, id)
}

func flows(t *testing.T, lines ...string) []Flow {
	t.Helper()
	var out []Flow
	for _, l := range lines {
		f, ok := ParseConntrack(l)
		if !ok {
			t.Fatalf("not parsed: %s", l)
		}
		out = append(out, f)
	}
	return out
}

var talkerEnv = Env{Local: func(a netip.Addr) bool { return a.String() == "69.156.169.77" }}

// Rates per inside device, from the growth of its connections' counters. The
// first look only takes a baseline: the bytes of old connections are no rate.
func TestTalkers_RatesPerDevice(t *testing.T) {
	tk := NewTalkers()
	t0 := time.Unix(1800000000, 0)
	tk.Sample(flows(t,
		ctLine(1, "192.168.2.131", "52.123.190.161", 1000, 9000000),
		ctLine(2, "192.168.2.131", "17.253.3.152", 500, 1000),
		ctLine(3, "192.168.2.185", "17.253.3.153", 2000, 2000)), talkerEnv, t0)
	if tk.Ready() || len(tk.Top("down", 10)) != 0 {
		t.Fatalf("baseline reported: %+v", tk.Top("down", 10))
	}
	tk.Sample(flows(t,
		ctLine(1, "192.168.2.131", "52.123.190.161", 1000+3000, 9000000+3000000),
		ctLine(2, "192.168.2.131", "17.253.3.152", 500, 1000+300000),
		ctLine(3, "192.168.2.185", "17.253.3.153", 2000+6000000, 2000+3000),
		ctLine(4, "192.168.2.185", "17.253.3.154", 150000, 3000)), talkerEnv, t0.Add(3*time.Second)) // new: all its bytes are new
	if !tk.Ready() {
		t.Fatal("not ready")
	}
	down := tk.Top("down", 10)
	if len(down) != 2 || down[0].IP != "192.168.2.131" {
		t.Fatalf("%+v", down)
	}
	a := down[0]
	if a.DownBps != 3300000*8/3 || a.UpBps != 3000*8/3 || a.Conns != 2 || a.DownBytes != 12301000 || a.UpBytes != 4500 {
		t.Fatalf("%+v", a)
	}
	up := tk.Top("up", 10)
	if up[0].IP != "192.168.2.185" || up[0].UpBps != 6150000*8/3 || up[0].Conns != 2 {
		t.Fatalf("%+v", up[0])
	}
	td, tu := tk.Totals()
	if td != (3300000+6000)*8/3 || tu != (3000+6150000)*8/3 {
		t.Fatalf("totals %d %d", td, tu)
	}
	if len(tk.Top("down", 1)) != 1 {
		t.Fatal("limit")
	}
}

// Peaks and the sparkline follow each device; a vanished connection or a
// reused id never gives a negative or huge rate.
func TestTalkers_HistoryAndCounters(t *testing.T) {
	tk := NewTalkers()
	t0 := time.Unix(1800000000, 0)
	h := "192.168.2.131"
	tk.Sample(flows(t, ctLine(1, h, "52.1.1.1", 0, 1000)), talkerEnv, t0)
	tk.Sample(flows(t, ctLine(1, h, "52.1.1.1", 0, 1000+3000000)), talkerEnv, t0.Add(3*time.Second))
	tk.Sample(flows(t, ctLine(1, h, "52.1.1.1", 0, 1000+3000000+300000)), talkerEnv, t0.Add(6*time.Second))
	a := tk.Top("down", 1)[0]
	if a.PeakDownBps != 8000000 || a.DownBps != 800000 || len(a.SparkDown) != 2 || a.SparkDown[0] != 8000000 || a.SparkDown[1] != 800000 {
		t.Fatalf("%+v", a)
	}
	// id reused by a smaller connection: its bytes are new, not negative
	tk.Sample(flows(t, ctLine(1, h, "52.1.1.1", 0, 3000)), talkerEnv, t0.Add(9*time.Second))
	a = tk.Top("down", 1)[0]
	if a.DownBps != 8000 {
		t.Fatalf("reused id: %+v", a)
	}
	// connections gone: the rate falls to zero, the device stays for a while
	tk.Sample(nil, talkerEnv, t0.Add(12*time.Second))
	if l := tk.Top("down", 1); len(l) != 1 || l[0].DownBps != 0 || l[0].Conns != 0 {
		t.Fatalf("%+v", l)
	}
}

// Not watched for a while (no popup open): a new baseline, no bogus burst.
func TestTalkers_GapIsANewBaseline(t *testing.T) {
	tk := NewTalkers()
	t0 := time.Unix(1800000000, 0)
	h := "192.168.2.131"
	tk.Sample(flows(t, ctLine(1, h, "52.1.1.1", 0, 1000)), talkerEnv, t0)
	tk.Sample(flows(t, ctLine(1, h, "52.1.1.1", 0, 900000000)), talkerEnv, t0.Add(10*time.Minute))
	if tk.Ready() {
		t.Fatalf("gap counted: %+v", tk.Top("down", 1))
	}
	tk.Sample(flows(t, ctLine(1, h, "52.1.1.1", 0, 900000300)), talkerEnv, t0.Add(10*time.Minute+3*time.Second))
	if a := tk.Top("down", 1)[0]; a.DownBps != 800 || a.PeakDownBps != 800 {
		t.Fatalf("%+v", a)
	}
}

// Only inside ↔ Internet traffic. An incoming connection (port forward) counts
// for the inside host: what it receives is its download. LAN ↔ LAN does not
// cross the gateway.
func TestTalkers_DirectionsAndScope(t *testing.T) {
	in := func(up, down int) string { // remote connects; DNAT to 192.168.2.50
		return fmt.Sprintf("ipv4 2 tcp 6 100 ESTABLISHED src=8.8.4.4 dst=69.156.169.77 sport=40000 dport=32400 packets=1 bytes=%d src=192.168.2.50 dst=8.8.4.4 sport=32400 dport=40000 packets=1 bytes=%d [ASSURED] mark=0 use=1 id=7", down, up)
	}
	lan := func(n int) string {
		return fmt.Sprintf("ipv4 2 tcp 6 100 ESTABLISHED src=192.168.2.131 dst=192.168.2.113 sport=57516 dport=8443 packets=7 bytes=%d src=192.168.2.113 dst=192.168.2.131 sport=8443 dport=57516 packets=4 bytes=%d [ASSURED] mark=0 use=1 id=8", n, n)
	}
	tk := NewTalkers()
	t0 := time.Unix(1800000000, 0)
	tk.Sample(flows(t, in(0, 0), lan(0)), talkerEnv, t0)
	tk.Sample(flows(t, in(3000, 300), lan(9000000)), talkerEnv, t0.Add(3*time.Second))
	l := tk.Top("up", 10)
	if len(l) != 1 || l[0].IP != "192.168.2.50" || l[0].UpBps != 8000 || l[0].DownBps != 800 {
		t.Fatalf("%+v", l)
	}
}

// This server is one device, whichever of its addresses a connection uses.
func TestTalkers_ThisServerIsOneEntry(t *testing.T) {
	env := Env{Local: func(a netip.Addr) bool { return a.String() == "10.250.0.2" || a.String() == "10.251.0.2" }}
	line := func(id int, src string, down int) string {
		return fmt.Sprintf("ipv4 2 tcp 6 100 ESTABLISHED src=%s dst=52.1.1.1 sport=1 dport=443 packets=1 bytes=0 src=52.1.1.1 dst=%s sport=443 dport=1 packets=1 bytes=%d [ASSURED] mark=0 use=1 id=%d", src, src, down, id)
	}
	tk := NewTalkers()
	t0 := time.Unix(1800000000, 0)
	tk.Sample(flows(t, line(1, "10.251.0.2", 0), line(2, "10.250.0.2", 0)), env, t0)
	tk.Sample(flows(t, line(1, "10.251.0.2", 3000), line(2, "10.250.0.2", 300)), env, t0.Add(3*time.Second))
	l := tk.Top("down", 10)
	if len(l) != 1 || l[0].Name != "This ZNAS" || l[0].DownBps != 8800 || l[0].Conns != 2 || l[0].IP != "10.250.0.2" {
		t.Fatalf("%+v", l)
	}
}
