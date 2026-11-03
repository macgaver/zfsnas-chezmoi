package system

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The gateway is the interface of the main table's default route with the
// lowest metric (/proc/net/route: destination 00000000, RTF_UP).
func TestProcRouteDefaultIface(t *testing.T) {
	in := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"enp6s0\t0000FA0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
		"enp8s0\t00000000\t0100FB0A\t0003\t0\t0\t200\t00000000\t0\t0\t0\n" +
		"enp6s0\t00000000\t0100FA0A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"down0\t00000000\t01000000\t0002\t0\t0\t0\t00000000\t0\t0\t0\n"
	if got := procRouteDefaultIface(in); got != "enp6s0" {
		t.Fatalf("got %q", got)
	}
	if got := procRouteDefaultIface("Iface\tDestination\n"); got != "" {
		t.Fatalf("no default route: %q", got)
	}
}

// Rates in bits per second from the interface counters; a switch of
// gateway (failover) or a counter reset starts over instead of showing a
// spike.
func TestGatewayNetSampler(t *testing.T) {
	dir := t.TempDir()
	write := func(dev string, rx, tx string) {
		d := filepath.Join(dir, dev, "statistics")
		_ = os.MkdirAll(d, 0755)
		_ = os.WriteFile(filepath.Join(d, "rx_bytes"), []byte(rx+"\n"), 0644)
		_ = os.WriteFile(filepath.Join(d, "tx_bytes"), []byte(tx+"\n"), 0644)
		_ = os.WriteFile(filepath.Join(dir, dev, "speed"), []byte("1000\n"), 0644)
	}
	iface := "enp6s0"
	s := &gwNetSampler{sysNet: dir, route: func() string { return iface }, addr: func(string) string { return "10.250.0.2/24" }}
	t0 := time.Unix(1800000000, 0)
	write("enp6s0", "1000", "500")
	s.sample(t0)
	if snap := s.snapshot(); snap.Iface != "enp6s0" || snap.Ready {
		t.Fatalf("first sample has no rate yet: %+v", snap)
	}
	write("enp6s0", "1000"+"000", "1000") // +999000 B rx, +500 B tx in 3 s
	s.sample(t0.Add(3 * time.Second))
	snap := s.snapshot()
	if !snap.Ready || snap.RxBps != 999000*8/3 || snap.TxBps != 500*8/3 || snap.SpeedMbps != 1000 || snap.Addr != "10.250.0.2/24" {
		t.Fatalf("%+v", snap)
	}
	// counter went backwards (interface re-created): no negative rate
	write("enp6s0", "10", "10")
	s.sample(t0.Add(6 * time.Second))
	if snap := s.snapshot(); snap.Ready {
		t.Fatalf("reset gave a rate: %+v", snap)
	}
	// failover to another link: starts over on it
	iface = "enp8s0"
	write("enp8s0", "5000000", "5000000")
	s.sample(t0.Add(9 * time.Second))
	if snap := s.snapshot(); snap.Iface != "enp8s0" || snap.Ready {
		t.Fatalf("switch: %+v", snap)
	}
	// no default route at all
	iface = ""
	s.sample(t0.Add(12 * time.Second))
	if snap := s.snapshot(); snap.Iface != "" || snap.Ready {
		t.Fatalf("no route: %+v", snap)
	}
}

// A counter that went backwards (interface re-created, PPPoE reconnect) gives
// no sample: the unsigned difference would be an impossible rate.
func TestNetRateMbps(t *testing.T) {
	if v, ok := netRateMbps(2_000_000, 1_000_000, 8); !ok || v != 1 {
		t.Fatalf("%v %v", v, ok)
	}
	if _, ok := netRateMbps(10, 1_000_000, 300); ok {
		t.Fatal("reset gave a rate")
	}
}

// With no link speed, the header gives the highest rate seen on this
// interface: the stored history or the live sampler, whichever is higher.
// Impossible stored values (old counter resets) are ignored.
func TestGatewayNetMaxSeen(t *testing.T) {
	dir := t.TempDir()
	write := func(rx, tx string, speed bool) {
		d := filepath.Join(dir, "ppp0", "statistics")
		_ = os.MkdirAll(d, 0755)
		_ = os.WriteFile(filepath.Join(d, "rx_bytes"), []byte(rx), 0644)
		_ = os.WriteFile(filepath.Join(d, "tx_bytes"), []byte(tx), 0644)
		if speed {
			_ = os.WriteFile(filepath.Join(dir, "ppp0", "speed"), []byte("1000"), 0644)
		}
	}
	calls := 0
	s := &gwNetSampler{sysNet: dir, route: func() string { return "ppp0" }, addr: func(string) string { return "" },
		history: func(string) (float64, float64, bool) { calls++; return 500, 40, true }} // Mbit/s
	t0 := time.Unix(1800000000, 0)
	write("0", "0", false)
	s.sample(t0)
	if g := s.snapshot(); g.MaxRxBps != 500_000_000 || g.MaxTxBps != 40_000_000 {
		t.Fatalf("history only: %+v", g)
	}
	write("3000", strconv.Itoa(30_000_000), false) // upload 80 Mbit/s: above the history
	s.sample(t0.Add(3 * time.Second))
	if g := s.snapshot(); g.MaxRxBps != 500_000_000 || g.MaxTxBps != 80_000_000 {
		t.Fatalf("live above history: %+v", g)
	}
	write("3000", strconv.Itoa(30_000_000), false)
	s.sample(t0.Add(6 * time.Second))
	if g := s.snapshot(); g.MaxTxBps != 80_000_000 {
		t.Fatalf("the live maximum is kept: %+v", g)
	}
	if calls != 1 {
		t.Fatalf("history read %d times, not cached", calls)
	}
	// a known link speed needs none of it
	write("3000", "1", true)
	s.sample(t0.Add(9 * time.Second))
	if g := s.snapshot(); g.SpeedMbps != 1000 || g.MaxRxBps != 0 || g.MaxTxBps != 0 {
		t.Fatalf("with a link speed: %+v", g)
	}
}

func TestSaneNetMax(t *testing.T) {
	got := saneNetMax([]float64{12, 491911589141.5, 95, 0})
	if got != 95 {
		t.Fatalf("%v", got)
	}
}

// The history opens after the sampler starts: "not open yet" is not cached
// as "nothing seen".
func TestGatewayNetMaxSeen_HistoryOpensLater(t *testing.T) {
	dir := t.TempDir()
	d := filepath.Join(dir, "ppp0", "statistics")
	_ = os.MkdirAll(d, 0755)
	_ = os.WriteFile(filepath.Join(d, "rx_bytes"), []byte("0"), 0644)
	_ = os.WriteFile(filepath.Join(d, "tx_bytes"), []byte("0"), 0644)
	open := false
	s := &gwNetSampler{sysNet: dir, route: func() string { return "ppp0" }, addr: func(string) string { return "" },
		history: func(string) (float64, float64, bool) { return 500, 40, open }}
	t0 := time.Unix(1800000000, 0)
	s.sample(t0)
	if g := s.snapshot(); g.MaxRxBps != 0 {
		t.Fatalf("%+v", g)
	}
	open = true
	s.sample(t0.Add(3 * time.Second))
	if g := s.snapshot(); g.MaxRxBps != 500_000_000 {
		t.Fatalf("history ignored after it opened: %+v", g)
	}
}

// A disk counter that went backwards (device re-attached) gives no sample.
func TestDiskRates(t *testing.T) {
	prev := diskstatSample{sectorsRead: 2048, sectorsWritten: 0, msIO: 1000}
	cur := diskstatSample{sectorsRead: 4096, sectorsWritten: 2048, msIO: 1500}
	r, w, b, ok := diskRates(cur, prev, 1)
	if !ok || r != 1 || w != 1 || b != 50 {
		t.Fatalf("%v %v %v %v", r, w, b, ok)
	}
	cur.msIO = 99999
	if _, _, b, _ := diskRates(cur, prev, 1); b != 100 {
		t.Fatalf("busy capped: %v", b)
	}
	for _, bad := range []diskstatSample{{sectorsRead: 1, sectorsWritten: 0, msIO: 2000}, {sectorsRead: 3000, sectorsWritten: 0, msIO: 10}} {
		if _, _, _, ok := diskRates(bad, prev, 1); ok {
			t.Fatalf("reset gave a rate: %+v", bad)
		}
	}
}
