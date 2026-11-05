package system

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"zfsnas/internal/sdn"
	"zfsnas/internal/traffic"
)

func writeCounters(t *testing.T, root, iface string, rx, tx int64) {
	t.Helper()
	d := filepath.Join(root, iface, "statistics")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(d, "rx_bytes"), []byte(strconv.FormatInt(rx, 10)+"\n"), 0o644)
	os.WriteFile(filepath.Join(d, "tx_bytes"), []byte(strconv.FormatInt(tx, 10)+"\n"), 0o644)
}

func TestVMNetLiveStackAndOther(t *testing.T) {
	root := t.TempDir()
	now := time.Unix(1_000_000, 0)
	s := &vmNetLiveSampler{
		sysNet: root,
		route:  func() string { return "wan0" },
		ifaces: func() []vmNetIf {
			return []vmNetIf{{"web", "container", "veth1"}, {"db", "virtual-machine", "tap2"}, {"db", "virtual-machine", "tap3"}, {"idle", "container", "veth4"}}
		},
		rank: func() []string { return []string{"db", "gone", "web"} },
		now:  func() time.Time { return now },
	}
	for _, i := range []string{"veth1", "tap2", "tap3", "veth4", "wan0"} {
		writeCounters(t, root, i, 0, 0)
	}
	s.sample(now)
	if len(s.roster) != 3 || s.roster[0].Name != "db" || s.roster[1].Name != "web" || s.roster[2].Name != "idle" {
		t.Fatalf("roster = %+v, want db, web (RRD order, gone skipped) then idle", s.roster)
	}
	// 5 s later: web sent 5 MB (host rx) and got 10 MB; db's two NICs 1 MB + 1 MB received.
	writeCounters(t, root, "veth1", 5_000_000, 10_000_000)
	writeCounters(t, root, "tap2", 0, 1_000_000)
	writeCounters(t, root, "tap3", 0, 1_000_000)
	writeCounters(t, root, "wan0", 50_000_000, 25_000_000) // gateway: 50 MB down, 25 MB up
	now = now.Add(5 * time.Second)
	s.sample(now)
	if len(s.ring) != 1 {
		t.Fatalf("ring = %d points, want 1", len(s.ring))
	}
	p := s.ring[0]
	if p.Up[1] != 8_000_000 || p.Down[1] != 16_000_000 {
		t.Errorf("web up/down = %d/%d, want 8 Mbit/s / 16 Mbit/s", p.Up[1], p.Down[1])
	}
	if p.Down[0] != 3_200_000 {
		t.Errorf("db down = %d, want both NICs summed 3.2 Mbit/s", p.Down[0])
	}
	if p.TotalDown != 80_000_000 || p.TotalUp != 40_000_000 {
		t.Errorf("gateway = %d down / %d up", p.TotalDown, p.TotalUp)
	}
	if p.OtherDown != 80_000_000-16_000_000-3_200_000 || p.OtherUp != 40_000_000-8_000_000 {
		t.Errorf("other = %d down / %d up", p.OtherDown, p.OtherUp)
	}
	// more instance traffic than the gateway (LAN traffic): other never negative
	writeCounters(t, root, "veth1", 500_000_000, 10_000_000)
	now = now.Add(5 * time.Second)
	s.sample(now)
	if s.ring[1].OtherUp != 0 {
		t.Errorf("other up = %d, want 0", s.ring[1].OtherUp)
	}
	if got := s.snapshotLocked(s.ring[0].TS); len(got) != 1 {
		t.Errorf("since filter returned %d points, want 1", len(got))
	}
}

func TestVMNetLiveRingIs20Minutes(t *testing.T) {
	if VMNetLivePoints*VMNetLiveStep != 20*time.Minute {
		t.Fatalf("timeline = %v, want 20m", VMNetLivePoints*VMNetLiveStep)
	}
}

func vnCt(id int, in, remote string, up, down int) string {
	return fmt.Sprintf("ipv4     2 tcp      6 431954 ESTABLISHED src=%s dst=%s sport=57407 dport=443 packets=13 bytes=%d src=%s dst=69.156.169.77 sport=443 dport=57407 packets=18 bytes=%d [ASSURED] mark=256 use=1 id=%d", in, remote, up, remote, down, id)
}

func vnFlows(t *testing.T, lines ...string) []traffic.Flow {
	t.Helper()
	var out []traffic.Flow
	for _, l := range lines {
		f, ok := traffic.ParseConntrack(l)
		if !ok {
			t.Fatalf("not parsed: %s", l)
		}
		out = append(out, f)
	}
	return out
}

// Firewall on: the gateway's devices, chosen at the first look by the bytes
// of their open connections, named by FQDN else IP; blocks every 2 s first.
func TestVMNetLiveDevices(t *testing.T) {
	root := t.TempDir()
	now := time.Unix(2_000_000, 0)
	var cur []traffic.Flow
	s := &vmNetLiveSampler{
		sysNet: root,
		route:  func() string { return "ppp0" },
		flows:  func() []traffic.Flow { return cur },
		env: func() traffic.Env {
			return traffic.Env{Local: func(a netip.Addr) bool { return a.String() == "69.156.169.77" }}
		},
		names: func(_ *sdn.Config, ips []string) map[string]string {
			return map[string]string{"192.168.2.10": "tv.home.lan"}
		},
		now:    func() time.Time { return now },
		noLoop: true,
	}
	writeCounters(t, root, "ppp0", 0, 0)
	cur = vnFlows(t,
		vnCt(1, "192.168.2.20", "1.1.1.1", 100, 900), // 1000 bytes so far
		vnCt(2, "192.168.2.10", "8.8.8.8", 1000, 50000))
	got := s.snapshot(0, &sdn.Config{})
	if got.Mode != VMNetModeDevices || len(got.Hosts) != 2 {
		t.Fatalf("first look: %+v", got)
	}
	if got.Hosts[0].IP != "192.168.2.10" || got.Hosts[0].Name != "tv.home.lan" || got.Hosts[1].Name != "192.168.2.20" {
		t.Fatalf("roster = %+v, want the busiest first, FQDN else IP", got.Hosts)
	}
	if st := s.nextStep(); st != VMNetLiveFastStep {
		t.Fatalf("first step %v, want 2 s", st)
	}
	// 2 s later: .20 downloaded 1 MB, the gateway 2 MB
	now = now.Add(2 * time.Second)
	cur = vnFlows(t,
		vnCt(1, "192.168.2.20", "1.1.1.1", 100, 900+1_000_000),
		vnCt(2, "192.168.2.10", "8.8.8.8", 1000, 50000))
	writeCounters(t, root, "ppp0", 2_000_000, 0)
	s.sample(now)
	s.mu.Lock()
	p := s.ring[len(s.ring)-1]
	s.mu.Unlock()
	if p.Down[1] != 4_000_000 || p.TotalDown != 8_000_000 || p.OtherDown != 4_000_000 || p.StepSec != 2 {
		t.Fatalf("point %+v", p)
	}
	for i := 0; i < VMNetLiveFastCount; i++ {
		now = now.Add(2 * time.Second)
		s.sample(now)
	}
	if st := s.nextStep(); st != VMNetLiveStep {
		t.Fatalf("after %d blocks: step %v, want 5 s", VMNetLiveFastCount, st)
	}
	// the Firewall turned off: instances, from scratch
	s.ifaces = func() []vmNetIf { return nil }
	s.rank = func() []string { return nil }
	if got := s.snapshot(0, nil); got.Mode != VMNetModeInstances || len(got.Data) != 0 {
		t.Fatalf("after switch: %+v", got)
	}
}
