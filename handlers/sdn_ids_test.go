package handlers

import (
	"testing"
	"time"

	"net/netip"

	"zfsnas/internal/ids"
	"zfsnas/internal/sdn"
)

func TestSDNIDSNotifier(t *testing.T) {
	n := &sdnIDSNotifier{}
	now := time.Now()
	e := ids.Event{SID: 1, Src: "81.2.69.142", Severity: 2}
	if n.want(e, 0, now) {
		t.Fatal("level 0 = never")
	}
	if n.want(ids.Event{SID: 1, Src: "x", Severity: 3}, 2, now) {
		t.Fatal("low severity notified at level 2")
	}
	if !n.want(e, 2, now) || n.want(e, 2, now.Add(10*time.Minute)) {
		t.Fatal("same signature+source must notify once an hour")
	}
	if !n.want(e, 2, now.Add(61*time.Minute)) {
		t.Fatal("must notify again after an hour")
	}
	m := &sdnIDSNotifier{}
	sent := 0
	for i := 0; i < 50; i++ {
		if m.want(ids.Event{SID: i, Src: "a", Severity: 1}, 1, now) {
			sent++
		}
	}
	if sent != 20 {
		t.Fatalf("hourly cap: %d sent", sent)
	}
}

func TestSDNIDSClassify(t *testing.T) {
	saved := sdnIsLocalAddr
	defer func() { sdnIsLocalAddr = saved }()
	sdnIsLocalAddr = func(a netip.Addr) bool { return a.String() == "69.156.169.77" } // our WAN address
	c := &sdn.Config{
		Interfaces:   []sdn.Interface{{ID: "wan", Device: "ppp0", Role: "wan", IPv4Mode: "pppoe"}},
		PortForwards: []sdn.PortForward{{ID: "f", Enabled: true, Interfaces: []string{"wan"}, Protocol: "tcp", PubPorts: "443", Target: "192.168.2.10"}},
	}
	env := sdn.Env{SSHPort: 22, PortalPorts: []int{8443}}
	for _, tc := range []struct {
		src, dst, proto string
		ports           []int
		dir             string
		open            bool
	}{
		{"45.1.2.3", "69.156.169.77", "TCP", []int{23}, "in", false},           // probe of a closed port
		{"45.1.2.3", "69.156.169.77", "TCP", []int{23, 443, 8080}, "in", true}, // a scan that touched the open 443
		{"45.1.2.3", "69.156.169.77", "UDP", []int{443}, "in", false},          // the forward is TCP only
		{"69.156.169.77", "93.184.216.34", "TCP", []int{80}, "out", true},      // we connected out (after NAT)
		{"192.168.2.50", "93.184.216.34", "TCP", []int{80}, "out", true},       // same, seen inside
		{"192.168.2.50", "192.168.2.10", "TCP", []int{445}, "internal", true},
		{"45.1.2.3", "69.156.169.77", "ICMP", []int{0}, "in", false}, // no ICMP rule
	} {
		dir, open := sdnIDSClassify(c, env, "wan", tc.src, tc.dst, tc.proto, tc.ports)
		if dir != tc.dir || open != tc.open {
			t.Errorf("%s→%s %s %v: got %s/%v, want %s/%v", tc.src, tc.dst, tc.proto, tc.ports, dir, open, tc.dir, tc.open)
		}
	}
}
