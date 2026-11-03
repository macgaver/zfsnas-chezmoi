package system

import (
	"net/netip"
	"testing"
	"time"

	"zfsnas/internal/ids"
)

// An alert seen on the WAN carries our public address: the inside host is
// read back from the connection-tracking entry of that exact connection.
func TestSDNIDSInside(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	pub := netip.MustParseAddr("69.156.169.77")
	oldLocal, oldHave := sdnIDSLocal, sdnIDSHaveConntrack
	sdnIDSLocal = func(a netip.Addr) bool { return a == pub }
	sdnIDSHaveConntrack = func() bool { return true }
	t.Cleanup(func() { sdnIDSLocal, sdnIDSHaveConntrack = oldLocal, oldHave })
	r := newSDNIDSNAT()

	// outgoing, SNAT: 10.97.8.20:51111 → 45.45.148.8:443, seen as 69.156.169.77:40001
	outCmd := "conntrack -L -p tcp -o extended,id --reply-src 45.45.148.8 --reply-dst 69.156.169.77 --reply-port-src 443 --reply-port-dst 40001"
	// incoming, port forward: 81.2.69.142:5555 → 69.156.169.77:8443 → 10.97.8.10:443
	inCmd := "conntrack -L -p tcp -o extended,id -s 81.2.69.142 -d 69.156.169.77 --sport 5555 --dport 8443"
	rec.out = map[string]string{
		outCmd: "ipv4     2 tcp      6 431999 ESTABLISHED src=10.97.8.20 dst=45.45.148.8 sport=51111 dport=443 packets=3 bytes=300 src=45.45.148.8 dst=69.156.169.77 sport=443 dport=40001 packets=2 bytes=200 [ASSURED] mark=0 use=1 id=11\n",
		inCmd:  "ipv4     2 tcp      6 431999 ESTABLISHED src=81.2.69.142 dst=69.156.169.77 sport=5555 dport=8443 packets=3 bytes=300 src=10.97.8.10 dst=81.2.69.142 sport=443 dport=5555 packets=2 bytes=200 [ASSURED] mark=0 use=1 id=12\n",
	}
	now := time.Unix(1_800_000_000, 0)

	out := ids.Event{Src: "69.156.169.77", SrcPort: 40001, Dst: "45.45.148.8", DstPort: 443, Proto: "TCP"}
	r.resolve(&out, now)
	if out.SrcInside != "10.97.8.20" || out.DstInside != "" {
		t.Fatalf("outgoing: %+v", out)
	}
	in := ids.Event{Src: "81.2.69.142", SrcPort: 5555, Dst: "69.156.169.77", DstPort: 8443, Proto: "TCP"}
	r.resolve(&in, now)
	if in.DstInside != "10.97.8.10" || in.SrcInside != "" {
		t.Fatalf("incoming: %+v", in)
	}

	// cached: the same connection is not looked up twice
	n := len(rec.cmds)
	again := ids.Event{Src: "81.2.69.142", SrcPort: 5555, Dst: "69.156.169.77", DstPort: 8443, Proto: "TCP"}
	r.resolve(&again, now.Add(time.Second))
	if len(rec.cmds) != n || again.DstInside != "10.97.8.10" {
		t.Fatalf("not cached: %v %+v", rec.cmds[n:], again)
	}

	// no NAT (the box itself answered, or a probe with no entry): nothing
	self := ids.Event{Src: "81.2.69.142", SrcPort: 6000, Dst: "69.156.169.77", DstPort: 22, Proto: "TCP"}
	r.resolve(&self, now)
	if self.DstInside != "" {
		t.Fatalf("self: %+v", self)
	}
	// between inside networks: never looked up
	n = len(rec.cmds)
	lan := ids.Event{Src: "10.97.8.10", Dst: "10.97.7.10", Proto: "TCP"}
	r.resolve(&lan, now)
	if len(rec.cmds) != n {
		t.Fatalf("looked up an internal alert: %v", rec.cmds[n:])
	}

	// a port scan: at most sdnIDSNATPerSec lookups a second
	n = len(rec.cmds)
	for p := 1; p <= 100; p++ {
		e := ids.Event{Src: "81.2.69.142", SrcPort: 7000, Dst: "69.156.169.77", DstPort: p, Proto: "TCP"}
		r.resolve(&e, now.Add(time.Minute))
	}
	if got := len(rec.cmds) - n; got != sdnIDSNATPerSec {
		t.Fatalf("lookups in one second: %d", got)
	}
}
