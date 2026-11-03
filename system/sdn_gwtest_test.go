package system

import (
	"strings"
	"testing"
	"time"

	"zfsnas/internal/sdn"
)

func TestSDNTestGateway(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	c := gwConfig()
	c.Normalize()
	answer := true
	old := sdnPing
	var gotTarget string
	var gotMark uint32
	sdnPing = func(dev, target string, mark uint32, n int) (bool, time.Duration) {
		gotTarget, gotMark = target, mark
		return answer, 2 * time.Millisecond
	}
	t.Cleanup(func() { sdnPing = old })

	r := SDNTestGateway(c, "if0wan01", "10.250.0.1", "", 3)
	if !r.OK || gotTarget != "10.250.0.1" || gotMark != 0x3ff || r.RTTms != 2 {
		t.Fatalf("default gateway: %+v %s", r, gotTarget)
	}
	if rec.index("ip route replace default via 10.250.0.1 dev enp6s0 table 399") < 0 || rec.index("ip rule add priority 3999 fwmark 0x3ff lookup 399") < 0 {
		t.Fatalf("no test route: %v", rec.cmds)
	}
	if l := rec.cmds[len(rec.cmds)-1]; l != "ip route flush table 399" {
		t.Fatalf("not cleaned up: %q", l)
	}
	answer = false
	if r = SDNTestGateway(c, "if0wan01", "10.250.0.1", "9.9.9.9", 1); r.OK || !strings.Contains(r.Error, "9.9.9.9") {
		t.Fatalf("no answer: %+v", r)
	}
	for _, bad := range []string{"9.9.9.9; reboot", "-f", "10.0.0.0/8"} {
		if r = SDNTestGateway(c, "if0wan01", "", bad, 1); r.OK || r.Error == "" {
			t.Fatalf("%q accepted", bad)
		}
	}
	if r = SDNTestGateway(&sdn.Config{}, "nope", "", "", 1); r.OK {
		t.Fatalf("unknown interface accepted")
	}
}
