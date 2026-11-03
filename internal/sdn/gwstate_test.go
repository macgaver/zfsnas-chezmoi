package sdn

import (
	"testing"
	"time"
)

var g0 = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func feed(tr *GWTracker, start time.Time, oks ...bool) time.Time {
	t := start
	for _, ok := range oks {
		tr.Add(GWSample{OK: ok, At: t})
		t = t.Add(2 * time.Second)
	}
	return t
}

func TestGWTracker_DownAfterTenSecondsOfSilence(t *testing.T) {
	// loss rule disabled (100 %) to test the silence rule alone
	tr := NewGWTracker(Gateway{ID: "g", Monitor: true, LossPct: 100}, true)
	at := feed(tr, g0, true, true, false, false, false, false)
	if !tr.Up {
		t.Fatal("8 s of failures must not be enough")
	}
	feed(tr, at, false, false)
	if tr.Up {
		t.Fatal("10 s without reply must be down")
	}
}

func TestGWTracker_DownOnLoss(t *testing.T) {
	tr := NewGWTracker(Gateway{ID: "g", Monitor: true}, true)
	feed(tr, g0, true, false, true, false, false)
	if tr.Up {
		t.Fatal("60 % loss over the window must be down")
	}
}

func TestGWTracker_ReturnsAfterHoldNoFlap(t *testing.T) {
	tr := NewGWTracker(Gateway{ID: "g", Monitor: true, HoldSecs: 10}, false)
	at := feed(tr, g0, true, true, true, true)
	if tr.Up {
		t.Fatal("must stay down until healthy for the hold time")
	}
	at = feed(tr, at, false) // a blip restarts the hold
	at = feed(tr, at, true, true, true, true, true)
	if tr.Up {
		t.Fatal("blip must restart the hold")
	}
	feed(tr, at, true)
	if !tr.Up {
		t.Fatal("healthy for the hold time: up")
	}
}

func TestGWTracker_UnmonitoredAlwaysUp(t *testing.T) {
	tr := NewGWTracker(Gateway{ID: "g", Monitor: false}, true)
	feed(tr, g0, false, false, false, false, false, false, false)
	if !tr.Up {
		t.Fatal("an unmonitored gateway is never declared down")
	}
}

func TestPlanRoutes(t *testing.T) {
	c := twoWAN() // PPPoE prio 1 (index 0), Bell router prio 2 (index 1)
	hops := map[string]Hop{"gwpppoe1": {Via: "", Dev: "ppp-ifpppoe1"}, "gwrouter": {Via: "192.168.2.1", Dev: "enp1s0"}}
	p := PlanRoutes(c, map[string]bool{"gwpppoe1": true, "gwrouter": true}, hops)
	if p.Default == nil || p.Default.Dev != "ppp-ifpppoe1" || p.Active != "gwpppoe1" {
		t.Fatalf("preferred gateway: %+v", p)
	}
	if h := p.Tables[GatewayTable(1, false)]; h == nil || h.Dev != "enp1s0" {
		t.Fatalf("follow table of the router: %+v", h)
	}
	// PPPoE down: everything follows to the router, "only" table unreachable
	p = PlanRoutes(c, map[string]bool{"gwpppoe1": false, "gwrouter": true}, hops)
	if p.Default.Dev != "enp1s0" || p.Active != "gwrouter" {
		t.Fatalf("failover: %+v", p.Default)
	}
	if h := p.Tables[GatewayTable(0, false)]; h == nil || h.Dev != "enp1s0" {
		t.Fatalf("follow table of PPPoE must point at the router: %+v", h)
	}
	if h := p.Tables[GatewayTable(0, true)]; h != nil {
		t.Fatalf("only-PPPoE table must be unreachable: %+v", h)
	}
	// a gateway with no known address (DHCP not leased yet) counts as down
	delete(hops, "gwrouter")
	p = PlanRoutes(c, map[string]bool{"gwpppoe1": false, "gwrouter": true}, hops)
	if p.Default != nil {
		t.Fatalf("no usable gateway: no default route, got %+v", p.Default)
	}
}

// Probes need a way out through their own gateway whatever its state:
// a probe table per gateway always points at it.
func TestPlanRoutes_ProbeTables(t *testing.T) {
	c := twoWAN()
	hops := map[string]Hop{"gwpppoe1": {Dev: "ppp-ifpppoe1"}, "gwrouter": {Via: "192.168.2.1", Dev: "enp1s0"}}
	p := PlanRoutes(c, map[string]bool{"gwpppoe1": false, "gwrouter": true}, hops)
	if h := p.Tables[ProbeTable(0)]; h == nil || h.Dev != "ppp-ifpppoe1" {
		t.Fatalf("probe table of the DOWN gateway must still point at it: %+v", h)
	}
	if h := p.Tables[ProbeTable(1)]; h == nil || h.Via != "192.168.2.1" {
		t.Fatalf("probe table: %+v", h)
	}
	if ProbeMark(1) != 0x301 || ProbeTable(1) != 301 {
		t.Fatal("probe mark/table numbering")
	}
}

// A monitor verdict can be wrong (the probe target, a short loss): with no
// other gateway to move to, traffic keeps trying the link it has instead of
// being cut by us. "Only" stays on its own gateway, so it never leaks.
func TestPlanRoutes_NoUsableGatewayKeepsTheLink(t *testing.T) {
	c := twoWAN()
	hops := map[string]Hop{"gwpppoe1": {Dev: "ppp-ifpppoe1"}, "gwrouter": {Via: "192.168.2.1", Dev: "enp1s0"}}
	p := PlanRoutes(c, map[string]bool{"gwpppoe1": false, "gwrouter": false}, hops)
	if p.Default != nil || p.Active != "" {
		t.Fatalf("nothing is usable, nothing is active: %+v", p)
	}
	for i, dev := range []string{"ppp-ifpppoe1", "enp1s0"} {
		if h := p.Tables[GatewayTable(i, true)]; h == nil || h.Dev != dev {
			t.Fatalf("only table %d must stay on %s: %+v", i, dev, h)
		}
	}
	for i := 0; i < 2; i++ {
		if h := p.Tables[GatewayTable(i, false)]; h == nil || h.Dev != "ppp-ifpppoe1" {
			t.Fatalf("follow table %d must use the first gateway by priority: %+v", i, h)
		}
	}
	// A gateway whose link is really gone has no route to offer.
	p = PlanRoutes(c, map[string]bool{"gwpppoe1": true, "gwrouter": false}, map[string]Hop{"gwrouter": {Via: "192.168.2.1", Dev: "enp1s0"}})
	if h := p.Tables[GatewayTable(0, true)]; h != nil {
		t.Fatalf("only table of a gateway without a link must be unreachable: %+v", h)
	}
	if h := p.Tables[GatewayTable(0, false)]; h == nil || h.Dev != "enp1s0" {
		t.Fatalf("follow table of a gateway without a link uses what is left: %+v", h)
	}
}
