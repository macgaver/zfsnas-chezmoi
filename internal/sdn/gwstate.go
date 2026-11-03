package sdn

import (
	"sort"
	"time"
)

// GWSample is one probe of a gateway.
type GWSample struct {
	OK  bool
	RTT time.Duration
	At  time.Time
}

// GWTracker decides whether a gateway is up (spec §7): down at ≥ LossPct
// loss over the last 5 probes or no reply for DownSecs; back up only after
// HoldSecs of uninterrupted health (no flapping). Unmonitored gateways are
// always up.
type GWTracker struct {
	G            Gateway
	Up           bool
	samples      []GWSample
	failSince    time.Time
	healthySince time.Time
}

func NewGWTracker(g Gateway, up bool) *GWTracker { return &GWTracker{G: g, Up: up} }

func (t *GWTracker) params() (loss int, down, hold time.Duration) {
	loss, down, hold = t.G.LossPct, time.Duration(t.G.DownSecs)*time.Second, time.Duration(t.G.HoldSecs)*time.Second
	if loss <= 0 {
		loss = 50
	}
	if down <= 0 {
		down = 10 * time.Second
	}
	if hold <= 0 {
		hold = 60 * time.Second
	}
	return
}

// Add records a probe and reports whether Up changed.
func (t *GWTracker) Add(s GWSample) bool {
	if !t.G.Monitor {
		changed := !t.Up
		t.Up = true
		return changed
	}
	t.samples = append(t.samples, s)
	if len(t.samples) > 5 {
		t.samples = t.samples[len(t.samples)-5:]
	}
	loss, down, hold := t.params()
	if s.OK {
		t.failSince = time.Time{}
		if t.healthySince.IsZero() {
			t.healthySince = s.At
		}
	} else {
		t.healthySince = time.Time{}
		if t.failSince.IsZero() {
			t.failSince = s.At
		}
	}
	was := t.Up
	if t.Up {
		failed := 0
		for _, x := range t.samples {
			if !x.OK {
				failed++
			}
		}
		if (!t.failSince.IsZero() && s.At.Sub(t.failSince) >= down) || (len(t.samples) >= 5 && failed*100/len(t.samples) >= loss) {
			t.Up = false
		}
	} else if !t.healthySince.IsZero() && s.At.Sub(t.healthySince) >= hold {
		t.Up = true
	}
	return was != t.Up
}

// LastRTT is the latest successful round trip (0 if none in the window).
func (t *GWTracker) LastRTT() time.Duration {
	for i := len(t.samples) - 1; i >= 0; i-- {
		if t.samples[i].OK {
			return t.samples[i].RTT
		}
	}
	return 0
}

// LossPct over the window.
func (t *GWTracker) Loss() int {
	if len(t.samples) == 0 {
		return 0
	}
	f := 0
	for _, x := range t.samples {
		if !x.OK {
			f++
		}
	}
	return f * 100 / len(t.samples)
}

// Hop is a next hop: Via "" means a point-to-point device (PPPoE).
type Hop struct {
	Via string `json:"via,omitempty"`
	Dev string `json:"dev"`
}

// RoutePlan is what the routing tables must hold.
type RoutePlan struct {
	Default *Hop // main table default route (nil: none)
	// LastResort: nothing is usable. A default route that exists is left alone;
	// this one is written only if it has gone, which a PPPoE redial causes.
	LastResort *Hop
	Active     string       // gateway id carrying the default route
	Tables     map[int]*Hop // per-gateway tables; nil = unreachable
}

// PlanRoutes computes the routes from the gateways' health: the default
// and every "follow" table use the best usable gateway by priority (a
// gateway's own table keeps it while it is usable); "only" tables become
// unreachable while their gateway is down. A gateway without a known next
// hop (DHCP lease not yet obtained) is not usable.
//
// With nothing usable there is nowhere to move traffic to, and the verdict may
// be wrong (the probe target, a short loss): the tables stay on the links that
// exist, so the monitor never cuts what the link can still carry. An "only"
// table keeps its own gateway, so it cannot leak through another one.
func PlanRoutes(c *Config, up map[string]bool, hops map[string]Hop) RoutePlan {
	usable := func(g Gateway) bool { _, ok := hops[g.ID]; return ok && up[g.ID] }
	order := make([]int, len(c.Gateways))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return c.Gateways[order[a]].Priority < c.Gateways[order[b]].Priority })
	p := RoutePlan{Tables: map[int]*Hop{}}
	for _, i := range order {
		if g := c.Gateways[i]; usable(g) {
			h := hops[g.ID]
			p.Default, p.Active = &h, g.ID
			break
		}
	}
	follow := p.Default
	if follow == nil {
		for _, i := range order {
			if h, ok := hops[c.Gateways[i].ID]; ok {
				follow = &h
				break
			}
		}
	}
	if p.Default == nil {
		p.LastResort = follow
	}
	for i, g := range c.Gateways {
		if usable(g) {
			h := hops[g.ID]
			p.Tables[GatewayTable(i, false)], p.Tables[GatewayTable(i, true)] = &h, &h
		} else {
			p.Tables[GatewayTable(i, false)], p.Tables[GatewayTable(i, true)] = follow, nil
			if h, ok := hops[g.ID]; ok && p.Default == nil {
				p.Tables[GatewayTable(i, true)] = &h
			}
		}
		// The monitor's probes leave through their own gateway, up or down.
		if h, ok := hops[g.ID]; ok {
			p.Tables[ProbeTable(i)] = &h
		}
	}
	return p
}

// ProbeMark / ProbeTable: the gateway monitor's pings for gateway i carry
// this mark, which an ip rule sends to a table pointing at that gateway.
func ProbeMark(i int) uint32 { return 0x300 + uint32(i) }
func ProbeTable(i int) int   { return 300 + i }
