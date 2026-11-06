package system

// The last 15 minutes of ping times per monitored gateway, kept by the
// gateway daemon and published in /run/znas-sdn/gw-rtt.json: the header's
// latency popup draws it, and the portal's 5-minute collector turns it into
// the gateway latency RRD (true min/avg/max of every ping in the window).

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"

	"zfsnas/internal/sdn"
)

// RTTPoint is one probe: MS nil means it went unanswered.
type RTTPoint struct {
	TS int64    `json:"ts"`
	MS *float64 `json:"ms"`
}

// GWRTTFile maps a gateway ID to its points, oldest first.
type GWRTTFile map[string][]RTTPoint

const sdnRTTKeep = 15 * 60 // seconds

func sdnGWRTTPath() string { return filepath.Join(sdnRunDir, "gw-rtt.json") }

// SDNGatewayRTT reads the published rings (empty when monitoring is off).
func SDNGatewayRTT() GWRTTFile {
	out := GWRTTFile{}
	if b, err := os.ReadFile(sdnGWRTTPath()); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// pushRTT appends p and drops what is older than 15 minutes before p.
func pushRTT(ring []RTTPoint, p RTTPoint) []RTTPoint {
	ring = append(ring, p)
	i := 0
	for i < len(ring) && ring[i].TS < p.TS-sdnRTTKeep {
		i++
	}
	return ring[i:]
}

// RTTWindow summarises the answered pings with from < ts <= to; n is 0 when
// none answered (nothing to record: an outage is not a latency of 0).
func RTTWindow(pts []RTTPoint, from, to int64) (mn, avg, mx float64, n int) {
	sum := 0.0
	for _, p := range pts {
		if p.TS <= from || p.TS > to || p.MS == nil {
			continue
		}
		v := *p.MS
		if n == 0 || v < mn {
			mn = v
		}
		if n == 0 || v > mx {
			mx = v
		}
		sum += v
		n++
	}
	if n > 0 {
		avg = sum / float64(n)
	}
	return
}

func writeGWRTT(f GWRTTFile) {
	b, _ := json.Marshal(f)
	_ = os.MkdirAll(sdnRunDir, 0755)
	tmp := sdnGWRTTPath() + ".tmp"
	if os.WriteFile(tmp, b, 0644) == nil {
		_ = os.Rename(tmp, sdnGWRTTPath())
	}
}

// SDNGatewayNames maps gateway IDs to the names the admin gave them (empty
// when the Firewall is off): the latency graph's legend.
func SDNGatewayNames() map[string]string {
	out := map[string]string{}
	if sdnConfigDir == "" {
		return out
	}
	st := sdn.Store{Dir: sdnConfigDir}
	if state, _ := st.LoadState(); !state.Enabled {
		return out
	}
	if c, err := st.LoadConfirmed(); err == nil {
		for _, g := range c.Gateways {
			out[g.ID] = g.Name
		}
	}
	return out
}

// GWRTTSummary is a gateway's latency over its 15-minute history, from the
// monitor's own checks: what the web header's popup and the iOS app show.
type GWRTTSummary struct {
	GatewayID    string     `json:"gateway_id"`
	Name         string     `json:"name"`
	Monitored    bool       `json:"monitored"`
	Active       bool       `json:"active"`         // carries the default route
	Target       string     `json:"target"`         // address pinged
	TargetIsPeer bool       `json:"target_is_peer"` // the PPPoE provider's end
	NowMS        *float64   `json:"now_ms"`         // latest check; null = no answer
	TS           int64      `json:"ts"`             // when the latest check ran
	AvgMS        *float64   `json:"avg_ms"`         // over the window; null = nothing answered
	MinMS        *float64   `json:"min_ms"`
	MaxMS        *float64   `json:"max_ms"`
	LossPct      float64    `json:"loss_pct"` // checks with no answer, %
	Checks       int        `json:"checks"`   // checks in the window
	WindowS      int        `json:"window_s"` // 900
	Points       []RTTPoint `json:"points,omitempty"`
}

// summarizeRTT fills the figures of s from a ring (oldest first).
func summarizeRTT(s *GWRTTSummary, pts []RTTPoint) {
	s.WindowS = sdnRTTKeep
	if len(pts) == 0 {
		return
	}
	last := pts[len(pts)-1]
	s.NowMS, s.TS, s.Checks = last.MS, last.TS, len(pts)
	mn, avg, mx, n := RTTWindow(pts, last.TS-sdnRTTKeep, last.TS)
	r2 := func(v float64) float64 { return math.Round(v*100) / 100 }
	if n > 0 {
		mn, avg, mx = r2(mn), r2(avg), r2(mx)
		s.MinMS, s.AvgMS, s.MaxMS = &mn, &avg, &mx
	}
	s.LossPct = r2(float64(len(pts)-n) * 100 / float64(len(pts)))
}

// SDNGatewayRTTSummary summarises gateway id, or the gateway carrying the
// default route when id is "". ok is false when no such gateway is known.
func SDNGatewayRTTSummary(id string, withPoints bool, isPPPoE func(gwID string) bool) (GWRTTSummary, bool) {
	st := SDNGatewayState()
	for _, g := range st.Gateways {
		if (id == "" && !g.Active) || (id != "" && g.ID != id) {
			continue
		}
		s := GWRTTSummary{GatewayID: g.ID, Name: g.Name, Monitored: g.Monitor, Active: g.Active, Target: g.Target,
			TargetIsPeer: g.Target != "" && g.Target == g.GatewayIP && isPPPoE != nil && isPPPoE(g.ID)}
		pts := SDNGatewayRTT()[g.ID]
		summarizeRTT(&s, pts)
		if withPoints {
			s.Points = pts
			if s.Points == nil {
				s.Points = []RTTPoint{}
			}
		}
		return s, true
	}
	return GWRTTSummary{}, false
}
