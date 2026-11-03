package system

// Gateway monitor (`zfsnas -sdn-gwmon`, systemd unit znas-sdn-gw.service):
// probes every gateway on its own schedule (2 s by default), decides up/down (sdn.GWTracker), keeps the
// default route and the per-gateway tables pointed at the best usable
// gateway (sdn.PlanRoutes), flushes connections NATed behind a gateway that
// went down, and publishes its state in /run/znas-sdn/gateways.json for the
// portal (Gateways page, WAN KPI, alerts). Runs without the portal: failover
// must work when the portal is down or being upgraded.

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"zfsnas/internal/sdn"
)

// GWStatus is one gateway in the published state.
type GWStatus struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Priority  int      `json:"priority"`
	Monitor   bool     `json:"monitor"`
	Up        bool     `json:"up"`
	Usable    bool     `json:"usable"` // up and its next hop is known
	Active    bool     `json:"active"` // carries the default route
	RTTms     float64  `json:"rtt_ms"`
	Loss      int      `json:"loss"`
	Hop       *sdn.Hop `json:"hop,omitempty"`
	Target    string   `json:"target,omitempty"`     // address probed
	GatewayIP string   `json:"gateway_ip,omitempty"` // next hop, or the PPPoE provider's end
	// ReconnectHeld: PPPoE, down, and the address tested has never answered,
	// which says nothing about the link, so it is not hung up.
	ReconnectHeld bool `json:"reconnect_held,omitempty"`
}

// GWEvent is a transition the portal turns into an alert.
type GWEvent struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"` // down | up | failover | reconnect
	ID     string    `json:"id"`
	Name   string    `json:"name"`
	Active string    `json:"active,omitempty"` // gateway now carrying traffic
}

// GWStateFile is /run/znas-sdn/gateways.json.
type GWStateFile struct {
	Updated  time.Time  `json:"updated"`
	Active   string     `json:"active"`
	Gateways []GWStatus `json:"gateways"`
	Events   []GWEvent  `json:"events"`
}

func sdnGWStatePath() string { return filepath.Join(sdnRunDir, "gateways.json") }

// SDNGatewayState reads the monitor's published state (zero value if none).
func SDNGatewayState() GWStateFile {
	var s GWStateFile
	if b, err := os.ReadFile(sdnGWStatePath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

var pingRTTRe = regexp.MustCompile(`time=([0-9.]+) ms`)

// sdnPing probes target through dev (1 s timeout); mark routes the probe
// through that gateway's probe table, whatever the main routes say.
var sdnPing = func(dev, target string, mark uint32, count int) (bool, time.Duration) {
	// ping exits 0 when at least one was answered.
	out, err := sdnRun.Run(nil, "ping", "-n", "-c", strconv.Itoa(count), "-i", "0.5", "-W", "1", "-m", fmt.Sprint(mark), "-I", dev, target)
	if err != nil {
		return false, 0
	}
	if m := pingRTTRe.FindSubmatch(out); m != nil {
		ms, _ := strconv.ParseFloat(string(m[1]), 64)
		return true, time.Duration(ms * float64(time.Millisecond))
	}
	return true, 0
}

// sdnPPPHangup makes pppd drop the session of ifname and dial again: SIGHUP,
// with "persist" in the peers file. The pid file comes from pppd's ifname.
var sdnPPPHangup = func(dev string) error {
	b, err := os.ReadFile(filepath.Join("/run", dev+".pid"))
	if err != nil {
		return err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return fmt.Errorf("%s: empty pid file", dev)
	}
	pid, err := strconv.Atoi(f[0])
	if err != nil {
		return err
	}
	if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err != nil || strings.TrimSpace(string(comm)) != "pppd" {
		return fmt.Errorf("%s: pid %d is not pppd", dev, pid)
	}
	return syscall.Kill(pid, syscall.SIGHUP)
}

// sdnPPPPeer is the provider's end of a PPPoE link ("" when not connected).
func sdnPPPPeer(dev string) string {
	out, _ := sdnRun.Run(nil, "ip", "-4", "-j", "addr", "show", "dev", dev)
	var ifs []struct {
		AddrInfo []struct {
			Address string `json:"address"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(out, &ifs) == nil {
		for _, i := range ifs {
			for _, a := range i.AddrInfo {
				if a.Address != "" {
					return a.Address
				}
			}
		}
	}
	return ""
}

const (
	gwReconnectFirstPause = time.Minute
	gwReconnectMaxPause   = 30 * time.Minute
)

// gwReconnect is what the monitor remembers about hanging up one PPPoE link.
type gwReconnect struct {
	target     string // the address "answered" is about
	answered   bool
	lastFailed bool
	next       time.Time
	pause      time.Duration
}

// gwMonitor holds the daemon's state between cycles (one per process).
type gwMonitor struct {
	nextProbe  map[string]time.Time
	reconnects map[string]*gwReconnect
	trackers   map[string]*sdn.GWTracker
	lastPlan   string
	active     string
	events     []GWEvent
}

func newGWMonitor(prev GWStateFile) *gwMonitor {
	m := &gwMonitor{nextProbe: map[string]time.Time{}, reconnects: map[string]*gwReconnect{}, trackers: map[string]*sdn.GWTracker{}, active: prev.Active, events: prev.Events}
	// Restart: resume the previous verdicts, so routes do not flap.
	for _, g := range prev.Gateways {
		m.trackers[g.ID] = sdn.NewGWTracker(sdn.Gateway{ID: g.ID}, g.Up)
	}
	return m
}

// cycle runs one probe/decide/route round for config c at time now.
func (m *gwMonitor) cycle(c *sdn.Config, now time.Time) GWStateFile {
	hops := SDNResolveHops(c)
	type res struct {
		ok  bool
		rtt time.Duration
	}
	results := make([]res, len(c.Gateways))
	targets := make([]string, len(c.Gateways))
	gatewayIPs := make([]string, len(c.Gateways))
	probed := make([]bool, len(c.Gateways))
	var wg sync.WaitGroup
	for i, g := range c.Gateways {
		h, ok := hops[g.ID]
		if !ok {
			continue
		}
		gatewayIPs[i] = h.Via
		if in := c.InterfaceByID(g.Interface); h.Via == "" && in != nil && in.Kind == "pppoe" {
			gatewayIPs[i] = sdnPPPPeer(h.Dev)
		}
		if !g.Monitor {
			continue
		}
		target := g.MonitorIP
		if target == "" {
			target = gatewayIPs[i]
		}
		if target == "" {
			target = "1.1.1.1"
		}
		targets[i] = target
		if now.Before(m.nextProbe[g.ID]) {
			continue
		}
		every, pings := g.ProbeEvery, g.ProbePings
		if every <= 0 {
			every = 2
		}
		if pings <= 0 {
			pings = 1
		}
		// Slightly early: the loop wakes a little after each whole second.
		m.nextProbe[g.ID] = now.Add(time.Duration(every)*time.Second - 200*time.Millisecond)
		probed[i] = true
		wg.Add(1)
		go func(i int, dev, target string, pings int) {
			defer wg.Done()
			ok, rtt := sdnPing(dev, target, sdn.ProbeMark(i), pings)
			results[i] = res{ok, rtt}
		}(i, h.Dev, target, pings)
	}
	wg.Wait()

	up := map[string]bool{}
	var wentDown []int
	for i, g := range c.Gateways {
		tr := m.trackers[g.ID]
		if tr == nil {
			tr = sdn.NewGWTracker(g, true)
			m.trackers[g.ID] = tr
		}
		tr.G = g
		if g.Monitor && probed[i] {
			if tr.Add(sdn.GWSample{OK: results[i].ok, RTT: results[i].rtt, At: now}) {
				kind := map[bool]string{true: "up", false: "down"}[tr.Up]
				m.events = append(m.events, GWEvent{At: now, Kind: kind, ID: g.ID, Name: g.Name})
				if !tr.Up {
					wentDown = append(wentDown, i)
				}
			}
		} else if !g.Monitor {
			tr.Add(sdn.GWSample{OK: true, At: now})
		}
		up[g.ID] = tr.Up
		m.maybeReconnect(c, g, tr, hops, targets[i], probed[i], probed[i] && results[i].ok, now)
	}

	plan := sdn.PlanRoutes(c, up, hops)
	// A link that redials loses its routes, maybe between two cycles: the plan
	// looks the same, but the device is new or the default route has gone.
	links := ""
	for _, h := range hops {
		if h.Via == "" {
			b, _ := os.ReadFile(filepath.Join(sdnSysClassNet, h.Dev, "ifindex"))
			links += h.Dev + "=" + strings.TrimSpace(string(b)) + ";"
		}
	}
	key := fmt.Sprintf("%+v|%v|%v", plan.Default, planKey(plan), sortedFields(links))
	// The same goes for a default route someone else replaced: a hook, or the
	// file's route given back when the last gateway was removed.
	cur := ""
	if plan.Default != nil || plan.LastResort != nil {
		cur = SDNDefaultRoute()
	}
	if key != m.lastPlan || ((plan.Default != nil || plan.LastResort != nil) && cur == "") ||
		(plan.Default != nil && cur != strings.Join(hopArgs(plan.Default), " ")) {
		if len(SDNApplyRoutes(plan)) == 0 {
			m.lastPlan = key
		}
	}
	// Connections move only if there is somewhere for them to go.
	if plan.Active != "" {
		for _, i := range wentDown {
			m.flush(c, i, hops[c.Gateways[i].ID])
		}
	}
	if plan.Active != m.active && plan.Active != "" && m.active != "" {
		name := plan.Active
		if g := c.GatewayByID(plan.Active); g != nil {
			name = g.Name
		}
		m.events = append(m.events, GWEvent{At: now, Kind: "failover", ID: plan.Active, Name: name, Active: plan.Active})
	}
	if plan.Active != "" {
		m.active = plan.Active
	}
	if len(m.events) > 50 {
		m.events = m.events[len(m.events)-50:]
	}

	st := GWStateFile{Updated: now, Active: m.active, Events: m.events}
	for i, g := range c.Gateways {
		tr := m.trackers[g.ID]
		s := GWStatus{ID: g.ID, Name: g.Name, Priority: g.Priority, Monitor: g.Monitor, Up: tr.Up, Active: g.ID == plan.Active,
			Loss: tr.Loss(), RTTms: float64(tr.LastRTT().Microseconds()) / 1000, Target: targets[i]}
		if h, ok := hops[g.ID]; ok {
			hc := h
			s.Hop, s.Usable = &hc, tr.Up
		}
		s.GatewayIP = gatewayIPs[i]
		if rc := m.reconnects[g.ID]; rc != nil && g.Monitor && !tr.Up && !rc.answered {
			s.ReconnectHeld = true
		}
		st.Gateways = append(st.Gateways, s)
	}
	return st
}

// maybeReconnect hangs up a monitored PPPoE link that its tests declare down,
// so a dead session is redialled. An address that has never answered proves
// nothing (some providers ignore ping), and a redial that did not help is not
// repeated at once: the pause doubles, up to 30 minutes, until the link is back.
func (m *gwMonitor) maybeReconnect(c *sdn.Config, g sdn.Gateway, tr *sdn.GWTracker, hops map[string]sdn.Hop, target string, tested, answered bool, now time.Time) {
	in := c.InterfaceByID(g.Interface)
	h, hasHop := hops[g.ID]
	if !g.Monitor || in == nil || in.Kind != "pppoe" || !hasHop {
		return
	}
	rc := m.reconnects[g.ID]
	if rc == nil {
		rc = &gwReconnect{}
		m.reconnects[g.ID] = rc
	}
	if rc.target != target {
		rc.target, rc.answered = target, false
	}
	if answered {
		rc.answered = true
	}
	if tr.Up {
		rc.pause, rc.next = 0, time.Time{}
		return
	}
	// A test that passed means the link has recovered and is only serving its
	// hold time: never hang up a link that answers.
	if tested {
		rc.lastFailed = !answered
	}
	if !rc.answered || !rc.lastFailed || now.Before(rc.next) {
		return
	}
	if rc.pause == 0 {
		rc.pause = gwReconnectFirstPause
	} else if rc.pause *= 2; rc.pause > gwReconnectMaxPause {
		rc.pause = gwReconnectMaxPause
	}
	rc.next = now.Add(rc.pause)
	if err := sdnPPPHangup(h.Dev); err != nil {
		log.Printf("[sdn] reconnect %s: %v", g.Name, err)
		return
	}
	log.Printf("[sdn] %s failed its ping tests: PPPoE link hung up, redialling", g.Name)
	m.events = append(m.events, GWEvent{At: now, Kind: "reconnect", ID: g.ID, Name: g.Name})
}

// sortedFields makes a list built from a map comparable.
func sortedFields(s string) string {
	f := strings.Split(s, ";")
	sort.Strings(f)
	return strings.Join(f, ";")
}

func planKey(p sdn.RoutePlan) string {
	k := fmt.Sprintf("last:%+v;", p.LastResort)
	for t := 100; t < 400; t++ {
		if h, ok := p.Tables[t]; ok {
			k += fmt.Sprintf("%d:%+v;", t, h)
		}
	}
	return k
}

// flush drops connections that went out through a gateway now down: those
// marked for it and those masqueraded behind its interface address, so
// clients reconnect at once through the next gateway.
func (m *gwMonitor) flush(c *sdn.Config, i int, h sdn.Hop) {
	for _, only := range []bool{false, true} {
		sdnRun.Run(nil, "conntrack", "-D", "--mark", fmt.Sprint(sdn.GatewayMark(i, only))) //nolint:errcheck
	}
	if a := sdnGatewayIfaceAddr(h.Dev); a != "" {
		sdnRun.Run(nil, "conntrack", "-D", "--reply-dst", a) //nolint:errcheck
	}
}

func writeGWState(st GWStateFile) {
	b, _ := json.Marshal(st)
	_ = os.MkdirAll(sdnRunDir, 0755)
	tmp := sdnGWStatePath() + ".tmp"
	if os.WriteFile(tmp, b, 0644) == nil {
		_ = os.Rename(tmp, sdnGWStatePath())
	}
}

// SDNGatewayMonitor is the daemon loop (never returns).
func SDNGatewayMonitor(st sdn.Store) {
	go sdnHealLoop(st)
	m := newGWMonitor(SDNGatewayState())
	var cfg *sdn.Config
	var cfgTime time.Time
	rulesFor := ""
	for {
		start := time.Now()
		state, _ := st.LoadState()
		// An apply in progress may be enabling a link config.json still has
		// disabled; read before the config, which is saved before this clears.
		_, aerr := st.LoadApplying()
		applying := aerr == nil
		if fi, err := os.Stat(filepath.Join(st.Dir, "sdn", "config.json")); err == nil && fi.ModTime() != cfgTime {
			if c, err := st.LoadConfirmed(); err == nil {
				cfg, cfgTime = c, fi.ModTime()
			}
		}
		if state.Enabled && cfg != nil && !applying {
			sdnHoldDisabledDown(cfg)
		}
		if !state.Enabled || cfg == nil || len(cfg.Gateways) == 0 {
			// Gateways removed or feature disabled: drop our ip rules once
			// (the main default route is left to whoever owns it now).
			if rulesFor != "0" && SDNSyncRules(&sdn.Config{}) == nil {
				rulesFor = "0"
				_ = os.Remove(sdnGWStatePath())
			}
			time.Sleep(5 * time.Second)
			continue
		}
		if k := fmt.Sprint(len(cfg.Gateways)); k != rulesFor {
			if SDNSyncRules(cfg) == nil {
				rulesFor = k
			}
		}
		writeGWState(m.cycle(cfg, start))
		if d := time.Second - time.Since(start); d > 0 {
			time.Sleep(d)
		}
	}
}

// SDNRunFile is a path under /run/znas-sdn (cleared at every boot): the
// portal keeps its "already alerted" marks there.
func SDNRunFile(name string) string { return filepath.Join(sdnRunDir, name) }
