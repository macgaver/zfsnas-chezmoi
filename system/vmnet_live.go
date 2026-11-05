package system

// Live traffic stack for the Network Focus (full) header: one block per 5 s,
// 20 minutes wide (the first 5 blocks come every 2 s so the graph fills in
// quickly). Two sources:
//
//   - devices (the Firewall is on): the 10 inside devices using the gateway
//     the most, from conntrack. They are chosen at the first look by the bytes
//     their open connections carried, then kept; each block is the growth of
//     their connections' counters. Labelled by FQDN when known, else the IP.
//   - instances (no Firewall): the 10 busiest Incus instances by their latest
//     5-minute RRD sample (the RRD is used only to choose); each block is the
//     host side of their NICs in /sys/class/net (host rx = guest upload).
//
// The gateway interface's counters give the total; "Other" is what the 10 do
// not explain. The sampler runs only while someone looks: the first request
// starts it, and it stops a minute after the last one.

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/sdn"
	"zfsnas/internal/traffic"
)

const (
	VMNetLiveStep      = 5 * time.Second
	VMNetLiveFastStep  = 2 * time.Second // the first blocks
	VMNetLiveFastCount = 5
	VMNetLivePoints    = 240 // 20 minutes of 5 s blocks
	VMNetLiveTop       = 10
	vmNetLiveIdle      = time.Minute      // stop sampling this long after the last viewer
	vmNetLiveRefresh   = 60 * time.Second // re-read interfaces / names
	VMNetModeDevices   = "devices"
	VMNetModeInstances = "instances"
)

// VMNetLiveHost is one line of the stack.
type VMNetLiveHost struct {
	Key  string `json:"key"`
	Name string `json:"name"`           // FQDN, else IP (devices); instance name
	IP   string `json:"ip,omitempty"`   // devices
	Type string `json:"type,omitempty"` // container / virtual-machine / device / server
}

// VMNetLivePoint is one block. Up/Down follow Hosts' order, bits/s.
type VMNetLivePoint struct {
	TS        int64   `json:"ts"`
	StepSec   int     `json:"step_sec"`
	Up        []int64 `json:"up"`
	Down      []int64 `json:"down"`
	OtherUp   int64   `json:"other_up"`
	OtherDown int64   `json:"other_down"`
	TotalUp   int64   `json:"total_up"`   // the gateway's upload (tx)
	TotalDown int64   `json:"total_down"` // the gateway's download (rx)
}

// VMNetLive is the header's data.
type VMNetLive struct {
	Available bool             `json:"available"`
	Mode      string           `json:"mode"`
	Iface     string           `json:"iface"`
	StepSec   int              `json:"step_sec"`
	Points    int              `json:"points"`
	Roster    int64            `json:"roster"` // changes when Hosts change
	Hosts     []VMNetLiveHost  `json:"hosts"`
	Data      []VMNetLivePoint `json:"data"` // oldest first, after ?since
}

type vmNetIf struct {
	inst, typ string
	host      string // host-side interface
}

type vmNetLiveSampler struct {
	mu     sync.Mutex
	sysNet string
	route  func() string
	ifaces func() []vmNetIf // running instances' host-side NICs
	rank   func() []string  // instances, busiest first (RRD)
	flows  func() []traffic.Flow
	env    func() traffic.Env
	names  func(c *sdn.Config, ips []string) map[string]string // ip → FQDN
	now    func() time.Time
	noLoop bool // tests: sample by hand

	running bool
	lastAsk time.Time
	cfg     *sdn.Config // nil: no Firewall
	mode    string

	roster   []VMNetLiveHost
	rosterID int64
	ring     []VMNetLivePoint

	// instances
	ifs   []vmNetIf
	ifsAt time.Time
	prev  map[string][2]int64 // host iface → rx, tx bytes
	// devices
	talk    *traffic.Talkers
	namesAt time.Time
	// gateway
	iface  string
	prevGw [2]int64
	prevOK bool
	prevAt time.Time
}

func (s *vmNetLiveSampler) counter(iface, name string) (int64, bool) {
	b, err := os.ReadFile(filepath.Join(s.sysNet, iface, "statistics", name))
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n, err == nil
}

// resetLocked forgets the roster and the timeline. Hold s.mu.
func (s *vmNetLiveSampler) resetLocked() {
	s.roster, s.ring, s.ifs, s.prev, s.prevOK = nil, nil, nil, nil, false
	s.talk, s.namesAt = nil, time.Time{}
}

func (s *vmNetLiveSampler) setRoster(r []VMNetLiveHost) {
	s.roster = r
	s.rosterID = s.now().UnixNano()
	s.ring = nil // the columns no longer match
	s.prevOK = false
}

// pickInstances: the RRD's busiest first, then the other running instances so
// a fresh server (no history yet) still shows something. Hold s.mu.
func (s *vmNetLiveSampler) pickInstances(rank []string) {
	types := map[string]string{}
	for _, f := range s.ifs {
		types[f.inst] = f.typ
	}
	var r []VMNetLiveHost
	seen := map[string]bool{}
	add := func(n string) {
		if len(r) < VMNetLiveTop && !seen[n] && types[n] != "" {
			seen[n] = true
			r = append(r, VMNetLiveHost{Key: n, Name: n, Type: types[n]})
		}
	}
	for _, n := range rank {
		add(n)
	}
	rest := make([]string, 0, len(types))
	for n := range types {
		rest = append(rest, n)
	}
	sort.Strings(rest)
	for _, n := range rest {
		add(n)
	}
	s.setRoster(r)
}

// instancesStale: no roster yet, or a member no longer runs. Hold s.mu.
func (s *vmNetLiveSampler) instancesStale() bool {
	if len(s.roster) == 0 {
		return true
	}
	alive := map[string]bool{}
	for _, f := range s.ifs {
		alive[f.inst] = true
	}
	for _, h := range s.roster {
		if !alive[h.Key] {
			return true
		}
	}
	return false
}

// pickDevices: the devices whose open connections carried the most, at the
// first look. Hold s.mu.
func (s *vmNetLiveSampler) pickDevices() {
	all := s.talk.Keyed()
	keys := make([]string, 0, len(all))
	for k, h := range all {
		if h.DownBytes+h.UpBytes > 0 {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := all[keys[i]], all[keys[j]]
		if x, y := a.DownBytes+a.UpBytes, b.DownBytes+b.UpBytes; x != y {
			return x > y
		}
		return keys[i] < keys[j]
	})
	if len(keys) > VMNetLiveTop {
		keys = keys[:VMNetLiveTop]
	}
	r := make([]VMNetLiveHost, 0, len(keys))
	for _, k := range keys {
		h := all[k]
		t := "device"
		if k == traffic.ThisServer {
			t = "server"
		}
		name := h.IP
		if t == "server" {
			name = s.selfName(s.cfg)
		}
		r = append(r, VMNetLiveHost{Key: k, Name: name, IP: h.IP, Type: t})
	}
	s.setRoster(r)
	s.namesAt = time.Time{} // name them now
}

// selfName: this server by its host name, in the Firewall's DNS domain.
func (s *vmNetLiveSampler) selfName(c *sdn.Config) string {
	h, _ := os.Hostname()
	if h == "" {
		return "This server"
	}
	if c != nil && c.DNS.Domain != "" && !strings.Contains(h, ".") {
		return h + "." + c.DNS.Domain
	}
	return h
}

func (s *vmNetLiveSampler) sample(now time.Time) {
	s.mu.Lock()
	mode, cfg := s.mode, s.cfg
	refresh := s.ifs == nil || now.Sub(s.ifsAt) >= vmNetLiveRefresh
	s.mu.Unlock()

	// Incus, conntrack and the RRD files are read outside the lock: a slow
	// daemon must not hold up the header's requests.
	var ifs []vmNetIf
	var flows []traffic.Flow
	if mode == VMNetModeDevices {
		flows = s.flows()
	} else if refresh {
		ifs = s.ifaces()
	}

	s.mu.Lock()
	if s.mode != mode { // switched meanwhile: the next tick starts over
		s.mu.Unlock()
		return
	}
	var cur map[string][2]int64
	ready := false
	if mode == VMNetModeDevices {
		if s.talk == nil {
			s.talk = traffic.NewTalkers()
		}
		s.talk.Sample(flows, s.env(), now)
		if len(s.roster) == 0 {
			s.pickDevices()
		}
		ready = s.talk.Ready()
	} else {
		if refresh {
			s.ifs, s.ifsAt = ifs, now
			if s.instancesStale() {
				s.mu.Unlock()
				rank := s.rank()
				s.mu.Lock()
				s.pickInstances(rank)
			}
		}
		cur = map[string][2]int64{}
		for _, f := range s.ifs {
			rx, ok1 := s.counter(f.host, "rx_bytes")
			tx, ok2 := s.counter(f.host, "tx_bytes")
			if ok1 && ok2 {
				cur[f.host] = [2]int64{rx, tx}
			}
		}
		ready = true
	}

	gw := s.route()
	if gw != s.iface {
		s.iface, s.prevOK = gw, false
	}
	var gwc [2]int64
	gwOK := false
	if gw != "" {
		rx, ok1 := s.counter(gw, "rx_bytes")
		tx, ok2 := s.counter(gw, "tx_bytes")
		gwc, gwOK = [2]int64{rx, tx}, ok1 && ok2
	}
	dt := now.Sub(s.prevAt).Seconds()
	if s.prevOK && ready && dt > 0 && dt < 3*VMNetLiveStep.Seconds() {
		rate := func(c, p int64) int64 {
			if c < p {
				return 0 // counter reset: interface re-created
			}
			return int64(float64(c-p) * 8 / dt)
		}
		p := VMNetLivePoint{TS: now.Unix(), StepSec: int(dt + 0.5), Up: make([]int64, len(s.roster)), Down: make([]int64, len(s.roster))}
		var keyed map[string]traffic.Talker
		if mode == VMNetModeDevices {
			keyed = s.talk.Keyed()
		}
		var sumUp, sumDown int64
		for i, h := range s.roster {
			if mode == VMNetModeDevices {
				t := keyed[h.Key]
				p.Up[i], p.Down[i] = t.UpBps, t.DownBps
			} else {
				for _, f := range s.ifs {
					if f.inst != h.Key {
						continue
					}
					c, ok1 := cur[f.host]
					pv, ok2 := s.prev[f.host]
					if ok1 && ok2 {
						p.Up[i] += rate(c[0], pv[0])   // host rx = guest sent
						p.Down[i] += rate(c[1], pv[1]) // host tx = guest received
					}
				}
			}
			sumUp += p.Up[i]
			sumDown += p.Down[i]
		}
		if gwOK {
			p.TotalUp, p.TotalDown = rate(gwc[1], s.prevGw[1]), rate(gwc[0], s.prevGw[0])
			p.OtherUp, p.OtherDown = max(0, p.TotalUp-sumUp), max(0, p.TotalDown-sumDown)
		}
		s.ring = append(s.ring, p)
		if len(s.ring) > VMNetLivePoints {
			s.ring = s.ring[len(s.ring)-VMNetLivePoints:]
		}
	}
	if cur != nil {
		s.prev = cur
	}
	s.prevGw, s.prevOK, s.prevAt = gwc, gwOK, now

	// devices: their names (reverse DNS can be slow: outside the lock)
	var ips []string
	if mode == VMNetModeDevices && s.names != nil && len(s.roster) > 0 && now.Sub(s.namesAt) >= vmNetLiveRefresh {
		s.namesAt = now
		for _, h := range s.roster {
			if h.Type != "server" { // named after its host name, not its WAN address
				ips = append(ips, h.IP)
			}
		}
	}
	id := s.rosterID
	s.mu.Unlock()
	if len(ips) > 0 {
		fq := s.names(cfg, ips)
		s.mu.Lock()
		if s.rosterID == id {
			for i := range s.roster {
				if f := fq[s.roster[i].IP]; f != "" {
					s.roster[i].Name = f
				}
			}
		}
		s.mu.Unlock()
	}
}

// snapshot starts the sampler when needed and returns the points after since.
// cfg is the Firewall's configuration, nil when it is off.
func (s *vmNetLiveSampler) snapshot(since int64, cfg *sdn.Config) VMNetLive {
	mode := VMNetModeInstances
	if cfg != nil {
		mode = VMNetModeDevices
	}
	s.mu.Lock()
	s.lastAsk = s.now()
	s.cfg = cfg
	if s.mode != mode {
		s.mode = mode
		s.resetLocked()
	}
	if !s.running {
		s.running = true
		s.mu.Unlock()
		// the first look chooses the lines at once (a baseline, no block
		// yet), so the header shows them without waiting a tick
		s.sample(s.now())
		if !s.noLoop {
			go s.loop()
		}
		s.mu.Lock()
	}
	out := VMNetLive{
		Available: len(s.roster) > 0, Mode: s.mode, Iface: s.iface,
		StepSec: int(VMNetLiveStep / time.Second), Points: VMNetLivePoints,
		Roster: s.rosterID, Hosts: append([]VMNetLiveHost{}, s.roster...),
		Data: s.snapshotLocked(since),
	}
	s.mu.Unlock()
	return out
}

// snapshotLocked: the points after since. Hold s.mu.
func (s *vmNetLiveSampler) snapshotLocked(since int64) []VMNetLivePoint {
	out := []VMNetLivePoint{}
	for _, p := range s.ring {
		if p.TS > since {
			out = append(out, p)
		}
	}
	return out
}

// nextStep: 2 s for the first blocks, then 5 s.
func (s *vmNetLiveSampler) nextStep() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ring) < VMNetLiveFastCount {
		return VMNetLiveFastStep
	}
	return VMNetLiveStep
}

func (s *vmNetLiveSampler) loop() {
	for {
		time.Sleep(s.nextStep())
		s.mu.Lock()
		idle := s.now().Sub(s.lastAsk) > vmNetLiveIdle
		if idle {
			// the next viewer starts over: a fresh choice, an empty timeline
			s.running = false
			s.resetLocked()
		}
		s.mu.Unlock()
		if idle {
			return
		}
		s.sample(s.now())
	}
}

// vmNetRankFromRRD: instances by their latest 5-minute network sample (guest
// side, real NICs only), busiest first; samples older than 15 min are ignored.
func vmNetRankFromRRD() []string {
	type sc struct {
		n string
		v float64
	}
	var all []sc
	cut := time.Now().Add(-15 * time.Minute).Unix()
	for _, name := range ListLXDMetricInstances() {
		db := GetLXDInstanceMetricsDB(name)
		if db == nil {
			continue
		}
		v := 0.0
		for _, k := range db.Keys() {
			dev := strings.TrimPrefix(strings.TrimPrefix(k, "net_rx:"), "net_tx:")
			if dev == k || dev == "lo" {
				continue
			}
			q := db.Query(0, k)
			if len(q) == 0 || q[len(q)-1].TS < cut {
				continue
			}
			v += q[len(q)-1].Avg
		}
		if v > 0 {
			all = append(all, sc{name, v})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	out := make([]string, len(all))
	for i, x := range all {
		out[i] = x.n
	}
	return out
}

// vmNetHostIfaces: every running instance's NICs with a host-side interface
// (volatile.<nic>.host_name: bridged and routed NICs; macvlan/physical/SR-IOV
// have none and cannot be counted here).
func vmNetHostIfaces() []vmNetIf {
	var insts []struct {
		Name   string            `json:"name"`
		Type   string            `json:"type"`
		Status string            `json:"status"`
		Config map[string]string `json:"config"`
	}
	if !IncusInstalled() {
		return []vmNetIf{}
	}
	if err := incusQuery("/1.0/instances?recursion=1", &insts); err != nil {
		return []vmNetIf{}
	}
	out := []vmNetIf{}
	for _, in := range insts {
		if in.Status != "Running" {
			continue
		}
		for k, v := range in.Config {
			if v != "" && strings.HasPrefix(k, "volatile.") && strings.HasSuffix(k, ".host_name") {
				out = append(out, vmNetIf{inst: in.Name, typ: in.Type, host: v})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].host < out[j].host })
	return out
}

// vmNetConntrack: the connections the Firewall tracks.
func vmNetConntrack() []traffic.Flow {
	out, err := sdnRun.Run(nil, "conntrack", "-L", "-o", "extended,id")
	if err != nil && len(out) == 0 {
		return nil
	}
	var flows []traffic.Flow
	for _, line := range strings.Split(string(out), "\n") {
		if f, ok := traffic.ParseConntrack(line); ok && !f.OrigSrc.IsLoopback() {
			flows = append(flows, f)
		}
	}
	return flows
}

// vmNetFQDNs: each address's FQDN when one is known (reverse DNS, DHCP
// leases and reservations, DNS host entries).
func vmNetFQDNs(c *sdn.Config, ips []string) map[string]string {
	out := map[string]string{}
	if c == nil {
		return out
	}
	known := SDNHostNames(c, ips, time.Now())
	local := sdnLocalNames(c)
	for _, ip := range ips {
		f := known[ip].FQDN
		if f == "" {
			_, f = local(ip)
		}
		if f != "" {
			out[ip] = f
		}
	}
	return out
}

var vmNetLive = &vmNetLiveSampler{
	sysNet: "/sys/class/net",
	route: func() string {
		b, _ := os.ReadFile("/proc/net/route")
		return procRouteDefaultIface(string(b))
	},
	ifaces: vmNetHostIfaces,
	rank:   vmNetRankFromRRD,
	flows:  vmNetConntrack,
	env:    func() traffic.Env { return sdnTC.env() },
	names:  vmNetFQDNs,
	now:    time.Now,
}

// GetVMNetLive is the Network Focus header's stack: points after since. cfg
// is the Firewall's configuration (nil when it is off: instances are shown).
func GetVMNetLive(since int64, cfg *sdn.Config) VMNetLive { return vmNetLive.snapshot(since, cfg) }
