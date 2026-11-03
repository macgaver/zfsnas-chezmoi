package system

// Traffic statistics collector for the Firewall (spec §12): conntrack event
// stream (DESTROY = final counters) + 60 s poll (growth of long-lived flows)
// + 60 s sample of the nft blocked-attempt set, aggregated in memory and
// written to the stats directory every 10 minutes. Runs inside the portal
// (statistics, unlike forwarding, may depend on it); at most 10 minutes are
// lost when the portal restarts.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/geoip"
	"zfsnas/internal/sdn"
	"zfsnas/internal/traffic"
)

const sdnRAMStatsDir = "/dev/shm/znas-sdn-stats"

// sdnStatsDir is where statistics and geo databases live: the configured
// pool dataset, else RAM (lost at reboot; the UI asks to pick a pool).
func sdnStatsDir(c *sdn.Config) (dir string, ramOnly bool) {
	if c != nil && c.Settings.StatsDir != "" {
		return c.Settings.StatsDir, false
	}
	return sdnRAMStatsDir, true
}

func sdnBlockedFromElems(elems []BlockedElem, c *sdn.Config) []traffic.Blocked {
	nums := sdn.BlockRuleNumbers(c)
	out := make([]traffic.Blocked, 0, len(elems))
	for _, e := range elems {
		rule := "default deny"
		if id, ok := nums[e.Rule]; ok && e.Rule > 0 {
			rule = id
			for _, r := range c.Rules {
				if r.ID == id && r.Description != "" {
					rule = r.Description
				}
			}
		}
		out = append(out, traffic.Blocked{Src: e.Src, Proto: e.Proto, Port: e.Port, Iface: e.Iface, Rule: rule, Packets: e.Packets})
	}
	return out
}

// SDNTrafficStatus is shown on the Traffic page.
type SDNTrafficStatus struct {
	Running   bool           `json:"running"`
	Error     string         `json:"error,omitempty"`
	StatsDir  string         `json:"stats_dir"`
	RAMOnly   bool           `json:"ram_only"`
	Geo       []SDNGeoStatus `json:"geo"`
	GeoError  string         `json:"geo_error,omitempty"`
	LastFlush time.Time      `json:"last_flush,omitempty"`
	Events    uint64         `json:"events"`
}

type sdnCollector struct {
	mu     sync.Mutex
	agg    *traffic.Aggregator
	store  *traffic.Store
	status SDNTrafficStatus
	cfg    *sdn.Config
	locals map[netip.Addr]string
	names  map[netip.Addr]string
}

var sdnTC = &sdnCollector{}

func (c *sdnCollector) env() traffic.Env {
	return traffic.Env{
		Local: func(a netip.Addr) bool { c.mu.Lock(); defer c.mu.Unlock(); _, ok := c.locals[a]; return ok },
		IfaceOf: func(a netip.Addr) string {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.locals[a]
		},
		NameOf: func(a netip.Addr) string { c.mu.Lock(); defer c.mu.Unlock(); return c.names[a] },
		Geo: func(a netip.Addr) geoip.Info {
			if r := SDNGeo(); r != nil {
				return r.Lookup(a)
			}
			return geoip.Info{}
		},
	}
}

// refreshFacts reloads local addresses and inside host names.
func (c *sdnCollector) refreshFacts() {
	locals := map[netip.Addr]string{}
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if ip, ok := netip.AddrFromSlice(ipn.IP.To4()); ok && ipn.IP.To4() != nil {
						locals[ip] = ifc.Name
					}
				}
			}
		}
	}
	names := map[netip.Addr]string{}
	if IncusUsable() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := exec.CommandContext(ctx, "incus", "list", "--format", "json").Output()
		cancel()
		if err == nil {
			var insts []struct {
				Name  string `json:"name"`
				State struct {
					Network map[string]lxdStateNetwork `json:"network"`
				} `json:"state"`
			}
			if json.Unmarshal(out, &insts) == nil {
				for _, in := range insts {
					for _, n := range in.State.Network {
						for _, a := range n.Addresses {
							if ip, err := netip.ParseAddr(a.Address); err == nil && ip.Is4() {
								names[ip] = in.Name
							}
						}
					}
				}
			}
		}
	}
	c.mu.Lock()
	c.locals, c.names = locals, names
	c.mu.Unlock()
}

func (c *sdnCollector) setErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.status.Error = ""
	} else {
		c.status.Error = err.Error()
	}
}

// StartSDNTraffic runs the collector for the life of the portal; it idles
// while the Firewall is disabled.
func StartSDNTraffic(configDir string) {
	SDNSetConfigDir(configDir)
	st := sdn.Store{Dir: configDir}
	c := sdnTC
	c.agg = traffic.NewAggregator(c.env())
	go func() {
		var cancel context.CancelFunc
		lastFlush, lastRollup, lastGeo := time.Now(), time.Time{}, time.Time{}
		tick := time.NewTicker(60 * time.Second)
		defer tick.Stop()
		for {
			state, _ := st.LoadState()
			cfg, cerr := st.LoadConfirmed()
			if cerr != nil || cfg == nil { // unreadable config: keep the last good one
				c.mu.Lock()
				cfg = c.cfg
				c.mu.Unlock()
			}
			if !state.Enabled || !binaryPresent("conntrack") {
				if cancel != nil {
					cancel()
					cancel = nil
				}
				c.mu.Lock()
				c.status.Running = false
				if state.Enabled {
					c.status.Error = "conntrack is not installed"
				}
				c.mu.Unlock()
				<-tick.C
				continue
			}
			dir, ram := sdnStatsDir(cfg)
			c.mu.Lock()
			c.cfg = cfg
			if c.store == nil || c.store.Dir != filepath.Join(dir, "traffic") {
				c.store = &traffic.Store{Dir: filepath.Join(dir, "traffic")}
				SDNSetGeoDir(SDNGeoDir(dir))
			}
			c.status.StatsDir, c.status.RAMOnly, c.status.Running = dir, ram, true
			c.status.Geo = SDNGeoDBStatus(SDNGeoDir(dir))
			c.mu.Unlock()
			c.refreshFacts()
			now := time.Now()
			c.poll(now)
			if cancel == nil { // after the seeding poll: no pre-existing flow counted twice
				var ctx context.Context
				ctx, cancel = context.WithCancel(context.Background())
				go c.events(ctx)
			}
			if elems, err := SDNBlockedSample(); err == nil {
				c.agg.AddBlocked(sdnBlockedFromElems(elems, cfg), now)
			}
			if now.Sub(lastFlush) >= 10*time.Minute {
				c.flush(now)
				lastFlush = now
			}
			if now.Sub(lastRollup) >= time.Hour {
				// Write the closed buckets first: an hour must never be
				// rolled while its last 5-minute buckets are in memory.
				c.flush(now)
				lastFlush = now
				if err := c.store.Rollup(now); err != nil {
					c.setErr(fmt.Errorf("rollup: %w", err))
				}
				c.store.Prune(now)
				lastRollup = now
			}
			if now.Sub(lastGeo) >= 24*time.Hour {
				lastGeo = now
				go func(gdir string) {
					err := SDNUpdateGeoDB(gdir, time.Now())
					c.mu.Lock()
					c.status.GeoError = ""
					if err != nil {
						c.status.GeoError = err.Error()
					}
					cur := SDNGeoDir(c.status.StatsDir)
					c.mu.Unlock()
					if cur == gdir { // the stats may have moved to a pool meanwhile
						SDNSetGeoDir(gdir)
					}
				}(SDNGeoDir(dir))
			}
			<-tick.C
		}
	}()
}

func (c *sdnCollector) flush(now time.Time) {
	bs := c.agg.Drain(now)
	if len(bs) == 0 {
		return
	}
	if err := os.MkdirAll(c.store.Dir, 0755); err != nil {
		c.setErr(err)
		return
	}
	if err := c.store.Write(bs); err != nil {
		c.setErr(fmt.Errorf("writing statistics: %w", err))
		return
	}
	c.mu.Lock()
	c.status.LastFlush = now
	c.mu.Unlock()
}

// SDNTrafficFlush writes the in-memory buckets now (graceful shutdown).
func SDNTrafficFlush() {
	sdnTC.mu.Lock()
	ok := sdnTC.store != nil && sdnTC.agg != nil
	sdnTC.mu.Unlock()
	if ok {
		sdnTC.flush(time.Now().Add(traffic.BucketSize))
	}
}

func (c *sdnCollector) poll(now time.Time) {
	out, err := sdnRun.Run(nil, "conntrack", "-L", "-o", "extended,id")
	if err != nil && len(out) == 0 {
		c.setErr(fmt.Errorf("conntrack poll: %w", err))
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if f, ok := traffic.ParseConntrack(line); ok {
			f.At = now
			c.agg.AddFlow(f)
		}
	}
	c.agg.SetSeeded()
	c.setErr(nil)
}

// events follows `conntrack -E` (DESTROY events) and restarts it with a
// backoff when it dies.
func (c *sdnCollector) events(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		args := []string{"conntrack", "-E", "-e", "DESTROY", "-o", "timestamp,extended,id"}
		var cmd *exec.Cmd
		if os.Getuid() == 0 {
			cmd = exec.CommandContext(ctx, args[0], args[1:]...)
		} else {
			cmd = exec.CommandContext(ctx, "sudo", append([]string{"-n"}, args...)...)
		}
		out, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			c.setErr(fmt.Errorf("conntrack events: %w", err))
		} else {
			sc := bufio.NewScanner(out)
			sc.Buffer(make([]byte, 64<<10), 1<<20)
			for sc.Scan() {
				if f, ok := traffic.ParseConntrack(sc.Text()); ok {
					c.agg.AddFlow(f)
					c.mu.Lock()
					c.status.Events++
					c.mu.Unlock()
				}
			}
			werr := cmd.Wait()
			if ctx.Err() == nil {
				c.setErr(fmt.Errorf("conntrack event stream stopped: %v", werr))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

// SDNTrafficQuery answers the Traffic page.
func SDNTrafficQuery(q traffic.Query) traffic.Result {
	c := sdnTC
	c.mu.Lock()
	store := c.store
	c.mu.Unlock()
	if store == nil || c.agg == nil {
		return traffic.Result{KPI: map[string]traffic.KPI{}}
	}
	if g := SDNGeo(); g != nil {
		q.Locate = func(remote string) (geoip.Info, bool) {
			a, err := netip.ParseAddr(remote)
			if err != nil {
				return geoip.Info{}, false
			}
			return g.Lookup(a), true
		}
	}
	return store.Query(q, c.agg.Snapshot(), time.Now())
}

func SDNTrafficStatusNow() SDNTrafficStatus {
	sdnTC.mu.Lock()
	defer sdnTC.mu.Unlock()
	return sdnTC.status
}

// LiveConn is one current connection on the Live connections page.
type LiveConn struct {
	traffic.Rec
	ID        uint64 `json:"id"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Sport     uint16 `json:"sport"`
	Dport     uint16 `json:"dport"`
	Initiator string `json:"initiator"` // "remote" | "inside" | "internal"
}

// SDNLiveConnections lists current connections, biggest first.
func SDNLiveConnections(limit int) ([]LiveConn, error) {
	out, err := sdnRun.Run(nil, "conntrack", "-L", "-o", "extended,id")
	if err != nil && len(out) == 0 {
		return nil, err
	}
	env := sdnTC.env()
	var list []LiveConn
	for _, line := range strings.Split(string(out), "\n") {
		f, ok := traffic.ParseConntrack(line)
		if !ok || f.OrigSrc.IsLoopback() {
			continue
		}
		lc := LiveConn{ID: f.ID, Src: f.OrigSrc.String(), Dst: f.OrigDst.String(), Sport: f.OrigSport, Dport: f.OrigDport}
		if _, r, ok := traffic.Classify(f, env); ok {
			lc.Rec = r
			lc.Initiator = map[string]string{"in": "remote", "out": "inside"}[r.Dir]
		} else {
			lc.Rec = traffic.Rec{Proto: f.Proto, BytesIn: f.BytesReply, BytesOut: f.BytesOrig, Pkts: f.PktsOrig + f.PktsReply}
			lc.Initiator = "internal"
		}
		list = append(list, lc)
	}
	sortLive(list)
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	return list, nil
}

func sortLive(l []LiveConn) {
	sort.Slice(l, func(i, j int) bool { return l[i].BytesIn+l[i].BytesOut > l[j].BytesIn+l[j].BytesOut })
}

// SDNKillConnection removes one connection from the tracking table (its
// packets then hit the rules again as a new connection).
func SDNKillConnection(proto, src, dst string, sport, dport uint16) error {
	args := []string{"-D", "-p", proto, "--orig-src", src, "--orig-dst", dst}
	if proto == "tcp" || proto == "udp" {
		args = append(args, "--sport", fmt.Sprint(sport), "--dport", fmt.Sprint(dport))
	}
	_, err := sdnRun.Run(nil, "conntrack", args...)
	return err
}

// SDNSetStatsPool creates <pool>/znas-netstats and returns its mountpoint.
func SDNSetStatsPool(pool string) (string, error) {
	ds := pool + "/znas-netstats"
	if _, err := sdnRun.Run(nil, "zfs", "list", "-H", ds); err != nil {
		if _, err := sdnRun.Run(nil, "zfs", "create", ds); err != nil {
			return "", err
		}
	}
	out, err := sdnRun.Run(nil, "zfs", "get", "-H", "-o", "value", "mountpoint", ds)
	if err != nil {
		return "", err
	}
	mp := strings.TrimSpace(string(out))
	if mp == "" || mp == "none" || mp == "legacy" {
		return "", fmt.Errorf("%s has no mountpoint", ds)
	}
	if os.Getuid() != 0 {
		sdnRun.Run(nil, "chown", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), mp) //nolint:errcheck
	}
	return mp, nil
}

// SDNPublicLocalAddrs lists this box's public IPv4 addresses (WAN).
func SDNPublicLocalAddrs() []netip.Addr {
	sdnTC.mu.Lock()
	defer sdnTC.mu.Unlock()
	var out []netip.Addr
	for a := range sdnTC.locals {
		if geoip.IsPublic(a) {
			out = append(out, a)
		}
	}
	return out
}

// SDNMoveStats moves collected statistics and geo databases to a new stats
// directory (RAM → pool): copy then delete, as they cross filesystems.
func SDNMoveStats(from, to string) error {
	if from == to {
		return nil
	}
	err := filepath.Walk(from, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		if fi.IsDir() {
			return os.MkdirAll(dst, 0755)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(dst + ".tmp")
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		return os.Rename(dst+".tmp", dst)
	})
	if err != nil {
		return err
	}
	return os.RemoveAll(from)
}

// SDNIsLocalAddr reports whether a is an address of this server (the WAN's
// public address included): from the traffic collector's view, else the
// kernel's.
func SDNIsLocalAddr(a netip.Addr) bool {
	sdnTC.mu.Lock()
	_, ok := sdnTC.locals[a]
	n := len(sdnTC.locals)
	sdnTC.mu.Unlock()
	if ok || n > 0 {
		return ok
	}
	addrs, _ := net.InterfaceAddrs()
	for _, x := range addrs {
		if p, err := netip.ParsePrefix(x.String()); err == nil && p.Addr().Unmap() == a.Unmap() {
			return true
		}
	}
	return false
}
