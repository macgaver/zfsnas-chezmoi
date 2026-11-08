package system

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/sdn"
)

// SDNLiveIface is a network device as the Interfaces page shows it.
type SDNLiveIface struct {
	Device    string   `json:"device"`
	Kind      string   `json:"kind"` // physical | vlan | bridge | bond | ppp | wireguard
	MAC       string   `json:"mac"`
	State     string   `json:"state"`
	SpeedMbps int      `json:"speed_mbps"`
	IPv4      []string `json:"ipv4"`
	MTU       int      `json:"mtu"`
	Master    string   `json:"master,omitempty"`
	Mgmt      bool     `json:"mgmt"`
	RxBps     int64    `json:"rx_bps"`
	TxBps     int64    `json:"tx_bps"`
	Adoptable bool     `json:"adoptable"`
	Incus     bool     `json:"incus,omitempty"` // Incus-managed bridge (adopted as kind "incus")
	// Incus network with its own address: adding it keeps its address and DHCP.
	IncusKeep bool   `json:"incus_keep,omitempty"`
	IncusNAT  bool   `json:"incus_nat,omitempty"` // Incus translates its outgoing traffic itself
	Reason    string `json:"reason,omitempty"`
	// Addressing as written in /etc/network/interfaces (adopting a port keeps
	// it): "static" | "dhcp" | "manual" | "" when the file has no stanza.
	CfgMode    string `json:"cfg_mode,omitempty"`
	CfgAddress string `json:"cfg_address,omitempty"`
	CfgGateway string `json:"cfg_gateway,omitempty"`
}

// Hooks (tests replace them).
var (
	// Incus-managed networks → their ipv4.address ("" / "none" = pure L2).
	sdnIncusManagedBridges = func() map[string]string {
		m := map[string]string{}
		if !IncusUsable() { // VMs & Containers not in use: never call incus
			return m
		}
		if nets, err := ListLXDNetworks(); err == nil {
			for _, n := range nets {
				if n.Managed {
					m[n.Name] = n.Config["ipv4.address"]
					if n.Config["user.znas.sdn"] == "true" {
						m[n.Name] = "none" // ours: the address is the Firewall's
					}
				}
			}
		}
		return m
	}
	sdnIfaceAddrs = func(name string) []string {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return nil
		}
		addrs, _ := ifi.Addrs()
		var out []string
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				out = append(out, ipn.String())
			}
		}
		return out
	}
	sdnRateWindow     = time.Second
	sdnIncusInstalled = IncusInstalled
)

func readSysTrim(dev, file string) string {
	b, _ := os.ReadFile(filepath.Join(sdnSysClassNet, dev, file))
	return strings.TrimSpace(string(b))
}

func readSysInt(dev, file string) int64 {
	n, _ := strconv.ParseInt(readSysTrim(dev, file), 10, 64)
	return n
}

func sysExists(dev, sub string) bool {
	_, err := os.Stat(filepath.Join(sdnSysClassNet, dev, sub))
	return err == nil
}

func sdnDeviceKind(dev string) string {
	switch {
	case sysExists(dev, "bridge"):
		return "bridge"
	case sysExists(dev, "bonding"):
		return "bond"
	case strings.Contains(readSysTrim(dev, "uevent"), "DEVTYPE=vlan"):
		return "vlan"
	case sysExists(dev, "device"):
		return "physical"
	// Links the Firewall brings up itself: listed for their live address
	// (PPPoE's public address, the tunnel's), never adoptable.
	case readSysTrim(dev, "type") == "512":
		return "ppp"
	case strings.Contains(readSysTrim(dev, "uevent"), "DEVTYPE=wireguard"):
		return "wireguard"
	}
	return ""
}

// SDNLiveInterfaces lists the devices the admin can turn into SDN
// interfaces, with live state. requestLocalAddr is the server address the
// browser reached; the device holding it is the management interface.
func SDNLiveInterfaces(requestLocalAddr string) ([]SDNLiveIface, error) {
	entries, err := os.ReadDir(sdnSysClassNet)
	if err != nil {
		return nil, err
	}
	incus := sdnIncusManagedBridges()
	// Incus installed but not answering: its networks are unknown, so a
	// bridge without an ifupdown stanza may be Incus' own.
	incusUnknown := sdnIncusInstalled() && !IncusUsable()
	ifFile, _ := os.ReadFile(hostInterfacesPath)
	owned := map[string]bool{}
	for _, d := range sdn.OwnedIfaces(string(ifFile)) {
		owned[d] = true
	}
	var out []SDNLiveIface
	rx0, tx0 := map[string]int64{}, map[string]int64{}
	for _, e := range entries {
		dev := e.Name()
		kind := sdnDeviceKind(dev)
		if dev == "lo" || kind == "" {
			continue
		}
		l := SDNLiveIface{Device: dev, Kind: kind, MAC: readSysTrim(dev, "address"), State: readSysTrim(dev, "operstate"),
			MTU: int(readSysInt(dev, "mtu")), IPv4: sdnIfaceAddrs(dev), Adoptable: true}
		if s := readSysInt(dev, "speed"); s > 0 {
			l.SpeedMbps = int(s)
		}
		if target, err := os.Readlink(filepath.Join(sdnSysClassNet, dev, "master")); err == nil {
			l.Master = filepath.Base(target)
		}
		for _, a := range l.IPv4 {
			if ip, _, _ := strings.Cut(a, "/"); ip == requestLocalAddr {
				l.Mgmt = true
			}
		}
		switch {
		case kind == "ppp":
			l.Adoptable, l.Reason = false, "PPPoE link"
		case kind == "wireguard":
			l.Adoptable, l.Reason = false, "WireGuard tunnel"
		case l.Master != "" && sysExists(l.Master, "bonding"):
			l.Adoptable, l.Reason = false, "member of bond "+l.Master
		case l.Master != "":
			l.Adoptable, l.Reason = false, "port of bridge "+l.Master
		case incusHas(incus, dev):
			l.Incus = true
			if a := incus[dev]; a != "" && a != "none" {
				l.IncusKeep, l.CfgMode, l.CfgAddress = true, "static", a
				l.IncusNAT = sdnIncusNetKey(dev, "ipv4.nat") == "true"
			}
		case incusUnknown && kind == "bridge" && !owned[dev] && !parseHostBridgeConfig(ifFile, dev).Exists:
			l.Adoptable, l.Reason = false, "may belong to Incus (Incus is not answering)"
		case strings.HasPrefix(dev, "docker") || (strings.HasPrefix(dev, "br-") && len(dev) == 15 && kind == "bridge" && !strings.Contains(dev, "-v")):
			l.Adoptable, l.Reason = false, "Docker network"
		}
		if hb, err := GetHostBridgeConfig(dev); err == nil && hb.Exists {
			l.CfgMode, l.CfgAddress, l.CfgGateway = hb.Mode, hb.Address, hb.Gateway
		}
		rx0[dev], tx0[dev] = readSysInt(dev, "statistics/rx_bytes"), readSysInt(dev, "statistics/tx_bytes")
		out = append(out, l)
	}
	if sdnRateWindow > 0 {
		time.Sleep(sdnRateWindow)
		secs := sdnRateWindow.Seconds()
		for i := range out {
			d := out[i].Device
			out[i].RxBps = int64(float64(readSysInt(d, "statistics/rx_bytes")-rx0[d]) / secs)
			out[i].TxBps = int64(float64(readSysInt(d, "statistics/tx_bytes")-tx0[d]) / secs)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Device < out[j].Device })
	return out, nil
}

// RuleCounter is a rule's hit counters plus its recent history.
type RuleCounter struct {
	Packets uint64    `json:"packets"`
	Bytes   uint64    `json:"bytes"`
	Spark   []uint64  `json:"spark,omitempty"`    // packets per 5-min sample, oldest first, max 288 (24 h)
	LastHit time.Time `json:"last_hit,omitempty"` // zero = not hit since the portal started
}

// SDNRuleCounters reads the live counters of every rule (`nft -j list
// table`), summing the lines of rules compiled into several chains/lines,
// and adds the sampled history.
func SDNRuleCounters() (map[string]RuleCounter, error) {
	out, err := sdnRun.Run(nil, "nft", "-j", "list", "table", "ip", sdn.TableName)
	if err != nil {
		return nil, err
	}
	m, err := parseNftCounters(out)
	if err != nil {
		return nil, err
	}
	for id, c := range m {
		c.Spark = sdnCounterHist.spark(id)
		c.LastHit = sdnCounterHist.lastHit(id)
		m[id] = c
	}
	return m, nil
}

func parseNftCounters(b []byte) (map[string]RuleCounter, error) {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Comment string            `json:"comment"`
				Expr    []json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	m := map[string]RuleCounter{}
	for _, it := range doc.Nftables {
		if it.Rule == nil {
			continue
		}
		id, ok := strings.CutPrefix(it.Rule.Comment, "r:")
		if !ok {
			continue
		}
		c := m[id]
		for _, raw := range it.Rule.Expr {
			var e struct {
				Counter *struct{ Packets, Bytes uint64 } `json:"counter"`
			}
			if json.Unmarshal(raw, &e) == nil && e.Counter != nil {
				c.Packets += e.Counter.Packets
				c.Bytes += e.Counter.Bytes
			}
		}
		m[id] = c
	}
	return m, nil
}

// counterHistory keeps the 24 h sparkline per rule in memory (phase 2 moves
// it into the traffic store). Counters restart when the table is reloaded,
// so a value lower than the previous sample counts as a fresh start.
type counterHistory struct {
	mu   sync.Mutex
	prev map[string]uint64
	hist map[string][]uint64
	last map[string]time.Time
}

const counterHistoryMax = 288

func newCounterHistory() *counterHistory {
	return &counterHistory{prev: map[string]uint64{}, hist: map[string][]uint64{}, last: map[string]time.Time{}}
}

func (h *counterHistory) observe(cur map[string]RuleCounter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	for id, c := range cur {
		delta := c.Packets
		if p, ok := h.prev[id]; ok && c.Packets >= p {
			delta = c.Packets - p
		}
		h.prev[id] = c.Packets
		s := append(h.hist[id], delta)
		if len(s) > counterHistoryMax {
			s = s[len(s)-counterHistoryMax:]
		}
		h.hist[id] = s
		if delta > 0 {
			h.last[id] = now
		}
	}
}

func (h *counterHistory) spark(id string) []uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]uint64(nil), h.hist[id]...)
}

func (h *counterHistory) lastHit(id string) time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last[id]
}

var sdnCounterHist = newCounterHistory()

// StartSDNCounterSampler samples rule counters every 5 minutes for the
// rules' 24 h sparklines. Cheap no-op while the feature's table is absent.
func StartSDNCounterSampler() {
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			if !SDNPackagesInstalled() {
				continue
			}
			out, err := sdnRun.Run(nil, "nft", "-j", "list", "table", "ip", sdn.TableName)
			if err != nil {
				continue
			}
			if m, err := parseNftCounters(out); err == nil {
				sdnCounterHist.observe(m)
			}
		}
	}()
}

// SDNDeviceNames lists the kernel network devices (except lo), cheaply —
// for the import device-mapping step.
func SDNDeviceNames() []string {
	entries, _ := os.ReadDir(sdnSysClassNet)
	var out []string
	for _, e := range entries {
		if e.Name() != "lo" {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func incusHas(m map[string]string, k string) bool { _, ok := m[k]; return ok }

// BlockedElem is one element of the blk set: packets from one source, on
// one protocol/port, entering one interface, dropped by one rule (0 =
// default deny), since the element appeared (it expires after 15 min idle).
type BlockedElem struct {
	Src     string `json:"src"`
	Proto   string `json:"proto"`
	Port    uint16 `json:"port"`
	Iface   string `json:"iface"`
	Rule    int    `json:"rule"`
	Packets uint64 `json:"packets"`
}

// SDNBlockedSample reads the blocked-attempt counters.
func SDNBlockedSample() ([]BlockedElem, error) {
	out, err := sdnRun.Run(nil, "nft", "-j", "list", "set", "ip", sdn.TableName, "blk")
	if err != nil {
		return nil, err
	}
	return parseBlockedSet(out)
}

func parseBlockedSet(b []byte) ([]BlockedElem, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []struct {
					Elem struct {
						Val struct {
							Concat []any `json:"concat"`
						} `json:"val"`
						Counter struct{ Packets uint64 } `json:"counter"`
					} `json:"elem"`
				} `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []BlockedElem
	for _, it := range doc.Nftables {
		if it.Set == nil {
			continue
		}
		for _, e := range it.Set.Elem {
			c := e.Elem.Val.Concat
			if len(c) != 5 {
				continue
			}
			be := BlockedElem{Packets: e.Elem.Counter.Packets}
			be.Src, _ = c[0].(string)
			be.Proto, _ = c[1].(string)
			if f, ok := c[2].(float64); ok {
				be.Port = uint16(f)
			}
			be.Iface, _ = c[3].(string)
			if f, ok := c[4].(float64); ok {
				be.Rule = int(f)
			}
			out = append(out, be)
		}
	}
	return out, nil
}
