package system

// Everything about the networks this Firewall manages, in one answer, for the
// Monitor → Local Topo dashboard: uplinks, networks and every host seen on
// them, merged by address and MAC from the DHCP leases and reservations, the
// kernel's neighbour table, VMs and containers, WireGuard peers and the live
// connection table.

import (
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/oui"
	"zfsnas/internal/sdn"
)

// SDNTopoHost is one machine on a network.
type SDNTopoHost struct {
	IP         string    `json:"ip,omitempty"` // "" = a stopped VM or container
	Name       string    `json:"name,omitempty"`
	Kind       string    `json:"kind"` // this-server | vip | router | vm | container | vpn | device
	MAC        string    `json:"mac,omitempty"`
	Vendor     string    `json:"vendor,omitempty"`
	MACPrivate bool      `json:"mac_private,omitempty"`
	Port       string    `json:"port,omitempty"` // bridge port the MAC was learned on
	Status     string    `json:"status"`         // online | idle | offline | unknown
	Addressing string    `json:"addressing"`     // reserved | lease | incus | static | vpn | self
	Expires    time.Time `json:"expires,omitzero"`
	Note       string    `json:"note,omitempty"`
	// VM or container
	InstStatus string `json:"inst_status,omitempty"`
	CPU        string `json:"cpu,omitempty"`
	Memory     string `json:"memory,omitempty"`
	OS         string `json:"os,omitempty"`
	// VPN client
	Endpoint  string    `json:"endpoint,omitempty"`
	Country   string    `json:"country,omitempty"`
	Handshake time.Time `json:"handshake,omitzero"`
	Networks  []string  `json:"networks,omitempty"` // behind the peer
	// Activity
	DownBps    int64  `json:"down_bps"`
	UpBps      int64  `json:"up_bps"`
	Conns      int    `json:"conns"`
	Bytes24h   uint64 `json:"bytes_24h"`
	DNSQueries int    `json:"dns_queries"`
	DNSBlocked int    `json:"dns_blocked"`
	IDSAlerts  int64  `json:"ids_alerts"`
	IDSHigh    int64  `json:"ids_high"`
	Forwards   int    `json:"forwards"`
}

// SDNTopoPort is a port of a network's bridge.
type SDNTopoPort struct {
	Name      string `json:"name"`
	Virtual   bool   `json:"virtual"`
	State     string `json:"state,omitempty"`
	SpeedMbps int    `json:"speed_mbps,omitempty"`
}

// SDNTopoDHCP is the network's DHCP service.
type SDNTopoDHCP struct {
	Server       string          `json:"server"` // Firewall | Incus
	Enabled      bool            `json:"enabled"`
	Range        string          `json:"range,omitempty"`
	PoolSize     int             `json:"pool_size"`
	PoolUsed     int             `json:"pool_used"`
	Reservations int             `json:"reservations"`
	LeaseHours   int             `json:"lease_hours,omitempty"`
	Gateway      string          `json:"gateway,omitempty"`
	DNS          []string        `json:"dns,omitempty"`
	Domain       string          `json:"domain,omitempty"`
	Routes       []sdn.DHCPRoute `json:"routes,omitempty"`
	Stopped      bool            `json:"stopped,omitempty"` // enabled, and its server says it is not running
	Error        string          `json:"error,omitempty"`
}

// SDNTopoPolicy sums the filter rules of a network.
type SDNTopoPolicy struct {
	Allow int      `json:"allow"`
	Block int      `json:"block"`
	Off   int      `json:"off"`
	Lines []string `json:"lines"` // "allow|description", first rules in order
}

// SDNTopoForward is a port forward into the network.
type SDNTopoForward struct {
	Proto       string `json:"proto"`
	Public      string `json:"public"`
	Target      string `json:"target"`
	TargetPorts string `json:"target_ports,omitempty"`
	Description string `json:"description,omitempty"`
	Active      bool   `json:"active"`
}

// SDNTopoNet is one inside network.
type SDNTopoNet struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Color    string           `json:"color,omitempty"`
	Kind     string           `json:"kind"`
	Device   string           `json:"device"`
	L3       string           `json:"l3"`
	Parent   string           `json:"parent,omitempty"`
	VLAN     int              `json:"vlan,omitempty"`
	CIDR     string           `json:"cidr,omitempty"`
	Address  string           `json:"address,omitempty"`
	VIPs     []string         `json:"vips,omitempty"`
	Disabled bool             `json:"disabled,omitempty"`
	State    string           `json:"state,omitempty"`
	MTU      int              `json:"mtu,omitempty"`
	Speed    int              `json:"speed_mbps,omitempty"`
	RxBits   int64            `json:"rx_bits"`
	TxBits   int64            `json:"tx_bits"`
	Ports    []SDNTopoPort    `json:"ports"`
	DHCP     *SDNTopoDHCP     `json:"dhcp,omitempty"`
	Policy   SDNTopoPolicy    `json:"policy"`
	Forwards []SDNTopoForward `json:"forwards"`
	Hosts    []SDNTopoHost    `json:"hosts"`
}

// SDNTopoGateway is a gateway on an uplink.
type SDNTopoGateway struct {
	Name      string  `json:"name"`
	Up        bool    `json:"up"`
	Active    bool    `json:"active"`
	Monitor   bool    `json:"monitor"`
	RTTms     float64 `json:"rtt_ms"`
	Loss      int     `json:"loss"`
	Target    string  `json:"target,omitempty"`
	GatewayIP string  `json:"gateway_ip,omitempty"`
}

// SDNTopoUplink is an Internet link.
type SDNTopoUplink struct {
	Name     string           `json:"name"`
	Color    string           `json:"color,omitempty"`
	Kind     string           `json:"kind"`
	Device   string           `json:"device"`
	Parent   string           `json:"parent,omitempty"`
	Address  string           `json:"address,omitempty"`
	State    string           `json:"state,omitempty"`
	Speed    int              `json:"speed_mbps,omitempty"`
	Disabled bool             `json:"disabled,omitempty"`
	RxBits   int64            `json:"rx_bits"`
	TxBits   int64            `json:"tx_bits"`
	Gateways []SDNTopoGateway `json:"gateways"`
}

// SDNTopoRoute is a local route.
type SDNTopoRoute struct {
	Destination string `json:"destination"`
	Via         string `json:"via,omitempty"`
	Network     string `json:"network,omitempty"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// SDNTopology is the whole dashboard.
type SDNTopology struct {
	At          time.Time       `json:"at"`
	Host        string          `json:"host"`
	Mode        string          `json:"mode"`
	OutboundNAT string          `json:"outbound_nat"`
	DNSRunning  bool            `json:"dns_running"`
	DNSDomain   string          `json:"dns_domain,omitempty"`
	IDSEnabled  bool            `json:"ids_enabled"`
	AnyRules    SDNTopoPolicy   `json:"any_rules"`
	Ready       bool            `json:"ready"` // live rates exist (not the first look)
	DownBps     int64           `json:"down_bps"`
	UpBps       int64           `json:"up_bps"`
	Uplinks     []SDNTopoUplink `json:"uplinks"`
	Networks    []SDNTopoNet    `json:"networks"`
	Routes      []SDNTopoRoute  `json:"routes"`
}

// sdnTopoInstance is a VM or container with its cards.
type sdnTopoInstance struct {
	Name, Type, Status, CPU, Memory, OS string
	NICs                                []sdnTopoNIC
}
type sdnTopoNIC struct {
	Name, MAC, Bridge string
	IPs               []string
}

// sdnTopoNeigh is one line of the kernel's neighbour table.
type sdnTopoNeigh struct {
	Dst    string   `json:"dst"`
	Dev    string   `json:"dev"`
	LLAddr string   `json:"lladdr"`
	State  []string `json:"state"`
}

// Hooks (tests replace them).
var (
	sdnTopoInstancesRaw = func() []byte {
		if !IncusUsable() {
			return nil
		}
		out, err := exec.Command("incus", "list", "--format", "json").Output()
		if err != nil {
			return nil
		}
		return out
	}
	sdnTopoFDBRaw = func(bridge string) []byte {
		out, err := exec.Command("bridge", "-j", "fdb", "show", "br", bridge).Output()
		if err != nil {
			return nil
		}
		return out
	}
	sdnTopoBridgePorts = func(dev string) []string {
		ents, err := os.ReadDir(filepath.Join("/sys/class/net", dev, "brif"))
		if err != nil {
			return nil
		}
		ports := []string{}
		for _, e := range ents {
			ports = append(ports, e.Name())
		}
		return ports
	}
	sdnTopoNow = time.Now
)

func parseTopoInstances(b []byte) []sdnTopoInstance {
	var raw []struct {
		Name    string                       `json:"name"`
		Type    string                       `json:"type"`
		Status  string                       `json:"status"`
		Config  map[string]string            `json:"expanded_config"`
		Devices map[string]map[string]string `json:"expanded_devices"`
		State   *struct {
			Network map[string]lxdStateNetwork `json:"network"`
		} `json:"state"`
	}
	if json.Unmarshal(b, &raw) != nil {
		return nil
	}
	out := []sdnTopoInstance{}
	for _, r := range raw {
		if strings.HasPrefix(r.Name, "bkup--") {
			continue
		}
		in := sdnTopoInstance{Name: r.Name, Type: r.Type, Status: r.Status, CPU: r.Config["limits.cpu"], Memory: r.Config["limits.memory"]}
		in.OS = strings.TrimSpace(r.Config["image.os"] + " " + r.Config["image.release"])
		if in.OS == "" {
			in.OS = r.Config["image.description"]
		}
		names := make([]string, 0, len(r.Devices))
		for n, d := range r.Devices {
			if d["type"] == "nic" {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			d := r.Devices[n]
			// An imported VM fixes its MAC in the device; others get a generated one.
			mac := d["hwaddr"]
			if mac == "" {
				mac = r.Config["volatile."+n+".hwaddr"]
			}
			nic := sdnTopoNIC{Name: n, MAC: strings.ToLower(mac), Bridge: d["parent"]}
			if nic.Bridge == "" {
				nic.Bridge = d["network"]
			}
			if r.State != nil {
				for _, st := range r.State.Network {
					if !strings.EqualFold(st.HWAddr, nic.MAC) || nic.MAC == "" {
						continue
					}
					for _, a := range st.Addresses {
						if a.Family == "inet" && a.Scope == "global" {
							nic.IPs = append(nic.IPs, a.Address)
						}
					}
				}
			}
			in.NICs = append(in.NICs, nic)
		}
		out = append(out, in)
	}
	return out
}

// sdnTopoFDB maps a MAC to the bridge port it was learned on.
func sdnTopoFDB(bridge string) map[string]string {
	var rows []struct {
		MAC    string   `json:"mac"`
		IfName string   `json:"ifname"`
		Master string   `json:"master"`
		State  string   `json:"state"`
		Flags  []string `json:"flags"`
	}
	out := map[string]string{}
	if json.Unmarshal(sdnTopoFDBRaw(bridge), &rows) != nil {
		return out
	}
	for _, r := range rows {
		if r.IfName == "" || r.IfName == bridge || r.State == "permanent" {
			continue
		}
		out[strings.ToLower(r.MAC)] = r.IfName
	}
	return out
}

func sdnTopoPortVirtual(dev string) bool {
	if strings.HasPrefix(dev, "tap") || strings.HasPrefix(dev, "veth") {
		return true
	}
	// A physical port (or a bond of them) has a device behind it.
	return !sysExists(dev, "device") && !sysExists(dev, "bonding") && !strings.Contains(dev, ".") && !strings.Contains(dev, "-v")
}

// sdnPolicyOf sums rules of an interface ("" = the "any interface" rules).
func sdnPolicyOf(c *sdn.Config, id string) SDNTopoPolicy {
	p := SDNTopoPolicy{Lines: []string{}}
	for _, r := range c.Rules {
		if r.Interface != id {
			continue
		}
		if !r.Enabled {
			p.Off++
			continue
		}
		if r.Action == "allow" {
			p.Allow++
		} else {
			p.Block++
		}
		if r.Description != "" && len(p.Lines) < 3 {
			p.Lines = append(p.Lines, r.Action+"|"+r.Description)
		}
	}
	return p
}

// sdnTopoUsage is what each address has been doing recently.
type sdnTopoUsage struct {
	dns     map[string][2]int   // queries, blocked
	ids     map[string][2]int64 // alerts, high severity
	talkers map[string]*struct {
		down, up int64
		conns    int
	}
}

func sdnTopoReadUsage(now time.Time) (u sdnTopoUsage, ready bool, down, up int64) {
	u.dns = map[string][2]int{}
	for _, q := range SDNDNSQueries("", "", "", 0, 5000) {
		v := u.dns[q.Client]
		v[0]++
		if q.Status == "blocked" {
			v[1]++
		}
		u.dns[q.Client] = v
	}
	u.ids = map[string][2]int64{}
	if st := SDNIDSStore(); st != nil {
		for _, g := range st.List(now.Add(-7 * 24 * time.Hour)) {
			seen := map[string]bool{}
			for _, ip := range []string{g.Src, g.Dst, g.SrcInside, g.DstInside} {
				if ip == "" || seen[ip] {
					continue
				}
				seen[ip] = true
				v := u.ids[ip]
				v[0] += g.Count
				if g.Severity == 1 {
					v[1] += g.Count
				}
				u.ids[ip] = v
			}
		}
	}
	u.talkers = map[string]*struct {
		down, up int64
		conns    int
	}{}
	sdnTalk.Lock()
	sdnTalkersSample(now)
	ready = sdnTalk.t.Ready()
	for _, t := range sdnTalk.t.Top("down", 1<<20) {
		u.talkers[t.IP] = &struct {
			down, up int64
			conns    int
		}{t.DownBps, t.UpBps, t.Conns}
	}
	down, up = sdnTalk.t.Totals()
	sdnTalk.Unlock()
	return
}

// sdnTopo24h keeps each address' last-24-hours total. Adding them up is a
// query per host, so it runs in the background, at most every two minutes.
var sdnTopo24h = struct {
	sync.Mutex
	bytes   map[string]uint64
	started time.Time
	running bool
}{bytes: map[string]uint64{}}

func sdnTopoRefresh24h(ips []string, now time.Time) {
	sdnTopo24h.Lock()
	defer sdnTopo24h.Unlock()
	if sdnTopo24h.running || now.Sub(sdnTopo24h.started) < 2*time.Minute {
		return
	}
	sdnTopo24h.running, sdnTopo24h.started = true, now
	go func() {
		m := make(map[string]uint64, len(ips))
		for _, ip := range ips {
			t := sdnHostTraffic(ip, time.Now())
			m[ip] = t.BytesIn + t.BytesOut
		}
		sdnTopo24h.Lock()
		sdnTopo24h.bytes, sdnTopo24h.running = m, false
		sdnTopo24h.Unlock()
	}()
}

var sdnTopoCache = struct {
	sync.Mutex
	at    time.Time
	value SDNTopology
}{}

// SDNTopologyNow answers from a 3-second cache: several open dashboards cost
// the same as one.
func SDNTopologyNow(c *sdn.Config) SDNTopology {
	now := sdnTopoNow()
	sdnTopoCache.Lock()
	defer sdnTopoCache.Unlock()
	if !sdnTopoCache.at.IsZero() && now.Sub(sdnTopoCache.at) < 3*time.Second {
		return sdnTopoCache.value
	}
	var inst []sdnTopoInstance
	if b := sdnTopoInstancesRaw(); b != nil {
		inst = parseTopoInstances(b)
	}
	sdnTopoCache.value, sdnTopoCache.at = buildSDNTopology(c, inst, now), now
	return sdnTopoCache.value
}

func sdnTopoLiveAddr(in sdn.Interface, l *SDNLiveIface) string {
	if in.IPv4Mode == "static" && in.IPv4 != "" {
		return in.IPv4
	}
	if l != nil && len(l.IPv4) > 0 {
		return l.IPv4[0]
	}
	return in.IPv4
}

func buildSDNTopology(c *sdn.Config, inst []sdnTopoInstance, now time.Time) SDNTopology {
	t := SDNTopology{At: now, Mode: c.Settings.Mode, OutboundNAT: c.Settings.OutboundNAT, DNSDomain: c.DNS.Domain,
		IDSEnabled: c.IDS.Enabled, AnyRules: sdnPolicyOf(c, ""), Uplinks: []SDNTopoUplink{}, Networks: []SDNTopoNet{}, Routes: []SDNTopoRoute{}}
	t.Host, _ = os.Hostname()
	active, _ := sdnRun.Run(nil, "systemctl", "is-active", sdnDNSUnitName)
	t.DNSRunning = strings.TrimSpace(string(active)) == "active"

	liveList, _ := SDNLiveInterfaces("")
	live := map[string]*SDNLiveIface{}
	for i := range liveList {
		live[liveList[i].Device] = &liveList[i]
	}
	usage, ready, down, up := sdnTopoReadUsage(now)
	t.Ready, t.DownBps, t.UpBps = ready, down, up

	gw := SDNGatewayState()
	var neigh []sdnTopoNeigh
	_ = json.Unmarshal(sdnHostIPJSON("neigh", "show"), &neigh)
	leases := SDNDHCPLeases(c)
	wgStatus := SDNWireGuardStatus(c)
	incusNets := map[string]SDNIncusNet{}
	if IncusUsable() {
		for _, n := range SDNIncusNetworks() {
			incusNets[n.Name] = n
		}
	}
	routers := map[string]string{} // next hop → description of what it leads to
	for _, r := range c.Routes {
		dest := SDNTopoRoute{Destination: r.Destination, Via: r.Via, Description: r.Description, Enabled: r.Enabled}
		if in := c.InterfaceByID(r.Interface); in != nil {
			dest.Network = in.Name
		}
		t.Routes = append(t.Routes, dest)
		if r.Via != "" && r.Enabled {
			routers[r.Via] = "Router to " + r.Destination
		}
	}
	localName := sdnLocalNames(c)
	dhcpStatus, dhcpBinary := SDNDHCPStatus()

	for _, in := range c.Interfaces {
		l := live[in.L3Device()]
		if l == nil {
			l = live[in.Device]
		}
		if in.Role == "wan" {
			u := SDNTopoUplink{Name: in.Name, Color: in.Color, Kind: in.Kind, Device: in.Device, Parent: in.Parent, Disabled: in.Disabled, Gateways: []SDNTopoGateway{}}
			u.Address = sdnTopoLiveAddr(in, l)
			if l != nil {
				u.State, u.Speed, u.RxBits, u.TxBits = l.State, l.SpeedMbps, l.RxBps*8, l.TxBps*8
			}
			for _, g := range c.Gateways {
				if g.Interface != in.ID {
					continue
				}
				x := SDNTopoGateway{Name: g.Name, Monitor: g.Monitor, Up: true}
				for _, s := range gw.Gateways {
					if s.ID == g.ID {
						x.Up, x.Active, x.RTTms, x.Loss, x.Target, x.GatewayIP = s.Up, s.Active, s.RTTms, s.Loss, s.Target, s.GatewayIP
					}
				}
				u.Gateways = append(u.Gateways, x)
			}
			t.Uplinks = append(t.Uplinks, u)
			continue
		}
		n := sdnTopoBuildNet(c, in, l, live, leases, neigh, inst, wgStatus[in.ID], incusNets[in.Device], routers, usage, localName)
		if st, ok := dhcpStatus[in.ID]; ok && dhcpBinary != "" && n.DHCP != nil && n.DHCP.Server == "Firewall" && n.DHCP.Enabled && !st.Running {
			n.DHCP.Stopped, n.DHCP.Error = true, st.Error
		}
		t.Networks = append(t.Networks, n)
	}
	sort.SliceStable(t.Networks, func(i, j int) bool {
		a, b := t.Networks[i], t.Networks[j]
		wa, wb := a.Kind == "wireguard", b.Kind == "wireguard"
		if wa != wb {
			return wb
		}
		return false
	})

	// Names from reverse DNS for what is still nameless: a few at a time, kept.
	var nameless, all []string
	for _, n := range t.Networks {
		for _, h := range n.Hosts {
			if h.IP == "" {
				continue
			}
			all = append(all, h.IP)
			if h.Name == "" {
				nameless = append(nameless, h.IP)
			}
		}
	}
	sort.Strings(nameless)
	if len(nameless) > 16 {
		start := int(now.Unix()/10) % len(nameless)
		nameless = append(nameless[start:], nameless[:start]...)[:16]
	}
	known := SDNHostNames(c, nameless, now)
	sdnTopoPTR.Lock()
	for ip, k := range known {
		if k.Name != "" {
			sdnTopoPTR.m[ip] = k.Name
		}
	}
	sdnTopo24h.Lock()
	totals := sdnTopo24h.bytes
	sdnTopo24h.Unlock()
	for i := range t.Networks {
		for j := range t.Networks[i].Hosts {
			h := &t.Networks[i].Hosts[j]
			if h.Name == "" {
				h.Name = sdnTopoPTR.m[h.IP]
			}
			h.Bytes24h = totals[h.IP]
		}
	}
	sdnTopoPTR.Unlock()
	sdnTopoRefresh24h(all, now)
	return t
}

var sdnTopoPTR = struct {
	sync.Mutex
	m map[string]string
}{m: map[string]string{}}

func sdnTopoNeighStatus(state string) string {
	switch state {
	case "REACHABLE", "DELAY", "PROBE", "PERMANENT":
		return "online"
	case "STALE":
		return "idle"
	case "FAILED", "INCOMPLETE":
		return "offline"
	}
	return "unknown"
}

func sdnTopoBuildNet(c *sdn.Config, in sdn.Interface, l *SDNLiveIface, live map[string]*SDNLiveIface, leases []SDNLease,
	neigh []sdnTopoNeigh, inst []sdnTopoInstance, wg SDNWGTunnelStatus, incus SDNIncusNet, routers map[string]string,
	usage sdnTopoUsage, localName func(string) (string, string)) SDNTopoNet {

	n := SDNTopoNet{ID: in.ID, Name: in.Name, Color: in.Color, Kind: in.Kind, Device: in.Device, L3: in.L3Device(), Parent: in.Parent,
		VLAN: in.VLANTag, Disabled: in.Disabled, Ports: []SDNTopoPort{}, Forwards: []SDNTopoForward{}, Hosts: []SDNTopoHost{}, Policy: sdnPolicyOf(c, in.ID)}
	addr := sdnTopoLiveAddr(in, l)
	pfx, perr := netip.ParsePrefix(addr)
	if perr == nil {
		n.CIDR, n.Address = pfx.Masked().String(), pfx.Addr().String()
	}
	if l != nil {
		n.State, n.MTU, n.Speed, n.RxBits, n.TxBits = l.State, l.MTU, l.SpeedMbps, l.RxBps*8, l.TxBps*8
	}
	for _, v := range in.VirtualIPs {
		n.VIPs = append(n.VIPs, v.Address)
	}
	portNames := sdnTopoBridgePorts(n.L3)
	sort.Strings(portNames)
	for _, p := range portNames {
		tp := SDNTopoPort{Name: p, Virtual: sdnTopoPortVirtual(p)}
		if pl := live[p]; pl != nil {
			tp.State, tp.SpeedMbps = pl.State, pl.SpeedMbps
		} else {
			tp.State = readSysTrim(p, "operstate")
			tp.SpeedMbps = int(readSysInt(p, "speed"))
		}
		if tp.SpeedMbps < 0 {
			tp.SpeedMbps = 0
		}
		n.Ports = append(n.Ports, tp)
	}
	fdb := map[string]string{}
	if len(portNames) > 0 {
		fdb = sdnTopoFDB(n.L3)
	}

	// Hosts, merged by address; a MAC finds the address of its VM.
	byIP := map[string]*SDNTopoHost{}
	order := []*SDNTopoHost{}
	inNet := func(ip string) bool {
		a, err := netip.ParseAddr(ip)
		return err == nil && perr == nil && pfx.Masked().Contains(a)
	}
	get := func(ip string) *SDNTopoHost {
		if h := byIP[ip]; h != nil {
			return h
		}
		h := &SDNTopoHost{IP: ip, Kind: "device", Status: "unknown", Addressing: "static"}
		byIP[ip] = h
		order = append(order, h)
		return h
	}
	if n.Address != "" {
		h := get(n.Address)
		h.Kind, h.Addressing, h.Status, h.Name = "this-server", "self", "online", "This ZNAS"
		if l != nil {
			h.MAC = strings.ToLower(l.MAC)
		}
	}
	for _, v := range in.VirtualIPs {
		h := get(v.Address)
		h.Kind, h.Addressing, h.Status, h.Note = "vip", "self", "online", v.Description
		h.Name = "Virtual IP"
		if l != nil {
			h.MAC = strings.ToLower(l.MAC)
		}
	}

	// DHCP
	if perr == nil {
		for _, d := range c.DHCP {
			if d.Interface != in.ID {
				continue
			}
			dh := &SDNTopoDHCP{Server: "Firewall", Enabled: d.Enabled, Range: d.RangeStart + " – " + d.RangeEnd, LeaseHours: d.LeaseHours,
				Gateway: d.Gateway, DNS: d.DNSServers, Domain: c.DHCPDomain(d), Routes: d.Routes, Reservations: len(d.Reservations)}
			first, e1 := netip.ParseAddr(d.RangeStart)
			last, e2 := netip.ParseAddr(d.RangeEnd)
			if e1 == nil && e2 == nil && first.Is4() && last.Is4() {
				fa, la := first.As4(), last.As4()
				dh.PoolSize = int(la[0])<<24 + int(la[1])<<16 + int(la[2])<<8 + int(la[3]) - (int(fa[0])<<24 + int(fa[1])<<16 + int(fa[2])<<8 + int(fa[3])) + 1
				if dh.PoolSize < 0 {
					dh.PoolSize = 0
				}
			}
			n.DHCP = dh
			for _, r := range d.Reservations {
				h := get(r.IP)
				h.Addressing, h.MAC, h.Note = "reserved", strings.ToLower(r.MAC), r.Description
				if r.Hostname != "" {
					h.Name = r.Hostname
				}
				if h.Kind == "device" && h.Status == "unknown" {
					h.Status = "offline"
				}
			}
			for _, x := range leases {
				a, err := netip.ParseAddr(x.IP)
				if err != nil || !inNet(x.IP) {
					continue
				}
				if e1 == nil && e2 == nil && first.Compare(a) <= 0 && a.Compare(last) <= 0 {
					dh.PoolUsed++
				}
				h := get(x.IP)
				if h.Addressing != "reserved" && h.Addressing != "self" {
					h.Addressing = "lease"
				}
				h.Expires, h.MAC = x.Expires, strings.ToLower(x.MAC)
				if x.Hostname != "" && h.Name == "" {
					h.Name = x.Hostname
				}
			}
		}
		if n.DHCP == nil && incus.DHCP {
			n.DHCP = &SDNTopoDHCP{Server: "Incus", Enabled: true, Range: strings.Join(incus.DHCPRanges, ", "), Domain: incus.Domain}
		}
		for _, x := range incus.Leases {
			if !inNet(x.Address) {
				continue
			}
			h := get(x.Address)
			if h.Addressing != "self" {
				h.Addressing = "incus"
			}
			h.MAC = strings.ToLower(x.MAC)
			if h.Name == "" {
				h.Name = x.Hostname
			}
		}
	}

	// The kernel: who is answering right now.
	for _, m := range neigh {
		if !inNet(m.Dst) {
			continue
		}
		state := ""
		if len(m.State) > 0 {
			state = m.State[0]
		}
		h := byIP[m.Dst]
		if h == nil {
			if m.LLAddr == "" {
				continue // asked for, nobody ever answered: not a host
			}
			h = get(m.Dst)
		}
		if h.Addressing != "self" {
			h.Status = sdnTopoNeighStatus(state)
		}
		if m.LLAddr != "" && h.MAC == "" {
			h.MAC = strings.ToLower(m.LLAddr)
		}
	}

	// Connections are proof of life even when the neighbour entry says little.
	for ip, tk := range usage.talkers {
		if inNet(ip) {
			h := get(ip)
			if h.Status != "online" && tk.conns > 0 && h.Addressing != "self" {
				h.Status = "online"
			}
		}
	}

	// VMs and containers
	for _, it := range inst {
		kind := "container"
		if it.Type == "virtual-machine" {
			kind = "vm"
		}
		for _, nic := range it.NICs {
			var hit []*SDNTopoHost
			for _, ip := range nic.IPs {
				if inNet(ip) {
					hit = append(hit, get(ip))
				}
			}
			if len(hit) == 0 && nic.MAC != "" {
				for _, h := range order {
					if h.MAC == nic.MAC {
						hit = append(hit, h)
					}
				}
			}
			onBridge := nic.Bridge != "" && (nic.Bridge == n.L3 || nic.Bridge == n.Device)
			if len(hit) == 0 && !onBridge {
				continue
			}
			if len(hit) == 0 {
				h := &SDNTopoHost{Kind: kind, Status: "offline", Addressing: "static", MAC: nic.MAC}
				order = append(order, h)
				hit = append(hit, h)
			}
			for _, h := range hit {
				h.Kind, h.Name, h.InstStatus, h.CPU, h.Memory, h.OS = kind, it.Name, it.Status, it.CPU, it.Memory, it.OS
				if h.MAC == "" {
					h.MAC = nic.MAC
				}
				if it.Status == "Running" {
					if h.Status != "online" && h.Status != "idle" {
						h.Status = "online"
					}
				} else {
					h.Status = "offline"
				}
			}
		}
	}

	// WireGuard peers
	if in.Kind == "wireguard" {
		for _, p := range c.WGPeers {
			if p.Tunnel != in.ID {
				continue
			}
			var h *SDNTopoHost
			nets := []string{}
			for _, a := range p.AllowedIPs {
				if x, err := netip.ParsePrefix(a); err == nil && x.Bits() == 32 && inNet(x.Addr().String()) && h == nil {
					h = get(x.Addr().String())
					continue
				}
				nets = append(nets, a)
			}
			if h == nil {
				h = &SDNTopoHost{}
				order = append(order, h)
			}
			h.Kind, h.Addressing, h.Name, h.Networks, h.Status = "vpn", "vpn", p.Name, nets, "offline"
			for _, s := range wg.Peers {
				if s.PublicKey != p.PublicKey {
					continue
				}
				h.Endpoint, h.Country, h.Handshake = s.Endpoint, s.Country, s.LastHandshake
				switch age := time.Since(s.LastHandshake); {
				case s.LastHandshake.IsZero():
				case age < 3*time.Minute:
					h.Status = "online"
				case age < 15*time.Minute:
					h.Status = "idle"
				}
			}
		}
	}

	// Port forwards
	for _, f := range c.PortForwards {
		if !inNet(f.Target) {
			continue
		}
		n.Forwards = append(n.Forwards, SDNTopoForward{Proto: f.Protocol, Public: f.PubPorts, Target: f.Target, TargetPorts: f.TargetPorts, Description: f.Description, Active: f.Active()})
		get(f.Target).Forwards++
	}

	for _, h := range order {
		if h.Kind == "device" && routers[h.IP] != "" {
			h.Kind = "router"
		}
		if routers[h.IP] != "" && h.Note == "" {
			h.Note = routers[h.IP]
		}
		if h.Name == "" && h.IP != "" {
			h.Name, _ = localName(h.IP)
		}
		if h.MAC != "" {
			h.Vendor, h.MACPrivate = oui.Vendor(h.MAC), oui.Private(h.MAC)
			h.Port = fdb[h.MAC]
		}
		if tk := usage.talkers[h.IP]; tk != nil && h.IP != "" {
			h.DownBps, h.UpBps, h.Conns = tk.down, tk.up, tk.conns
		}
		if d, ok := usage.dns[h.IP]; ok {
			h.DNSQueries, h.DNSBlocked = d[0], d[1]
		}
		if d, ok := usage.ids[h.IP]; ok {
			h.IDSAlerts, h.IDSHigh = d[0], d[1]
		}
		n.Hosts = append(n.Hosts, *h)
	}
	sort.SliceStable(n.Hosts, func(i, j int) bool {
		a, b := n.Hosts[i], n.Hosts[j]
		if (a.IP == "") != (b.IP == "") {
			return b.IP == ""
		}
		if a.IP == "" {
			return a.Name < b.Name
		}
		x, e1 := netip.ParseAddr(a.IP)
		y, e2 := netip.ParseAddr(b.IP)
		return e1 == nil && e2 == nil && x.Compare(y) < 0
	})
	return n
}
