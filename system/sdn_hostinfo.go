package system

// Everything known about one inside address, for the hover card of the
// Firewall tables: names, MAC and its maker, network, DHCP, VM or container,
// where the Firewall's configuration uses it, its traffic, DNS and IDS alerts.

import (
	"encoding/json"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"time"

	"zfsnas/internal/oui"
	"zfsnas/internal/sdn"
	"zfsnas/internal/traffic"
)

// SDNHostNet is the network an address belongs to.
type SDNHostNet struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name"`
	Color  string `json:"color,omitempty"`
	CIDR   string `json:"cidr,omitempty"`
	Device string `json:"device,omitempty"`
	Kind   string `json:"kind,omitempty"`
	Role   string `json:"role,omitempty"`
	VLAN   int    `json:"vlan,omitempty"`
}

// SDNHostDHCP is the address' DHCP state.
type SDNHostDHCP struct {
	Hostname    string    `json:"hostname,omitempty"`
	Expires     time.Time `json:"expires,omitzero"`
	Leased      bool      `json:"leased"`
	Reserved    bool      `json:"reserved"`
	Description string    `json:"description,omitempty"`
	InPool      bool      `json:"in_pool"`
	Server      string    `json:"server,omitempty"` // "Firewall" | "Incus"
}

// SDNHostInstance is the VM or container using the address.
type SDNHostInstance struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Status  string `json:"status"`
	OS      string `json:"os,omitempty"`
	CPU     string `json:"cpu,omitempty"`
	Memory  string `json:"memory,omitempty"`
	Project string `json:"project,omitempty"`
	mac     string // of the card holding the address
}

// SDNHostForward is a port forward reaching the address.
type SDNHostForward struct {
	Proto       string `json:"proto"`
	Public      string `json:"public"`
	Target      string `json:"target"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// SDNHostRule is a firewall rule naming the address or one of its groups.
type SDNHostRule struct {
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// SDNHostConn is one open connection of the address.
type SDNHostConn struct {
	Peer     string `json:"peer"`
	Port     uint16 `json:"port,omitempty"`
	Proto    string `json:"proto,omitempty"`
	Dir      string `json:"dir"` // in | out | internal
	CC       string `json:"cc,omitempty"`
	City     string `json:"city,omitempty"`
	Org      string `json:"org,omitempty"`
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
}

// SDNHostLive is what changes by the second.
type SDNHostLive struct {
	Ready     bool          `json:"ready"` // rates exist (not the first look)
	DownBps   int64         `json:"down_bps"`
	UpBps     int64         `json:"up_bps"`
	PeakDown  int64         `json:"peak_down_bps"`
	PeakUp    int64         `json:"peak_up_bps"`
	SparkDown []int64       `json:"spark_down"`
	SparkUp   []int64       `json:"spark_up"`
	Conns     int           `json:"conns"`
	TCP       int           `json:"tcp"`
	UDP       int           `json:"udp"`
	Top       []SDNHostConn `json:"top"`
}

// SDNHostPeer is a place the address exchanged traffic with.
type SDNHostPeer struct {
	Remote string `json:"remote"`
	CC     string `json:"cc,omitempty"`
	City   string `json:"city,omitempty"`
	Org    string `json:"org,omitempty"`
	Bytes  uint64 `json:"bytes"`
}

// SDNHostTraffic sums the saved statistics over the last 24 hours.
type SDNHostTraffic struct {
	BytesIn  uint64        `json:"bytes_in"`
	BytesOut uint64        `json:"bytes_out"`
	Sessions uint64        `json:"sessions"`
	Remotes  int           `json:"remotes"`
	Last     time.Time     `json:"last,omitzero"`
	Top      []SDNHostPeer `json:"top"`
}

// SDNHostDNS sums the address' recent lookups (the query log is a ring).
type SDNHostDNS struct {
	Queries int           `json:"queries"`
	Blocked int           `json:"blocked"`
	Last    int64         `json:"last,omitempty"`
	First   int64         `json:"first,omitempty"`
	Top     []SDNDNSCount `json:"top"`
}

// SDNHostAlert is one IDS alert of the address.
type SDNHostAlert struct {
	Signature string    `json:"signature"`
	Severity  int       `json:"severity"`
	Count     int64     `json:"count"`
	Last      time.Time `json:"last"`
}

// SDNHostIDS sums the last 7 days of alerts.
type SDNHostIDS struct {
	Alerts int64          `json:"alerts"`
	High   int64          `json:"high"`
	Top    []SDNHostAlert `json:"top"`
}

// SDNHostInfo is the whole card.
type SDNHostInfo struct {
	IP         string `json:"ip"`
	Name       string `json:"name,omitempty"`
	FQDN       string `json:"fqdn,omitempty"`
	Role       string `json:"role"` // this-server | gateway | instance | vpn | device
	MAC        string `json:"mac,omitempty"`
	MACSource  string `json:"mac_source,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	MACPrivate bool   `json:"mac_private,omitempty"`
	// MACHypervisor: a VM or container's MAC prefix, and no instance of this
	// server has it: the card asks the InterLink peers (/api/sdn/hostinfo/owner).
	MACHypervisor bool             `json:"mac_hypervisor,omitempty"`
	State         string           `json:"state,omitempty"` // REACHABLE, STALE… from the neighbour table
	Device        string           `json:"device,omitempty"`
	Via           string           `json:"via,omitempty"` // router it is reached through
	Network       *SDNHostNet      `json:"network,omitempty"`
	DHCP          *SDNHostDHCP     `json:"dhcp,omitempty"`
	Instance      *SDNHostInstance `json:"instance,omitempty"`
	VPNPeer       string           `json:"vpn_peer,omitempty"`
	VirtualIP     bool             `json:"virtual_ip,omitempty"`
	Groups        []string         `json:"groups"`
	DNSNames      []string         `json:"dns_names"`
	Forwards      []SDNHostForward `json:"forwards"`
	Rules         []SDNHostRule    `json:"rules"`
	Live          SDNHostLive      `json:"live"`
	Traffic       SDNHostTraffic   `json:"traffic"`
	DNS           SDNHostDNS       `json:"dns"`
	IDS           SDNHostIDS       `json:"ids"`
}

// Hooks (tests replace them). Neither needs root.
var (
	sdnHostIPJSON = func(args ...string) []byte {
		out, err := exec.Command("ip", append([]string{"-j"}, args...)...).Output()
		if err != nil {
			return nil
		}
		return out
	}
	sdnHostInstanceOf = func(name, addr string) *SDNHostInstance {
		if !IncusUsable() {
			return nil
		}
		out, err := exec.Command("incus", "list", "^"+name+"$", "--format", "json").Output()
		if err != nil {
			return nil
		}
		return parseHostInstance(out, addr)
	}
)

func parseHostInstance(b []byte, addr string) *SDNHostInstance {
	var list []struct {
		Name    string            `json:"name"`
		Type    string            `json:"type"`
		Status  string            `json:"status"`
		Project string            `json:"project"`
		Config  map[string]string `json:"expanded_config"`
		State   struct {
			Network map[string]lxdStateNetwork `json:"network"`
		} `json:"state"`
	}
	if json.Unmarshal(b, &list) != nil || len(list) == 0 {
		return nil
	}
	in := list[0]
	h := &SDNHostInstance{Name: in.Name, Type: in.Type, Status: in.Status, Project: in.Project, CPU: in.Config["limits.cpu"], Memory: in.Config["limits.memory"]}
	h.OS = strings.TrimSpace(in.Config["image.os"] + " " + in.Config["image.release"])
	if h.OS == "" {
		h.OS = in.Config["image.description"]
	}
	for _, n := range in.State.Network {
		for _, a := range n.Addresses {
			if a.Address == addr {
				h.mac = n.HWAddr
			}
		}
	}
	return h
}

// sdnHostContains: a member or rule value ("a.b.c.d", CIDR, "first-last")
// covers the address.
func sdnHostContains(v string, a netip.Addr) bool {
	if x, err := netip.ParseAddr(v); err == nil {
		return x == a
	}
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Masked().Contains(a)
	}
	if f, l, ok := strings.Cut(v, "-"); ok {
		x, e1 := netip.ParseAddr(strings.TrimSpace(f))
		y, e2 := netip.ParseAddr(strings.TrimSpace(l))
		return e1 == nil && e2 == nil && x.Compare(a) <= 0 && a.Compare(y) <= 0
	}
	return false
}

func sdnHostNetOf(in sdn.Interface, cidr string) *SDNHostNet {
	return &SDNHostNet{ID: in.ID, Name: in.Name, Color: in.Color, CIDR: cidr, Device: in.L3Device(), Kind: in.Kind, Role: in.Role, VLAN: in.VLANTag}
}

// SDNHostInfoFor gathers the card of one address.
func SDNHostInfoFor(c *sdn.Config, a netip.Addr, now time.Time) SDNHostInfo {
	s := a.String()
	h := SDNHostInfo{IP: s, Role: "device", Groups: []string{}, DNSNames: []string{}, Forwards: []SDNHostForward{}, Rules: []SDNHostRule{}}
	known := SDNHostNames(c, []string{s}, now)[s]
	h.Name, h.FQDN = known.Name, known.FQDN
	local := sdnIDSLocal(a)
	if local {
		h.Role = "this-server"
	}
	sdnHostFillConfig(c, a, &h)
	sdnHostFillLease(c, a, &h)
	sdnHostFillInstance(a, &h)
	sdnHostFillNeighbour(c, a, &h)
	if local {
		if dev := sdnTC.env().IfaceOf(a); dev != "" {
			h.Device = dev
			if h.MAC == "" {
				h.MAC, h.MACSource = readSysTrim(dev, "address"), "This server's network port"
			}
		}
	}
	if h.MAC == "" {
		sdnHostFillIncusLease(a, &h)
	}
	if h.MAC != "" {
		h.MAC = strings.ToLower(h.MAC)
		h.Vendor, h.MACPrivate = oui.Vendor(h.MAC), oui.Private(h.MAC)
		if h.Instance == nil && oui.Hypervisor(h.MAC) {
			if o := LXDInstanceByMAC(h.MAC); o != nil {
				h.Instance = &SDNHostInstance{Name: o.Name, Type: o.Type, Status: o.Status, OS: o.OS, CPU: o.CPU, Memory: o.Memory}
				if h.Role == "device" {
					h.Role = "instance"
				}
				if h.Name == "" {
					h.Name = o.Name
				}
			} else if !local {
				h.MACHypervisor = true
			}
		}
	}
	if lname, fq := sdnLocalNames(c)(s); h.Name == "" || (h.FQDN == "" && fq != "") {
		if h.Name == "" {
			h.Name = lname
		}
		if h.FQDN == "" {
			h.FQDN = fq
		}
	}
	h.Live = SDNHostLiveNow(a, now)
	h.Traffic = sdnHostTraffic(s, now)
	h.DNS = sdnHostDNS(s)
	h.IDS = sdnHostIDS(s, now)
	return h
}

func sdnHostFillConfig(c *sdn.Config, a netip.Addr, h *SDNHostInfo) {
	s := a.String()
	for _, in := range c.Interfaces {
		if p, err := netip.ParsePrefix(in.IPv4); err == nil && p.Masked().Contains(a) {
			h.Network = sdnHostNetOf(in, p.Masked().String())
			if p.Addr() == a && h.Role == "device" {
				h.Role = "gateway"
			}
		}
		for _, v := range in.VirtualIPs {
			if v.Address == s {
				h.VirtualIP = true
				if h.Role == "device" {
					h.Role = "gateway"
				}
			}
		}
	}
	for _, g := range c.Groups {
		if g.Kind != "hosts" {
			continue
		}
		for _, m := range g.Members {
			if sdnHostContains(m, a) {
				h.Groups = append(h.Groups, g.Name)
				break
			}
		}
	}
	inGroup := func(id string) bool {
		for _, g := range c.Groups {
			if g.ID == id && g.Kind == "hosts" {
				for _, m := range g.Members {
					if sdnHostContains(m, a) {
						return true
					}
				}
			}
		}
		return false
	}
	names := func(e sdn.Endpoint) bool {
		return (e.Type == "cidr" && sdnHostContains(e.Value, a)) || (e.Type == "group" && inGroup(e.Value))
	}
	for _, r := range c.Rules {
		if names(r.Source) || names(r.Destination) {
			h.Rules = append(h.Rules, SDNHostRule{Action: r.Action, Description: r.Description, Enabled: r.Enabled})
		}
	}
	for _, f := range c.PortForwards {
		if f.Target == s {
			h.Forwards = append(h.Forwards, SDNHostForward{Proto: f.Protocol, Public: f.PubPorts, Target: f.TargetPorts, Description: f.Description, Enabled: f.Enabled})
		}
	}
	for _, d := range c.DNS.Hosts {
		if d.IP == s {
			h.DNSNames = append(h.DNSNames, d.Name)
		}
	}
	for _, p := range c.WGPeers {
		for _, ip := range p.AllowedIPs {
			if sdnHostContains(ip, a) {
				h.VPNPeer = p.Name
				if h.Role == "device" {
					h.Role = "vpn"
				}
				if h.Name == "" {
					h.Name = p.Name
				}
			}
		}
	}
}

func sdnHostFillLease(c *sdn.Config, a netip.Addr, h *SDNHostInfo) {
	s := a.String()
	var d SDNHostDHCP
	for _, srv := range c.DHCP {
		first, e1 := netip.ParseAddr(srv.RangeStart)
		last, e2 := netip.ParseAddr(srv.RangeEnd)
		if srv.Enabled && e1 == nil && e2 == nil && first.Compare(a) <= 0 && a.Compare(last) <= 0 {
			d.InPool, d.Server = true, "Firewall"
		}
		for _, r := range srv.Reservations {
			if r.IP == s {
				d.Reserved, d.Hostname, d.Description, d.Server = true, r.Hostname, r.Description, "Firewall"
				h.MAC, h.MACSource = r.MAC, "DHCP reservation"
			}
		}
	}
	for _, l := range SDNDHCPLeases(c) {
		if l.IP == s {
			d.Leased, d.Expires, d.Server = true, l.Expires, "Firewall"
			if l.Hostname != "" {
				d.Hostname = l.Hostname
			}
			h.MAC, h.MACSource = l.MAC, "DHCP lease"
		}
	}
	if d.Leased || d.Reserved || d.InPool {
		h.DHCP = &d
	}
}

func sdnHostFillInstance(a netip.Addr, h *SDNHostInfo) {
	sdnTC.mu.Lock()
	name := sdnTC.names[a]
	sdnTC.mu.Unlock()
	if name == "" {
		return
	}
	h.Instance = sdnHostInstanceOf(name, a.String())
	if h.Instance == nil {
		h.Instance = &SDNHostInstance{Name: name}
	}
	if h.Instance.mac != "" {
		h.MAC, h.MACSource = h.Instance.mac, "VM or container settings"
	}
	if h.Role == "device" {
		h.Role = "instance"
	}
	if h.Name == "" {
		h.Name = name
	}
}

// sdnHostFillNeighbour reads the kernel: how the address is reached and, on a
// network of this server, the MAC that answers for it right now.
func sdnHostFillNeighbour(c *sdn.Config, a netip.Addr, h *SDNHostInfo) {
	s := a.String()
	var routes []struct {
		Dev     string `json:"dev"`
		Gateway string `json:"gateway"`
	}
	if json.Unmarshal(sdnHostIPJSON("route", "get", s), &routes) == nil && len(routes) > 0 {
		h.Device, h.Via = routes[0].Dev, routes[0].Gateway
	}
	if h.Network == nil && h.Device != "" {
		for _, in := range c.Interfaces {
			if in.L3Device() == h.Device || in.Device == h.Device {
				h.Network = sdnHostNetOf(in, "")
			}
		}
	}
	if h.Network == nil && h.Device != "" {
		h.Network = &SDNHostNet{Name: h.Device, Device: h.Device}
	}
	var neigh []struct {
		Dev    string   `json:"dev"`
		LLAddr string   `json:"lladdr"`
		State  []string `json:"state"`
	}
	if json.Unmarshal(sdnHostIPJSON("neigh", "show", s), &neigh) != nil {
		return
	}
	for _, n := range neigh {
		if len(n.State) > 0 {
			h.State = n.State[0]
		}
		if n.LLAddr != "" {
			h.MAC, h.Device = n.LLAddr, n.Dev
			h.MACSource = "Seen on the network"
			return
		}
	}
}

func sdnHostFillIncusLease(a netip.Addr, h *SDNHostInfo) {
	for _, n := range SDNIncusNetworks() {
		for _, l := range n.Leases {
			if l.Address == a.String() {
				h.MAC, h.MACSource = l.MAC, "Incus DHCP"
				if h.Network == nil || h.Network.CIDR == "" {
					h.Network = &SDNHostNet{Name: n.Name, Device: n.Name, CIDR: n.Address, Kind: "incus"}
				}
				if h.DHCP == nil {
					h.DHCP = &SDNHostDHCP{Leased: true, Hostname: l.Hostname, Server: "Incus", Reserved: l.Type == "static"}
				}
				if h.Name == "" {
					h.Name = l.Hostname
				}
				return
			}
		}
	}
}

// SDNHostLiveNow reads the address' open connections and current rates.
func SDNHostLiveNow(a netip.Addr, now time.Time) SDNHostLive {
	s := a.String()
	l := SDNHostLive{SparkDown: []int64{}, SparkUp: []int64{}, Top: []SDNHostConn{}}
	sdnTalk.Lock()
	sdnTalkersSample(now)
	l.Ready = sdnTalk.t.Ready()
	t, ok := sdnTalk.t.Host(s, sdnIDSLocal(a))
	sdnTalk.Unlock()
	if ok {
		l.DownBps, l.UpBps, l.PeakDown, l.PeakUp = t.DownBps, t.UpBps, t.PeakDownBps, t.PeakUpBps
		if t.SparkDown != nil {
			l.SparkDown, l.SparkUp = t.SparkDown, t.SparkUp
		}
	}
	conns, err := SDNLiveConnections(0)
	if err != nil {
		return l
	}
	for _, c := range conns { // biggest first
		if c.Inside != s && c.Src != s && c.Dst != s {
			continue
		}
		l.Conns++
		switch c.Proto {
		case "tcp":
			l.TCP++
		case "udp":
			l.UDP++
		}
		if len(l.Top) >= 6 {
			continue
		}
		hc := SDNHostConn{Proto: c.Proto, CC: c.CC, City: c.City, Org: c.ASOrg, BytesIn: c.BytesIn, BytesOut: c.BytesOut, Peer: c.Remote, Port: c.Dport, Dir: c.Dir}
		if c.Dir == "in" {
			hc.Port = c.Port
		}
		if c.Initiator == "internal" {
			hc.Dir, hc.Peer = "internal", c.Dst
			if c.Dst == s {
				hc.Peer = c.Src
			}
		}
		l.Top = append(l.Top, hc)
	}
	return l
}

func sdnHostTraffic(ip string, now time.Time) SDNHostTraffic {
	t := SDNHostTraffic{Top: []SDNHostPeer{}}
	res := SDNTrafficQuery(traffic.Query{From: now.Add(-24 * time.Hour), To: now.Add(time.Minute), Dir: "all", Group: "ip", Inside: ip, Limit: 500})
	t.Remotes = res.Total
	for _, r := range res.Rows {
		t.BytesIn += r.BytesIn
		t.BytesOut += r.BytesOut
		t.Sessions += r.Sessions
		if r.Last.After(t.Last) {
			t.Last = r.Last
		}
		if r.Remote != "" && len(t.Top) < 5 {
			t.Top = append(t.Top, SDNHostPeer{Remote: r.Remote, CC: r.CC, City: r.City, Org: r.ASOrg, Bytes: r.BytesIn + r.BytesOut})
		}
	}
	return t
}

func sdnHostDNS(ip string) SDNHostDNS {
	d := SDNHostDNS{Top: []SDNDNSCount{}}
	qs := SDNDNSQueries("", ip, "", 0, 2000) // newest first
	domains := map[string]int{}
	for _, q := range qs {
		d.Queries++
		if q.Status == "blocked" {
			d.Blocked++
		}
		domains[q.Domain]++
	}
	if len(qs) > 0 {
		d.Last, d.First = qs[0].T, qs[len(qs)-1].T
		d.Top = topN(domains, 5)
	}
	return d
}

func sdnHostIDS(ip string, now time.Time) SDNHostIDS {
	d := SDNHostIDS{Top: []SDNHostAlert{}}
	st := SDNIDSStore()
	if st == nil {
		return d
	}
	var hits []SDNHostAlert
	for _, g := range st.List(now.Add(-7 * 24 * time.Hour)) {
		if g.Src != ip && g.Dst != ip && g.SrcInside != ip && g.DstInside != ip {
			continue
		}
		d.Alerts += g.Count
		if g.Severity == 1 {
			d.High += g.Count
		}
		hits = append(hits, SDNHostAlert{Signature: g.Signature, Severity: g.Severity, Count: g.Count, Last: g.Last})
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Last.After(hits[j].Last) })
	if len(hits) > 3 {
		hits = hits[:3]
	}
	if hits != nil {
		d.Top = hits
	}
	return d
}
