// Package sdn holds the pure logic of the SDN (routing & firewall) feature:
// the configuration model, its validation, the nftables compiler, the
// ifupdown stanza renderer, the on-disk store (confirmed config, draft,
// history) and the single-file export. Nothing here touches the running
// system — side effects live in system/sdn*.go — so all of it is unit-tested
// without root. Spec: PLANS/spec-sdn-firewall.md.
package sdn

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"strings"
)

// Config is the whole feature configuration. The confirmed copy is what the
// kernel runs; the draft is what the admin is editing.
type Config struct {
	Version    int         `json:"version"` // schema version, 1
	Settings   Settings    `json:"settings"`
	Interfaces []Interface `json:"interfaces"`
	Groups     []Group     `json:"groups"`
	Rules      []Rule      `json:"rules"` // ordered; order = evaluation order per interface
	// Phase 3: gateways (failover order = priority), port forwards (DNAT),
	// outbound NAT rules.
	Gateways     []Gateway     `json:"gateways"`
	PortForwards []PortForward `json:"port_forwards"`
	SNATRules    []SNATRule    `json:"snat_rules"`
	// Phase 4: DHCP & DNS (dnsmasq), WireGuard peers (tunnels are
	// interfaces of kind "wireguard").
	DHCP    []DHCPServer `json:"dhcp"`
	DNS     DNSSettings  `json:"dns"`
	WGPeers []WGPeer     `json:"wg_peers"`
	// Phase 5: intrusion detection (Suricata).
	IDS IDSSettings `json:"ids"`
	// Dynamic DNS (ddclient), per gateway.
	DDNS []DDNSEntry `json:"ddns"`
	// Local routes: networks reached through a router on an inside network.
	Routes []StaticRoute `json:"routes"`
}

// StaticRoute is a local route the Firewall keeps in the main routing table.
type StaticRoute struct {
	ID          string `json:"id"`
	Enabled     bool   `json:"enabled"`
	Destination string `json:"destination"`      // network or address
	Via         string `json:"via,omitempty"`    // next hop; "" = directly on the link
	Interface   string `json:"interface"`        // interface id
	Metric      int    `json:"metric,omitempty"` // lower wins
	Description string `json:"description,omitempty"`
}

// Gateway is an Internet link. The monitor daemon pings it and moves
// traffic to the next UP gateway (by priority) when it fails.
type Gateway struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Interface string `json:"interface"`         // interface id
	Address   string `json:"address,omitempty"` // next hop; "" = dynamic (DHCP lease, PPPoE peer)
	Priority  int    `json:"priority"`          // lowest = preferred
	Monitor   bool   `json:"monitor"`
	MonitorIP string `json:"monitor_ip,omitempty"` // default: the gateway, else 1.1.1.1
	LossPct   int    `json:"loss_pct,omitempty"`   // down at ≥ this loss (default 50)
	DownSecs  int    `json:"down_secs,omitempty"`  // or no reply for this long (default 10)
	HoldSecs  int    `json:"hold_secs,omitempty"`  // healthy this long before returning (default 60)
	// One test every ProbeEvery seconds (default 2) sends ProbePings pings
	// (default 1) and fails only if none of them is answered.
	ProbeEvery int `json:"probe_every,omitempty"`
	ProbePings int `json:"probe_pings,omitempty"`
}

// PortForward is a destination NAT rule. Instance/NIC are set for forwards
// owned by a VM/container (edited from the instance editor).
type PortForward struct {
	ID          string   `json:"id"`
	Enabled     bool     `json:"enabled"`
	Interfaces  []string `json:"interfaces"` // inbound interfaces (ids); none = paused
	Protocol    string   `json:"protocol"`   // tcp | udp | tcpudp
	PubPorts    string   `json:"pub_ports"`  // "443" or "16261-16263"
	Source      Endpoint `json:"source"`     // who may use it (any, countries, groups…)
	Target      string   `json:"target"`     // inside IPv4
	TargetPorts string   `json:"target_ports"`
	Reflection  bool     `json:"reflection,omitempty"` // inside clients via the public address
	Description string   `json:"description"`
	Instance    string   `json:"instance,omitempty"`
	NIC         string   `json:"nic,omitempty"`
	TargetAuto  bool     `json:"target_auto,omitempty"` // Target looked up from the instance, not typed
}

// Paused: an instance forward nobody has published on an interface yet
// (owner: existing forwards stay disabled until an interface is chosen).
func (p PortForward) Paused() bool { return len(p.Interfaces) == 0 }

// Active: compiled into the ruleset. An instance forward whose address is
// not known yet (instance just created, no lease) waits.
func (p PortForward) Active() bool { return p.Enabled && !p.Paused() && p.Target != "" }

// SNATRule is a manual outbound NAT rule; Gateway chooses the way out.
type SNATRule struct {
	ID              string   `json:"id"`
	Enabled         bool     `json:"enabled"`
	Source          Endpoint `json:"source"`
	Destination     Endpoint `json:"destination"`
	Protocol        string   `json:"protocol"`
	DstPorts        string   `json:"dst_ports,omitempty"`
	Gateway         string   `json:"gateway"`
	OnlyThisGateway bool     `json:"only_this_gateway,omitempty"`
	Translate       string   `json:"translate"` // iface | ip | none
	TranslateIP     string   `json:"translate_ip,omitempty"`
	Description     string   `json:"description"`
}

type Settings struct {
	Mode          string `json:"mode"`           // "monitor" | "router"
	MgmtInterface string `json:"mgmt_interface"` // kernel name protected by anti-lockout
	AntiLockout   bool   `json:"anti_lockout"`
	// StatsDir holds traffic statistics and the geo databases: a pool
	// dataset (never the appliance's USB stick); "" = RAM only.
	StatsDir string `json:"stats_dir,omitempty"`
	// OutboundNAT: automatic (LAN nets masqueraded out of every WAN) |
	// hybrid (manual rules first, then automatic) | manual.
	OutboundNAT string `json:"outbound_nat,omitempty"`
}

// Interface is a network the feature routes/filters. Only VLANs are created by
// SDN (Owned); physical NICs and existing bridges are adopted.
type Interface struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Color    string `json:"color"`
	Kind     string `json:"kind"`   // "physical" | "vlan" | "bridge" (host, ifupdown) | "incus" (Incus-managed L2 bridge)
	Device   string `json:"device"` // kernel name; computed for vlan
	Parent   string `json:"parent,omitempty"`
	VLANTag  int    `json:"vlan_tag,omitempty"`
	Role     string `json:"role"`      // "wan" | "lan" | ""
	IPv4Mode string `json:"ipv4_mode"` // "static" | "dhcp" | "none"
	IPv4     string `json:"ipv4,omitempty"`
	Gateway  string `json:"gateway,omitempty"`
	MTU      int    `json:"mtu,omitempty"`
	AllowVMs bool   `json:"allow_vms"` // vlan: realized as bridge br-<device> with the vlan as port
	// BridgeDevice is the computed L3 device of an "Allow VMs" VLAN (set by
	// Normalize, read-only for the UI so it never re-derives the name).
	BridgeDevice string `json:"bridge_device,omitempty"`
	Owned        bool   `json:"owned"`
	// Disabled: the settings are kept, but the link is down and nothing runs
	// on it. Off the JSON when false: an interface is on unless told otherwise.
	Disabled bool `json:"disabled,omitempty"`
	// IncusKeep (kind "incus"): Incus keeps the network's address, DHCP and
	// DNS; the Firewall only filters and translates its traffic. IncusDHCP and
	// IncusDNS say what Incus serves there, read from Incus (sdnSyncIncusKept).
	IncusKeep bool `json:"incus_keep,omitempty"`
	IncusDHCP bool `json:"incus_dhcp,omitempty"`
	IncusDNS  bool `json:"incus_dns,omitempty"`
	// DisableForced: the admin was told what disabling it breaks and chose to
	// go on (validateDisabled). Only means something while Disabled.
	DisableForced bool `json:"disable_forced,omitempty"`
	// PPPoE (kind "pppoe", IPv4Mode "pppoe"): Parent is the port (or VLAN
	// device) the PPPoE session runs on.
	PPPoEUser        string `json:"pppoe_user,omitempty"`
	PPPoEPassword    string `json:"pppoe_password,omitempty"`
	PPPoEPasswordSet bool   `json:"pppoe_password_set,omitempty"` // API: a password is stored
	// WireGuard (kind "wireguard"): IPv4 is the tunnel address; the private
	// key is generated on this box (EnsureWGKeys).
	WGListenPort    int    `json:"wg_listen_port,omitempty"`
	WGPrivateKey    string `json:"wg_private_key,omitempty"`
	WGPrivateKeySet bool   `json:"wg_private_key_set,omitempty"` // API: a key is stored
	WGPublicKey     string `json:"wg_public_key,omitempty"`
	WGEndpoint      string `json:"wg_endpoint,omitempty"` // public name/IP clients connect to
	// Routes (computed by Normalize): networks behind the tunnel's peers.
	Routes []string `json:"routes,omitempty"`
	// Extra addresses in this interface's network that can move to another
	// server (static addressing only).
	VirtualIPs []VirtualIP `json:"virtual_ips,omitempty"`
}

// Group is a named list of hosts/networks or ports used by rules.
type Group struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"` // "hosts" | "ports"
	Members []string `json:"members"`
}

// Endpoint is a rule's source or destination.
type Endpoint struct {
	Type  string `json:"type"` // "any" | "cidr" | "group" | "iface_net" | "iface_addr" | "internal" (every non-WAN static network) | "this_znas"
	Value string `json:"value,omitempty"`
	Not   bool   `json:"not,omitempty"`
}

// Rule is one filter rule. Interface "" means "Any interface" (evaluated first).
type Rule struct {
	ID          string   `json:"id"`
	Enabled     bool     `json:"enabled"`
	Interface   string   `json:"interface"`
	Action      string   `json:"action"`   // "allow" | "block" | "reject"
	Protocol    string   `json:"protocol"` // "any" | "tcp" | "udp" | "tcpudp" | "icmp"
	Source      Endpoint `json:"source"`
	Destination Endpoint `json:"destination"`
	DstPorts    string   `json:"dst_ports,omitempty"` // "443", "80,443", "16261-16263" or "group:<id>"
	Log         bool     `json:"log"`
	Description string   `json:"description"`
	// Gateway routes matching connections out of this gateway (policy
	// routing); OnlyGateway blocks them while it is down instead of
	// following failover.
	Gateway     string `json:"gateway,omitempty"`
	OnlyGateway bool   `json:"only_gateway,omitempty"`
}

// NewID returns a random 8-character lowercase hex id.
func NewID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on Linux
	}
	return hex.EncodeToString(b)
}

// Normalize fills computed fields (VLAN device names, bridge devices).
func (c *Config) Normalize() {
	if c.Version == 0 {
		c.Version = 1
	}
	// Empty lists must reach the UI as [] (a nil slice marshals as null).
	if c.Interfaces == nil {
		c.Interfaces = []Interface{}
	}
	for i := range c.Interfaces {
		if !c.Interfaces[i].Disabled {
			c.Interfaces[i].DisableForced = false
		}
	}
	if c.Groups == nil {
		c.Groups = []Group{}
	}
	if c.Rules == nil {
		c.Rules = []Rule{}
	}
	for i := range c.Groups {
		if c.Groups[i].Members == nil {
			c.Groups[i].Members = []string{}
		}
	}
	for i := range c.Interfaces {
		in := &c.Interfaces[i]
		if in.Kind == "vlan" && in.Parent != "" && in.VLANTag > 0 {
			in.Device = VLANDeviceName(in.Parent, in.VLANTag)
		}
		in.BridgeDevice = ""
		if in.Kind == "vlan" && in.AllowVMs {
			in.BridgeDevice = BridgeDeviceName(in.Device)
		}
		if in.Kind == "pppoe" {
			in.Device = PPPoEDeviceName(in.ID)
			in.IPv4Mode, in.Owned = "pppoe", true
		}
	}
	if c.Gateways == nil {
		c.Gateways = []Gateway{}
	}
	if c.Routes == nil {
		c.Routes = []StaticRoute{}
	}
	for i := range c.Routes {
		if d, ok := CanonicalRouteDest(c.Routes[i].Destination); ok {
			c.Routes[i].Destination = d
		}
	}
	if c.PortForwards == nil {
		c.PortForwards = []PortForward{}
	}
	for i := range c.PortForwards {
		if c.PortForwards[i].Source.Type == "" {
			c.PortForwards[i].Source.Type = "any"
		}
		if c.PortForwards[i].Interfaces == nil {
			c.PortForwards[i].Interfaces = []string{}
		}
	}
	if c.SNATRules == nil {
		c.SNATRules = []SNATRule{}
	}
	if c.Settings.OutboundNAT == "" {
		c.Settings.OutboundNAT = "automatic"
	}
	c.normalizeServices()
	c.normalizeIDS()
	c.normalizeDDNS()
}

// VLANDeviceName is the kernel name of a VLAN sub-interface: <parent>-v<tag>,
// parent truncated so the whole name fits IFNAMSIZ-1 (15). Same rule as
// system.vlanIfaceName so both features name VLANs identically.
func VLANDeviceName(parent string, tag int) string {
	suffix := fmt.Sprintf("-v%d", tag)
	max := 15 - len(suffix)
	if max < 1 {
		max = 1
	}
	if len(parent) > max {
		parent = parent[:max]
	}
	return parent + suffix
}

// BridgeDeviceName is the bridge carrying an "Allow VMs" VLAN: br-<device>
// when that fits IFNAMSIZ-1 (15). On a longer port name (enp5s0f0-v700) a
// plain cut made VLAN 700 and 701 share "br-enp5s0f0-v70", so the name keeps
// the whole "-v<tag>" and marks the cut parent with 2 hex digits of the
// device's CRC: br-enp5s<hh>-v700. Validate refuses the rare leftover clash.
// The "br-" prefix stays: other code recognises bridges by it.
func BridgeDeviceName(device string) string {
	n := "br-" + device
	if len(n) <= 15 {
		return n
	}
	parent, suffix := device, ""
	if k := strings.LastIndex(device, "-v"); k > 0 {
		parent, suffix = device[:k], device[k:]
	}
	keep := 15 - 3 - 2 - len(suffix)
	if keep < 1 {
		keep = 1
	}
	if len(parent) > keep {
		parent = parent[:keep]
	}
	n = fmt.Sprintf("br-%s%02x%s", parent, crc32.ChecksumIEEE([]byte(device))&0xff, suffix)
	if len(n) > 15 {
		n = n[:15]
	}
	return n
}

// L3Device is the device that carries the interface's IPv4 address and that
// traffic enters on: the bridge for an "Allow VMs" VLAN, the device otherwise.
func (i Interface) L3Device() string {
	if i.Kind == "vlan" && i.AllowVMs {
		return BridgeDeviceName(i.Device)
	}
	return i.Device
}

// InterfaceNameByDevice is the name the admin gave the interface a Linux
// device belongs to ("" when none): its L3 device (a VLAN's bridge, a PPPoE
// link) or its own device.
func (c *Config) InterfaceNameByDevice(dev string) string {
	for _, in := range c.Interfaces {
		if dev != "" && (in.L3Device() == dev || in.Device == dev) {
			return in.Name
		}
	}
	return ""
}

// DeviceNames maps every Linux device of a configured interface (its own
// and its L3 device) to the interface's name.
func (c *Config) DeviceNames() map[string]string {
	m := map[string]string{}
	for _, in := range c.Interfaces {
		if in.Name == "" {
			continue
		}
		for _, d := range []string{in.Device, in.L3Device()} {
			if d != "" {
				m[d] = in.Name
			}
		}
	}
	return m
}

func (c *Config) InterfaceByID(id string) *Interface {
	for i := range c.Interfaces {
		if c.Interfaces[i].ID == id {
			return &c.Interfaces[i]
		}
	}
	return nil
}

func (c *Config) GroupByID(id string) *Group {
	for i := range c.Groups {
		if c.Groups[i].ID == id {
			return &c.Groups[i]
		}
	}
	return nil
}

// PPPoEDeviceName is the ppp interface name of a PPPoE interface.
func PPPoEDeviceName(id string) string {
	if len(id) > 11 {
		id = id[:11]
	}
	return "ppp-" + id
}

func (c *Config) GatewayByID(id string) *Gateway {
	for i := range c.Gateways {
		if c.Gateways[i].ID == id {
			return &c.Gateways[i]
		}
	}
	return nil
}

// Redacted is a copy safe to send to a browser: secrets replaced by a flag.
func (c *Config) Redacted() *Config {
	b, _ := json.Marshal(c)
	var r Config
	_ = json.Unmarshal(b, &r)
	for i := range r.Interfaces {
		if r.Interfaces[i].PPPoEPassword != "" {
			r.Interfaces[i].PPPoEPassword, r.Interfaces[i].PPPoEPasswordSet = "", true
		}
		if r.Interfaces[i].WGPrivateKey != "" {
			r.Interfaces[i].WGPrivateKey, r.Interfaces[i].WGPrivateKeySet = "", true
		}
	}
	for i := range r.WGPeers {
		if r.WGPeers[i].PresharedKey != "" {
			r.WGPeers[i].PresharedKey, r.WGPeers[i].PresharedKeySet = "", true
		}
	}
	for i := range r.DDNS {
		if r.DDNS[i].Password != "" {
			r.DDNS[i].Password, r.DDNS[i].PasswordSet = "", true
		}
	}
	return &r
}

// KeepSecretsFrom fills secrets the browser did not send back (redacted)
// from the stored config, interface by interface.
func (c *Config) KeepSecretsFrom(stored *Config) {
	if stored == nil {
		return
	}
	for i := range c.Interfaces {
		in := &c.Interfaces[i]
		if in.PPPoEPassword == "" {
			if old := stored.InterfaceByID(in.ID); old != nil {
				in.PPPoEPassword = old.PPPoEPassword
			}
		}
		in.PPPoEPasswordSet = false
		if in.WGPrivateKey == "" {
			if old := stored.InterfaceByID(in.ID); old != nil {
				in.WGPrivateKey = old.WGPrivateKey
			}
		}
		in.WGPrivateKeySet = false
	}
	for i := range c.WGPeers {
		p := &c.WGPeers[i]
		if p.PresharedKey == "" && p.PresharedKeySet {
			for _, old := range stored.WGPeers {
				if old.ID == p.ID {
					p.PresharedKey = old.PresharedKey
				}
			}
		}
		p.PresharedKeySet = false
	}
	for i := range c.DDNS {
		e := &c.DDNS[i]
		if e.Password == "" && e.PasswordSet {
			for _, old := range stored.DDNS {
				if old.ID == e.ID {
					e.Password = old.Password
				}
			}
		}
		e.PasswordSet = false
	}
}
