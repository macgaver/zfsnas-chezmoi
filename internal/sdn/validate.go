package sdn

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// FieldError points at one invalid field. Path uses the JSON names, e.g.
// "rules[3].source", so the UI can highlight the field.
type FieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// ValidationErrors is returned by Validate; it is the error a rejected apply
// carries back to the UI.
type ValidationErrors []FieldError

func (v ValidationErrors) Error() string {
	parts := make([]string, len(v))
	for i, e := range v {
		parts[i] = e.Path + ": " + e.Message
	}
	return strings.Join(parts, "; ")
}

var groupNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,31}$`)

// idRe: ids become nft chain/set names and ifupdown markers — keep them to
// lowercase alphanumerics (NewID produces 8 hex chars).
var idRe = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// devRe: kernel interface names (IFNAMSIZ-1 = 15). Device and parent names
// are written into root-executed files (/etc/network/interfaces, sysctl.d),
// so anything outside this set — spaces, quotes, newlines, "/" — is refused.
var devRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

func pppSafe(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

func validDevice(s string) bool { return devRe.MatchString(s) && s != "." && s != ".." }

var colorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// Validate checks the configuration. It reports at most one error per
// interface/group/rule (the first found), so a single mistake never shows up
// as a cascade.
func (c *Config) Validate() error {
	var errs ValidationErrors
	add := func(path, format string, a ...any) {
		errs = append(errs, FieldError{Path: path, Message: fmt.Sprintf(format, a...)})
	}

	switch c.Settings.Mode {
	case "monitor", "router":
	default:
		add("settings.mode", "mode must be monitor or router")
	}
	if m := c.Settings.MgmtInterface; m != "" && !validDevice(m) {
		add("settings.mgmt_interface", "%q is not a valid network device name", m)
	}

	ids := map[string]bool{}
	devices := map[string]bool{}
	vlans := map[string]bool{}
	var nets []netip.Prefix
	var netOwner []int
	for i, in := range c.Interfaces {
		p := fmt.Sprintf("interfaces[%d]", i)
		if msg := c.checkInterface(in, ids, devices, vlans); msg != "" {
			field, text, _ := strings.Cut(msg, "|")
			add(p+"."+field, "%s", text)
			continue
		}
		ids[in.ID] = true
		devices[in.Device] = true
		if in.Kind == "vlan" {
			vlans[fmt.Sprintf("%s/%d", in.Parent, in.VLANTag)] = true
		}
		if in.IPv4Mode == "static" {
			pfx, _ := netip.ParsePrefix(in.IPv4)
			pfx = pfx.Masked()
			overlap := -1
			for k, other := range nets {
				if other.Overlaps(pfx) {
					overlap = netOwner[k]
				}
			}
			if overlap >= 0 {
				add(p+".ipv4", "network %s overlaps %s", pfx, c.Interfaces[overlap].Name)
				continue
			}
			nets = append(nets, pfx)
			netOwner = append(netOwner, i)
		}
	}

	c.validateDisabled(add)

	gnames := map[string]bool{}
	for i, g := range c.Groups {
		p := fmt.Sprintf("groups[%d]", i)
		switch {
		case !idRe.MatchString(g.ID):
			add(p+".id", "invalid id")
			continue
		case !groupNameRe.MatchString(g.Name):
			add(p+".name", "name may only use letters, digits, - and _ (max 31)")
			continue
		case gnames[strings.ToLower(g.Name)]:
			add(p+".name", "a group named %s already exists", g.Name)
			continue
		case g.Kind != "hosts" && g.Kind != "ports" && g.Kind != "countries":
			add(p+".kind", "kind must be hosts, ports or countries")
			continue
		}
		gnames[strings.ToLower(g.Name)] = true
		for k, m := range g.Members {
			var ok bool
			switch g.Kind {
			case "hosts":
				ok = validHostMember(m)
			case "countries":
				ok = CountryName(m) != ""
			default:
				ok = validPortSpec(m)
			}
			if !ok {
				add(fmt.Sprintf("%s.members[%d]", p, k), "%q is not a valid %s entry", m, g.Kind)
				break
			}
		}
	}

	for i, r := range c.Rules {
		p := fmt.Sprintf("rules[%d]", i)
		label := r.Description
		if label == "" {
			label = fmt.Sprintf("rule %d", i+1)
		}
		if field, msg := c.checkRule(r); field != "" {
			add(p+"."+field, "%s: %s", label, msg)
		}
	}

	c.validatePhase3(add)
	c.validateServices(add, ids)
	c.validateVIPs(add)
	c.validateIDS(add)
	c.validateDDNS(add)
	c.validateRoutes(add)
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// validatePhase3 checks gateways, port forwards and outbound NAT rules.
func (c *Config) validatePhase3(add func(path, format string, a ...any)) {
	prios := map[int]bool{}
	for i, g := range c.Gateways {
		p := fmt.Sprintf("gateways[%d]", i)
		in := c.InterfaceByID(g.Interface)
		switch {
		case !idRe.MatchString(g.ID):
			add(p+".id", "invalid id")
		case in == nil:
			add(p+".interface", "%s: its interface no longer exists", g.Name)
		case in.IPv4Mode == "none":
			add(p+".interface", "%s: %s has no IPv4 address", g.Name, in.Name)
		case g.Address != "" && !gatewayInNet(*in, g.Address):
			add(p+".address", "%s: %s is not an IPv4 address inside %s's network", g.Name, g.Address, in.Name)
		case g.MonitorIP != "" && !plainIPv4(g.MonitorIP):
			add(p+".monitor_ip", "%q is not an IPv4 address", g.MonitorIP)
		case g.ProbeEvery != 0 && (g.ProbeEvery < 2 || g.ProbeEvery > 3600):
			add(p+".probe_every", "%s: test every 2 to 3600 seconds", g.Name)
		case g.ProbePings != 0 && (g.ProbePings < 1 || g.ProbePings > MaxProbePings):
			add(p+".probe_pings", "%s: send 1 to %d pings per test", g.Name, MaxProbePings)
		case g.Priority < 1 || prios[g.Priority]:
			add(p+".priority", "%s: priorities must be unique numbers from 1", g.Name)
		default:
			prios[g.Priority] = true
		}
	}
	for i, f := range c.PortForwards {
		p := fmt.Sprintf("port_forwards[%d]", i)
		label := f.Description
		if label == "" {
			label = "port forward " + f.PubPorts
		}
		bad := func(field, format string, a ...any) { add(p+"."+field, "%s: "+format, append([]any{label}, a...)...) }
		switch {
		case !idRe.MatchString(f.ID):
			bad("id", "invalid id")
		case f.Protocol != "tcp" && f.Protocol != "udp" && f.Protocol != "tcpudp":
			bad("protocol", "protocol must be TCP, UDP or TCP+UDP")
		case !validPortSpec(f.PubPorts):
			bad("pub_ports", "%q is not a valid port or range", f.PubPorts)
		// An instance forward may have no target yet: the portal looks the
		// instance's address up (and follows it when it changes).
		case (f.Target != "" || f.Instance == "") && (!validHostMember(f.Target) || strings.ContainsAny(f.Target, "/-")):
			bad("target", "%q is not an IPv4 address", f.Target)
		case !validPortSpec(f.TargetPorts):
			bad("target_ports", "%q is not a valid port or range", f.TargetPorts)
		case portCount(f.TargetPorts) != 1 && f.TargetPorts != f.PubPorts:
			// nft cannot shift a range: 100-110 → 200-210 is not expressible
			bad("target_ports", "an inside range must be the same as the public range (or a single port)")
		case len(f.Interfaces) == 0 && f.Instance == "":
			bad("interfaces", "choose at least one interface")
		default:
			for _, id := range f.Interfaces {
				if c.InterfaceByID(id) == nil {
					bad("interfaces", "an interface no longer exists")
					break
				}
			}
			src := f.Source
			if src.Type == "" {
				src.Type = "any"
			}
			if m := c.checkEndpoint(src, false); m != "" {
				bad("source", "%s", m)
			}
		}
	}
	// One public port on one interface reaches one inside service.
	for i, f := range c.PortForwards {
		if !f.Enabled || f.Paused() || !validPortSpec(f.PubPorts) {
			continue
		}
		for _, g := range c.PortForwards[:i] {
			if !g.Enabled || g.Paused() || !validPortSpec(g.PubPorts) || !protoOverlap(f.Protocol, g.Protocol) || !portsOverlap(f.PubPorts, g.PubPorts) {
				continue
			}
			if shared := sharedIface(f.Interfaces, g.Interfaces); shared != "" {
				name := g.Description
				if name == "" {
					name = g.Target
				}
				iname := shared
				if in := c.InterfaceByID(shared); in != nil {
					iname = in.Name
				}
				add(fmt.Sprintf("port_forwards[%d].pub_ports", i), "port %s on %s is already forwarded (to %s)", f.PubPorts, iname, name)
				break
			}
		}
	}
	for i, r := range c.SNATRules {
		p := fmt.Sprintf("snat_rules[%d]", i)
		switch {
		case !idRe.MatchString(r.ID):
			add(p+".id", "invalid id")
		case r.Gateway == "" && len(c.Gateways) > 1:
			add(p+".gateway", "%s: choose the outgoing gateway (there is more than one)", r.Description)
		case r.Gateway != "" && c.GatewayByID(r.Gateway) == nil:
			add(p+".gateway", "%s: its gateway no longer exists", r.Description)
		case r.Translate != "iface" && r.Translate != "ip" && r.Translate != "none":
			add(p+".translate", "translate must be iface, ip or none")
		case r.Translate == "ip" && (!validHostMember(r.TranslateIP) || strings.ContainsAny(r.TranslateIP, "/-")):
			add(p+".translate_ip", "%q is not an IPv4 address", r.TranslateIP)
		default:
			if m := c.checkEndpoint(r.Source, false); m != "" {
				add(p+".source", "%s", m)
			} else if m := c.checkEndpoint(r.Destination, true); m != "" {
				add(p+".destination", "%s", m)
			}
		}
	}
	switch c.Settings.OutboundNAT {
	case "", "automatic", "hybrid", "manual":
	default:
		add("settings.outbound_nat", "outbound NAT must be automatic, hybrid or manual")
	}
}

func gatewayInNet(in Interface, gw string) bool {
	a, err := netip.ParseAddr(gw)
	if err != nil || !a.Is4() {
		return false
	}
	if in.IPv4Mode != "static" {
		return true // dynamic interface: network unknown until it is up
	}
	p, err := netip.ParsePrefix(in.IPv4)
	return err == nil && p.Masked().Contains(a)
}

func portBounds(spec string) (int, int) {
	a, b, ok := strings.Cut(spec, "-")
	lo, _ := strconv.Atoi(a)
	if !ok {
		return lo, lo
	}
	hi, _ := strconv.Atoi(b)
	return lo, hi
}

func portsOverlap(a, b string) bool {
	alo, ahi := portBounds(a)
	blo, bhi := portBounds(b)
	return alo <= bhi && blo <= ahi
}

func protoOverlap(a, b string) bool { return a == b || a == "tcpudp" || b == "tcpudp" }

func sharedIface(a, b []string) string {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return x
			}
		}
	}
	return ""
}

func portCount(spec string) int {
	a, b, ok := strings.Cut(spec, "-")
	if !ok {
		return 1
	}
	lo, _ := strconv.Atoi(a)
	hi, _ := strconv.Atoi(b)
	return hi - lo + 1
}

// checkInterface returns "field|message" for the first problem, "" if valid.
func (c *Config) checkInterface(in Interface, ids, devices, vlans map[string]bool) string {
	switch {
	case !idRe.MatchString(in.ID) || ids[in.ID]:
		return "id|missing, invalid or duplicate id"
	case in.Color != "" && !colorRe.MatchString(in.Color):
		return "color|colour must be #rrggbb"
	case in.IncusKeep && in.Kind != "incus":
		return "incus_keep|only an Incus network keeps its own settings"
	}
	switch in.Kind {
	case "physical", "bridge":
		if !validDevice(in.Device) {
			return "device|a valid network device name is required"
		}
	case "pppoe":
		if !validDevice(in.Parent) {
			return "parent|a valid port for the PPPoE session is required"
		}
		if strings.TrimSpace(in.PPPoEUser) == "" {
			return "pppoe_user|the PPPoE user name is required"
		}
		// Both end up quoted in /etc/ppp/*-secrets and the peers file.
		if !pppSafe(in.PPPoEUser) {
			return "pppoe_user|the PPPoE user name cannot contain quotes, backslashes or control characters"
		}
		if !pppSafe(in.PPPoEPassword) {
			return "pppoe_password|the PPPoE password cannot contain quotes, backslashes or control characters"
		}
	case "incus":
		// An Incus-managed L2 bridge (VMs & Containers): its address is set
		// through Incus, which has no DHCP-client mode for a bridge.
		if !validDevice(in.Device) {
			return "device|a valid network device name is required"
		}
		if in.IPv4Mode == "dhcp" {
			return "ipv4_mode|an Incus network takes a static address or none"
		}
		if in.IncusKeep && in.IPv4Mode != "static" {
			return "ipv4|this Incus network has no address to keep"
		}
	case "vlan":
		if !validDevice(in.Parent) {
			return "parent|a valid parent port is required"
		}
		if in.VLANTag < 1 || in.VLANTag > 4094 {
			return "vlan_tag|VLAN tag must be between 1 and 4094"
		}
		if vlans[fmt.Sprintf("%s/%d", in.Parent, in.VLANTag)] {
			return fmt.Sprintf("vlan_tag|VLAN %d already exists on %s", in.VLANTag, in.Parent)
		}
	case "wireguard":
		if msg := checkWireGuard(in); msg != "" {
			return msg
		}
	default:
		return "kind|kind must be physical, vlan, bridge, incus, pppoe or wireguard"
	}
	if devices[in.Device] {
		return "device|" + in.Device + " is already used by another interface"
	}
	switch in.Role {
	case "wan", "lan", "":
	default:
		return "role|role must be wan, lan or empty"
	}
	switch in.IPv4Mode {
	case "static":
		pfx, err := netip.ParsePrefix(in.IPv4)
		if err != nil || !pfx.Addr().Is4() {
			return "ipv4|enter an IPv4 address with prefix, e.g. 10.128.8.1/24"
		}
		if in.Gateway != "" {
			gw, err := netip.ParseAddr(in.Gateway)
			if err != nil || !gw.Is4() || !pfx.Masked().Contains(gw) {
				return "gateway|gateway must be an IPv4 address inside " + pfx.Masked().String()
			}
		}
	case "dhcp", "none", "pppoe":
	default:
		return "ipv4_mode|IPv4 mode must be static, dhcp or none"
	}
	if in.MTU != 0 && (in.MTU < 576 || in.MTU > 9216) {
		return "mtu|MTU must be between 576 and 9216"
	}
	return ""
}

func (c *Config) checkRule(r Rule) (field, msg string) {
	if !idRe.MatchString(r.ID) {
		return "id", "invalid id"
	}
	if r.Interface != "" && c.InterfaceByID(r.Interface) == nil {
		return "interface", "its interface no longer exists"
	}
	if r.Gateway != "" && c.GatewayByID(r.Gateway) == nil {
		return "gateway", "its gateway no longer exists"
	}
	switch r.Action {
	case "allow", "block", "reject":
	default:
		return "action", "action must be allow, block or reject"
	}
	switch r.Protocol {
	case "any", "tcp", "udp", "tcpudp", "icmp":
	default:
		return "protocol", "unknown protocol"
	}
	if m := c.checkEndpoint(r.Source, false); m != "" {
		return "source", m
	}
	if m := c.checkEndpoint(r.Destination, true); m != "" {
		return "destination", m
	}
	if r.DstPorts != "" {
		if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "tcpudp" {
			return "dst_ports", "ports need protocol TCP, UDP or TCP+UDP"
		}
		if id, ok := strings.CutPrefix(r.DstPorts, "group:"); ok {
			g := c.GroupByID(id)
			if g == nil || g.Kind != "ports" {
				return "dst_ports", "its port group no longer exists"
			}
		} else {
			for _, part := range strings.Split(r.DstPorts, ",") {
				if !validPortSpec(strings.TrimSpace(part)) {
					return "dst_ports", fmt.Sprintf("%q is not a valid port or range", part)
				}
			}
		}
	}
	return "", ""
}

func (c *Config) checkEndpoint(e Endpoint, isDst bool) string {
	switch e.Type {
	case "any":
	case "cidr":
		if !validHostMember(e.Value) {
			return fmt.Sprintf("%q is not an IPv4 address or network", e.Value)
		}
	case "group":
		g := c.GroupByID(e.Value)
		if g == nil || (g.Kind != "hosts" && g.Kind != "countries") {
			return "its group no longer exists"
		}
	case "countries":
		codes := strings.Split(e.Value, ",")
		if e.Value == "" {
			return "choose at least one country"
		}
		for _, cc := range codes {
			if CountryName(cc) == "" {
				return fmt.Sprintf("%q is not a country code", cc)
			}
		}
	case "iface_net", "iface_addr":
		in := c.InterfaceByID(e.Value)
		if in == nil {
			return "its interface no longer exists"
		}
		if in.IPv4Mode != "static" {
			return in.Name + " has no static IPv4 address"
		}
	case "internal":
	case "this_znas":
		if !isDst {
			return "This ZNAS can only be a destination"
		}
	default:
		return "unknown endpoint type"
	}
	return ""
}

// validHostMember accepts an IPv4 address, an IPv4 CIDR, or a range a-b.
func validHostMember(s string) bool {
	if a, b, ok := strings.Cut(s, "-"); ok {
		x, err1 := netip.ParseAddr(strings.TrimSpace(a))
		y, err2 := netip.ParseAddr(strings.TrimSpace(b))
		return err1 == nil && err2 == nil && x.Is4() && y.Is4() && !y.Less(x)
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return err == nil && p.Addr().Is4()
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}

// validPortSpec accepts "443" or "16261-16263".
func validPortSpec(s string) bool {
	a, b, isRange := strings.Cut(s, "-")
	lo, err := strconv.Atoi(a)
	if err != nil || lo < 1 || lo > 65535 {
		return false
	}
	if !isRange {
		return true
	}
	hi, err := strconv.Atoi(b)
	return err == nil && hi >= lo && hi <= 65535
}

// AddStarterRules gives every LAN interface that has no rule yet the
// editable "Allow LAN → anywhere" rule ("Router defaults", spec §4.1/§10.1):
// without it, switching to Router mode would block every LAN service (SMB,
// NFS, DNS…) while the portal — protected by anti-lockout — keeps working, so
// the countdown would not catch it.
func AddStarterRules(c *Config) {
	has := map[string]bool{}
	for _, r := range c.Rules {
		has[r.Interface] = true
	}
	for _, in := range c.Interfaces {
		if in.Role != "lan" || has[in.ID] {
			continue
		}
		c.Rules = append(c.Rules, Rule{ID: NewID(), Enabled: true, Interface: in.ID, Action: "allow", Protocol: "any",
			Source: Endpoint{Type: "any"}, Destination: Endpoint{Type: "any"}, Description: "Default allow " + in.Name + " → anywhere"})
	}
}

// validateDisabled: an interface that cannot go down without taking something
// that stays on with it — the way in to this server, or a VLAN or PPPoE link
// running on it — unless the admin forces it. WireGuard tunnels are turned
// off on their own page.
func (c *Config) validateDisabled(add func(path, format string, a ...any)) {
	for i, in := range c.Interfaces {
		if !in.Disabled {
			continue
		}
		p := fmt.Sprintf("interfaces[%d].disabled", i)
		if in.Kind == "wireguard" {
			add(p, "a WireGuard tunnel cannot be disabled here")
		}
		if in.DisableForced {
			continue
		}
		if m := c.Settings.MgmtInterface; m != "" && (m == in.Device || m == in.L3Device()) {
			add(p, "%s is the management interface: disabling it would cut you off from this server", in.Name)
		}
		for k, o := range c.Interfaces {
			if !o.Disabled && o.Parent != "" && (o.Parent == in.Device || o.Parent == in.L3Device()) {
				add(p, "%s runs on it: disable that first", o.Name)
				add(fmt.Sprintf("interfaces[%d].disabled", k), "it runs on %s, which is disabled", in.Name)
				break
			}
		}
	}
}
