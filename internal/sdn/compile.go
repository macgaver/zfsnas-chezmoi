package sdn

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// TableName is the only nftables table the feature owns. It is replaced as a
// whole on every apply (one atomic `nft -f` transaction) and never shares
// state with Incus' or Docker's tables.
const TableName = "znas_sdn"

// Env carries the live facts the compiler needs but the config does not hold.
type Env struct {
	PortalPorts []int // appCfg.Port, plus 443 when BindPort443
	SSHPort     int
	// CountryCIDRs returns a country's IPv4 networks (geo database). Nil, or
	// an error, makes any country rule fail to compile: a country rule must
	// never silently match nothing.
	CountryCIDRs func(cc string) ([]string, error)
}

// countrySet names the nft set of a country endpoint and lists its codes.
func countrySet(c *Config, e Endpoint) (string, []string) {
	switch e.Type {
	case "group":
		if g := c.GroupByID(e.Value); g != nil && g.Kind == "countries" {
			return "c_" + g.ID, g.Members
		}
	case "countries":
		codes := strings.Split(e.Value, ",")
		name := "c_" + strings.ToLower(strings.Join(codes, "_"))
		if len(name) > 48 { // nft names stop at 256; keep them readable and short
			h := fnv.New32a()
			h.Write([]byte(e.Value))
			name = fmt.Sprintf("c_%dcc_%08x", len(codes), h.Sum32())
		}
		return name, codes
	}
	return "", nil
}

func writeCountrySets(b *strings.Builder, c *Config, env Env) error {
	done := map[string]bool{}
	type user struct {
		Description string
		eps         []Endpoint
	}
	var users []user
	for _, r := range c.Rules {
		if r.Enabled {
			users = append(users, user{r.Description, []Endpoint{r.Source, r.Destination}})
		}
	}
	for _, f := range c.PortForwards {
		if f.Enabled && !f.Paused() {
			users = append(users, user{f.Description, []Endpoint{f.Source}})
		}
	}
	for _, r := range c.SNATRules {
		if r.Enabled {
			users = append(users, user{r.Description, []Endpoint{r.Source, r.Destination}})
		}
	}
	for _, r := range users {
		for _, e := range r.eps {
			name, codes := countrySet(c, e)
			if name == "" || done[name] {
				continue
			}
			done[name] = true
			if env.CountryCIDRs == nil {
				return fmt.Errorf("rule %q uses countries but the country database is not available — download it from Firewall → Traffic first", r.Description)
			}
			var elems []string
			for _, cc := range codes {
				cidrs, err := env.CountryCIDRs(cc)
				if err != nil {
					return fmt.Errorf("country database: %w", err)
				}
				elems = append(elems, cidrs...)
			}
			if len(elems) == 0 {
				return fmt.Errorf("rule %q: the country database has no known networks for %s — refusing an empty country set", r.Description, strings.Join(codes, ", "))
			}
			fmt.Fprintf(b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n", name)
			if len(elems) > 0 {
				fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
			}
			b.WriteString("\t}\n")
		}
	}
	return nil
}

// RuleComment tags every compiled line of a rule so hit counters can be read
// back per rule (`nft -j list table`).
func RuleComment(ruleID string) string { return "r:" + ruleID }

// Compile validates the config and renders the full `nft -f` script.
//
// Shape: base chains input/forward accept anything that did not enter on an
// SDN-managed device (Incus bridges, Docker, loopback are left alone), accept
// established traffic, apply anti-lockout, then jump to the "Any interface"
// chain and the per-interface chain; whatever returns hits the default deny.
// Rules whose destination is This ZNAS go only to the input chains; all other
// rules go to both, so "to VLAN800 net" also covers the router's own address
// on that network, as on OPNsense.
func Compile(c *Config, env Env) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	header(&b)
	b.WriteString("\tset managed {\n\t\ttype ifname\n")
	if devs := managedDevices(c); len(devs) > 0 {
		fmt.Fprintf(&b, "\t\telements = { %s }\n", quoteJoin(devs))
	}
	b.WriteString("\t}\n")
	for _, g := range c.Groups {
		if g.Kind != "countries" {
			writeGroupSet(&b, g)
		}
	}
	if err := writeCountrySets(&b, c, env); err != nil {
		return "", err
	}

	router := c.Settings.Mode == "router"
	if router {
		// Blocked attempts are counted by nft itself (traffic statistics):
		// every drop path updates this set; the mark part is the block
		// rule's number (0 = default deny), see BlockRuleNumbers.
		b.WriteString("\tset blk {\n\t\ttype ipv4_addr . inet_proto . inet_service . ifname . mark\n\t\tflags dynamic,timeout\n\t\ttimeout 15m\n\t\tsize 65536\n\t\tcounter\n\t}\n")
	}
	nums := map[string]int{}
	for n, id := range BlockRuleNumbers(c) {
		nums[id] = n
	}
	for _, hook := range []string{"input", "forward"} {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority filter; policy accept;\n", hook, hook)
		if hook == "input" {
			for _, l := range noDNSLines(c) {
				fmt.Fprintf(&b, "\t\t%s\n", l)
			}
		}
		if !router {
			b.WriteString("\t\tcounter accept\n\t}\n")
			continue
		}
		b.WriteString("\t\tiifname != @managed accept\n")
		b.WriteString("\t\tct state established,related accept\n")
		b.WriteString("\t\tct state invalid drop\n")
		// Port forwards (SDN, Incus NAT proxies, Docker published ports):
		// a translated connection was already allowed by its forward's own
		// source restriction.
		b.WriteString("\t\tct status dnat accept\n")
		if hook == "input" && c.Settings.AntiLockout && c.Settings.MgmtInterface != "" {
			fmt.Fprintf(&b, "\t\t%s\n", antiLockoutLine(c.Settings.MgmtInterface, env))
		}
		if hook == "input" {
			for _, l := range serviceAllowLines(c) {
				fmt.Fprintf(&b, "\t\t%s\n", l)
			}
		}
		prefix := map[string]string{"input": "in", "forward": "fw"}[hook]
		fmt.Fprintf(&b, "\t\tjump any_%s\n", prefix)
		for _, in := range c.Interfaces {
			fmt.Fprintf(&b, "\t\tiifname %q jump %s_%s\n", in.L3Device(), prefix, in.ID)
		}
		// Counting and verdict on separate lines: when the blk set is full
		// the kernel skips the rest of the rule holding the failed update —
		// a drop on the same line would be skipped and the packet accepted.
		fmt.Fprintf(&b, "\t\tmeta l4proto { tcp, udp } %s\n", blkUpdate(true, 0))
		fmt.Fprintf(&b, "\t\tmeta l4proto != { tcp, udp } %s\n", blkUpdate(false, 0))
		b.WriteString("\t\tcounter drop comment \"default-deny\"\n\t}\n")
	}

	// Rule chains are emitted in monitor mode too (not jumped to) so that
	// switching modes is a pure dispatch change.
	chains := []struct{ name, iface string }{{"any_in", ""}, {"any_fw", ""}}
	for _, in := range c.Interfaces {
		chains = append(chains, struct{ name, iface string }{"in_" + in.ID, in.ID}, struct{ name, iface string }{"fw_" + in.ID, in.ID})
	}
	for _, ch := range chains {
		isInput := strings.HasPrefix(ch.name, "in_") || ch.name == "any_in"
		fmt.Fprintf(&b, "\tchain %s {\n", ch.name)
		for _, r := range c.Rules {
			if !r.Enabled || r.Interface != ch.iface {
				continue
			}
			if r.Destination.Type == "this_znas" && !isInput {
				continue
			}
			n := 0
			if router {
				n = nums[r.ID]
			}
			for _, line := range ruleLines(c, r, n) {
				fmt.Fprintf(&b, "\t\t%s\n", line)
			}
		}
		b.WriteString("\t}\n")
	}
	writeNAT(&b, c)
	b.WriteString("}\n")
	return b.String(), nil
}

// SafeModeRuleset is loaded at boot when the confirmed config cannot be
// applied. It keeps the management interface reachable (portal, SSH, ping,
// DHCP client), drops everything else entering SDN-managed devices and stops
// forwarding from them. Devices SDN does not manage stay untouched. With a nil
// config (unreadable file) every interface is locked except portal/SSH.
func SafeModeRuleset(c *Config, env Env) string {
	var b strings.Builder
	header(&b)
	ports := portList(env)
	if c == nil {
		b.WriteString("\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n")
		b.WriteString("\t\tiifname \"lo\" accept\n\t\tct state established,related accept\n")
		fmt.Fprintf(&b, "\t\ttcp dport { %s } accept comment \"anti-lockout\"\n", ports)
		b.WriteString("\t\tudp sport 67 udp dport 68 accept\n\t\ticmp type echo-request accept\n\t}\n")
		b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n")
		b.WriteString("\t\tct state established,related accept\n\t}\n}\n")
		return b.String()
	}
	b.WriteString("\tset managed {\n\t\ttype ifname\n")
	if devs := managedDevices(c); len(devs) > 0 {
		fmt.Fprintf(&b, "\t\telements = { %s }\n", quoteJoin(devs))
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n")
	b.WriteString("\t\tiifname != @managed accept\n\t\tct state established,related accept\n")
	if m := c.Settings.MgmtInterface; m != "" {
		fmt.Fprintf(&b, "\t\tiifname %q tcp dport { %s } accept comment \"anti-lockout\"\n", m, ports)
		fmt.Fprintf(&b, "\t\tiifname %q icmp type echo-request accept\n", m)
		fmt.Fprintf(&b, "\t\tiifname %q udp sport 67 udp dport 68 accept\n", m)
	}
	b.WriteString("\t\tcounter drop comment \"safe-mode\"\n\t}\n")
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n")
	b.WriteString("\t\tiifname != @managed accept\n\t\tct state established,related accept\n")
	b.WriteString("\t\tcounter drop comment \"safe-mode\"\n\t}\n}\n")
	return b.String()
}

// header declares then deletes the table so the delete never fails on a
// first apply, all inside the same transaction.
func header(b *strings.Builder) {
	fmt.Fprintf(b, "table ip %s\ndelete table ip %s\ntable ip %s {\n", TableName, TableName, TableName)
}

func managedDevices(c *Config) []string {
	seen := map[string]bool{}
	var out []string
	for _, in := range c.Interfaces {
		if d := in.L3Device(); d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

func portList(env Env) string {
	set := map[int]bool{}
	if env.SSHPort > 0 {
		set[env.SSHPort] = true
	}
	for _, p := range env.PortalPorts {
		if p > 0 {
			set[p] = true
		}
	}
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}

func antiLockoutLine(mgmt string, env Env) string {
	return fmt.Sprintf("iifname %q tcp dport { %s } accept comment \"anti-lockout\"", mgmt, portList(env))
}

func writeGroupSet(b *strings.Builder, g Group) {
	if g.Kind == "hosts" {
		fmt.Fprintf(b, "\tset g_%s {\n\t\ttype ipv4_addr\n\t\tflags interval\n", g.ID)
	} else {
		fmt.Fprintf(b, "\tset p_%s {\n\t\ttype inet_service\n\t\tflags interval\n", g.ID)
	}
	if len(g.Members) > 0 {
		fmt.Fprintf(b, "\t\tauto-merge\n\t\telements = { %s }\n", strings.Join(g.Members, ", "))
	}
	b.WriteString("\t}\n")
}

// BlockRuleNumbers numbers the enabled block/reject rules in order (1…n):
// the number is the mark part of the blk set key, so blocked attempts can
// be attributed to their rule.
func BlockRuleNumbers(c *Config) map[int]string {
	m := map[int]string{}
	if c == nil {
		return m
	}
	n := 0
	for _, r := range c.Rules {
		if r.Enabled && (r.Action == "block" || r.Action == "reject") {
			n++
			m[n] = r.ID
		}
	}
	return m
}

// blkUpdate is the statement adding a blocked packet to the blk set; the
// port is only readable for TCP/UDP.
func blkUpdate(hasPort bool, n int) string {
	port := "0"
	if hasPort {
		port = "th dport"
	}
	return fmt.Sprintf("update @blk { ip saddr . meta l4proto . %s . iifname . 0x%x }", port, n)
}

// ruleLines renders one rule; a reject on a mixed protocol needs one line for
// TCP (tcp reset) and one for the rest (ICMP admin-prohibited). count > 0
// (block/reject in router mode) prepends the blocked-attempt counting
// lines — never on a verdict line (see Compile: a full set must not turn a
// drop into a fall-through).
func ruleLines(c *Config, r Rule, count int) []string {
	matchSrc := endpointMatch(c, "saddr", r.Source)
	matchDst := endpointMatch(c, "daddr", r.Destination)
	ports := portMatch(r.DstPorts)
	match := func(proto string) []string {
		parts := []string{}
		for _, p := range []string{proto, matchSrc, matchDst, ports} {
			if p != "" {
				parts = append(parts, p)
			}
		}
		return parts
	}
	tail := func(verdict string) string {
		t := ""
		if r.Log {
			t += fmt.Sprintf("log prefix \"znas %s \" ", RuleComment(r.ID))
		}
		return t + "counter " + verdict + fmt.Sprintf(" comment %q", RuleComment(r.ID))
	}
	join := func(proto, verdict string) string {
		return strings.Join(append(match(proto), tail(verdict)), " ")
	}
	upd := func(proto string, hasPort bool) string {
		return strings.Join(append(match(proto), blkUpdate(hasPort, count)), " ")
	}
	proto := map[string]string{
		"any": "", "tcp": "meta l4proto tcp", "udp": "meta l4proto udp",
		"tcpudp": "meta l4proto { tcp, udp }", "icmp": "meta l4proto icmp",
	}[r.Protocol]

	var counting []string
	if count > 0 && (r.Action == "block" || r.Action == "reject") {
		switch r.Protocol {
		case "tcp", "udp", "tcpudp":
			counting = []string{upd(proto, true)}
		case "icmp":
			counting = []string{upd(proto, false)}
		default:
			counting = []string{upd("meta l4proto { tcp, udp }", true), upd("meta l4proto != { tcp, udp }", false)}
		}
	}
	switch r.Action {
	case "allow":
		return []string{join(proto, "accept")}
	case "block":
		return append(counting, join(proto, "drop"))
	}
	// reject
	const icmpReject = "reject with icmp type admin-prohibited"
	switch r.Protocol {
	case "tcp":
		return append(counting, join(proto, "reject with tcp reset"))
	case "udp", "icmp":
		return append(counting, join(proto, icmpReject))
	case "tcpudp":
		return append(counting, join("meta l4proto tcp", "reject with tcp reset"), join("meta l4proto udp", icmpReject))
	default: // any
		return append(counting, join("meta l4proto tcp", "reject with tcp reset"), join("meta l4proto != tcp", icmpReject))
	}
}

func endpointMatch(c *Config, dir string, e Endpoint) string {
	op := ""
	if e.Not {
		op = "!= "
	}
	switch e.Type {
	case "cidr":
		return fmt.Sprintf("ip %s %s%s", dir, op, e.Value)
	case "group", "countries":
		if name, _ := countrySet(c, e); name != "" {
			return fmt.Sprintf("ip %s %s@%s", dir, op, name)
		}
		return fmt.Sprintf("ip %s %s@g_%s", dir, op, e.Value)
	case "iface_net", "iface_addr":
		in := c.InterfaceByID(e.Value)
		pfx, _ := netip.ParsePrefix(in.IPv4)
		v := pfx.Masked().String()
		if e.Type == "iface_addr" {
			v = pfx.Addr().String()
		}
		return fmt.Sprintf("ip %s %s%s", dir, op, v)
	case "this_znas":
		return "fib daddr type " + op + "local"
	case "internal":
		nets := c.InternalNets()
		if len(nets) == 0 { // no inside network: matches nothing
			return fmt.Sprintf("ip %s %s255.255.255.255", dir, op)
		}
		return fmt.Sprintf("ip %s %s{ %s }", dir, op, strings.Join(nets, ", "))
	}
	return ""
}

// InternalNets lists the networks of the "Internal networks" alias: every
// interface that is not a WAN and has a static address (LANs, VLANs, VM
// networks, WireGuard tunnels), de-duplicated, in interface order.
func (c *Config) InternalNets() []string {
	var out []string
	seen := map[string]bool{}
	for _, in := range c.Interfaces {
		if in.Role == "wan" || in.IPv4Mode != "static" {
			continue
		}
		pfx, err := netip.ParsePrefix(in.IPv4)
		if err != nil {
			continue
		}
		if n := pfx.Masked().String(); !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func portMatch(spec string) string {
	if spec == "" {
		return ""
	}
	if id, ok := strings.CutPrefix(spec, "group:"); ok {
		return "th dport @p_" + id
	}
	parts := strings.Split(spec, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) == 1 {
		return "th dport " + parts[0]
	}
	return "th dport { " + strings.Join(parts, ", ") + " }"
}

func quoteJoin(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = strconv.Quote(x)
	}
	return strings.Join(q, ", ")
}
