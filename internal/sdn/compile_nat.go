package sdn

import (
	"fmt"
	"strings"
)

// Gateway i (its position in Config.Gateways) routes marked connections
// through table 100+i ("follow failover": the monitor points it at the best
// UP gateway) or 200+i ("only this gateway": unreachable while it is down).
func GatewayMark(i int, only bool) uint32 {
	if only {
		return 0x200 + uint32(i)
	}
	return 0x100 + uint32(i)
}

func GatewayTable(i int, only bool) int {
	if only {
		return 200 + i
	}
	return 100 + i
}

func (c *Config) gatewayIndex(id string) int {
	for i, g := range c.Gateways {
		if g.ID == id {
			return i
		}
	}
	return -1
}

// gatewayDevices: the L3 device of every gateway's interface, in order.
func (c *Config) gatewayDevices() []string {
	var out []string
	seen := map[string]bool{}
	for _, g := range c.Gateways {
		if in := c.InterfaceByID(g.Interface); in != nil && !seen[in.L3Device()] {
			seen[in.L3Device()] = true
			out = append(out, in.L3Device())
		}
	}
	return out
}

func protoMatch(p string) string {
	return map[string]string{"tcp": "meta l4proto tcp", "udp": "meta l4proto udp", "tcpudp": "meta l4proto { tcp, udp }"}[p]
}

func dnatTarget(f PortForward) string {
	if f.TargetPorts == f.PubPorts && strings.Contains(f.PubPorts, "-") {
		return f.Target // same range: keep the ports
	}
	return f.Target + ":" + f.TargetPorts
}

func joinParts(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

// writeNAT emits the routing/NAT part of the table: port forwards,
// outbound NAT, policy-routing marks (rule/SNAT gateways, reply-to) and MSS
// clamping on PPPoE. Active in both modes: "monitor" only disables filtering.
func writeNAT(b *strings.Builder, c *Config) {
	b.WriteString("\tset private {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16 }\n\t}\n")
	b.WriteString("\tset wan {\n\t\ttype ifname\n")
	if devs := c.gatewayDevices(); len(devs) > 0 {
		fmt.Fprintf(b, "\t\telements = { %s }\n", quoteJoin(devs))
	}
	b.WriteString("\t}\n")

	// ── port forwards ──
	b.WriteString("\tchain nat_pre {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
	for _, f := range c.PortForwards {
		if !f.Active() {
			continue
		}
		src := endpointMatch(c, "saddr", f.Source)
		for _, id := range f.Interfaces {
			in := c.InterfaceByID(id)
			if in == nil {
				continue
			}
			fmt.Fprintf(b, "\t\t%s comment \"pf:%s\"\n", joinParts(fmt.Sprintf("iifname %q", in.L3Device()), protoMatch(f.Protocol), src,
				"th dport "+f.PubPorts, "dnat to "+dnatTarget(f)), f.ID)
		}
		if f.Reflection {
			fmt.Fprintf(b, "\t\t%s comment \"pf:%s\"\n", joinParts("iifname != @wan fib daddr type local", protoMatch(f.Protocol),
				"th dport "+f.PubPorts, "dnat to "+f.Target+":"+f.TargetPorts), f.ID)
		}
	}
	b.WriteString("\t}\n")

	// ── outbound NAT ──
	b.WriteString("\tchain nat_post {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	for _, f := range c.PortForwards {
		if f.Active() && f.Reflection {
			fmt.Fprintf(b, "\t\t%s comment \"pf:%s\"\n", joinParts("iifname != @wan ct status dnat ip daddr "+f.Target, protoMatch(f.Protocol),
				"th dport "+f.TargetPorts, "masquerade"), f.ID)
		}
	}
	mode := c.Settings.OutboundNAT
	if mode == "hybrid" || mode == "manual" {
		for _, r := range c.SNATRules {
			if !r.Enabled {
				continue
			}
			out := ""
			if g := c.GatewayByID(r.Gateway); g != nil {
				if in := c.InterfaceByID(g.Interface); in != nil {
					out = fmt.Sprintf("oifname %q", in.L3Device())
				}
			}
			verdict := map[string]string{"iface": "masquerade", "ip": "snat to " + r.TranslateIP, "none": "return"}[r.Translate]
			fmt.Fprintf(b, "\t\t%s comment \"sn:%s\"\n", joinParts(out, snatProto(r), endpointMatch(c, "saddr", r.Source),
				endpointMatch(c, "daddr", r.Destination), portMatch(r.DstPorts), verdict), r.ID)
		}
	}
	if mode != "manual" {
		for _, g := range c.Gateways {
			in := c.InterfaceByID(g.Interface)
			if in == nil {
				continue
			}
			own := ""
			if in.IPv4Mode == "static" {
				own = "ip saddr != " + endpointMatch(c, "", Endpoint{Type: "iface_net", Value: in.ID})[len("ip  "):]
			}
			fmt.Fprintf(b, "\t\t%s comment \"auto\"\n", joinParts(fmt.Sprintf("oifname %q", in.L3Device()), own, "ip daddr != @private", "masquerade"))
		}
	}
	b.WriteString("\t}\n")

	// ── policy routing marks ──
	b.WriteString("\tchain mangle_pre {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	b.WriteString("\t\tct mark != 0 meta mark set ct mark\n")
	for i, g := range c.Gateways {
		if in := c.InterfaceByID(g.Interface); in != nil {
			// reply-to: a connection from the Internet arriving on a gateway's
			// interface answers through that gateway — its always-on table
			// (the one the monitor probes with): traffic arriving proves the
			// link works, whatever the monitor currently thinks of it.
			fmt.Fprintf(b, "\t\tiifname %q ct state new ip saddr != @private ct mark set 0x%x\n", in.L3Device(), ProbeMark(i))
		}
	}
	for _, r := range c.Rules {
		gi := c.gatewayIndex(r.Gateway)
		if !r.Enabled || r.Action != "allow" || gi < 0 {
			continue
		}
		iif := ""
		if in := c.InterfaceByID(r.Interface); in != nil {
			iif = fmt.Sprintf("iifname %q", in.L3Device())
		}
		fmt.Fprintf(b, "\t\t%s comment %q\n", joinParts("meta mark 0", iif, "ct state new", protoMatchRule(r.Protocol), endpointMatch(c, "saddr", r.Source),
			endpointMatch(c, "daddr", r.Destination), portMatch(r.DstPorts), fmt.Sprintf("meta mark set 0x%x ct mark set meta mark", GatewayMark(gi, r.OnlyGateway))), RuleComment(r.ID))
	}
	if mode == "hybrid" || mode == "manual" {
		for _, r := range c.SNATRules {
			gi := c.gatewayIndex(r.Gateway)
			if !r.Enabled || gi < 0 {
				continue
			}
			fmt.Fprintf(b, "\t\t%s comment \"sn:%s\"\n", joinParts("meta mark 0 ct state new", snatProto(r), endpointMatch(c, "saddr", r.Source),
				endpointMatch(c, "daddr", r.Destination), portMatch(r.DstPorts), fmt.Sprintf("meta mark set 0x%x ct mark set meta mark", GatewayMark(gi, r.OnlyThisGateway))), r.ID)
		}
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain mangle_out {\n\t\ttype route hook output priority mangle; policy accept;\n\t\tct mark != 0 meta mark set ct mark\n\t}\n")

	// ── MSS clamping on PPPoE (MTU 1492) ──
	var ppp []string
	for _, in := range c.Interfaces {
		if in.Kind == "pppoe" {
			ppp = append(ppp, in.Device)
		}
	}
	if len(ppp) > 0 {
		b.WriteString("\tchain mss {\n\t\ttype filter hook forward priority mangle; policy accept;\n")
		for _, d := range ppp {
			fmt.Fprintf(b, "\t\toifname %q tcp flags syn tcp option maxseg size set rt mtu\n", d)
			fmt.Fprintf(b, "\t\tiifname %q tcp flags syn tcp option maxseg size set rt mtu\n", d)
		}
		b.WriteString("\t}\n")
	}
}

func snatProto(r SNATRule) string {
	if r.Protocol == "" || r.Protocol == "any" {
		return ""
	}
	return protoMatchRule(r.Protocol)
}

func protoMatchRule(p string) string {
	return map[string]string{"any": "", "tcp": "meta l4proto tcp", "udp": "meta l4proto udp",
		"tcpudp": "meta l4proto { tcp, udp }", "icmp": "meta l4proto icmp"}[p]
}
