package sdn

import (
	"strconv"
	"strings"
)

// PortOpen reports whether traffic from the Internet arriving on interface
// ifaceID for proto/port would be let in by the configuration: an enabled
// port forward published there, an allow rule of that interface (or Any
// interface) covering the port, a WireGuard listen port, or the anti-lockout
// ports on the management interface. Sources (countries, groups) are ignored:
// a port open to some of the Internet is open. Used to tell intrusion alerts
// on exposed services from probes the firewall dropped anyway.
func (c *Config) PortOpen(ifaceID, proto string, port int, env Env) bool {
	proto = strings.ToLower(proto)
	in := c.InterfaceByID(ifaceID)
	for _, f := range c.PortForwards {
		if f.Enabled && containsString(f.Interfaces, ifaceID) && protoCovers(f.Protocol, proto) && portSpecHas(c, f.PubPorts, port) {
			return true
		}
	}
	for _, r := range c.Rules {
		if !r.Enabled || r.Action != "allow" || (r.Interface != "" && r.Interface != ifaceID) || !protoCovers(r.Protocol, proto) {
			continue
		}
		if r.DstPorts == "" || proto == "icmp" || portSpecHas(c, r.DstPorts, port) {
			return true
		}
	}
	if proto == "udp" {
		for _, w := range c.Interfaces {
			if w.Kind == "wireguard" && w.WGListenPort == port {
				return true
			}
		}
	}
	if c.Settings.AntiLockout && in != nil && in.Device == c.Settings.MgmtInterface && proto == "tcp" {
		if port == env.SSHPort {
			return true
		}
		for _, p := range env.PortalPorts {
			if p == port {
				return true
			}
		}
	}
	return false
}

// protoCovers: does a rule/forward protocol ("any", "tcpudp", "tcp"…) match
// a packet protocol ("tcp", "udp", "icmp"…)?
func protoCovers(rule, pkt string) bool {
	switch rule {
	case "any":
		return true
	case "tcpudp":
		return pkt == "tcp" || pkt == "udp"
	}
	return rule == pkt
}

// portSpecHas: "443", "80, 8000-8100" or "group:<id>" (a ports group).
func portSpecHas(c *Config, spec string, port int) bool {
	if id, ok := strings.CutPrefix(spec, "group:"); ok {
		g := c.GroupByID(id)
		if g == nil {
			return false
		}
		spec = strings.Join(g.Members, ",")
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			continue
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				continue
			}
		}
		if port >= a && port <= b {
			return true
		}
	}
	return false
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
