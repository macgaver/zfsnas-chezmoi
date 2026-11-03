package sdn

// Local routes (Firewall -> Routing): validation and the form the kernel
// reports them in. system/sdn_static_routes.go keeps them in the routing table.

import (
	"fmt"
	"net/netip"
)

// MaxProbePings bounds one gateway test: pings are 0.5 s apart and the monitor
// waits for the test to finish.
const MaxProbePings = 10

// IsIPv4 reports whether s is one plain IPv4 address.
func IsIPv4(s string) bool { return plainIPv4(s) }

func plainIPv4(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}

// CanonicalRouteDest normalizes a destination the way "ip route" prints it:
// host bits cleared, and a single address without "/32".
func CanonicalRouteDest(s string) (string, bool) {
	if s == "default" {
		return "0.0.0.0/0", true
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
		return a.String(), true
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() {
		return "", false
	}
	if p.Bits() == 32 {
		return p.Addr().String(), true
	}
	return p.Masked().String(), true
}

func (c *Config) validateRoutes(add func(path, format string, a ...any)) {
	seen := map[string]bool{}
	for i, r := range c.Routes {
		p := fmt.Sprintf("routes[%d]", i)
		dest, ok := CanonicalRouteDest(r.Destination)
		in := c.InterfaceByID(r.Interface)
		key := fmt.Sprintf("%s/%d", dest, r.Metric)
		switch {
		case !idRe.MatchString(r.ID):
			add(p+".id", "invalid id")
		case !ok:
			add(p+".destination", "%q is not an IPv4 network or address, such as 10.20.0.0/16", r.Destination)
		case dest == "0.0.0.0/0" && r.Enabled && len(c.Gateways) > 0:
			add(p+".destination", "The default route belongs to the gateways while there are any: change it on the gateway")
		case seen[key]:
			add(p+".destination", "%s already has a route with metric %d: give one of them another metric", dest, r.Metric)
		case in == nil:
			add(p+".interface", "Choose the interface that leads to this network")
		case r.Via != "" && !gatewayInNet(*in, r.Via):
			add(p+".via", "%s is not an IPv4 address inside %s's network", r.Via, in.Name)
		case r.Metric < 0 || r.Metric > 65535:
			add(p+".metric", "The metric is a number from 0 to 65535")
		case len(r.Description) > 80:
			add(p+".description", "The description is limited to 80 characters")
		}
		seen[key] = true
	}
}
