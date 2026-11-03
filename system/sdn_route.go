package system

// Policy routing for the Firewall's gateways (spec §7): ip rules sending
// marked connections to per-gateway tables, and the routes in those tables
// and the main default — written by SDNApply and owned at run time by the
// gateway monitor daemon (zfsnas -sdn-gwmon), which moves them on failover.

import (
	"encoding/json"
	"fmt"
	"strings"

	"zfsnas/internal/sdn"
)

// SDNSyncRules makes the ip rules match the config: the suppress rule
// (inside destinations keep using the main table) and two fwmark rules per
// gateway. Stale rules from more gateways before are removed.
func SDNSyncRules(c *sdn.Config) error {
	out, _ := sdnRun.Run(nil, "ip", "-j", "rule", "show")
	var rules []struct {
		Priority int `json:"priority"`
	}
	_ = json.Unmarshal(out, &rules)
	for _, r := range rules {
		if r.Priority == 999 || (r.Priority >= 1000 && r.Priority < 4000) {
			sdnRun.Run(nil, "ip", "rule", "del", "priority", fmt.Sprint(r.Priority)) //nolint:errcheck
		}
	}
	if len(c.Gateways) == 0 {
		return nil
	}
	if _, err := sdnRun.Run(nil, "ip", "rule", "add", "priority", "999", "lookup", "main", "suppress_prefixlength", "0"); err != nil {
		return err
	}
	for i := range c.Gateways {
		if _, err := sdnRun.Run(nil, "ip", "rule", "add", "priority", fmt.Sprint(3000+i), "fwmark", fmt.Sprintf("0x%x", sdn.ProbeMark(i)),
			"lookup", fmt.Sprint(sdn.ProbeTable(i))); err != nil {
			return err
		}
		for _, only := range []bool{false, true} {
			prio := 1000 + i
			if only {
				prio = 2000 + i
			}
			if _, err := sdnRun.Run(nil, "ip", "rule", "add", "priority", fmt.Sprint(prio), "fwmark", fmt.Sprintf("0x%x", sdn.GatewayMark(i, only)),
				"lookup", fmt.Sprint(sdn.GatewayTable(i, only))); err != nil {
				return err
			}
		}
	}
	return nil
}

func hopArgs(h *sdn.Hop) []string {
	if h.Via == "" {
		return []string{"dev", h.Dev}
	}
	return []string{"via", h.Via, "dev", h.Dev}
}

// SDNApplyRoutes writes a route plan. Errors are logged by the caller's
// next cycle; a route that cannot be set now is retried then.
func SDNApplyRoutes(p sdn.RoutePlan) []error {
	var errs []error
	run := func(args ...string) {
		if _, err := sdnRun.Run(nil, "ip", args...); err != nil {
			errs = append(errs, err)
		}
	}
	if p.Default != nil {
		run(append(append([]string{"route", "replace", "default"}, hopArgs(p.Default)...), "metric", "0")...)
	} else if p.LastResort != nil && SDNDefaultRoute() == "" {
		run(append(append([]string{"route", "replace", "default"}, hopArgs(p.LastResort)...), "metric", "0")...)
	}
	tables := make([]int, 0, len(p.Tables))
	for t := range p.Tables {
		tables = append(tables, t)
	}
	for _, t := range tables {
		if h := p.Tables[t]; h != nil {
			run(append(append([]string{"route", "replace", "default"}, hopArgs(h)...), "table", fmt.Sprint(t))...)
		} else {
			run("route", "replace", "unreachable", "default", "table", fmt.Sprint(t))
		}
	}
	return errs
}

// SDNResolveHops finds each gateway's current next hop: the configured
// address, the PPPoE device itself (point to point), or the DHCP lease's
// router (the client's default route on that device).
func SDNResolveHops(c *sdn.Config) map[string]sdn.Hop {
	hops := map[string]sdn.Hop{}
	for _, g := range c.Gateways {
		in := c.InterfaceByID(g.Interface)
		if in == nil || in.Disabled {
			continue
		}
		dev := in.L3Device()
		switch {
		case g.Address != "":
			hops[g.ID] = sdn.Hop{Via: g.Address, Dev: dev}
		case in.Kind == "pppoe":
			if _, err := sdnRun.Run(nil, "ip", "link", "show", dev); err == nil {
				hops[g.ID] = sdn.Hop{Dev: dev}
			}
		default:
			out, _ := sdnRun.Run(nil, "ip", "-4", "-j", "route", "show", "default", "dev", dev)
			var rs []struct {
				Gateway string `json:"gateway"`
			}
			if json.Unmarshal(out, &rs) == nil {
				for _, r := range rs {
					if r.Gateway != "" {
						hops[g.ID] = sdn.Hop{Via: r.Gateway, Dev: dev}
						break
					}
				}
			}
		}
	}
	return hops
}

// sdnGatewayIfaceAddr returns the IPv4 address of a gateway's interface (to
// flush connections NATed behind it when it goes down).
func sdnGatewayIfaceAddr(dev string) string {
	out, _ := sdnRun.Run(nil, "ip", "-4", "-j", "addr", "show", "dev", dev)
	var ifs []struct {
		AddrInfo []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(out, &ifs) == nil {
		for _, i := range ifs {
			for _, a := range i.AddrInfo {
				if a.Local != "" {
					return a.Local
				}
			}
		}
	}
	return ""
}

// SDNDefaultRoute is the main table's IPv4 default route as ip arguments
// ("via 192.168.2.254 dev enp5s0"), recorded at enable so disable can put
// it back once the gateway monitor no longer owns it.
func SDNDefaultRoute() string {
	out, _ := sdnRun.Run(nil, "ip", "-4", "-j", "route", "show", "default")
	var rs []struct {
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
	}
	if json.Unmarshal(out, &rs) != nil || len(rs) == 0 || rs[0].Dev == "" {
		return ""
	}
	if rs[0].Gateway == "" {
		return "dev " + rs[0].Dev
	}
	return "via " + rs[0].Gateway + " dev " + rs[0].Dev
}

// sdnUndoRouting removes the policy routing (disable): our ip rules, the
// per-gateway tables, and puts the pre-Firewall default route back.
func sdnUndoRouting(c *sdn.Config, preDefault string) {
	_ = SDNSyncRules(&sdn.Config{})
	SDNSyncStaticRoutes(&sdn.Config{}) //nolint:errcheck
	if c != nil {
		for i := range c.Gateways {
			for _, t := range []int{sdn.GatewayTable(i, false), sdn.GatewayTable(i, true), sdn.ProbeTable(i)} {
				sdnRun.Run(nil, "ip", "route", "flush", "table", fmt.Sprint(t)) //nolint:errcheck
			}
		}
	}
	if preDefault != "" {
		sdnRun.Run(nil, "ip", append([]string{"route", "replace", "default"}, strings.Fields(preDefault)...)...) //nolint:errcheck
	}
}
