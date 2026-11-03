package system

// Local routes (Firewall -> Routing). They live in the main table under a
// routing protocol number of our own, which tells them from every other route
// and lets them be removed without touching the rest. SDNApply writes them and
// the gateway monitor's repair loop keeps them there, so they come back after
// a reboot and whenever a link they use returns.

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"zfsnas/internal/sdn"
)

const sdnRouteProto = "76" // unassigned in rt_protos (187 prints as "isis")

// SDNRoute is a route as the kernel reports it.
type SDNRoute struct {
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway,omitempty"`
	Dev      string `json:"dev"`
	Metric   int    `json:"metric,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Scope    string `json:"scope,omitempty"`
	// Source: the /etc/network/interfaces stanza that also writes this route.
	Source string `json:"source,omitempty"`
}

// sdnInterfacesFile and sdnUptime are variables for the tests.
var sdnInterfacesFile = "/etc/network/interfaces"

var sdnUptime = func() float64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 1 << 30
	}
	var up float64
	fmt.Sscanf(string(b), "%f", &up)
	return up
}

// sdnBootSettle: ifupdown runs "ip route add" lines during boot and gives up on
// the rest of a stanza when one fails, so a route that file also writes is left
// to the file for this long.
const sdnBootSettle = 180

// sdnFileRoute is a route /etc/network/interfaces writes at boot.
type sdnFileRoute struct{ Dst, Via, Dev, Stanza string }

// sdnFileRoutes reads the "gateway" lines and the "ip route add|replace" hooks.
// The file stays the admin's: it is only read.
func sdnFileRoutes() []sdnFileRoute {
	b, err := os.ReadFile(sdnInterfacesFile)
	if err != nil {
		return nil
	}
	var out []sdnFileRoute
	stanza := ""
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		switch f[0] {
		case "iface":
			if len(f) > 1 {
				stanza = f[1]
			}
		case "auto", "allow-hotplug", "mapping", "source", "source-directory":
			stanza = ""
		case "gateway":
			if stanza != "" && len(f) > 1 {
				out = append(out, sdnFileRoute{Dst: "default", Via: f[1], Dev: stanza, Stanza: stanza})
			}
		case "up", "post-up":
			if r, ok := sdnParseRouteHook(f[1:], stanza); ok {
				out = append(out, r)
			}
		}
	}
	return out
}

// sdnParseRouteHook reads "ip route add|replace DST [via X] [dev Y]".
func sdnParseRouteHook(f []string, stanza string) (sdnFileRoute, bool) {
	if stanza == "" || len(f) < 4 || !strings.HasSuffix(f[0], "ip") || f[1] != "route" || (f[2] != "add" && f[2] != "replace") {
		return sdnFileRoute{}, false
	}
	dst := f[3]
	if dst != "default" {
		d, ok := sdn.CanonicalRouteDest(dst)
		if !ok {
			return sdnFileRoute{}, false
		}
		dst = d
	}
	r := sdnFileRoute{Dst: dst, Dev: stanza, Stanza: stanza}
	for i := 4; i+1 < len(f); i += 2 {
		switch f[i] {
		case "via":
			r.Via = f[i+1]
		case "dev":
			r.Dev = f[i+1]
		case "metric":
			if f[i+1] != "0" { // only the plain form is restored or matched
				return sdnFileRoute{}, false
			}
		default:
			if strings.HasPrefix(f[i], "|") {
				return r, true
			}
			return sdnFileRoute{}, false
		}
	}
	return r, true
}

// sdnKernelDest is how the kernel prints a canonical destination.
func sdnKernelDest(dst string) string {
	if dst == "0.0.0.0/0" {
		return "default"
	}
	return dst
}

// sdnKernelRoutes lists the main table's IPv4 routes (only ours with proto).
func sdnKernelRoutes(proto string) ([]SDNRoute, error) {
	args := []string{"-4", "-j", "route", "show"}
	if proto != "" {
		args = append(args, "proto", proto)
	}
	out, err := sdnRun.Run(nil, "ip", args...)
	if err != nil {
		return nil, err
	}
	var rs []SDNRoute
	if len(out) > 0 {
		if err := json.Unmarshal(out, &rs); err != nil {
			return nil, err
		}
	}
	return rs, nil
}

// SDNRoutesLive is the main table now, for the Routing page.
func SDNRoutesLive() ([]SDNRoute, error) {
	rs, err := sdnKernelRoutes("")
	file := sdnFileRoutes()
	for i := range rs {
		if rs[i].Protocol == sdnRouteProto {
			rs[i].Protocol = "znas"
		}
		if rs[i].Metric != 0 {
			continue
		}
		for _, f := range file {
			if f.Dst == rs[i].Dst {
				rs[i].Source = f.Stanza
				break
			}
		}
	}
	return rs, err
}

func sdnRouteKey(dst, via, dev string, metric int) string {
	return fmt.Sprintf("%s|%s|%s|%d", dst, via, dev, metric)
}

// SDNSyncStaticRoutes makes our routes match c. A route on a link that is not
// there now is left for the next pass; what cannot be written is returned, and
// everything else is still done.
func SDNSyncStaticRoutes(c *sdn.Config) []error {
	want, wantDest := map[string]bool{}, map[string]bool{}
	for _, r := range c.Routes {
		in := c.InterfaceByID(r.Interface)
		if !r.Enabled || in == nil || in.Disabled {
			continue
		}
		if dst, ok := sdn.CanonicalRouteDest(r.Destination); ok {
			dst = sdnKernelDest(dst)
			want[sdnRouteKey(dst, r.Via, in.L3Device(), r.Metric)] = true
			wantDest[dst+"/"+strconv.Itoa(r.Metric)] = true
		}
	}
	file := sdnFileRoutes()
	fileRoute := func(dst string) *sdnFileRoute {
		for i := range file {
			if file[i].Dst == dst {
				return &file[i]
			}
		}
		return nil
	}
	cur, err := sdnKernelRoutes(sdnRouteProto)
	if err != nil {
		return []error{err}
	}
	var errs []error
	have := map[string]bool{}
	for _, r := range cur {
		k := sdnRouteKey(r.Dst, r.Gateway, r.Dev, r.Metric)
		if want[k] {
			have[k] = true
			continue
		}
		if _, err := sdnRun.Run(nil, "ip", "route", "del", r.Dst, "proto", sdnRouteProto, "metric", strconv.Itoa(r.Metric)); err != nil {
			errs = append(errs, err)
			continue
		}
		// A route taken over from the system file goes back to what the file
		// says, or a removed default route would leave the server unreachable.
		if f := fileRoute(r.Dst); f != nil && r.Metric == 0 && !wantDest[r.Dst+"/0"] {
			args := []string{"route", "replace", f.Dst}
			if f.Via != "" {
				args = append(args, "via", f.Via)
			}
			if _, err := sdnRun.Run(nil, "ip", append(args, "dev", f.Dev)...); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, r := range c.Routes {
		in := c.InterfaceByID(r.Interface)
		if !r.Enabled || in == nil || in.Disabled {
			continue
		}
		dst, ok := sdn.CanonicalRouteDest(r.Destination)
		dev := in.L3Device()
		dst = sdnKernelDest(dst)
		if !ok || have[sdnRouteKey(dst, r.Via, dev, r.Metric)] {
			continue
		}
		if exists, up := sdnLinkFlags(dev); !exists || !up {
			continue
		}
		if r.Metric == 0 && fileRoute(dst) != nil && sdnUptime() < sdnBootSettle {
			continue
		}
		args := []string{"route", "replace", dst}
		if r.Via != "" {
			args = append(args, "via", r.Via)
		}
		args = append(args, "dev", dev, "proto", sdnRouteProto, "metric", strconv.Itoa(r.Metric))
		if _, err := sdnRun.Run(nil, "ip", args...); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
