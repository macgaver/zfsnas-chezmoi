package system

// Test of a gateway's ping target, before the gateway form may be saved. The
// gateway may not be applied yet, so it has no probe table of its own: the
// pings use a temporary table pointing at that gateway, as the monitor's do.

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"zfsnas/internal/sdn"
)

const (
	sdnTestTable    = 399
	sdnTestRulePrio = 3999
	sdnTestMark     = uint32(0x3ff)
)

var sdnTestMu sync.Mutex

// SDNGatewayTest is what the form shows.
type SDNGatewayTest struct {
	OK     bool    `json:"ok"`
	Target string  `json:"target,omitempty"`
	RTTms  float64 `json:"rtt_ms,omitempty"`
	Error  string  `json:"error,omitempty"`
}

// SDNTestGateway pings target ("" = the default gateway) through the gateway
// made of iface ("port:<device>" for a port not in the Firewall yet) and address.
func SDNTestGateway(c *sdn.Config, iface, address, target string, pings int) SDNGatewayTest {
	if pings < 1 {
		pings = 1
	}
	if pings > sdn.MaxProbePings {
		pings = sdn.MaxProbePings
	}
	fail := func(t, format string, a ...any) SDNGatewayTest {
		return SDNGatewayTest{Target: t, Error: fmt.Sprintf(format, a...)}
	}
	if target != "" && !sdn.IsIPv4(target) {
		return fail("", "%q is not an IPv4 address", target)
	}
	if address != "" && !sdn.IsIPv4(address) {
		return fail("", "The gateway address %q is not an IPv4 address", address)
	}
	t := &sdn.Config{Gateways: []sdn.Gateway{{ID: "test", Interface: iface, Address: address}}}
	name := iface
	if len(iface) > 5 && iface[:5] == "port:" {
		dev := iface[5:]
		if dev != filepath.Base(dev) {
			return fail("", "Unknown interface")
		}
		if _, err := os.Stat(filepath.Join(sdnSysClassNet, dev)); err != nil {
			return fail("", "%s does not exist on this server", dev)
		}
		name = dev
		t.Interfaces = []sdn.Interface{{ID: iface, Name: dev, Kind: "physical", Device: dev}}
	} else {
		in := c.InterfaceByID(iface)
		if in == nil {
			return fail("", "Choose an interface")
		}
		name = in.Name
		t.Interfaces = []sdn.Interface{*in}
	}
	hop, ok := SDNResolveHops(t)["test"]
	if !ok {
		return fail("", "%s is not connected, so it cannot be tested yet. Apply it or wait for it to connect, or save with the test turned off.", name)
	}
	gatewayIP := hop.Via
	if gatewayIP == "" && t.Interfaces[0].Kind == "pppoe" {
		gatewayIP = sdnPPPPeer(hop.Dev)
	}
	if target == "" {
		target = gatewayIP
	}
	if target == "" {
		return fail("", "%s has no default gateway to test. Choose a custom address.", name)
	}

	sdnTestMu.Lock()
	defer sdnTestMu.Unlock()
	cleanup := func() {
		sdnRun.Run(nil, "ip", "rule", "del", "priority", fmt.Sprint(sdnTestRulePrio)) //nolint:errcheck
		sdnRun.Run(nil, "ip", "route", "flush", "table", fmt.Sprint(sdnTestTable))    //nolint:errcheck
	}
	cleanup()
	defer cleanup()
	h := hop
	if _, err := sdnRun.Run(nil, "ip", append(append([]string{"route", "replace", "default"}, hopArgs(&h)...), "table", fmt.Sprint(sdnTestTable))...); err != nil {
		return fail(target, "Could not set up the test: %v", err)
	}
	if _, err := sdnRun.Run(nil, "ip", "rule", "add", "priority", fmt.Sprint(sdnTestRulePrio), "fwmark", fmt.Sprintf("0x%x", sdnTestMark), "lookup", fmt.Sprint(sdnTestTable)); err != nil {
		return fail(target, "Could not set up the test: %v", err)
	}
	answered, rtt := sdnPing(hop.Dev, target, sdnTestMark, pings)
	if !answered {
		return fail(target, "%s did not answer %d ping(s) through %s.", target, pings, name)
	}
	return SDNGatewayTest{OK: true, Target: target, RTTms: float64(rtt/time.Microsecond) / 1000}
}
