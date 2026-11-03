package sdn

import (
	"strings"
	"testing"
)

func disable(c *Config, id string) {
	for i := range c.Interfaces {
		if c.Interfaces[i].ID == id {
			c.Interfaces[i].Disabled = true
		}
	}
}

func hasErr(err error, path string) bool {
	ve, _ := err.(ValidationErrors)
	for _, e := range ve {
		if strings.HasPrefix(e.Path, path) {
			return true
		}
	}
	return false
}

// The settings stay, the setting survives a reload, and an interface is on
// unless told otherwise (every config saved before this field existed).
func TestDisabled_DefaultsOnAndKeepsSettings(t *testing.T) {
	c := ownerSample()
	if c.Interfaces[1].Disabled {
		t.Fatal("on by default")
	}
	disable(c, "if000400")
	c.Normalize()
	in := c.InterfaceByID("if000400")
	if !in.Disabled || in.IPv4 != "10.128.4.1/24" || in.VLANTag != 400 {
		t.Fatalf("%+v", in)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDisabled_RefusesTheManagementInterface(t *testing.T) {
	c := ownerSample()
	disable(c, "if000001")
	if err := c.Validate(); !hasErr(err, "interfaces[0].disabled") {
		t.Fatalf("%v", err)
	}
}

func TestDisabled_RefusesAPortAnEnabledVLANRunsOn(t *testing.T) {
	c := ownerSample()
	c.Interfaces = append(c.Interfaces, Interface{ID: "ifparent", Name: "Trunk", Kind: "physical", Device: "enp2s0", Role: "lan", IPv4Mode: "none"})
	c.Normalize()
	disable(c, "ifparent")
	if err := c.Validate(); !hasErr(err, "interfaces[5].disabled") {
		t.Fatalf("%v", err)
	}
	// with its VLANs off too, it is fine
	for _, id := range []string{"if000400", "if000500", "if000700", "if000800"} {
		disable(c, id)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDisabled_RefusesATunnel(t *testing.T) {
	c := servicesSample()
	for i, in := range c.Interfaces {
		if in.Kind == "wireguard" {
			c.Interfaces[i].Disabled = true
			if err := c.Validate(); !hasErr(err, "interfaces") {
				t.Fatalf("%v", err)
			}
			return
		}
	}
	t.Skip("no tunnel in the sample")
}

func TestDisabled_NoStanza(t *testing.T) {
	c := ownerSample()
	disable(c, "if000400")
	got := SpliceOwned("auto lo\n", c.Interfaces)
	if strings.Contains(got, "if000400") || !strings.Contains(got, "id=if000500") {
		t.Fatal(got)
	}
}

func TestDisabled_NoDHCPServer(t *testing.T) {
	c := servicesSample()
	id := c.DHCP[0].Interface
	before := len(RenderDHCP(c, "/l"))
	disable(c, id)
	got := RenderDHCP(c, "/l")
	if len(got) != before-1 {
		t.Fatalf("%d → %d", before, len(got))
	}
	if _, ok := got[id]; ok {
		t.Fatal("server still rendered")
	}
}

func TestDisabled_DNSStopsListening(t *testing.T) {
	c := servicesSample()
	c.DNS.Enabled = true
	in := c.InterfaceByID(c.DNS.Interfaces[0])
	dev := in.L3Device()
	c.DNS.Interfaces = c.DNS.Interfaces[:1]
	disable(c, in.ID)
	// with no interface listed dnsmasq would listen on every one
	if got := RenderDNS(c, dnsPaths); got != "" {
		t.Fatalf("%s must not get DNS:\n%s", dev, got)
	}
}

func TestDisabled_IDSDoesNotWatchIt(t *testing.T) {
	c := ownerSample()
	c.IDS.Interfaces = []string{"if000400", "if000500"}
	disable(c, "if000400")
	if got := strings.Join(c.IDSDevices(), ","); strings.Contains(got, "v400") || got == "" {
		t.Fatal(got)
	}
}

func TestDisabled_DDNSSkipsItsGateway(t *testing.T) {
	c := ownerSample()
	c.Gateways = []Gateway{{ID: "gw000001", Name: "ISP", Interface: "if000400", Priority: 1}}
	c.DDNS = []DDNSEntry{{ID: "dd000001", Enabled: true, Provider: "duckdns", Gateway: "gw000001", Hostnames: []string{"a.duckdns.org"}}}
	if RenderDDClient(c) == "" {
		t.Skip("entry not rendered in this shape")
	}
	disable(c, "if000400")
	if got := RenderDDClient(c); got != "" {
		t.Fatal(got)
	}
}

func TestDisabled_SummaryNamesIt(t *testing.T) {
	prev, next := ownerSample(), ownerSample()
	disable(next, "if000400")
	if got := Summarize(prev, next); !strings.Contains(got, "interface VLAN400 disabled") {
		t.Fatal(got)
	}
	if got := Summarize(next, prev); !strings.Contains(got, "interface VLAN400 enabled") {
		t.Fatal(got)
	}
}

// The only WAN disabled: intrusion detection has nothing to watch for now.
// Not an error; it stays on and resumes with the interface.
func TestDisabled_OnlyWANLeavesIDSIdle(t *testing.T) {
	c := idsSample()
	for i := range c.Interfaces {
		if c.Interfaces[i].Role == "wan" {
			c.Interfaces[i].Disabled = true
		}
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.IDS.Enabled || c.IDSRuns() {
		t.Fatalf("enabled %v runs %v", c.IDS.Enabled, c.IDSRuns())
	}
	for i := range c.Interfaces {
		c.Interfaces[i].Disabled = false
	}
	if !c.IDSRuns() {
		t.Fatal("does not resume")
	}
}

// What is refused without force goes through with it.
func TestDisabled_ForceAllowsManagementAndParent(t *testing.T) {
	c := ownerSample()
	disable(c, "if000001")
	c.Interfaces[0].DisableForced = true
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c = ownerSample()
	c.Interfaces = append(c.Interfaces, Interface{ID: "ifparent", Name: "Trunk", Kind: "physical", Device: "enp2s0", Role: "lan", IPv4Mode: "none"})
	c.Normalize()
	disable(c, "ifparent")
	c.Interfaces[5].DisableForced = true
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDisabled_ForceDoesNotCoverATunnel(t *testing.T) {
	c := servicesSample()
	for i, in := range c.Interfaces {
		if in.Kind == "wireguard" {
			c.Interfaces[i].Disabled, c.Interfaces[i].DisableForced = true, true
		}
	}
	if err := c.Validate(); !hasErr(err, "interfaces") {
		t.Fatalf("%v", err)
	}
}

// Enabled again, the force does not linger for the next time.
func TestDisabled_ForceClearedWhenEnabled(t *testing.T) {
	c := ownerSample()
	c.Interfaces[0].DisableForced = true
	c.Normalize()
	if c.Interfaces[0].DisableForced {
		t.Fatal("kept")
	}
}

func TestRemapDevicesAndNeededCoverPPPoEAndTunnels(t *testing.T) {
	c := DefaultConfig()
	c.Interfaces = []Interface{
		{ID: "a", Kind: "physical", Device: "eth0"},
		{ID: "b", Kind: "pppoe", Device: "ppp0", Parent: "eth1"},
		{ID: "c", Kind: "wireguard", Device: "wg-c"},
		{ID: "d", Kind: "vlan", Parent: "eth2", VLANTag: 7},
	}
	got := DevicesNeeded(c)
	if strings.Join(got, ",") != "eth0,eth1,eth2" {
		t.Fatalf("needed = %v: tunnels and PPPoE devices are created here, only their parents must exist", got)
	}
	out := RemapDevices(c, map[string]string{"eth1": "enp1s0"})
	if p := out.InterfaceByID("b").Parent; p != "enp1s0" {
		t.Fatalf("PPPoE parent = %q", p)
	}
}
