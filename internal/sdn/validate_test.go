package sdn

import (
	"encoding/json"
	"strings"
	"testing"
)

// ownerSample mirrors the layout of the owner's current router: the untagged
// LAN plus four VLANs on one trunk port.
func ownerSample() *Config {
	c := &Config{
		Version:  1,
		Settings: Settings{Mode: "router", MgmtInterface: "enp1s0", AntiLockout: true},
		Interfaces: []Interface{
			{ID: "if000001", Name: "VLAN192", Kind: "physical", Device: "enp1s0", Role: "lan", IPv4Mode: "static", IPv4: "192.168.2.254/24"},
			{ID: "if000400", Name: "VLAN400", Kind: "vlan", Parent: "enp2s0", VLANTag: 400, Role: "lan", IPv4Mode: "static", IPv4: "10.128.4.1/24", Owned: true},
			{ID: "if000500", Name: "VLAN500", Kind: "vlan", Parent: "enp2s0", VLANTag: 500, Role: "lan", IPv4Mode: "static", IPv4: "10.128.5.1/24", Owned: true},
			{ID: "if000700", Name: "VLAN700", Kind: "vlan", Parent: "enp2s0", VLANTag: 700, Role: "lan", IPv4Mode: "static", IPv4: "10.128.7.1/24", Owned: true},
			{ID: "if000800", Name: "VLAN800", Kind: "vlan", Parent: "enp2s0", VLANTag: 800, Role: "lan", IPv4Mode: "static", IPv4: "10.128.8.1/24", Owned: true, AllowVMs: true},
		},
		Groups: []Group{
			{ID: "g0000001", Name: "ALXInternalSubnets", Kind: "hosts", Members: []string{"10.0.0.0/8", "192.168.0.0/16"}},
			{ID: "g0000002", Name: "game", Kind: "ports", Members: []string{"16261-16263"}},
		},
		Rules: []Rule{
			{ID: "r0000001", Enabled: true, Interface: "if000700", Action: "allow", Protocol: "tcp",
				Source: Endpoint{Type: "iface_net", Value: "if000700"}, Destination: Endpoint{Type: "cidr", Value: "10.128.8.4"},
				DstPorts: "3008", Description: "proxy homepage"},
			{ID: "r0000002", Enabled: true, Interface: "if000700", Action: "reject", Protocol: "any",
				Source: Endpoint{Type: "any"}, Destination: Endpoint{Type: "any"}, Description: "DROP ALL 700"},
		},
	}
	c.Normalize()
	return c
}

func onlyErr(t *testing.T, c *Config) FieldError {
	t.Helper()
	err := c.Validate()
	if err == nil {
		t.Fatalf("expected a validation error, got nil")
	}
	ve, ok := err.(ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T: %v", err, err)
	}
	if len(ve) != 1 {
		t.Fatalf("expected exactly 1 error, got %d: %v", len(ve), ve)
	}
	return ve[0]
}

func TestValidate_OwnerSampleOK(t *testing.T) {
	if err := ownerSample().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidate_Cases(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *Config)
		path   string
	}{
		{"ipv6 address", func(c *Config) { c.Interfaces[0].IPv4 = "2001:db8::1/64" }, "interfaces[0].ipv4"},
		{"vlan tag 0", func(c *Config) { c.Interfaces[1].VLANTag = 0 }, "interfaces[1].vlan_tag"},
		{"vlan tag 4095", func(c *Config) { c.Interfaces[1].VLANTag = 4095 }, "interfaces[1].vlan_tag"},
		{"duplicate parent+tag", func(c *Config) { c.Interfaces[2].VLANTag = 400; c.Interfaces[2].IPv4 = "10.128.99.1/24" }, "interfaces[2].vlan_tag"},
		{"overlapping networks", func(c *Config) { c.Interfaces[2].IPv4 = "10.128.4.2/24" }, "interfaces[2].ipv4"},
		{"missing group", func(c *Config) { c.Rules[0].Source = Endpoint{Type: "group", Value: "gdeleted"} }, "rules[0].source"},
		{"deleted interface", func(c *Config) { c.Rules[0].Interface = "ifgone00" }, "rules[0].interface"},
		{"ports with protocol any", func(c *Config) { c.Rules[1].DstPorts = "443" }, "rules[1].dst_ports"},
		{"ports with icmp", func(c *Config) { c.Rules[0].Protocol = "icmp" }, "rules[0].dst_ports"},
		{"reversed range", func(c *Config) { c.Rules[0].DstPorts = "200-100" }, "rules[0].dst_ports"},
		{"group name with space", func(c *Config) { c.Groups[0].Name = "bad name" }, "groups[0].name"},
		{"bad cidr member", func(c *Config) { c.Groups[0].Members[0] = "10.0.0.0/33" }, "groups[0].members[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := ownerSample()
			tc.mutate(c)
			c.Normalize()
			fe := onlyErr(t, c)
			if fe.Path != tc.path {
				t.Fatalf("path = %q, want %q (msg %q)", fe.Path, tc.path, fe.Message)
			}
		})
	}
}

func TestValidate_MissingGroupMessageNamesRule(t *testing.T) {
	c := ownerSample()
	c.Rules[0].Source = Endpoint{Type: "group", Value: "gdeleted"}
	fe := onlyErr(t, c)
	if !strings.Contains(fe.Message, "proxy homepage") {
		t.Fatalf("message %q does not name the rule", fe.Message)
	}
}

func TestNormalize_VLANDeviceName(t *testing.T) {
	c := &Config{Interfaces: []Interface{{ID: "a", Kind: "vlan", Parent: "enx00e04c680a1b", VLANTag: 800}}}
	c.Normalize()
	if got := c.Interfaces[0].Device; got != "enx00e04c6-v800" {
		t.Fatalf("device = %q, want enx00e04c6-v800", got)
	}
}

func TestNewID(t *testing.T) {
	a, b := NewID(), NewID()
	if len(a) != 8 || a == b || strings.Trim(a, "0123456789abcdef") != "" {
		t.Fatalf("bad ids %q %q", a, b)
	}
}

func TestNormalize_EmptyListsMarshalAsArrays(t *testing.T) {
	c := DefaultConfig()
	c.Groups = []Group{{ID: "g", Name: "x", Kind: "hosts"}}
	c.Normalize()
	b, _ := json.Marshal(c)
	for _, want := range []string{`"interfaces":[]`, `"rules":[]`, `"members":[]`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("%s missing in %s", want, b)
		}
	}
}

func TestValidate_NamesAndIDs(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *Config)
		path   string
	}{
		{"newline in parent", func(c *Config) { c.Interfaces[1].Parent = "enp2s0\n    pre-up touch /tmp/x" }, "interfaces[1].parent"},
		{"device with space", func(c *Config) { c.Interfaces[0].Device = "enp1s0 x" }, "interfaces[0].device"},
		{"device too long", func(c *Config) { c.Interfaces[0].Device = "abcdefghijklmnop" }, "interfaces[0].device"},
		{"device dotdot", func(c *Config) { c.Interfaces[0].Device = ".." }, "interfaces[0].device"},
		{"interface id with dash", func(c *Config) { c.Interfaces[2].ID = "if-500" }, "interfaces[2].id"},
		{"group id with quote", func(c *Config) { c.Groups[1].ID = `g"x` }, "groups[1].id"},
		{"rule id uppercase", func(c *Config) { c.Rules[1].ID = "R1" }, "rules[1].id"},
		{"mgmt with newline", func(c *Config) { c.Settings.MgmtInterface = "enp1s0\nkernel.x=1" }, "settings.mgmt_interface"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := ownerSample()
			tc.mutate(c)
			c.Normalize()
			fe := onlyErr(t, c)
			if fe.Path != tc.path {
				t.Fatalf("path = %q, want %q (%s)", fe.Path, tc.path, fe.Message)
			}
		})
	}
}

func TestAddStarterRules(t *testing.T) {
	c := ownerSample()
	c.Rules = nil
	c.Interfaces[0].Role = "wan"
	AddStarterRules(c)
	if len(c.Rules) != 4 { // the 4 LAN VLANs, not the WAN
		t.Fatalf("got %d starter rules", len(c.Rules))
	}
	for _, r := range c.Rules {
		if r.Action != "allow" || r.Source.Type != "any" || r.Destination.Type != "any" || r.Interface == "if000001" {
			t.Fatalf("bad starter rule %+v", r)
		}
	}
	AddStarterRules(c)
	if len(c.Rules) != 4 {
		t.Fatal("starter rules must not be added twice")
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidate_IncusKind(t *testing.T) {
	c := ownerSample()
	c.Interfaces = append(c.Interfaces, Interface{ID: "ifincus1", Name: "VMs 900", Kind: "incus", Device: "vmbr0-900", Role: "lan", IPv4Mode: "static", IPv4: "10.128.9.1/24"})
	c.Normalize()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Interfaces[5].L3Device() != "vmbr0-900" {
		t.Fatal("incus bridge is its own L3 device")
	}
	c.Interfaces[5].IPv4Mode, c.Interfaces[5].IPv4 = "dhcp", ""
	if fe := onlyErr(t, c); fe.Path != "interfaces[5].ipv4_mode" {
		t.Fatalf("incus bridges take static or none, got %v", fe)
	}
}

func TestOwnedIfaces(t *testing.T) {
	ifs := labVLANs()
	got := OwnedIfaces(SpliceOwned(baseInterfaces, ifs))
	want := []string{"enp7s0-v700", "enp7s0-v800", "br-enp7s0-v800"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v", got)
	}
}

func TestValidateRoutes(t *testing.T) {
	base := func() *Config {
		c := &Config{Version: 1, Settings: Settings{Mode: "monitor"}, Interfaces: []Interface{{ID: "if000001", Name: "LAN", Color: "#0a84ff", Kind: "physical", Device: "eth0", Role: "lan", IPv4Mode: "static", IPv4: "192.168.1.1/24"}}}
		return c
	}
	for _, tc := range []struct {
		name string
		r    StaticRoute
		want string
	}{
		{"ok", StaticRoute{ID: "r1", Destination: "10.0.0.0/8", Via: "192.168.1.9", Interface: "if000001"}, ""},
		{"address", StaticRoute{ID: "r1", Destination: "10.0.0.1", Interface: "if000001"}, ""},
		{"default", StaticRoute{ID: "r1", Enabled: true, Destination: "0.0.0.0/0", Via: "192.168.1.9", Interface: "if000001"}, ""},
		{"bad destination", StaticRoute{ID: "r1", Destination: "10.0.0.0/8 x", Interface: "if000001"}, "not an IPv4"},
		{"via outside", StaticRoute{ID: "r1", Destination: "10.0.0.0/8", Via: "172.16.0.1", Interface: "if000001"}, "inside"},
		{"no interface", StaticRoute{ID: "r1", Destination: "10.0.0.0/8"}, "interface"},
		{"metric", StaticRoute{ID: "r1", Destination: "10.0.0.0/8", Interface: "if000001", Metric: -1}, "metric"},
	} {
		c := base()
		c.Routes = []StaticRoute{tc.r}
		err := c.Validate()
		if tc.want == "" && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	c := base()
	c.Routes = []StaticRoute{{ID: "r1", Destination: "10.0.0.0/8", Interface: "if000001"}, {ID: "r2", Destination: "10.1.2.3/8", Interface: "if000001"}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("duplicate: %v", err)
	}
	c = base()
	c.Gateways = []Gateway{{ID: "gw000001", Name: "G", Interface: "if000001", Priority: 1, ProbeEvery: 1}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "2 to 3600") {
		t.Errorf("interval: %v", err)
	}
}

// With no gateway the default route may be a local route; with one, the
// gateway monitor owns it.
func TestDefaultLocalRouteOnlyWithoutGateways(t *testing.T) {
	c := ownerSample()
	id := c.Interfaces[0].ID
	c.Gateways = nil
	c.Routes = []StaticRoute{{ID: "r1", Enabled: true, Destination: "default", Interface: id}}
	if err := c.Validate(); err != nil && strings.Contains(err.Error(), "routes[0]") {
		t.Fatalf("no gateway: %v", err)
	}
	c.Gateways = []Gateway{{ID: "g1", Name: "g", Interface: id, Priority: 1}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "belongs to the gateways") {
		t.Fatalf("default route accepted next to a gateway: %v", err)
	}
}
