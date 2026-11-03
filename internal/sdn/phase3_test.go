package sdn

import (
	"encoding/json"
	"strings"
	"testing"
)

// twoWAN: the owner's shape — PPPoE on the trunk + the Bell router on the LAN.
func twoWAN() *Config {
	c := ownerSample()
	c.Interfaces = append(c.Interfaces,
		Interface{ID: "ifpppoe1", Name: "BELL PPPoE", Kind: "pppoe", Parent: "enp2s0", Role: "wan", IPv4Mode: "pppoe",
			PPPoEUser: "b1xexd57", PPPoEPassword: "secret", Owned: true})
	c.Gateways = []Gateway{
		{ID: "gwpppoe1", Name: "BELL PPPoE", Interface: "ifpppoe1", Priority: 1, Monitor: true},
		{ID: "gwrouter", Name: "BELL Router", Interface: "if000001", Address: "192.168.2.1", Priority: 2, Monitor: true},
	}
	c.PortForwards = []PortForward{{ID: "pf000001", Enabled: true, Interfaces: []string{"ifpppoe1"}, Protocol: "tcp", PubPorts: "52400",
		Source: Endpoint{Type: "any"}, Target: "10.128.8.8", TargetPorts: "32400", Description: "Plex"}}
	c.SNATRules = []SNATRule{{ID: "sn000001", Enabled: true, Source: Endpoint{Type: "iface_net", Value: "if000500"},
		Destination: Endpoint{Type: "any"}, Protocol: "any", Gateway: "gwrouter", Translate: "iface", Description: "VLAN500 via router"}}
	c.Normalize()
	return c
}

func TestPhase3_Valid(t *testing.T) {
	if err := twoWAN().Validate(); err != nil {
		t.Fatal(err)
	}
	if d := twoWAN().InterfaceByID("ifpppoe1").Device; d != "ppp-ifpppoe1" {
		t.Fatalf("pppoe device %q", d)
	}
}

func TestPhase3_ValidationCases(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *Config)
		path   string
	}{
		{"gateway on missing iface", func(c *Config) { c.Gateways[0].Interface = "nope" }, "gateways[0].interface"},
		{"static gw outside net", func(c *Config) { c.Gateways[1].Address = "10.9.9.9" }, "gateways[1].address"},
		{"duplicate priority", func(c *Config) { c.Gateways[1].Priority = 1 }, "gateways[1].priority"},
		{"pppoe without user", func(c *Config) { c.Interfaces[5].PPPoEUser = "" }, "interfaces[5].pppoe_user"},
		{"pppoe bad parent", func(c *Config) { c.Interfaces[5].Parent = "bad name" }, "interfaces[5].parent"},
		{"forward bad target", func(c *Config) { c.PortForwards[0].Target = "plex" }, "port_forwards[0].target"},
		{"forward bad port", func(c *Config) { c.PortForwards[0].PubPorts = "70000" }, "port_forwards[0].pub_ports"},
		{"forward no interface", func(c *Config) { c.PortForwards[0].Interfaces = nil }, "port_forwards[0].interfaces"},
		{"forward port count mismatch", func(c *Config) { c.PortForwards[0].PubPorts = "100-110"; c.PortForwards[0].TargetPorts = "200-205" }, "port_forwards[0].target_ports"},
		{"forward shifted range", func(c *Config) { c.PortForwards[0].PubPorts = "100-110"; c.PortForwards[0].TargetPorts = "200-210" }, "port_forwards[0].target_ports"},
		{"snat needs gateway with 2 gws", func(c *Config) { c.SNATRules[0].Gateway = "" }, "snat_rules[0].gateway"},
		{"snat ip translate", func(c *Config) { c.SNATRules[0].Translate = "ip"; c.SNATRules[0].TranslateIP = "x" }, "snat_rules[0].translate_ip"},
		{"rule unknown gateway", func(c *Config) { c.Rules[0].Gateway = "gwnope" }, "rules[0].gateway"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := twoWAN()
			tc.mutate(c)
			c.Normalize()
			fe := onlyErr(t, c)
			if fe.Path != tc.path {
				t.Fatalf("path %q, want %q (%s)", fe.Path, tc.path, fe.Message)
			}
		})
	}
}

// An instance forward without interface is paused, not invalid (owner).
func TestPhase3_PausedInstanceForward(t *testing.T) {
	c := twoWAN()
	c.PortForwards = append(c.PortForwards, PortForward{ID: "pfinst01", Enabled: true, Instance: "vm-plex", NIC: "eth0", Protocol: "tcp",
		PubPorts: "8080", Target: "10.66.0.15", TargetPorts: "80"})
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.PortForwards[1].Paused() {
		t.Fatal("instance forward with no interface must be paused")
	}
}

func TestPhase3_SecretsRedacted(t *testing.T) {
	c := twoWAN()
	r := c.Redacted()
	in := r.InterfaceByID("ifpppoe1")
	if in.PPPoEPassword != "" || !in.PPPoEPasswordSet {
		t.Fatalf("%+v", in)
	}
	if c.InterfaceByID("ifpppoe1").PPPoEPassword != "secret" {
		t.Fatal("Redacted must not modify the original")
	}
	if strings.Contains(string(mustJSON(r)), "secret") {
		t.Fatal("secret in redacted JSON")
	}
	// a draft saved from the UI without the password keeps the stored one
	r.KeepSecretsFrom(c)
	if r.InterfaceByID("ifpppoe1").PPPoEPassword != "secret" {
		t.Fatal("secret lost on save")
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func compile3(t *testing.T, c *Config) string {
	t.Helper()
	got, err := Compile(c, countryEnv())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestCompileNAT(t *testing.T) {
	c := twoWAN()
	c.PortForwards = append(c.PortForwards,
		PortForward{ID: "pf000002", Enabled: true, Interfaces: []string{"ifpppoe1"}, Protocol: "udp", PubPorts: "16261-16263",
			Source: Endpoint{Type: "countries", Value: "CA"}, Target: "10.128.7.89", TargetPorts: "16261-16263", Description: "game"},
		PortForward{ID: "pfpaused", Enabled: true, Instance: "vm1", Protocol: "tcp", PubPorts: "8080", Target: "10.66.0.15", TargetPorts: "80"},
		PortForward{ID: "pfrefl01", Enabled: true, Interfaces: []string{"ifpppoe1"}, Protocol: "tcp", PubPorts: "443", Target: "10.128.7.4",
			TargetPorts: "443", Reflection: true, Description: "proxy"})
	c.Rules = append(c.Rules, Rule{ID: "rgw00001", Enabled: true, Interface: "if000500", Action: "allow", Protocol: "any",
		Source: Endpoint{Type: "any"}, Destination: Endpoint{Type: "any"}, Gateway: "gwpppoe1", Description: "VLAN500 via PPPoE"})
	c.Settings.OutboundNAT = "hybrid"
	c.Normalize()
	got := compile3(t, c)
	for _, want := range []string{
		// port forwards (DNAT) — source restriction inside the translation
		`iifname "ppp-ifpppoe1" meta l4proto tcp th dport 52400 dnat to 10.128.8.8:32400 comment "pf:pf000001"`,
		`iifname "ppp-ifpppoe1" meta l4proto udp ip saddr @c_ca th dport 16261-16263 dnat to 10.128.7.89 comment "pf:pf000002"`,
		// reflection: inside clients using the public address
		`iifname != @wan fib daddr type local meta l4proto tcp th dport 443 dnat to 10.128.7.4:443 comment "pf:pfrefl01"`,
		`iifname != @wan ct status dnat ip daddr 10.128.7.4 meta l4proto tcp th dport 443 masquerade comment "pf:pfrefl01"`,
		// manual SNAT out of the BELL Router gateway, then automatic
		`ip saddr 10.128.5.0/24 meta mark set 0x101 ct mark set meta mark`,
		`oifname "enp1s0" ip saddr 10.128.5.0/24 masquerade comment "sn:sn000001"`,
		`oifname "ppp-ifpppoe1" ip daddr != @private masquerade comment "auto"`,
		`oifname "enp1s0" ip saddr != 192.168.2.0/24 ip daddr != @private masquerade comment "auto"`,
		// reply-to: connections arriving on a gateway interface leave through it
		`iifname "ppp-ifpppoe1" ct state new ip saddr != @private ct mark set 0x300`,
		`iifname "enp1s0" ct state new ip saddr != @private ct mark set 0x301`,
		`ct mark != 0 meta mark set ct mark`,
		// rule with a gateway → policy routing mark (follow failover)
		`iifname "enp2s0-v500" ct state new meta mark set 0x100 ct mark set meta mark comment "r:rgw00001"`,
		// MSS clamping on PPPoE
		`oifname "ppp-ifpppoe1" tcp flags syn tcp option maxseg size set rt mtu`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing:\n%s\nin:\n%s", want, got)
		}
	}
	if strings.Contains(got, "pfpaused") {
		t.Fatal("a paused instance forward must never translate")
	}
	golden(t, "compile_nat.nft", got)
}

func TestCompileNAT_OutboundModes(t *testing.T) {
	c := twoWAN()
	c.Settings.OutboundNAT = "manual"
	if got := compile3(t, c); strings.Contains(got, `comment "auto"`) {
		t.Fatal("manual mode: no automatic masquerade")
	}
	c.Settings.OutboundNAT = "automatic"
	if got := compile3(t, c); strings.Contains(got, "sn:sn000001") {
		t.Fatal("automatic mode ignores manual rules")
	}
}

func TestGatewayMarks(t *testing.T) {
	if GatewayMark(0, false) != 0x100 || GatewayMark(3, true) != 0x203 || GatewayTable(2, false) != 102 || GatewayTable(2, true) != 202 {
		t.Fatal("marks/tables")
	}
}

// Interfaces are shown by the name the admin gave them: the Linux device
// (a VLAN's bridge, a PPPoE link's ppp- device) leads back to it.
func TestInterfaceNameByDevice(t *testing.T) {
	c := twoWAN()
	for dev, want := range map[string]string{
		"ppp-ifpppoe1":   "BELL PPPoE",
		"br-enp2s0-v800": "VLAN800",
		"enp2s0-v800":    "VLAN800",
		"enp2s0-v700":    "VLAN700",
		"nope0":          "",
	} {
		if got := c.InterfaceNameByDevice(dev); got != want {
			t.Errorf("%s: %q, want %q", dev, got, want)
		}
	}
}

// The whole table, for the pages outside the Firewall (dashboard charts,
// bridges): every Linux device of a configured interface → its name.
func TestDeviceNames(t *testing.T) {
	m := twoWAN().DeviceNames()
	if m["ppp-ifpppoe1"] != "BELL PPPoE" || m["br-enp2s0-v800"] != "VLAN800" || m["enp2s0-v800"] != "VLAN800" || m["enp2s0-v700"] != "VLAN700" {
		t.Fatalf("%v", m)
	}
	if len((&Config{}).DeviceNames()) != 0 {
		t.Fatal("names without interfaces")
	}
}
