package sdn

import (
	"strings"
	"testing"
)

// "Internal networks" = every non-WAN interface network with a static
// address, computed at compile time (a new VLAN joins it without editing rules).
func TestCompile_InternalNetworksEndpoint(t *testing.T) {
	c := ownerSample()
	c.Settings.Mode = "router"
	c.Interfaces = append(c.Interfaces, Interface{ID: "ifwan001", Name: "WAN", Kind: "physical", Device: "enp9s0", Role: "wan", IPv4Mode: "static", IPv4: "198.51.100.2/30"})
	c.Rules = append(c.Rules, Rule{ID: "rint0001", Enabled: true, Interface: "", Action: "allow", Protocol: "icmp",
		Source: Endpoint{Type: "internal"}, Destination: Endpoint{Type: "internal", Not: true}, Description: "inside to outside"})
	got, err := Compile(c, testEnv)
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(got, "\n") {
		if strings.Contains(l, `r:rint0001`) {
			line = l
			break
		}
	}
	for _, n := range []string{"192.168.2.0/24", "10.128.4.0/24", "10.128.5.0/24", "10.128.7.0/24", "10.128.8.0/24"} {
		if strings.Count(line, n) != 2 {
			t.Errorf("%s missing from source and/or destination: %s", n, line)
		}
	}
	if strings.Contains(line, "198.51.100.0/30") {
		t.Errorf("WAN network must not be internal: %s", line)
	}
	if !strings.Contains(line, "ip saddr { ") || !strings.Contains(line, "ip daddr != { ") {
		t.Errorf("want set matches (and != for the negated side): %s", line)
	}
	if msg := c.checkEndpoint(Endpoint{Type: "internal"}, false); msg != "" {
		t.Errorf("internal must validate as a source: %s", msg)
	}
}

// With no inside network at all the alias matches nothing (and its negation everything).
func TestInternalNetworksEmpty(t *testing.T) {
	c := &Config{Interfaces: []Interface{{ID: "w", Role: "wan", IPv4Mode: "static", IPv4: "198.51.100.2/30"}}}
	if got := endpointMatch(c, "saddr", Endpoint{Type: "internal"}); got != "ip saddr 255.255.255.255" {
		t.Fatalf("empty: %q", got)
	}
}
