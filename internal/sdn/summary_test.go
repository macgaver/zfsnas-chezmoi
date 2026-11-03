package sdn

import (
	"strings"
	"testing"
)

func TestSummarize(t *testing.T) {
	addRule := func(c *Config, iface string) {
		c.Rules = append(c.Rules, Rule{ID: NewID(), Enabled: true, Interface: iface, Action: "allow", Protocol: "any",
			Source: Endpoint{Type: "any"}, Destination: Endpoint{Type: "any"}})
	}
	t.Run("no changes", func(t *testing.T) {
		if got := Summarize(ownerSample(), ownerSample()); got != "no changes" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("two rules added", func(t *testing.T) {
		next := ownerSample()
		addRule(next, "if000700")
		addRule(next, "if000700")
		if got := Summarize(ownerSample(), next); got != "+2 rules on VLAN700" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("rule edited and interface added", func(t *testing.T) {
		next := ownerSample()
		next.Rules[0].DstPorts = "3009"
		next.Interfaces = append(next.Interfaces, Interface{ID: "if000999", Name: "VLAN999", Kind: "vlan", Parent: "enp2s0", VLANTag: 999, IPv4Mode: "none"})
		if got := Summarize(ownerSample(), next); got != "interface VLAN999 added · 1 rule edited" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("mode", func(t *testing.T) {
		prev := ownerSample()
		prev.Settings.Mode = "monitor"
		if got := Summarize(prev, ownerSample()); got != "mode: router" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("removed rule any interface", func(t *testing.T) {
		prev := ownerSample()
		addRule(prev, "")
		if got := Summarize(prev, ownerSample()); got != "-1 rule on Any interface" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestSummarize_Phase3(t *testing.T) {
	prev := &Config{Interfaces: []Interface{{ID: "wan1", Name: "WAN"}}}
	next := &Config{Interfaces: prev.Interfaces,
		Gateways:     []Gateway{{ID: "g1", Name: "ISP1", Interface: "wan1", Priority: 1}},
		PortForwards: []PortForward{{ID: "p1", Description: "web", PubPorts: "443"}, {ID: "p2", PubPorts: "22"}},
		SNATRules:    []SNATRule{{ID: "s1"}},
		Settings:     Settings{OutboundNAT: "hybrid"}}
	got := Summarize(prev, next)
	for _, want := range []string{"gateway ISP1 added", "+2 port forwards", "+1 outbound NAT rule", "outbound NAT: hybrid"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q lacks %q", got, want)
		}
	}
	edited := *next
	edited.Gateways = []Gateway{{ID: "g1", Name: "ISP1", Interface: "wan1", Priority: 2}}
	edited.PortForwards = []PortForward{{ID: "p1", Description: "web", PubPorts: "8443"}}
	got = Summarize(next, &edited)
	for _, want := range []string{"gateway ISP1 edited", "-1 port forward", "1 port forward edited"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q lacks %q", got, want)
		}
	}
}

func TestSummarize_SNATReorder(t *testing.T) {
	a := &Config{SNATRules: []SNATRule{{ID: "s1"}, {ID: "s2"}}}
	b := &Config{SNATRules: []SNATRule{{ID: "s2"}, {ID: "s1"}}}
	if got := Summarize(a, b); got != "outbound NAT rules reordered" {
		t.Fatalf("got %q", got)
	}
}
