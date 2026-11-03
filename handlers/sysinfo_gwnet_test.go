package handlers

import (
	"testing"

	"zfsnas/internal/sdn"
	"zfsnas/system"
)

// The header names the gateway as the admin named its interface; without
// the Firewall (or for a device it does not manage) the Linux name stays.
func TestGatewayNetNamed(t *testing.T) {
	c := &sdn.Config{Interfaces: []sdn.Interface{{ID: "ifwan001", Name: "WAN — fake ISP", Kind: "physical", Device: "enp6s0"}}}
	if g := gatewayNetNamed(system.GatewayNet{Iface: "enp6s0"}, c); g.Name != "WAN — fake ISP" {
		t.Fatalf("%+v", g)
	}
	if g := gatewayNetNamed(system.GatewayNet{Iface: "vmbr0"}, c); g.Name != "" {
		t.Fatalf("unmanaged device named: %+v", g)
	}
	if g := gatewayNetNamed(system.GatewayNet{Iface: "enp6s0"}, nil); g.Name != "" {
		t.Fatalf("no Firewall: %+v", g)
	}
}
