package sdn

import (
	"reflect"
	"strings"
	"testing"
)

const baseInterfaces = `# This file describes the network interfaces available on your system
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

auto enp5s0
iface enp5s0 inet dhcp

allow-hotplug enp7s0
iface enp7s0 inet manual

auto vmbr0
iface vmbr0 inet static
    address 192.168.2.10/24
    bridge_ports enp5s0
`

func labVLANs() []Interface {
	c := &Config{Interfaces: []Interface{
		{ID: "if000700", Name: "VLAN700", Kind: "vlan", Parent: "enp7s0", VLANTag: 700, IPv4Mode: "static", IPv4: "10.128.7.1/24", Owned: true},
		{ID: "if000800", Name: "VLAN800", Kind: "vlan", Parent: "enp7s0", VLANTag: 800, IPv4Mode: "static", IPv4: "10.128.8.1/24", Owned: true, AllowVMs: true, MTU: 1500},
	}}
	c.Normalize()
	return c.Interfaces
}

func TestSpliceOwned_InsertAfterParent(t *testing.T) {
	got := SpliceOwned(baseInterfaces, labVLANs())
	golden(t, "stanza_splice.interfaces", got)
	if strings.Index(got, "enp7s0-v700") < strings.Index(got, "iface enp7s0 inet manual") ||
		strings.Index(got, "enp7s0-v700") > strings.Index(got, "auto vmbr0") {
		t.Fatal("VLAN block must sit right after its parent stanza")
	}
}

func TestSpliceOwned_Idempotent(t *testing.T) {
	once := SpliceOwned(baseInterfaces, labVLANs())
	if twice := SpliceOwned(once, labVLANs()); twice != once {
		t.Fatalf("not idempotent:\n%s", twice)
	}
}

func TestSpliceOwned_RemovesDeleted(t *testing.T) {
	with := SpliceOwned(baseInterfaces, labVLANs())
	if got := SpliceOwned(with, nil); got != baseInterfaces {
		t.Fatalf("removing all blocks must restore the file byte for byte:\n%q", got)
	}
	one := SpliceOwned(with, labVLANs()[:1])
	if strings.Contains(one, "v800") || !strings.Contains(one, "v700") {
		t.Fatalf("wrong blocks kept:\n%s", one)
	}
}

func TestSpliceOwned_NoParentAppends(t *testing.T) {
	in := labVLANs()[:1]
	in[0].Parent = "enp9s0"
	in[0].Device = VLANDeviceName("enp9s0", 700)
	got := SpliceOwned(baseInterfaces, in)
	if !strings.HasSuffix(got, "# znas-sdn-end\n") {
		t.Fatalf("expected block appended at end:\n%s", got)
	}
	if SpliceOwned(got, nil) != baseInterfaces {
		t.Fatal("append path not reversible")
	}
}

func TestRenderOwned_AllowVMsBridge(t *testing.T) {
	got := RenderOwned(labVLANs()[1])
	golden(t, "stanza_allowvms.interfaces", got)
	for _, want := range []string{
		"iface enp7s0-v800 inet manual",
		"    pre-up ip link set enp7s0 up",
		"iface br-enp7s0-v800 inet static",
		"    bridge_ports enp7s0-v800",
		"    address 10.128.8.1/24",
		"net.ipv6.conf.br-enp7s0-v800.disable_ipv6=1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "dns-") {
		t.Fatal("SDN stanzas must not carry dns-* lines")
	}
}

func TestRenderOwned_DHCP(t *testing.T) {
	in := labVLANs()[0]
	in.IPv4Mode, in.IPv4 = "dhcp", ""
	got := RenderOwned(in)
	if !strings.Contains(got, "iface enp7s0-v700 inet dhcp") || strings.Contains(got, "address") {
		t.Fatalf("bad dhcp stanza:\n%s", got)
	}
	in.IPv4Mode = "none"
	if got := RenderOwned(in); !strings.Contains(got, "iface enp7s0-v700 inet manual") {
		t.Fatalf("none must render manual:\n%s", got)
	}
}

func TestOwnedDevices(t *testing.T) {
	got := OwnedDevices(SpliceOwned(baseInterfaces, labVLANs()))
	if !reflect.DeepEqual(got, []string{"enp7s0-v700", "enp7s0-v800"}) {
		t.Fatalf("got %v", got)
	}
}
