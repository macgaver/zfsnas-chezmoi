package system

import (
	"reflect"
	"testing"
)

// A bridge stanza written with no bridge-utils leaves networking.service
// failing at boot ("Cannot find device <bridge>"); a vlan-raw-device stanza
// needs the vlan package the same way. ifupdownHelperPkgsFor is the predicate
// that drives the install, so pin it (observed on a fresh Debian 13 test VM).
func TestIfupdownHelperPkgsFor(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			"bridge_ports",
			"auto vmbr0\niface vmbr0 inet static\n    bridge_ports enp5s0\n    bridge_stp off\n",
			[]string{"bridge-utils"},
		},
		{
			"vlan-aware bridge",
			"iface vmbr0 inet static\n    bridge-vlan-aware yes\n    bridge-vids 2-4094\n",
			[]string{"bridge-utils"},
		},
		{
			"vlan sub-interface",
			"auto enp5s0.10\niface enp5s0.10 inet static\n    vlan-raw-device enp5s0\n",
			[]string{"vlan"},
		},
		{
			"plain dhcp needs nothing",
			"auto lo\niface lo inet loopback\n\nauto enp5s0\niface enp5s0 inet dhcp\n",
			nil,
		},
	}
	for _, c := range cases {
		got := ifupdownHelperPkgsFor(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
