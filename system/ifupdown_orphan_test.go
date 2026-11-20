package system

import (
	"reflect"
	"testing"
)

// The file the 6.11.17 bridge step left on the #187 host.
const leftover187 = `# interfaces(5) file used by ifup(8) and ifdown(8)
source /etc/network/interfaces.d/*

auto enp5s0
iface enp5s0 inet manual

auto vmbr0
iface vmbr0 inet dhcp
    bridge_ports enp5s0
    bridge_stp off
`

func TestIfupdownFileNICs(t *testing.T) {
	if got := ifupdownFileNICs(leftover187); !reflect.DeepEqual(got, []string{"enp5s0", "vmbr0"}) {
		t.Fatalf("got %v", got)
	}
	if got := ifupdownFileNICs("auto lo\niface lo inet loopback\n"); len(got) != 0 {
		t.Fatalf("lo only: %v", got)
	}
}

func TestOrphanIfupdownAction(t *testing.T) {
	user := "auto eth1\niface eth1 inet manual\n" // a user keeping eth1 away from NM on purpose
	cases := []struct {
		name          string
		content       string
		iface         string
		ifup, nm, act bool
	}{
		{"#187 leftover at start-up", leftover187, "", false, true, true},
		{"#187 leftover, static IP on enp5s0", leftover187, "enp5s0", false, true, true},
		{"ifupdown installed: file is live", leftover187, "", true, true, false},
		{"no NetworkManager: nothing drops NICs", leftover187, "", false, false, false},
		{"user file at start-up: leave it", user, "", false, true, false},
		{"user file, static IP on another NIC", user, "enp5s0", false, true, false},
		{"user file names the NIC being set", user, "eth1", false, true, true},
		{"loopback only", "auto lo\niface lo inet loopback\n", "enp5s0", false, true, false},
	}
	for _, c := range cases {
		if got := orphanIfupdownAction(c.content, c.iface, c.ifup, c.nm); got != c.act {
			t.Errorf("%s: got %v want %v", c.name, got, c.act)
		}
	}
}
