package system

import "testing"

// The NAT uplink is derived from the default route, so the parser has to cope
// with the real shapes `ip route show default` emits.
func TestParseDefaultRouteIface(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"onlink via bridge", "default via 192.168.2.1 dev vmbr0 onlink \n", "vmbr0"},
		{"plain nic", "default via 10.0.0.1 dev enp5s0 proto dhcp src 10.0.0.5 metric 100\n", "enp5s0"},
		{"dev before via", "default dev wg0 scope link\n", "wg0"},
		{"multiple routes, default wins", "10.0.0.0/24 dev eth9 scope link\ndefault via 1.2.3.4 dev eth0\n", "eth0"},
		{"no default route", "10.0.0.0/24 dev eth9 scope link\n", ""},
		{"empty", "", ""},
		{"malformed dev at end", "default via 1.2.3.4 dev\n", ""},
	}
	for _, c := range cases {
		if got := parseDefaultRouteIface(c.in); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestHostNatIndex(t *testing.T) {
	cases := map[string]int{
		"host-nat":   0,
		"host-nat2":  1,
		"host-nat10": 9,
		"host-nat1":  -1, // never a name we generate
		"vmbr0":      -1,
		"incusbr0":   -1,
		"host-natX":  -1,
	}
	for in, want := range cases {
		if got := hostNatIndex(in); got != want {
			t.Errorf("hostNatIndex(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestNatUplinkForPrefersRecordedPairing(t *testing.T) {
	// The recorded pairing wins over anything derived from the live host, so
	// two NAT networks never report the same port again.
	phys, _ := natUplinkFor("host-nat2", map[string]string{HostNatUplinkKey: "enp6s0"})
	if phys != "enp6s0" {
		t.Fatalf("want enp6s0 from the recorded key, got %q", phys)
	}
}
