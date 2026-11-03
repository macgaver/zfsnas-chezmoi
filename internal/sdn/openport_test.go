package sdn

import "testing"

func TestPortOpen(t *testing.T) {
	c := &Config{
		Settings: Settings{MgmtInterface: "enp1s0", AntiLockout: true},
		Interfaces: []Interface{
			{ID: "lan", Name: "LAN", Device: "enp1s0", Role: "lan", IPv4Mode: "static", IPv4: "192.168.2.1/24"},
			{ID: "wan", Name: "WAN", Device: "enp2s0", Role: "wan", IPv4Mode: "dhcp"},
			{ID: "wg", Name: "Road", Kind: "wireguard", Device: "wg-road", Role: "lan", IPv4Mode: "static", IPv4: "10.67.0.1/24", WGListenPort: 51820},
		},
		Groups: []Group{{ID: "web", Name: "web", Kind: "ports", Members: []string{"80", "8000-8100"}}},
		Rules: []Rule{
			{ID: "r1", Enabled: true, Interface: "wan", Action: "allow", Protocol: "tcp", Source: Endpoint{Type: "any"}, Destination: Endpoint{Type: "this_znas"}, DstPorts: "22, 2200-2210"},
			{ID: "r2", Enabled: true, Interface: "", Action: "allow", Protocol: "tcpudp", Source: Endpoint{Type: "countries", Value: "CA"}, Destination: Endpoint{Type: "any"}, DstPorts: "group:web"},
			{ID: "r3", Enabled: false, Interface: "wan", Action: "allow", Protocol: "tcp", Source: Endpoint{Type: "any"}, Destination: Endpoint{Type: "any"}, DstPorts: "25"},
			{ID: "r4", Enabled: true, Interface: "wan", Action: "block", Protocol: "tcp", Source: Endpoint{Type: "any"}, Destination: Endpoint{Type: "any"}, DstPorts: "23"},
			{ID: "r5", Enabled: true, Interface: "wan", Action: "allow", Protocol: "icmp", Source: Endpoint{Type: "any"}, Destination: Endpoint{Type: "this_znas"}},
		},
		PortForwards: []PortForward{
			{ID: "f1", Enabled: true, Interfaces: []string{"wan"}, Protocol: "tcp", PubPorts: "443", Target: "192.168.2.10", TargetPorts: "443"},
			{ID: "f2", Enabled: true, Interfaces: []string{"wan"}, Protocol: "udp", PubPorts: "16261-16263", Target: "192.168.2.11"},
			{ID: "f3", Enabled: true, Interfaces: nil, Protocol: "tcp", PubPorts: "3389", Target: "192.168.2.12"}, // paused
			{ID: "f4", Enabled: false, Interfaces: []string{"wan"}, Protocol: "tcp", PubPorts: "5900", Target: "192.168.2.13"},
		},
	}
	env := Env{PortalPorts: []int{8443}, SSHPort: 22}
	cases := []struct {
		iface, proto string
		port         int
		want         bool
	}{
		{"wan", "tcp", 22, true}, {"wan", "TCP", 2205, true}, {"wan", "udp", 22, false}, // rule ports + range, proto mismatch
		{"wan", "tcp", 8050, true}, {"wan", "udp", 80, true}, {"lan", "tcp", 80, true}, // Any-interface rule, port group, tcpudp
		{"wan", "tcp", 25, false}, {"wan", "tcp", 23, false}, // disabled allow, block rule
		{"wan", "tcp", 443, true}, {"wan", "udp", 16262, true}, {"wan", "udp", 443, false}, // forwards
		{"wan", "tcp", 3389, false}, {"wan", "tcp", 5900, false}, // paused, disabled forward
		{"wan", "udp", 51820, true},                         // WireGuard listen port
		{"wan", "icmp", 0, true}, {"lan", "icmp", 0, false}, // ICMP allowed on WAN only
		{"lan", "tcp", 8443, true}, {"wan", "tcp", 8443, false}, // anti-lockout only on the management interface
		{"wan", "tcp", 12345, false},
	}
	for _, tc := range cases {
		if got := c.PortOpen(tc.iface, tc.proto, tc.port, env); got != tc.want {
			t.Errorf("PortOpen(%s %s %d) = %v, want %v", tc.iface, tc.proto, tc.port, got, tc.want)
		}
	}
}
