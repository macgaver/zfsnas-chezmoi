package sdn

import (
	"strings"
	"testing"
)

// A virtual IP is an extra address in an interface's own network: it can be
// moved to another server without touching this one's address.
func TestVirtualIP_Validate(t *testing.T) {
	ok := ownerSample()
	ok.InterfaceByID("if000001").VirtualIPs = []VirtualIP{{Address: "192.168.2.1", Description: "LAN gateway", ForClients: true}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid VIP refused: %v", err)
	}
	if got := ok.InterfaceByID("if000001").VIPPrefixes(); len(got) != 1 || got[0].String() != "192.168.2.1/24" {
		t.Fatalf("prefix %v", got)
	}

	bad := []struct {
		name  string
		iface string
		mode  string
		vips  []VirtualIP
		want  string
	}{
		{"outside the network", "if000001", "", []VirtualIP{{Address: "10.9.9.9"}}, "inside 192.168.2.0/24"},
		{"not an address", "if000001", "", []VirtualIP{{Address: "gateway"}}, "IPv4 address"},
		{"with a prefix", "if000001", "", []VirtualIP{{Address: "192.168.2.1/24"}}, "IPv4 address"},
		{"the interface's own", "if000001", "", []VirtualIP{{Address: "192.168.2.254"}}, "already used"},
		{"network address", "if000001", "", []VirtualIP{{Address: "192.168.2.0"}}, "network or broadcast"},
		{"broadcast", "if000001", "", []VirtualIP{{Address: "192.168.2.255"}}, "network or broadcast"},
		{"twice", "if000001", "", []VirtualIP{{Address: "192.168.2.1"}, {Address: "192.168.2.1"}}, "already used"},
		{"another interface's", "if000400", "", []VirtualIP{{Address: "10.128.4.1"}}, "already used"},
		{"two for clients", "if000001", "", []VirtualIP{{Address: "192.168.2.1", ForClients: true}, {Address: "192.168.2.2", ForClients: true}}, "only one"},
		{"interface without a static address", "if000001", "dhcp", []VirtualIP{{Address: "192.168.2.1"}}, "static address"},
		{"in the DHCP range", "if000800", "", []VirtualIP{{Address: "10.128.8.150"}}, "DHCP range"},
		{"a DHCP reservation", "if000800", "", []VirtualIP{{Address: "10.128.8.8"}}, "reserved"},
	}
	for _, tc := range bad {
		c := servicesSample()
		in := c.InterfaceByID(tc.iface)
		in.VirtualIPs = tc.vips
		if tc.mode != "" {
			in.IPv4Mode, in.IPv4 = tc.mode, ""
		}
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", tc.name, tc.want, err)
		}
	}
}

// "For clients": DHCP hands the virtual IP out as the gateway and DNS server
// of that network, so clients follow it when it moves to another server.
func TestVirtualIP_DHCPHandsItOut(t *testing.T) {
	c := servicesSample()
	in := c.InterfaceByID("if000800")
	in.VirtualIPs = []VirtualIP{{Address: "10.128.8.2", Description: "moves", ForClients: false}}
	got := allDHCP(c)
	if !strings.Contains(got, "dhcp-option=tag:if000800,option:router,10.128.8.1\n") {
		t.Fatalf("without ForClients the interface address stays the gateway:\n%s", got)
	}
	in.VirtualIPs[0].ForClients = true
	got = allDHCP(c)
	for _, want := range []string{"dhcp-option=tag:if000800,option:router,10.128.8.2\n", "dhcp-option=tag:if000800,option:dns-server,10.128.8.2\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	// an explicit gateway / DNS list in the DHCP settings still wins
	c.DHCP[0].Gateway, c.DHCP[0].DNSServers = "10.128.8.3", []string{"9.9.9.9"}
	got = allDHCP(c)
	if !strings.Contains(got, "option:router,10.128.8.3\n") || !strings.Contains(got, "option:dns-server,9.9.9.9\n") {
		t.Errorf("explicit settings lost:\n%s", got)
	}
}

// An address excluded from the DHCP range is never handed out: it can be a
// virtual IP.
func TestVirtualIP_InExcludedPartOfTheRange(t *testing.T) {
	c := servicesSample()
	c.DHCP[0].Exclude = []string{"10.128.8.150-10.128.8.152"}
	c.InterfaceByID("if000800").VirtualIPs = []VirtualIP{{Address: "10.128.8.151"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("excluded address refused: %v", err)
	}
	c.InterfaceByID("if000800").VirtualIPs = []VirtualIP{{Address: "10.128.8.153"}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "DHCP range") {
		t.Fatalf("address handed out by DHCP accepted: %v", err)
	}
}
