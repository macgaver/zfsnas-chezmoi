package sdn

import (
	"strings"
	"testing"
)

// An Incus VLAN bridge as on the owner's router: Incus keeps the address and
// DHCP, the Firewall filters and translates.
func incusKept() *Config {
	c := ownerSample()
	c.Interfaces = append(c.Interfaces, Interface{ID: "ifppp001", Name: "WAN", Kind: "physical", Device: "enp9s0", Role: "wan", IPv4Mode: "dhcp"},
		Interface{ID: "ifinc400", Name: "VM400", Kind: "incus", Device: "vmbr0-400", Role: "lan", IPv4Mode: "static", IPv4: "10.128.14.1/24", IncusKeep: true, IncusDHCP: true})
	c.Gateways = []Gateway{{ID: "gw000001", Name: "WAN", Interface: "ifppp001", Priority: 1}}
	c.Settings.OutboundNAT = "manual"
	c.SNATRules = []SNATRule{{ID: "sn000001", Enabled: true, Gateway: "gw000001", Translate: "iface", Protocol: "any",
		Source: Endpoint{Type: "iface_net", Value: "ifinc400"}, Destination: Endpoint{Type: "any"}}}
	c.PortForwards = []PortForward{{ID: "pf000001", Enabled: true, Interfaces: []string{"ifppp001"}, Protocol: "tcp", PubPorts: "8080", Target: "10.128.14.20", TargetPorts: "80", Source: Endpoint{Type: "any"}}}
	c.Normalize()
	return c
}

func TestIncusKept_NATBothWays(t *testing.T) {
	s, err := Compile(incusKept(), Env{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"vmbr0-400"`,
		`oifname "enp9s0" ip saddr 10.128.14.0/24 masquerade`,
		`iifname "enp9s0" meta l4proto tcp th dport 8080 dnat to 10.128.14.20:80`,
		`iifname "vmbr0-400" jump fw_ifinc400`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in:\n%s", want, s)
		}
	}
}

// Default deny must not cut the VMs off Incus' own DHCP (or DNS, when it
// serves it): those keep working as they did before the bridge was added.
func TestIncusKept_IncusServicesStayReachable(t *testing.T) {
	s, err := Compile(incusKept(), Env{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, `iifname "vmbr0-400" udp dport 67 accept`) {
		t.Errorf("Incus DHCP blocked:\n%s", s)
	}
	if strings.Contains(s, `iifname "vmbr0-400" meta l4proto { tcp, udp } th dport 53 accept`) {
		t.Errorf("DNS opened while Incus serves none:\n%s", s)
	}
	c := incusKept()
	c.Interfaces[len(c.Interfaces)-1].IncusDHCP, c.Interfaces[len(c.Interfaces)-1].IncusDNS = false, true
	s, err = Compile(c, Env{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s, `iifname "vmbr0-400" udp dport 67 accept`) || !strings.Contains(s, `iifname "vmbr0-400" meta l4proto { tcp, udp } th dport 53 accept`) {
		t.Errorf("services do not follow Incus:\n%s", s)
	}
}

func TestIncusKept_Validate(t *testing.T) {
	if err := incusKept().Validate(); err != nil {
		t.Fatal(err)
	}
	c := incusKept()
	c.Interfaces[len(c.Interfaces)-1].IPv4Mode, c.Interfaces[len(c.Interfaces)-1].IPv4 = "none", ""
	if err := c.Validate(); !hasErr(err, "interfaces[6].ipv4") {
		t.Fatalf("kept Incus address required: %v", err)
	}
	c = incusKept()
	c.Interfaces[1].IncusKeep = true
	if err := c.Validate(); !hasErr(err, "interfaces[1].incus_keep") {
		t.Fatalf("only an Incus network keeps its settings: %v", err)
	}
}

// Two DHCP servers on one network: refused while Incus' is on, fine once off.
func TestIncusKept_FirewallDHCPOnlyWhenIncusOff(t *testing.T) {
	c := incusKept()
	c.DHCP = []DHCPServer{{Interface: "ifinc400", Enabled: true, RangeStart: "10.128.14.100", RangeEnd: "10.128.14.200"}}
	c.Normalize()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "Incus") {
		t.Fatalf("got %v", err)
	}
	c.Interfaces[len(c.Interfaces)-1].IncusDHCP = false
	if err := c.Validate(); err != nil && strings.Contains(err.Error(), "Incus") {
		t.Fatalf("got %v", err)
	}
}

// Incus' own dnsmasq and ours cannot share an address: Incus fails to bring
// the network up at the next boot.
func TestIncusKept_RefusesOurDNSWhereIncusServesDNS(t *testing.T) {
	c := incusKept()
	c.Interfaces[len(c.Interfaces)-1].IncusDNS = true
	c.DNS.Enabled, c.DNS.Interfaces = true, []string{"ifinc400"}
	c.Normalize()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "Incus") {
		t.Fatalf("err = %v", err)
	}
	c.Interfaces[len(c.Interfaces)-1].IncusDNS = false
	if ve, ok := c.Validate().(ValidationErrors); ok {
		for _, e := range ve {
			if strings.HasPrefix(e.Path, "dns.") {
				t.Fatalf("Incus DNS off: %v", e)
			}
		}
	}
}
