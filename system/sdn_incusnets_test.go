package system

import (
	"reflect"
	"testing"
)

// Incus networks with their own address (host-nat) are shown read-only on
// the Firewall pages: what Incus does on them (address, NAT, DHCP range,
// domain) and who has a lease. Pure L2 bridges, networks the Firewall owns
// and unmanaged bridges are not Incus' to describe.
func TestSDNIncusNetsFrom(t *testing.T) {
	nets := []LXDNetwork{
		{Name: "host-nat", Type: "bridge", Managed: true, Config: map[string]string{"ipv4.address": "10.191.155.1/24", "ipv4.nat": "true", "ipv6.address": "none"},
			UsedBy: []string{"/1.0/instances/ubuntu-desktop", "/1.0/profiles/default"}},
		{Name: "isol", Type: "bridge", Managed: true, Config: map[string]string{"ipv4.address": "10.9.0.1/24", "ipv4.dhcp": "false",
			"ipv4.dhcp.ranges": "10.9.0.50-10.9.0.99", "dns.domain": "lab", "dns.mode": "none"}},
		{Name: "ranged", Type: "bridge", Managed: true, Config: map[string]string{"ipv4.address": "10.8.0.1/24", "ipv4.dhcp.ranges": "10.8.0.50-10.8.0.99,10.8.0.200-10.8.0.210"}},
		{Name: "l2", Type: "bridge", Managed: true, Config: map[string]string{"ipv4.address": "none"}},
		{Name: "adopted", Type: "bridge", Managed: true, Config: map[string]string{"ipv4.address": "10.7.0.1/24", "user.znas.sdn": "true"}},
		{Name: "vmbr0", Type: "bridge", Managed: false, IPv4: "192.168.2.113/24"},
		{Name: "enp1s0", Type: "physical"},
	}
	leases := func(name string) []SDNIncusLease {
		if name != "host-nat" {
			return nil
		}
		return []SDNIncusLease{{Hostname: "ubuntu-desktop", MAC: "10:66:6a:89:67:0b", Address: "10.191.155.163", Type: "dynamic"}}
	}
	got := sdnIncusNetsFrom(nets, leases)
	want := []SDNIncusNet{
		{Name: "host-nat", Address: "10.191.155.1/24", NAT: true, DHCP: true, DHCPRanges: []string{"10.191.155.2-10.191.155.254"},
			DNS: true, Domain: "incus", Instances: 1, Leases: []SDNIncusLease{{Hostname: "ubuntu-desktop", MAC: "10:66:6a:89:67:0b", Address: "10.191.155.163", Type: "dynamic"}}},
		{Name: "isol", Address: "10.9.0.1/24", DHCP: false, Domain: "lab", Leases: []SDNIncusLease{}},
		{Name: "ranged", Address: "10.8.0.1/24", DHCP: true, DHCPRanges: []string{"10.8.0.50-10.8.0.99", "10.8.0.200-10.8.0.210"},
			DNS: true, Domain: "incus", Leases: []SDNIncusLease{}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

// The default DHCP range is the whole subnet but the gateway, wherever the
// gateway sits.
func TestSDNIncusDefaultRange(t *testing.T) {
	for cidr, want := range map[string]string{
		"10.191.155.1/24":   "10.191.155.2-10.191.155.254",
		"10.0.0.254/24":     "10.0.0.1-10.0.0.253",
		"10.0.0.100/24":     "10.0.0.1-10.0.0.254",
		"172.16.0.1/16":     "172.16.0.2-172.16.255.254",
		"not an address/24": "",
	} {
		if got := sdnIncusDefaultRange(cidr); got != want {
			t.Errorf("%s: got %q want %q", cidr, got, want)
		}
	}
}

// Incus lists the gateway and IPv6 addresses among the leases: only the
// devices' IPv4 addresses are shown.
func TestParseIncusLeases(t *testing.T) {
	in := `[{"hostname":"host-nat.gw","hwaddr":"","address":"10.191.155.1","type":"gateway","location":"","project":"default"},
		{"hostname":"ubuntu-desktop","hwaddr":"10:66:6a:89:67:0b","address":"10.191.155.163","type":"dynamic","location":"","project":"default"},
		{"hostname":"ubuntu-desktop","hwaddr":"10:66:6a:89:67:0b","address":"fd42::1","type":"dynamic","location":"","project":"default"}]`
	got := parseIncusLeases([]byte(in))
	want := []SDNIncusLease{{Hostname: "ubuntu-desktop", MAC: "10:66:6a:89:67:0b", Address: "10.191.155.163", Type: "dynamic"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if got := parseIncusLeases([]byte("garbage")); len(got) != 0 {
		t.Fatalf("garbage parsed: %+v", got)
	}
}
