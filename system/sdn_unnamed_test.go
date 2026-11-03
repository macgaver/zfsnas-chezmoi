package system

import "testing"

// Named hosts drop out, stopped instances have no address to name, and the
// binding says how the name will be kept: only this Firewall's own leases and
// reservations follow the device.
func TestSDNUnnamedFrom(t *testing.T) {
	fw := &SDNTopoDHCP{Server: "Firewall", Enabled: true}
	topo := SDNTopology{Networks: []SDNTopoNet{
		{ID: "a", Name: "LAN", DHCP: fw, Hosts: []SDNTopoHost{
			{IP: "10.0.0.5", MAC: "aa:00:00:00:00:01", Addressing: "lease", Kind: "device", Vendor: "Acme"},
			{IP: "10.0.0.6", MAC: "aa:00:00:00:00:02", Addressing: "reserved", Kind: "vm", Name: "web"},
			{IP: "10.0.0.7", MAC: "aa:00:00:00:00:03", Addressing: "static", Kind: "device"},
			{IP: "10.0.0.8", Addressing: "lease", Kind: "device", Name: "gone"},
			{IP: "10.0.0.4", MAC: "aa:00:00:00:00:01", Addressing: "static", Kind: "device"}, // its old address
			{IP: "10.0.0.9", Addressing: "lease", Kind: "device"},
			{Name: "stopped", Kind: "container"},
		}},
		{ID: "b", Name: "Inc", DHCP: &SDNTopoDHCP{Server: "Incus", Enabled: true}, Hosts: []SDNTopoHost{
			{IP: "10.1.0.5", MAC: "aa:00:00:00:00:04", Addressing: "incus", Kind: "container", Name: "ct"},
		}},
	}}
	got := sdnUnnamedFrom(topo, map[string]string{"10.0.0.9": "x.example."}, func(ip string) bool { return ip == "10.0.0.8" }, map[string]string{"a": "lan"}, "home")
	want := map[string]string{"10.0.0.5": "lease", "10.0.0.6": "reserved", "10.0.0.7": "static", "10.1.0.5": "static"}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for _, u := range got {
		if want[u.IP] != u.Binding {
			t.Errorf("%s: %s", u.IP, u.Binding)
		}
	}
	if got[0].Domain != "lan" || got[1].Instance != "web" || got[3].Domain != "home" || got[3].Instance != "ct" {
		t.Errorf("%+v", got)
	}
}
