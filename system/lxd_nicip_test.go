package system

import "testing"

// The address is on what sits on top of the card: a VLAN sharing its MAC.
func TestLXDGuestIPByMAC(t *testing.T) {
	addr := func(ip string) lxdStateNetwork {
		n := lxdStateNetwork{HWAddr: "AA:00:00:00:00:01"}
		if ip != "" {
			n.Addresses = append(n.Addresses, struct {
				Family  string `json:"family"`
				Address string `json:"address"`
				Scope   string `json:"scope"`
			}{"inet", ip, "global"})
		}
		return n
	}
	net := map[string]lxdStateNetwork{"eth0": addr(""), "eth0.800": addr("10.0.0.5"), "docker0": {HWAddr: "bb:00:00:00:00:00"}}
	if got := lxdGuestIPByMAC(net, "aa:00:00:00:00:01"); got != "10.0.0.5" {
		t.Errorf("got %q", got)
	}
	if got := lxdGuestIPByMAC(net, ""); got != "" {
		t.Errorf("no MAC: %q", got)
	}
}

// What the guest reported stays; only silent cards take what the host saw.
func TestLXDFillHostSeenIPs(t *testing.T) {
	old := lxdHostSeen
	defer func() { lxdHostSeen = old }()
	lxdHostSeen = func() map[string]string {
		return map[string]string{"aa:00:00:00:00:01": "10.0.0.9", "aa:00:00:00:00:02": "10.0.0.8"}
	}
	n := []LXDNICConfig{{MAC: "AA:00:00:00:00:01"}, {MAC: "aa:00:00:00:00:02", CurrentIP: "10.0.0.2"}, {MAC: "aa:00:00:00:00:03"}, {}}
	lxdFillHostSeenIPs(n)
	if n[0].CurrentIP != "10.0.0.9" || n[0].IPSource != "host" {
		t.Errorf("silent card: %+v", n[0])
	}
	if n[1].CurrentIP != "10.0.0.2" || n[1].IPSource != "" {
		t.Errorf("reported card: %+v", n[1])
	}
	if n[2].CurrentIP != "" || n[3].CurrentIP != "" {
		t.Errorf("unknown: %+v", n)
	}
}

// A MAC fixed in the device (imported VM) identifies its instance too.
func TestLXDOwnerOf(t *testing.T) {
	list := parseTopoInstances([]byte(`[{"name":"ipsvc","type":"virtual-machine","status":"Running","expanded_config":{},
	 "expanded_devices":{"net0":{"type":"nic","hwaddr":"BC:24:11:7A:43:49","parent":"vmbr0"}}},
	 {"name":"ct","type":"container","status":"Stopped","expanded_config":{"volatile.eth0.hwaddr":"10:66:6a:00:00:01"},"expanded_devices":{"eth0":{"type":"nic","network":"br"}}}]`))
	if o := lxdOwnerOf(list, "bc:24:11:7a:43:49"); o == nil || o.Name != "ipsvc" || o.NIC != "net0" || o.Bridge != "vmbr0" {
		t.Errorf("%+v", o)
	}
	if o := lxdOwnerOf(list, "10:66:6A:00:00:01"); o == nil || o.Name != "ct" {
		t.Errorf("%+v", o)
	}
	if o := lxdOwnerOf(list, "10:66:6a:00:00:02"); o != nil {
		t.Errorf("%+v", o)
	}
}
