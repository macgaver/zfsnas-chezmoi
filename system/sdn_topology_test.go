package system

import (
	"testing"

	"zfsnas/internal/sdn"
)

// A VM holding a DHCP lease is shown as the VM, once, on its address; a
// stopped VM on the bridge is listed without one; a dead neighbour with no MAC
// is not a host; a card on another network stays off this one.
func TestSDNTopoNetMerges(t *testing.T) {
	inst := parseTopoInstances([]byte(`[
	 {"name":"web","type":"virtual-machine","status":"Running","expanded_config":{"volatile.eth0.hwaddr":"AA:AA:00:00:00:01","limits.cpu":"2"},
	  "expanded_devices":{"eth0":{"type":"nic","parent":"vmbr0"}},
	  "state":{"network":{"eth0":{"hwaddr":"aa:aa:00:00:00:01","addresses":[{"family":"inet","address":"10.0.0.50","scope":"global"}]},
	    "docker0":{"hwaddr":"bb:00:00:00:00:00","addresses":[{"family":"inet","address":"172.17.0.1","scope":"global"}]}}}},
	 {"name":"off","type":"container","status":"Stopped","expanded_config":{"volatile.eth0.hwaddr":"aa:aa:00:00:00:02"},
	  "expanded_devices":{"eth0":{"type":"nic","network":"vmbr0"}}},
	 {"name":"elsewhere","type":"container","status":"Stopped","expanded_config":{},"expanded_devices":{"eth0":{"type":"nic","network":"other"}}},
	 {"name":"bkup--x","type":"container","status":"Stopped","expanded_config":{},"expanded_devices":{}}]`))
	if len(inst) != 3 {
		t.Fatalf("instances: %+v", inst)
	}
	in := sdn.Interface{ID: "a", Name: "LAN", Kind: "bridge", Device: "vmbr0", IPv4Mode: "static", IPv4: "10.0.0.1/24"}
	c := &sdn.Config{Interfaces: []sdn.Interface{in}, DHCP: []sdn.DHCPServer{{Interface: "a", Enabled: true, RangeStart: "10.0.0.50", RangeEnd: "10.0.0.59",
		Reservations: []sdn.DHCPReservation{{MAC: "cc:00:00:00:00:01", IP: "10.0.0.9", Hostname: "printer"}}}},
		PortForwards: []sdn.PortForward{{Enabled: true, Interfaces: []string{"w"}, Protocol: "tcp", PubPorts: "443", Target: "10.0.0.50"}}}
	leases := []SDNLease{{Interface: "a", MAC: "aa:aa:00:00:00:01", IP: "10.0.0.50", Hostname: "dhcpname"}}
	neigh := []sdnTopoNeigh{{Dst: "10.0.0.9", LLAddr: "cc:00:00:00:00:01", State: []string{"STALE"}}, {Dst: "10.0.0.77", State: []string{"FAILED"}},
		{Dst: "10.0.0.8", LLAddr: "dd:00:00:00:00:01", State: []string{"REACHABLE"}}, {Dst: "192.168.9.9", LLAddr: "ee:00:00:00:00:01", State: []string{"REACHABLE"}}}
	n := sdnTopoBuildNet(c, in, nil, map[string]*SDNLiveIface{}, leases, neigh, inst, SDNWGTunnelStatus{}, SDNIncusNet{}, map[string]string{"10.0.0.8": "Router to 10.9.0.0/16"},
		sdnTopoUsage{dns: map[string][2]int{"10.0.0.8": {5, 1}}, ids: map[string][2]int64{}}, func(string) (string, string) { return "", "" })

	got := map[string]SDNTopoHost{}
	for _, h := range n.Hosts {
		got[h.IP] = h
	}
	if len(n.Hosts) != 5 {
		t.Fatalf("hosts: %+v", n.Hosts)
	}
	if h := got["10.0.0.50"]; h.Kind != "vm" || h.Name != "web" || h.Status != "online" || h.Addressing != "lease" || h.Forwards != 1 {
		t.Errorf("vm on a lease: %+v", h)
	}
	if h := got["10.0.0.9"]; h.Name != "printer" || h.Addressing != "reserved" || h.Status != "idle" {
		t.Errorf("reservation: %+v", h)
	}
	if h := got["10.0.0.8"]; h.Kind != "router" || h.Addressing != "static" || h.DNSQueries != 5 || h.DNSBlocked != 1 {
		t.Errorf("router: %+v", h)
	}
	if h := got[""]; h.Name != "off" || h.Kind != "container" || h.Status != "offline" {
		t.Errorf("stopped instance: %+v", h)
	}
	if h := got["10.0.0.1"]; h.Kind != "this-server" {
		t.Errorf("self: %+v", h)
	}
	if n.DHCP == nil || n.DHCP.PoolSize != 10 || n.DHCP.PoolUsed != 1 || n.DHCP.Reservations != 1 {
		t.Errorf("dhcp: %+v", n.DHCP)
	}
}
