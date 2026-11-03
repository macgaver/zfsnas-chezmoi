package system

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zfsnas/internal/sdn"
)

func hostInfoEnv(t *testing.T, neigh, route string) {
	t.Helper()
	sdnTestEnv(t)
	dir := t.TempDir()
	oldLease, oldPTR, oldLocal, oldIP, oldInst := sdnLegacyLeasePath, sdnLookupAddr, sdnIDSLocal, sdnHostIPJSON, sdnHostInstanceOf
	t.Cleanup(func() {
		sdnLegacyLeasePath, sdnLookupAddr, sdnIDSLocal, sdnHostIPJSON, sdnHostInstanceOf = oldLease, oldPTR, oldLocal, oldIP, oldInst
	})
	sdnLegacyLeasePath = filepath.Join(dir, "leases")
	os.WriteFile(sdnLegacyLeasePath, []byte("1900000000 10:e9:92:00:00:01 192.168.2.50 tv-salon *\n"), 0644)
	sdnIDSLocal = func(netip.Addr) bool { return false }
	sdnHostNameCache.reset()
	sdnHostIPJSON = func(args ...string) []byte {
		if args[0] == "neigh" {
			return []byte(neigh)
		}
		return []byte(route)
	}
}

func hostInfoConfig() *sdn.Config {
	c := &sdn.Config{
		Interfaces: []sdn.Interface{{ID: "if1", Name: "Maison", Kind: "bridge", Device: "vmbr0", Role: "lan", IPv4Mode: "static", IPv4: "192.168.2.1/24", Color: "#112233"}},
		Groups: []sdn.Group{{ID: "g1", Name: "TVs", Kind: "hosts", Members: []string{"192.168.2.50"}},
			{ID: "g2", Name: "Other", Kind: "hosts", Members: []string{"10.0.0.0/8"}},
			{ID: "g3", Name: "Web", Kind: "ports", Members: []string{"192.168.2.50"}}},
		Rules: []sdn.Rule{{ID: "r1", Action: "block", Description: "No TV internet", Enabled: true, Source: sdn.Endpoint{Type: "group", Value: "g1"}},
			{ID: "r2", Action: "allow", Description: "Whole LAN", Enabled: true, Source: sdn.Endpoint{Type: "cidr", Value: "192.168.2.0/24"}},
			{ID: "r3", Action: "allow", Description: "Somebody else", Source: sdn.Endpoint{Type: "cidr", Value: "192.168.3.0/24"}}},
		PortForwards: []sdn.PortForward{{ID: "p1", Protocol: "tcp", PubPorts: "8443", Target: "192.168.2.50", TargetPorts: "443", Enabled: true}},
		DHCP: []sdn.DHCPServer{{Interface: "if1", Enabled: true, RangeStart: "192.168.2.20", RangeEnd: "192.168.2.99",
			Reservations: []sdn.DHCPReservation{{MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.2.7", Hostname: "nas", Description: "Bureau"}}}},
		DNS:     sdn.DNSSettings{Hosts: []sdn.DNSHost{{Name: "television", IP: "192.168.2.50"}}},
		WGPeers: []sdn.WGPeer{{Name: "iPad", AllowedIPs: []string{"10.8.0.2/32"}}},
	}
	return c
}

func TestSDNHostInfo_LeasedDevice(t *testing.T) {
	hostInfoEnv(t, `[{"dst":"192.168.2.50","dev":"vmbr0","lladdr":"10:e9:92:00:00:01","state":["REACHABLE"]}]`, `[{"dst":"192.168.2.50","dev":"vmbr0"}]`)
	h := SDNHostInfoFor(hostInfoConfig(), netip.MustParseAddr("192.168.2.50"), time.Now())
	if h.Name != "tv-salon" || h.Role != "device" {
		t.Fatalf("identity: %+v", h)
	}
	if h.MAC != "10:e9:92:00:00:01" || h.Vendor != "INGRAM MICRO SERVICES" || h.MACPrivate || h.State != "REACHABLE" {
		t.Fatalf("mac: %+v", h)
	}
	if h.Network == nil || h.Network.Name != "Maison" || h.Network.CIDR != "192.168.2.0/24" {
		t.Fatalf("network: %+v", h.Network)
	}
	if h.DHCP == nil || !h.DHCP.Leased || !h.DHCP.InPool || h.DHCP.Reserved || h.DHCP.Hostname != "tv-salon" {
		t.Fatalf("dhcp: %+v", h.DHCP)
	}
	if strings.Join(h.Groups, ",") != "TVs" {
		t.Fatalf("groups (ports groups do not count): %v", h.Groups)
	}
	if len(h.Rules) != 2 || h.Rules[0].Description != "No TV internet" || h.Rules[1].Description != "Whole LAN" {
		t.Fatalf("rules: %+v", h.Rules)
	}
	if len(h.Forwards) != 1 || h.Forwards[0].Public != "8443" || strings.Join(h.DNSNames, ",") != "television" {
		t.Fatalf("forwards %+v names %v", h.Forwards, h.DNSNames)
	}
}

// A reservation names the MAC even while the device is away; what answers on
// the network wins when it differs.
func TestSDNHostInfo_ReservationAndNeighbour(t *testing.T) {
	hostInfoEnv(t, `[]`, `[{"dev":"vmbr0"}]`)
	h := SDNHostInfoFor(hostInfoConfig(), netip.MustParseAddr("192.168.2.7"), time.Now())
	if h.MAC != "aa:aa:aa:aa:aa:aa" || h.MACSource != "DHCP reservation" || !h.DHCP.Reserved || h.DHCP.Description != "Bureau" || h.DHCP.InPool {
		t.Fatalf("reservation: %+v dhcp %+v", h, h.DHCP)
	}
	if !h.MACPrivate {
		t.Fatal("aa:… is locally administered")
	}
	hostInfoEnv(t, `[{"dev":"vmbr0","lladdr":"BB:00:00:00:00:02","state":["STALE"]}]`, `[{"dev":"vmbr0"}]`)
	h = SDNHostInfoFor(hostInfoConfig(), netip.MustParseAddr("192.168.2.7"), time.Now())
	if h.MAC != "bb:00:00:00:00:02" || h.MACSource != "Seen on the network" || h.State != "STALE" {
		t.Fatalf("neighbour: %+v", h)
	}
}

func TestSDNHostInfo_RolesAndRouted(t *testing.T) {
	hostInfoEnv(t, `[]`, `[{"dev":"vmbr0","gateway":"192.168.2.254"}]`)
	c := hostInfoConfig()
	if h := SDNHostInfoFor(c, netip.MustParseAddr("192.168.2.1"), time.Now()); h.Role != "gateway" {
		t.Fatalf("network's address: %+v", h)
	}
	h := SDNHostInfoFor(c, netip.MustParseAddr("10.8.0.2"), time.Now())
	if h.Role != "vpn" || h.VPNPeer != "iPad" || h.Name != "iPad" {
		t.Fatalf("vpn: %+v", h)
	}
	h = SDNHostInfoFor(c, netip.MustParseAddr("10.50.0.9"), time.Now())
	if h.Via != "192.168.2.254" || h.Network == nil || h.Network.Name != "Maison" || h.Network.CIDR != "" || h.MAC != "" {
		t.Fatalf("routed: %+v", h)
	}
}

func TestSDNHostInfo_Instance(t *testing.T) {
	hostInfoEnv(t, `[]`, `[]`)
	a := netip.MustParseAddr("192.168.2.60")
	sdnTC.mu.Lock()
	sdnTC.names = map[netip.Addr]string{a: "web01"}
	sdnTC.mu.Unlock()
	t.Cleanup(func() { sdnTC.mu.Lock(); sdnTC.names = nil; sdnTC.mu.Unlock() })
	sdnHostInstanceOf = func(_, addr string) *SDNHostInstance {
		return parseHostInstance([]byte(`[{"name":"web01","type":"container","status":"Running","project":"default","expanded_config":{"limits.cpu":"2","limits.memory":"4GiB","image.os":"Debian","image.release":"trixie"},"state":{"network":{"eth0":{"hwaddr":"00:16:3e:00:00:09","addresses":[{"family":"inet","address":"192.168.2.60"}]}}}}]`), addr)
	}
	h := SDNHostInfoFor(hostInfoConfig(), a, time.Now())
	if h.Role != "instance" || h.Name != "web01" || h.Instance.CPU != "2" || h.Instance.Memory != "4GiB" || h.Instance.OS != "Debian trixie" || h.MAC != "00:16:3e:00:00:09" {
		t.Fatalf("instance: %+v %+v", h, h.Instance)
	}
}

func TestSDNHostContains(t *testing.T) {
	a := netip.MustParseAddr("192.168.2.50")
	for v, want := range map[string]bool{"192.168.2.50": true, "192.168.2.0/24": true, "192.168.2.40-192.168.2.60": true, "192.168.2.51": false, "10.0.0.0/8": false, "": false, "nonsense": false} {
		if sdnHostContains(v, a) != want {
			t.Errorf("%q: want %v", v, want)
		}
	}
}
