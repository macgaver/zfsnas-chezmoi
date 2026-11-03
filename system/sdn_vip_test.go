package system

import (
	"strings"
	"testing"

	"zfsnas/internal/sdn"
)

func vipTestConfig(vips ...sdn.VirtualIP) *sdn.Config {
	c := &sdn.Config{Interfaces: []sdn.Interface{
		{ID: "if000001", Name: "LAN", Kind: "bridge", Device: "vmbr0", Role: "lan", IPv4Mode: "static", IPv4: "192.168.2.113/24", VirtualIPs: vips},
	}}
	c.Normalize()
	return c
}

const vipAddrJSON = `[{"ifname":"vmbr0","addr_info":[{"family":"inet","local":"192.168.2.113","prefixlen":24}%s]}]`

// The keeper adds a missing virtual IP only when nobody answers for it, then
// announces it; an address held elsewhere is left alone and reported.
func TestSDNReconcileVIPs(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	old := sdnConfigDir
	sdnConfigDir = dir
	t.Cleanup(func() { sdnConfigDir = old })
	oldA := sdnHaveArping
	sdnHaveArping = func() bool { return true }
	t.Cleanup(func() { sdnHaveArping = oldA })

	show := "ip -4 -j addr show dev vmbr0"
	probe := "arping -D -c 2 -w 3 -I vmbr0 192.168.2.1"
	rec.out = map[string]string{show: strings.Replace(vipAddrJSON, "%s", "", 1)}

	// free: added, then announced
	c := vipTestConfig(sdn.VirtualIP{Address: "192.168.2.1", ForClients: true})
	SDNReconcileVIPs(c)
	add, garp := rec.index("ip addr add 192.168.2.1/24 dev vmbr0"), rec.index("arping -U -c 2 -I vmbr0 192.168.2.1")
	if rec.index(probe) < 0 || add < 0 || garp < add {
		t.Fatalf("probe, add, announce expected: %v", rec.cmds)
	}
	if st := SDNVIPStatus()["192.168.2.1"]; st.State != "active" {
		t.Fatalf("status %+v", st)
	}

	// already there: nothing to do
	rec.cmds = nil
	rec.out[show] = strings.Replace(vipAddrJSON, "%s", `,{"family":"inet","local":"192.168.2.1","prefixlen":24}`, 1)
	SDNReconcileVIPs(c)
	if rec.index("ip addr add") >= 0 || rec.index("arping") >= 0 {
		t.Fatalf("present VIP touched: %v", rec.cmds)
	}

	// removed from the configuration: taken off the device
	rec.cmds = nil
	SDNReconcileVIPs(vipTestConfig())
	if rec.index("ip addr del 192.168.2.1/24 dev vmbr0") < 0 {
		t.Fatalf("stale VIP kept: %v", rec.cmds)
	}
	if _, ok := SDNVIPStatus()["192.168.2.1"]; ok {
		t.Fatal("status of a removed VIP kept")
	}

	// held by another server: not added, reported with its MAC
	rec.cmds = nil
	rec.out[show] = strings.Replace(vipAddrJSON, "%s", "", 1)
	rec.out[probe] = "ARPING 192.168.2.1 from 0.0.0.0 vmbr0\nUnicast reply from 192.168.2.1 [AA:BB:CC:00:11:22]  0.812ms\nSent 1 probes (1 broadcast(s))\nReceived 1 response(s)\n"
	SDNReconcileVIPs(c)
	if rec.index("ip addr add") >= 0 {
		t.Fatalf("added over another holder: %v", rec.cmds)
	}
	if st := SDNVIPStatus()["192.168.2.1"]; st.State != "conflict" || st.MAC != "aa:bb:cc:00:11:22" {
		t.Fatalf("status %+v", st)
	}
}

// Without arping the probe falls back to ping + the neighbour table (ARP
// answers even when the other host drops pings); no announcement then.
func TestSDNReconcileVIPs_NoArping(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	old := sdnConfigDir
	sdnConfigDir = dir
	t.Cleanup(func() { sdnConfigDir = old })
	oldA, oldP := sdnHaveArping, sdnVIPPing
	sdnHaveArping = func() bool { return false }
	pinged := ""
	sdnVIPPing = func(dev, ip string) { pinged = dev + " " + ip }
	t.Cleanup(func() { sdnHaveArping, sdnVIPPing = oldA, oldP })
	show, neigh := "ip -4 -j addr show dev vmbr0", "ip -4 -j neigh show to 192.168.2.1 dev vmbr0"
	rec.out = map[string]string{show: strings.Replace(vipAddrJSON, "%s", "", 1), neigh: `[]`}
	c := vipTestConfig(sdn.VirtualIP{Address: "192.168.2.1"})
	SDNReconcileVIPs(c)
	if pinged != "vmbr0 192.168.2.1" || rec.index("ip addr add 192.168.2.1/24 dev vmbr0") < 0 || rec.index("arping") >= 0 {
		t.Fatalf("pinged %q, cmds %v", pinged, rec.cmds)
	}
	rec.cmds = nil
	SDNReconcileVIPs(vipTestConfig()) // forget it
	rec.out[neigh] = `[{"dst":"192.168.2.1","dev":"vmbr0","lladdr":"aa:bb:cc:00:11:22","state":["REACHABLE"]}]`
	SDNReconcileVIPs(c)
	if rec.index("ip addr add") >= 0 || SDNVIPStatus()["192.168.2.1"].State != "conflict" {
		t.Fatalf("in use, yet: %v %+v", rec.cmds, SDNVIPStatus())
	}
}
