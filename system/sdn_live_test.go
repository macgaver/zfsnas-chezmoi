package system

import (
	"os"
	"path/filepath"
	"testing"
)

func fakeNIC(t *testing.T, sys, name string, files map[string]string, dirs ...string) {
	t.Helper()
	base := filepath.Join(sys, name)
	_ = os.MkdirAll(filepath.Join(base, "statistics"), 0755)
	defaults := map[string]string{"address": "10:66:6a:00:00:01", "operstate": "up", "mtu": "1500",
		"statistics/rx_bytes": "1000", "statistics/tx_bytes": "2000"}
	for k, v := range files {
		defaults[k] = v
	}
	for k, v := range defaults {
		_ = os.WriteFile(filepath.Join(base, k), []byte(v+"\n"), 0644)
	}
	for _, d := range dirs {
		_ = os.MkdirAll(filepath.Join(base, d), 0755)
	}
}

func TestSDNLive_KindsAndAdoptable(t *testing.T) {
	_, _ = sdnTestEnv(t)
	sys := sdnSysClassNet
	_ = os.RemoveAll(sys)
	fakeNIC(t, sys, "lo", nil)
	fakeNIC(t, sys, "enp5s0", map[string]string{"speed": "1000"}, "device")
	fakeNIC(t, sys, "enp7s0", nil, "device")
	fakeNIC(t, sys, "enp6s0", nil, "device")
	_ = os.Symlink("../vmbr0", filepath.Join(sys, "enp6s0", "master"))
	fakeNIC(t, sys, "vmbr0", nil, "bridge")
	fakeNIC(t, sys, "host-nat", nil, "bridge")
	fakeNIC(t, sys, "enp7s0-v700", map[string]string{"uevent": "DEVTYPE=vlan"})
	fakeNIC(t, sys, "tap1234", map[string]string{"uevent": "DEVTYPE=tap"})
	fakeNIC(t, sys, "docker0", nil, "bridge")
	// links the Firewall itself brings up: listed for their address only
	fakeNIC(t, sys, "ppp-a5157f4c", map[string]string{"type": "512"})
	fakeNIC(t, sys, "wg-0d69bdab", map[string]string{"uevent": "DEVTYPE=wireguard"})

	oldInc, oldAddrs, oldWin := sdnIncusManagedBridges, sdnIfaceAddrs, sdnRateWindow
	t.Cleanup(func() { sdnIncusManagedBridges, sdnIfaceAddrs, sdnRateWindow = oldInc, oldAddrs, oldWin })
	sdnIncusManagedBridges = func() map[string]string { return map[string]string{"host-nat": "10.72.36.1/24"} }
	sdnIfaceAddrs = func(name string) []string {
		switch name {
		case "vmbr0":
			return []string{"192.168.2.129/24"}
		case "ppp-a5157f4c":
			return []string{"69.156.169.77/32"}
		}
		return nil
	}
	sdnRateWindow = 0

	list, err := SDNLiveInterfaces("192.168.2.129")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]SDNLiveIface{}
	for _, l := range list {
		got[l.Device] = l
	}
	if _, ok := got["lo"]; ok {
		t.Fatal("loopback listed")
	}
	if _, ok := got["tap1234"]; ok {
		t.Fatal("tap device listed")
	}
	check := func(dev, kind string, adoptable bool, reason string) {
		t.Helper()
		l, ok := got[dev]
		if !ok {
			t.Fatalf("%s missing", dev)
		}
		if l.Kind != kind || l.Adoptable != adoptable || (reason != "" && l.Reason != reason) {
			t.Fatalf("%s = %+v", dev, l)
		}
	}
	check("enp5s0", "physical", true, "")
	check("enp6s0", "physical", false, "port of bridge vmbr0")
	check("vmbr0", "bridge", true, "")
	check("host-nat", "bridge", true, "")
	check("docker0", "bridge", false, "Docker network")
	check("enp7s0-v700", "vlan", true, "")
	check("ppp-a5157f4c", "ppp", false, "PPPoE link")
	check("wg-0d69bdab", "wireguard", false, "WireGuard tunnel")
	if a := got["ppp-a5157f4c"].IPv4; len(a) != 1 || a[0] != "69.156.169.77/32" {
		t.Fatalf("PPPoE address %v", a)
	}
	if !got["vmbr0"].Mgmt || got["enp5s0"].Mgmt {
		t.Fatal("mgmt detection wrong")
	}
	if got["enp5s0"].SpeedMbps != 1000 || got["enp5s0"].MTU != 1500 {
		t.Fatalf("enp5s0 = %+v", got["enp5s0"])
	}
}

func TestParseNftCounters(t *testing.T) {
	b, err := os.ReadFile("testdata/nft_list_znas_sdn.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseNftCounters(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if got["r0000002"].Packets != 7 || got["r0000002"].Bytes != 420 {
		t.Fatalf("reject rule must sum its two lines: %+v", got["r0000002"])
	}
	if got["r0000001"].Packets != 12 || got["r0000001"].Bytes != 980 {
		t.Fatalf("r0000001 = %+v", got["r0000001"])
	}
}

func TestSDNCounterSamplerDelta(t *testing.T) {
	s := newCounterHistory()
	s.observe(map[string]RuleCounter{"a": {Packets: 10}})
	s.observe(map[string]RuleCounter{"a": {Packets: 15}})
	s.observe(map[string]RuleCounter{"a": {Packets: 3}}) // table reloaded: counters restart
	sp := s.spark("a")
	if len(sp) != 3 || sp[0] != 10 || sp[1] != 5 || sp[2] != 3 {
		t.Fatalf("spark = %v", sp)
	}
	if s.lastHit("a").IsZero() {
		t.Fatal("last hit not recorded")
	}
}

func TestParseBlockedSet(t *testing.T) {
	b, _ := os.ReadFile("testdata/nft_list_blk.json")
	got, err := parseBlockedSet(b)
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	if g := got[0]; g.Src != "175.16.199.1" || g.Proto != "tcp" || g.Port != 22 || g.Iface != "enp6s0" || g.Rule != 0 || g.Packets != 8 {
		t.Fatalf("%+v", g)
	}
	if got[1].Rule != 2 || got[1].Proto != "icmp" {
		t.Fatalf("%+v", got[1])
	}
}
