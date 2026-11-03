package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zfsnas/internal/sdn"
)

func withPort(c *sdn.Config, off bool) *sdn.Config {
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "if0port1", Name: "Guests", Kind: "physical", Device: "enp6s0", Role: "lan", IPv4Mode: "static", IPv4: "10.9.0.1/24", Disabled: off})
	c.Normalize()
	return c
}

func offVLAN(c *sdn.Config) *sdn.Config {
	c.Interfaces[len(c.Interfaces)-1].Disabled = true
	return c
}

// A disabled VLAN leaves the system; enabling it brings it back.
func TestSDNApply_DisabledVLANGoesAndComesBack(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	on, off := withVLAN700(labBase()), offVLAN(withVLAN700(labBase()))
	if _, err := SDNApply(labBase(), on, sdnEnv); err != nil {
		t.Fatal(err)
	}
	rec.cmds = nil
	if _, err := SDNApply(on, off, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("ifdown --force enp7s0-v700") < 0 {
		t.Fatalf("not taken down: %v", rec.cmds)
	}
	if b, _ := os.ReadFile(hostInterfacesPath); strings.Contains(string(b), "enp7s0-v700") {
		t.Fatalf("stanza kept:\n%s", b)
	}
	rec.cmds = nil
	if _, err := SDNApply(off, on, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("ifup enp7s0-v700") < 0 {
		t.Fatalf("not brought back: %v", rec.cmds)
	}
}

// An adopted port keeps its stanza (it is not ours to delete): its link is
// held down instead, and released again.
func TestSDNApply_DisabledPortLinkDownAndUp(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	on, off := withPort(labBase(), false), withPort(labBase(), true)
	if _, err := SDNApply(on, off, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("ifdown --force enp6s0") < 0 || rec.index("ip link set dev enp6s0 down") < 0 {
		t.Fatalf("not down: %v", rec.cmds)
	}
	rec.cmds = nil
	if _, err := SDNApply(off, off, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("ifdown") >= 0 || rec.index("ifup enp6s0") >= 0 {
		t.Fatalf("an unrelated apply bounced it: %v", rec.cmds)
	}
	rec.cmds = nil
	if _, err := SDNApply(off, on, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("ip link set dev enp6s0 up") < 0 {
		t.Fatalf("not released: %v", rec.cmds)
	}
	// removed from the Firewall while disabled: released as well
	rec.cmds = nil
	if _, err := SDNApply(off, labBase(), sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("ip link set dev enp6s0 up") < 0 {
		t.Fatalf("left down after removal: %v", rec.cmds)
	}
}

// A missing port that is disabled is no reason for safe mode at boot.
func TestSDNMissingDevices_IgnoresDisabled(t *testing.T) {
	sdnTestEnv(t)
	c := labBase()
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "if0gone1", Name: "Gone", Kind: "physical", Device: "enp99s0", IPv4Mode: "none", Disabled: true})
	if m := sdnMissingDevices(c); len(m) != 0 {
		t.Fatalf("%v", m)
	}
}

// Networking brings "auto" ports up at boot: the monitor puts them back.
func TestSDNHoldDisabledDown(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	c := withPort(labBase(), true)
	flags := filepath.Join(sdnSysClassNet, "enp6s0", "flags")
	_ = os.WriteFile(flags, []byte("0x1003\n"), 0644)
	sdnHoldDisabledDown(c)
	if rec.index("ip link set dev enp6s0 down") < 0 {
		t.Fatalf("%v", rec.cmds)
	}
	rec.cmds = nil
	_ = os.WriteFile(flags, []byte("0x1002\n"), 0644)
	sdnHoldDisabledDown(c)
	if len(rec.cmds) != 0 {
		t.Fatalf("already down: %v", rec.cmds)
	}
}

// A gateway on a disabled interface is not usable, whatever its address.
func TestSDNResolveHops_SkipsDisabled(t *testing.T) {
	sdnTestEnv(t)
	c := withPort(labBase(), true)
	c.Gateways = []sdn.Gateway{{ID: "gw000001", Name: "ISP", Interface: "if0port1", Address: "10.9.0.254", Priority: 1}}
	if h := SDNResolveHops(c); len(h) != 0 {
		t.Fatalf("%v", h)
	}
}

// No virtual IP is added to a disabled interface.
func TestSDNDisabled_NoVIP(t *testing.T) {
	sdnTestEnv(t)
	c := withPort(labBase(), true)
	c.Interfaces[len(c.Interfaces)-1].VirtualIPs = []sdn.VirtualIP{{Address: "10.9.0.2"}}
	SDNReconcileVIPs(c)
	if st := SDNVIPStatus(); len(st) != 0 {
		t.Fatalf("%v", st)
	}
}

// Nothing to watch: Suricata is stopped and has no config with no interface.
func TestSDNIDS_IdleWhenWatchedInterfaceDisabled(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	c := withPort(labBase(), false)
	c.Interfaces[len(c.Interfaces)-1].Role = "wan"
	c.IDS.Enabled = true
	if _, _, err := sdnIDSFiles(c); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sdnIDSConf); err != nil {
		t.Fatal(err)
	}
	c.Interfaces[len(c.Interfaces)-1].Disabled = true
	changed, _, err := sdnIDSFiles(c)
	if err != nil || !changed {
		t.Fatalf("%v %v", changed, err)
	}
	if _, err := os.Stat(sdnIDSConf); err == nil {
		t.Fatal("config kept")
	}
	rec.cmds = nil
	sdnApplyIDS(c, changed, false, &SDNApplyResult{})
	if rec.index("systemctl stop") < 0 || rec.index("systemctl restart") >= 0 {
		t.Fatalf("%v", rec.cmds)
	}
}

// The portal cannot list /etc/ppp/peers (root:dip 2750): a removed link's
// peer file goes by name.
func TestSDNApply_RemovedPPPoELosesItsPeerFile(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	on := labBase()
	on.Interfaces = append(on.Interfaces, sdn.Interface{ID: "ifppp001", Name: "Bell", Kind: "pppoe", Parent: "enp6s0", Role: "wan", IPv4Mode: "pppoe", PPPoEUser: "u", PPPoEPassword: "p"})
	on.Normalize()
	if _, err := SDNApply(on, labBase(), sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("rm "+filepath.Join(sdnPPPDir, "peers", sdn.PPPoEPeerName("ifppp001"))) < 0 {
		t.Fatalf("%v", rec.cmds)
	}
}
