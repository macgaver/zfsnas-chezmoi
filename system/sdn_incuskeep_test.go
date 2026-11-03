package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zfsnas/internal/sdn"
)

func keptCfg() *sdn.Config {
	c := labBase()
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "ifinc400", Name: "VM400", Kind: "incus", Device: "vmbr0-400", Role: "lan",
		IPv4Mode: "static", IPv4: "10.128.14.1/24", IncusKeep: true, IncusDHCP: true})
	c.Normalize()
	return c
}

func incusCalls(rec *recorder) []string {
	var out []string
	for _, l := range rec.cmds {
		if strings.HasPrefix(l, "incus ") {
			out = append(out, l)
		}
	}
	return out
}

// Adding, keeping and removing a kept bridge never touches Incus: its address
// and DHCP stay what the VMs depend on.
func TestSDNApply_KeptIncusUntouched(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	base := labBase()
	kept := keptCfg()
	for _, step := range [][2]*sdn.Config{{base, kept}, {kept, kept}, {kept, base}} {
		if _, err := SDNApply(step[0], step[1], sdnEnv); err != nil {
			t.Fatal(err)
		}
	}
	if got := incusCalls(rec); len(got) != 0 {
		t.Fatalf("Incus was changed: %v", got)
	}
}

// Disabling the Firewall hands adopted bridges back by clearing their
// address; a kept one has to keep it.
func TestIncusRelease_KeptKeepsAddress(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	sdnReleaseIncusBridges(keptCfg())
	if got := incusCalls(rec); len(got) != 0 {
		t.Fatalf("Incus was changed: %v", got)
	}
}

// What Incus says wins: address, and DHCP/DNS with their Incus defaults (on
// when unset).
func TestSDNSyncIncusKept(t *testing.T) {
	sdnTestEnv(t)
	vals := map[string]string{"ipv4.address": "10.128.44.1/24", "dns.mode": "none"}
	sdnIncusNetKey = func(_, k string) string { return vals[k] }
	c := keptCfg()
	if !sdnSyncIncusKept(c) {
		t.Fatal("no change seen")
	}
	in := c.Interfaces[len(c.Interfaces)-1]
	if in.IPv4 != "10.128.44.1/24" || !in.IncusDHCP || in.IncusDNS {
		t.Fatalf("%+v", in)
	}
	if sdnSyncIncusKept(c) {
		t.Fatal("a second sync changed something")
	}
	vals["ipv4.dhcp"], vals["dns.mode"] = "false", "managed"
	sdnSyncIncusKept(c)
	if in = c.Interfaces[len(c.Interfaces)-1]; in.IncusDHCP || !in.IncusDNS {
		t.Fatalf("%+v", in)
	}
	// Incus not answering / no address: keep what is known.
	vals = map[string]string{}
	if sdnSyncIncusKept(c) || c.Interfaces[len(c.Interfaces)-1].IPv4 != "10.128.44.1/24" {
		t.Fatalf("%+v", c.Interfaces[len(c.Interfaces)-1])
	}
}

// A kept network stays editable in VMs & Containers, but cannot be deleted
// from under the Firewall's rules.
func TestFirewallOwns_KeptIsIncus(t *testing.T) {
	_, dir := sdnTestEnv(t)
	cfgDir := filepath.Join(dir, "cfg")
	_ = os.MkdirAll(cfgDir, 0755)
	old := sdnConfigDir
	sdnConfigDir = cfgDir
	t.Cleanup(func() { sdnConfigDir = old })
	st := sdn.Store{Dir: cfgDir}
	if err := st.SaveConfirmed(keptCfg()); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveState(sdn.State{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := FirewallOwnsNetwork("vmbr0-400"); err != nil {
		t.Fatalf("edit refused: %v", err)
	}
	if err := FirewallUsesNetwork("vmbr0-400"); err == nil {
		t.Fatal("delete allowed")
	}
	if err := FirewallUsesNetwork("other"); err != nil {
		t.Fatal(err)
	}
}
