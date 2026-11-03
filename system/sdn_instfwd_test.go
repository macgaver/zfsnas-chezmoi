package system

import (
	"strconv"
	"strings"
	"testing"

	"zfsnas/internal/sdn"
)

// instFwdEnv: SDN enabled with a WAN interface, instance address lookup faked.
func instFwdEnv(t *testing.T) (*recorder, sdn.Store) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	old, oldDir, oldEnv := sdnInstanceAddr, sdnConfigDir, sdnRuntimeEnv
	sdnInstanceAddr = func(instance, nic string) string {
		if instance == "web" {
			return "10.128.7.20"
		}
		return ""
	}
	sdnConfigDir, sdnRuntimeEnv = dir, sdnEnv
	t.Cleanup(func() { sdnInstanceAddr, sdnConfigDir, sdnRuntimeEnv = old, oldDir, oldEnv })
	_ = st.SaveState(sdn.State{Enabled: true})
	_ = st.SaveConfirmed(gwConfig())
	return rec, st
}

func TestSDNSetInstanceForwards(t *testing.T) {
	rec, st := instFwdEnv(t)
	err := SDNSetInstanceForwards("web", "eth0", []NICPortForward{
		{SourcePort: 8443, TargetPort: 443, Protocol: "tcp", Interfaces: []string{"if0wan01"}},
		{SourcePort: 2222, TargetPort: 22, Protocol: "tcp"}, // no interface: paused
	}, "demo")
	if err != nil {
		t.Fatal(err)
	}
	i := rec.index("nft -f -")
	if i < 0 || !strings.Contains(rec.stdin[i], "dnat to 10.128.7.20:443") || strings.Contains(rec.stdin[i], ":22 ") {
		t.Fatalf("ruleset: %v\n%s", rec.cmds, rec.stdin[i])
	}
	c, _ := st.LoadConfirmed()
	if len(c.PortForwards) != 2 || !c.PortForwards[0].TargetAuto {
		t.Fatalf("saved: %+v", c.PortForwards)
	}
	if h, _ := st.ListSnapshots(); len(h) != 1 || !strings.Contains(h[0].Summary, "web") || h[0].Outcome != "confirmed" {
		t.Fatalf("history: %+v", h)
	}
	// GET round trip: interfaces kept, auto address not shown as typed.
	got := SDNInstanceForwards("web")["eth0"]
	if len(got) != 2 || got[0].SourcePort != 8443 || got[0].TargetAddr != "" || len(got[0].Interfaces) != 1 || len(got[1].Interfaces) != 0 {
		t.Fatalf("round trip: %+v", got)
	}
}

func TestSDNSetInstanceForwards_ExplicitTargetAndUnknownAddress(t *testing.T) {
	_, st := instFwdEnv(t)
	// Address unknown (just created): saved, waits, not in the ruleset.
	if err := SDNSetInstanceForwards("db", "eth0", []NICPortForward{{SourcePort: 5432, TargetPort: 5432, Protocol: "tcp", Interfaces: []string{"if0wan01"}}}, "demo"); err != nil {
		t.Fatal(err)
	}
	if err := SDNSetInstanceForwards("db", "eth0", []NICPortForward{{SourcePort: 5432, TargetPort: 5432, Protocol: "tcp", TargetAddr: "10.128.7.30", Interfaces: []string{"if0wan01"}}}, "demo"); err != nil {
		t.Fatal(err)
	}
	c, _ := st.LoadConfirmed()
	if c.PortForwards[0].Target != "10.128.7.30" || c.PortForwards[0].TargetAuto {
		t.Fatalf("%+v", c.PortForwards[0])
	}
	if got := SDNInstanceForwards("db")["eth0"]; got[0].TargetAddr != "10.128.7.30" {
		t.Fatalf("explicit address lost: %+v", got)
	}
}

func TestSDNSetInstanceForwards_CarriedIntoDraft(t *testing.T) {
	_, st := instFwdEnv(t)
	d, _ := st.LoadDraft()
	d.Config.Interfaces[0].Name = "LAN renamed"
	if _, err := st.SaveDraft(d.Config, 0, "demo"); err != nil {
		t.Fatal(err)
	}
	if err := SDNSetInstanceForwards("web", "eth0", []NICPortForward{{SourcePort: 80, TargetPort: 80, Protocol: "tcp"}}, "demo"); err != nil {
		t.Fatal(err)
	}
	d, _ = st.LoadDraft()
	if d.Config.Interfaces[0].Name != "LAN renamed" || len(d.Config.PortForwards) != 1 {
		t.Fatalf("draft: %+v", d.Config)
	}
}

func TestSDNSetInstanceForwards_RefusedDuringCountdown(t *testing.T) {
	_, st := instFwdEnv(t)
	if err := SDNArmRevert(st, "/bin/true", PreviousTarget, "x", 30, ""); err != nil {
		t.Fatal(err)
	}
	if err := SDNSetInstanceForwards("web", "eth0", nil, "demo"); err == nil || !strings.Contains(err.Error(), "confirmation") {
		t.Fatalf("accepted during countdown: %v", err)
	}
}

func TestSDNForgetInstance(t *testing.T) {
	rec, st := instFwdEnv(t)
	_ = SDNSetInstanceForwards("web", "eth0", []NICPortForward{{SourcePort: 80, TargetPort: 80, Protocol: "tcp", Interfaces: []string{"if0wan01"}}}, "demo")
	rec.cmds = nil
	SDNForgetInstance("web")
	c, _ := st.LoadConfirmed()
	if len(c.PortForwards) != 0 || rec.index("nft -f -") < 0 {
		t.Fatalf("left %+v / %v", c.PortForwards, rec.cmds)
	}
	rec.cmds = nil
	SDNForgetInstance("nothing")
	if rec.index("nft -f -") >= 0 {
		t.Fatal("reloaded for an instance without forwards")
	}
}

func TestSDNRefreshInstanceTargets(t *testing.T) {
	rec, st := instFwdEnv(t)
	addr := map[string]string{}
	sdnInstanceAddr = func(instance, nic string) string { return addr[instance] }
	_ = SDNSetInstanceForwards("web", "eth0", []NICPortForward{{SourcePort: 80, TargetPort: 80, Protocol: "tcp", Interfaces: []string{"if0wan01"}}}, "demo")
	_ = SDNSetInstanceForwards("db", "eth0", []NICPortForward{{SourcePort: 5432, TargetPort: 5432, Protocol: "tcp", TargetAddr: "10.0.0.9", Interfaces: []string{"if0wan01"}}}, "demo")

	rec.cmds = nil
	if n := SDNRefreshInstanceTargets(); n != 0 || rec.index("nft -f -") >= 0 {
		t.Fatalf("no address yet: changed %d", n)
	}
	addr["web"], addr["db"] = "10.128.7.20", "10.0.0.50"
	if n := SDNRefreshInstanceTargets(); n != 1 {
		t.Fatalf("changed %d, want 1 (explicit target must not follow)", n)
	}
	c, _ := st.LoadConfirmed()
	for _, f := range c.PortForwards {
		if f.Instance == "web" && f.Target != "10.128.7.20" || f.Instance == "db" && f.Target != "10.0.0.9" {
			t.Fatalf("%+v", f)
		}
	}
	// Address briefly unknown (instance stopped): keep the last one.
	addr["web"] = ""
	rec.cmds = nil
	if n := SDNRefreshInstanceTargets(); n != 0 {
		t.Fatalf("cleared on unknown: %d", n)
	}
	addr["web"] = "10.128.7.21"
	if SDNRefreshInstanceTargets() != 1 {
		t.Fatal("did not follow the new lease")
	}
}

func fakeIncusDevices(t *testing.T, devs map[string]map[string]map[string]string) *[]string {
	var removed []string
	oldList, oldRm, oldAdd, oldOK := sdnListInstanceDevices, sdnRemoveInstanceDevice, sdnAddProxyForwards, sdnIncusOK
	sdnIncusOK = func() bool { return true }
	sdnListInstanceDevices = func() (map[string]map[string]map[string]string, error) { return devs, nil }
	sdnRemoveInstanceDevice = func(instance, dev string) error {
		removed = append(removed, instance+"/"+dev)
		return nil
	}
	sdnAddProxyForwards = func(instance, nic string, f []NICPortForward) error {
		removed = append(removed, "add "+instance+"/"+nic+" "+strconv.Itoa(len(f)))
		return nil
	}
	t.Cleanup(func() {
		sdnListInstanceDevices, sdnRemoveInstanceDevice, sdnAddProxyForwards, sdnIncusOK = oldList, oldRm, oldAdd, oldOK
	})
	return &removed
}

var webProxies = map[string]map[string]map[string]string{"web": {
	"eth0":             {"type": "nic"},
	"fwd-eth0-tcp-443": {"type": "proxy", "listen": "tcp:192.168.2.130:443", "connect": "tcp:0.0.0.0:8443", "nat": "true"},
	"fwd-eth0-udp-53":  {"type": "proxy", "listen": "udp:0.0.0.0:53", "connect": "udp:10.1.1.5:53"},
	"mine":             {"type": "proxy", "listen": "tcp:0.0.0.0:1", "connect": "tcp:127.0.0.1:1"},
}}

func TestSDNAdoptProxyForwards(t *testing.T) {
	_, _ = instFwdEnv(t)
	fakeIncusDevices(t, webProxies)
	last := gwConfig()
	// Re-enable: the forward published before keeps its interfaces.
	last.PortForwards = []sdn.PortForward{{ID: sdn.InstanceForwardID("web", "eth0", "tcp", 443), Instance: "web", NIC: "eth0", Interfaces: []string{"if0wan01"}}}
	got := SDNAdoptProxyForwards(last)
	if len(got) != 2 {
		t.Fatalf("adopted %+v", got)
	}
	byPort := map[string]sdn.PortForward{}
	for _, f := range got {
		byPort[f.PubPorts] = f
	}
	https, dns := byPort["443"], byPort["53"]
	if https.TargetPorts != "8443" || !https.TargetAuto || https.Target != "10.128.7.20" || len(https.Interfaces) != 1 {
		t.Fatalf("443: %+v", https)
	}
	if dns.Protocol != "udp" || dns.Target != "10.1.1.5" || dns.TargetAuto || !dns.Paused() {
		t.Fatalf("53 (new → paused, explicit target): %+v", dns)
	}
}

func TestSDNDropProxyForwards(t *testing.T) {
	_, st := instFwdEnv(t)
	removed := fakeIncusDevices(t, webProxies)
	c, _ := st.LoadConfirmed()
	c.PortForwards = SDNAdoptProxyForwards(c)
	_ = st.SaveConfirmed(c)
	SDNDropProxyForwards()
	if strings.Join(*removed, ",") != "web/fwd-eth0-tcp-443,web/fwd-eth0-udp-53" {
		t.Fatalf("removed %v", *removed)
	}
	// Not while a change waits for confirmation (the enable could revert).
	*removed = nil
	_ = SDNArmRevert(st, "/bin/true", PreSDNTarget, "x", 30, "")
	SDNDropProxyForwards()
	if len(*removed) != 0 {
		t.Fatalf("removed during countdown: %v", *removed)
	}
}

func TestSDNRestoreProxyForwards(t *testing.T) {
	_, _ = instFwdEnv(t)
	added := fakeIncusDevices(t, nil)
	c := gwConfig()
	c.PortForwards = []sdn.PortForward{
		{ID: "a", Instance: "web", NIC: "eth0", Protocol: "tcp", PubPorts: "443", TargetPorts: "8443", Target: "10.1.1.1", TargetAuto: true},
		{ID: "b", Instance: "web", NIC: "eth0", Protocol: "udp", PubPorts: "53", TargetPorts: "53", Target: "10.1.1.5", Interfaces: []string{"if0wan01"}},
		{ID: "c", Instance: "db", NIC: "eth1", Protocol: "tcp", PubPorts: "5432", TargetPorts: "5432"},
		{ID: "m", Protocol: "tcp", PubPorts: "80", TargetPorts: "80", Target: "10.0.0.2"},
	}
	SDNRestoreProxyForwards(c)
	if strings.Join(*added, ",") != "add db/eth1 1,add web/eth0 2" {
		t.Fatalf("got %v", *added)
	}
}

func TestSDNSetInstanceForwards_UnchangedIsNoop(t *testing.T) {
	rec, st := instFwdEnv(t)
	fw := []NICPortForward{{SourcePort: 80, TargetPort: 80, Protocol: "tcp", Interfaces: []string{"if0wan01"}}}
	_ = SDNSetInstanceForwards("web", "eth0", fw, "demo")
	rec.cmds = nil
	_ = SDNSetInstanceForwards("web", "eth0", fw, "demo")
	_ = SDNSetInstanceForwards("web", "eth1", nil, "demo") // a NIC without forwards
	if rec.index("nft -f -") >= 0 {
		t.Fatalf("reloaded for nothing: %v", rec.cmds)
	}
	if h, _ := st.ListSnapshots(); len(h) != 1 {
		t.Fatalf("history entries: %d", len(h))
	}
}
