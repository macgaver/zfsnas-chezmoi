package system

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"zfsnas/internal/sdn"
)

func twoGateways() *sdn.Config {
	c := gwConfig()
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "if0wan02", Name: "WAN2", Kind: "physical", Device: "enp8s0", Role: "wan", IPv4Mode: "static", IPv4: "10.251.0.2/24"})
	c.Gateways = append(c.Gateways, sdn.Gateway{ID: "gwisp002", Name: "ISP2", Interface: "if0wan02", Address: "10.251.0.1", Priority: 2, Monitor: true})
	c.Normalize()
	return c
}

func fakePing(t *testing.T, down map[string]bool) {
	old := sdnPing
	sdnPing = func(dev, target string, mark uint32, count int) (bool, time.Duration) {
		return !down[dev], 3 * time.Millisecond
	}
	t.Cleanup(func() { sdnPing = old })
}

func TestGWMonitor_Failover(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	rec.out = map[string]string{"ip -4 -j addr show dev enp6s0": `[{"addr_info":[{"local":"10.250.0.2"}]}]`,
		"ip -4 -j route show default": `[{"gateway":"10.250.0.1","dev":"enp6s0"}]`}
	down := map[string]bool{}
	fakePing(t, down)
	c := twoGateways()
	m := newGWMonitor(GWStateFile{})
	t0 := time.Unix(1_800_000_000, 0)

	st := m.cycle(c, t0)
	if st.Active != "gwisp001" || rec.index("ip route replace default via 10.250.0.1 dev enp6s0 metric 0") < 0 {
		t.Fatalf("start: active %q cmds %v", st.Active, rec.cmds)
	}
	if st.Gateways[0].RTTms != 3 || !st.Gateways[0].Usable {
		t.Fatalf("status: %+v", st.Gateways[0])
	}

	// ISP1 stops answering: down after 10 s, traffic moves to ISP2.
	down["enp6s0"] = true
	rec.cmds = nil
	for s := 2; s <= 12; s += 2 {
		st = m.cycle(c, t0.Add(time.Duration(s)*time.Second))
	}
	if st.Active != "gwisp002" || st.Gateways[0].Up {
		t.Fatalf("no failover: %+v", st)
	}
	for _, want := range []string{
		"conntrack -D --mark 256", "conntrack -D --mark 512", "conntrack -D --reply-dst 10.250.0.2",
		"ip route replace default via 10.251.0.1 dev enp8s0 metric 0",
		"ip route replace unreachable default table 200",
	} {
		if rec.index(want) < 0 {
			t.Fatalf("missing %q in %v", want, rec.cmds)
		}
	}
	kinds := ""
	for _, e := range st.Events {
		kinds += e.Kind + " "
	}
	if kinds != "down failover " {
		t.Fatalf("events %q", kinds)
	}

	// Routes are written only when the plan changes...
	rec.out["ip -4 -j route show default"] = `[{"gateway":"10.251.0.1","dev":"enp8s0"}]`
	rec.cmds = nil
	m.cycle(c, t0.Add(14*time.Second))
	if rec.index("ip route replace default") >= 0 {
		t.Fatalf("rewrote unchanged routes: %v", rec.cmds)
	}

	// ...or when someone else replaced the default route.
	rec.out["ip -4 -j route show default"] = `[{"gateway":"192.168.2.254","dev":"enp5s0"}]`
	rec.cmds = nil
	m.cycle(c, t0.Add(15*time.Second))
	if rec.index("ip route replace default via 10.251.0.1 dev enp8s0 metric 0") < 0 {
		t.Fatalf("default route not put back: %v", rec.cmds)
	}
	rec.out["ip -4 -j route show default"] = `[{"gateway":"10.251.0.1","dev":"enp8s0"}]`

	// A restarted daemon resumes the verdict: no flap back to ISP1.
	m2 := newGWMonitor(st)
	rec.cmds = nil
	st2 := m2.cycle(c, t0.Add(16*time.Second))
	if st2.Active != "gwisp002" || rec.index("ip route replace default via 10.250.0.1 dev enp6s0 metric 0") >= 0 {
		t.Fatalf("restart flapped: active %q cmds %v", st2.Active, rec.cmds)
	}

	// ISP1 back: returns only after the 60 s hold.
	down["enp6s0"] = false
	for s := 18; s < 78; s += 2 {
		st2 = m2.cycle(c, t0.Add(time.Duration(s)*time.Second))
		if st2.Active != "gwisp002" {
			t.Fatalf("returned early at %ds", s)
		}
	}
	st2 = m2.cycle(c, t0.Add(80*time.Second))
	if st2.Active != "gwisp001" {
		t.Fatalf("did not return: %+v", st2)
	}
}

// The only gateway stops answering its probes: it is reported down, but with
// nowhere to move traffic to, connections are left alone and new ones keep
// using the link (the probe target may be what failed, not the link).
func TestGWMonitor_OnlyGatewayDownKeepsTraffic(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	rec.out = map[string]string{"ip -4 -j addr show dev enp6s0": `[{"addr_info":[{"local":"10.250.0.2"}]}]`}
	down := map[string]bool{}
	fakePing(t, down)
	c := gwConfig()
	m := newGWMonitor(GWStateFile{})
	t0 := time.Unix(1_800_000_000, 0)
	m.cycle(c, t0)

	down["enp6s0"] = true
	rec.cmds = nil
	var st GWStateFile
	for s := 2; s <= 12; s += 2 {
		st = m.cycle(c, t0.Add(time.Duration(s)*time.Second))
	}
	if st.Gateways[0].Up || len(st.Events) != 1 || st.Events[0].Kind != "down" {
		t.Fatalf("must be reported down: %+v", st)
	}
	for _, bad := range []string{"conntrack -D", "ip route replace unreachable"} {
		if rec.index(bad) >= 0 {
			t.Fatalf("%q cuts the traffic of the only gateway: %v", bad, rec.cmds)
		}
	}
}

// Two gateways probing the same remote address: each probe leaves through
// its own gateway (mark → probe table), never through a shared host route.
func TestGWMonitor_ProbesUseTheirOwnGateway(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	got := map[string]uint32{}
	var mu sync.Mutex
	old := sdnPing
	sdnPing = func(dev, target string, mark uint32, count int) (bool, time.Duration) {
		mu.Lock()
		got[dev+">"+target] = mark
		mu.Unlock()
		return true, time.Millisecond
	}
	t.Cleanup(func() { sdnPing = old })
	c := twoGateways()
	c.Gateways[0].MonitorIP, c.Gateways[1].MonitorIP = "1.1.1.1", "1.1.1.1"
	newGWMonitor(GWStateFile{}).cycle(c, time.Now())
	if got["enp6s0>1.1.1.1"] != 0x300 || got["enp8s0>1.1.1.1"] != 0x301 {
		t.Fatalf("probe marks %v", got)
	}
	if rec.index("ip route replace 1.1.1.1/32") >= 0 {
		t.Fatalf("shared host route: %v", rec.cmds)
	}
	for _, want := range []string{"ip route replace default via 10.250.0.1 dev enp6s0 table 300", "ip route replace default via 10.251.0.1 dev enp8s0 table 301"} {
		if rec.index(want) < 0 {
			t.Fatalf("missing %q: %v", want, rec.cmds)
		}
	}
}

func TestSDNInstallUnit_GatewayMonitor(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	if err := SDNInstallUnit("/opt/zfsnas/zfsnas", "/opt/zfsnas/config"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "znas-sdn-gw.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ExecStart=/opt/zfsnas/zfsnas -config /opt/zfsnas/config -sdn-gwmon", "Restart=always",
		"After=znas-sdn.service", "ConditionPathExists=/opt/zfsnas/config/sdn/config.json"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("unit lacks %q:\n%s", want, b)
		}
	}
	if rec.index("systemctl enable znas-sdn.service znas-sdn-gw.service") < 0 || rec.index("systemctl restart znas-sdn-gw.service") < 0 {
		t.Fatalf("not enabled/started: %v", rec.cmds)
	}
	rec.cmds = nil
	if err := SDNRemoveUnit(); err != nil {
		t.Fatal(err)
	}
	if rec.index("systemctl disable --now znas-sdn-gw.service") < 0 {
		t.Fatalf("monitor left running: %v", rec.cmds)
	}
	if rec.index("rm -f "+filepath.Join(dir, "znas-sdn.service")+" "+filepath.Join(dir, "znas-sdn-gw.service")) < 0 {
		t.Fatalf("monitor unit left behind: %v", rec.cmds)
	}
}

func TestSDNApply_PPPoEFiles(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	_ = os.MkdirAll(filepath.Join(dir, "ppp", "peers"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "ppp", "chap-secrets"), []byte("\"x\" * \"y\" *\n"), 0600)
	_ = os.WriteFile(filepath.Join(dir, "ppp", "peers", "znas-wanold"), []byte("stale"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "ppp", "peers", "provider"), []byte("foreign"), 0644)
	next := labBase()
	next.Interfaces = append(next.Interfaces, sdn.Interface{ID: "wanpppoe1", Name: "Fibre", Kind: "pppoe", Parent: "enp6s0", Role: "wan",
		PPPoEUser: "u@isp", PPPoEPassword: "pw"})
	next.Normalize()
	if _, err := SDNApply(labBase(), next, sdnEnv); err != nil {
		t.Fatal(err)
	}
	peers, err := os.ReadFile(filepath.Join(dir, "ppp", "peers", "znas-wanpppoe1"))
	if err != nil || !strings.Contains(string(peers), "nic-enp6s0") {
		t.Fatalf("peers: %v %s", err, peers)
	}
	for _, f := range []string{"chap-secrets", "pap-secrets"} {
		b, _ := os.ReadFile(filepath.Join(dir, "ppp", f))
		if !strings.Contains(string(b), "\"u@isp\" * \"pw\" * # znas-sdn id=wanpppoe1") {
			t.Fatalf("%s: %s", f, b)
		}
		if fi, _ := os.Stat(filepath.Join(dir, "ppp", f)); fi.Mode().Perm() != 0600 {
			t.Fatalf("%s mode %v", f, fi.Mode().Perm())
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "ppp", "chap-secrets")); !strings.Contains(string(b), "\"x\" * \"y\" *") {
		t.Fatal("foreign secret lost")
	}
	if _, err := os.Stat(filepath.Join(dir, "ppp", "peers", "znas-wanold")); err == nil {
		t.Fatal("stale peers file kept")
	}
	if _, err := os.Stat(filepath.Join(dir, "ppp", "peers", "provider")); err != nil {
		t.Fatal("foreign peers file removed")
	}
	// Files are written before the session is brought up.
	if w, up := rec.index("write "+filepath.Join(dir, "ppp", "peers", "znas-wanpppoe1")), rec.index("ifup ppp-wanpppoe1"); w < 0 || up < 0 || w > up {
		t.Fatalf("order write=%d ifup=%d: %v", w, up, rec.cmds)
	}

	// A password change alone restarts the session.
	again := *next
	again.Interfaces = append([]sdn.Interface(nil), next.Interfaces...)
	again.Interfaces[1].PPPoEPassword = "new"
	rec.cmds = nil
	if _, err := SDNApply(next, &again, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("ifdown --force ppp-wanpppoe1") < 0 || rec.index("ifup ppp-wanpppoe1") < 0 {
		t.Fatalf("session not restarted: %v", rec.cmds)
	}
}

func pppoeConfig() *sdn.Config {
	c := labBase()
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "wanpppoe1", Name: "Fibre", Kind: "pppoe", Parent: "enp6s0", Role: "wan",
		PPPoEUser: "u@isp", PPPoEPassword: "pw"})
	c.Normalize()
	return c
}

func TestSDNBoot_WritesPPPoEFiles(t *testing.T) {
	_, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveState(sdn.State{Enabled: true})
	_ = st.SaveConfirmed(pppoeConfig())
	if err := SDNBoot(st, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ppp", "peers", "znas-wanpppoe1")); err != nil {
		t.Fatal("peers file not regenerated at boot")
	}
	if SDNSafeModeReason() != "" {
		t.Fatalf("safe mode: %s", SDNSafeModeReason())
	}
}

func TestSDNBoot_PPPoEMissingParentSafeMode(t *testing.T) {
	_, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveState(sdn.State{Enabled: true})
	c := pppoeConfig()
	c.Interfaces[1].Parent = "enp9s0"
	_ = st.SaveConfirmed(c)
	_ = SDNBoot(st, sdnEnv)
	if !strings.Contains(SDNSafeModeReason(), "enp9s0") {
		t.Fatalf("safe mode reason %q", SDNSafeModeReason())
	}
}

func TestSDNRestorePreSDN_RemovesPPPoEFiles(t *testing.T) {
	_, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	c := pppoeConfig()
	_ = st.SaveConfirmed(c)
	if _, err := SDNApply(labBase(), c, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if err := SDNRestorePreSDN(st, sdn.State{}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ppp", "peers", "znas-wanpppoe1")); err == nil {
		t.Fatal("peers file left")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "ppp", "chap-secrets")); strings.Contains(string(b), "znas-sdn") {
		t.Fatalf("secret left: %s", b)
	}
}

func TestSDNRestorePreSDN_UndoesPolicyRouting(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveConfirmed(twoGateways())
	rec.out = map[string]string{"ip -j rule show": `[{"priority":999},{"priority":1000},{"priority":2001},{"priority":3001},{"priority":32766}]`}
	if err := SDNRestorePreSDN(st, sdn.State{PreSDNDefaultRoute: "via 192.168.2.254 dev enp5s0"}, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ip rule del priority 999", "ip rule del priority 3001",
		"ip route flush table 100", "ip route flush table 201", "ip route flush table 301",
		"ip route replace default via 192.168.2.254 dev enp5s0"} {
		if rec.index(want) < 0 {
			t.Fatalf("missing %q in %v", want, rec.cmds)
		}
	}
	if rec.index("ip rule add") >= 0 {
		t.Fatalf("rules added on disable: %v", rec.cmds)
	}
}

func TestSDNDefaultRoute(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	rec.out = map[string]string{"ip -4 -j route show default": `[{"dst":"default","gateway":"192.168.2.254","dev":"enp5s0","flags":[]}]`}
	if got := SDNDefaultRoute(); got != "via 192.168.2.254 dev enp5s0" {
		t.Fatalf("got %q", got)
	}
}

func pppoeGateway(every, pings int) *sdn.Config {
	c := gwConfig()
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "ifppp001", Name: "Fibre", Kind: "pppoe", Parent: "enp8s0", PPPoEUser: "u", IPv4Mode: "pppoe", Owned: true})
	c.Gateways = []sdn.Gateway{{ID: "gwppp001", Name: "Fibre", Interface: "ifppp001", Priority: 1, Monitor: true, MonitorIP: "9.9.9.9", ProbeEvery: every, ProbePings: pings}}
	c.Normalize()
	return c
}

func fakeHangup(t *testing.T) *int {
	n := 0
	old := sdnPPPHangup
	sdnPPPHangup = func(string) error { n++; return nil }
	t.Cleanup(func() { sdnPPPHangup = old })
	return &n
}

func TestGWMonitor_PPPoEReconnect(t *testing.T) {
	sdnTestEnv(t)
	down := map[string]bool{}
	fakePing(t, down)
	hangups := fakeHangup(t)
	c := pppoeGateway(10, 3)
	dev := c.Interfaces[len(c.Interfaces)-1].Device
	m := newGWMonitor(GWStateFile{})
	t0 := time.Unix(1_800_000_000, 0)
	m.cycle(c, t0)

	// One failed test is not enough.
	down[dev] = true
	m.cycle(c, t0.Add(10*time.Second))
	if *hangups != 0 {
		t.Fatalf("hung up after one failed test")
	}
	st := m.cycle(c, t0.Add(20*time.Second))
	if *hangups != 1 || st.Events[len(st.Events)-1].Kind != "reconnect" {
		t.Fatalf("second failed test must hang up: %d %+v", *hangups, st.Events)
	}
	// Still failing: waits, then doubles.
	m.cycle(c, t0.Add(40*time.Second))
	if *hangups != 1 {
		t.Fatalf("repeated within the pause")
	}
	m.cycle(c, t0.Add(81*time.Second))
	if *hangups != 2 {
		t.Fatalf("no retry after the pause: %d", *hangups)
	}
	m.cycle(c, t0.Add(150*time.Second))
	if *hangups != 2 {
		t.Fatalf("pause did not double: %d", *hangups)
	}
}

func TestGWMonitor_NeverAnsweredDoesNotReconnect(t *testing.T) {
	sdnTestEnv(t)
	c := pppoeGateway(10, 1)
	fakePing(t, map[string]bool{c.Interfaces[len(c.Interfaces)-1].Device: true})
	hangups := fakeHangup(t)
	m := newGWMonitor(GWStateFile{})
	t0 := time.Unix(1_800_000_000, 0)
	var st GWStateFile
	for s := 0; s <= 300; s += 10 {
		st = m.cycle(c, t0.Add(time.Duration(s)*time.Second))
	}
	if *hangups != 0 || !st.Gateways[0].ReconnectHeld {
		t.Fatalf("hangups %d, status %+v", *hangups, st.Gateways[0])
	}
}

func TestGWMonitor_ProbeSchedule(t *testing.T) {
	sdnTestEnv(t)
	c := pppoeGateway(10, 4)
	calls, count := 0, 0
	old := sdnPing
	sdnPing = func(dev, target string, mark uint32, n int) (bool, time.Duration) { calls++; count = n; return true, 0 }
	t.Cleanup(func() { sdnPing = old })
	m := newGWMonitor(GWStateFile{})
	t0 := time.Unix(1_800_000_000, 0)
	for s := 0; s < 30; s++ {
		m.cycle(c, t0.Add(time.Duration(s)*time.Second))
	}
	if calls != 3 || count != 4 {
		t.Fatalf("calls %d, pings %d", calls, count)
	}
}

func TestSyncStaticRoutes(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	dir := t.TempDir()
	old := sdnSysClassNet
	sdnSysClassNet = dir
	t.Cleanup(func() { sdnSysClassNet = old })
	os.MkdirAll(filepath.Join(dir, "enp6s0"), 0755)
	os.WriteFile(filepath.Join(dir, "enp6s0", "flags"), []byte("0x1003\n"), 0644)
	c := gwConfig()
	c.Routes = []sdn.StaticRoute{
		{ID: "r1", Enabled: true, Destination: "10.20.0.5/16", Via: "10.250.0.9", Interface: "if0wan01", Metric: 5},
		{ID: "r2", Enabled: false, Destination: "10.21.0.0/16", Via: "10.250.0.9", Interface: "if0wan01"},
		{ID: "r3", Enabled: true, Destination: "10.22.0.0/16", Via: "10.250.0.9", Interface: "if0wan01"},
	}
	c.Normalize()
	rec.out = map[string]string{"ip -4 -j route show proto 76": `[{"dst":"10.22.0.0/16","gateway":"10.250.0.9","dev":"enp6s0"},{"dst":"10.99.0.0/16","gateway":"10.250.0.9","dev":"enp6s0","metric":7}]`}
	if errs := SDNSyncStaticRoutes(c); len(errs) > 0 {
		t.Fatal(errs)
	}
	if rec.index("ip route replace 10.20.0.0/16 via 10.250.0.9 dev enp6s0 proto 76 metric 5") < 0 {
		t.Fatalf("not added: %v", rec.cmds)
	}
	if rec.index("ip route del 10.99.0.0/16 proto 76 metric 7") < 0 {
		t.Fatalf("stale kept: %v", rec.cmds)
	}
	for _, x := range rec.cmds {
		if strings.Contains(x, "10.21.0.0") || strings.Contains(x, "replace 10.22.0.0") {
			t.Fatalf("unexpected %q", x)
		}
	}
}

// Back up but still in its hold time: the next retry must not hang up a link
// that answers.
func TestGWMonitor_NoReconnectWhileRecovering(t *testing.T) {
	sdnTestEnv(t)
	down := map[string]bool{}
	fakePing(t, down)
	hangups := fakeHangup(t)
	c := pppoeGateway(10, 1)
	dev := c.Interfaces[len(c.Interfaces)-1].Device
	m := newGWMonitor(GWStateFile{})
	t0 := time.Unix(1_800_000_000, 0)
	m.cycle(c, t0)
	down[dev] = true
	m.cycle(c, t0.Add(10*time.Second))
	m.cycle(c, t0.Add(20*time.Second))
	if *hangups != 1 {
		t.Fatalf("first: %d", *hangups)
	}
	down[dev] = false
	for s := 30; s <= 75; s += 5 {
		st := m.cycle(c, t0.Add(time.Duration(s)*time.Second))
		if s == 75 && st.Gateways[0].Up {
			t.Fatalf("still in the hold time")
		}
	}
	if *hangups != 1 {
		t.Fatalf("hung up a link that answers: %d", *hangups)
	}
}

// A route taken over from /etc/network/interfaces, default included: written
// under our protocol, and given back to the file when it is removed.
func TestSDNStaticRoutesTakeOverAndGiveBack(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	dir := t.TempDir()
	oldNet, oldFile, oldUp := sdnSysClassNet, sdnInterfacesFile, sdnUptime
	sdnSysClassNet, sdnInterfacesFile = dir, filepath.Join(dir, "interfaces")
	sdnUptime = func() float64 { return 9999 }
	t.Cleanup(func() { sdnSysClassNet, sdnInterfacesFile, sdnUptime = oldNet, oldFile, oldUp })
	os.MkdirAll(filepath.Join(dir, "enp6s0"), 0755)
	os.WriteFile(filepath.Join(dir, "enp6s0", "flags"), []byte("0x1003\n"), 0644)
	os.WriteFile(sdnInterfacesFile, []byte("auto enp6s0\niface enp6s0 inet static\n  address 10.250.0.2/24\n  gateway 10.250.0.1\n  post-up ip route add 10.77.0.0/24 via 10.250.0.9 || true\n"), 0644)

	fr := sdnFileRoutes()
	if len(fr) != 2 || fr[0] != (sdnFileRoute{"default", "10.250.0.1", "enp6s0", "enp6s0"}) || fr[1] != (sdnFileRoute{"10.77.0.0/24", "10.250.0.9", "enp6s0", "enp6s0"}) {
		t.Fatalf("file routes: %+v", fr)
	}
	c := gwConfig()
	c.Routes = []sdn.StaticRoute{{ID: "r1", Enabled: true, Destination: "default", Via: "10.250.0.7", Interface: "if0wan01"}}
	c.Normalize()
	if errs := SDNSyncStaticRoutes(c); len(errs) > 0 {
		t.Fatal(errs)
	}
	if rec.index("ip route replace default via 10.250.0.7 dev enp6s0 proto 76 metric 0") < 0 {
		t.Fatalf("default not written: %v", rec.cmds)
	}

	// During boot the file goes first.
	rec.cmds = nil
	sdnUptime = func() float64 { return 30 }
	SDNSyncStaticRoutes(c)
	if rec.index("ip route replace default via 10.250.0.7 dev enp6s0 proto 76 metric 0") >= 0 {
		t.Fatalf("raced ifupdown at boot: %v", rec.cmds)
	}
	sdnUptime = func() float64 { return 9999 }

	// Already there: left alone.
	rec.cmds = nil
	rec.out = map[string]string{"ip -4 -j route show proto 76": `[{"dst":"default","gateway":"10.250.0.7","dev":"enp6s0"}]`}
	SDNSyncStaticRoutes(c)
	for _, x := range rec.cmds {
		if strings.Contains(x, "replace") || strings.Contains(x, " del ") {
			t.Fatalf("unexpected %q", x)
		}
	}

	// Removed: the file's route is back at once.
	rec.cmds = nil
	c.Routes = nil
	SDNSyncStaticRoutes(c)
	del, back := rec.index("ip route del default proto 76 metric 0"), rec.index("ip route replace default via 10.250.0.1 dev enp6s0")
	if del < 0 || back < del {
		t.Fatalf("not given back: %v", rec.cmds)
	}
}
