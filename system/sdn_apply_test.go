package system

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zfsnas/internal/sdn"
)

// recorder replaces the real command runner: it records every command (sudo
// is the runner's business, not the caller's) and can fail chosen commands.
type recorder struct {
	cmds  []string
	stdin map[int]string
	fail  func(cmd string) error
	out   map[string]string // canned output per command line
}

func (r *recorder) Run(stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	if r.stdin == nil {
		r.stdin = map[int]string{}
	}
	r.stdin[len(r.cmds)] = string(stdin)
	r.cmds = append(r.cmds, cmd)
	if r.fail != nil {
		if err := r.fail(cmd); err != nil {
			return []byte(err.Error()), err
		}
	}
	if o, ok := r.out[cmd]; ok {
		return []byte(o), nil
	}
	return nil, nil
}

func (r *recorder) index(prefix string) int {
	for i, c := range r.cmds {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

// sdnTestEnv points every SDN path at a temp dir and installs a recorder.
func sdnTestEnv(t *testing.T) (*recorder, string) {
	t.Helper()
	dir := t.TempDir()
	rec := &recorder{}
	oldRun, oldIf, oldSysctl, oldUnit, oldRunDir, oldSys, oldWriteIf, oldWrite :=
		sdnRun, hostInterfacesPath, sdnSysctlPath, sdnUnitPath, sdnRunDir, sdnSysClassNet, sdnWriteInterfaces, sdnWriteFile
	sdnRun = rec
	oldKey := sdnIncusNetKey
	sdnIncusNetKey = func(string, string) string { return "" }
	t.Cleanup(func() { sdnIncusNetKey = oldKey })
	oldWait := sdnBootWait
	sdnBootWait = 0
	t.Cleanup(func() { sdnBootWait = oldWait })
	hostInterfacesPath = filepath.Join(dir, "interfaces")
	sdnSysctlPath = filepath.Join(dir, "90-znas-sdn.conf")
	sdnUnitPath = filepath.Join(dir, "znas-sdn.service")
	sdnRunDir = filepath.Join(dir, "run")
	sdnSysClassNet = filepath.Join(dir, "sys")
	sdnWriteInterfaces = func(p string, b []byte) error {
		rec.cmds = append(rec.cmds, "write "+p)
		return os.WriteFile(p, b, 0644)
	}
	sdnWriteFile = func(p string, b []byte) error {
		rec.cmds = append(rec.cmds, "write "+p)
		return os.WriteFile(p, b, 0644)
	}
	oldSecret, oldRemove, oldPPP := sdnWriteSecret, sdnRemoveFile, sdnPPPDir
	sdnWriteSecret = func(p string, b []byte) error {
		rec.cmds = append(rec.cmds, "write "+p)
		if err := os.WriteFile(p, b, 0600); err != nil {
			return err
		}
		return os.Chmod(p, 0600)
	}
	sdnRemoveFile = func(p string) error {
		rec.cmds = append(rec.cmds, "rm "+p)
		return os.RemoveAll(p)
	}
	sdnPPPDir = filepath.Join(dir, "ppp")
	t.Cleanup(func() { sdnWriteSecret, sdnRemoveFile, sdnPPPDir = oldSecret, oldRemove, oldPPP })
	oldConf, oldWG, oldLease := sdnDnsmasqConf, sdnWGDir, sdnLegacyLeasePath
	sdnDnsmasqConf, sdnWGDir, sdnLegacyLeasePath = filepath.Join(dir, "znas-sdn", "dnsmasq.conf"), filepath.Join(dir, "wireguard"), filepath.Join(dir, "leases")
	t.Cleanup(func() { sdnDnsmasqConf, sdnWGDir, sdnLegacyLeasePath = oldConf, oldWG, oldLease })
	oldDHCPDir, oldLeaseDir, oldHosts, oldStatus, oldWaitDHCP := sdnDHCPDir, sdnLeaseDir, sdnHostsDir, sdnDHCPStatusPath, sdnDHCPWait
	oldQLog, oldBL := sdnQueryLog, sdnBlocklistFile
	sdnDHCPDir, sdnLeaseDir, sdnHostsDir, sdnDHCPStatusPath, sdnDHCPWait = filepath.Join(dir, "znas-sdn", "dhcp.d"), filepath.Join(dir, "leasedir"), filepath.Join(dir, "hosts.d"), filepath.Join(dir, "dhcp-status.json"), 0
	sdnQueryLog, sdnBlocklistFile = filepath.Join(dir, "queries.log"), filepath.Join(dir, "blocklist.hosts")
	t.Cleanup(func() {
		sdnDHCPDir, sdnLeaseDir, sdnHostsDir, sdnDHCPStatusPath, sdnDHCPWait = oldDHCPDir, oldLeaseDir, oldHosts, oldStatus, oldWaitDHCP
		sdnQueryLog, sdnBlocklistFile = oldQLog, oldBL
	})
	oldIDS, oldThr, oldSock, oldState := sdnIDSConf, sdnIDSThreshold, sdnIDSSocket, sdnIDSState
	sdnIDSConf, sdnIDSThreshold = filepath.Join(dir, "znas-sdn", "suricata.yaml"), filepath.Join(dir, "znas-sdn", "threshold.config")
	sdnIDSSocket, sdnIDSState = filepath.Join(dir, "ids.sock"), filepath.Join(dir, "ids-state.json")
	t.Cleanup(func() { sdnIDSConf, sdnIDSThreshold, sdnIDSSocket, sdnIDSState = oldIDS, oldThr, oldSock, oldState })
	oldAddrs := sdnHostAddrs
	sdnHostAddrs = func() map[string][]string { return nil }
	t.Cleanup(func() { sdnHostAddrs = oldAddrs })
	oldDD, oldDDCache := sdnDDClientConf, sdnDDClientCache
	sdnDDClientConf, sdnDDClientCache = filepath.Join(dir, "znas-sdn", "ddclient.conf"), filepath.Join(dir, "ddclient.cache")
	t.Cleanup(func() { sdnDDClientConf, sdnDDClientCache = oldDD, oldDDCache })
	t.Cleanup(func() {
		sdnRun, hostInterfacesPath, sdnSysctlPath, sdnUnitPath, sdnRunDir, sdnSysClassNet, sdnWriteInterfaces, sdnWriteFile =
			oldRun, oldIf, oldSysctl, oldUnit, oldRunDir, oldSys, oldWriteIf, oldWrite
	})
	_ = os.WriteFile(hostInterfacesPath, []byte("auto lo\niface lo inet loopback\n\nauto enp5s0\niface enp5s0 inet dhcp\n"), 0644)
	for _, d := range []string{"lo", "enp5s0", "enp6s0", "enp7s0"} {
		_ = os.MkdirAll(filepath.Join(sdnSysClassNet, d), 0755)
	}
	return rec, dir
}

var sdnEnv = sdn.Env{PortalPorts: []int{8443}, SSHPort: 22}

func labBase() *sdn.Config {
	c := &sdn.Config{Version: 1, Settings: sdn.Settings{Mode: "router", MgmtInterface: "enp5s0", AntiLockout: true},
		Interfaces: []sdn.Interface{
			{ID: "if0mgmt0", Name: "LAN", Kind: "physical", Device: "enp5s0", Role: "lan", IPv4Mode: "dhcp"},
		}}
	c.Normalize()
	return c
}

func withVLAN700(c *sdn.Config) *sdn.Config {
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "if000700", Name: "VLAN700", Kind: "vlan", Parent: "enp7s0",
		VLANTag: 700, Role: "lan", IPv4Mode: "static", IPv4: "10.128.7.1/24", Owned: true})
	c.Normalize()
	return c
}

func TestSDNApply_Order(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	if _, err := SDNApply(labBase(), withVLAN700(labBase()), sdnEnv); err != nil {
		t.Fatal(err)
	}
	w, up, tee, sysctl, nft := rec.index("write "+hostInterfacesPath), rec.index("ifup enp7s0-v700"),
		rec.index("write "+sdnSysctlPath), rec.index("sysctl -e -p"), rec.index("nft -f -")
	if w < 0 || up < 0 || tee < 0 || sysctl < 0 || nft < 0 || !(w < up && up < tee && tee < sysctl && sysctl < nft) {
		t.Fatalf("wrong order: %v", rec.cmds)
	}
	if !strings.Contains(rec.stdin[nft], "table ip znas_sdn {") {
		t.Fatal("nft did not receive the compiled script")
	}
	b, _ := os.ReadFile(sdnSysctlPath)
	for _, want := range []string{"net.ipv4.ip_forward = 1", "net.netfilter.nf_conntrack_acct = 1", "net.ipv6.conf.enp7s0-v700.disable_ipv6 = 1", "net.ipv6.conf.enp5s0.disable_ipv6 = 1"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("sysctl file missing %q:\n%s", want, b)
		}
	}
}

func TestSDNApply_NoIfupWhenUnchanged(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	prev := withVLAN700(labBase())
	_, _ = SDNApply(labBase(), prev, sdnEnv)
	rec.cmds = nil
	next := withVLAN700(labBase())
	next.Rules = []sdn.Rule{{ID: "r1", Enabled: true, Interface: "if000700", Action: "allow", Protocol: "any",
		Source: sdn.Endpoint{Type: "any"}, Destination: sdn.Endpoint{Type: "any"}}}
	if _, err := SDNApply(prev, next, sdnEnv); err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.cmds {
		if strings.HasPrefix(c, "ifup") || strings.HasPrefix(c, "ifdown") || c == "write "+hostInterfacesPath {
			t.Fatalf("rule-only change touched interfaces: %v", rec.cmds)
		}
	}
}

func TestSDNApply_MgmtNotBounced(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	next := labBase()
	next.Interfaces[0].Name = "Management LAN"
	if _, err := SDNApply(labBase(), next, sdnEnv); err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.cmds {
		if strings.Contains(c, "enp5s0") && (strings.HasPrefix(c, "ifdown") || strings.HasPrefix(c, "ifup")) {
			t.Fatalf("mgmt bounced: %v", rec.cmds)
		}
	}
}

func TestSDNApply_RemovedVLANGoesDownFirst(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	prev := withVLAN700(labBase())
	_, _ = SDNApply(labBase(), prev, sdnEnv)
	rec.cmds = nil
	if _, err := SDNApply(prev, labBase(), sdnEnv); err != nil {
		t.Fatal(err)
	}
	down, w := rec.index("ifdown --force enp7s0-v700"), rec.index("write "+hostInterfacesPath)
	if down < 0 || w < 0 || down > w {
		t.Fatalf("removed VLAN must go down before the file loses its stanza: %v", rec.cmds)
	}
	b, _ := os.ReadFile(hostInterfacesPath)
	if strings.Contains(string(b), "v700") {
		t.Fatal("stanza not removed")
	}
}

func TestSDNApply_NftFailureReturnsError(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	rec.fail = func(cmd string) error {
		if strings.HasPrefix(cmd, "nft -f") {
			return errors.New("Error: syntax error")
		}
		return nil
	}
	if _, err := SDNApply(labBase(), labBase(), sdnEnv); err == nil || !strings.Contains(err.Error(), "syntax error") {
		t.Fatalf("err = %v", err)
	}
}

func TestSDNBoot_DisabledNoop(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveConfirmed(labBase())
	if err := SDNBoot(st, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if len(rec.cmds) != 0 {
		t.Fatalf("disabled boot ran commands: %v", rec.cmds)
	}
}

func TestSDNBoot_LoadsConfirmed(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveState(sdn.State{Enabled: true})
	_ = st.SaveConfirmed(withVLAN700(labBase()))
	if err := SDNBoot(st, sdnEnv); err != nil {
		t.Fatal(err)
	}
	i := rec.index("nft -f -")
	if i < 0 || !strings.Contains(rec.stdin[i], "jump in_if000700") {
		t.Fatalf("confirmed ruleset not loaded: %v", rec.cmds)
	}
	if SDNSafeModeReason() != "" {
		t.Fatal("unexpected safe mode")
	}
}

func TestSDNBoot_MissingDeviceSafeMode(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveState(sdn.State{Enabled: true})
	c := labBase()
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "if0wan00", Name: "WAN", Kind: "physical", Device: "enp9s0", Role: "wan", IPv4Mode: "dhcp"})
	_ = st.SaveConfirmed(c)
	if err := SDNBoot(st, sdnEnv); err != nil {
		t.Fatal(err)
	}
	i := rec.index("nft -f -")
	if i < 0 || !strings.Contains(rec.stdin[i], `comment "anti-lockout"`) || strings.Contains(rec.stdin[i], "jump fw_") {
		t.Fatalf("safe ruleset not loaded: %v", rec.stdin[i])
	}
	if !strings.Contains(SDNSafeModeReason(), "enp9s0") {
		t.Fatalf("reason = %q", SDNSafeModeReason())
	}
}

func TestSDNBoot_NftFailureSafeMode(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveState(sdn.State{Enabled: true})
	_ = st.SaveConfirmed(labBase())
	calls := 0
	rec.fail = func(cmd string) error {
		if strings.HasPrefix(cmd, "nft -f") {
			calls++
			if calls == 1 {
				return errors.New("Error: Could not process rule")
			}
		}
		return nil
	}
	_ = SDNBoot(st, sdnEnv)
	if calls != 2 || !strings.Contains(SDNSafeModeReason(), "Could not process rule") {
		t.Fatalf("calls=%d reason=%q", calls, SDNSafeModeReason())
	}
}

func TestSDNBoot_PendingIsReverted(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveState(sdn.State{Enabled: true})
	good := labBase()
	_ = st.AddSnapshot(sdn.Snapshot{ID: "good0001", Outcome: "confirmed", Config: good})
	bad := withVLAN700(labBase())
	_ = st.SaveConfirmed(bad)
	_ = st.AddSnapshot(sdn.Snapshot{ID: "bad00001", Outcome: "pending", Config: bad})
	_ = writePending(st, SDNPending{Target: "good0001", Applied: "bad00001"})
	if err := SDNBoot(st, sdnEnv); err != nil {
		t.Fatal(err)
	}
	cur, _ := st.LoadConfirmed()
	if len(cur.Interfaces) != 1 {
		t.Fatalf("boot kept the unconfirmed config: %+v", cur.Interfaces)
	}
	sn, _ := st.LoadSnapshot("bad00001")
	if sn.Outcome != "auto-reverted" {
		t.Fatalf("outcome %q", sn.Outcome)
	}
	if _, ok := SDNPendingRevert(st); ok {
		t.Fatal("pending marker left behind")
	}
	_ = rec
}

func TestSDNArmRevert_Args(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	if err := SDNArmRevert(st, "/opt/zfsnas/zfsnas", "abc", "def", 30, "zfsnas"); err != nil {
		t.Fatal(err)
	}
	// A sleeping transient service, not a timer: transient timers default to
	// AccuracySec=1min and fired up to a minute late in the lab.
	want := "systemd-run --unit znas-sdn-revert --collect --uid zfsnas /opt/zfsnas/zfsnas -config " + dir + " -sdn-revert abc -sdn-revert-delay 30"
	if rec.index(want) < 0 {
		t.Fatalf("missing %q in %v", want, rec.cmds)
	}
	for _, c := range rec.cmds {
		if strings.HasPrefix(c, "systemd-run") {
			for _, a := range strings.Fields(c) {
				if strings.Contains(a, "=") {
					t.Fatalf("arg %q contains '=' (sudo-rs rejects it)", a)
				}
			}
		}
	}
	p, ok := SDNPendingRevert(st)
	if !ok || p.Target != "abc" || p.Applied != "def" {
		t.Fatalf("pending = %+v %v", p, ok)
	}
	rec.cmds = nil
	if err := SDNCancelRevert(st); err != nil {
		t.Fatal(err)
	}
	if rec.index("systemctl stop znas-sdn-revert.service") < 0 {
		t.Fatalf("cancel did not stop the timer: %v", rec.cmds)
	}
	if _, ok := SDNPendingRevert(st); ok {
		t.Fatal("pending not cleared")
	}
}

func TestSDNUnitFile(t *testing.T) {
	u := sdnUnitText("/opt/zfsnas/zfsnas", "/opt/zfsnas/config")
	for _, want := range []string{
		"ExecStart=/opt/zfsnas/zfsnas -config /opt/zfsnas/config -sdn-boot",
		"ConditionPathExists=/opt/zfsnas/config/sdn/config.json",
		"Before=network-pre.target",
		"After=local-fs.target systemd-modules-load.service nftables.service",
		"Type=oneshot",
	} {
		if !strings.Contains(u, want) {
			t.Fatalf("unit missing %q:\n%s", want, u)
		}
	}
}

func TestSDNBoot_PendingRevertNoLinkOps(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveState(sdn.State{Enabled: true})
	_ = st.AddSnapshot(sdn.Snapshot{ID: "good0001", Outcome: "confirmed", Config: labBase()})
	bad := withVLAN700(labBase())
	_, _ = SDNApply(labBase(), bad, sdnEnv)
	_ = st.SaveConfirmed(bad)
	_ = writePending(st, SDNPending{Target: "good0001", Applied: "x"})
	rec.cmds = nil
	_ = SDNBoot(st, sdnEnv)
	for _, c := range rec.cmds {
		if strings.HasPrefix(c, "ifup") || strings.HasPrefix(c, "ifdown") {
			t.Fatalf("boot revert bounced links: %v", rec.cmds)
		}
	}
	b, _ := os.ReadFile(hostInterfacesPath)
	if strings.Contains(string(b), "v700") {
		t.Fatal("boot revert did not restore the interfaces file")
	}
}

func TestSDNRestorePreSDN_BridgeBeforeVLAN(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	c := withVLAN700(labBase())
	c.Interfaces[1].AllowVMs = true
	pre, _ := os.ReadFile(hostInterfacesPath)
	_, _ = SDNApply(labBase(), c, sdnEnv)
	_ = st.SaveConfirmed(c)
	rec.cmds = nil
	if err := SDNRestorePreSDN(st, sdn.State{Enabled: true, PreSDNInterfaces: string(pre)}, false); err != nil {
		t.Fatal(err)
	}
	br, vl := rec.index("ifdown --force br-enp7s0-v700"), rec.index("ifdown --force enp7s0-v700")
	if br < 0 || vl < 0 || br > vl {
		t.Fatalf("bridge must go down before its VLAN: %v", rec.cmds)
	}
	b, _ := os.ReadFile(hostInterfacesPath)
	if string(b) != string(pre) {
		t.Fatal("interfaces file not restored")
	}
	s, _ := st.LoadState()
	if s.Enabled {
		t.Fatal("state still enabled")
	}
}

func TestSDNRevertPendingNow_Previous(t *testing.T) {
	_, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveRevertPoint(labBase())
	_ = st.SaveConfirmed(withVLAN700(labBase()))
	_ = st.DiscardDraft() // apply leaves draft == applied config
	_ = st.AddSnapshot(sdn.Snapshot{ID: "app00001", Outcome: "pending", Config: withVLAN700(labBase())})
	_ = writePending(st, SDNPending{Target: PreviousTarget, Applied: "app00001"})
	if err := SDNRevertPendingNow(st, sdnEnv, "reverted"); err != nil {
		t.Fatal(err)
	}
	cur, _ := st.LoadConfirmed()
	sn, _ := st.LoadSnapshot("app00001")
	if len(cur.Interfaces) != 1 || sn.Outcome != "reverted" {
		t.Fatalf("cur=%d outcome=%q", len(cur.Interfaces), sn.Outcome)
	}
	// The reverted change must not linger as pending edits (the next Apply
	// would silently re-send it).
	d, _ := st.LoadDraft()
	if len(d.Config.Interfaces) != 1 {
		t.Fatalf("draft still holds the reverted change: %d interfaces", len(d.Config.Interfaces))
	}
}

func TestSDNApply_ClearsSafeMode(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	_ = os.MkdirAll(sdnRunDir, 0755)
	_ = os.WriteFile(filepath.Join(sdnRunDir, "safemode"), []byte("network port(s) not found: enp9s0\n"), 0644)
	if _, err := SDNApply(labBase(), withVLAN700(labBase()), sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("rm -f "+filepath.Join(sdnRunDir, "safemode")) < 0 {
		t.Fatalf("a successful apply must clear safe mode: %v", rec.cmds)
	}
}

// ── final-review fixes ─────────────────────────────────────────────────

func pendingSetup(t *testing.T, current, target *sdn.Config) (*recorder, sdn.Store) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveState(sdn.State{Enabled: true})
	_, _ = SDNApply(labBase(), current, sdnEnv)
	_ = st.SaveConfirmed(current)
	_ = st.SaveRevertPoint(target)
	_ = st.AddSnapshot(sdn.Snapshot{ID: "app00001", Outcome: "pending", Config: current})
	_ = writePending(st, SDNPending{Target: PreviousTarget, Applied: "app00001"})
	rec.cmds = nil
	return rec, st
}

// C1: an interface step failing during a revert must not stop the target's
// ruleset from loading.
func TestSDNRevertPendingNow_IfupFailureStillLoadsTarget(t *testing.T) {
	rec, st := pendingSetup(t, labBase(), withVLAN700(labBase()))
	rec.fail = func(c string) error {
		if strings.HasPrefix(c, "ifup") {
			return errors.New("ifup: no carrier")
		}
		return nil
	}
	if err := SDNRevertPendingNow(st, sdnEnv, "auto-reverted"); err != nil {
		t.Fatalf("revert must succeed best-effort, got %v", err)
	}
	i := rec.index("nft -f -")
	if i < 0 || !strings.Contains(rec.stdin[i], "jump in_if000700") {
		t.Fatalf("target ruleset not loaded: %v", rec.cmds)
	}
	cur, _ := st.LoadConfirmed()
	if len(cur.Interfaces) != 2 {
		t.Fatal("confirmed config not switched to the target")
	}
}

// C1: if even the target ruleset cannot load, fall back to safe mode — never
// keep the unconfirmed ruleset.
func TestSDNRevertPendingNow_NftFailureSafeMode(t *testing.T) {
	rec, st := pendingSetup(t, withVLAN700(labBase()), labBase())
	n := 0
	rec.fail = func(c string) error {
		if strings.HasPrefix(c, "nft -f") {
			n++
			if n == 1 {
				return errors.New("Error: boom")
			}
		}
		return nil
	}
	_ = SDNRevertPendingNow(st, sdnEnv, "auto-reverted")
	last := -1
	for k, c := range rec.cmds {
		if strings.HasPrefix(c, "nft -f") {
			last = k
		}
	}
	if last < 0 || !strings.Contains(rec.stdin[last], `"safe-mode"`) {
		t.Fatalf("safe mode not loaded after a failed revert: %v", rec.cmds)
	}
	if !strings.Contains(SDNSafeModeReason(), "boom") {
		t.Fatalf("reason %q", SDNSafeModeReason())
	}
	if _, ok := SDNPendingRevert(st); ok {
		t.Fatal("marker left")
	}
}

// C1: at boot, a pending revert that fails must end in safe mode, not in the
// unconfirmed config.
func TestSDNBoot_PendingRevertFailsSafeMode(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveState(sdn.State{Enabled: true})
	_ = st.SaveConfirmed(withVLAN700(labBase()))
	_ = writePending(st, SDNPending{Target: "missing0", Applied: "x"})
	_ = SDNBoot(st, sdnEnv)
	last := -1
	for k, c := range rec.cmds {
		if strings.HasPrefix(c, "nft -f") {
			last = k
		}
	}
	if last < 0 || strings.Contains(rec.stdin[last], "jump in_if000700") {
		t.Fatalf("boot loaded the unconfirmed config: %v", rec.cmds)
	}
	if SDNSafeModeReason() == "" {
		t.Fatal("no safe mode reason")
	}
}

// I4: when the portal died mid-apply, applying.json tells the revert what
// the kernel may hold (the new VLAN must go down).
func TestSDNRevert_UsesApplyingAsPrev(t *testing.T) {
	rec, st := pendingSetup(t, labBase(), labBase())
	_, _ = SDNApply(labBase(), withVLAN700(labBase()), sdnEnv) // kernel has the VLAN, config.json does not
	_ = st.SaveApplying(withVLAN700(labBase()))
	rec.cmds = nil
	if err := SDNRevertPendingNow(st, sdnEnv, "auto-reverted"); err != nil {
		t.Fatal(err)
	}
	if rec.index("ifdown --force enp7s0-v700") < 0 {
		t.Fatalf("half-applied VLAN not taken down: %v", rec.cmds)
	}
	if _, err := st.LoadApplying(); err == nil {
		t.Fatal("applying.json not cleared")
	}
}

// I2
func TestSDNStopRevertService(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	SDNStopRevertService()
	if rec.index("systemctl stop znas-sdn-revert.service") < 0 {
		t.Fatalf("%v", rec.cmds)
	}
}

// I10: disabling removes SDN's own stanzas and undoes SDN's readdressing,
// but keeps every other change made to the file since enabling.
func TestSDNRestorePreSDN_KeepsForeignStanzas(t *testing.T) {
	_, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	pre, _ := os.ReadFile(hostInterfacesPath)
	c := withVLAN700(labBase())
	_, _ = SDNApply(labBase(), c, sdnEnv)
	_ = st.SaveConfirmed(c)
	cur, _ := os.ReadFile(hostInterfacesPath)
	foreign := "\nauto vmbr9\niface vmbr9 inet manual\n    bridge_ports none\n"
	_ = os.WriteFile(hostInterfacesPath, append(cur, []byte(foreign)...), 0644)
	if err := SDNRestorePreSDN(st, sdn.State{Enabled: true, PreSDNInterfaces: string(pre)}, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(hostInterfacesPath)
	if strings.Contains(string(b), "znas-sdn") || !strings.Contains(string(b), "iface vmbr9 inet manual") {
		t.Fatalf("disable must drop SDN blocks and keep foreign stanzas:\n%s", b)
	}
	if string(b) != string(pre)+foreign {
		t.Fatalf("unexpected file:\n%q", b)
	}
}

func TestSDNRestorePreSDN_VerbatimForEnableRevert(t *testing.T) {
	_, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	pre, _ := os.ReadFile(hostInterfacesPath)
	_ = os.WriteFile(hostInterfacesPath, append(pre, []byte("\n# junk\n")...), 0644)
	_ = SDNRestorePreSDN(st, sdn.State{Enabled: true, PreSDNInterfaces: string(pre)}, true)
	b, _ := os.ReadFile(hostInterfacesPath)
	if string(b) != string(pre) {
		t.Fatal("verbatim restore expected right after enabling")
	}
}

// I11
func TestSDNRestorePreSDN_ReenablesNftablesService(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = SDNRestorePreSDN(st, sdn.State{Enabled: true, NftablesServiceEnabled: true}, false)
	if rec.index("systemctl enable nftables.service") < 0 {
		t.Fatalf("%v", rec.cmds)
	}
}

// I12
func TestSDNApply_ReaddressKeepsDNS(t *testing.T) {
	_, _ = sdnTestEnv(t)
	_ = os.WriteFile(hostInterfacesPath, []byte("auto enp5s0\niface enp5s0 inet static\n    address 192.168.2.10/24\n    gateway 192.168.2.1\n    dns-nameservers 192.168.2.33 1.1.1.1\n"), 0644)
	var got HostBridgeConfig
	old := sdnSetAddressing
	sdnSetAddressing = func(c HostBridgeConfig) error { got = c; return nil }
	t.Cleanup(func() { sdnSetAddressing = old })
	prev := labBase()
	prev.Interfaces[0].IPv4Mode, prev.Interfaces[0].IPv4, prev.Interfaces[0].Gateway = "static", "192.168.2.10/24", "192.168.2.1"
	next := labBase()
	next.Interfaces[0].IPv4Mode, next.Interfaces[0].IPv4, next.Interfaces[0].Gateway = "static", "192.168.2.11/24", "192.168.2.1"
	if _, err := SDNApply(prev, next, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.DNS, " ") != "192.168.2.33 1.1.1.1" {
		t.Fatalf("DNS lost: %+v", got)
	}
}

// I13: a NIC that shows up a little late (udev) must not trigger safe mode.
func TestSDNBoot_WaitsForLateDevice(t *testing.T) {
	_, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveState(sdn.State{Enabled: true})
	c := labBase()
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "if0wan00", Name: "WAN", Kind: "physical", Device: "enp9s0", Role: "wan", IPv4Mode: "dhcp"})
	_ = st.SaveConfirmed(c)
	old := sdnBootWait
	sdnBootWait = 3 * time.Second
	t.Cleanup(func() { sdnBootWait = old })
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = os.MkdirAll(filepath.Join(sdnSysClassNet, "enp9s0"), 0755)
	}()
	_ = SDNBoot(st, sdnEnv)
	if r := SDNSafeModeReason(); r != "" {
		t.Fatalf("safe mode for a late NIC: %s", r)
	}
}

// ── VMs & Containers compatibility ──────────────────────────────────────

func withIncusBridge(c *sdn.Config, ip string) *sdn.Config {
	mode := "static"
	if ip == "" {
		mode = "none"
	}
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "ifincus1", Name: "VMs 800", Kind: "incus", Device: "vmbr0-800", Role: "lan", IPv4Mode: mode, IPv4: ip})
	c.Normalize()
	return c
}

// An adopted Incus L2 bridge gets the gateway address through Incus, with
// Incus' own DHCP/NAT/DNS/firewall switched off (memory: an address on a
// managed bridge silently starts dnsmasq DHCP+NAT otherwise).
func TestSDNApply_IncusBridgeAddressedThroughIncus(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	if _, err := SDNApply(labBase(), withIncusBridge(labBase(), "10.97.9.1/24"), sdnEnv); err != nil {
		t.Fatal(err)
	}
	want := "incus network set vmbr0-800 ipv4.address=10.97.9.1/24 ipv4.nat=false ipv4.dhcp=false ipv4.firewall=false dns.mode=none ipv6.address=none user.znas.sdn=true"
	if rec.index(want) < 0 {
		t.Fatalf("missing %q in %v", want, rec.cmds)
	}
	rec.cmds = nil
	if _, err := SDNApply(withIncusBridge(labBase(), "10.97.9.1/24"), labBase(), sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("incus network set vmbr0-800 ipv4.address=none") < 0 || rec.index("incus network unset vmbr0-800 user.znas.sdn") < 0 {
		t.Fatalf("released bridge not reset: %v", rec.cmds)
	}
	for _, c := range rec.cmds {
		if strings.HasPrefix(c, "ifup") || strings.HasPrefix(c, "ifdown") {
			t.Fatalf("Incus bridges are not ifupdown's: %v", rec.cmds)
		}
	}
}

func TestSDNApply_IncusBridgeUnchangedNoIncusCall(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	c := withIncusBridge(labBase(), "10.97.9.1/24")
	if _, err := SDNApply(c, withIncusBridge(labBase(), "10.97.9.1/24"), sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("incus network") >= 0 {
		t.Fatalf("unchanged Incus bridge touched: %v", rec.cmds)
	}
}

// A VLAN the VMs & Containers feature (or a hand edit) already defines must
// not be created a second time by the Firewall.
func TestSDNApply_VLANNameConflict(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	b, _ := os.ReadFile(hostInterfacesPath)
	foreign := "\n# znas-managed-vlan-start name=enp7s0-v700 vid=700\nauto enp7s0-v700\niface enp7s0-v700 inet manual\n# znas-managed-vlan-end\n"
	_ = os.WriteFile(hostInterfacesPath, append(b, []byte(foreign)...), 0644)
	_, err := SDNApply(labBase(), withVLAN700(labBase()), sdnEnv)
	if err == nil || !strings.Contains(err.Error(), "enp7s0-v700") {
		t.Fatalf("conflict not reported: %v", err)
	}
	if rec.index("write "+hostInterfacesPath) >= 0 || rec.index("nft -f") >= 0 {
		t.Fatalf("conflicting apply touched the system: %v", rec.cmds)
	}
}

func TestSDNLive_IncusL2BridgeAdoptable(t *testing.T) {
	_, _ = sdnTestEnv(t)
	sys := sdnSysClassNet
	_ = os.RemoveAll(sys)
	fakeNIC(t, sys, "vmbr0-800", nil, "bridge")
	fakeNIC(t, sys, "host-nat", nil, "bridge")
	oldInc, oldAddrs, oldWin := sdnIncusManagedBridges, sdnIfaceAddrs, sdnRateWindow
	t.Cleanup(func() { sdnIncusManagedBridges, sdnIfaceAddrs, sdnRateWindow = oldInc, oldAddrs, oldWin })
	sdnIncusManagedBridges = func() map[string]string { return map[string]string{"vmbr0-800": "none", "host-nat": "10.72.36.1/24"} }
	sdnIfaceAddrs = func(string) []string { return nil }
	sdnRateWindow = 0
	list, _ := SDNLiveInterfaces("")
	got := map[string]SDNLiveIface{}
	for _, l := range list {
		got[l.Device] = l
	}
	if l := got["vmbr0-800"]; !l.Adoptable || !l.Incus {
		t.Fatalf("Incus L2 bridge must be adoptable: %+v", l)
	}
	if l := got["host-nat"]; !l.Adoptable || !l.IncusKeep || l.CfgMode != "static" || l.CfgAddress == "" {
		t.Fatalf("Incus bridge with an address is adopted keeping it: %+v", l)
	}
}

// Infrastructure side: Firewall-owned networks are marked and protected.
func TestFirewallOwnedNetworks(t *testing.T) {
	_, _ = sdnTestEnv(t)
	_, _ = SDNApply(labBase(), func() *sdn.Config { c := withVLAN700(labBase()); c.Interfaces[1].AllowVMs = true; return c }(), sdnEnv)
	nets := []LXDNetwork{{Name: "br-enp7s0-v700"}, {Name: "vmbr0-800", Config: map[string]string{"user.znas.sdn": "true"}}, {Name: "vmbr0"}}
	markFirewallOwned(nets)
	if !nets[0].FirewallOwned || !nets[1].FirewallOwned || nets[2].FirewallOwned {
		t.Fatalf("%+v", nets)
	}
	if err := FirewallOwnsNetwork("br-enp7s0-v700"); err == nil {
		t.Fatal("editing a Firewall-owned bridge from Infrastructure must be refused")
	}
	if err := FirewallOwnsNetwork("vmbr0"); err != nil {
		t.Fatal(err)
	}
	if err := sdnVLANOwnedByFirewall("enp7s0-v700"); err == nil {
		t.Fatal("Infrastructure must refuse a VLAN the Firewall owns")
	}
}

func TestSDNRestorePreSDN_ReleasesIncusBridges(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveConfirmed(withIncusBridge(labBase(), "10.97.9.1/24"))
	_ = SDNRestorePreSDN(st, sdn.State{Enabled: true}, false)
	if rec.index("incus network set vmbr0-800 ipv4.address=none") < 0 {
		t.Fatalf("adopted Incus bridge not handed back: %v", rec.cmds)
	}
}

// I7: ports the Firewall adopted (WAN, management bridge) belong to it too.
func TestFirewallOwnsAdoptedInterfaces(t *testing.T) {
	_, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveState(sdn.State{Enabled: true})
	c := labBase()
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "if0wan00", Name: "WAN", Kind: "physical", Device: "enp6s0", Role: "wan", IPv4Mode: "dhcp"})
	_ = st.SaveConfirmed(c)
	old := sdnConfigDir
	sdnConfigDir = dir
	t.Cleanup(func() { sdnConfigDir = old })
	if err := FirewallOwnsNetwork("enp6s0"); err == nil {
		t.Fatal("an adopted WAN port must be refused to Infrastructure")
	}
	if err := FirewallOwnsNetwork("enp5s0"); err == nil {
		t.Fatal("the adopted management port must be refused to Infrastructure")
	}
	if err := FirewallOwnsNetwork("enp9s0"); err != nil {
		t.Fatal(err)
	}
	_ = st.SaveState(sdn.State{Enabled: false})
	if err := FirewallOwnsNetwork("enp6s0"); err != nil {
		t.Fatal("a disabled Firewall owns nothing")
	}
}

// I8: Incus installed but not answering → a bridge with no ifupdown stanza
// may be Incus' own: never offer it for adoption.
func TestSDNLive_IncusUnknownBridgeNotAdoptable(t *testing.T) {
	_, _ = sdnTestEnv(t)
	sys := sdnSysClassNet
	_ = os.RemoveAll(sys)
	fakeNIC(t, sys, "incusbr0", nil, "bridge")
	oldInc, oldAddrs, oldWin, oldInst := sdnIncusManagedBridges, sdnIfaceAddrs, sdnRateWindow, sdnIncusInstalled
	t.Cleanup(func() {
		sdnIncusManagedBridges, sdnIfaceAddrs, sdnRateWindow, sdnIncusInstalled = oldInc, oldAddrs, oldWin, oldInst
	})
	sdnIncusManagedBridges = func() map[string]string { return map[string]string{} }
	sdnIfaceAddrs = func(string) []string { return nil }
	sdnRateWindow = 0
	sdnIncusInstalled = func() bool { return true }
	incusUsable.Store(false)
	list, _ := SDNLiveInterfaces("")
	if len(list) != 1 || list[0].Adoptable || !strings.Contains(list[0].Reason, "Incus") {
		t.Fatalf("%+v", list)
	}
}

// A new portal version may compile safer rules (e.g. the blk fix): on start
// the running ruleset is refreshed from the confirmed config — firewall only,
// never the links, and never while a change waits for confirmation.
func TestSDNRefreshRuleset(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: dir}
	_ = st.SaveState(sdn.State{Enabled: true})
	_ = st.SaveConfirmed(withVLAN700(labBase()))
	if err := SDNRefreshRuleset(st, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("nft -f -") < 0 {
		t.Fatalf("ruleset not refreshed: %v", rec.cmds)
	}
	for _, c := range rec.cmds {
		if strings.HasPrefix(c, "ifup") || strings.HasPrefix(c, "ifdown") || strings.HasPrefix(c, "write ") {
			t.Fatalf("refresh touched links/files: %v", rec.cmds)
		}
	}
	rec.cmds = nil
	_ = writePending(st, SDNPending{Target: PreviousTarget, Applied: "x"})
	_ = SDNRefreshRuleset(st, sdnEnv)
	if rec.index("nft -f -") >= 0 {
		t.Fatal("must not reload while a change waits for confirmation")
	}
	rec.cmds = nil
	_ = os.Remove(pendingPath(st))
	_ = st.SaveState(sdn.State{Enabled: false})
	_ = SDNRefreshRuleset(st, sdnEnv)
	if len(rec.cmds) != 0 {
		t.Fatal("disabled feature must not be touched")
	}
}

// A port adopted with an address it does not have yet (no stanza, or a
// different one) is configured and brought up; adopted as-is it is not.
func TestSDNApply_AdoptNewPortConfiguresIt(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	var got []HostBridgeConfig
	old := sdnSetAddressing
	sdnSetAddressing = func(c HostBridgeConfig) error { got = append(got, c); return nil }
	t.Cleanup(func() { sdnSetAddressing = old })
	next := labBase() // enp5s0 dhcp, as in the interfaces file: untouched
	next.Interfaces = append(next.Interfaces,
		sdn.Interface{ID: "ifwan0002", Name: "WAN2", Kind: "physical", Device: "enp6s0", Role: "wan", IPv4Mode: "static", IPv4: "10.251.0.2/24"},
		sdn.Interface{ID: "ifspare01", Name: "spare", Kind: "physical", Device: "enp7s0", Role: "lan", IPv4Mode: "none"})
	next.Normalize()
	if _, err := SDNApply(labBase(), next, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "enp6s0" || got[0].Mode != "static" || got[0].Address != "10.251.0.2/24" {
		t.Fatalf("addressing written: %+v", got)
	}
	if rec.index("ifup enp6s0") < 0 || rec.index("ifdown --force enp5s0") >= 0 {
		t.Fatalf("cmds %v", rec.cmds)
	}
	// It had no stanza: one is created for the addressing to go in.
	if b, _ := os.ReadFile(hostInterfacesPath); !strings.Contains(string(b), "auto enp6s0\niface enp6s0 inet manual") {
		t.Fatalf("no stanza created:\n%s", b)
	}
	// Disable: a port that had no stanza before the Firewall loses the
	// address it was given (back to manual).
	st := sdn.Store{Dir: filepath.Dir(hostInterfacesPath)}
	_ = st.SaveConfirmed(next)
	b, _ := os.ReadFile(hostInterfacesPath) // what the real setter wrote
	_ = os.WriteFile(hostInterfacesPath, []byte(strings.Replace(string(b), "iface enp6s0 inet manual", "iface enp6s0 inet static\n    address 10.251.0.2/24", 1)), 0644)
	got = nil
	pre := "auto lo\niface lo inet loopback\n\nauto enp5s0\niface enp5s0 inet dhcp\n"
	if err := SDNRestorePreSDN(st, sdn.State{PreSDNInterfaces: pre}, false); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "enp6s0" || got[0].Mode != "manual" {
		t.Fatalf("restore: %+v", got)
	}
}
