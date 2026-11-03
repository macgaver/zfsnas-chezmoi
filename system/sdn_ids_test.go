package system

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zfsnas/internal/sdn"
)

func withIDS(c *sdn.Config) *sdn.Config {
	c = withVLAN700(c)
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "ifwan001", Name: "WAN", Kind: "physical", Device: "enp6s0", Role: "wan", IPv4Mode: "dhcp"})
	c.IDS = sdn.IDSSettings{Enabled: true}
	c.Normalize()
	return c
}

func TestSDNApply_IDSStartsReloadsStops(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	on := withIDS(labBase())
	if _, err := SDNApply(labBase(), on, sdnEnv); err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(sdnIDSConf)
	if err != nil || !strings.Contains(string(conf), "interface: enp6s0") || !strings.Contains(string(conf), "filename: "+sdnIDSSocket) {
		t.Fatalf("suricata config: %v\n%s", err, conf)
	}
	if rec.index("systemctl restart "+sdnIDSUnitName) < rec.index("nft -f -") {
		t.Fatalf("engine must start after the ruleset: %v", rec.cmds)
	}
	// Suppressing a signature only reloads the rules.
	sup := withIDS(labBase())
	sup.IDS.Suppressed = []sdn.IDSSuppress{{SID: 2001219}}
	rec.cmds = nil
	rec.out = map[string]string{"systemctl is-active " + sdnIDSUnitName: "active\n"}
	if _, err := SDNApply(on, sup, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("systemctl reload "+sdnIDSUnitName) < 0 || rec.index("systemctl restart "+sdnIDSUnitName) >= 0 {
		t.Fatalf("expected a reload only: %v", rec.cmds)
	}
	// Off: files gone, engine stopped.
	off := withIDS(labBase())
	off.IDS.Enabled = false
	rec.cmds = nil
	if _, err := SDNApply(sup, off, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sdnIDSConf); !os.IsNotExist(err) || rec.index("systemctl stop "+sdnIDSUnitName) < 0 {
		t.Fatalf("not stopped/cleaned: %v", rec.cmds)
	}
}

func TestSDNIDSUpdate_FirstRunFiltersCategories(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	c := withIDS(labBase())
	c.Settings.StatsDir = filepath.Join(dir, "stats")
	calls := 0
	old := sdnETGroups
	sdnETGroups = func(string) []string {
		calls++
		if calls == 1 {
			return nil // nothing downloaded yet
		}
		return []string{"botcc", "emerging-games", "emerging-malware", "tor"}
	}
	defer func() { sdnETGroups = old }()
	rec.out = map[string]string{}
	if err := SDNIDSUpdate(c); err != nil {
		t.Fatal(err)
	}
	var runs []string
	for _, cmd := range rec.cmds {
		if strings.HasPrefix(cmd, "suricata-update") && strings.Contains(cmd, " -o ") {
			runs = append(runs, cmd)
		}
	}
	if len(runs) != 2 || strings.Contains(runs[0], "--offline") || !strings.Contains(runs[1], "--offline") {
		t.Fatalf("expected an online run then an offline filtered run: %v", runs)
	}
	if rec.index("suricata-update -D "+filepath.Join(c.Settings.StatsDir, "suricata", "data")+" enable-source abuse.ch/sslbl-c2") < 0 ||
		rec.index("suricata-update -D "+filepath.Join(c.Settings.StatsDir, "suricata", "data")+" enable-source et/open") < 0 {
		t.Fatalf("sources not enabled: %v", rec.cmds)
	}
	b, _ := os.ReadFile(filepath.Join(c.Settings.StatsDir, "suricata", "data", "disable.conf"))
	if !strings.Contains(string(b), "group:emerging-games\ngroup:tor\n") || strings.Contains(string(b), "group:botcc\n") {
		t.Fatalf("disable.conf:\n%s", b)
	}
	st := SDNIDSReadState()
	if st.UpdatedAt.IsZero() || len(st.Groups) != 4 || SDNIDSNeedsUpdate(c) != true {
		// rules file does not exist in the test: still "needs update"
		t.Fatalf("state %+v", st)
	}
}

func TestSDNIDSUnit_MatchesApplianceImage(t *testing.T) {
	b, err := os.ReadFile("../usbimage/chroot-setup.sh")
	if err != nil {
		t.Skip(err)
	}
	s := string(b)
	start, end := strings.Index(s, "<<'SDNIDSUNIT'\n"), strings.Index(s, "\nSDNIDSUNIT\n")
	if start < 0 || end < 0 {
		t.Fatal("znas-sdn-ids.service not baked in usbimage/chroot-setup.sh")
	}
	if baked := s[start+len("<<'SDNIDSUNIT'\n") : end+1]; baked != sdnIDSUnitText() {
		t.Fatalf("baked unit differs:\n--- baked ---\n%s\n--- portal ---\n%s", baked, sdnIDSUnitText())
	}
}

// A portal upgrade may render the service files differently: the refresh
// at portal start rewrites them and restarts only what changed.
func TestSDNRefreshRuleset_RefreshesServiceFiles(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: filepath.Join(dir, "cfg")}
	c := withServices(labBase())
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "ifwan001", Name: "WAN", Kind: "physical", Device: "enp6s0", Role: "wan", IPv4Mode: "dhcp"})
	c.IDS = sdn.IDSSettings{Enabled: true}
	c.Normalize()
	if err := st.SaveConfirmed(c); err != nil {
		t.Fatal(err)
	}
	_ = st.SaveState(sdn.State{Enabled: true})
	_ = os.MkdirAll(filepath.Dir(sdnIDSConf), 0755)
	_ = os.WriteFile(sdnIDSConf, []byte("old rendering"), 0644)
	if err := SDNRefreshRuleset(st, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(sdnIDSConf); !strings.Contains(string(b), "af-packet") {
		t.Fatal("suricata config not refreshed")
	}
	if rec.index("systemctl restart "+sdnIDSUnitName) < 0 || rec.index("systemctl restart "+sdnDNSUnitName) < 0 {
		t.Fatalf("changed services not restarted: %v", rec.cmds)
	}
	rec.cmds = nil
	rec.out = map[string]string{"systemctl is-active " + sdnIDSUnitName: "active\n", "systemctl is-active " + sdnDNSUnitName: "active\n",
		"systemctl is-active " + sdnDHCPUnitName: "active\n"}
	_ = SDNRefreshRuleset(st, sdnEnv)
	if rec.index("systemctl restart") >= 0 {
		t.Fatalf("unchanged files must not restart anything: %v", rec.cmds)
	}
}

// Group names come from a downloaded archive: only plain rule-file names
// may reach disable.conf.
func TestSDNETGroups_FiltersOddNames(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "update", "cache")
	_ = os.MkdirAll(cache, 0755)
	f, _ := os.Create(filepath.Join(cache, "x-emerging.rules.tar.gz"))
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	for _, n := range []string{"rules/emerging-malware.rules", "rules/bad\nname.rules", "rules/UPPER.rules", "rules/emerging-deleted.rules", "rules/README"} {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0644, Size: 0})
	}
	tw.Close()
	zw.Close()
	f.Close()
	if got := strings.Join(sdnETGroups(dir), ","); got != "emerging-malware" {
		t.Fatalf("groups %q", got)
	}
}
