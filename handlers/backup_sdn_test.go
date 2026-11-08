package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zfsnas/internal/backup"
	"zfsnas/internal/sdn"
)

func TestZnasbakSkipsMachineLocalSDN(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"sdn/config.json", "sdn/state.json", "sdn/pending.json", "sdn/revert.json", "sdn/draft.json", "sdn-history/x.json", "shares.json"} {
		p := filepath.Join(dir, f)
		_ = os.MkdirAll(filepath.Dir(p), 0755)
		_ = os.WriteFile(p, []byte("{}"), 0600)
	}
	files, err := collectConfigFiles(dir, backup.ExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["config/sdn/config.json"]; !ok {
		t.Fatal("firewall config must travel in the backup")
	}
	for _, k := range []string{"config/sdn/state.json", "config/sdn/pending.json", "config/sdn/revert.json", "config/sdn/draft.json", "config/sdn-history/x.json"} {
		if _, ok := files[k]; ok {
			t.Fatalf("%s is machine-local and must not be exported", k)
		}
	}
	if _, ok := files["config/shares.json"]; !ok {
		t.Fatal("regular config dropped")
	}
}

func TestZnasbakImportSDNGoesToDraft(t *testing.T) {
	dir := t.TempDir()
	st := sdn.Store{Dir: dir}
	running := sdn.DefaultConfig()
	running.Settings.Mode = "router"
	_ = st.SaveConfirmed(running)
	_ = st.SaveState(sdn.State{Enabled: true})
	imported := sdn.DefaultConfig()
	imported.Groups = []sdn.Group{{ID: "g1", Name: "lan", Kind: "hosts", Members: []string{"10.0.0.0/8"}}}
	b, _ := json.Marshal(imported)
	if err := writeConfigFiles(dir, map[string][]byte{"config/sdn/config.json": b}, false); err != nil {
		t.Fatal(err)
	}
	cur, _ := st.LoadConfirmed()
	if cur.Settings.Mode != "router" || len(cur.Groups) != 0 {
		t.Fatal("a backup import must never replace the running firewall config")
	}
	d, _ := st.LoadDraft()
	if len(d.Config.Groups) != 1 || d.EditedBy != "backup import" {
		t.Fatalf("draft = %+v", d)
	}
}

func TestZnasbakImportFirewallOffKeepsConfigForEnable(t *testing.T) {
	dir := t.TempDir()
	st := sdn.Store{Dir: dir}
	imported := sdn.DefaultConfig()
	imported.Groups = []sdn.Group{{ID: "g1", Name: "lan", Kind: "hosts", Members: []string{"10.0.0.0/8"}}}
	b, _ := json.Marshal(imported)
	if err := writeConfigFiles(dir, map[string][]byte{"config/sdn/config.json": b}, false); err != nil {
		t.Fatal(err)
	}
	cur, _ := st.LoadConfirmed()
	if len(cur.Groups) != 1 {
		t.Fatal("Enable starts from the confirmed config: the restored one must be there")
	}
	if !st.Restored() {
		t.Fatal("the Enable wizard must be told the config came from a backup")
	}
	if state, _ := st.LoadState(); state.Enabled {
		t.Fatal("a restore must not switch the Firewall on")
	}
	files, _ := collectConfigFiles(dir, backup.ExportOptions{})
	if _, ok := files["config/sdn/restored.json"]; ok {
		t.Fatal("the restored marker is machine-local")
	}
}

func TestRollbackForgetsRestoredFirewallConfig(t *testing.T) {
	dir, snap := t.TempDir(), t.TempDir()
	_ = os.MkdirAll(filepath.Join(snap, "sdn"), 0750)
	imported, _ := json.Marshal(sdn.DefaultConfig())
	if err := writeConfigFiles(dir, map[string][]byte{"config/sdn/config.json": imported}, false); err != nil {
		t.Fatal(err)
	}
	if err := restoreSnapshot(dir, snap); err != nil {
		t.Fatal(err)
	}
	st := sdn.Store{Dir: dir}
	if st.Restored() {
		t.Fatal("marker survived the rollback")
	}
	if _, err := os.Stat(filepath.Join(dir, "sdn", "config.json")); !os.IsNotExist(err) {
		t.Fatal("restored firewall config survived the rollback")
	}
}

func TestRestoredEnableKeepsAddressingModeAndDDNS(t *testing.T) {
	last := sdn.DefaultConfig()
	last.Interfaces = []sdn.Interface{
		{ID: "up", Kind: "bridge", Device: "vmbr0", Role: "wan", IPv4Mode: "static", IPv4: "203.0.113.2/24"},
		{ID: "in", Kind: "incus", Device: "host-nat", Role: "lan", IPv4Mode: "static", IPv4: "10.77.0.1/24"},
	}
	body := []sdn.Interface{
		{ID: "x1", Kind: "bridge", Device: "vmbr0", IPv4Mode: "dhcp"},
		{ID: "x2", Kind: "incus", Device: "host-nat", IPv4Mode: "static", IPv4: "10.200.1.1/24", IncusKeep: true},
	}
	out := sdnReuseLastInterfaces(last, body, "vmbr0", true)
	if out[0].ID != "up" || out[0].IPv4Mode != "dhcp" {
		t.Fatalf("the management port keeps the address the admin reaches it on: %+v", out[0])
	}
	if out[1].ID != "in" || out[1].IPv4 != "10.77.0.1/24" || out[1].IncusKeep {
		t.Fatalf("a restored network keeps its address and mode: %+v", out[1])
	}
	if got := sdnReuseLastInterfaces(last, body, "vmbr0", false); got[1].IPv4 != "10.200.1.1/24" {
		t.Fatalf("re-enabling here: the wizard's addressing still wins: %+v", got[1])
	}
}

func TestCarryOverKeepsDDNSOfExistingGateways(t *testing.T) {
	last := sdn.DefaultConfig()
	last.Interfaces = []sdn.Interface{{ID: "up", Kind: "bridge", Device: "vmbr0", Role: "wan", IPv4Mode: "dhcp"}}
	last.Gateways = []sdn.Gateway{{ID: "g", Name: "gw", Interface: "up", Priority: 1}, {ID: "gone", Name: "old", Interface: "nope", Priority: 2}}
	last.DDNS = []sdn.DDNSEntry{{ID: "a", Gateway: "g"}, {ID: "b", Gateway: "gone"}}
	next := &sdn.Config{Version: 1, Settings: last.Settings, Interfaces: last.Interfaces}
	sdnCarryOver(last, next)
	if len(next.DDNS) != 1 || next.DDNS[0].ID != "a" {
		t.Fatalf("ddns = %+v", next.DDNS)
	}
	if got := sdnCarryDropped(last, next); len(got) == 0 {
		t.Fatal("a dropped gateway and dynamic DNS name must be reported")
	}
}

func TestZnasbakSDNSettingsTravel(t *testing.T) {
	src := t.TempDir()
	for f, body := range map[string]string{
		"sdn/config.json": "{}", "sdn/geo.json": `{"provider":"maxmind","account_id":"1","license_key":"k"}`,
		"sdn/events.jsonl": `{"kind":"ppp_up"}` + "\n", "sdn/country-cache.json": "{}",
		"sdn/blocklists.json": "{}", "sdn/vips-applied.json": "[]", "sdn/ids-state.json": "{}",
	} {
		p := filepath.Join(src, f)
		_ = os.MkdirAll(filepath.Dir(p), 0755)
		_ = os.WriteFile(p, []byte(body), 0600)
	}
	files, err := collectConfigFiles(src, backup.ExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"config/sdn/geo.json", "config/sdn/events.jsonl"} {
		if _, ok := files[k]; !ok {
			t.Fatalf("%s must be exported", k)
		}
	}
	// a fresh machine (Firewall off): every setting comes back
	dst := t.TempDir()
	if err := writeConfigFiles(dst, files, false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "sdn", "geo.json")); !strings.Contains(string(b), "license_key") {
		t.Fatal("MaxMind account and license key lost on import")
	}
	if fi, err := os.Stat(filepath.Join(dst, "sdn", "geo.json")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatal("geo.json holds a license key: 0600")
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "sdn", "events.jsonl")); !strings.Contains(string(b), "ppp_up") {
		t.Fatal("event history lost on import")
	}
	for _, f := range []string{"blocklists.json", "vips-applied.json"} {
		if _, err := os.Stat(filepath.Join(dst, "sdn", f)); err == nil {
			t.Fatalf("sdn/%s is the source machine's runtime state", f)
		}
	}
	// a machine with its own history keeps it
	own := t.TempDir()
	_ = os.MkdirAll(filepath.Join(own, "sdn"), 0700)
	_ = os.WriteFile(filepath.Join(own, "sdn", "events.jsonl"), []byte(`{"kind":"mine"}`+"\n"), 0644)
	if err := writeConfigFiles(own, files, false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(own, "sdn", "events.jsonl")); !strings.Contains(string(b), "mine") {
		t.Fatal("an import must not replace this machine's own event history")
	}
}
