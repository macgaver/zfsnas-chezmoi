package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zfsnas/internal/sdn"
)

func autoGroupFixture(t *testing.T) (*recorder, string, string) {
	rec, dir := sdnTestEnv(t)
	stats := filepath.Join(dir, "stats")
	st := sdn.Store{Dir: dir}
	c := &sdn.Config{Settings: sdn.Settings{StatsDir: stats, Mode: "router"}, Rules: []sdn.Rule{
		{ID: "r1", Enabled: true, Action: "block", Protocol: "any", Source: sdn.Endpoint{Type: "auto", Value: "fw-tor-exit"}, Destination: sdn.Endpoint{Type: "any"}},
		{ID: "r2", Enabled: true, Action: "block", Protocol: "any", Source: sdn.Endpoint{Type: "auto", Value: "ids-et-cins"}, Destination: sdn.Endpoint{Type: "any"}},
	}}
	if err := st.SaveConfirmed(c); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveState(sdn.State{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rep := SDNRepDir(SDNGeoDir(stats))
	os.MkdirAll(rep, 0755)
	os.WriteFile(filepath.Join(rep, "tor-exit.txt"), []byte("1.2.3.4\n5.6.7.8\n10.1.1.1\n"), 0644)
	rules := filepath.Join(sdnIDSPaths(c).RulesDir, "suricata.rules")
	os.MkdirAll(filepath.Dir(rules), 0755)
	os.WriteFile(rules, []byte(`alert ip [45.1.1.1,45.1.1.2] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 1"; sid:1;)`+"\n"), 0644)
	return rec, dir, rules
}

func nftScripts(rec *recorder) []string {
	var out []string
	for i, c := range rec.cmds {
		if c == "nft -f -" {
			out = append(out, rec.stdin[i])
		}
	}
	return out
}

func TestSDNRefreshAutoSets(t *testing.T) {
	sdnAutoSetMu.Lock()
	sdnAutoSetHash = map[string]string{}
	sdnAutoSetMu.Unlock()
	rec, dir, rules := autoGroupFixture(t)

	SDNRefreshAutoSets(dir)
	s := nftScripts(rec)
	if len(s) != 1 || !strings.Contains(s[0], "add element ip znas_sdn a_fw_tor_exit { 1.2.3.4, 5.6.7.8 }") ||
		!strings.Contains(s[0], "add element ip znas_sdn a_ids_et_cins { 45.1.1.1, 45.1.1.2 }") {
		t.Fatalf("first refresh: %q", s)
	}
	if strings.Contains(s[0], "10.1.1.1") {
		t.Fatal("private address reached the set")
	}

	// unchanged lists: nothing touched
	SDNRefreshAutoSets(dir)
	if n := len(nftScripts(rec)); n != 1 {
		t.Fatalf("unchanged lists reloaded (%d scripts)", n)
	}

	// one list changes: only its set is replaced
	tor := filepath.Join(SDNRepDir(SDNGeoDir(filepath.Join(dir, "stats"))), "tor-exit.txt")
	os.WriteFile(tor, []byte("1.2.3.4\n9.9.9.9\n"), 0644)
	later := time.Now().Add(time.Minute)
	os.Chtimes(tor, later, later)
	SDNRefreshAutoSets(dir)
	s = nftScripts(rec)
	if len(s) != 2 || !strings.Contains(s[1], "a_fw_tor_exit { 1.2.3.4, 9.9.9.9 }") || strings.Contains(s[1], "a_ids_et_cins") {
		t.Fatalf("changed list: %q", s)
	}

	// IDS rules gone: the boot cache keeps the list, nothing is emptied
	os.Remove(rules)
	SDNRefreshAutoSets(dir)
	if n := len(nftScripts(rec)); n != 2 {
		t.Fatal("a list that disappeared must not empty its set")
	}
	v, err := SDNAutoGroupCIDRsFunc(dir)("ids-et-cins")
	if err != nil || strings.Join(v, ",") != "45.1.1.1,45.1.1.2" {
		t.Fatalf("cache fallback: %v %v", v, err)
	}
	// and with no cache either: still nothing flushed
	os.Remove(autoGroupCachePath(dir))
	SDNRefreshAutoSets(dir)
	if n := len(nftScripts(rec)); n != 2 {
		t.Fatal("an unreadable list must leave its set alone")
	}
}

func TestSDNAutoGroupsInfo(t *testing.T) {
	_, dir, _ := autoGroupFixture(t)
	by := map[string]SDNAutoGroupInfo{}
	for _, g := range SDNAutoGroups(dir) {
		by[g.ID] = g
	}
	if g := by["fw-tor-exit"]; !g.Available || g.Entries != 2 || g.Removed != 1 {
		t.Fatalf("tor: %+v", g)
	}
	if g := by["ids-et-cins"]; !g.Available || !g.Present || g.Entries != 2 {
		t.Fatalf("cins: %+v", g)
	}
	if g := by["ids-et-dshield"]; g.Available || g.Note == "" {
		t.Fatalf("dshield should be unavailable with a note: %+v", g)
	}
	if g := by["fw-spamhaus-drop"]; g.Available || !strings.Contains(g.Note, "Not downloaded") {
		t.Fatalf("spamhaus: %+v", g)
	}
}
