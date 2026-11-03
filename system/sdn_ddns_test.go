package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zfsnas/internal/sdn"
)

func ddnsTestConfig() *sdn.Config {
	c := &sdn.Config{
		Interfaces: []sdn.Interface{{ID: "ifwan001", Name: "WAN", Kind: "physical", Device: "enp6s0", Role: "wan", IPv4Mode: "dhcp"}},
		Gateways:   []sdn.Gateway{{ID: "gw000001", Name: "ISP", Interface: "ifwan001", Priority: 1}},
		DDNS: []sdn.DDNSEntry{{ID: "dd000001", Enabled: true, Gateway: "gw000001", Provider: "duckdns",
			Hostnames: []string{"home.duckdns.org"}, Password: "tok"}},
	}
	c.Normalize()
	return c
}

// The ddclient file holds the provider tokens: written root-only, rewritten
// only when it changes, removed (and the unit stopped) when nothing is left.
func TestSDNDDNSFilesAndApply(t *testing.T) {
	rec, dir := sdnTestEnv(t)
	c := ddnsTestConfig()

	changed, err := sdnDDNSFiles(c)
	if err != nil || !changed {
		t.Fatalf("first write: changed=%v err=%v", changed, err)
	}
	b, _ := os.ReadFile(sdnDDClientConf)
	if string(b) != sdn.RenderDDClient(c) {
		t.Fatalf("file content:\n%s", b)
	}
	if st, _ := os.Stat(sdnDDClientConf); st.Mode().Perm() != 0600 {
		t.Fatalf("token file mode %v", st.Mode().Perm())
	}
	if filepath.Dir(sdnDDClientConf) != filepath.Join(dir, "znas-sdn") {
		t.Fatalf("test env not isolated: %s", sdnDDClientConf)
	}
	// a new configuration (other names, a corrected token) is sent again
	// right away: ddclient's memory of what it sent is dropped first
	_ = os.WriteFile(sdnDDClientCache, []byte("old"), 0600)
	var res SDNApplyResult
	sdnApplyDDNS(changed, &res)
	rm, restart := rec.index("rm "+sdnDDClientCache), rec.index("systemctl restart "+sdnDDNSUnitName)
	if restart < 0 || rm < 0 || rm > restart {
		t.Fatalf("cache not dropped before the restart: %v", rec.cmds)
	}

	rec.cmds = nil
	if changed, _ = sdnDDNSFiles(c); changed {
		t.Fatal("unchanged file rewritten")
	}
	rec.out = map[string]string{"systemctl is-active " + sdnDDNSUnitName: "active\n"}
	sdnApplyDDNS(changed, &res)
	if rec.index("systemctl restart") >= 0 {
		t.Fatalf("restarted for nothing: %v", rec.cmds)
	}

	rec.cmds = nil
	c.DDNS[0].Enabled = false
	if changed, _ = sdnDDNSFiles(c); !changed {
		t.Fatal("removal not reported")
	}
	if _, err := os.Stat(sdnDDClientConf); !os.IsNotExist(err) {
		t.Fatal("file kept with nothing to update")
	}
	sdnApplyDDNS(changed, &res)
	if rec.index("systemctl stop "+sdnDDNSUnitName) < 0 {
		t.Fatalf("not stopped: %v", rec.cmds)
	}
}

// ddclient's cache says, per name, the last address sent and how it went.
func TestParseDDClientCache(t *testing.T) {
	in := `## ddclient-3.11.2
## last updated at Fri Oct 30 16:51:19 2026 (1793379079)
atime=1793379079,backupmx=0,host=bad.example.net,mtime=0,status=noconnect,status-ipv4=noconnect,wtime=0 bad.example.net
atime=1793379079,host=h.example.net,ip=10.250.0.2,ipv4=10.250.0.2,mtime=1793379000,status=good,status-ipv4=good h.example.net
`
	got := parseDDClientCache(in)
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	h := got["h.example.net"]
	if h.IP != "10.250.0.2" || h.Status != "good" || !h.Updated.Equal(time.Unix(1793379000, 0)) || !h.Checked.Equal(time.Unix(1793379079, 0)) {
		t.Fatalf("good host %+v", h)
	}
	if b := got["bad.example.net"]; b.Status != "noconnect" || !b.Updated.IsZero() {
		t.Fatalf("failed host %+v", b)
	}
}

// The appliance image bakes the dynamic DNS unit: it must stay the unit the
// portal writes.
func TestSDNDDNSUnit_MatchesApplianceImage(t *testing.T) {
	b, err := os.ReadFile("../usbimage/chroot-setup.sh")
	if err != nil {
		t.Skip(err)
	}
	s := string(b)
	start, end := strings.Index(s, "<<'SDNDDNSUNIT'\n"), strings.Index(s, "\nSDNDDNSUNIT\n")
	if start < 0 || end < 0 {
		t.Fatal("znas-sdn-ddns.service not baked in usbimage/chroot-setup.sh")
	}
	baked := s[start+len("<<'SDNDDNSUNIT'\n") : end+1]
	want := strings.ReplaceAll(sdnDDNSUnitText(), sdnDDClientBinary(), "/usr/bin/ddclient")
	if baked != want {
		t.Fatalf("baked unit differs:\n--- baked ---\n%s\n--- portal ---\n%s", baked, want)
	}
	if !strings.Contains(s, "znas-sdn-ids.service znas-sdn-ddns.service") {
		t.Fatal("the appliance does not enable znas-sdn-ddns.service")
	}
}
