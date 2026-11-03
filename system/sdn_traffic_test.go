package system

import (
	"os"
	"path/filepath"
	"testing"

	"zfsnas/internal/sdn"
)

func TestSDNBlockedAttribution(t *testing.T) {
	c := labBase()
	c.Rules = []sdn.Rule{
		{ID: "r1", Enabled: true, Action: "allow", Protocol: "any", Source: sdn.Endpoint{Type: "any"}, Destination: sdn.Endpoint{Type: "any"}},
		{ID: "r2", Enabled: true, Action: "block", Protocol: "any", Source: sdn.Endpoint{Type: "countries", Value: "CN"}, Destination: sdn.Endpoint{Type: "any"}, Description: "no China"},
	}
	got := sdnBlockedFromElems([]BlockedElem{{Src: "175.16.199.1", Proto: "tcp", Port: 22, Iface: "enp6s0", Rule: 1, Packets: 4},
		{Src: "216.160.83.56", Proto: "icmp", Iface: "enp6s0", Rule: 0, Packets: 2}}, c)
	if got[0].Rule != "no China" || got[1].Rule != "default deny" || got[0].Packets != 4 || got[0].Port != 22 {
		t.Fatalf("%+v", got)
	}
}

func TestSDNStatsDir(t *testing.T) {
	if d, ram := sdnStatsDir(&sdn.Config{}); !ram || d != "/dev/shm/znas-sdn-stats" {
		t.Fatalf("%s %v", d, ram)
	}
	c := &sdn.Config{Settings: sdn.Settings{StatsDir: "/tank/znas-netstats"}}
	if d, ram := sdnStatsDir(c); ram || d != "/tank/znas-netstats" {
		t.Fatalf("%s %v", d, ram)
	}
}

func TestSDNMoveStats(t *testing.T) {
	from, to := t.TempDir(), t.TempDir()
	_ = os.MkdirAll(filepath.Join(from, "traffic", "5m"), 0755)
	_ = os.WriteFile(filepath.Join(from, "traffic", "5m", "20261028.jsonl.gz"), []byte("x"), 0644)
	_ = os.MkdirAll(filepath.Join(from, "geo"), 0755)
	_ = os.WriteFile(filepath.Join(from, "geo", "dbip-city-lite.mmdb"), []byte("y"), 0644)
	if err := SDNMoveStats(from, to); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"traffic/5m/20261028.jsonl.gz", "geo/dbip-city-lite.mmdb"} {
		if _, err := os.Stat(filepath.Join(to, f)); err != nil {
			t.Fatalf("%s not moved", f)
		}
		if _, err := os.Stat(filepath.Join(from, f)); err == nil {
			t.Fatalf("%s left behind", f)
		}
	}
}

func TestSDNBlockedFromElems_NilConfig(t *testing.T) {
	got := sdnBlockedFromElems([]BlockedElem{{Src: "1.1.1.1", Rule: 3, Packets: 1}}, nil)
	if len(got) != 1 || got[0].Rule != "default deny" {
		t.Fatalf("%+v", got)
	}
}
