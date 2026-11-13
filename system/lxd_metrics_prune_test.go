package system

import (
	"path/filepath"
	"testing"
	"time"

	"zfsnas/internal/capacityrrd"
)

func TestPruneLXDMetricSeries(t *testing.T) {
	db, err := capacityrrd.Open(filepath.Join(t.TempDir(), "nc.rrd.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	old := now.Add(-40 * 24 * time.Hour)
	db.Record("net_rx:vethab12cd", 1, now)  // transient: goes
	db.Record("disk_r:loop3", 1, now)       // transient: goes
	db.Record("net_rx:tap5b45637b", 1, now) // transient: goes
	db.Record("net_rx:eth1", 1, old)        // removed NIC, silent 40 days: goes
	db.Record("net_rx:eth0", 1, now)        // stays
	db.Record("fs_used:/", 1, old)          // not a device series: stays
	db.Record("cpu", 1, now)                // the instance reports
	if n := pruneLXDMetricSeries(db, now); n != 4 {
		t.Fatalf("pruned %d, want 4: left %v", n, db.AllKeys())
	}
	left := map[string]bool{}
	for _, k := range db.AllKeys() {
		left[k] = true
	}
	if !left["net_rx:eth0"] || !left["fs_used:/"] || !left["cpu"] || len(left) != 3 {
		t.Fatalf("left %v", left)
	}

	// a stopped instance (no recent cpu) keeps its silent devices
	st, _ := capacityrrd.Open(filepath.Join(t.TempDir(), "off.rrd.json"))
	defer st.Close()
	st.Record("cpu", 1, old)
	st.Record("net_rx:eth0", 1, old)
	if n := pruneLXDMetricSeries(st, now); n != 0 {
		t.Fatalf("stopped instance lost %d series", n)
	}
	if !lxdTransientDevice("veth0") || lxdTransientDevice("eth0") || lxdTransientDevice("enp5s0") {
		t.Fatal("lxdTransientDevice")
	}
}
