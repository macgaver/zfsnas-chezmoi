package system

import (
	"path/filepath"
	"testing"
	"time"

	"zfsnas/internal/capacityrrd"
)

func TestPruneCapacitySeries(t *testing.T) {
	db, _ := capacityrrd.Open(filepath.Join(t.TempDir(), "capacity.rrd.json"))
	defer db.Close()
	now := time.Now()
	old := now.Add(-40 * 24 * time.Hour)
	db.Record("ds:tank/gone:used", 1, old)        // gone and silent: drops
	db.Record("ds:tank/gone:avail", 1, old)       // idem
	db.Record("ds:tank/recent-gone:used", 1, now) // gone, but sampled lately: stays for now
	db.Record("ds:tank/live:used", 1, old)        // exists (listing just failed for it before): stays
	db.Record("zv:tank/vm-disk:used", 1, old)     // gone zvol: drops
	db.Record("pool:tank:used", 1, old)           // pools: never pruned here
	live := map[string]bool{"ds:tank/live": true}
	if n := pruneCapacitySeries(db, live, now); n != 3 {
		t.Fatalf("pruned %d, left %v", n, db.AllKeys())
	}
	left := map[string]bool{}
	for _, k := range db.AllKeys() {
		left[k] = true
	}
	for _, k := range []string{"ds:tank/recent-gone:used", "ds:tank/live:used", "pool:tank:used"} {
		if !left[k] {
			t.Fatalf("%s pruned; left %v", k, left)
		}
	}
}
