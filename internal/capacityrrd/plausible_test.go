package capacityrrd

import (
	"path/filepath"
	"testing"
	"time"
)

const resetSpike = 491911589141.5

// Refused before it reaches any tier, so no 30-minute or daily maximum is
// poisoned either.
func TestRecordRefusesImpossibleValues(t *testing.T) {
	db, _ := Open(filepath.Join(t.TempDir(), "x.json"))
	t0 := time.Unix(1800000000, 0)
	db.Record("net_e_rx", 10, t0)
	db.Record("net_e_rx", resetSpike, t0.Add(5*time.Minute))
	for i := 2; i < 400; i++ { // past 30-minute and daily boundaries
		db.Record("net_e_rx", 20, t0.Add(time.Duration(i)*5*time.Minute))
	}
	for tier := 0; tier <= 2; tier++ {
		for _, s := range db.Query(tier, "net_e_rx") {
			if s.Max > 20 {
				t.Fatalf("tier %d holds %+v", tier, s)
			}
		}
	}
	if len(db.Query(1, "net_e_rx")) == 0 {
		t.Fatal("tier 1 empty: the test proves nothing")
	}
}

// Peaks stored by an earlier version leave every tier at the next load; the
// other values of the series stay, and other series are untouched.
func TestOpenScrubsStoredImpossibleValues(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.json")
	db, _ := Open(p)
	ts := int64(1800000000)
	for _, tier := range []*tierStore{&db.data.Tier0, &db.data.Tier1, &db.data.Tier2} {
		s := tier.get("net_e_rx")
		s.push(CapSample{TS: ts, Min: 1, Avg: 1, Max: 1, N: 1})
		s.push(CapSample{TS: ts + 1, Min: 2, Avg: resetSpike / 6, Max: resetSpike, N: 6}) // an aggregate holding it
		s.push(CapSample{TS: ts + 2, Min: 3, Avg: 3, Max: 3, N: 1})
		tier.get("pool:tank:used").push(CapSample{TS: ts, Min: 8e15, Avg: 8e15, Max: 8e15, N: 1})
	}
	db.dirty = true // filled directly, not through Record
	if err := db.FlushNow(); err != nil {
		t.Fatal(err)
	}
	r, _ := Open(p)
	for tier := 0; tier <= 2; tier++ {
		got := r.Query(tier, "net_e_rx")
		if len(got) != 2 || got[0].Max != 1 || got[1].Max != 3 {
			t.Fatalf("tier %d: %+v", tier, got)
		}
		if len(r.Query(tier, "pool:tank:used")) != 1 {
			t.Fatalf("tier %d: capacity lost", tier)
		}
	}
	r.Record("net_e_rx", 4, time.Unix(ts+3000, 0))
	if got := r.Query(0, "net_e_rx"); got[len(got)-1].Max != 4 {
		t.Fatalf("writes go on after the scrub: %+v", got)
	}
}
