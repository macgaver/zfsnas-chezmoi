package capacityrrd

import (
	"math"
	"path/filepath"
	"testing"
	"time"
)

func TestRecordAggRollup(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "x.json"))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1762390800, 0) // a 30-min boundary
	db.RecordAgg("gwrtt_a", 1, 2, 3, 10, base)
	db.RecordAgg("gwrtt_a", 2, 5, 9, 30, base.Add(5*time.Minute))
	db.RecordAgg("gwrtt_a", 1, 1, 1, 1, base.Add(30*time.Minute)) // rolls the bucket

	t0 := db.Query(0, "gwrtt_a")
	if len(t0) != 3 || t0[0].Min != 1 || t0[0].Avg != 2 || t0[0].Max != 3 || t0[0].N != 10 {
		t.Fatalf("tier0 must keep the slot as given: %+v", t0)
	}
	t1 := db.Query(1, "gwrtt_a")
	if len(t1) != 1 {
		t.Fatalf("tier1: %+v", t1)
	}
	if s := t1[0]; s.Min != 1 || s.Max != 9 || math.Abs(s.Avg-4.25) > 1e-9 || s.N != 40 {
		t.Fatalf("tier1 rollup = %+v, want min 1 avg 4.25 max 9 n 40", s)
	}
	db.RecordAgg("gwrtt_a", 1, 20000, 1, 5, base.Add(35*time.Minute))
	if got := db.Query(0, "gwrtt_a"); len(got) != 3 {
		t.Fatal("an impossible latency must be refused")
	}
	db.RecordAgg("gwrtt_a", 1, 1, 1, 0, base.Add(40*time.Minute))
	if got := db.Query(0, "gwrtt_a"); len(got) != 3 {
		t.Fatal("n=0 must record nothing")
	}
}
