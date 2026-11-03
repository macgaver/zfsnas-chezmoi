package rrd

import (
	"math"
	"path/filepath"
	"testing"
	"time"
)

// The value a counter reset produced on the lab (Mbit/s).
const resetSpike = 491911589141.5

func TestPlausible(t *testing.T) {
	cases := []struct {
		key  string
		v    float64
		want bool
	}{
		{"net_enp6s0_rx", 9400, true}, // a real 10 Gbit/s link
		{"net_ppp-a5157f4c_tx", 47.05, true},
		{"net_enp6s0_rx", resetSpike, false},
		{"net_enp6s0_tx", -1, false},
		{"net_rx:eth0", 1.2e10, true}, // VM NIC, bytes/s: ~100 Gbit/s
		{"net_tx:eth0", 1e15, false},
		{"disk_r:root", 5e9, true},
		{"disk_w:root", 1e15, false},
		{"disk_read", 6000, true},
		{"disk_write_mbps", 3e13, false},
		{"read:tank:sda", 550, true},
		{"write:tank:sda", 3e13, false},
		{"busy:tank:sda", 100, true},
		{"busy:tank:sda", 101, false},
		{"disk_busy_pct", 4e9, false},
		{"disk_busy", -3, false},
		// not rates: their magnitude is free, only non-numbers are refused
		{"pool:tank:used", 8e15, true},
		{"cpu", 240, true},
		{"cpu", math.NaN(), false},
		{"temp:tank:sda", math.Inf(1), false},
	}
	for _, c := range cases {
		if got := Plausible(c.key, c.v); got != c.want {
			t.Errorf("%s = %v: %v, want %v", c.key, c.v, got, c.want)
		}
	}
}

func TestRecordRefusesImpossibleValues(t *testing.T) {
	db, _ := Open(filepath.Join(t.TempDir(), "x.json"))
	now := time.Unix(1800000000, 0)
	db.Record("net_e_rx", 10, now)
	db.Record("net_e_rx", resetSpike, now.Add(time.Minute))
	if s := db.Query("net_e_rx"); len(s) != 1 || s[0].V != 10 {
		t.Fatalf("%+v", s)
	}
}

// What an earlier version stored leaves at the next load, the rest in order.
func TestOpenScrubsStoredImpossibleValues(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.json")
	db, _ := Open(p)
	now := time.Unix(1800000000, 0)
	for i, v := range []float64{1, resetSpike, 2, 3} {
		s := db.data.Series["net_e_rx"]
		if s == nil {
			s = &series{}
			db.data.Series["net_e_rx"] = s
		}
		s.Samples[s.Head] = Sample{TS: now.Unix() + int64(i), V: v}
		s.Head++
		s.Count++
	}
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	r, _ := Open(p)
	got := r.Query("net_e_rx")
	if len(got) != 3 || got[0].V != 1 || got[1].V != 2 || got[2].V != 3 || got[2].TS != now.Unix()+3 {
		t.Fatalf("%+v", got)
	}
	r.Record("net_e_rx", 4, now.Add(time.Hour))
	if got := r.Query("net_e_rx"); len(got) != 4 || got[3].V != 4 {
		t.Fatalf("writes go on after the scrub: %+v", got)
	}
}
