package system

import (
	"math"
	"testing"
	"time"

	"zfsnas/internal/capacityrrd"
)

// A constant 8 Mbit/s since well before the month: 1 MB/s, so the month so
// far is (now − from) MB whichever tiers it is read from.
func TestRRDMbitSecondsMonth(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, loc)
	from := monthStart(now).Unix()
	var t0, t1, t2 []capacityrrd.CapSample
	for ts := now.Add(-7 * 24 * time.Hour).Unix(); ts < now.Unix(); ts += 300 {
		t0 = append(t0, capacityrrd.CapSample{TS: ts, Avg: 8, N: 1})
	}
	for ts := now.Add(-30*24*time.Hour).Unix() / 1800 * 1800; ts < now.Unix()-1800; ts += 1800 {
		t1 = append(t1, capacityrrd.CapSample{TS: ts, Avg: 8, N: 6})
	}
	for ts := now.Add(-60*24*time.Hour).Unix() / 86400 * 86400; ts < now.Unix()-86400; ts += 86400 {
		t2 = append(t2, capacityrrd.CapSample{TS: ts, Avg: 8, N: 288})
	}
	want := float64(now.Unix()-from) * 8
	got := rrdMbitSeconds(t0, t1, t2, from, now.Unix())
	if math.Abs(got-want)/want > 0.001 {
		t.Fatalf("19.5 days: got %.0f Mbit·s, want %.0f", got, want)
	}
	// the 31st: the 30-min tier no longer reaches the 1st, the daily one fills in
	now = time.Date(2026, 12, 31, 18, 0, 0, 0, loc)
	from = monthStart(now).Unix()
	t0, t1, t2 = nil, nil, nil
	for ts := now.Add(-7 * 24 * time.Hour).Unix(); ts < now.Unix(); ts += 300 {
		t0 = append(t0, capacityrrd.CapSample{TS: ts, Avg: 8, N: 1})
	}
	for ts := now.Add(-30*24*time.Hour).Unix()/1800*1800 + 1800; ts < now.Unix()-1800; ts += 1800 {
		t1 = append(t1, capacityrrd.CapSample{TS: ts, Avg: 8, N: 6})
	}
	for ts := now.Add(-60*24*time.Hour).Unix() / 86400 * 86400; ts < now.Unix()-86400; ts += 86400 {
		t2 = append(t2, capacityrrd.CapSample{TS: ts, Avg: 8, N: 288})
	}
	want = float64(now.Unix()-from) * 8
	got = rrdMbitSeconds(t0, t1, t2, from, now.Unix())
	if math.Abs(got-want)/want > 0.001 {
		t.Fatalf("30.75 days: got %.0f, want %.0f", got, want)
	}
	// a new install, 2 days of history: only what was measured
	now = time.Date(2026, 11, 20, 12, 0, 0, 0, loc)
	t0 = nil
	for ts := now.Add(-48 * time.Hour).Unix(); ts < now.Unix(); ts += 300 {
		t0 = append(t0, capacityrrd.CapSample{TS: ts, Avg: 8, N: 1})
	}
	got = rrdMbitSeconds(t0, nil, nil, monthStart(now).Unix(), now.Unix())
	if want = 48 * 3600 * 8; math.Abs(got-want)/want > 0.02 {
		t.Fatalf("2 days: got %.0f, want %.0f", got, want)
	}
	// a 15-min restart hole between two 8 Mbit/s points is filled at 8
	t0 = nil
	for ts := now.Add(-2 * time.Hour).Unix(); ts < now.Unix(); ts += 300 {
		if ts > now.Add(-time.Hour).Unix() && ts <= now.Add(-45*time.Minute).Unix() {
			continue
		}
		t0 = append(t0, capacityrrd.CapSample{TS: ts, Avg: 8, N: 1})
	}
	got = rrdMbitSeconds(t0, nil, nil, monthStart(now).Unix(), now.Unix())
	if want = 2 * 3600 * 8; math.Abs(got-want)/want > 0.01 {
		t.Fatalf("hole: got %.0f, want %.0f", got, want)
	}
}
