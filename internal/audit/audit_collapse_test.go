package audit

import (
	"testing"
	"time"
)

func TestCollapseLoginBursts(t *testing.T) {
	t0 := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	e := func(sec int, action, result, user, details string) Entry {
		return Entry{Timestamp: t0.Add(time.Duration(sec) * time.Second),
			Action: action, Result: result, User: user, Details: details}
	}
	in := []Entry{
		e(0, ActionLogin, ResultOK, "demo", "from 192.168.2.209"),    // kept — first
		e(10, ActionLogin, ResultOK, "demo", "from 192.168.2.209"),   // dropped — same key <60s
		e(20, ActionCreateShare, ResultOK, "demo", "x"),              // kept — not a login
		e(30, ActionLogin, ResultOK, "demo", "from 192.168.2.50"),    // kept — different IP
		e(40, ActionLogin, ResultOK, "alice", "from 192.168.2.209"),  // kept — different user
		e(50, ActionLoginFailed, ResultError, "demo", "from 192.168.2.209"), // kept — failures never collapse
		e(59, ActionLogin, ResultOK, "demo", "from 192.168.2.209"),   // dropped — still within 60s of t0
		e(61, ActionLogin, ResultOK, "demo", "from 192.168.2.209"),   // kept — new 60s window
		e(70, ActionLogin, ResultOK, "demo", "from 192.168.2.209"),   // dropped — within window of t61
	}
	out := collapseLoginBursts(in)
	wantTimes := []int{0, 20, 30, 40, 50, 61}
	if len(out) != len(wantTimes) {
		t.Fatalf("got %d entries, want %d: %+v", len(out), len(wantTimes), out)
	}
	for i, sec := range wantTimes {
		if !out[i].Timestamp.Equal(t0.Add(time.Duration(sec) * time.Second)) {
			t.Errorf("entry %d: got t+%v, want t+%ds", i, out[i].Timestamp.Sub(t0), sec)
		}
	}
}
