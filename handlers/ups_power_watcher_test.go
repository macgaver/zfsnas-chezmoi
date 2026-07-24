package handlers

import "testing"

// The UPS power watcher is edge-triggered and immediate (chosen behavior):
//   - first reading only establishes a baseline, it never notifies;
//   - every subsequent change of the on-battery state notifies exactly once;
//   - a "lost" event is emitted when going ON battery, "recovered" when going OFF;
//   - repeat outages are NOT deduped — each confirmed transition notifies again.

func TestUPSPowerStateBaselineIsSilent(t *testing.T) {
	// Booting already on battery must not fire a spurious "power lost".
	var s upsPowerState
	if send, _ := s.observe(true); send {
		t.Fatalf("first reading (on battery) should be a silent baseline, got send=true")
	}
	// Booting on AC must also be silent.
	var s2 upsPowerState
	if send, _ := s2.observe(false); send {
		t.Fatalf("first reading (on AC) should be a silent baseline, got send=true")
	}
}

func TestUPSPowerLostThenRecovered(t *testing.T) {
	var s upsPowerState
	s.observe(false) // baseline: on AC

	send, lost := s.observe(true) // AC lost
	if !send || !lost {
		t.Fatalf("AC lost: want send=true lost=true, got send=%v lost=%v", send, lost)
	}
	send, lost = s.observe(false) // AC restored
	if !send || lost {
		t.Fatalf("AC restored: want send=true lost=false, got send=%v lost=%v", send, lost)
	}
}

func TestUPSPowerNoEventWhenUnchanged(t *testing.T) {
	var s upsPowerState
	s.observe(false) // baseline on AC
	if send, _ := s.observe(false); send {
		t.Fatalf("still on AC should not notify")
	}
	s.observe(true) // lost (baseline->battery)
	if send, _ := s.observe(true); send {
		t.Fatalf("still on battery should not notify")
	}
}

func TestUPSPowerRepeatOutageNotDeduped(t *testing.T) {
	var s upsPowerState
	s.observe(false) // baseline on AC
	// down, up, down, up — every confirmed transition must fire.
	want := []struct {
		cur        bool
		send, lost bool
	}{
		{true, true, true},   // lost
		{false, true, false}, // recovered
		{true, true, true},   // lost again — no throttling
		{false, true, false}, // recovered again
	}
	for i, w := range want {
		send, lost := s.observe(w.cur)
		if send != w.send || lost != w.lost {
			t.Errorf("step %d (cur=%v): want send=%v lost=%v, got send=%v lost=%v",
				i, w.cur, w.send, w.lost, send, lost)
		}
	}
}
