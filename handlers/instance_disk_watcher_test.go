package handlers

import (
	"testing"

	"zfsnas/system"
)

func TestEvalInstanceDiskAlerts(t *testing.T) {
	u := func(used uint64) []system.InstanceDiskUsage {
		return []system.InstanceDiskUsage{{Instance: "c1", Disk: "root", Used: used, Size: 100, Threshold: 90}}
	}
	st := map[string]bool{}
	steps := []struct {
		used  uint64
		sends int
	}{
		{50, 0}, {91, 1}, {99, 0}, // crosses once, no repeat
		{87, 0}, {92, 0}, // 87 is within 5 points: not re-armed
		{80, 0}, {95, 1}, // re-armed below 85, alerts again
	}
	for i, s := range steps {
		var sends []system.InstanceDiskUsage
		st, sends = evalInstanceDiskAlerts(u(s.used), st)
		if len(sends) != s.sends {
			t.Fatalf("step %d (used %d): %d sends, want %d", i, s.used, len(sends), s.sends)
		}
	}
	if st, _ = evalInstanceDiskAlerts(nil, st); len(st) != 0 {
		t.Fatalf("gone disk not forgotten: %v", st)
	}
}
