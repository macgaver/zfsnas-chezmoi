package handlers

import (
	"testing"
	"time"

	"zfsnas/internal/config"
)

// mergerfsSnapDue drives the coordinated-snapshot scheduler; pin its cadence.
func TestMergerfsSnapDue(t *testing.T) {
	// day at 02:00
	p := config.MergerFSSnapshotPolicy{EveryN: 1, Unit: "day", HourOfDay: 2, MinuteOfHour: 0}
	at := time.Date(2026, 7, 13, 2, 0, 0, 0, time.Local)
	if !mergerfsSnapDue(p, at) {
		t.Error("daily 02:00 should be due at 02:00")
	}
	if mergerfsSnapDue(p, at.Add(time.Hour)) {
		t.Error("daily 02:00 should NOT be due at 03:00")
	}
	// hourly at :30
	h := config.MergerFSSnapshotPolicy{EveryN: 2, Unit: "hour", MinuteOfHour: 30}
	if !mergerfsSnapDue(h, time.Date(2026, 7, 13, 4, 30, 0, 0, time.Local)) {
		t.Error("every-2h at :30 should be due at 04:30")
	}
	if mergerfsSnapDue(h, time.Date(2026, 7, 13, 5, 30, 0, 0, time.Local)) {
		t.Error("every-2h should NOT be due at odd hour 05:30")
	}
	// disabled / unset unit
	if mergerfsSnapDue(config.MergerFSSnapshotPolicy{EveryN: 0, Unit: "day"}, at) {
		t.Error("EveryN=0 must never be due")
	}
}
