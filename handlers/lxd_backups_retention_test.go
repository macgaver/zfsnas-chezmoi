package handlers

import (
	"testing"
	"time"

	"zfsnas/internal/config"
)

// The v6.7.8 retention fix: policies must translate into a usable prune
// request (the old code filtered destination snapshots for a bare "auto-*"
// prefix that never matched, so retention silently pruned nothing).
func TestRetentionCutoff(t *testing.T) {
	cases := []struct {
		name   string
		p      config.LXDBackupPolicy
		ok     bool
		maxAge time.Duration // expected distance of cutoff from now (approx)
	}{
		{"hours", config.LXDBackupPolicy{RetentionKind: "age", RetentionAgeN: 6, RetentionAgeU: "hours"}, true, 6 * time.Hour},
		{"days", config.LXDBackupPolicy{RetentionKind: "age", RetentionAgeN: 2, RetentionAgeU: "days"}, true, 48 * time.Hour},
		{"weeks", config.LXDBackupPolicy{RetentionKind: "age", RetentionAgeN: 1, RetentionAgeU: "weeks"}, true, 7 * 24 * time.Hour},
		{"bad unit", config.LXDBackupPolicy{RetentionKind: "age", RetentionAgeN: 1, RetentionAgeU: "fortnights"}, false, 0},
		{"zero n", config.LXDBackupPolicy{RetentionKind: "age", RetentionAgeN: 0, RetentionAgeU: "days"}, false, 0},
		{"count kind", config.LXDBackupPolicy{RetentionKind: "count", RetentionCount: 3}, false, 0},
	}
	for _, c := range cases {
		cutoff, ok := retentionCutoff(c.p)
		if ok != c.ok {
			t.Errorf("%s: ok=%v want %v", c.name, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		got := time.Since(cutoff)
		if got < c.maxAge-time.Minute || got > c.maxAge+time.Minute {
			t.Errorf("%s: cutoff %v from now, want ~%v", c.name, got, c.maxAge)
		}
	}
}

func TestRemoteRetentionArgs(t *testing.T) {
	kind, count, cutoff, ok := remoteRetentionArgs(config.LXDBackupPolicy{RetentionKind: "count", RetentionCount: 3})
	if !ok || kind != "count" || count != 3 || cutoff != 0 {
		t.Errorf("count policy: got kind=%q count=%d cutoff=%d ok=%v", kind, count, cutoff, ok)
	}

	kind, count, cutoff, ok = remoteRetentionArgs(config.LXDBackupPolicy{RetentionKind: "age", RetentionAgeN: 1, RetentionAgeU: "days"})
	if !ok || kind != "age" || count != 0 || cutoff == 0 {
		t.Errorf("age policy: got kind=%q count=%d cutoff=%d ok=%v", kind, count, cutoff, ok)
	}
	want := time.Now().Add(-24 * time.Hour).Unix()
	if cutoff < want-60 || cutoff > want+60 {
		t.Errorf("age policy cutoff %d, want ~%d", cutoff, want)
	}

	if _, _, _, ok := remoteRetentionArgs(config.LXDBackupPolicy{RetentionKind: "count", RetentionCount: 0}); ok {
		t.Error("count=0 policy should not produce prune args")
	}
	if _, _, _, ok := remoteRetentionArgs(config.LXDBackupPolicy{}); ok {
		t.Error("empty policy should not produce prune args")
	}
}
