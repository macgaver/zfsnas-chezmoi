package handlers

import (
	"testing"

	"zfsnas/internal/config"
)

// The "Run backup" button posts the saved schedule's own dest_kind/dest_pool.
// resolveBackupNowPolicy must inherit the saved policy's retention (and
// compression) so a manual run prunes exactly like a scheduled run — the bug
// was that an explicit dest produced a bare policy with retention_kind="", so
// a keep-2 schedule grew unbounded on every manual Run backup.
func TestResolveBackupNowPolicyInheritsRetention(t *testing.T) {
	saved := &config.LXDBackupPolicy{
		Instance:       "opnsense-home",
		DestKind:       "remote",
		DestServerID:   "srv-znas5",
		DestPool:       "BIGRAID5",
		RetentionKind:  "count",
		RetentionCount: 2,
		Compression:    "zstd-19",
	}

	// UI flow: request echoes the saved dest back.
	got := resolveBackupNowPolicy("opnsense-home", saved, "remote", "srv-znas5", "BIGRAID5")
	if got.RetentionKind != "count" || got.RetentionCount != 2 {
		t.Errorf("retention not inherited: kind=%q count=%d", got.RetentionKind, got.RetentionCount)
	}
	if got.Compression != "zstd-19" {
		t.Errorf("compression not inherited: %q", got.Compression)
	}
	if got.DestPool != "BIGRAID5" || got.DestKind != "remote" {
		t.Errorf("dest wrong: %s/%s", got.DestKind, got.DestPool)
	}

	// Explicit dest overrides only the destination, retention still inherited.
	got = resolveBackupNowPolicy("opnsense-home", saved, "local", "", "tank")
	if got.DestKind != "local" || got.DestPool != "tank" || got.DestServerID != "" {
		t.Errorf("dest override failed: %s/%s/%s", got.DestKind, got.DestPool, got.DestServerID)
	}
	if got.RetentionKind != "count" || got.RetentionCount != 2 {
		t.Errorf("retention lost on dest override: kind=%q count=%d", got.RetentionKind, got.RetentionCount)
	}

	// No saved policy + explicit dest: ad-hoc one-off, no retention (accepted).
	got = resolveBackupNowPolicy("x", nil, "local", "", "tank")
	if got.Instance != "x" || got.DestPool != "tank" {
		t.Errorf("ad-hoc policy wrong: %+v", got)
	}
	if got.RetentionKind != "" {
		t.Errorf("ad-hoc should have no retention, got %q", got.RetentionKind)
	}

	// No saved policy + no dest: empty → handler rejects.
	got = resolveBackupNowPolicy("x", nil, "", "", "")
	if got.DestKind != "" || got.DestPool != "" {
		t.Errorf("expected empty dest, got %s/%s", got.DestKind, got.DestPool)
	}
}
