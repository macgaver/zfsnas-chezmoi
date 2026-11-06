package system

import "testing"

// LXDISOFetchJobGet must return a field snapshot, not a struct copy carrying
// the (held) mutex and the cancel func. Locking the snapshot must not block.
func TestLXDISOFetchJobGetSnapshot(t *testing.T) {
	called := false
	j := &LXDISOFetchJob{URL: "https://x/a.iso", Pool: "tank", Name: "a.iso",
		BytesDone: 5, TotalBytes: 10, Status: "running", StartedAt: 42,
		cancel: func() { called = true }}
	lxdISOFetchJobs.Store("snap-test", j)
	defer lxdISOFetchJobs.Delete("snap-test")

	cp := LXDISOFetchJobGet("snap-test")
	if cp == nil || cp == j {
		t.Fatalf("expected a distinct snapshot, got %p (job %p)", cp, j)
	}
	if cp.URL != j.URL || cp.Pool != j.Pool || cp.Name != j.Name || cp.BytesDone != 5 ||
		cp.TotalBytes != 10 || cp.Status != "running" || cp.StartedAt != 42 {
		t.Fatalf("snapshot fields mismatch: %+v", cp)
	}
	if cp.cancel != nil {
		t.Fatal("snapshot must not carry the cancel func")
	}
	cp.mu.Lock() // must not deadlock
	cp.mu.Unlock()
	if called {
		t.Fatal("cancel invoked unexpectedly")
	}
	if LXDISOFetchJobGet("missing") != nil {
		t.Fatal("expected nil for unknown job")
	}
}
