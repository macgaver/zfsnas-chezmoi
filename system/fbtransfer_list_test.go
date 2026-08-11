package system

import (
	"testing"
	"time"
)

// FbTransfers backs the discovery endpoint every browser polls, so a running
// transfer must sort ahead of finished ones however old it is — otherwise a
// long copy is pushed off the visible part of the activity bar by the finished
// jobs still inside the retention window.
func TestFbTransfersRunningSortFirst(t *testing.T) {
	fbTransfers.Range(func(k, _ interface{}) bool { fbTransfers.Delete(k); return true })

	now := time.Now()
	fbTransfers.Store("old-running", &FbTransferJob{
		ID: "old-running", Status: "running", StartedAt: now.Add(-time.Hour),
	})
	fbTransfers.Store("new-done", &FbTransferJob{
		ID: "new-done", Status: "done", StartedAt: now, FinishedAt: now,
	})

	got := FbTransfers()
	if len(got) != 2 {
		t.Fatalf("want 2 jobs, got %d", len(got))
	}
	if got[0].ID != "old-running" {
		t.Errorf("running job must sort first, got %q", got[0].ID)
	}
}

func TestFbTransfersNewestFirstWithinAGroup(t *testing.T) {
	fbTransfers.Range(func(k, _ interface{}) bool { fbTransfers.Delete(k); return true })

	now := time.Now()
	fbTransfers.Store("older", &FbTransferJob{
		ID: "older", Status: "running", StartedAt: now.Add(-time.Minute),
	})
	fbTransfers.Store("newer", &FbTransferJob{
		ID: "newer", Status: "running", StartedAt: now,
	})

	got := FbTransfers()
	if got[0].ID != "newer" {
		t.Errorf("newest running job must sort first, got %q", got[0].ID)
	}
}
