package system

import (
	"os"
	"testing"
	"time"
)

func TestProcsIdleSkip(t *testing.T) {
	now := time.Now()
	procsViewedAt.Store(0) // nobody looked
	if procsIdleSkip(time.Time{}, now) {
		t.Fatal("the first sample must run")
	}
	if !procsIdleSkip(now.Add(-10*time.Second), now) {
		t.Fatal("idle: a sample 10 s old should be enough")
	}
	if procsIdleSkip(now.Add(-31*time.Second), now) {
		t.Fatal("idle: a sample 31 s old must be refreshed")
	}
	MarkProcsViewed()
	if procsIdleSkip(now.Add(-3*time.Second), time.Now()) {
		t.Fatal("viewed: every tick samples")
	}
}

func TestCategorizeProcCached(t *testing.T) {
	pid := os.Getpid()
	procCatCache.Lock()
	delete(procCatCache.m, pid)
	procCatCache.Unlock()
	a := categorizeProc(pid, "smbd")
	procCatCache.Lock()
	e, ok := procCatCache.m[pid]
	procCatCache.Unlock()
	if !ok || e.cat != a || a != CpuCatSMB {
		t.Fatalf("not cached: %v %v %q", ok, e, a)
	}
	// same pid, another program: categorized again
	if b := categorizeProc(pid, "qemu-system-x86_64"); b != CpuCatVM {
		t.Fatalf("reused pid kept the old category: %q", b)
	}
}
