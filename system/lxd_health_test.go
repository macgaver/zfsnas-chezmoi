package system

import "testing"

func resetIncusHealth(t *testing.T, probe func() (bool, bool)) *incusWatch {
	t.Helper()
	oldP, oldI := incusProbe, incusInstalledFn
	incusProbe, incusInstalledFn = probe, func() bool { return true }
	t.Cleanup(func() {
		incusProbe, incusInstalledFn = oldP, oldI
		incusHealthCurrent = IncusHealthState{}
		incusUsable.Store(false)
	})
	incusHealthCurrent = IncusHealthState{}
	return &incusWatch{}
}

// Incus installed but not usable by the portal (feature not enabled, no
// socket access): the probe fails at once. That is not a hung daemon — no
// banner, and nothing else should call incus.
func TestIncusHealth_FastFailureIsNotStuck(t *testing.T) {
	w := resetIncusHealth(t, func() (bool, bool) { return false, false })
	for i := 0; i < 5; i++ {
		w.tick(nil)
	}
	if IncusHealth().Stuck {
		t.Fatal("a fast failure raised the hung-daemon banner")
	}
	if IncusUsable() {
		t.Fatal("IncusUsable must be false when the probe fails")
	}
}

func TestIncusHealth_TimeoutsAreStuck(t *testing.T) {
	w := resetIncusHealth(t, func() (bool, bool) { return false, true })
	w.tick(nil)
	if IncusHealth().Stuck {
		t.Fatal("one timeout must not flip to stuck")
	}
	w.tick(nil)
	if !IncusHealth().Stuck {
		t.Fatal("two timeouts must flip to stuck")
	}
}

func TestIncusHealth_SuccessMakesUsable(t *testing.T) {
	w := resetIncusHealth(t, func() (bool, bool) { return true, false })
	w.tick(nil)
	if !IncusUsable() || IncusHealth().Stuck {
		t.Fatal("a working daemon must be usable and not stuck")
	}
}
