package system

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// The shutdown notice must never be able to delay the shutdown itself past its
// budget: the machine is on a battery that already hit the user's threshold, so
// a hung mail relay must not keep it running.
func withFastNotifyTimings(t *testing.T) {
	t.Helper()
	budget, attempt, retry, max := upsNotifyBudget, upsNotifyAttempt, upsNotifyRetryIn, upsNotifyMaxAttempts
	upsNotifyBudget = 300 * time.Millisecond
	upsNotifyAttempt = 120 * time.Millisecond
	upsNotifyRetryIn = 20 * time.Millisecond
	t.Cleanup(func() {
		upsNotifyBudget, upsNotifyAttempt, upsNotifyRetryIn, upsNotifyMaxAttempts = budget, attempt, retry, max
	})
}

func TestNotifyUPSShutdownDeliversOnFirstTry(t *testing.T) {
	withFastNotifyTimings(t)
	var calls int32
	OnUPSShutdown = func(name, summary, details string) error {
		atomic.AddInt32(&calls, 1)
		if name != "ups0" || summary == "" || details == "" {
			t.Errorf("bad args: %q %q %q", name, summary, details)
		}
		return nil
	}
	t.Cleanup(func() { OnUPSShutdown = nil })

	notifyUPSShutdown("ups0", "battery threshold reached", "charge=18%")
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("want exactly 1 send on success, got %d", got)
	}
}

func TestNotifyUPSShutdownRetriesOnceThenGivesUp(t *testing.T) {
	withFastNotifyTimings(t)
	var calls int32
	OnUPSShutdown = func(string, string, string) error {
		atomic.AddInt32(&calls, 1)
		return errors.New("smtp unreachable")
	}
	t.Cleanup(func() { OnUPSShutdown = nil })

	start := time.Now()
	notifyUPSShutdown("ups0", "threshold", "details")
	if got := atomic.LoadInt32(&calls); got != int32(upsNotifyMaxAttempts) {
		t.Errorf("want %d attempts, got %d", upsNotifyMaxAttempts, got)
	}
	if el := time.Since(start); el > upsNotifyBudget {
		t.Errorf("failing sends blocked the shutdown for %s, past the %s budget", el, upsNotifyBudget)
	}
}

// A target that never answers is the dangerous case: the send must be abandoned,
// not waited on.
func TestNotifyUPSShutdownAbandonsAHungTarget(t *testing.T) {
	withFastNotifyTimings(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	OnUPSShutdown = func(string, string, string) error {
		<-release // never returns while the test runs
		return nil
	}
	t.Cleanup(func() { OnUPSShutdown = nil })

	done := make(chan time.Duration, 1)
	go func() { s := time.Now(); notifyUPSShutdown("ups0", "t", "d"); done <- time.Since(s) }()
	select {
	case el := <-done:
		if el > upsNotifyBudget+100*time.Millisecond {
			t.Errorf("hung target held the shutdown for %s", el)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("notifyUPSShutdown never returned — a hung notifier would block the shutdown forever")
	}
}

// No hook wired (or nobody subscribed) must be an instant no-op, never a stall.
func TestNotifyUPSShutdownWithoutHookIsANoop(t *testing.T) {
	withFastNotifyTimings(t)
	OnUPSShutdown = nil
	start := time.Now()
	notifyUPSShutdown("ups0", "t", "d")
	if el := time.Since(start); el > 50*time.Millisecond {
		t.Errorf("no-op path took %s", el)
	}
}

// A panic inside the notifier must not escape into the shutdown path.
func TestNotifyUPSShutdownSurvivesAPanickingNotifier(t *testing.T) {
	withFastNotifyTimings(t)
	OnUPSShutdown = func(string, string, string) error { panic("boom") }
	t.Cleanup(func() { OnUPSShutdown = nil })
	notifyUPSShutdown("ups0", "t", "d") // must return normally
}
