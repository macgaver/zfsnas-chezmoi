package system

// Incus daemon health watchdog (v6.5.26 fix).
//
// Reason this exists: every ZNAS handler that shells out to `incus …`
// inherits the daemon's responsiveness. When the daemon hangs (cluster
// recovery, broken socket, leaked lock, kernel-namespace stall…), each
// hit spawns a goroutine that blocks forever and the portal looks
// frozen even though its own listener is up. Worse, before the 6.5.26
// startup-goroutine fix, the very first `incus list` at boot would
// wedge main before the HTTPS listener bound — service appeared running
// with sudo activity in the logs, but :8443 never came up.
//
// The watchdog runs in its own goroutine, calls `incus list` with a
// bounded deadline, and toggles a `stuck=true/false` state. State
// transitions broadcast to every browser session on /ws/alerts so the
// UI can surface a persistent red banner (auto-clears when the daemon
// recovers). Two consecutive failures before flipping to `stuck` keeps
// a single transient `incus list` slow tick from spamming the banner.

import (
	"context"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// IncusHealthState is what the watchdog broadcasts on state change and
// what /api/incus/health serves to brand-new browser sessions that
// reconnect after a flap.
type IncusHealthState struct {
	Stuck     bool      `json:"stuck"`
	LastError string    `json:"last_error,omitempty"`
	ChangedAt time.Time `json:"changed_at"`
}

var (
	incusHealthMu      sync.RWMutex
	incusHealthCurrent = IncusHealthState{Stuck: false, ChangedAt: time.Now()}
)

// IncusHealth returns the latest probed state. Safe to call from any
// goroutine; reads are RLock-cheap.
func IncusHealth() IncusHealthState {
	incusHealthMu.RLock()
	defer incusHealthMu.RUnlock()
	return incusHealthCurrent
}

// incusProbe runs `incus list` with a deadline and tells apart a daemon that
// answers (ok), one that hangs (hung: deadline hit) and one that fails at
// once (neither) — the latter is Incus installed but not usable by the
// portal (feature not enabled, no socket access), which is not "stuck".
var incusProbe = func() (ok, hung bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := exec.CommandContext(ctx, "incus", "list", "--format", "json").Run()
	return err == nil, ctx.Err() == context.DeadlineExceeded
}

var incusInstalledFn = IncusInstalled

// incusUsable: the last probe got an answer from the daemon. Code that only
// wants Incus when the VMs & Containers feature really works (the Firewall's
// interface list, for one) checks IncusUsable() instead of calling incus.
var incusUsable atomic.Bool

// IncusUsable reports whether the last health probe reached a working Incus.
func IncusUsable() bool { return incusUsable.Load() }

type incusWatch struct{ fails int }

func (w *incusWatch) setStuck(stuck bool, lastErr string, onChange func(IncusHealthState)) {
	incusHealthMu.Lock()
	changed := incusHealthCurrent.Stuck != stuck
	if changed {
		incusHealthCurrent = IncusHealthState{Stuck: stuck, LastError: lastErr, ChangedAt: time.Now()}
	}
	snap := incusHealthCurrent
	incusHealthMu.Unlock()
	if changed && onChange != nil {
		onChange(snap)
	}
}

// tick is one probe of the watchdog. A single timeout does NOT flip the
// state — two consecutive ones do, so a one-off slow tick doesn't paint the
// banner. Recovery is immediate. No binary, or a fast failure, is "not in
// use", never "stuck".
func (w *incusWatch) tick(onChange func(IncusHealthState)) {
	if !incusInstalledFn() {
		w.fails = 0
		incusUsable.Store(false)
		w.setStuck(false, "", onChange)
		return
	}
	ok, hung := incusProbe()
	switch {
	case ok:
		w.fails = 0
		incusUsable.Store(true)
		w.setStuck(false, "", onChange)
	case !hung:
		w.fails = 0
		incusUsable.Store(false)
		w.setStuck(false, "", onChange)
	default:
		w.fails++
		incusUsable.Store(false)
		if w.fails >= 2 {
			w.setStuck(true, "incus list timed out", onChange)
		}
	}
}

// StartIncusHealthWatcher probes Incus every 30 s (10 s deadline) and calls
// onChange only on stuck/healthy transitions.
func StartIncusHealthWatcher(onChange func(IncusHealthState)) {
	go func() {
		w := &incusWatch{}
		for {
			w.tick(onChange)
			time.Sleep(30 * time.Second)
		}
	}()
}
