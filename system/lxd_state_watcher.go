package system

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/audit"
)

// OnVMUnexpectedStop is an optional callback invoked when the state watcher
// observes a VM/container leaving the Running state without ZNAS itself
// having issued the stop. main.go wires this to alerts.Send(...) — keeping
// the dep indirect avoids an import cycle (internal/alerts already imports
// the system package via the interlink relay subscription).
//
// Arguments: instance name, details ("Running → Stopped" plus an OOM tag
// when applicable), and a human-readable cause string.
var OnVMUnexpectedStop func(name, details, cause string)

// recentUserStops tracks instance names that the portal itself stopped or
// restarted recently. Entries are added by MarkUserInitiatedStop and consumed
// (cleared on lookup) by the state watcher when it sees Running→Stopped, so
// a deliberate stop via the UI / edit-modal stop-apply-start flow does NOT
// fire the "VM stopped unexpectedly" alert. The TTL covers the gap between
// the `incus stop` call returning and the next watcher poll.
var (
	userStopsMu sync.Mutex
	userStops   = map[string]time.Time{}
)

const userStopTTL = 90 * time.Second

// MarkUserInitiatedStop records that ZNAS itself just asked Incus to stop or
// restart `name`. Call BEFORE issuing the `incus stop` / `incus restart`
// command. The next time the state watcher sees Running → Stopped (or
// Crashed / Aborted) for that name, the entry is consumed and the
// "unexpected stop" alert is suppressed.
func MarkUserInitiatedStop(name string) {
	if name == "" {
		return
	}
	userStopsMu.Lock()
	userStops[name] = time.Now()
	userStopsMu.Unlock()
}

// consumeUserInitiatedStop returns true and clears the entry if a stop for
// `name` was marked within userStopTTL. Used by the state watcher to decide
// whether a Running→Stopped transition was deliberate.
func consumeUserInitiatedStop(name string) bool {
	userStopsMu.Lock()
	defer userStopsMu.Unlock()
	ts, ok := userStops[name]
	if !ok {
		return false
	}
	delete(userStops, name)
	return time.Since(ts) <= userStopTTL
}

// instanceForceRunningEnabled returns true when the Incus config key
// `user.zfsnas.force_running` is set on the instance. Cheap to call from
// the state-watcher tick — uses `incus config get`, no full state query.
func instanceForceRunningEnabled(name string) bool {
	if !lxdNameRe.MatchString(name) {
		return false
	}
	out, err := exec.Command("incus", "config", "get", name, "user.zfsnas.force_running").Output()
	if err != nil {
		return false
	}
	v := strings.TrimSpace(string(out))
	return v == "true" || v == "1"
}

// Crash-loop guard for force-restart: remember the last time we
// auto-restarted each instance, and refuse to restart again within the
// cooldown window. Prevents a VM that keeps dying immediately on boot from
// triggering a restart storm (and the alert flood that comes with it).
var (
	lastForceRestartMu sync.Mutex
	lastForceRestart   = map[string]time.Time{}
)

const forceRestartCooldown = 90 * time.Second

// maybeForceRestart issues `incus start <name>` to bring the instance back
// up after an unexpected stop, subject to the crash-loop guard above.
// Runs in a goroutine so a slow start doesn't stall the state-watcher tick.
// Always emits an audit entry (success or error) so the Activity & Events
// view distinguishes a force-running auto-restart from a normal user start.
//
// state is the canonical status that triggered the restart. When it is a
// terminal-error state (Error/Crashed/Aborted) a plain `incus start` is
// rejected ("cannot be started as in Error status"), so we force-stop the
// instance and wait 5 s for Incus to settle it back to Stopped first.
func maybeForceRestart(name, cause, state string) {
	lastForceRestartMu.Lock()
	last, seen := lastForceRestart[name]
	if seen && time.Since(last) < forceRestartCooldown {
		lastForceRestartMu.Unlock()
		log.Printf("[force-running] %s: skipping restart (last attempt %.0fs ago — crash-loop guard)", name, time.Since(last).Seconds())
		return
	}
	lastForceRestart[name] = time.Now()
	lastForceRestartMu.Unlock()

	// Tiny delay lets QEMU finish exiting and Incus release the
	// instance state file before we ask it to start again.
	time.Sleep(2 * time.Second)
	// Don't let the upcoming stop/start be misread by the state watcher as a
	// user-initiated event triggering further alert noise downstream.
	MarkUserInitiatedStop(name)
	// An instance wedged in Error/Crashed/Aborted refuses `incus start`.
	// Force-stop it first so Incus moves it back to Stopped, then give it
	// 5 s to settle before we attempt the start.
	if state == "Error" || state == "Crashed" || state == "Aborted" {
		log.Printf("[force-running] %s: in %s state — force-stopping before restart", name, state)
		if sout, serr := exec.Command("incus", "stop", "--force", name).CombinedOutput(); serr != nil {
			log.Printf("[force-running] %s: force-stop failed: %v — %s", name, serr, strings.TrimSpace(string(sout)))
		}
		time.Sleep(5 * time.Second)
		MarkUserInitiatedStop(name)
	}
	out, err := exec.Command("incus", "start", name).CombinedOutput()
	if err != nil {
		log.Printf("[force-running] %s: incus start failed: %v — %s", name, err, strings.TrimSpace(string(out)))
		details := "force-running auto-restart failed: " + strings.TrimSpace(string(out))
		// A terminal-error state also schedules maybeForceRebootIfStillError,
		// which issues a hard reset 120 s later — tell the operator so the
		// failure doesn't read as a dead end.
		if state == "Error" || state == "Crashed" || state == "Aborted" {
			details += " — will force-restart the VM in 120s"
		}
		audit.Log(audit.Entry{
			User:    "system",
			Role:    "system",
			Action:  audit.ActionIncusStart,
			Target:  name,
			Result:  audit.ResultError,
			Details: details,
		})
		return
	}
	log.Printf("[force-running] %s: auto-restarted after unexpected stop (%s)", name, cause)
	audit.Log(audit.Entry{
		User:    "system",
		Role:    "system",
		Action:  audit.ActionIncusStart,
		Target:  name,
		Result:  audit.ResultOK,
		Details: "force-running auto-restart after unexpected stop (" + cause + ")",
	})
}

// maybeForceRebootIfStillError escalates from a soft `incus start` to a
// hard reset when an instance is wedged in Error / Crashed / Aborted for
// 120 s. Triggered alongside maybeForceRestart whenever a force-running
// instance enters a terminal-error state. If the soft start managed to
// recover the instance (status moved out of error within the window)
// this is a quiet no-op.
func maybeForceRebootIfStillError(name string) {
	time.Sleep(120 * time.Second)
	insts, err := ListLXDInstances()
	if err != nil {
		return
	}
	cur := ""
	for _, inst := range insts {
		if inst.Name == name {
			cur = canonicalLXDStatus(inst.Status)
			break
		}
	}
	if cur != "Error" && cur != "Crashed" && cur != "Aborted" {
		log.Printf("[force-running] %s: error cleared (now %s) — no hard reset needed", name, cur)
		return
	}
	log.Printf("[force-running] %s: still %s after 120 s — issuing hard reset", name, cur)
	MarkUserInitiatedStop(name)
	out, rerr := exec.Command("incus", "restart", "--force", name).CombinedOutput()
	if rerr != nil {
		log.Printf("[force-running] %s: hard reset failed: %v — %s", name, rerr, strings.TrimSpace(string(out)))
		audit.Log(audit.Entry{
			User:    "system",
			Role:    "system",
			Action:  audit.ActionIncusRestart,
			Target:  name,
			Result:  audit.ResultError,
			Details: "force-running hard reset failed (still " + cur + "): " + strings.TrimSpace(string(out)),
		})
		return
	}
	audit.Log(audit.Entry{
		User:    "system",
		Role:    "system",
		Action:  audit.ActionIncusRestart,
		Target:  name,
		Result:  audit.ResultOK,
		Details: "force-running hard reset after 120 s in " + cur + " state",
	})
}

// StartLXDStateWatcher starts a background goroutine that polls Incus instance
// statuses every 10 seconds and emits an audit-log entry whenever a VM or
// container changes state — including state changes that happen outside the
// portal (CLI, host reboot, autostart on boot, qemu crash, …).
//
// Behaviour:
//   - First successful poll establishes a baseline; nothing is logged.
//   - On each subsequent poll, instances that flipped state vs. the previous
//     snapshot generate one audit entry with action ActionIncusStateChange,
//     user "system", and details "<old> → <new>".
//   - Brand-new instances (e.g. just created) are added to the baseline
//     silently; the dedicated incus_create_* audit covers their birth event.
//   - Instances that disappeared from the list are dropped from the map; the
//     dedicated incus_delete audit covers that event.
//
// Hot-loops are avoided: when LXDAvailable() returns false we sleep one tick
// without listing. This lets the watcher run unconditionally — it costs
// nothing on hosts that haven't enabled the VMs & Containers feature.
func StartLXDStateWatcher() {
	go lxdStateWatcherLoop()
}

var (
	lxdStateOnce   sync.Once
	lxdStateMu     sync.Mutex
	lxdStateMap    = map[string]string{}
	lxdStatePrimed bool
)

func lxdStateWatcherLoop() {
	// Make double-start a no-op (defensive against accidental wiring).
	started := false
	lxdStateOnce.Do(func() { started = true })
	if !started {
		return
	}
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for range t.C {
		lxdStateWatcherTick()
	}
}

func lxdStateWatcherTick() {
	if !LXDAvailable() {
		return
	}
	insts, err := ListLXDInstances()
	if err != nil {
		// Transient errors (Incus restarting, race with a config edit) are
		// silent; persistent failure shows up via LXDAvailable() returning
		// false on the next probe.
		return
	}

	lxdStateMu.Lock()
	defer lxdStateMu.Unlock()

	// Build the current snapshot first so a partial list doesn't poison the
	// baseline.
	now := map[string]string{}
	for _, inst := range insts {
		now[inst.Name] = canonicalLXDStatus(inst.Status)
	}

	if !lxdStatePrimed {
		lxdStateMap = now
		lxdStatePrimed = true
		return
	}

	// Diff: emit one audit entry per instance whose state has changed.
	for name, newSt := range now {
		oldSt, known := lxdStateMap[name]
		if !known {
			// New instance — silently absorb. The create handler already
			// emitted incus_create_*.
			continue
		}
		if oldSt == newSt {
			continue
		}
		details := oldSt + " → " + newSt
		// When a VM/container left the Running state, look for a recent
		// kernel OOM event tied to this instance. If we find one, surface
		// it in the activity feed: it's a much more useful signal than a
		// bare "Running → Stopped" when the host ran out of RAM. The OOM
		// scan is best-effort — fails silently when journalctl isn't
		// reachable.
		oom := false
		leftRunning := oldSt == "Running" && (newSt == "Stopped" || newSt == "Crashed" || newSt == "Error" || newSt == "Aborted")
		if leftRunning {
			if LooksLikeOOMKilled(name, 90*time.Second) {
				details += " (system out of memory)"
				oom = true
			}
		}
		audit.Log(audit.Entry{
			User:    "system",
			Role:    "system",
			Action:  audit.ActionIncusStateChange,
			Target:  name,
			Result:  audit.ResultOK,
			Details: details,
		})
		log.Printf("LXD state watcher: %s %s", name, details)

		// Fire the "VM stopped unexpectedly" alert when this transition is
		// NOT one the portal initiated. MarkUserInitiatedStop is called by
		// every ZNAS code path that issues `incus stop` / `incus restart`
		// (HandleLXDStop, HandleLXDRestart, LXDReset, and the stop-apply-
		// start cycle inside LXDSetConfig). Anything else — guest poweroff,
		// QEMU crash, OOM, external `incus stop` on the CLI — surfaces here.
		if leftRunning && !consumeUserInitiatedStop(name) {
			cause := "stopped outside the portal (guest shutdown, crash, or external CLI stop)"
			if oom {
				cause = "killed by the kernel out-of-memory handler"
			} else if newSt == "Crashed" || newSt == "Error" || newSt == "Aborted" {
				cause = fmt.Sprintf("entered %s state — likely a QEMU crash", newSt)
			}
			if OnVMUnexpectedStop != nil {
				OnVMUnexpectedStop(name, details, cause)
			}
			// Per-instance "Force running" — when set, ZNAS automatically
			// brings the VM/container back up after the unexpected stop.
			// Crash-loop guard: if we already restarted this instance within
			// the last forceRestartCooldown window, skip and just log so a
			// VM that keeps dying doesn't get a restart storm.
			if instanceForceRunningEnabled(name) {
				go maybeForceRestart(name, cause, newSt)
				// Error / Crashed / Aborted is a different failure mode than
				// a clean stop — `incus start` often doesn't fix it. Schedule
				// a 120 s re-check; if the instance is still wedged in one
				// of those terminal-error states, issue a hard reset
				// (`incus restart --force`).
				if newSt == "Error" || newSt == "Crashed" || newSt == "Aborted" {
					go maybeForceRebootIfStillError(name)
				}
			}
		}
	}
	// Drop deleted instances; the delete handler already emitted incus_delete.
	lxdStateMap = now
}

// canonicalLXDStatus normalises Incus' status strings (which can include
// trailing whitespace or odd casing on rare occasions) so the diff is stable.
// Empty input becomes "Unknown" so a transient blank doesn't churn the log.
func canonicalLXDStatus(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "Unknown"
	}
	return s
}
