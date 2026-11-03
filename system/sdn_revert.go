package system

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"zfsnas/internal/sdn"
)

// SDNPending describes an applied change waiting for the admin's "All good".
// It lives in the config dir (not /run) on purpose: if the box reboots inside
// the countdown, -sdn-boot finds it and restores Target instead of keeping an
// unconfirmed configuration.
type SDNPending struct {
	Target   string    `json:"target"`  // snapshot id to restore, or "pre-sdn"
	Applied  string    `json:"applied"` // snapshot id of the change being tested
	Deadline time.Time `json:"deadline"`
}

// PreSDNTarget restores the networking that existed before the feature was
// enabled (first apply after enabling has no earlier snapshot).
const PreSDNTarget = "pre-sdn"

// PreviousTarget restores the revert point saved just before the apply.
const PreviousTarget = "previous"

const sdnRevertUnit = "znas-sdn-revert"

func pendingPath(st sdn.Store) string { return filepath.Join(st.Dir, "sdn", "pending.json") }

func writePending(st sdn.Store, p SDNPending) error {
	b, _ := json.Marshal(p)
	if err := os.MkdirAll(filepath.Dir(pendingPath(st)), 0700); err != nil {
		return err
	}
	return os.WriteFile(pendingPath(st), b, 0600)
}

// SDNPendingRevert returns the change waiting for confirmation, if any.
func SDNPendingRevert(st sdn.Store) (SDNPending, bool) {
	var p SDNPending
	b, err := os.ReadFile(pendingPath(st))
	if err != nil || json.Unmarshal(b, &p) != nil {
		return p, false
	}
	return p, true
}

// SDNArmRevert writes the pending marker and starts a transient systemd
// service running `<binary> -config <dir> -sdn-revert <target>
// -sdn-revert-delay <seconds>`, which waits then reverts unless the marker
// is gone. It is owned by systemd, not by the portal: if the browser loses
// the portal or the portal dies, the revert still happens. Arguments are passed
// as separate argv items (no "=": sudo-rs rejects it in sudo arguments).
func SDNArmRevert(st sdn.Store, binary, target, applied string, seconds int, runAsUser string) error {
	if err := writePending(st, SDNPending{Target: target, Applied: applied,
		Deadline: time.Now().Add(time.Duration(seconds) * time.Second).UTC()}); err != nil {
		return err
	}
	sdnRun.Run(nil, "systemctl", "reset-failed", sdnRevertUnit+".service") //nolint:errcheck — absent unit is fine
	// A transient service that sleeps the countdown itself — not a timer:
	// transient timers default to AccuracySec=1min and fire up to a minute
	// late. --collect drops the unit when it ends, whatever its result.
	args := []string{"--unit", sdnRevertUnit, "--collect"}
	if runAsUser != "" {
		args = append(args, "--uid", runAsUser)
	}
	args = append(args, binary, "-config", st.Dir, "-sdn-revert", target, "-sdn-revert-delay", strconv.Itoa(seconds))
	if _, err := sdnRun.Run(nil, "systemd-run", args...); err != nil {
		_ = os.Remove(pendingPath(st))
		return err
	}
	return nil
}

// SDNCancelRevert disarms the timer and clears the marker (the admin
// confirmed).
func SDNCancelRevert(st sdn.Store) error {
	sdnRun.Run(nil, "systemctl", "stop", sdnRevertUnit+".service") //nolint:errcheck
	if err := os.Remove(pendingPath(st)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// SDNRevertPendingNow restores the pending change's target and records
// outcome ("auto-reverted" from the timer or at boot, "reverted" when the
// admin clicks "Revert now") on the applied snapshot.
func SDNRevertPendingNow(st sdn.Store, env sdn.Env, outcome string) error {
	p, ok := SDNPendingRevert(st)
	if !ok {
		return errors.New("nothing is waiting for confirmation")
	}
	var err error
	if p.Target == PreSDNTarget {
		var state sdn.State
		if state, err = st.LoadState(); err == nil {
			err = SDNRestorePreSDN(st, state, true)
		}
	} else {
		var target *sdn.Config
		if p.Target == PreviousTarget {
			target, err = st.LoadRevertPoint()
		} else {
			var sn *sdn.Snapshot
			if sn, err = st.LoadSnapshot(p.Target); err == nil {
				target = sn.Config
			}
		}
		if err == nil {
			// What the kernel may hold: the config being applied when the
			// portal died (applying.json), else the confirmed one.
			prev, aerr := st.LoadApplying()
			if aerr != nil {
				prev, _ = st.LoadConfirmed()
				_ = st.SaveApplying(prev) // the gateway monitor leaves links alone meanwhile
			}
			sdnBestEffortLinks = true
			_, err = SDNApply(prev, target, env)
			sdnBestEffortLinks = false
			if err != nil {
				// Even the previous ruleset will not load: never leave the
				// unconfirmed one in place.
				_ = sdnSafeMode(target, env, "the automatic revert failed: "+err.Error())
			}
			_ = st.SaveConfirmed(target)
		}
	}
	if p.Applied != "" {
		_ = st.SetOutcome(p.Applied, outcome)
	}
	if err == nil && p.Target != PreSDNTarget {
		// The draft held the reverted change; start editing from what runs.
		_ = st.DiscardDraft()
	}
	st.ClearApplying()
	_ = os.Remove(pendingPath(st))
	return err
}

// SDNStopRevertService stops a sleeping revert service ("Revert now" and
// failure paths), so it can neither fire later nor block the next arm.
func SDNStopRevertService() {
	sdnRun.Run(nil, "systemctl", "stop", sdnRevertUnit+".service") //nolint:errcheck
}
