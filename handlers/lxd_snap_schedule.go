package handlers

// Per-VM/Container snapshot schedule (v6.5.19+).
//
// Stores one LXDSnapshotPolicy per instance in AppConfig.LXDSnapshotPolicies.
// The ticker in this package fires due policies once a minute.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"
)

// snapSchedMu guards in-memory edits of AppConfig.LXDSnapshotPolicies so that
// a "user saved a policy" PUT and the scheduler ticker can never race the
// slice. Save calls flush to disk via config.SaveAppConfig.
var snapSchedMu sync.Mutex

var allowedSnapUnits = map[string][]int{
	"minute": {5, 10, 15, 20, 30},
	"hour":   {1, 2, 3, 4, 6, 8, 12},
	"day":    {1, 2, 3, 7, 14},
	"week":   {1, 2, 4},
	"month":  {1, 2, 3, 6, 12},
}

// minimumSnapPeriodSec is the smallest effective period (in seconds) we
// allow for snapshot schedules. 5 minutes — matches the policy doc.
const minimumSnapPeriodSec = 5 * 60

// HandleGetLXDSnapPolicy returns the saved policy for the named instance,
// or the zero-valued shape if no policy exists yet.
// GET /api/incus/instances/{name}/snapshot-schedule
func HandleGetLXDSnapPolicy(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := mux.Vars(r)["name"]
		snapSchedMu.Lock()
		defer snapSchedMu.Unlock()
		for _, p := range appCfg.LXDSnapshotPolicies {
			if p.Instance == name {
				jsonOK(w, map[string]interface{}{"exists": true, "policy": p, "next_run": lxdSnapNextRun(p, time.Now())})
				return
			}
		}
		jsonOK(w, map[string]interface{}{
			"exists": false,
			"policy": config.LXDSnapshotPolicy{
				Instance:   name,
				EveryN:     1,
				Unit:       "hour",
				NamePrefix: "auto",
				KeepLast:   24,
			},
		})
	}
}

// HandlePutLXDSnapPolicy saves (or replaces) the policy for the instance.
// PUT /api/incus/instances/{name}/snapshot-schedule
func HandlePutLXDSnapPolicy(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := mux.Vars(r)["name"]
		sess := MustSession(r)
		var p config.LXDSnapshotPolicy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		p.Instance = name
		if p.NamePrefix == "" {
			p.NamePrefix = "auto"
		}
		// Validate prefix — alphanumeric + dash, keeps snapshot names sane.
		for _, c := range p.NamePrefix {
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				jsonErr(w, http.StatusBadRequest, "name_prefix must be alphanumeric (with optional dashes)")
				return
			}
		}
		if err := validateSnapInterval(p.Unit, p.EveryN); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if p.KeepLast < 1 {
			p.KeepLast = 1
		}
		if p.KeepLast > 10000 {
			p.KeepLast = 10000
		}
		if p.HourOfDay < 0 || p.HourOfDay > 23 {
			p.HourOfDay = 0
		}
		if p.MinuteOfHour < 0 || p.MinuteOfHour > 59 {
			p.MinuteOfHour = 0
		}
		// Clamp the new weekly/monthly knobs to legal ranges so a
		// malformed save can't break the scheduler later.
		if p.Weekday < 0 || p.Weekday > 6 {
			p.Weekday = 0
		}
		if p.DayOfMonth < 1 || p.DayOfMonth > 31 {
			p.DayOfMonth = 1
		}

		snapSchedMu.Lock()
		replaced := false
		for i := range appCfg.LXDSnapshotPolicies {
			if appCfg.LXDSnapshotPolicies[i].Instance == name {
				p.LastRun = appCfg.LXDSnapshotPolicies[i].LastRun
				appCfg.LXDSnapshotPolicies[i] = p
				replaced = true
				break
			}
		}
		if !replaced {
			appCfg.LXDSnapshotPolicies = append(appCfg.LXDSnapshotPolicies, p)
		}
		err := config.SaveAppConfig(appCfg)
		snapSchedMu.Unlock()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		audit.Log(audit.Entry{
			User: sess.Username, Role: sess.Role,
			Action: audit.ActionUpdateSchedule,
			Target: "snapshot-schedule:" + name,
			Result: audit.ResultOK,
			Details: fmt.Sprintf("every %d %s, keep %d (%s)", p.EveryN, p.Unit, p.KeepLast,
				map[bool]string{true: "enabled", false: "disabled"}[p.Enabled]),
		})
		jsonOK(w, map[string]interface{}{"ok": true, "next_run": lxdSnapNextRun(p, time.Now())})
	}
}

// HandleDeleteLXDSnapPolicy removes the schedule (turns off auto-snapshots).
// DELETE /api/incus/instances/{name}/snapshot-schedule
func HandleDeleteLXDSnapPolicy(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := mux.Vars(r)["name"]
		sess := MustSession(r)
		snapSchedMu.Lock()
		kept := appCfg.LXDSnapshotPolicies[:0]
		removed := false
		for _, p := range appCfg.LXDSnapshotPolicies {
			if p.Instance == name {
				removed = true
				continue
			}
			kept = append(kept, p)
		}
		appCfg.LXDSnapshotPolicies = kept
		err := config.SaveAppConfig(appCfg)
		snapSchedMu.Unlock()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if removed {
			audit.Log(audit.Entry{
				User: sess.Username, Role: sess.Role,
				Action: audit.ActionDeleteSchedule,
				Target: "snapshot-schedule:" + name,
				Result: audit.ResultOK,
			})
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

func validateSnapInterval(unit string, n int) error {
	allowed, ok := allowedSnapUnits[unit]
	if !ok {
		return fmt.Errorf("unit must be minute|hour|day|week|month")
	}
	for _, v := range allowed {
		if v == n {
			return nil
		}
	}
	return fmt.Errorf("invalid every_n %d for unit %s", n, unit)
}

// StartLXDSnapshotScheduler kicks off the per-minute snapshot-schedule loop.
// Called from main.go alongside the other schedulers.
func StartLXDSnapshotScheduler(appCfg *config.AppConfig) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for now := range t.C {
			tickLXDSnapPolicies(now, appCfg)
		}
	}()
}

func tickLXDSnapPolicies(now time.Time, appCfg *config.AppConfig) {
	snapSchedMu.Lock()
	// Snapshot the slice into a local copy so we can release the mutex
	// before any potentially slow `incus` call.
	policies := make([]config.LXDSnapshotPolicy, len(appCfg.LXDSnapshotPolicies))
	copy(policies, appCfg.LXDSnapshotPolicies)
	snapSchedMu.Unlock()

	for i := range policies {
		p := policies[i]
		if !p.Enabled || !lxdSnapDue(p, now) {
			continue
		}
		go runLXDSnapshotPolicy(p, appCfg)
	}
}

func lxdSnapDue(p config.LXDSnapshotPolicy, now time.Time) bool {
	if p.EveryN <= 0 || p.Unit == "" {
		return false
	}
	switch p.Unit {
	case "minute":
		return now.Minute()%p.EveryN == 0 && now.Second() < 60
	case "hour":
		return now.Minute() == p.MinuteOfHour && now.Hour()%p.EveryN == 0
	case "day":
		if now.Hour() != p.HourOfDay || now.Minute() != p.MinuteOfHour {
			return false
		}
		days := now.Unix() / 86400
		return days%int64(p.EveryN) == 0
	case "week":
		// v6.5.19+: weekday is configurable. 0=Sun..6=Sat matches Go's
		// time.Weekday() integer values.
		if int(now.Weekday()) != normalizeWeekday(p.Weekday) {
			return false
		}
		if now.Hour() != p.HourOfDay || now.Minute() != p.MinuteOfHour {
			return false
		}
		weeks := now.Unix() / (86400 * 7)
		return weeks%int64(p.EveryN) == 0
	case "month":
		// v6.5.19+: day-of-month is configurable. Clamped to the last
		// day of the current month when the configured day doesn't
		// exist (e.g. DOM=31 on a 30-day month).
		want := effectiveDayOfMonth(p.DayOfMonth, now)
		if now.Day() != want || now.Hour() != p.HourOfDay || now.Minute() != p.MinuteOfHour {
			return false
		}
		return int(now.Month())%p.EveryN == 1
	}
	return false
}

// normalizeWeekday returns a weekday integer in [0..6]. Falls back to 0
// (Sunday) for values outside the range.
func normalizeWeekday(w int) int {
	if w >= 0 && w <= 6 {
		return w
	}
	return 0
}

// effectiveDayOfMonth clamps a 1..31 configured day to the last day of
// the calendar month at `now`. Values outside 1..31 fall back to 1.
func effectiveDayOfMonth(dom int, now time.Time) int {
	if dom < 1 || dom > 31 {
		dom = 1
	}
	// Last day of the current month: day 0 of next month.
	last := time.Date(now.Year(), now.Month()+1, 0, 0, 0, 0, 0, now.Location()).Day()
	if dom > last {
		return last
	}
	return dom
}

func lxdSnapNextRun(p config.LXDSnapshotPolicy, from time.Time) time.Time {
	// Step forward minute-by-minute up to 1 month. Cheap, correct, and
	// easy to verify; matches the existing scheduler.NextRun pattern.
	t := from.Truncate(time.Minute).Add(time.Minute)
	end := from.Add(31 * 24 * time.Hour)
	for ; t.Before(end); t = t.Add(time.Minute) {
		if lxdSnapDue(p, t) {
			return t
		}
	}
	return time.Time{}
}

func runLXDSnapshotPolicy(p config.LXDSnapshotPolicy, appCfg *config.AppConfig) {
	now := time.Now()
	snapName := system.LXDSnapshotName(p.NamePrefix, now)

	err := system.CreateLXDSnapshot(p.Instance, snapName, false)
	updateSnapPolicyStatus(appCfg, p.Instance, now, snapName, err)
	if err != nil {
		log.Printf("[lxd-snap-sched] %s/%s: %v", p.Instance, snapName, err)
		audit.Log(audit.Entry{
			User:   "system",
			Role:   "system",
			Action: audit.ActionLXDScheduledSnapshot,
			Target: p.Instance + "/" + snapName,
			Result: audit.ResultError,
			Details: err.Error(),
		})
		return
	}
	audit.Log(audit.Entry{
		User:   "system",
		Role:   "system",
		Action: audit.ActionLXDScheduledSnapshot,
		Target: p.Instance + "/" + snapName,
		Result: audit.ResultOK,
	})

	// Retention — fetch fresh snapshot list from Incus and drop the oldest
	// auto-* ones past p.KeepLast.
	snaps, err := system.ListLXDSnapshots(p.Instance)
	if err != nil {
		return
	}
	// Filter to prefix-* and sort newest-first. Don't trust the incus query
	// ordering — if it ever came back oldest-first, the slice below would
	// delete the NEWEST snapshots instead of the oldest.
	matched := snaps[:0]
	for _, s := range snaps {
		if strings.HasPrefix(s.Name, p.NamePrefix+"-") || s.Name == p.NamePrefix {
			matched = append(matched, s)
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].CreatedAt.After(matched[j].CreatedAt) })
	var keep []string
	for _, s := range matched {
		keep = append(keep, s.Name)
	}
	if len(keep) <= p.KeepLast {
		return
	}
	for _, name := range keep[p.KeepLast:] {
		if delErr := system.DeleteLXDSnapshot(p.Instance, name); delErr != nil {
			log.Printf("[lxd-snap-sched] prune %s/%s: %v", p.Instance, name, delErr)
		}
	}
}

func updateSnapPolicyStatus(appCfg *config.AppConfig, instance string, runAt time.Time, snapName string, err error) {
	snapSchedMu.Lock()
	defer snapSchedMu.Unlock()
	for i := range appCfg.LXDSnapshotPolicies {
		if appCfg.LXDSnapshotPolicies[i].Instance != instance {
			continue
		}
		appCfg.LXDSnapshotPolicies[i].LastRun = runAt
		if err != nil {
			appCfg.LXDSnapshotPolicies[i].LastStatus = "error"
			appCfg.LXDSnapshotPolicies[i].LastError = err.Error()
		} else {
			appCfg.LXDSnapshotPolicies[i].LastStatus = "ok"
			appCfg.LXDSnapshotPolicies[i].LastError = ""
			appCfg.LXDSnapshotPolicies[i].LastSnap = snapName
		}
		_ = config.SaveAppConfig(appCfg)
		return
	}
}
