package handlers

// Coordinated global-snapshot endpoints + scheduler for all-ZFS MergerFS
// unions (v6.7.13). Mirrors the per-VM snapshot UX: list / take now / restore /
// delete, plus a keep-count schedule.

import (
	"encoding/json"
	"net/http"
	"time"

	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"

	"github.com/gorilla/mux"
)

// requireAllZFSPool resolves the pool and rejects non-all-ZFS unions (global
// snapshots need every branch to be a ZFS dataset).
func requireAllZFSPool(appCfg *config.AppConfig, w http.ResponseWriter, name string) (config.MergerFSPool, bool) {
	p, ok := findMergerFSPool(appCfg, name)
	if !ok {
		jsonErr(w, http.StatusNotFound, "mergerfs not found")
		return p, false
	}
	if !p.AllZFS {
		jsonErr(w, http.StatusBadRequest, "global snapshots require every source to be a ZFS dataset")
		return p, false
	}
	return p, true
}

// GET /api/mergerfs/pools/{name}/snapshots
func HandleMergerFSSnapshots(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := requireAllZFSPool(appCfg, w, mux.Vars(r)["name"])
		if !ok {
			return
		}
		jsonOK(w, map[string]interface{}{"snapshots": system.MergerFSListSnapshots(p)})
	}
}

// POST /api/mergerfs/pools/{name}/snap-now
func HandleMergerFSSnapNow(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		p, ok := requireAllZFSPool(appCfg, w, mux.Vars(r)["name"])
		if !ok {
			return
		}
		name, errs := system.MergerFSTakeSnapshot(p)
		result := audit.ResultOK
		if len(errs) > 0 {
			result = audit.ResultError
		}
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionCreateSnapshot,
			Target: "mergerfs:" + p.Name + "@" + name, Result: result})
		if len(errs) > 0 {
			jsonErr(w, http.StatusInternalServerError, "some datasets failed to snapshot: "+firstErr(errs))
			return
		}
		jsonOK(w, map[string]string{"snapshot": name})
	}
}

// POST /api/mergerfs/pools/{name}/snap-restore  {snap_name}
func HandleMergerFSSnapRestore(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		p, ok := requireAllZFSPool(appCfg, w, mux.Vars(r)["name"])
		if !ok {
			return
		}
		var body struct {
			SnapName string `json:"snap_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.SnapName == "" {
			jsonErr(w, http.StatusBadRequest, "snap_name is required")
			return
		}
		errs := system.MergerFSRestoreSnapshot(p, body.SnapName)
		result := audit.ResultOK
		if len(errs) > 0 {
			result = audit.ResultError
		}
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionRestoreSnapshot,
			Target: "mergerfs:" + p.Name + "@" + body.SnapName, Result: result})
		if len(errs) > 0 {
			jsonErr(w, http.StatusInternalServerError, "some datasets failed to roll back: "+firstErr(errs))
			return
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// DELETE /api/mergerfs/pools/{name}/snapshots  {snap_name}
func HandleMergerFSSnapDelete(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		p, ok := requireAllZFSPool(appCfg, w, mux.Vars(r)["name"])
		if !ok {
			return
		}
		var body struct {
			SnapName string `json:"snap_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.SnapName == "" {
			jsonErr(w, http.StatusBadRequest, "snap_name is required")
			return
		}
		errs := system.MergerFSDeleteSnapshot(p, body.SnapName)
		if len(errs) > 0 {
			jsonErr(w, http.StatusInternalServerError, "some datasets failed to delete: "+firstErr(errs))
			return
		}
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionDeleteSnapshot,
			Target: "mergerfs:" + p.Name + "@" + body.SnapName, Result: audit.ResultOK})
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// GET /api/mergerfs/pools/{name}/snap-schedule
func HandleGetMergerFSSnapSchedule(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := mux.Vars(r)["name"]
		for _, pol := range appCfg.MergerFSSnapshotPolicies {
			if pol.Pool == name {
				jsonOK(w, map[string]interface{}{"exists": true, "policy": pol})
				return
			}
		}
		jsonOK(w, map[string]interface{}{"exists": false, "policy": config.MergerFSSnapshotPolicy{
			Pool: name, EveryN: 1, Unit: "day", HourOfDay: 2, KeepLast: 7}})
	}
}

// PUT /api/mergerfs/pools/{name}/snap-schedule
func HandlePutMergerFSSnapSchedule(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		name := mux.Vars(r)["name"]
		if _, ok := requireAllZFSPool(appCfg, w, name); !ok {
			return
		}
		var p config.MergerFSSnapshotPolicy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		p.Pool = name
		if p.KeepLast < 1 {
			p.KeepLast = 1
		}
		if p.KeepLast > 10000 {
			p.KeepLast = 10000
		}
		mergerfsMu.Lock()
		replaced := false
		for i := range appCfg.MergerFSSnapshotPolicies {
			if appCfg.MergerFSSnapshotPolicies[i].Pool == name {
				p.LastRun = appCfg.MergerFSSnapshotPolicies[i].LastRun
				appCfg.MergerFSSnapshotPolicies[i] = p
				replaced = true
				break
			}
		}
		if !replaced {
			appCfg.MergerFSSnapshotPolicies = append(appCfg.MergerFSSnapshotPolicies, p)
		}
		err := config.SaveAppConfig(appCfg)
		mergerfsMu.Unlock()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionUpdateSchedule,
			Target: "mergerfs-snap-schedule:" + name, Result: audit.ResultOK})
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// DELETE /api/mergerfs/pools/{name}/snap-schedule
func HandleDeleteMergerFSSnapSchedule(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		name := mux.Vars(r)["name"]
		mergerfsMu.Lock()
		var kept []config.MergerFSSnapshotPolicy
		for _, pol := range appCfg.MergerFSSnapshotPolicies {
			if pol.Pool != name {
				kept = append(kept, pol)
			}
		}
		appCfg.MergerFSSnapshotPolicies = kept
		err := config.SaveAppConfig(appCfg)
		mergerfsMu.Unlock()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionDeleteSchedule,
			Target: "mergerfs-snap-schedule:" + name, Result: audit.ResultOK})
		jsonOK(w, map[string]bool{"ok": true})
	}
}

func firstErr(m map[string]string) string {
	for k, v := range m {
		return k + ": " + v
	}
	return ""
}

// ── scheduler ────────────────────────────────────────────────────────────────

// StartMergerFSSnapshotScheduler runs the per-minute coordinated-snapshot loop.
func StartMergerFSSnapshotScheduler(appCfg *config.AppConfig) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for now := range t.C {
			tickMergerFSSnapshotPolicies(now, appCfg)
		}
	}()
}

func tickMergerFSSnapshotPolicies(now time.Time, appCfg *config.AppConfig) {
	mergerfsMu.Lock()
	pols := append([]config.MergerFSSnapshotPolicy(nil), appCfg.MergerFSSnapshotPolicies...)
	mergerfsMu.Unlock()
	for _, pol := range pols {
		if !pol.Enabled || !mergerfsSnapDue(pol, now) {
			continue
		}
		p, ok := findMergerFSPool(appCfg, pol.Pool)
		if !ok || !p.AllZFS {
			continue
		}
		go runMergerFSSnapshotPolicy(p, pol, appCfg)
	}
}

func runMergerFSSnapshotPolicy(p config.MergerFSPool, pol config.MergerFSSnapshotPolicy, appCfg *config.AppConfig) {
	name, errs := system.MergerFSTakeSnapshot(p)
	res := audit.ResultOK
	det := "scheduled global snapshot"
	if len(errs) > 0 {
		res = audit.ResultError
		det = firstErr(errs)
	} else {
		system.MergerFSPruneSnapshots(p, pol.KeepLast)
	}
	audit.Log(audit.Entry{User: "system", Role: "system", Action: audit.ActionCreateSnapshot,
		Target: "mergerfs:" + p.Name + "@" + name, Result: res, Details: det})
	mergerfsMu.Lock()
	for i := range appCfg.MergerFSSnapshotPolicies {
		if appCfg.MergerFSSnapshotPolicies[i].Pool == p.Name {
			appCfg.MergerFSSnapshotPolicies[i].LastRun = time.Now()
			appCfg.MergerFSSnapshotPolicies[i].LastStatus = res
			if len(errs) > 0 {
				appCfg.MergerFSSnapshotPolicies[i].LastError = det
			} else {
				appCfg.MergerFSSnapshotPolicies[i].LastError = ""
			}
			break
		}
	}
	_ = config.SaveAppConfig(appCfg)
	mergerfsMu.Unlock()
}

// mergerfsSnapDue mirrors lxdSnapDue's cadence semantics.
func mergerfsSnapDue(p config.MergerFSSnapshotPolicy, now time.Time) bool {
	if p.EveryN <= 0 || p.Unit == "" {
		return false
	}
	switch p.Unit {
	case "minute":
		return now.Minute()%p.EveryN == 0
	case "hour":
		return now.Minute() == p.MinuteOfHour && now.Hour()%p.EveryN == 0
	case "day":
		if now.Hour() != p.HourOfDay || now.Minute() != p.MinuteOfHour {
			return false
		}
		return (now.Unix()/86400)%int64(p.EveryN) == 0
	case "week":
		if int(now.Weekday()) != normalizeWeekday(p.Weekday) || now.Hour() != p.HourOfDay || now.Minute() != p.MinuteOfHour {
			return false
		}
		return (now.Unix()/(86400*7))%int64(p.EveryN) == 0
	case "month":
		if now.Day() != effectiveDayOfMonth(p.DayOfMonth, now) || now.Hour() != p.HourOfDay || now.Minute() != p.MinuteOfHour {
			return false
		}
		return int(now.Month())%p.EveryN == 1
	}
	return false
}
