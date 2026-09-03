package handlers

// HTTP handlers for the optional MergerFS feature (v6.7.13): install/uninstall,
// enable/disable, and pool CRUD + live status. Coordinated ZFS snapshots live
// in mergerfs_snap_schedule.go.

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"

	"github.com/gorilla/mux"
)

var mergerfsMu sync.Mutex // guards AppConfig.MergerFS mutations

// HandleMergerFSStatus reports install + enable state for the Requisites card
// and nav gating. GET /api/mergerfs/status
func HandleMergerFSStatus(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]interface{}{
			"installed": system.MergerFSInstalled(),
			"enabled":   appCfg.MergerFS.Enabled,
			"pools":     len(appCfg.MergerFS.Pools),
		})
	}
}

// HandleInstallMergerFS installs mergerfs (admin). POST /api/prerequisites/install-mergerfs
func HandleInstallMergerFS(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		var logLines []string
		err := system.InstallMergerFS(func(s string) { logLines = append(logLines, s) })
		if err != nil {
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionInstallPrereqs,
				Target: "mergerfs", Result: audit.ResultError, Details: err.Error()})
			jsonErr(w, http.StatusInternalServerError, err.Error()+"\n\n"+strings.Join(logLines, "\n"))
			return
		}
		// Installing the feature reveals its nav; enable it by default so the
		// user immediately sees "Datasets & FS" + the + Other action.
		mergerfsMu.Lock()
		appCfg.MergerFS.Enabled = true
		appCfg.MergerFS.HideNav = false
		_ = config.SaveAppConfig(appCfg)
		mergerfsMu.Unlock()
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionInstallPrereqs,
			Target: "mergerfs", Result: audit.ResultOK})
		jsonOK(w, map[string]interface{}{"installed": true, "log": strings.Join(logLines, "\n")})
	}
}

// HandleUninstallMergerFS removes the feature (admin). POST /api/prerequisites/uninstall-mergerfs
func HandleUninstallMergerFS(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if applianceBlock(w) {
			return
		}
		sess := MustSession(r)
		mergerfsMu.Lock()
		pools := appCfg.MergerFS.Pools
		mergerfsMu.Unlock()
		if err := system.UninstallMergerFS(pools); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		mergerfsMu.Lock()
		appCfg.MergerFS = config.MergerFSConfig{}
		appCfg.MergerFSSnapshotPolicies = nil
		_ = config.SaveAppConfig(appCfg)
		mergerfsMu.Unlock()
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionInstallPrereqs,
			Target: "mergerfs (uninstall)", Result: audit.ResultOK})
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleMergerFSEnable toggles the feature nav on/off. PUT /api/mergerfs/enable
func HandleMergerFSEnable(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if body.Enabled && !system.MergerFSInstalled() {
			jsonErr(w, http.StatusBadRequest, "mergerfs is not installed")
			return
		}
		mergerfsMu.Lock()
		appCfg.MergerFS.Enabled = body.Enabled
		err := config.SaveAppConfig(appCfg)
		mergerfsMu.Unlock()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, map[string]bool{"enabled": body.Enabled})
	}
}

// HandleListMergerFSPools returns the configured unions. GET /api/mergerfs/pools
func HandleListMergerFSPools(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mergerfsMu.Lock()
		pools := append([]config.MergerFSPool(nil), appCfg.MergerFS.Pools...)
		mergerfsMu.Unlock()
		jsonOK(w, map[string]interface{}{"pools": pools})
	}
}

// HandleCreateMergerFSPool validates + creates a union. POST /api/mergerfs/pools
func HandleCreateMergerFSPool(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		var spec config.MergerFSPool
		if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		mergerfsMu.Lock()
		for _, p := range appCfg.MergerFS.Pools {
			if p.Name == spec.Name || p.Mountpoint == spec.Mountpoint {
				mergerfsMu.Unlock()
				jsonErr(w, http.StatusBadRequest, "a mergerfs with that name or mount point already exists")
				return
			}
		}
		mergerfsMu.Unlock()

		created, err := system.CreateMergerFS(spec)
		if err != nil {
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionCreateDataset,
				Target: "mergerfs:" + spec.Name, Result: audit.ResultError, Details: err.Error()})
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		mergerfsMu.Lock()
		appCfg.MergerFS.Pools = append(appCfg.MergerFS.Pools, created)
		err = config.SaveAppConfig(appCfg)
		mergerfsMu.Unlock()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionCreateDataset,
			Target: "mergerfs:" + created.Name, Result: audit.ResultOK})
		jsonOK(w, created)
	}
}

// HandleMergerFSPoolStatus returns live status. GET /api/mergerfs/pools/{name}/status
func HandleMergerFSPoolStatus(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := findMergerFSPool(appCfg, mux.Vars(r)["name"])
		if !ok {
			jsonErr(w, http.StatusNotFound, "mergerfs not found")
			return
		}
		jsonOK(w, system.MergerFSGetStatus(p))
	}
}

// HandleUpdateMergerFSPool changes the runtime-settable options + branches.
// PUT /api/mergerfs/pools/{name}
func HandleUpdateMergerFSPool(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		name := mux.Vars(r)["name"]
		var body config.MergerFSPool
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		cur, ok := findMergerFSPool(appCfg, name)
		if !ok {
			jsonErr(w, http.StatusNotFound, "mergerfs not found")
			return
		}
		updated, err := system.UpdateMergerFS(cur, body)
		if err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		mergerfsMu.Lock()
		for i := range appCfg.MergerFS.Pools {
			if appCfg.MergerFS.Pools[i].Name == name {
				appCfg.MergerFS.Pools[i] = updated
				break
			}
		}
		err = config.SaveAppConfig(appCfg)
		mergerfsMu.Unlock()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionUpdateDataset,
			Target: "mergerfs:" + name, Result: audit.ResultOK})
		jsonOK(w, updated)
	}
}

// HandleDeleteMergerFSPool tears down a union (source data untouched).
// DELETE /api/mergerfs/pools/{name}
func HandleDeleteMergerFSPool(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		name := mux.Vars(r)["name"]
		p, ok := findMergerFSPool(appCfg, name)
		if !ok {
			jsonErr(w, http.StatusNotFound, "mergerfs not found")
			return
		}
		if err := system.DestroyMergerFS(p); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		mergerfsMu.Lock()
		kept := appCfg.MergerFS.Pools[:0]
		for _, x := range appCfg.MergerFS.Pools {
			if x.Name != name {
				kept = append(kept, x)
			}
		}
		appCfg.MergerFS.Pools = kept
		// drop any snapshot policy for this pool
		var keptPol []config.MergerFSSnapshotPolicy
		for _, pol := range appCfg.MergerFSSnapshotPolicies {
			if pol.Pool != name {
				keptPol = append(keptPol, pol)
			}
		}
		appCfg.MergerFSSnapshotPolicies = keptPol
		err := config.SaveAppConfig(appCfg)
		mergerfsMu.Unlock()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionDeleteDataset,
			Target: "mergerfs:" + name, Result: audit.ResultOK})
		jsonOK(w, map[string]bool{"ok": true})
	}
}

func findMergerFSPool(appCfg *config.AppConfig, name string) (config.MergerFSPool, bool) {
	mergerfsMu.Lock()
	defer mergerfsMu.Unlock()
	for _, p := range appCfg.MergerFS.Pools {
		if p.Name == name {
			return p, true
		}
	}
	return config.MergerFSPool{}, false
}
