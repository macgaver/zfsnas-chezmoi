package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/termsessions"
	"zfsnas/system"

	"github.com/creack/pty"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// lxdAvailable is set once at startup by main and read-only afterwards.
var lxdAvailable bool
var lxdAvailableMu sync.RWMutex

// SetLXDAvailable stores the LXD probe result.
func SetLXDAvailable(v bool) {
	lxdAvailableMu.Lock()
	lxdAvailable = v
	lxdAvailableMu.Unlock()
}

func isLXDAvailable() bool {
	lxdAvailableMu.RLock()
	defer lxdAvailableMu.RUnlock()
	return lxdAvailable
}

// lxdJob tracks an async LXD create operation.
type lxdJob struct {
	mu     sync.Mutex
	Status string `json:"status"` // "running", "done", "error"
	Error  string `json:"error,omitempty"`
	Lines  []string
}

var lxdJobs sync.Map // job_id → *lxdJob

// HandleLXDStatus returns whether LXD is available and its version.
// GET /api/lxd/status
func HandleLXDStatus(w http.ResponseWriter, r *http.Request) {
	available := isLXDAvailable()
	ver := ""
	if available {
		ver = system.LXDVersion()
	}
	jsonOK(w, map[string]interface{}{
		"available": available,
		"version":   ver,
	})
}

// HandleLXDRefreshStatus re-probes LXD and updates cached availability.
// POST /api/lxd/refresh-status
func HandleLXDRefreshStatus(w http.ResponseWriter, r *http.Request) {
	v := system.LXDAvailable()
	SetLXDAvailable(v)
	ver := ""
	if v {
		ver = system.LXDVersion()
	}
	jsonOK(w, map[string]interface{}{
		"available": v,
		"version":   ver,
	})
}

// HandleListInstances returns all LXD instances.
// GET /api/lxd/instances
func HandleListInstances(w http.ResponseWriter, r *http.Request) {
	instances, err := system.ListLXDInstances()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Standard users with an instance-visibility regex see only the
	// VMs/containers whose ID matches it.
	if p := standardPermsForSession(r); p != nil {
		visible := make([]system.LXDInstance, 0, len(instances))
		for _, inst := range instances {
			if p.InstanceVisible(inst.Name) {
				visible = append(visible, inst)
			}
		}
		instances = visible
	}
	jsonOK(w, instances)
}

// HandleLXDInstanceStats returns live CPU/memory/disk usage for one instance.
// GET /api/lxd/instances/{name}/stats
func HandleLXDInstanceStats(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	stats, err := system.LXDGetInstanceStats(name)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, stats)
}

// HandleLXDInstanceStatus returns the current status of one instance.
// GET /api/lxd/instances/{name}/status
func HandleLXDInstanceStatus(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	status, err := system.LXDGetStatus(name)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]string{"status": status})
}

// HandleLXDListSnapshots returns all snapshots for an instance.
// GET /api/lxd/instances/{name}/snapshots
func HandleLXDListSnapshots(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	snaps, err := system.ListLXDSnapshots(name)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, snaps)
}

// HandleLXDCreateSnapshot starts an async snapshot job and returns a job_id immediately.
// POST /api/lxd/instances/{name}/snapshots
func HandleLXDCreateSnapshot(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	sess := MustSession(r)
	var req struct {
		SnapName string `json:"name"`
		Stateful bool   `json:"stateful"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	jobID := fmt.Sprintf("%d", time.Now().UnixNano())
	job := &lxdJob{Status: "running"}
	lxdJobs.Store(jobID, job)
	go func() {
		err := system.CreateLXDSnapshot(name, req.SnapName, req.Stateful)
		job.mu.Lock()
		defer job.mu.Unlock()
		if err != nil {
			job.Status = "error"
			job.Error = err.Error()
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDSnapshot, Target: name + "/" + req.SnapName, Result: audit.ResultError, Details: err.Error()})
		} else {
			job.Status = "done"
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDSnapshot, Target: name + "/" + req.SnapName, Result: audit.ResultOK})
		}
	}()
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
}

// HandleLXDRestoreSnapshot reverts an instance to a snapshot.
// POST /api/lxd/instances/{name}/snapshots/{snap}/restore
// Body (optional): {"remove_subsequent": true}
func HandleLXDRestoreSnapshot(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, snap := vars["name"], vars["snap"]
	sess := MustSession(r)
	var req struct {
		RemoveSubsequent bool `json:"remove_subsequent"`
	}
	json.NewDecoder(r.Body).Decode(&req) // body is optional; ignore decode errors
	jobID := fmt.Sprintf("%d", time.Now().UnixNano())
	job := &lxdJob{Status: "running"}
	lxdJobs.Store(jobID, job)
	go func() {
		err := system.RestoreLXDSnapshot(name, snap, req.RemoveSubsequent)
		job.mu.Lock()
		defer job.mu.Unlock()
		if err != nil {
			job.Status = "error"
			job.Error = err.Error()
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDRestore, Target: name + "/" + snap, Result: audit.ResultError, Details: err.Error()})
		} else {
			job.Status = "done"
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDRestore, Target: name + "/" + snap, Result: audit.ResultOK})
		}
	}()
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
}

// HandleLXDCloneFromSnapshot creates a new instance from a snapshot copy.
// POST /api/lxd/instances/{name}/snapshots/{snap}/clone
func HandleLXDCloneFromSnapshot(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, snap := vars["name"], vars["snap"]
	sess := MustSession(r)
	var req struct {
		NewName     string `json:"new_name"`
		Description string `json:"description"`
		TargetPool  string `json:"target_pool"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.NewName) == "" {
		jsonErr(w, http.StatusBadRequest, "new_name is required")
		return
	}
	newName := strings.TrimSpace(req.NewName)
	targetPool := strings.TrimSpace(req.TargetPool)
	jobID := fmt.Sprintf("%d", time.Now().UnixNano())
	job := &lxdJob{Status: "running"}
	lxdJobs.Store(jobID, job)
	go func() {
		err := system.CloneLXDFromSnapshot(name, snap, newName, req.Description, targetPool)
		job.mu.Lock()
		defer job.mu.Unlock()
		if err != nil {
			job.Status = "error"
			job.Error = err.Error()
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDClone, Target: name + "/" + snap + " → " + newName, Result: audit.ResultError, Details: err.Error()})
		} else {
			job.Status = "done"
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDClone, Target: name + "/" + snap + " → " + newName, Result: audit.ResultOK})
		}
	}()
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
}

// HandleLXDDeleteSnapshot deletes a snapshot from an instance.
// DELETE /api/lxd/instances/{name}/snapshots/{snap}
func HandleLXDDeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name, snap := vars["name"], vars["snap"]
	sess := MustSession(r)
	if err := system.DeleteLXDSnapshot(name, snap); err != nil {
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDDeleteSnapshot, Target: name + "/" + snap, Result: audit.ResultError, Details: err.Error()})
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDDeleteSnapshot, Target: name + "/" + snap, Result: audit.ResultOK})
	jsonOK(w, map[string]string{"ok": "deleted"})
}

// HandleLXDInstanceLogs returns recent log entries for the named instance.
// Optional ?file=<basename> narrows the response to a single log file (the
// dropdown the frontend renders); when omitted the response merges every
// log file Incus exposes.
// GET /api/lxd/instances/{name}/logs[?file=qemu.log]
func HandleLXDInstanceLogs(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	fileFilter := r.URL.Query().Get("file")
	entries, err := system.GetLXDInstanceLogs(name, fileFilter)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, entries)
}

// HandleLXDInstanceLogFiles returns the list of log files Incus exposes
// for the instance, each annotated with a current line count so the
// frontend's picker can show "qemu.log (12,453 lines)" labels.
// GET /api/lxd/instances/{name}/log-files
func HandleLXDInstanceLogFiles(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	files, err := system.ListLXDInstanceLogFiles(name)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{
		"files":   files,
		"default": system.DefaultLXDLogFileName(name),
	})
}

// HandleLXDInstanceConsoleLog returns the boot/console.log contents for a
// container (the kernel + init output since the last start). Returns plain
// text in a JSON envelope so the frontend can render it in a terminal-styled
// pane.
// GET /api/lxd/instances/{name}/console-log
func HandleLXDInstanceConsoleLog(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	text, err := system.GetLXDInstanceConsoleLog(name)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]string{"log": text})
}

// HandleLXDCloneInstance clones an instance directly (no snapshot required).
// POST /api/lxd/instances/{name}/clone
func HandleLXDCloneInstance(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	sess := MustSession(r)
	var req struct {
		NewName     string `json:"new_name"`
		Description string `json:"description"`
		TargetPool  string `json:"target_pool"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.NewName) == "" {
		jsonErr(w, http.StatusBadRequest, "new_name is required")
		return
	}
	newName := strings.TrimSpace(req.NewName)
	targetPool := strings.TrimSpace(req.TargetPool)
	jobID := fmt.Sprintf("%d", time.Now().UnixNano())
	job := &lxdJob{Status: "running"}
	lxdJobs.Store(jobID, job)
	go func() {
		err := system.CloneLXDInstance(name, newName, req.Description, targetPool)
		job.mu.Lock()
		defer job.mu.Unlock()
		if err != nil {
			job.Status = "error"
			job.Error = err.Error()
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDClone, Target: name + " → " + newName, Result: audit.ResultError, Details: err.Error()})
		} else {
			job.Status = "done"
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDClone, Target: name + " → " + newName, Result: audit.ResultOK})
		}
	}()
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
}

// HandleLXDMoveStorage migrates all instance volumes to a different local storage pool.
// POST /api/lxd/instances/{name}/move-storage
func HandleLXDMoveStorage(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	sess := MustSession(r)
	var req struct {
		TargetPool string `json:"target_pool"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.TargetPool) == "" {
		jsonErr(w, http.StatusBadRequest, "target_pool is required")
		return
	}
	targetPool := strings.TrimSpace(req.TargetPool)
	jobID := fmt.Sprintf("%d", time.Now().UnixNano())
	job := &lxdJob{Status: "running"}
	lxdJobs.Store(jobID, job)
	go func() {
		err := system.LXDMoveStorage(name, targetPool)
		job.mu.Lock()
		defer job.mu.Unlock()
		if err != nil {
			job.Status = "error"
			job.Error = err.Error()
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDMoveStorage, Target: name + " → " + targetPool, Result: audit.ResultError, Details: err.Error()})
		} else {
			job.Status = "done"
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDMoveStorage, Target: name + " → " + targetPool, Result: audit.ResultOK})
		}
	}()
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
}

// HandleLXDStart starts an instance.
// POST /api/lxd/instances/{name}/start
func HandleLXDStart(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	sess := MustSession(r)
	if err := system.LXDStart(name); err != nil {
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDStart, Target: name, Result: audit.ResultError, Details: err.Error()})
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDStart, Target: name, Result: audit.ResultOK})
	jsonOK(w, map[string]string{"ok": "started"})
}

// HandleLXDStop stops an instance.
// POST /api/lxd/instances/{name}/stop
func HandleLXDStop(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	sess := MustSession(r)
	var req struct {
		Force bool `json:"force"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if err := system.LXDStop(name, req.Force); err != nil {
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDStop, Target: name, Result: audit.ResultError, Details: err.Error()})
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDStop, Target: name, Result: audit.ResultOK})
	jsonOK(w, map[string]string{"ok": "stopped"})
}

// HandleLXDRestart restarts an instance.
// POST /api/lxd/instances/{name}/restart
func HandleLXDRestart(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	sess := MustSession(r)
	if err := system.LXDRestart(name); err != nil {
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDRestart, Target: name, Result: audit.ResultError, Details: err.Error()})
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDRestart, Target: name, Result: audit.ResultOK})
	jsonOK(w, map[string]string{"ok": "restarted"})
}

// HandleLXDReset cold-boots an instance — used by the VGA console's
// keyboard menu so a stuck guest (BSOD, frozen boot loader, OVMF setup)
// can be recovered without dropping out of the viewer.
// POST /api/lxd/instances/{name}/reset
func HandleLXDReset(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	sess := MustSession(r)
	if err := system.LXDReset(name); err != nil {
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDRestart, Target: name, Result: audit.ResultError, Details: "reset: " + err.Error()})
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDRestart, Target: name, Result: audit.ResultOK, Details: "force reset (VGA Reset button)"})
	jsonOK(w, map[string]string{"ok": "reset"})
}

// HandleListFreeZVols returns ZFS volumes available for VM attachment.
// GET /api/lxd/free-zvols
func HandleListFreeZVols(w http.ResponseWriter, r *http.Request) {
	zvols, err := system.ListFreeZVols()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, zvols)
}

// HandleListBridges returns available network bridges (LXD managed + OS host bridges).
// GET /api/lxd/bridges
func HandleListBridges(w http.ResponseWriter, r *http.Request) {
	infos, _ := system.LXDListNetworkInfos()
	host, _ := system.ListHostBridges()

	managedNames := []string{}
	seen := map[string]bool{}
	allNames := []string{}
	objects := []map[string]interface{}{}

	for _, info := range infos {
		if info.Managed {
			managedNames = append(managedNames, info.Name)
		}
		if !seen[info.Name] {
			allNames = append(allNames, info.Name)
			seen[info.Name] = true
			objects = append(objects, map[string]interface{}{
				"name":        info.Name,
				"description": info.Description,
				"managed":     info.Managed,
			})
		}
	}
	for _, b := range host {
		if !seen[b] {
			allNames = append(allNames, b)
			seen[b] = true
			objects = append(objects, map[string]interface{}{
				"name":        b,
				"description": "",
				"managed":     false,
			})
		}
	}
	if allNames == nil {
		allNames = []string{}
	}
	jsonOK(w, map[string]interface{}{"managed": managedNames, "all": allNames, "objects": objects})
}

// HandleLXDGetConfig returns the editable configuration of an instance.
// GET /api/lxd/instances/{name}/config
func HandleLXDGetConfig(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	cfg, err := system.LXDGetConfig(name)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, cfg)
}

// HandleLXDSetConfig applies editable configuration to an instance.
// PUT /api/lxd/instances/{name}/config
func HandleLXDSetConfig(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	sess := MustSession(r)
	var req struct {
		system.LXDInstanceConfig
		CDROMPool string `json:"cdrom_pool"`
		CDROMIso  string `json:"cdrom_iso"`
		CDROMList []struct {
			Pool string `json:"pool"`
			Iso  string `json:"iso"`
		} `json:"cdrom_list"`
	}
	// Read the body once so we can decode it twice — into the typed struct
	// for use, and into a key-presence map so we know which device sections
	// the caller actually included. A partial PUT (e.g. just `{"nics":[…]}`)
	// must NOT trigger destructive diffs on sections the caller didn't
	// mention. See LXDInstanceConfig.Manage* doc for the full rationale.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "could not read request body")
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var present map[string]json.RawMessage
	if err := json.Unmarshal(body, &present); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if _, ok := present["nics"]; ok {
		req.LXDInstanceConfig.ManageNICs = true
	}
	if _, ok := present["disks"]; ok {
		req.LXDInstanceConfig.ManageDisks = true
	}
	if _, ok := present["bind_mounts"]; ok {
		req.LXDInstanceConfig.ManageBindMounts = true
	}
	if _, ok := present["usb_devices"]; ok {
		req.LXDInstanceConfig.ManageUSBDevices = true
	}
	if _, ok := present["pci_devices"]; ok {
		req.LXDInstanceConfig.ManagePCIDevices = true
	}
	if _, ok := present["passthrough_devices"]; ok {
		req.LXDInstanceConfig.ManagePassthroughDevices = true
	}
	if _, ok := present["existing_disks_raw"]; ok {
		req.LXDInstanceConfig.ManageExistingDisks = true
	}
	// Scalar/config section (CPU, memory, description, firmware, …) is applied
	// only when the body actually carries one of those keys — otherwise a
	// device-only partial PUT (e.g. `{"nics":[...]}`) would unset them by
	// writing zero-values. The web edit modal sends the full config so this is
	// always true for normal edits.
	for _, k := range []string{
		"description", "cpu_limit", "cpu_pin", "cpu_sockets", "cpu_shares",
		"cpu_limit_pct", "memory_limit", "memory_hugepages", "memory_reservation",
		"nesting", "autostart", "force_running", "stateful_snapshots",
		"unprivileged", "firmware", "secure_boot", "tpm", "machine_type",
		"disable_virtual_vga", "swap_limit", "feature_keyctl",
	} {
		if _, ok := present[k]; ok {
			req.LXDInstanceConfig.ManageResources = true
			break
		}
	}
	// Multi-drive path: resolve cdrom_list entries to absolute paths.
	if len(req.CDROMList) > 0 {
		req.LXDInstanceConfig.ApplyCDROMs = true
		var paths []string
		for _, entry := range req.CDROMList {
			if entry.Pool == "" || entry.Iso == "" {
				paths = append(paths, "") // empty drive slot
				continue
			}
			isoDir, err := system.LXDISODir(entry.Pool)
			if err != nil {
				jsonErr(w, http.StatusBadRequest, "cannot resolve ISO directory: "+err.Error())
				return
			}
			paths = append(paths, filepath.Join(isoDir, entry.Iso))
		}
		req.LXDInstanceConfig.CDROMs = paths
	} else if req.CDROMPool != "" || req.CDROMIso != "" {
		// Legacy single-drive path.
		req.LXDInstanceConfig.ApplyCDROM = true
		if req.CDROMPool != "" && req.CDROMIso != "" {
			isoDir, err := system.LXDISODir(req.CDROMPool)
			if err != nil {
				jsonErr(w, http.StatusBadRequest, "cannot resolve ISO directory: "+err.Error())
				return
			}
			req.LXDInstanceConfig.CDROMPath = filepath.Join(isoDir, req.CDROMIso)
		} else {
			req.LXDInstanceConfig.CDROMPath = ""
		}
	}
	if err := system.LXDSetConfig(name, req.LXDInstanceConfig); err != nil {
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDEditConfig, Target: name, Result: audit.ResultError, Details: err.Error()})
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDEditConfig, Target: name, Result: audit.ResultOK})
	// Config edits can add/remove disk devices — refresh the cached
	// instance→disks mapping so topology + Virtual Disks associations are
	// immediately accurate (v6.7.7).
	invalidateInstanceDisks()
	jsonOK(w, map[string]string{"ok": "updated"})
}

// HandleLXDDelete deletes an instance.
// DELETE /api/lxd/instances/{name}
func HandleLXDDelete(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	sess := MustSession(r)
	var req struct {
		DeleteVolumes bool `json:"delete_volumes"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if err := system.LXDDelete(name, req.DeleteVolumes); err != nil {
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDDelete, Target: name, Result: audit.ResultError, Details: err.Error()})
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDDelete, Target: name, Result: audit.ResultOK})
	// Drop any per-instance metrics history (v6.4.28). Non-fatal: losing
	// history must never block instance deletion itself.
	if err := system.DeleteLXDInstanceMetrics(name); err != nil {
		log.Printf("delete metrics history for %q: %v", name, err)
	}
	jsonOK(w, map[string]string{"ok": "deleted"})
}

// HandleListRemotes returns all configured LXD image remotes.
// GET /api/lxd/remotes
func HandleListRemotes(w http.ResponseWriter, r *http.Request) {
	remotes, err := system.LXDListRemotes()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, remotes)
}

// HandleListImages returns images filtered by kind and source.
// GET /api/lxd/images?kind=virtual-machine|container&source=local|<remote-name>
func HandleListImages(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "local"
	}
	var imgs []system.LXDImage
	var err error
	if source == "local" {
		imgs, err = system.LXDListLocalImages(kind)
	} else {
		imgs, err = system.LXDListRemoteImages(source+":", kind)
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Only show x86_64 images (amd64 and x86_64 are both names for the same arch).
	filtered := imgs[:0]
	for _, img := range imgs {
		if img.Arch == "amd64" || img.Arch == "x86_64" {
			filtered = append(filtered, img)
		}
	}
	// Sort most-recent first; serial is YYYYMMDD[_HHMMSS] so lexicographic descending works.
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Serial > filtered[j].Serial
	})
	jsonOK(w, filtered)
}

// HandleListProfiles returns LXD profile names.
// GET /api/lxd/profiles
func HandleListProfiles(w http.ResponseWriter, r *http.Request) {
	names, err := system.LXDListProfiles()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, names)
}

// HandleListStoragePools returns LXD storage pool names.
// GET /api/lxd/storage-pools
func HandleListStoragePools(w http.ResponseWriter, r *http.Request) {
	names, err := system.LXDListStoragePools()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, names)
}

// HandleDefaultRootPool returns the storage pool that the `default` profile's
// root disk resolves to, so the create dialogs can label their "profile
// default" option with the datastore it will actually use.
// GET /api/lxd/default-root-pool
func HandleDefaultRootPool(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"pool": system.LXDDefaultProfileRootPool()})
}

// HandleListNetworks returns LXD network names.
// GET /api/lxd/networks
func HandleListNetworks(w http.ResponseWriter, r *http.Request) {
	names, err := system.LXDListNetworks()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, names)
}

// HandleListUSB returns USB devices on the host.
// GET /api/lxd/usb-devices
func HandleListUSB(w http.ResponseWriter, r *http.Request) {
	devices, err := system.ListUSBDevices()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, devices)
}

// HandleListPCI returns PCI devices on the host.
// GET /api/lxd/pci-devices
func HandleListPCI(w http.ResponseWriter, r *http.Request) {
	devices, err := system.ListPCIDevices()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, devices)
}

// HandleLXDCPUTopology returns the host CPU topology (P-cores, E-cores, total).
// GET /api/lxd/cpu-topology
func HandleLXDCPUTopology(w http.ResponseWriter, r *http.Request) {
	topo, err := system.GetCPUTopology()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{
		"total_cpus":  topo.TotalCPUs,
		"p_cores":     topo.PCores,
		"e_cores":     topo.ECores,
		"hybrid":      topo.Hybrid,
		"p_cores_lxd": system.CPUIdsToLXD(topo.PCores),
		"e_cores_lxd": system.CPUIdsToLXD(topo.ECores),
	})
}

// HandleLXDMachineVersions returns the QEMU machine type versions supported by this host.
// GET /api/lxd/machine-versions
func HandleLXDMachineVersions(w http.ResponseWriter, r *http.Request) {
	mv, err := system.GetLXDMachineVersions()
	if err != nil {
		jsonErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	jsonOK(w, mv)
}

// HandleCreateVM starts async VM creation and returns a job_id.
// POST /api/lxd/vms
func HandleCreateVM(w http.ResponseWriter, r *http.Request) {
	var body struct {
		system.LXDCreateVMRequest
		CDROMList []struct {
			Pool string `json:"pool"`
			Iso  string `json:"iso"`
		} `json:"cdrom_list"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := body.LXDCreateVMRequest
	if req.Name == "" {
		jsonErr(w, http.StatusBadRequest, "name is required")
		return
	}

	// Resolve cdrom_list (multi-drive) or fallback to legacy single-drive.
	if len(body.CDROMList) > 0 {
		for _, entry := range body.CDROMList {
			if entry.Pool == "" || entry.Iso == "" {
				req.CDROMs = append(req.CDROMs, "")
				continue
			}
			dir, err := system.LXDISODir(entry.Pool)
			if err != nil {
				jsonErr(w, http.StatusBadRequest, "invalid cdrom pool: "+err.Error())
				return
			}
			req.CDROMs = append(req.CDROMs, filepath.Join(dir, entry.Iso))
		}
	} else if req.CDROMPool != "" && req.CDROMIso != "" {
		dir, err := system.LXDISODir(req.CDROMPool)
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid cdrom pool: "+err.Error())
			return
		}
		req.CDROMPath = filepath.Join(dir, req.CDROMIso)
	}

	sess := MustSession(r)
	jobID := fmt.Sprintf("%d", time.Now().UnixNano())
	job := &lxdJob{Status: "running"}
	lxdJobs.Store(jobID, job)

	go func() {
		logCh := make(chan string, 64)
		go func() {
			for line := range logCh {
				job.mu.Lock()
				job.Lines = append(job.Lines, line)
				job.mu.Unlock()
			}
		}()
		err := system.LXDCreateVM(req, logCh)
		close(logCh)
		job.mu.Lock()
		if err != nil {
			job.Status = "error"
			job.Error = err.Error()
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDCreateVM, Target: req.Name, Result: audit.ResultError, Details: err.Error()})
		} else {
			job.Status = "done"
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDCreateVM, Target: req.Name, Result: audit.ResultOK})
		}
		job.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
}

// HandleCreateContainer starts async container creation and returns a job_id.
// POST /api/lxd/containers
func HandleCreateContainer(w http.ResponseWriter, r *http.Request) {
	var req system.LXDCreateContainerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || req.Image == "" {
		jsonErr(w, http.StatusBadRequest, "name and image are required")
		return
	}

	sess := MustSession(r)
	jobID := fmt.Sprintf("%d", time.Now().UnixNano())
	job := &lxdJob{Status: "running"}
	lxdJobs.Store(jobID, job)

	go func() {
		logCh := make(chan string, 64)
		go func() {
			for line := range logCh {
				job.mu.Lock()
				job.Lines = append(job.Lines, line)
				job.mu.Unlock()
			}
		}()
		err := system.LXDCreateContainer(req, logCh)
		close(logCh)
		job.mu.Lock()
		if err != nil {
			job.Status = "error"
			job.Error = err.Error()
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDCreateContainer, Target: req.Name, Result: audit.ResultError, Details: err.Error()})
		} else {
			job.Status = "done"
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDCreateContainer, Target: req.Name, Result: audit.ResultOK})
		}
		job.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
}

// HandleCreateComposeStack creates a Compose stack — an LXC container running
// Podman with the supplied docker-compose file deployed. Reuses the container
// create request shape; the base image comes from the ComposeBaseImage
// setting. Runs as a progress job, same as VM/container creation.
// POST /api/lxd/compose-stacks
func HandleCreateComposeStack(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDCreateContainerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.Name == "" {
			jsonErr(w, http.StatusBadRequest, "name is required")
			return
		}
		if strings.TrimSpace(req.ComposeYAML) == "" {
			jsonErr(w, http.StatusBadRequest, "docker-compose content is required")
			return
		}
		alias, distro := system.ComposeBaseImageAlias(appCfg.ComposeBaseImage)
		req.Image = alias

		sess := MustSession(r)
		jobID := fmt.Sprintf("%d", time.Now().UnixNano())
		job := &lxdJob{Status: "running"}
		lxdJobs.Store(jobID, job)

		go func() {
			logCh := make(chan string, 64)
			go func() {
				for line := range logCh {
					job.mu.Lock()
					job.Lines = append(job.Lines, line)
					job.mu.Unlock()
				}
			}()
			err := system.LXDCreateComposeStack(req, distro, req.ComposeYAML, req.ComposeEnv, logCh)
			close(logCh)
			job.mu.Lock()
			if err != nil {
				job.Status = "error"
				job.Error = err.Error()
			} else {
				job.Status = "done"
			}
			job.mu.Unlock()
			result, details := audit.ResultOK, ""
			if err != nil {
				result, details = audit.ResultError, err.Error()
			}
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDCreateContainer, Target: "compose:" + req.Name, Result: result, Details: details})
		}()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
	}
}

// HandleLXDCreateProgress returns job status + accumulated log lines.
// GET /api/lxd/create-progress?job_id=<id>
func HandleLXDCreateProgress(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("job_id")
	val, ok := lxdJobs.Load(id)
	if !ok {
		jsonErr(w, http.StatusNotFound, "job not found")
		return
	}
	job := val.(*lxdJob)
	job.mu.Lock()
	defer job.mu.Unlock()
	jsonOK(w, map[string]interface{}{
		"status": job.Status,
		"error":  job.Error,
		"lines":  job.Lines,
	})
}

// lxcRootHasPassword returns true when the container's root account has a
// real password hash in /etc/shadow (i.e. not locked with * or !).
func lxcRootHasPassword(name string) bool {
	out, err := exec.Command("incus", "exec", name, "--", "grep", "^root:", "/etc/shadow").Output()
	if err != nil {
		return false
	}
	// Shadow line: root:HASH:...
	parts := strings.SplitN(strings.TrimSpace(string(out)), ":", 3)
	if len(parts) < 2 {
		return false
	}
	hash := parts[1]
	return strings.HasPrefix(hash, "$") // real hashes start with $
}

var lxdConsoleUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		return strings.HasSuffix(origin, "://"+r.Host)
	},
}

// HandleLXDConsole opens a WebSocket attached to a persistent terminal
// session targeting an LXD/Incus instance. Same attach/detach contract as
// HandleTerminal — see handlers/terminal.go for the session lifecycle.
// WS /ws/lxd-console?name=<name>[&session_id=<id>]
func HandleLXDConsole(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	conn, err := lxdConsoleUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	sess := MustSession(r)
	wsAttachOrCreate(conn, r, sess.UserID, termsessions.KindLXD, name, name, func() (*exec.Cmd, *os.File, error) {
		var cmd *exec.Cmd
		if lxcRootHasPassword(name) {
			cmd = exec.Command("incus", "exec", name, "--", "login")
		} else {
			shell := "bash"
			if exec.Command("incus", "exec", name, "--", "which", "bash").Run() != nil {
				shell = "sh"
			}
			cmd = exec.Command("incus", "exec", name, "--", shell)
		}
		cmd.Env = append(os.Environ(), "TERM=xterm-256color")
		ptmx, err := pty.Start(cmd)
		return cmd, ptmx, err
	})
}

// ServeLXDConsolePage serves the full-page xterm.js console for an LXD instance.
// GET /lxd-console/{name}
func ServeLXDConsolePage(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if name == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprintf(w, lxdConsolePageHTML, name, name)
}

const lxdConsolePageHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Console — %s</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css">
<style>
* { margin:0; padding:0; box-sizing:border-box; }
html, body { width:100%%; height:100%%; background:#0d1117; overflow:hidden; }
#term { width:100%%; height:100%%; }
</style>
</head>
<body>
<div id="term"></div>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
<script>
const name = %q;
const term = new Terminal({ cursorBlink: true, fontSize: 14, theme: { background: '#0d1117' } });
const fitAddon = new FitAddon.FitAddon();
term.loadAddon(fitAddon);
term.open(document.getElementById('term'));
fitAddon.fit();

const proto = location.protocol === 'https:' ? 'wss' : 'ws';
const ws = new WebSocket(proto + '://' + location.host + '/ws/lxd-console?name=' + encodeURIComponent(name));
ws.binaryType = 'arraybuffer';

ws.onopen = () => {
  term.focus();
  ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
};
ws.onmessage = e => {
  if (e.data instanceof ArrayBuffer) term.write(new Uint8Array(e.data));
  else term.write(e.data);
};
ws.onclose = () => term.write('\r\n\x1b[31m[Connection closed]\x1b[0m\r\n');

term.onData(data => { if (ws.readyState === WebSocket.OPEN) ws.send(data); });

window.addEventListener('resize', () => {
  fitAddon.fit();
  if (ws.readyState === WebSocket.OPEN)
    ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
});
</script>
</body>
</html>`
