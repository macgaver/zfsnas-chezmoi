package handlers

// extstorage.go — v6.7.7 External Storage + Filesystem rsync API.
//
//   GET    /api/extstorage                  list (secrets redacted, live state)
//   POST   /api/extstorage                  create
//   PUT    /api/extstorage/{id}             update
//   DELETE /api/extstorage/{id}             delete (unmounts + removes secrets)
//   POST   /api/extstorage/test             test connection (unsaved params ok)
//   POST   /api/extstorage/{id}/mount       ensure mounted (file-browser entry) + touch
//   POST   /api/extstorage/{id}/unmount     unmount (force=lazy on ?force=1)
//   PUT    /api/extstorage/{id}/rsync       set/replace/remove the rsync config
//   POST   /api/extstorage/{id}/rsync/run   manual run → {job_id}
//   GET    /api/extstorage/{id}/rsync/log   last full run log
//   GET    /api/extstorage/prereqs          helper-binary presence per type
//   POST   /api/extstorage/install          {type} → apt-get install helper pkg
//   GET    /api/rsync-jobs                  all jobs (activity-bar discovery)
//   GET    /api/rsync-jobs/{id}/progress    poller endpoint (_bgPollJob contract)
//   POST   /api/rsync-jobs/{id}/cancel
//
// Plain HTTP throughout → interlink relay forwards these to the viewed peer
// automatically (no WS forward-list entries needed).

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/scheduler"
	"zfsnas/system"
)

// extMu serializes every mutation of appCfg.ExternalStorages (handlers,
// scheduler ticker, job-finish callbacks all touch the slice).
var extMu sync.Mutex

func extFind(cfg *config.AppConfig, id string) *config.ExternalStorage {
	for i := range cfg.ExternalStorages {
		if cfg.ExternalStorages[i].ID == id {
			return &cfg.ExternalStorages[i]
		}
	}
	return nil
}

// extWire is the redacted list shape sent to the frontend.
type extWire struct {
	config.ExternalStorage
	Password    string `json:"password,omitempty"` // always emptied
	HasPassword bool   `json:"has_password"`
	Mounted     bool   `json:"mounted"`
	Mountpoint  string `json:"mountpoint"`
	RootToken   string `json:"root_token"` // file-browser root token for the mountpoint
	NextRun     string `json:"next_run,omitempty"`
	RunningJob  string `json:"running_job,omitempty"`
}

func extToWire(es config.ExternalStorage) extWire {
	w := extWire{ExternalStorage: es}
	w.HasPassword = es.Password != ""
	w.ExternalStorage.Password = ""
	w.Password = ""
	w.Mounted = system.ExtIsMounted(es.ID)
	w.Mountpoint = system.ExtMountpoint(es.ID)
	w.RootToken = base64.RawURLEncoding.EncodeToString([]byte(w.Mountpoint))
	// Keep the log out of the list payload — it's fetched on demand.
	w.ExternalStorage.LastSyncLog = ""
	if es.Rsync != nil && es.Rsync.Enabled && es.Rsync.Frequency != "" && es.Rsync.Frequency != "manual" {
		next := scheduler.NextRun(extSchedPolicy(es.Rsync), time.Now())
		if !next.IsZero() {
			w.NextRun = next.Format(time.RFC3339)
		}
	}
	for _, j := range system.RsyncJobs() {
		if j.StorageID == es.ID && j.Status == "running" {
			w.RunningJob = j.ID
			break
		}
	}
	return w
}

// ── Daily run window (v6.7.7) ───────────────────────────────────────────────

// parseHHMM parses "HH:MM"; ok=false for anything malformed.
func parseHHMM(s string) (h, m int, ok bool) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

func rsyncWindowConfigured(rc *config.RsyncConfig) bool {
	if rc == nil {
		return false
	}
	_, _, ok1 := parseHHMM(rc.WindowStart)
	_, _, ok2 := parseHHMM(rc.WindowEnd)
	return ok1 && ok2
}

// rsyncInWindow reports whether now falls inside the daily window. A window
// may wrap midnight (e.g. 22:00→06:00).
func rsyncInWindow(rc *config.RsyncConfig, now time.Time) bool {
	sh, sm, ok1 := parseHHMM(rc.WindowStart)
	eh, em, ok2 := parseHHMM(rc.WindowEnd)
	if !ok1 || !ok2 {
		return true // no valid window = always allowed
	}
	cur := now.Hour()*60 + now.Minute()
	start := sh*60 + sm
	end := eh*60 + em
	if start == end {
		return true // degenerate window = always
	}
	if start < end {
		return cur >= start && cur < end
	}
	// Wraps midnight.
	return cur >= start || cur < end
}

// rsyncNextWindowStart returns the next moment the window opens after now.
func rsyncNextWindowStart(rc *config.RsyncConfig, now time.Time) time.Time {
	sh, sm, ok := parseHHMM(rc.WindowStart)
	if !ok {
		return time.Time{}
	}
	t := time.Date(now.Year(), now.Month(), now.Day(), sh, sm, 0, 0, now.Location())
	if !t.After(now) {
		t = t.AddDate(0, 0, 1)
	}
	return t
}

// extPauseResumeAt computes when a paused sync should auto-resume: the next
// window opening when a window is configured, otherwise the next scheduled
// run; zero (manual resume only) for unscheduled, window-less syncs.
func extPauseResumeAt(rc *config.RsyncConfig, now time.Time) time.Time {
	if rsyncWindowConfigured(rc) {
		return rsyncNextWindowStart(rc, now)
	}
	if rc != nil && rc.Enabled && rc.Frequency != "" && rc.Frequency != "manual" {
		return scheduler.NextRun(extSchedPolicy(rc), now)
	}
	return time.Time{}
}

// extSchedPolicy maps an RsyncConfig onto a scheduler.Policy so IsDue/NextRun
// are reused unchanged.
func extSchedPolicy(rc *config.RsyncConfig) scheduler.Policy {
	return scheduler.Policy{
		Frequency:  rc.Frequency,
		Hour:       rc.Hour,
		Minute:     rc.Minute,
		Weekday:    rc.Weekday,
		DayOfMonth: rc.DayOfMonth,
	}
}

func extAudit(r *http.Request, action, target, details string) {
	user := ""
	if sess, _ := SessionFromRequest(r); sess != nil {
		user = sess.Username
	}
	audit.Log(audit.Entry{User: user, Action: action, Target: target,
		Result: audit.ResultOK, Details: details})
}

// extValidate normalizes + validates a storage submitted by the UI.
func extValidate(es *config.ExternalStorage) error {
	es.Name = strings.TrimSpace(es.Name)
	es.Host = strings.TrimSpace(es.Host)
	es.Share = strings.TrimSpace(es.Share)
	es.Username = strings.TrimSpace(es.Username)
	if es.Name == "" {
		return fmt.Errorf("name is required")
	}
	if es.Host == "" {
		return fmt.Errorf("host is required")
	}
	switch es.Type {
	case "smb":
		if es.Share == "" {
			return fmt.Errorf("share name is required")
		}
		if es.Username == "" {
			return fmt.Errorf("username is required")
		}
	case "nfs":
		if es.Share == "" {
			return fmt.Errorf("export path is required")
		}
	case "ftp", "ssh":
		if es.Username == "" {
			return fmt.Errorf("username is required")
		}
		es.MountMode = "ondemand" // fuse mounts are always on-demand
	default:
		return fmt.Errorf("invalid type %q", es.Type)
	}
	if es.MountMode != "persistent" {
		es.MountMode = "ondemand"
	}
	return nil
}

// extCreateReq / extUpdateReq carry an optional pasted SSH private key that is
// stored as a file, never in config.json.
type extStorageReq struct {
	config.ExternalStorage
	SSHPrivateKey string `json:"ssh_private_key,omitempty"`
}

// HandleExtStorageList — GET /api/extstorage
func HandleExtStorageList(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		extMu.Lock()
		defer extMu.Unlock()
		out := make([]extWire, 0, len(appCfg.ExternalStorages))
		for _, es := range appCfg.ExternalStorages {
			out = append(out, extToWire(es))
		}
		jsonOK(w, out)
	}
}

// HandleExtStorageCreate — POST /api/extstorage
func HandleExtStorageCreate(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req extStorageReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		es := req.ExternalStorage
		if err := extValidate(&es); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		es.ID = newID()
		es.Rsync = nil // sync is configured through its own endpoint
		es.LastSyncStatus, es.LastSyncError, es.LastSyncLog = "", "", ""
		if req.SSHPrivateKey != "" && es.Type == "ssh" {
			if err := system.WriteExtSSHKey(appCfg.ConfigDir, es.ID, req.SSHPrivateKey); err != nil {
				jsonErr(w, http.StatusInternalServerError, "store ssh key: "+err.Error())
				return
			}
			es.SSHKey = true
			es.Password = ""
		}
		extMu.Lock()
		appCfg.ExternalStorages = append(appCfg.ExternalStorages, es)
		err := config.SaveAppConfig(appCfg)
		extMu.Unlock()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "save config: "+err.Error())
			return
		}
		if es.MountMode == "persistent" {
			if merr := system.ExtMount(appCfg.ConfigDir, &es); merr != nil {
				// Saved fine — surface the mount problem without failing the create.
				extAudit(r, audit.ActionExtStorageCreate, es.Name, "created ("+es.Type+"); mount failed: "+merr.Error())
				jsonOK(w, map[string]interface{}{"ok": true, "id": es.ID, "mount_error": merr.Error()})
				return
			}
		}
		extAudit(r, audit.ActionExtStorageCreate, es.Name, "created external storage ("+es.Type+"://"+es.Host+")")
		jsonOK(w, map[string]interface{}{"ok": true, "id": es.ID})
	}
}

// HandleExtStorageUpdate — PUT /api/extstorage/{id}
func HandleExtStorageUpdate(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		var req extStorageReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		in := req.ExternalStorage
		if err := extValidate(&in); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		extMu.Lock()
		es := extFind(appCfg, id)
		if es == nil {
			extMu.Unlock()
			jsonErr(w, http.StatusNotFound, "storage not found")
			return
		}
		wasMounted := system.ExtIsMounted(id)
		// Empty password on update = keep the stored one.
		if in.Password == "" {
			in.Password = es.Password
		}
		if req.SSHPrivateKey != "" && in.Type == "ssh" {
			if err := system.WriteExtSSHKey(appCfg.ConfigDir, id, req.SSHPrivateKey); err != nil {
				extMu.Unlock()
				jsonErr(w, http.StatusInternalServerError, "store ssh key: "+err.Error())
				return
			}
			in.SSHKey = true
		} else if in.Type == "ssh" && es.SSHKey && !in.SSHKey {
			// Explicitly switched back to password auth.
			system.RemoveExtSecrets(appCfg.ConfigDir, id)
		} else {
			in.SSHKey = es.SSHKey && in.Type == "ssh"
		}
		// Immutable / server-owned fields.
		in.ID = es.ID
		in.Rsync = es.Rsync
		in.LastSyncTime, in.LastSyncStatus = es.LastSyncTime, es.LastSyncStatus
		in.LastSyncError, in.LastSyncLog = es.LastSyncError, es.LastSyncLog
		in.LastSyncBytes, in.LastSyncSeconds = es.LastSyncBytes, es.LastSyncSeconds
		*es = in
		err := config.SaveAppConfig(appCfg)
		esCopy := *es
		extMu.Unlock()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "save config: "+err.Error())
			return
		}
		// Remount so edited endpoint/credentials take effect.
		if wasMounted {
			_ = system.ExtUnmount(id, true)
		}
		var mountErr string
		if esCopy.MountMode == "persistent" {
			if merr := system.ExtMount(appCfg.ConfigDir, &esCopy); merr != nil {
				mountErr = merr.Error()
			}
		}
		extAudit(r, audit.ActionExtStorageUpdate, esCopy.Name, "updated external storage")
		resp := map[string]interface{}{"ok": true}
		if mountErr != "" {
			resp["mount_error"] = mountErr
		}
		jsonOK(w, resp)
	}
}

// HandleExtStorageDelete — DELETE /api/extstorage/{id}
func HandleExtStorageDelete(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		if system.RsyncActiveForStorage(id) {
			jsonErr(w, http.StatusConflict, "a sync is currently running for this storage")
			return
		}
		_ = system.ExtUnmount(id, true)
		extMu.Lock()
		name := ""
		kept := appCfg.ExternalStorages[:0]
		for _, es := range appCfg.ExternalStorages {
			if es.ID == id {
				name = es.Name
				continue
			}
			kept = append(kept, es)
		}
		appCfg.ExternalStorages = kept
		err := config.SaveAppConfig(appCfg)
		extMu.Unlock()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "save config: "+err.Error())
			return
		}
		system.RemoveExtSecrets(appCfg.ConfigDir, id)
		extAudit(r, audit.ActionExtStorageDelete, name, "deleted external storage")
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleExtStorageTest — POST /api/extstorage/test
// Accepts either a full parameter set (unsaved form) or {"id": "..."} plus
// overrides; an omitted password falls back to the stored one so testing an
// existing storage doesn't require retyping it.
func HandleExtStorageTest(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req extStorageReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		es := req.ExternalStorage
		if es.ID != "" {
			extMu.Lock()
			if stored := extFind(appCfg, es.ID); stored != nil {
				if es.Password == "" {
					es.Password = stored.Password
				}
				if es.Type == "ssh" && stored.SSHKey && req.SSHPrivateKey == "" {
					es.SSHKey = true
				}
			}
			extMu.Unlock()
		}
		if err := extValidate(&es); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// Unsaved SSH-key test: park the key under a probe id.
		if req.SSHPrivateKey != "" && es.Type == "ssh" {
			probeID := es.ID
			if probeID == "" {
				probeID = "probe"
			}
			if err := system.WriteExtSSHKey(appCfg.ConfigDir, probeID, req.SSHPrivateKey); err != nil {
				jsonErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			es.ID = probeID
			es.SSHKey = true
		}
		entries, err := system.ExtTestConnection(appCfg.ConfigDir, &es)
		if err != nil {
			jsonOK(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		jsonOK(w, map[string]interface{}{"ok": true, "entries": entries})
	}
}

// HandleExtStorageMount — POST /api/extstorage/{id}/mount
// The file browser's entry point: ensures the mount exists, bumps the idle
// timer, and returns the root token to open the browser at.
func HandleExtStorageMount(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		extMu.Lock()
		es := extFind(appCfg, id)
		var esCopy config.ExternalStorage
		if es != nil {
			esCopy = *es
		}
		extMu.Unlock()
		if es == nil {
			jsonErr(w, http.StatusNotFound, "storage not found")
			return
		}
		if err := system.ExtMount(appCfg.ConfigDir, &esCopy); err != nil {
			jsonErr(w, http.StatusBadGateway, err.Error())
			return
		}
		mp := system.ExtMountpoint(id)
		jsonOK(w, map[string]interface{}{
			"ok":         true,
			"mountpoint": mp,
			"root_token": base64.RawURLEncoding.EncodeToString([]byte(mp)),
			"label":      "Ext: " + esCopy.Name,
		})
	}
}

// HandleExtStorageBrowse — GET /api/extstorage/{id}/browse
// Mounts the storage if needed and returns its directories up to 2 levels
// deep (relative to the share root). Feeds the sync modal's remote-path
// folder picker.
func HandleExtStorageBrowse(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		extMu.Lock()
		es := extFind(appCfg, id)
		var esCopy config.ExternalStorage
		if es != nil {
			esCopy = *es
		}
		extMu.Unlock()
		if es == nil {
			jsonErr(w, http.StatusNotFound, "storage not found")
			return
		}
		dirs, err := system.ExtListDirs(appCfg.ConfigDir, &esCopy, 2, 400)
		if err != nil {
			jsonErr(w, http.StatusBadGateway, err.Error())
			return
		}
		jsonOK(w, map[string]interface{}{"dirs": dirs})
	}
}

// HandleExtStorageUnmount — POST /api/extstorage/{id}/unmount
func HandleExtStorageUnmount(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		if system.RsyncActiveForStorage(id) {
			jsonErr(w, http.StatusConflict, "a sync is currently running for this storage")
			return
		}
		force := r.URL.Query().Get("force") == "1"
		if err := system.ExtUnmount(id, force); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleExtStorageSetRsync — PUT /api/extstorage/{id}/rsync
// Body: RsyncConfig, or {"remove": true} to unconfigure.
func HandleExtStorageSetRsync(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		var req struct {
			config.RsyncConfig
			Remove bool `json:"remove,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		extMu.Lock()
		defer extMu.Unlock()
		es := extFind(appCfg, id)
		if es == nil {
			jsonErr(w, http.StatusNotFound, "storage not found")
			return
		}
		if req.Remove {
			es.Rsync = nil
			es.SyncPaused, es.SyncPauseReason, es.SyncResumeAt = false, "", time.Time{}
			if es.LastSyncStatus == "paused" {
				es.LastSyncStatus = ""
			}
		} else {
			rc := req.RsyncConfig
			if rc.Direction != "pull" && rc.Direction != "push" {
				jsonErr(w, http.StatusBadRequest, "direction must be pull or push")
				return
			}
			if rc.LocalPath == "" || !strings.HasPrefix(rc.LocalPath, "/") {
				jsonErr(w, http.StatusBadRequest, "local path must be an absolute path")
				return
			}
			if rc.MaxDelete < 0 {
				rc.MaxDelete = 0
			}
			if !rc.Delete {
				rc.MaxDelete = 0 // only meaningful with mirror deletions
			}
			switch rc.Frequency {
			case "manual", "hourly", "daily", "weekly", "monthly":
			default:
				jsonErr(w, http.StatusBadRequest, "invalid frequency")
				return
			}
			// Daily window: both bounds or neither, valid HH:MM.
			rc.WindowStart = strings.TrimSpace(rc.WindowStart)
			rc.WindowEnd = strings.TrimSpace(rc.WindowEnd)
			if (rc.WindowStart == "") != (rc.WindowEnd == "") {
				jsonErr(w, http.StatusBadRequest, "time window needs both a start and an end time")
				return
			}
			if rc.WindowStart != "" {
				if _, _, ok := parseHHMM(rc.WindowStart); !ok {
					jsonErr(w, http.StatusBadRequest, "invalid window start time (use HH:MM)")
					return
				}
				if _, _, ok := parseHHMM(rc.WindowEnd); !ok {
					jsonErr(w, http.StatusBadRequest, "invalid window end time (use HH:MM)")
					return
				}
			}
			es.Rsync = &rc
			// Window removed/changed — recompute or drop a stale pause marker.
			if es.SyncPaused && es.SyncPauseReason == "window" {
				if rsyncWindowConfigured(&rc) {
					es.SyncResumeAt = rsyncNextWindowStart(&rc, time.Now())
				} else {
					es.SyncPaused, es.SyncPauseReason, es.SyncResumeAt = false, "", time.Time{}
					if es.LastSyncStatus == "paused" {
						es.LastSyncStatus = ""
					}
				}
			}
		}
		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, "save config: "+err.Error())
			return
		}
		extAudit(r, audit.ActionExtStorageUpdate, es.Name, "rsync configuration updated")
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleExtStorageRunRsync — POST /api/extstorage/{id}/rsync/run
func HandleExtStorageRunRsync(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		extMu.Lock()
		es := extFind(appCfg, id)
		var esCopy config.ExternalStorage
		if es != nil {
			esCopy = *es
		}
		extMu.Unlock()
		if es == nil {
			jsonErr(w, http.StatusNotFound, "storage not found")
			return
		}
		if esCopy.Rsync == nil {
			jsonErr(w, http.StatusBadRequest, "rsync is not configured for this storage")
			return
		}
		job, err := system.StartRsyncJob(appCfg.ConfigDir, &esCopy, func(j *system.RsyncJob) {
			extFinishRsync(appCfg, j)
		})
		if err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// A manual Run is also the "force resume now" action for a paused
		// sync — clear the pause marker so the UI stops showing it.
		extMu.Lock()
		if live := extFind(appCfg, id); live != nil && live.SyncPaused {
			live.SyncPaused, live.SyncPauseReason, live.SyncResumeAt = false, "", time.Time{}
			_ = config.SaveAppConfig(appCfg)
		}
		extMu.Unlock()
		extAudit(r, audit.ActionRsyncRun, esCopy.Name, "manual rsync "+esCopy.Rsync.Direction+" started")
		jsonOK(w, map[string]interface{}{"ok": true, "job_id": job.ID})
	}
}

// extFinishRsync persists a finished job's outcome onto its storage record
// and fires failure alerts. Runs in the job goroutine.
func extFinishRsync(appCfg *config.AppConfig, j *system.RsyncJob) {
	snap := j.Snapshot()
	lines, _ := snap["lines"].([]string)
	extMu.Lock()
	es := extFind(appCfg, j.StorageID)
	if es != nil {
		es.LastSyncTime = j.StartedAt
		es.LastSyncSeconds = int(j.FinishedAt.Sub(j.StartedAt).Seconds())
		es.LastSyncBytes = j.Bytes
		es.LastSyncLog = strings.Join(lines, "\n")
		switch j.Status {
		case "done":
			es.LastSyncStatus = "ok"
			es.LastSyncError = ""
			es.SyncPaused, es.SyncPauseReason, es.SyncResumeAt = false, "", time.Time{}
		case "paused":
			// Interrupted-but-resumable: window closed or the user stopped
			// it. The scheduler restarts it at SyncResumeAt (zero = manual).
			es.LastSyncStatus = "paused"
			es.LastSyncError = ""
			es.SyncPaused = true
			es.SyncPauseReason = j.PausedBy
			es.SyncResumeAt = extPauseResumeAt(es.Rsync, time.Now())
		case "canceled":
			es.LastSyncStatus = "error"
			es.LastSyncError = "canceled by user"
		default:
			es.LastSyncStatus = "error"
			es.LastSyncError = j.Error
			es.SyncPaused, es.SyncPauseReason, es.SyncResumeAt = false, "", time.Time{}
		}
		_ = config.SaveAppConfig(appCfg)
	}
	extMu.Unlock()

	result := audit.ResultOK
	details := fmt.Sprintf("rsync %s finished: %s", j.Direction, j.Status)
	if j.Status == "paused" {
		details = fmt.Sprintf("rsync %s paused (%s) — will resume automatically", j.Direction, j.PausedBy)
	} else if j.Status != "done" {
		result = audit.ResultError
		details += " — " + j.Error
	}
	audit.Log(audit.Entry{Action: audit.ActionRsyncRun, Target: j.StorageName,
		Result: result, Details: details})
	if j.Status == "error" {
		go alerts.Send(
			alerts.EventReplicationFailure,
			"rsync failed: "+j.StorageName,
			"Filesystem rsync Failed",
			fmt.Sprintf("rsync %s for external storage '%s' failed: %s",
				j.Direction, j.StorageName, j.Error),
		)
	}
}

// HandleExtStorageRsyncLog — GET /api/extstorage/{id}/rsync/log
func HandleExtStorageRsyncLog(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		extMu.Lock()
		defer extMu.Unlock()
		es := extFind(appCfg, id)
		if es == nil {
			jsonErr(w, http.StatusNotFound, "storage not found")
			return
		}
		jsonOK(w, map[string]interface{}{
			"log":    es.LastSyncLog,
			"status": es.LastSyncStatus,
			"error":  es.LastSyncError,
			"time":   es.LastSyncTime,
			"bytes":  es.LastSyncBytes,
			"secs":   es.LastSyncSeconds,
		})
	}
}

// HandleExtStoragePrereqs — GET /api/extstorage/prereqs
func HandleExtStoragePrereqs(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, system.ExtStoragePrereqs())
}

// HandleExtStorageInstall — POST /api/extstorage/install  body: {"type": "smb"}
func HandleExtStorageInstall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	out, err := system.ExtInstallPackage(req.Type)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error()+"\n"+out)
		return
	}
	extAudit(r, audit.ActionInstallPrereqs, system.ExtPackageForType(req.Type), "installed for external storage")
	jsonOK(w, map[string]bool{"ok": true})
}

// HandleRsyncJobs — GET /api/rsync-jobs
func HandleRsyncJobs(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, localRsyncJobSnapshots())
}

func localRsyncJobSnapshots() []map[string]interface{} {
	hostname, _ := os.Hostname()
	jobs := system.RsyncJobs()
	out := make([]map[string]interface{}, 0, len(jobs))
	for _, j := range jobs {
		s := j.Snapshot()
		delete(s, "lines") // keep the discovery payload small
		s["system"] = hostname
		out = append(out, s)
	}
	return out
}

// HandleRsyncJobsAggregate — GET /api/rsync-jobs/aggregate
// Local rsync jobs merged with every interlink peer's, each stamped with the
// originating hostname. Lets any server's UI show fleet-wide background jobs
// (the activity bar renders these with a host chip in All-Servers mode), so
// a job never "disappears" just because the user is viewing another server.
func HandleRsyncJobsAggregate(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all := localRsyncJobSnapshots()
		var (
			mu sync.Mutex
			wg sync.WaitGroup
		)
		for i := range appCfg.InterLink {
			ls := appCfg.InterLink[i]
			if ls.URL == "" || ls.LinkedBy == "" {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				remote, err := fetchPeerRsyncJobs(ls)
				if err != nil {
					return
				}
				for j := range remote {
					if remote[j]["system"] == nil || remote[j]["system"] == "" {
						remote[j]["system"] = ls.Hostname
					}
				}
				mu.Lock()
				all = append(all, remote...)
				mu.Unlock()
			}()
		}
		wg.Wait()
		jsonOK(w, all)
	}
}

// fetchPeerRsyncJobs dials a peer's /api/rsync-jobs with the standard
// X-Interlink-Relay-* HMAC headers (same pattern as fetchPeerLiveAlerts).
func fetchPeerRsyncJobs(ls config.LinkedServer) ([]map[string]interface{}, error) {
	ts := time.Now().Unix()
	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonceHex := hex.EncodeToString(nonceBytes)
	sig := system.RelayForwardHMAC(ls.SharedSecret, ls.LinkedBy, ts, nonceHex)

	req, err := http.NewRequest("GET", strings.TrimRight(ls.URL, "/")+"/api/rsync-jobs", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Interlink-Relay-User", ls.LinkedBy)
	req.Header.Set("X-Interlink-Relay-TS", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Interlink-Relay-Nonce", nonceHex)
	req.Header.Set("X-Interlink-Relay-HMAC", sig)

	client := system.InterlinkClientForRelay(ls.TLSFingerprint)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var out []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// HandleRsyncJobProgress — GET /api/rsync-jobs/{id}/progress
// Response follows the shared _bgPollJob contract: {lines, status, error,
// progress}, with status mapped running|done|error|canceled.
func HandleRsyncJobProgress(w http.ResponseWriter, r *http.Request) {
	j := system.RsyncJobByID(mux.Vars(r)["id"])
	if j == nil {
		jsonErr(w, http.StatusNotFound, "job not found")
		return
	}
	jsonOK(w, j.Snapshot())
}

// HandleRsyncJobCancel — POST /api/rsync-jobs/{id}/cancel
// A user stop is a PAUSE, not a failure: rsync --partial keeps the partial
// transfer, the storage records "paused by user" with an auto-resume time
// (next window opening / next scheduled run), and the ▶ Run button forces an
// immediate resume.
func HandleRsyncJobCancel(w http.ResponseWriter, r *http.Request) {
	j := system.RsyncJobByID(mux.Vars(r)["id"])
	if j == nil {
		jsonErr(w, http.StatusNotFound, "job not found")
		return
	}
	j.Pause("user")
	jsonOK(w, map[string]bool{"ok": true})
}

// ExtStoragesSnapshot returns a locked copy of the storage list — shared by
// the mount janitor and the file-browser known-roots provider.
func ExtStoragesSnapshot(appCfg *config.AppConfig) []config.ExternalStorage {
	extMu.Lock()
	defer extMu.Unlock()
	out := make([]config.ExternalStorage, len(appCfg.ExternalStorages))
	copy(out, appCfg.ExternalStorages)
	return out
}

// StartRsyncScheduler fires due rsync jobs once a minute and starts the
// on-demand mount janitor. Called from main.go.
func StartRsyncScheduler(appCfg *config.AppConfig) {
	system.SetExtStorageSource(func() []config.ExternalStorage {
		return ExtStoragesSnapshot(appCfg)
	})
	system.StartExtMountJanitor(
		func() []config.ExternalStorage { return ExtStoragesSnapshot(appCfg) },
		system.RsyncActiveForStorage,
	)
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for now := range tick.C {
			// 1) Window enforcement — pause any running sync whose daily
			//    window just closed. It auto-resumes at the next opening.
			for _, j := range system.RsyncJobs() {
				if j.Status != "running" {
					continue
				}
				extMu.Lock()
				es := extFind(appCfg, j.StorageID)
				var rc *config.RsyncConfig
				if es != nil {
					rc = es.Rsync
				}
				extMu.Unlock()
				if rc != nil && rsyncWindowConfigured(rc) && !rsyncInWindow(rc, now) {
					log.Printf("[rsync-scheduler] %s: window closed — pausing (resumes %s)",
						j.StorageName, rsyncNextWindowStart(rc, now).Format("Mon 15:04"))
					j.Pause("window") // extFinishRsync records the paused state
				}
			}

			// 2) Collect work under the lock: auto-resumes + due schedule fires.
			extMu.Lock()
			start := []config.ExternalStorage{}
			changed := false
			for i := range appCfg.ExternalStorages {
				es := &appCfg.ExternalStorages[i]
				rc := es.Rsync
				if rc == nil {
					continue
				}
				// Auto-resume a paused sync when its resume time arrives.
				if es.SyncPaused && !es.SyncResumeAt.IsZero() && !now.Before(es.SyncResumeAt) {
					start = append(start, *es)
					continue
				}
				if !rc.Enabled || rc.Frequency == "" || rc.Frequency == "manual" {
					continue
				}
				if !scheduler.IsDue(extSchedPolicy(rc), now) {
					continue
				}
				if rsyncWindowConfigured(rc) && !rsyncInWindow(rc, now) {
					// Scheduled start outside the window — defer to the next
					// opening instead of running now.
					if !es.SyncPaused {
						es.SyncPaused = true
						es.SyncPauseReason = "window"
						es.SyncResumeAt = rsyncNextWindowStart(rc, now)
						es.LastSyncStatus = "paused"
						es.LastSyncError = ""
						changed = true
					}
					continue
				}
				start = append(start, *es)
			}
			if changed {
				_ = config.SaveAppConfig(appCfg)
			}
			extMu.Unlock()

			// 3) Start/resume outside the lock.
			for i := range start {
				es := start[i]
				if system.RsyncActiveForStorage(es.ID) {
					continue // previous run still going — skip this slot
				}
				if _, err := system.StartRsyncJob(appCfg.ConfigDir, &es, func(j *system.RsyncJob) {
					extFinishRsync(appCfg, j)
				}); err != nil {
					log.Printf("[rsync-scheduler] %s: %v", es.Name, err)
					extMu.Lock()
					if live := extFind(appCfg, es.ID); live != nil {
						live.LastSyncTime = now
						live.LastSyncStatus = "error"
						live.LastSyncError = err.Error()
						live.SyncPaused, live.SyncPauseReason, live.SyncResumeAt = false, "", time.Time{}
						_ = config.SaveAppConfig(appCfg)
					}
					extMu.Unlock()
					go alerts.Send(
						alerts.EventReplicationFailure,
						"rsync failed: "+es.Name,
						"Filesystem rsync Failed",
						fmt.Sprintf("Scheduled rsync for external storage '%s' could not start: %v", es.Name, err),
					)
				} else {
					// Started — clear any pause marker (this was the resume).
					extMu.Lock()
					if live := extFind(appCfg, es.ID); live != nil && live.SyncPaused {
						live.SyncPaused, live.SyncPauseReason, live.SyncResumeAt = false, "", time.Time{}
						_ = config.SaveAppConfig(appCfg)
					}
					extMu.Unlock()
				}
			}
		}
	}()
}
