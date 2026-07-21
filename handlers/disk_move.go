package handlers

// Per-disk move job (v6.5.37).
//
// Mirrors the proxmox_import.go pattern: an in-memory job map indexed by
// job_id, with start / progress / cancel endpoints. Each job runs in its
// own goroutine, accumulates log lines for the modal terminal, and is
// cancellable via context.CancelFunc so the activity-bar cancel button can SIGKILL
// the underlying `incus` process. State is intentionally in-memory only
// — same caveat as the Proxmox importer: a zfsnas restart kills the
// transfer (Incus rolls back any partial volume copy itself).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"zfsnas/internal/audit"
	"zfsnas/system"
)

type dmvJob struct {
	mu       sync.Mutex
	Status   string   `json:"status"` // "queued" | "running" | "done" | "error" | "canceled"
	Error    string   `json:"error,omitempty"`
	Lines    []string `json:"lines"`
	Instance string   `json:"instance"`
	DiskName string   `json:"disk_name"`
	Target   string   `json:"target_pool"`
	cancelFn context.CancelFunc
}

func (j *dmvJob) cancel() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.Status == "queued" || j.Status == "running" {
		j.Status = "canceled"
		if j.cancelFn != nil {
			j.cancelFn()
		}
	}
}

var dmvJobs sync.Map // job_id → *dmvJob

// HandleDiskMoveStart kicks off an async per-disk move.
// POST /api/incus/instances/{name}/disk-move/start
// Body: { "disk_name": "...", "target_pool": "..." }
// Response: { "job_id": "..." }
//
// Refuses to start if the instance is currently running — moves of
// attached storage are stop-only on Incus 6.0.5 and would silently fail
// halfway through otherwise. The frontend greys the menu in the same
// case; this is the server-side belt-and-suspenders.
func HandleDiskMoveStart(w http.ResponseWriter, r *http.Request) {
	instance := mux.Vars(r)["name"]
	var req struct {
		DiskName   string `json:"disk_name"`
		TargetPool string `json:"target_pool"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.DiskName = strings.TrimSpace(req.DiskName)
	req.TargetPool = strings.TrimSpace(req.TargetPool)
	if req.DiskName == "" || req.TargetPool == "" {
		jsonErr(w, http.StatusBadRequest, "disk_name and target_pool are required")
		return
	}

	status, err := system.LXDGetStatus(instance)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "lookup instance status: "+err.Error())
		return
	}
	if !strings.EqualFold(status, "Stopped") {
		jsonErr(w, http.StatusConflict, "instance must be stopped before moving a disk (current status: "+status+")")
		return
	}

	// Validate that the disk exists and that the target differs from
	// current — surface a friendly error rather than letting `incus` shell
	// out and report a cryptic one.
	ref, err := system.LookupInstanceDisk(instance, req.DiskName)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if ref.Pool == req.TargetPool {
		jsonErr(w, http.StatusBadRequest, "disk is already on pool "+req.TargetPool)
		return
	}

	sess := MustSession(r)
	jobID := fmt.Sprintf("dmv-%d", time.Now().UnixNano())
	ctx, cancelFn := context.WithCancel(context.Background())
	job := &dmvJob{
		Status:   "running",
		Instance: instance,
		DiskName: req.DiskName,
		Target:   req.TargetPool,
		cancelFn: cancelFn,
	}
	dmvJobs.Store(jobID, job)

	go func() {
		logFn := func(line string) {
			job.mu.Lock()
			job.Lines = append(job.Lines, line)
			job.mu.Unlock()
		}
		err := system.LXDMoveInstanceDisk(ctx, instance, req.DiskName, req.TargetPool, logFn)

		job.mu.Lock()
		result := audit.ResultOK
		details := ""
		if err != nil {
			// A canceled context is the user cancelling, not a failure.
			// Preserve job.Status = "canceled" (already set by cancel())
			// rather than overwriting with "error".
			if job.Status != "canceled" {
				job.Status = "error"
				job.Error = err.Error()
			}
			result = audit.ResultError
			details = err.Error()
		} else {
			job.Status = "done"
		}
		job.mu.Unlock()

		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionIncusDiskMove,
			Target:  instance + ":" + req.DiskName + " → " + req.TargetPool,
			Result:  result,
			Details: details,
		})
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
}

// HandleDiskMoveProgress returns the accumulated log lines + status.
// GET /api/incus/instances/{name}/disk-move/progress?job_id=<id>
func HandleDiskMoveProgress(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("job_id")
	val, ok := dmvJobs.Load(id)
	if !ok {
		jsonErr(w, http.StatusNotFound, "job not found")
		return
	}
	job := val.(*dmvJob)
	job.mu.Lock()
	defer job.mu.Unlock()
	jsonOK(w, map[string]interface{}{
		"status":      job.Status,
		"error":       job.Error,
		"lines":       job.Lines,
		"instance":    job.Instance,
		"disk_name":   job.DiskName,
		"target_pool": job.Target,
	})
}

// HandleDiskMoveCancel kills the underlying `incus` process by canceling
// the job's context. Idempotent — re-cancel of a completed job is a no-op.
// POST /api/incus/instances/{name}/disk-move/cancel?job_id=<id>
func HandleDiskMoveCancel(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("job_id")
	val, ok := dmvJobs.Load(id)
	if !ok {
		jsonErr(w, http.StatusNotFound, "job not found")
		return
	}
	val.(*dmvJob).cancel()
	jsonOK(w, map[string]bool{"ok": true})
}
