package handlers

// Datastore default + "Move contents" endpoints (6.11.26). See
// system/lxd_pool_evacuate.go for what the steps do.
//
//   GET  /api/incus/storage-pools/{name}/usage           what still uses it (Delete reasons)
//   POST /api/incus/storage-pools/{name}/set-default     default profile root → this pool
//   GET  /api/incus/storage-pools/{name}/evacuate-plan?target=…
//   POST /api/incus/storage-pools/{name}/evacuate        {target, restart} → {job_id}
//   GET  /api/incus/storage-evacuate/{id}/progress
//   POST /api/incus/storage-evacuate/{id}/cancel
//
// The job runs under context.Background() and is listed on the job board, so
// it survives the browser closing and an InterLink switch.

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

type dseJob struct {
	mu        sync.Mutex
	Status    string            `json:"status"` // running | done | error | canceled
	Error     string            `json:"error,omitempty"`
	Pool      string            `json:"pool"`
	Target    string            `json:"target"`
	Restart   bool              `json:"restart"`
	Steps     []system.EvacStep `json:"steps"`
	Lines     []string          `json:"lines"`
	StartedAt time.Time         `json:"started_at"`
	cancelFn  context.CancelFunc
}

var dseJobs sync.Map // id → *dseJob

func (j *dseJob) progressPct() float64 {
	if len(j.Steps) == 0 {
		return 0
	}
	n := 0
	for _, s := range j.Steps {
		if s.Status == "done" || s.Status == "skipped" {
			n++
		}
	}
	return float64(n) * 100 / float64(len(j.Steps))
}

// runningEvacuationFor returns the id of a running job touching pool (as
// source or target), so two moves never fight over the same datastore.
func runningEvacuationFor(pool string) string {
	found := ""
	dseJobs.Range(func(k, v interface{}) bool {
		j := v.(*dseJob)
		j.mu.Lock()
		busy := j.Status == "running" && (j.Pool == pool || j.Target == pool)
		j.mu.Unlock()
		if busy {
			found = k.(string)
			return false
		}
		return true
	})
	return found
}

func init() {
	system.RegisterJobProvider("ds-evacuate", func() []system.JobSummary {
		out := []system.JobSummary{}
		dseJobs.Range(func(k, v interface{}) bool {
			id := k.(string)
			j := v.(*dseJob)
			j.mu.Lock()
			defer j.mu.Unlock()
			base := "/api/incus/storage-evacuate/" + id
			out = append(out, system.JobSummary{
				Key: "dse-" + id, ID: id, Kind: "ds-evacuate",
				Label:       "Moving contents of " + j.Pool + " → " + j.Target,
				Status:      j.Status,
				Progress:    j.progressPct(),
				StartedAt:   j.StartedAt,
				ProgressURL: base + "/progress",
				CancelURL:   base + "/cancel",
				LocalOnly:   true,
			})
			return true
		})
		return out
	})
}

func poolNameFromReq(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := mux.Vars(r)["name"]
	if !system.ValidIncusPoolName(name) {
		jsonErr(w, http.StatusBadRequest, "invalid datastore name")
		return "", false
	}
	return name, true
}

// HandleStoragePoolUsage — GET /api/incus/storage-pools/{name}/usage
func HandleStoragePoolUsage(w http.ResponseWriter, r *http.Request) {
	name, ok := poolNameFromReq(w, r)
	if !ok {
		return
	}
	u, err := system.LXDPoolUsage(name)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{"usage": u, "is_default": system.LXDDefaultProfileRootPool() == name})
}

// HandleSetDefaultStoragePool — POST /api/incus/storage-pools/{name}/set-default
func HandleSetDefaultStoragePool(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	name, ok := poolNameFromReq(w, r)
	if !ok {
		return
	}
	prev := system.LXDDefaultProfileRootPool()
	if err := system.LXDSetDefaultStoragePool(name); err != nil {
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionIncusStorageDefault, Target: name, Result: audit.ResultError, Details: err.Error()})
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionIncusStorageDefault, Target: name, Result: audit.ResultOK, Details: "was " + prev})
	jsonOK(w, map[string]string{"ok": "default", "previous": prev})
}

// HandleEvacuatePlan — GET /api/incus/storage-pools/{name}/evacuate-plan?target=…
func HandleEvacuatePlan(w http.ResponseWriter, r *http.Request) {
	name, ok := poolNameFromReq(w, r)
	if !ok {
		return
	}
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	plan, err := system.LXDPoolEvacuationPlan(name, target)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]interface{}{"plan": plan}
	if t := target; t != "" && system.ValidIncusPoolName(t) {
		used, total, err := system.LXDPoolSpace(t)
		if err == nil {
			free := total - used
			resp["target_free"] = free
			resp["space_ok"] = total == 0 || plan.UsedBytes <= free
		}
	}
	if id := runningEvacuationFor(name); id != "" {
		resp["running_job"] = id
	}
	jsonOK(w, resp)
}

// HandleEvacuateStart — POST /api/incus/storage-pools/{name}/evacuate
func HandleEvacuateStart(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	name, ok := poolNameFromReq(w, r)
	if !ok {
		return
	}
	var req struct {
		Target  string `json:"target"`
		Restart *bool  `json:"restart"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	if !system.ValidIncusPoolName(req.Target) || req.Target == name {
		jsonErr(w, http.StatusBadRequest, "pick another datastore as the target")
		return
	}
	pools, err := system.LXDListStoragePools()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	found := false
	for _, p := range pools {
		found = found || p == req.Target
	}
	if !found {
		jsonErr(w, http.StatusBadRequest, "datastore "+req.Target+" does not exist")
		return
	}
	if id := runningEvacuationFor(name); id != "" {
		jsonErr(w, http.StatusConflict, "a move is already running for this datastore")
		return
	}
	if id := runningEvacuationFor(req.Target); id != "" {
		jsonErr(w, http.StatusConflict, "a move is already running for datastore "+req.Target)
		return
	}
	plan, err := system.LXDPoolEvacuationPlan(name, req.Target)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if plan.Blocked != "" {
		jsonErr(w, http.StatusConflict, plan.Blocked)
		return
	}
	if used, total, err := system.LXDPoolSpace(req.Target); err == nil && total > 0 && plan.UsedBytes > total-used {
		jsonErr(w, http.StatusConflict, fmt.Sprintf("not enough free space on %s (%s needed, %s free)",
			req.Target, fmtBytesIEC(uint64(plan.UsedBytes)), fmtBytesIEC(uint64(total-used))))
		return
	}
	restart := req.Restart == nil || *req.Restart

	id := fmt.Sprintf("%d", time.Now().UnixNano())
	ctx, cancel := context.WithCancel(context.Background())
	job := &dseJob{Status: "running", Pool: name, Target: req.Target, Restart: restart,
		Steps: plan.Steps, Lines: []string{}, StartedAt: time.Now(), cancelFn: cancel}
	dseJobs.Store(id, job)
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionIncusStorageEvacuate,
		Target: name + " → " + req.Target, Result: audit.ResultOK, Details: fmt.Sprintf("started, %d steps", len(plan.Steps))})

	go runEvacuation(ctx, job, sess.Username, sess.Role)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"job_id": id})
}

func runEvacuation(ctx context.Context, job *dseJob, user, role string) {
	logFn := func(s string) {
		job.mu.Lock()
		job.Lines = append(job.Lines, s)
		if len(job.Lines) > 2000 {
			job.Lines = job.Lines[len(job.Lines)-2000:]
		}
		job.mu.Unlock()
	}
	var failed error
	for i := range job.Steps {
		job.mu.Lock()
		if job.Status == "canceled" {
			job.mu.Unlock()
			break
		}
		job.Steps[i].Status = "running"
		st := job.Steps[i] // copy; the step reads only immutable fields
		job.mu.Unlock()

		logFn(fmt.Sprintf("── %s %s", st.Kind, st.Name))
		err := system.LXDPoolEvacuateStep(ctx, job.Pool, job.Target, &st, job.Restart, logFn)

		job.mu.Lock()
		if err != nil {
			job.Steps[i].Status = "error"
			job.Steps[i].Error = err.Error()
		} else {
			job.Steps[i].Status = "done"
		}
		job.mu.Unlock()
		if err != nil {
			failed = err
			logFn("  failed: " + err.Error())
			break
		}
	}
	if failed == nil {
		system.LXDRepointProfileVolumes(job.Pool, job.Target, logFn)
	}

	job.mu.Lock()
	for i := range job.Steps {
		if job.Steps[i].Status == "pending" {
			job.Steps[i].Status = "skipped"
		}
	}
	result, details := audit.ResultOK, "done"
	switch {
	case job.Status == "canceled":
		result, details = audit.ResultError, "canceled"
	case failed != nil:
		job.Status = "error"
		job.Error = failed.Error()
		result, details = audit.ResultError, failed.Error()
	default:
		job.Status = "done"
	}
	job.mu.Unlock()
	if failed == nil && details == "done" {
		logFn("All moved. The datastore is empty and can be deleted.")
	}
	audit.Log(audit.Entry{User: user, Role: role, Action: audit.ActionIncusStorageEvacuate,
		Target: job.Pool + " → " + job.Target, Result: result, Details: details})
}

func dseFromReq(w http.ResponseWriter, r *http.Request) *dseJob {
	v, ok := dseJobs.Load(mux.Vars(r)["id"])
	if !ok {
		jsonErr(w, http.StatusNotFound, "job not found")
		return nil
	}
	return v.(*dseJob)
}

// HandleEvacuateProgress — GET /api/incus/storage-evacuate/{id}/progress
func HandleEvacuateProgress(w http.ResponseWriter, r *http.Request) {
	j := dseFromReq(w, r)
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	jsonOK(w, map[string]interface{}{
		"status": j.Status, "error": j.Error, "pool": j.Pool, "target": j.Target,
		"steps": j.Steps, "lines": j.Lines, "progress": int(j.progressPct()),
	})
}

// HandleEvacuateCancel — POST /api/incus/storage-evacuate/{id}/cancel
// Stops after the current incus command is killed; that step puts its
// instances back (Incus rolls a partial copy back itself).
func HandleEvacuateCancel(w http.ResponseWriter, r *http.Request) {
	j := dseFromReq(w, r)
	if j == nil {
		return
	}
	j.mu.Lock()
	if j.Status == "running" {
		j.Status = "canceled"
		if j.cancelFn != nil {
			j.cancelFn()
		}
	}
	j.mu.Unlock()
	jsonOK(w, map[string]bool{"ok": true})
}
