package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/keystore"
	"zfsnas/system"
)

// poolCreateJob tracks an async pool creation.
type poolCreateJob struct {
	mu     sync.Mutex
	Status string      `json:"status"` // "running" | "done" | "error"
	Pool   *system.Pool `json:"pool,omitempty"`
	Error  string      `json:"error,omitempty"`
}

var poolCreateJobs sync.Map // key: string job ID → *poolCreateJob

func HandleGetPools(w http.ResponseWriter, r *http.Request) {
	pools, err := system.GetAllPools()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pools == nil {
		pools = []*system.Pool{}
	}
	jsonOK(w, pools)
}

func HandleGetPool(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	var (
		pool *system.Pool
		err  error
	)
	if name != "" {
		pool, err = system.GetPoolByName(name)
	} else {
		pool, err = system.GetPool()
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, pool) // null if no pool
}

func HandleCreatePool(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		Layout      string   `json:"layout"`
		Ashift      int      `json:"ashift"`
		Compression string   `json:"compression"`
		Dedup       string   `json:"dedup"`
		Devices     []string `json:"devices"`
		Encrypted   bool     `json:"encrypted"`    // enable ZFS native encryption
		KeyFileID   string   `json:"key_file_id"`  // EncryptionKey.ID to use
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		jsonErr(w, http.StatusBadRequest, "pool name is required")
		return
	}
	if len(req.Devices) == 0 {
		jsonErr(w, http.StatusBadRequest, "at least one device is required")
		return
	}
	validLayouts := map[string]bool{"stripe": true, "mirror": true, "raidz1": true, "raidz2": true}
	if !validLayouts[req.Layout] {
		jsonErr(w, http.StatusBadRequest, "layout must be stripe, mirror, raidz1, or raidz2")
		return
	}
	validAshift := map[int]bool{9: true, 12: true, 13: true}
	if !validAshift[req.Ashift] {
		req.Ashift = 12
	}
	if req.Compression == "" {
		req.Compression = "lz4"
	}
	validDedup := map[string]bool{"off": true, "on": true, "verify": true}
	if !validDedup[req.Dedup] {
		req.Dedup = "off"
	}
	min := map[string]int{"stripe": 1, "mirror": 2, "raidz1": 3, "raidz2": 4}
	if len(req.Devices) < min[req.Layout] {
		jsonErr(w, http.StatusBadRequest,
			"not enough devices for "+req.Layout+" (need at least "+string(rune('0'+min[req.Layout]))+")")
		return
	}

	// Resolve encryption key file path.
	var keyFilePath string
	if req.Encrypted {
		req.KeyFileID = strings.TrimSpace(req.KeyFileID)
		if req.KeyFileID == "" {
			jsonErr(w, http.StatusBadRequest, "key_file_id is required when encrypted is true")
			return
		}
		keys, err := config.LoadEncryptionKeys()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to load encryption keys")
			return
		}
		var found bool
		for _, k := range keys {
			if k.ID == req.KeyFileID {
				found = true
				break
			}
		}
		if !found {
			jsonErr(w, http.StatusBadRequest, "encryption key not found")
			return
		}
		if !keystore.Exists(req.KeyFileID) {
			jsonErr(w, http.StatusBadRequest, "encryption key file missing from disk")
			return
		}
		keyFilePath = keystore.KeyFilePath(req.KeyFileID)
	}

	sess := MustSession(r)
	jobID := fmt.Sprintf("%d", time.Now().UnixNano())
	job := &poolCreateJob{Status: "running"}
	poolCreateJobs.Store(jobID, job)

	go func() {
		err := system.CreatePool(req.Name, req.Layout, req.Ashift, req.Compression, req.Dedup, req.Devices, keyFilePath)
		job.mu.Lock()
		defer job.mu.Unlock()
		if err != nil {
			job.Status = "error"
			job.Error = err.Error()
			audit.Log(audit.Entry{
				User: sess.Username, Role: sess.Role,
				Action: audit.ActionCreatePool, Target: req.Name, Result: audit.ResultError,
				Details: err.Error(),
			})
			return
		}
		diskCacheStale = true
		pool, _ := system.GetPoolByName(req.Name)
		job.Pool = pool
		job.Status = "done"
		encDetails := ""
		if req.Encrypted {
			encDetails = " encrypted=aes-256-gcm"
		}
		audit.Log(audit.Entry{
			User: sess.Username, Role: sess.Role,
			Action:  audit.ActionCreatePool,
			Target:  req.Name,
			Result:  audit.ResultOK,
			Details: req.Layout + " ashift=" + string(rune('0'+req.Ashift)) + " compression=" + req.Compression + " dedup=" + req.Dedup + encDetails,
		})
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
}

func HandlePoolCreateStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	val, ok := poolCreateJobs.Load(id)
	if !ok {
		jsonErr(w, http.StatusNotFound, "job not found")
		return
	}
	job := val.(*poolCreateJob)
	job.mu.Lock()
	defer job.mu.Unlock()
	jsonOK(w, job)
}

func HandleSetPoolProperties(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pool        string `json:"pool"`
		Compression string `json:"compression"`
		Dedup       string `json:"dedup"`
		Sync        string `json:"sync"`
		Atime       string `json:"atime"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Pool = strings.TrimSpace(req.Pool)
	var pool *system.Pool
	var err error
	if req.Pool != "" {
		pool, err = system.GetPoolByName(req.Pool)
	} else {
		pool, err = system.GetPool()
	}
	if err != nil || pool == nil {
		jsonErr(w, http.StatusBadRequest, "no pool available")
		return
	}

	valid := map[string]map[string]bool{
		"compression": {"off": true, "lz4": true, "zstd": true, "zstd-fast": true, "gzip": true},
		"dedup":       {"off": true, "on": true, "verify": true},
		"sync":        {"standard": true, "always": true, "disabled": true},
		"atime":       {"on": true, "off": true},
	}
	props := map[string]string{}
	if req.Compression != "" && valid["compression"][req.Compression] {
		props["compression"] = req.Compression
	}
	if req.Dedup != "" && valid["dedup"][req.Dedup] {
		props["dedup"] = req.Dedup
	}
	if req.Sync != "" && valid["sync"][req.Sync] {
		props["sync"] = req.Sync
	}
	if req.Atime != "" && valid["atime"][req.Atime] {
		props["atime"] = req.Atime
	}
	if len(props) == 0 {
		jsonErr(w, http.StatusBadRequest, "no valid properties to set")
		return
	}
	if err := system.SetPoolProperties(pool.Name, props); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	parts := make([]string, 0, len(props))
	for k, v := range props {
		parts = append(parts, k+"="+v)
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionUpdatePool,
		Target:  pool.Name,
		Result:  audit.ResultOK,
		Details: strings.Join(parts, " "),
	})

	updated, _ := system.GetPoolByName(pool.Name)
	jsonOK(w, updated)
}

func HandlePoolStatus(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	out, err := system.GetPoolStatusByName(name)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]string{"output": out})
}

func HandleGetZFSVersion(w http.ResponseWriter, r *http.Request) {
	major, minor, patch, err := system.GetZFSVersion()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	raidzExpand := major > 2 || (major == 2 && minor >= 2)
	jsonOK(w, map[string]interface{}{
		"version":      fmt.Sprintf("%d.%d.%d", major, minor, patch),
		"major":        major,
		"minor":        minor,
		"patch":        patch,
		"raidz_expand": raidzExpand,
	})
}

func HandleGrowPool(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pool    string   `json:"pool"`
		Devices []string `json:"devices"`
		Mode    string   `json:"mode"` // "expand" | "stripe" | "mirror" | "raidz1" | "raidz2"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Devices) == 0 {
		jsonErr(w, http.StatusBadRequest, "at least one device is required")
		return
	}

	// Validate minimum device counts per mode.
	minForMode := map[string]int{"expand": 1, "stripe": 1, "mirror": 2, "raidz1": 3, "raidz2": 4}
	if min, ok := minForMode[req.Mode]; ok && len(req.Devices) < min {
		jsonErr(w, http.StatusBadRequest, fmt.Sprintf("%s requires at least %d disk(s)", req.Mode, min))
		return
	}

	req.Pool = strings.TrimSpace(req.Pool)
	var pool *system.Pool
	var err error
	if req.Pool != "" {
		pool, err = system.GetPoolByName(req.Pool)
	} else {
		pool, err = system.GetPool()
	}
	if err != nil || pool == nil {
		jsonErr(w, http.StatusBadRequest, "no pool available")
		return
	}

	var growErr error
	switch req.Mode {
	case "expand":
		growErr = system.GrowPoolRaidz(pool.Name, req.Devices)
	case "mirror", "raidz1", "raidz2":
		growErr = system.GrowPoolWithVdev(pool.Name, req.Mode, req.Devices)
	default: // "stripe" or legacy empty
		growErr = system.GrowPool(pool.Name, req.Devices)
	}
	if growErr != nil {
		jsonErr(w, http.StatusInternalServerError, growErr.Error())
		return
	}
	diskCacheStale = true

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionGrowPool,
		Target:  pool.Name,
		Result:  audit.ResultOK,
		Details: fmt.Sprintf("mode=%s devices=%s", req.Mode, strings.Join(req.Devices, ", ")),
	})

	updated, _ := system.GetPoolByName(pool.Name)
	jsonOK(w, updated)
}

func HandleDestroyPool(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		jsonErr(w, http.StatusBadRequest, "pool name is required")
		return
	}

	pool, err := system.GetPoolByName(req.Name)
	if err != nil || pool == nil {
		jsonErr(w, http.StatusBadRequest, "pool not found")
		return
	}

	if err := system.DestroyPool(pool.Name); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionDestroyPool,
		Target: pool.Name,
		Result: audit.ResultOK,
	})

	jsonOK(w, map[string]string{"message": "pool destroyed"})
}

func HandleUpgradePool(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pool string `json:"pool"`
	}
	json.NewDecoder(r.Body).Decode(&req) // pool field is optional
	req.Pool = strings.TrimSpace(req.Pool)
	var pool *system.Pool
	var err error
	if req.Pool != "" {
		pool, err = system.GetPoolByName(req.Pool)
	} else {
		pool, err = system.GetPool()
	}
	if err != nil || pool == nil {
		jsonErr(w, http.StatusBadRequest, "no pool configured")
		return
	}
	if err := system.UpgradePool(pool.Name); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionUpgradePool,
		Target: pool.Name,
		Result: audit.ResultOK,
	})
	jsonOK(w, map[string]string{"message": "pool upgraded"})
}

func HandleAddPoolCache(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pool   string `json:"pool"`
		Device string `json:"device"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Device = strings.TrimSpace(req.Device)
	if req.Device == "" {
		jsonErr(w, http.StatusBadRequest, "device is required")
		return
	}
	req.Pool = strings.TrimSpace(req.Pool)
	var pool *system.Pool
	var err error
	if req.Pool != "" {
		pool, err = system.GetPoolByName(req.Pool)
	} else {
		pool, err = system.GetPool()
	}
	if err != nil || pool == nil {
		jsonErr(w, http.StatusBadRequest, "no pool available")
		return
	}
	if err := system.AddPoolCache(pool.Name, req.Device); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	diskCacheStale = true
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionGrowPool,
		Target:  pool.Name,
		Result:  audit.ResultOK,
		Details: "add cache " + req.Device,
	})
	updated, _ := system.GetPoolByName(pool.Name)
	jsonOK(w, updated)
}

func HandleRemovePoolCache(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pool   string `json:"pool"`
		Device string `json:"device"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Device = strings.TrimSpace(req.Device)
	if req.Device == "" {
		jsonErr(w, http.StatusBadRequest, "device is required")
		return
	}
	req.Pool = strings.TrimSpace(req.Pool)
	var pool *system.Pool
	var err error
	if req.Pool != "" {
		pool, err = system.GetPoolByName(req.Pool)
	} else {
		pool, err = system.GetPool()
	}
	if err != nil || pool == nil {
		jsonErr(w, http.StatusBadRequest, "no pool available")
		return
	}
	if err := system.RemovePoolCache(pool.Name, req.Device); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	diskCacheStale = true
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionGrowPool,
		Target:  pool.Name,
		Result:  audit.ResultOK,
		Details: "remove cache " + req.Device,
	})
	updated, _ := system.GetPoolByName(pool.Name)
	jsonOK(w, updated)
}

func HandleDetectPools(w http.ResponseWriter, r *http.Request) {
	pools, err := system.DetectImportablePools()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pools == nil {
		pools = []system.ImportablePool{}
	}
	jsonOK(w, pools)
}

func HandleImportPool(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string `json:"name"`
		Force bool   `json:"force"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		jsonErr(w, http.StatusBadRequest, "pool name is required")
		return
	}
	var importErr error
	if req.Force {
		importErr = system.ImportPoolForce(req.Name)
	} else {
		importErr = system.ImportPool(req.Name)
	}
	if importErr != nil {
		jsonErr(w, http.StatusInternalServerError, importErr.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionImportPool,
		Target: req.Name,
		Result: audit.ResultOK,
	})

	pool, _ := system.GetPoolByName(req.Name)
	jsonOK(w, pool)
}

// HandleClearPool runs `zpool clear` on the specified pool to clear errors and
// bring a SUSPENDED pool back online when its disks have recovered.
func HandleClearPool(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pool string `json:"pool"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Pool = strings.TrimSpace(req.Pool)
	if req.Pool == "" {
		jsonErr(w, http.StatusBadRequest, "pool is required")
		return
	}
	if err := system.ClearPool(req.Pool); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionImportPool,
		Target: req.Pool,
		Result: audit.ResultOK,
		Details: "zpool clear (pool fixer)",
	})
	pool, _ := system.GetPoolByName(req.Pool)
	LogPoolHealthEvents(pool)
	jsonOK(w, pool)
}

// HandlePoolFixerOnline handles the "bring offline disks back online" step of the Pool Fixer Wizard.
// The pool is SUSPENDED, so we must clear it first (resumes I/O), then bring the disks online.
func HandlePoolFixerOnline(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pool    string   `json:"pool"`
		Devices []string `json:"devices"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Pool = strings.TrimSpace(req.Pool)
	if req.Pool == "" || len(req.Devices) == 0 {
		jsonErr(w, http.StatusBadRequest, "pool and devices are required")
		return
	}
	// Step 1: clear the suspended state first — zpool online cannot run while I/O is suspended.
	if err := system.ClearPool(req.Pool); err != nil {
		jsonErr(w, http.StatusInternalServerError, "zpool clear failed: "+err.Error())
		return
	}
	// Step 2: bring the recovered disks back online.
	if err := system.OnlinePoolDisks(req.Pool, req.Devices); err != nil {
		jsonErr(w, http.StatusInternalServerError, "zpool online failed: "+err.Error())
		return
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionUpdatePool,
		Target:  req.Pool,
		Result:  audit.ResultOK,
		Details: "pool fixer: zpool clear; zpool online " + strings.Join(req.Devices, " "),
	})
	pool, _ := system.GetPoolByName(req.Pool)
	LogPoolHealthEvents(pool)
	jsonOK(w, pool)
}

func HandleDiskOffline(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pool   string `json:"pool"`
		Device string `json:"device"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Pool   = strings.TrimSpace(req.Pool)
	req.Device = strings.TrimSpace(req.Device)
	if req.Pool == "" || req.Device == "" {
		jsonErr(w, http.StatusBadRequest, "pool and device are required")
		return
	}
	if err := system.SetDiskOffline(req.Pool, req.Device); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionUpdatePool,
		Target:  req.Pool,
		Result:  audit.ResultOK,
		Details: "disk offline: " + req.Device,
	})
	pool, _ := system.GetPoolByName(req.Pool)
	jsonOK(w, pool)
}

func HandleDiskOnline(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pool   string `json:"pool"`
		Device string `json:"device"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Pool   = strings.TrimSpace(req.Pool)
	req.Device = strings.TrimSpace(req.Device)
	if req.Pool == "" || req.Device == "" {
		jsonErr(w, http.StatusBadRequest, "pool and device are required")
		return
	}
	if err := system.SetDiskOnline(req.Pool, req.Device); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionUpdatePool,
		Target:  req.Pool,
		Result:  audit.ResultOK,
		Details: "disk online: " + req.Device,
	})
	pool, _ := system.GetPoolByName(req.Pool)
	LogPoolHealthEvents(pool)
	jsonOK(w, pool)
}
