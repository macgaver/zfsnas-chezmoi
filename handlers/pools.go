package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"zfsnas/internal/audit"
	"zfsnas/system"
)

func HandleGetPool(w http.ResponseWriter, r *http.Request) {
	pool, err := system.GetPool()
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
		Devices     []string `json:"devices"`
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
	validLayouts := map[string]bool{"stripe": true, "raidz1": true, "raidz2": true}
	if !validLayouts[req.Layout] {
		jsonErr(w, http.StatusBadRequest, "layout must be stripe, raidz1, or raidz2")
		return
	}
	validAshift := map[int]bool{9: true, 12: true, 13: true}
	if !validAshift[req.Ashift] {
		req.Ashift = 12 // default to 4K
	}
	if req.Compression == "" {
		req.Compression = "lz4"
	}

	// Validate minimum device count for layouts.
	min := map[string]int{"stripe": 1, "raidz1": 3, "raidz2": 4}
	if len(req.Devices) < min[req.Layout] {
		jsonErr(w, http.StatusBadRequest,
			"not enough devices for "+req.Layout+" (need at least "+string(rune('0'+min[req.Layout]))+")")
		return
	}

	if err := system.CreatePool(req.Name, req.Layout, req.Ashift, req.Compression, req.Devices); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionCreatePool,
		Target:  req.Name,
		Result:  audit.ResultOK,
		Details: req.Layout + " ashift=" + string(rune('0'+req.Ashift)) + " compression=" + req.Compression,
	})

	pool, _ := system.GetPool()
	jsonCreated(w, pool)
}

func HandlePoolStatus(w http.ResponseWriter, r *http.Request) {
	out, err := system.GetPoolStatus()
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
	raidzExpand := major > 2 || (major == 2 && minor >= 4)
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
		Devices []string `json:"devices"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Devices) == 0 {
		jsonErr(w, http.StatusBadRequest, "at least one device is required")
		return
	}

	pool, err := system.GetPool()
	if err != nil || pool == nil {
		jsonErr(w, http.StatusBadRequest, "no pool available")
		return
	}

	// Use RAIDZ expansion (zpool attach) on ZFS >= 2.4; fall back to zpool add.
	major, minor, _, _ := system.GetZFSVersion()
	raidzExpand := major > 2 || (major == 2 && minor >= 4)

	var growErr error
	if raidzExpand {
		growErr = system.GrowPoolRaidz(pool.Name, req.Devices)
	} else {
		growErr = system.GrowPool(pool.Name, req.Devices)
	}
	if growErr != nil {
		jsonErr(w, http.StatusInternalServerError, growErr.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionGrowPool,
		Target:  pool.Name,
		Result:  audit.ResultOK,
		Details: strings.Join(req.Devices, ", "),
	})

	updated, _ := system.GetPool()
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

	pool, err := system.GetPool()
	if err != nil || pool == nil {
		jsonErr(w, http.StatusBadRequest, "no pool available")
		return
	}
	if pool.Name != req.Name {
		jsonErr(w, http.StatusBadRequest, "pool name does not match")
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
	pool, err := system.GetPool()
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

	pool, _ := system.GetPool()
	jsonOK(w, pool)
}
