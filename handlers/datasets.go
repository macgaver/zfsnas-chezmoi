package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"zfsnas/internal/audit"
	"zfsnas/internal/keystore"
	"zfsnas/system"

	"github.com/gorilla/mux"
)

// poolNameFromDatasets extracts the pool name from any dataset path.
func poolFromAny(name string) string {
	return strings.SplitN(name, "/", 2)[0]
}

func HandleListDatasets(w http.ResponseWriter, r *http.Request) {
	datasets, err := system.ListAllDatasets()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if datasets == nil {
		datasets = []system.Dataset{}
	}
	jsonOK(w, datasets)
}

func HandleCreateDataset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name            string `json:"name"`
		Quota           uint64 `json:"quota"`
		QuotaType       string `json:"quota_type"`
		Refreservation  uint64 `json:"refreservation"`
		Compression     string `json:"compression"`
		Sync            string `json:"sync"`
		Dedup           string `json:"dedup"`
		CaseSensitivity string `json:"case_sensitivity"`
		RecordSize      string `json:"record_size"`
		Comment         string `json:"comment"`
		KeyID           string `json:"key_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || !strings.Contains(req.Name, "/") {
		jsonErr(w, http.StatusBadRequest, "dataset name must include pool (e.g. tank/data)")
		return
	}
	if req.QuotaType == "" {
		req.QuotaType = "quota"
	}
	if req.Compression == "" {
		req.Compression = "inherit"
	}

	var keyFilePath string
	if req.KeyID != "" {
		if !keystore.Exists(req.KeyID) {
			jsonErr(w, http.StatusBadRequest, "encryption key not found")
			return
		}
		keyFilePath = keystore.KeyFilePath(req.KeyID)
	}

	opts := system.DatasetCreateOptions{
		Quota:           req.Quota,
		QuotaType:       req.QuotaType,
		Refreservation:  req.Refreservation,
		Compression:     req.Compression,
		Sync:            req.Sync,
		Dedup:           req.Dedup,
		CaseSensitivity: req.CaseSensitivity,
		RecordSize:      req.RecordSize,
		Comment:         strings.TrimSpace(req.Comment),
		KeyFilePath:     keyFilePath,
	}
	if err := system.CreateDataset(req.Name, opts); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionCreateDataset,
		Target:  req.Name,
		Result:  audit.ResultOK,
		Details: "compression=" + req.Compression,
	})

	jsonCreated(w, map[string]string{"name": req.Name})
}

func HandleUpdateDataset(w http.ResponseWriter, r *http.Request) {
	path := mux.Vars(r)["path"]
	if path == "" {
		jsonErr(w, http.StatusBadRequest, "dataset path required")
		return
	}

	var req struct {
		Quota          *uint64 `json:"quota"`
		QuotaType      string  `json:"quota_type"`
		Refreservation *uint64 `json:"refreservation"`
		Compression    string  `json:"compression"`
		Sync           string  `json:"sync"`
		Dedup          string  `json:"dedup"`
		RecordSize     string  `json:"record_size"`
		Comment        *string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	props := map[string]string{}
	if req.Quota != nil {
		qt := "quota"
		if req.QuotaType == "refquota" {
			qt = "refquota"
		}
		if *req.Quota == 0 {
			props[qt] = "none"
		} else {
			props[qt] = strconv.FormatUint(*req.Quota, 10)
		}
	}
	if req.Refreservation != nil {
		if *req.Refreservation == 0 {
			props["refreservation"] = "none"
		} else {
			props["refreservation"] = strconv.FormatUint(*req.Refreservation, 10)
		}
	}
	if req.Compression != "" {
		props["compression"] = req.Compression
	}
	if req.Sync != "" {
		props["sync"] = req.Sync
	}
	if req.Dedup != "" {
		props["dedup"] = req.Dedup
	}
	if req.RecordSize != "" {
		if req.RecordSize == "inherit" {
			props["recordsize"] = "inherit"
		} else {
			props["recordsize"] = req.RecordSize
		}
	}
	if req.Comment != nil {
		// Empty string clears via `zfs inherit`; non-empty sets the property.
		props["zfsnas:comment"] = strings.TrimSpace(*req.Comment)
	}

	if len(props) == 0 {
		jsonErr(w, http.StatusBadRequest, "nothing to update")
		return
	}

	if err := system.SetDatasetProps(path, props); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionUpdateDataset,
		Target: path,
		Result: audit.ResultOK,
	})

	jsonOK(w, map[string]string{"message": "dataset updated"})
}

func HandleDeleteDataset(w http.ResponseWriter, r *http.Request) {
	path := mux.Vars(r)["path"]
	if path == "" {
		jsonErr(w, http.StatusBadRequest, "dataset path required")
		return
	}
	// Prevent deleting the pool root.
	if !strings.Contains(path, "/") {
		jsonErr(w, http.StatusBadRequest, "cannot delete pool root dataset")
		return
	}

	recursive := r.URL.Query().Get("recursive") == "true"
	var destroyErr error
	if recursive {
		destroyErr = system.DestroyDatasetRecursive(path)
	} else {
		destroyErr = system.DestroyDataset(path)
	}
	if destroyErr != nil {
		jsonErr(w, http.StatusInternalServerError, destroyErr.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionDeleteDataset,
		Target: path,
		Result: audit.ResultOK,
	})

	jsonOK(w, map[string]string{"message": "dataset deleted"})
}

// HandleLoadDatasetKey loads an encryption key for a locked dataset and mounts it.
// Body: {"key_id": "<uuid>"}
func HandleLoadDatasetKey(w http.ResponseWriter, r *http.Request) {
	path := mux.Vars(r)["path"]
	if path == "" {
		jsonErr(w, http.StatusBadRequest, "dataset path required")
		return
	}
	var req struct {
		KeyID string `json:"key_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.KeyID == "" {
		jsonErr(w, http.StatusBadRequest, "key_id is required")
		return
	}
	if !keystore.Exists(req.KeyID) {
		jsonErr(w, http.StatusBadRequest, "key not found")
		return
	}
	keyPath := keystore.KeyFilePath(req.KeyID)
	if err := system.LoadPoolKey(path, keyPath); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load key: "+err.Error())
		return
	}
	// Persist the keylocation so autoLoadEncryptionKeys can reload it after reboot.
	if err := system.SetDatasetProps(path, map[string]string{
		"keylocation": "file://" + keyPath,
	}); err != nil {
		// Non-fatal: key is loaded now, just won't survive reboot.
		_ = err
	}
	if err := system.MountDataset(path); err != nil {
		jsonErr(w, http.StatusInternalServerError, "key loaded but mount failed: "+err.Error())
		return
	}
	// Mount any unlocked child datasets that weren't auto-mounted.
	system.MountUnlockedChildren(path)
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionLoadKey,
		Target: path,
		Result: audit.ResultOK,
	})
	jsonOK(w, map[string]string{"message": "key loaded and dataset mounted"})
}
