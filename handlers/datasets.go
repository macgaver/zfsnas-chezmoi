package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"zfsnas/internal/audit"
	"zfsnas/system"

	"github.com/gorilla/mux"
)

// poolNameFromDatasets extracts the pool name from any dataset path.
func poolFromAny(name string) string {
	return strings.SplitN(name, "/", 2)[0]
}

func HandleListDatasets(w http.ResponseWriter, r *http.Request) {
	pool, err := system.GetPool()
	if err != nil || pool == nil {
		jsonOK(w, []system.Dataset{})
		return
	}
	datasets, err := system.ListDatasets(pool.Name)
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
		Name        string `json:"name"`
		Quota       uint64 `json:"quota"`
		QuotaType   string `json:"quota_type"`
		Compression string `json:"compression"`
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

	if err := system.CreateDataset(req.Name, req.Quota, req.QuotaType, req.Compression); err != nil {
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
		Quota       *uint64 `json:"quota"`
		QuotaType   string  `json:"quota_type"`
		Compression string  `json:"compression"`
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
	if req.Compression != "" {
		props["compression"] = req.Compression
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

	if err := system.DestroyDataset(path); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
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
