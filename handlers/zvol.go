package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/internal/keystore"
	"zfsnas/system"
)

func HandleListZVols(w http.ResponseWriter, r *http.Request) {
	zvols, err := system.ListAllZVols()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if zvols == nil {
		zvols = []system.ZVol{}
	}
	jsonOK(w, zvols)
}

func HandleCreateZVol(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Parent       string `json:"parent"`
		Name         string `json:"name"`
		Size         string `json:"size"`
		Comment      string `json:"comment"`
		Provisioning string `json:"provisioning"`
		Sync         string `json:"sync"`
		Compression  string `json:"compression"`
		Dedup        string `json:"dedup"`
		BlockSize    string `json:"block_size"`
		Encryption   string `json:"encryption"`
		KeyID        string `json:"key_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Parent = strings.TrimSpace(req.Parent)
	req.Name = strings.TrimSpace(req.Name)
	req.Size = strings.TrimSpace(req.Size)
	if req.Parent == "" {
		jsonErr(w, http.StatusBadRequest, "parent is required")
		return
	}
	if req.Name == "" {
		jsonErr(w, http.StatusBadRequest, "zvol name is required")
		return
	}
	if req.Size == "" {
		jsonErr(w, http.StatusBadRequest, "size is required")
		return
	}

	var keyFilePath string
	if req.Encryption == "enabled" {
		if req.KeyID == "" {
			jsonErr(w, http.StatusBadRequest, "encryption key is required when encryption is enabled")
			return
		}
		if !keystore.Exists(req.KeyID) {
			jsonErr(w, http.StatusBadRequest, "encryption key not found")
			return
		}
		keyFilePath = keystore.KeyFilePath(req.KeyID)
	}

	createReq := system.ZVolCreateRequest{
		Parent:       req.Parent,
		Name:         req.Name,
		Size:         req.Size,
		Comment:      strings.TrimSpace(req.Comment),
		Provisioning: req.Provisioning,
		Sync:         req.Sync,
		Compression:  req.Compression,
		Dedup:        req.Dedup,
		BlockSize:    req.BlockSize,
		Encryption:   req.Encryption,
		KeyFilePath:  keyFilePath,
	}
	if err := system.CreateZVol(createReq); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	fullName := req.Parent + "/" + req.Name
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionCreateZVol,
		Target:  fullName,
		Result:  audit.ResultOK,
		Details: "size=" + req.Size,
	})
	go alerts.Send(
		alerts.EventPoolActions,
		"ZVol created: "+fullName,
		"ZFS ZVol Created",
		"ZVol '"+fullName+"' (size: "+req.Size+") was created by "+sess.Username+".",
	)

	jsonCreated(w, map[string]string{"name": fullName})
}

func HandleEditZVol(w http.ResponseWriter, r *http.Request) {
	var req system.ZVolEditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		jsonErr(w, http.StatusBadRequest, "zvol name is required")
		return
	}

	if err := system.EditZVol(req); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionEditZVol,
		Target: req.Name,
		Result: audit.ResultOK,
	})

	jsonOK(w, map[string]string{"message": "zvol updated"})
}

func HandleDeleteZVol(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string `json:"name"`
		Force bool   `json:"force"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		jsonErr(w, http.StatusBadRequest, "zvol name is required")
		return
	}

	var delErr error
	if req.Force {
		delErr = system.DeleteZVolForce(req.Name)
	} else {
		delErr = system.DeleteZVol(req.Name)
	}
	if delErr != nil {
		jsonErr(w, http.StatusInternalServerError, delErr.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionDeleteZVol,
		Target: req.Name,
		Result: audit.ResultOK,
	})
	go alerts.Send(
		alerts.EventPoolActions,
		"ZVol deleted: "+req.Name,
		"ZFS ZVol Deleted",
		"ZVol '"+req.Name+"' was deleted by "+sess.Username+".",
	)

	jsonOK(w, map[string]string{"message": "zvol deleted"})
}
