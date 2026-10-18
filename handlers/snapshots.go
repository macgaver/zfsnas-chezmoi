package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"zfsnas/internal/audit"
	"zfsnas/system"
)

func HandleListSnapshots(w http.ResponseWriter, r *http.Request) {
	// If a specific pool is requested, return only its snapshots.
	if name := strings.TrimSpace(r.URL.Query().Get("pool")); name != "" {
		p, err := system.GetPoolByName(name)
		if err != nil || p == nil {
			jsonOK(w, []system.Snapshot{})
			return
		}
		snaps, err := system.ListSnapshots(p.Name)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if snaps == nil {
			snaps = []system.Snapshot{}
		}
		jsonOK(w, snaps)
		return
	}

	// No pool specified — return snapshots from all pools combined.
	pools, err := system.GetAllPools()
	if err != nil || len(pools) == 0 {
		jsonOK(w, []system.Snapshot{})
		return
	}
	var all []system.Snapshot
	for _, p := range pools {
		snaps, err := system.ListSnapshots(p.Name)
		if err != nil {
			continue
		}
		all = append(all, snaps...)
	}
	if all == nil {
		all = []system.Snapshot{}
	}
	jsonOK(w, all)
}

func HandleCreateSnapshot(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Dataset string `json:"dataset"`
		Label   string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Dataset = strings.TrimSpace(req.Dataset)
	req.Label = strings.TrimSpace(req.Label)
	if req.Dataset == "" {
		jsonErr(w, http.StatusBadRequest, "dataset is required")
		return
	}
	if req.Label == "" {
		req.Label = "snap"
	}
	// Sanitise label: only alphanumeric, dash, underscore.
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, req.Label)
	// Shadow Copy shares find the timestamp at the first "-20" of the name
	// (issue #175): a label such as "before-2026" would hide the snapshot
	// from Windows Previous Versions, so it becomes "before_2026".
	safe = strings.ReplaceAll(safe, "-20", "_20")

	fullName, err := system.CreateSnapshot(req.Dataset, safe)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionCreateSnapshot,
		Target: fullName,
		Result: audit.ResultOK,
	})

	jsonCreated(w, map[string]string{"name": fullName})
}

func HandleRestoreSnapshot(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || !strings.Contains(req.Name, "@") {
		jsonErr(w, http.StatusBadRequest, "valid snapshot name required")
		return
	}
	if err := system.RollbackSnapshot(req.Name); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionRestoreSnapshot,
		Target:  req.Name,
		Result:  audit.ResultOK,
		Details: "rollback -r applied",
	})

	jsonOK(w, map[string]string{"message": "snapshot restored"})
}

func HandleCloneSnapshot(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || req.Target == "" {
		jsonErr(w, http.StatusBadRequest, "name and target are required")
		return
	}
	if err := system.CloneSnapshot(req.Name, req.Target); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionCreateSnapshot,
		Target:  req.Target,
		Result:  audit.ResultOK,
		Details: "cloned from " + req.Name,
	})

	jsonOK(w, map[string]string{"message": "snapshot cloned to " + req.Target})
}

// HandleDeleteAllSnapshots deletes every snapshot belonging to the given dataset.
func HandleDeleteAllSnapshots(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Dataset string `json:"dataset"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Dataset == "" {
		jsonErr(w, http.StatusBadRequest, "dataset is required")
		return
	}

	snaps, err := system.ListSnapshots(req.Dataset)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	var deleted int
	var lastErr error
	for _, s := range snaps {
		if s.Dataset != req.Dataset {
			continue
		}
		if delErr := system.DestroySnapshot(s.Name); delErr != nil {
			lastErr = delErr
		} else {
			deleted++
		}
	}
	if lastErr != nil {
		jsonErr(w, http.StatusInternalServerError, lastErr.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionDeleteSnapshot,
		Target:  req.Dataset,
		Result:  audit.ResultOK,
		Details: fmt.Sprintf("deleted all %d snapshots", deleted),
	})
	jsonOK(w, map[string]interface{}{"deleted": deleted})
}

func HandleDeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || !strings.Contains(req.Name, "@") {
		jsonErr(w, http.StatusBadRequest, "valid snapshot name required")
		return
	}
	if err := system.DestroySnapshot(req.Name); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionDeleteSnapshot,
		Target: req.Name,
		Result: audit.ResultOK,
	})

	jsonOK(w, map[string]string{"message": "snapshot deleted"})
}
