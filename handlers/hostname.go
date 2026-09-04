package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"zfsnas/internal/audit"
	"zfsnas/system"
)

// HandleGetHostname returns the server's current hostname.
// GET /api/settings/hostname
func HandleGetHostname(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"hostname": system.GetHostname()})
}

// HandleSetHostname renames the server, live and across reboots.
// PUT /api/settings/hostname
func HandleSetHostname(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	var req struct {
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	name := strings.TrimSpace(req.Hostname)
	old := system.GetHostname()
	if err := system.SetHostname(name); err != nil {
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionHostnameChange,
			Target: name, Result: audit.ResultError, Details: err.Error()})
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if name == old {
		jsonOK(w, map[string]string{"hostname": name, "message": "Hostname is already " + name + "."})
		return
	}
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionHostnameChange,
		Target: name, Result: audit.ResultOK, Details: "hostname changed from " + old + " to " + name})
	jsonOK(w, map[string]string{
		"hostname": name,
		"message": "Hostname changed to " + name + ". Services that advertise the old name " +
			"(SMB, mDNS, certificates) pick it up on their next restart.",
	})
}
