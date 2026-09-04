// Appliance-mode (USB image) glue for the handlers package. v6.8.28.
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"zfsnas/internal/audit"
	"zfsnas/system"
)

// updaterDestPath returns where the self-updater must write the new binary:
// on the appliance the squashfs is read-only, so it goes to the persist
// store; run-zfsnas.sh adopts it at next service start.
func updaterDestPath(exePath string) string {
	if system.ApplianceMode() {
		return system.AppliancePersistBin()
	}
	return exePath
}

// applianceBlock writes a 403 and returns true on the appliance, for
// endpoints that mutate OS packages (managed by reflashing the image).
func applianceBlock(w http.ResponseWriter) bool {
	if !system.ApplianceMode() {
		return false
	}
	jsonErr(w, http.StatusForbidden,
		"This system runs from a read-only USB image — OS packages are updated by reflashing the image, not from here.")
	return true
}

// HandleApplianceSSHAccess sets the root password and/or an authorized key
// (appliance only — this is how the user unlocks the shipped-locked SSH).
func HandleApplianceSSHAccess(w http.ResponseWriter, r *http.Request) {
	if !system.ApplianceMode() {
		jsonErr(w, http.StatusBadRequest, "not running on the USB appliance")
		return
	}
	var req struct {
		RootPassword  string `json:"root_password"`
		AuthorizedKey string `json:"authorized_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := system.SetRootSSHAccess(req.RootPassword, req.AuthorizedKey); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Audit WITHOUT the password — record only which fields were set.
	var set []string
	if req.RootPassword != "" {
		set = append(set, "password")
	}
	if req.AuthorizedKey != "" {
		set = append(set, "authorized_key")
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  "appliance-ssh-access",
		Result:  audit.ResultOK,
		Details: "set: " + strings.Join(set, ", "),
	})

	jsonOK(w, map[string]string{"status": "ok"})
}
