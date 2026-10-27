package handlers

import (
	"fmt"
	"os"
	"encoding/json"
	"net/http"
	"strings"
	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"

	"github.com/gorilla/mux"
)

// HandleGetNFSSessions returns active NFS mounts grouped by export path.
func HandleGetNFSSessions(w http.ResponseWriter, r *http.Request) {
	if !system.IsNFSInstalled() {
		jsonOK(w, map[string][]system.ShareClient{})
		return
	}
	exports, _ := system.ListNFSShares(config.Dir())
	jsonOK(w, system.GetNFSSessions(exports))
}

// HandleNFSStatus returns NFS installation and service status.
func HandleNFSStatus(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"installed": system.IsNFSInstalled(),
		"status":    system.NFSStatus(),
	})
}

// HandleNFSService starts, stops, or restarts the nfs-server systemd unit.
func HandleNFSService(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := system.ControlNFS(req.Action); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]string{
		"status": system.NFSStatus(),
	})
}

// HandleListNFSShares returns all configured NFS exports.
func HandleListNFSShares(w http.ResponseWriter, r *http.Request) {
	shares, err := system.ListNFSShares(config.Dir())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, shares)
}

// HandleCreateNFSShare adds a new NFS export.
func HandleCreateNFSShare(w http.ResponseWriter, r *http.Request) {
	var req system.NFSShare
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Path = strings.TrimSpace(req.Path)
	req.Client = strings.TrimSpace(req.Client)
	if req.Path == "" {
		jsonErr(w, http.StatusBadRequest, "path is required")
		return
	}
	req.Normalize()
	if err := system.ValidateNFSShare(req); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// exportfs refuses a missing path, but only after the share was saved.
	if fi, err := os.Stat(req.Path); err != nil || !fi.IsDir() {
		jsonErr(w, http.StatusBadRequest, "the path "+req.Path+" does not exist or is not a folder")
		return
	}
	req.ID = newID()

	shares, err := system.ListNFSShares(config.Dir())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	shares = append(shares, req)
	if err := system.SaveNFSShares(config.Dir(), shares); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var chmodWarn string
	if err := system.ChmodNFSPath(req.Path); err != nil {
		chmodWarn = "chmod 0777 failed: " + err.Error() + " — add /usr/bin/chmod 0777 * to the sudoers file (Settings > Sudoers Hardening)"
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionCreateNFSShare,
		Target: req.Path,
		Result: audit.ResultOK,
	})
	go alerts.Send(
		alerts.EventShareCreated,
		"NFS share created: "+req.Path,
		"NFS Share Created",
		"NFS export '"+req.Path+"' (client: "+req.Client+") was created by "+sess.Username+".",
	)
	jsonCreated(w, struct {
		system.NFSShare
		Warning string `json:"warning,omitempty"`
	}{req, chmodWarn})
}

// HandleUpdateNFSShare replaces an existing NFS export by ID.
func HandleUpdateNFSShare(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var req system.NFSShare
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.ID = id
	req.Path = strings.TrimSpace(req.Path)
	req.Client = strings.TrimSpace(req.Client)
	req.Normalize()
	if err := system.ValidateNFSShare(req); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// exportfs refuses a missing path, but only after the share was saved.
	if fi, err := os.Stat(req.Path); err != nil || !fi.IsDir() {
		jsonErr(w, http.StatusBadRequest, "the path "+req.Path+" does not exist or is not a folder")
		return
	}

	shares, err := system.ListNFSShares(config.Dir())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	found := false
	for i, s := range shares {
		if s.ID == id {
			shares[i] = req
			found = true
			break
		}
	}
	if !found {
		jsonErr(w, http.StatusNotFound, "share not found")
		return
	}
	if err := system.SaveNFSShares(config.Dir(), shares); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var chmodWarn string
	if err := system.ChmodNFSPath(req.Path); err != nil {
		chmodWarn = "chmod 0777 failed: " + err.Error() + " — add /usr/bin/chmod 0777 * to the sudoers file (Settings > Sudoers Hardening)"
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionUpdateNFSShare,
		Target:  req.Path,
		Result:  audit.ResultOK,
		Details: "updated",
	})
	jsonOK(w, struct {
		system.NFSShare
		Warning string `json:"warning,omitempty"`
	}{req, chmodWarn})
}

// HandleDeleteNFSShare removes an NFS export by ID.
func HandleDeleteNFSShare(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	shares, err := system.ListNFSShares(config.Dir())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	newShares := shares[:0]
	var target string
	for _, s := range shares {
		if s.ID == id {
			target = s.Path
			continue
		}
		newShares = append(newShares, s)
	}
	if target == "" {
		jsonErr(w, http.StatusNotFound, "share not found")
		return
	}
	if err := system.SaveNFSShares(config.Dir(), newShares); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionDeleteNFSShare,
		Target: target,
		Result: audit.ResultOK,
	})
	go alerts.Send(
		alerts.EventShareCreated,
		"NFS share deleted: "+target,
		"NFS Share Deleted",
		"NFS export '"+target+"' was deleted by "+sess.Username+".",
	)
	jsonOK(w, map[string]string{"message": "NFS share removed"})
}

// HandleGetNFSServer returns the server-wide NFS settings and what the
// server actually uses. GET /api/nfs/server
func HandleGetNFSServer(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]any{
			"settings":  appCfg.NFSServer,
			"effective": system.GetNFSEffective(),
		})
	}
}

// HandleSetNFSServer saves and applies the server-wide NFS settings.
// PUT /api/nfs/server
func HandleSetNFSServer(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req config.NFSServerConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.Threads < 0 || req.Threads > 256 {
			jsonErr(w, http.StatusBadRequest, "threads must be between 1 and 256 (0 = default)")
			return
		}
		if req.DisableV3 && system.GetNFSEffective().V4RootBroken {
			jsonErr(w, http.StatusBadRequest, "NFSv4 cannot work on this system (its root filesystem is not NFS-exportable), so NFSv3 cannot be turned off: clients would lose every share. Upgrade the USB appliance image first.")
			return
		}
		appCfg.NFSServer = req
		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, "save config: "+err.Error())
			return
		}
		changed, err := system.ApplyNFSServerSettings(req)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		sess := MustSession(r)
		audit.Log(audit.Entry{
			User: sess.Username, Role: sess.Role, Action: audit.ActionUpdateNFSShare,
			Target: "NFS server settings", Result: audit.ResultOK,
			Details: fmt.Sprintf("trust client groups %s, threads %s, NFSv3 %s",
				map[bool]string{true: "on", false: "off"}[req.TrustClientGroups],
				map[bool]string{true: fmt.Sprint(req.Threads), false: "default"}[req.Threads > 0],
				map[bool]string{true: "off", false: "on"}[req.DisableV3]),
		})
		jsonOK(w, map[string]any{"changed": changed, "effective": system.GetNFSEffective()})
	}
}
