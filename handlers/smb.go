package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"

	"github.com/gorilla/mux"
)

// HandleGetSMBGlobalConfig returns global Samba settings (max processes, home dataset, workgroup).
func HandleGetSMBGlobalConfig(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		wg := appCfg.SMBWorkgroup
		if wg == "" {
			wg = "WORKGROUP"
		}
		jsonOK(w, map[string]interface{}{
			"max_smbd_processes": appCfg.MaxSmbdProcesses,
			"home_dataset":       appCfg.SMBHomeDataset,
			"clean_defaults":     appCfg.SMBCleanDefaults,
			"workgroup":          wg,
			"custom_global":      appCfg.SMBCustomGlobal,
			"socket_options":     appCfg.SMBSocketOptions,
		})
	}
}

// HandleUpdateSMBGlobalConfig saves global Samba settings and applies them immediately.
func HandleUpdateSMBGlobalConfig(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			MaxSmbdProcesses *int    `json:"max_smbd_processes"`
			HomeDataset      *string `json:"home_dataset"`
			CleanDefaults    *bool   `json:"clean_defaults"`
			Workgroup        *string `json:"workgroup"`
			CustomGlobal     *string `json:"custom_global"`
			SocketOptions    *bool   `json:"socket_options"`
			RestartNow       *bool   `json:"restart_now"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}

		changed := false
		homeDatasetChanged := false
		workgroupChanged := false
		socketOptionsChanged := false
		prevHomeDataset := appCfg.SMBHomeDataset
		if req.MaxSmbdProcesses != nil {
			if *req.MaxSmbdProcesses < 1 || *req.MaxSmbdProcesses > 10000 {
				jsonErr(w, http.StatusBadRequest, "max_smbd_processes must be between 1 and 10000")
				return
			}
			appCfg.MaxSmbdProcesses = *req.MaxSmbdProcesses
			changed = true
		}
		if req.HomeDataset != nil {
			ds := strings.TrimSpace(*req.HomeDataset)
			if ds != "" && !system.DatasetExists(ds) {
				jsonErr(w, http.StatusBadRequest, "dataset not found: "+ds)
				return
			}
			if ds != appCfg.SMBHomeDataset {
				appCfg.SMBHomeDataset = ds
				homeDatasetChanged = true
			}
			changed = true
		}
		if req.CleanDefaults != nil {
			appCfg.SMBCleanDefaults = *req.CleanDefaults
			changed = true
		}
		if req.Workgroup != nil {
			wg := strings.TrimSpace(*req.Workgroup)
			if wg == "" {
				wg = "WORKGROUP"
			}
			prev := appCfg.SMBWorkgroup
			if prev == "" {
				prev = "WORKGROUP"
			}
			if wg != prev {
				workgroupChanged = true
			}
			appCfg.SMBWorkgroup = wg
			changed = true
		}
		if req.CustomGlobal != nil {
			appCfg.SMBCustomGlobal = *req.CustomGlobal
			changed = true
		}
		if req.SocketOptions != nil {
			if *req.SocketOptions != appCfg.SMBSocketOptions {
				socketOptionsChanged = true
			}
			appCfg.SMBSocketOptions = *req.SocketOptions
			changed = true
		}

		if !changed {
			jsonOK(w, map[string]string{"message": "no changes"})
			return
		}

		// Before writing smb.conf, migrate any active parameter lines from the
		// distro-written [global] section into SMBCustomGlobal so they are not
		// silently lost when we comment that section out.  This is a no-op once
		// the external [global] has already been commented out.
		if extracted, err := system.ExtractExternalGlobalParams(); err == nil && extracted != "" {
			appCfg.SMBCustomGlobal = mergeGlobalLines(appCfg.SMBCustomGlobal, extracted)
		}

		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to save settings")
			return
		}
		// When the home dataset changes, create home dirs in the new dataset and
		// remove empty home dirs from the previous dataset.
		if homeDatasetChanged {
			users, _ := config.LoadUsers()
			for _, u := range users {
				if !u.SMBHomeFolder {
					continue
				}
				if appCfg.SMBHomeDataset != "" {
					if err := system.EnsureSMBHomeDir(appCfg.SMBHomeDataset, u.Username); err != nil {
						log.Printf("smb global config: EnsureSMBHomeDir %s: %v", u.Username, err)
					}
				}
				if prevHomeDataset != "" {
					if err := system.RemoveSMBHomeDirIfEmpty(prevHomeDataset, u.Username); err != nil {
						log.Printf("smb global config: RemoveSMBHomeDirIfEmpty %s: %v", u.Username, err)
					}
				}
			}
		}
		restartNow := req.RestartNow != nil && *req.RestartNow
		if system.IsSambaInstalled() {
			if err := system.ApplySmbGlobal(config.Dir(), appCfg.MaxSmbdProcesses, appCfg.SMBWorkgroup, appCfg.SMBCustomGlobal, appCfg.SMBHomeDataset, smbHomeUsernames(), appCfg.SMBCleanDefaults, appCfg.SMBSocketOptions); err != nil {
				log.Printf("smb global config: ApplySmbGlobal: %v", err)
			} else if workgroupChanged || homeDatasetChanged || (socketOptionsChanged && restartNow) {
				// Workgroup, [homes], and socket options (when user chose restart now) require a full restart.
				if err := system.RestartSamba(); err != nil {
					log.Printf("smb global config: RestartSamba: %v", err)
				}
			} else if err := system.ReloadSamba(); err != nil {
				log.Printf("smb global config: ReloadSamba: %v", err)
			}
		}
		sess := MustSession(r)
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionUpdateSettings,
			Result:  audit.ResultOK,
			Details: "SMB global config updated",
		})
		jsonOK(w, map[string]interface{}{
			"message":                "SMB global settings saved",
			"socket_options_changed": socketOptionsChanged,
			"restarted":              workgroupChanged || homeDatasetChanged || (socketOptionsChanged && restartNow),
		})
	}
}

// smbHomeUsernames returns the usernames of all users with SMBHomeFolder enabled.
func smbHomeUsernames() []string {
	users, err := config.LoadUsers()
	if err != nil {
		return nil
	}
	var names []string
	for _, u := range users {
		if u.SMBHomeFolder {
			names = append(names, u.Username)
		}
	}
	return names
}

// mergeGlobalLines merges addition into existing, deduplicating by parameter key
// (the part before "=").  existing lines take precedence; addition lines whose
// key is already present in existing are skipped.  This prevents duplicate
// entries when migrating distro-written [global] params into SMBCustomGlobal.
func mergeGlobalLines(existing, addition string) string {
	existingKeys := make(map[string]bool)
	var result []string

	for _, line := range strings.Split(existing, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		result = append(result, t)
		if idx := strings.IndexByte(t, '='); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(t[:idx]))
			existingKeys[key] = true
		}
	}
	for _, line := range strings.Split(addition, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if idx := strings.IndexByte(t, '='); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(t[:idx]))
			if existingKeys[key] {
				continue // user's explicit value takes precedence
			}
		}
		result = append(result, t)
	}
	return strings.Join(result, "\n")
}

// HandleGetSMBSessions returns active Samba connections grouped by share name.
func HandleGetSMBSessions(w http.ResponseWriter, r *http.Request) {
	if !system.IsSambaInstalled() {
		jsonOK(w, map[string][]system.ShareClient{})
		return
	}
	jsonOK(w, system.GetSMBSessions())
}

// HandleSMBStatus returns Samba installation and service status.
func HandleSMBStatus(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"installed": system.IsSambaInstalled(),
		"status":    system.SambaStatus(),
	})
}

// HandleSMBService starts, stops, or restarts the smbd systemd unit.
func HandleSMBService(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := system.ControlSamba(req.Action); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]string{
		"status": system.SambaStatus(),
	})
}

// HandleListShares returns all configured SMB shares.
func HandleListShares(w http.ResponseWriter, r *http.Request) {
	shares, err := system.ListSMBShares(config.Dir())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, shares)
}

// HandleCreateShare creates a new SMB share.
func HandleCreateShare(w http.ResponseWriter, r *http.Request) {
	var req system.SMBShare
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Path = strings.TrimSpace(req.Path)
	if req.Name == "" {
		jsonErr(w, http.StatusBadRequest, "share name is required")
		return
	}
	if req.Path == "" {
		jsonErr(w, http.StatusBadRequest, "path is required")
		return
	}

	shares, err := system.ListSMBShares(config.Dir())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, s := range shares {
		if strings.EqualFold(s.Name, req.Name) {
			jsonErr(w, http.StatusConflict, "a share with that name already exists")
			return
		}
	}

	shares = append(shares, req)
	if err := system.SaveSMBShares(config.Dir(), shares); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := system.ReloadSamba(); err != nil {
		// Non-fatal: config was written, samba may not be running yet.
		_ = err
	}
	// Make the share path world-accessible so SMB clients can read and write.
	_ = system.ChmodSharePath(req.Path)
	// Apply (or skip) Windows ACL ZFS dataset properties.
	_ = system.SetWindowsACLDatasetProps(req.Path, req.WindowsACL)
	// Shadow Copy requires snapdir=visible so Samba can enumerate .zfs/snapshot/.
	applySnaqdirForShare(req)

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionCreateShare,
		Target: req.Name,
		Result: audit.ResultOK,
	})
	go alerts.Send(
		alerts.EventShareCreated,
		"SMB share created: "+req.Name,
		"SMB Share Created",
		"SMB share '"+req.Name+"' (path: "+req.Path+") was created by "+sess.Username+".",
	)
	jsonCreated(w, req)
}

// HandleUpdateShare replaces an existing SMB share by name.
func HandleUpdateShare(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(mux.Vars(r)["name"])
	if name == "" {
		jsonErr(w, http.StatusBadRequest, "share name required in URL")
		return
	}

	var req system.SMBShare
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = name // canonical name from URL

	shares, err := system.ListSMBShares(config.Dir())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	found := false
	availabilityChanged := false
	for i, s := range shares {
		if strings.EqualFold(s.Name, name) {
			availabilityChanged = s.Disabled != req.Disabled
			shares[i] = req
			found = true
			break
		}
	}
	if !found {
		jsonErr(w, http.StatusNotFound, "share not found")
		return
	}

	if err := system.SaveSMBShares(config.Dir(), shares); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if r.URL.Query().Get("restart") == "true" || availabilityChanged {
		// A full restart is required when the available flag changes because Samba
		// does not reliably pick up availability changes on a mere reload.
		_ = system.RestartSamba()
	} else {
		_ = system.ReloadSamba()
	}
	// Apply (or revert) Windows ACL ZFS dataset properties.
	_ = system.SetWindowsACLDatasetProps(req.Path, req.WindowsACL)
	// Shadow Copy requires snapdir=visible so Samba can enumerate .zfs/snapshot/.
	applySnaqdirForShare(req)

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionEnableShare,
		Target:  name,
		Result:  audit.ResultOK,
		Details: "updated",
	})
	jsonOK(w, req)
}

// HandleSetSMBPassword creates a Linux system account (if needed) and sets
// the Samba password for a portal user.
func HandleSetSMBPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		jsonErr(w, http.StatusBadRequest, "username and password are required")
		return
	}
	if err := system.EnsureSambaUser(req.Username, req.Password, nil, nil); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionUpdateUser,
		Target:  req.Username,
		Result:  audit.ResultOK,
		Details: "smb password set",
	})
	jsonOK(w, map[string]string{"message": "SMB password set for " + req.Username})
}

// HandleCleanShareRecycleBin immediately runs the recycle-bin cleanup for one share.
func HandleCleanShareRecycleBin(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(mux.Vars(r)["name"])
	if name == "" {
		jsonErr(w, http.StatusBadRequest, "share name required in URL")
		return
	}
	if err := system.CleanShareRecycleBin(config.Dir(), name); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionEnableShare,
		Target:  name,
		Result:  audit.ResultOK,
		Details: "recycle bin cleaned manually",
	})
	jsonOK(w, map[string]string{"message": "recycle bin cleaned"})
}

// HandleDeleteShare removes an SMB share by name.
func HandleDeleteShare(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(mux.Vars(r)["name"])
	if name == "" {
		jsonErr(w, http.StatusBadRequest, "share name required in URL")
		return
	}

	shares, err := system.ListSMBShares(config.Dir())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	newShares := shares[:0]
	found := false
	for _, s := range shares {
		if strings.EqualFold(s.Name, name) {
			found = true
			continue
		}
		newShares = append(newShares, s)
	}
	if !found {
		jsonErr(w, http.StatusNotFound, "share not found")
		return
	}

	if err := system.SaveSMBShares(config.Dir(), newShares); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := system.ReloadSamba(); err != nil {
		_ = err
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionDeleteShare,
		Target: name,
		Result: audit.ResultOK,
	})
	go alerts.Send(
		alerts.EventShareCreated,
		"SMB share deleted: "+name,
		"SMB Share Deleted",
		"SMB share '"+name+"' was deleted by "+sess.Username+".",
	)
	jsonOK(w, map[string]string{"message": "share deleted"})
}

// applySnaqdirForShare sets snapdir=hidden on the backing ZFS dataset when
// Shadow Copy is enabled. ZFS hides .zfs at the filesystem level so SMB users
// never see it, while vfs_shadow_copy2 can still reach .zfs/snapshot/ by
// direct path (it constructs the path itself, bypassing the readdir filter).
// Non-fatal: errors are silently ignored (dataset may not exist yet, or path
// may be a bind-mount rather than a ZFS dataset).
func applySnaqdirForShare(s system.SMBShare) {
	if !s.ShadowCopy {
		return
	}
	dataset := strings.TrimPrefix(s.Path, "/")
	if dataset == "" {
		return
	}
	_ = system.SetDatasetProps(dataset, map[string]string{"snapdir": "hidden"})
}

// HandleCreateVSSSnapshot creates a ZFS snapshot named @GMT-YYYY.MM.DD-HH.MM.SS
// for the dataset backing the named SMB share. This format is required by Samba's
// vfs_shadow_copy2 module for Windows Previous Versions (VSS) support.
// POST /api/smb/shares/vss-snapshot  Body: {"share_name":"sharename"}
func HandleCreateVSSSnapshot(w http.ResponseWriter, r *http.Request) {
	{
		var req struct {
			ShareName string `json:"share_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.ShareName == "" {
			jsonErr(w, http.StatusBadRequest, "share_name is required")
			return
		}

		// Load shares from the JSON store (same as other SMB handlers).
		shares, err := system.ListSMBShares(config.Dir())
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "load shares: "+err.Error())
			return
		}

		// Find the share and confirm shadow copy is enabled.
		var share *system.SMBShare
		for i := range shares {
			if shares[i].Name == req.ShareName {
				share = &shares[i]
				break
			}
		}
		if share == nil {
			jsonErr(w, http.StatusNotFound, "share not found")
			return
		}
		if !share.ShadowCopy {
			jsonErr(w, http.StatusBadRequest, "shadow copy is not enabled on this share")
			return
		}

		if share.Path == "" {
			jsonErr(w, http.StatusBadRequest, "share has no backing path")
			return
		}
		// Resolve the share's mount path to its ZFS dataset name. The previous
		// "strip leading /" shortcut produced things like "mnt/tank/testds" which
		// is a path, not a dataset, and broke "zfs snapshot" for any pool not
		// mounted at /<poolname>.
		dataset, err := system.DatasetForPath(share.Path)
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "resolve dataset for share path: "+err.Error())
			return
		}

		snapName, err := system.CreateShadowCopySnapshot(dataset, share.ShadowCopyFormat)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "create snapshot: "+err.Error())
			return
		}

		sess := MustSession(r)
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionCreateSnapshot,
			Result:  audit.ResultOK,
			Target:  snapName,
			Details: "VSS GMT snapshot for shadow copy share: " + req.ShareName,
		})

		jsonOK(w, map[string]string{"snapshot": snapName})
	}
}
