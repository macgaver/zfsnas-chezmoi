package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"
)

// HandleISCSIStatus returns prereq + service status.
func HandleISCSIStatus(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		prereqs := system.ISCSIPrereqsInstalled()
		svc := system.GetISCSIServiceStatus()
		jsonOK(w, map[string]interface{}{
			"prereqs_installed": prereqs,
			"service_active":    svc.Active,
			"service_status":    svc.Status,
			"hide_nav":          appCfg.ISCSI.HideNav,
		})
	}
}

// HandleISCSIServiceAction starts/stops/restarts the iSCSI daemon.
func HandleISCSIServiceAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var err error
	switch req.Action {
	case "start":
		err = system.StartISCSIService()
	case "stop":
		err = system.StopISCSIService()
	case "restart":
		err = system.RestartISCSIService()
	default:
		jsonErr(w, http.StatusBadRequest, "invalid action")
		return
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// HandleGetISCSIConfig returns the iSCSI base config (base_name, port, enabled).
func HandleGetISCSIConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{
		"enabled":   cfg.ISCSI.Enabled,
		"base_name": cfg.ISCSI.BaseName,
		"port":      cfg.ISCSI.Port,
	})
}

// HandleSaveISCSIConfig persists base_name + port and re-applies targetcli config.
func HandleSaveISCSIConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BaseName string `json:"base_name"`
		Port     int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.BaseName = strings.TrimSpace(req.BaseName)
	if req.BaseName == "" {
		jsonErr(w, http.StatusBadRequest, "base_name is required")
		return
	}
	if req.Port < 1 || req.Port > 65535 {
		jsonErr(w, http.StatusBadRequest, "port must be between 1 and 65535")
		return
	}

	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg.ISCSI.BaseName = req.BaseName
	cfg.ISCSI.Port = req.Port
	if err := config.SaveAppConfig(cfg); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if system.ISCSIPrereqsInstalled() {
		if err := system.ApplyISCSIConfig(&cfg.ISCSI); err != nil {
			jsonErr(w, http.StatusInternalServerError, "config saved but apply failed: "+err.Error())
			return
		}
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionEditISCSIConfig,
		Result: audit.ResultOK,
	})

	jsonOK(w, map[string]string{"message": "iSCSI config saved"})
}

// HandleListISCSIHosts returns all registered initiator hosts.
func HandleListISCSIHosts(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cfg.ISCSI.Hosts == nil {
		cfg.ISCSI.Hosts = []config.ISCSIHost{}
	}
	jsonOK(w, cfg.ISCSI.Hosts)
}

// HandleSaveISCSIHost creates or updates a host entry.
func HandleSaveISCSIHost(w http.ResponseWriter, r *http.Request) {
	var req config.ISCSIHost
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.IQN = strings.TrimSpace(req.IQN)
	if req.IQN == "" {
		jsonErr(w, http.StatusBadRequest, "iqn is required")
		return
	}

	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if req.ID == "" {
		req.ID = newID()
		cfg.ISCSI.Hosts = append(cfg.ISCSI.Hosts, req)
	} else {
		found := false
		for i, h := range cfg.ISCSI.Hosts {
			if h.ID == req.ID {
				cfg.ISCSI.Hosts[i] = req
				found = true
				break
			}
		}
		if !found {
			jsonErr(w, http.StatusNotFound, "host not found")
			return
		}
	}

	if err := config.SaveAppConfig(cfg); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, req)
}

// HandleDeleteISCSIHost removes a host if it is not in use by any share.
func HandleDeleteISCSIHost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ID == "" {
		jsonErr(w, http.StatusBadRequest, "id is required")
		return
	}

	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Check in-use.
	for _, share := range cfg.ISCSI.Shares {
		for _, hid := range share.HostIDs {
			if hid == req.ID {
				jsonErr(w, http.StatusConflict, "host is in use by share "+share.IQN)
				return
			}
		}
	}

	hosts := cfg.ISCSI.Hosts[:0]
	for _, h := range cfg.ISCSI.Hosts {
		if h.ID != req.ID {
			hosts = append(hosts, h)
		}
	}
	cfg.ISCSI.Hosts = hosts
	if err := config.SaveAppConfig(cfg); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "host deleted"})
}

// iscsiShareEntry is the API response shape for a single iSCSI share.
// Orphaned is true when the share exists on the system but not in the app config.
type iscsiShareEntry struct {
	config.ISCSIShare
	Orphaned bool `json:"orphaned,omitempty"`
}

// HandleListISCSIShares returns all iSCSI shares, including any orphaned targets
// that are present on the system but missing from the app config.
func HandleListISCSIShares(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	result := make([]iscsiShareEntry, 0, len(cfg.ISCSI.Shares))
	for _, s := range cfg.ISCSI.Shares {
		result = append(result, iscsiShareEntry{ISCSIShare: s})
	}

	// Detect orphaned targets: present on system but not in config.
	if system.ISCSIPrereqsInstalled() {
		configIQNs := make(map[string]bool, len(cfg.ISCSI.Shares))
		for _, s := range cfg.ISCSI.Shares {
			configIQNs[s.IQN] = true
		}
		for _, iqn := range system.GetSystemISCSITargets() {
			if !configIQNs[iqn] {
				result = append(result, iscsiShareEntry{
					ISCSIShare: config.ISCSIShare{IQN: iqn},
					Orphaned:   true,
				})
			}
		}
	}

	jsonOK(w, result)
}

// HandleEditISCSIShare updates the editable fields of an existing share (comment, host_ids, host_creds).
// The IQN and ZVol are immutable after creation.
func HandleEditISCSIShare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID        string            `json:"id"`
		Comment   string            `json:"comment"`
		HostIDs   []string          `json:"host_ids"`
		HostCreds map[string]string `json:"host_creds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ID == "" {
		jsonErr(w, http.StatusBadRequest, "id is required")
		return
	}
	if req.HostIDs == nil {
		req.HostIDs = []string{}
	}
	if req.HostCreds == nil {
		req.HostCreds = map[string]string{}
	}

	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	found := false
	for i, s := range cfg.ISCSI.Shares {
		if s.ID == req.ID {
			cfg.ISCSI.Shares[i].Comment = strings.TrimSpace(req.Comment)
			cfg.ISCSI.Shares[i].HostIDs = req.HostIDs
			cfg.ISCSI.Shares[i].HostCreds = req.HostCreds
			found = true
			break
		}
	}
	if !found {
		jsonErr(w, http.StatusNotFound, "share not found")
		return
	}

	if err := config.SaveAppConfig(cfg); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if system.ISCSIPrereqsInstalled() {
		if err := system.ApplyISCSIConfig(&cfg.ISCSI); err != nil {
			jsonErr(w, http.StatusInternalServerError, "share saved but apply failed: "+err.Error())
			return
		}
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionEditISCSIConfig,
		Target: req.ID,
		Result: audit.ResultOK,
	})

	jsonOK(w, map[string]string{"message": "share updated"})
}

// HandleCreateISCSIShare creates a new iSCSI share backed by a ZVol.
func HandleCreateISCSIShare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ZVol      string            `json:"zvol"`
		HostIDs   []string          `json:"host_ids"`
		HostCreds map[string]string `json:"host_creds"`
		Comment   string            `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.ZVol = strings.TrimSpace(req.ZVol)
	if req.ZVol == "" {
		jsonErr(w, http.StatusBadRequest, "zvol is required")
		return
	}

	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	shareID := newID()
	share := config.ISCSIShare{
		ID:        shareID,
		ZVol:      req.ZVol,
		IQN:       system.GenerateTargetIQN(cfg.ISCSI.BaseName, shareID),
		HostIDs:   req.HostIDs,
		HostCreds: req.HostCreds,
		Comment:   strings.TrimSpace(req.Comment),
		CreatedAt: time.Now().Unix(),
	}
	if share.HostIDs == nil {
		share.HostIDs = []string{}
	}
	if share.HostCreds == nil {
		share.HostCreds = map[string]string{}
	}

	cfg.ISCSI.Shares = append(cfg.ISCSI.Shares, share)
	if err := config.SaveAppConfig(cfg); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if system.ISCSIPrereqsInstalled() {
		if err := system.ApplyISCSIConfig(&cfg.ISCSI); err != nil {
			jsonErr(w, http.StatusInternalServerError, "share saved but apply failed: "+err.Error())
			return
		}
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionCreateISCSIShare,
		Target:  share.IQN,
		Result:  audit.ResultOK,
		Details: "zvol=" + req.ZVol,
	})

	jsonCreated(w, share)
}

// HandleDeleteISCSIShare removes an iSCSI share and re-applies the config.
// For orphaned shares (present on system but not in config), pass iqn instead of id.
func HandleDeleteISCSIShare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		IQN      string `json:"iqn"` // used for orphaned shares
		Orphaned bool   `json:"orphaned"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	var targetIQN string

	if req.Orphaned {
		// Orphaned share: not in config, just re-apply so targetcli clears it.
		targetIQN = req.IQN
		if targetIQN == "" {
			jsonErr(w, http.StatusBadRequest, "iqn is required for orphaned share")
			return
		}
	} else {
		if req.ID == "" {
			jsonErr(w, http.StatusBadRequest, "id is required")
			return
		}
		shares := cfg.ISCSI.Shares[:0]
		for _, s := range cfg.ISCSI.Shares {
			if s.ID == req.ID {
				targetIQN = s.IQN
			} else {
				shares = append(shares, s)
			}
		}
		if targetIQN == "" {
			jsonErr(w, http.StatusNotFound, "share not found")
			return
		}
		cfg.ISCSI.Shares = shares
		if err := config.SaveAppConfig(cfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	sess := MustSession(r)

	if system.ISCSIPrereqsInstalled() {
		if err := system.ApplyISCSIConfig(&cfg.ISCSI); err != nil {
			jsonErr(w, http.StatusInternalServerError, "share deleted but apply failed: "+err.Error())
			return
		}
		// Verify the IQN is no longer present on the system.
		for _, iqn := range system.GetSystemISCSITargets() {
			if iqn == targetIQN {
				audit.Log(audit.Entry{
					User:    sess.Username,
					Role:    sess.Role,
					Action:  audit.ActionDeleteISCSIShare,
					Target:  targetIQN,
					Result:  audit.ResultError,
					Details: "removed from config but target still present on system after apply",
				})
				jsonErr(w, http.StatusInternalServerError, "share still present on system after apply — iSCSI config may need a service restart")
				return
			}
		}
	}

	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionDeleteISCSIShare,
		Target: targetIQN,
		Result: audit.ResultOK,
	})

	jsonOK(w, map[string]string{"message": "share deleted"})
}

// credResp is the API shape for a credential — passwords are never sent to the client.
type credResp struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Method         string `json:"method"`
	InUsername     string `json:"in_username"`
	InPasswordSet  bool   `json:"in_password_set"`
	OutUsername    string `json:"out_username,omitempty"`
	OutPasswordSet bool   `json:"out_password_set,omitempty"`
}

// HandleGetISCSISessions returns active initiator sessions grouped by target IQN.
func HandleGetISCSISessions(w http.ResponseWriter, r *http.Request) {
	if !system.ISCSIPrereqsInstalled() {
		jsonOK(w, map[string][]string{})
		return
	}
	jsonOK(w, system.GetISCSISessions())
}

// HandleListISCSICredentials returns all CHAP credentials (passwords never included).
func HandleListISCSICredentials(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	result := make([]credResp, 0, len(cfg.ISCSI.Credentials))
	for _, c := range cfg.ISCSI.Credentials {
		result = append(result, credResp{
			ID:             c.ID,
			Name:           c.Name,
			Method:         c.Method,
			InUsername:     c.InUsername,
			InPasswordSet:  c.InPassword != "",
			OutUsername:    c.OutUsername,
			OutPasswordSet: c.OutPassword != "",
		})
	}
	jsonOK(w, result)
}

// HandleSaveISCSICredential creates or updates a CHAP credential.
func HandleSaveISCSICredential(w http.ResponseWriter, r *http.Request) {
	var req config.ISCSICredential
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.InUsername = strings.TrimSpace(req.InUsername)
	req.InPassword = strings.TrimSpace(req.InPassword)
	req.OutUsername = strings.TrimSpace(req.OutUsername)
	req.OutPassword = strings.TrimSpace(req.OutPassword)

	if req.Method != "incoming" && req.Method != "bidirectional" {
		jsonErr(w, http.StatusBadRequest, "method must be 'incoming' or 'bidirectional'")
		return
	}
	if req.InUsername == "" || req.InPassword == "" {
		jsonErr(w, http.StatusBadRequest, "username and password are required")
		return
	}
	if len(req.InPassword) < 12 {
		jsonErr(w, http.StatusBadRequest, "password must be at least 12 characters")
		return
	}
	if req.Method == "bidirectional" {
		if req.OutUsername == "" || req.OutPassword == "" {
			jsonErr(w, http.StatusBadRequest, "outgoing username and password are required for bidirectional CHAP")
			return
		}
		if len(req.OutPassword) < 12 {
			jsonErr(w, http.StatusBadRequest, "outgoing password must be at least 12 characters")
			return
		}
	}

	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if req.ID == "" {
		req.ID = newID()
		cfg.ISCSI.Credentials = append(cfg.ISCSI.Credentials, req)
	} else {
		found := false
		for i, c := range cfg.ISCSI.Credentials {
			if c.ID == req.ID {
				// Preserve existing passwords when the field is left blank.
				if req.InPassword == "" {
					req.InPassword = c.InPassword
				}
				if req.OutPassword == "" {
					req.OutPassword = c.OutPassword
				}
				cfg.ISCSI.Credentials[i] = req
				found = true
				break
			}
		}
		if !found {
			jsonErr(w, http.StatusNotFound, "credential not found")
			return
		}
	}

	if err := config.SaveAppConfig(cfg); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionCreateISCSICredential,
		Target: req.Name,
		Result: audit.ResultOK,
	})

	jsonOK(w, credResp{
		ID:             req.ID,
		Name:           req.Name,
		Method:         req.Method,
		InUsername:     req.InUsername,
		InPasswordSet:  req.InPassword != "",
		OutUsername:    req.OutUsername,
		OutPasswordSet: req.OutPassword != "",
	})
}

// HandleDeleteISCSICredential removes a CHAP credential if it is not referenced by any share.
func HandleDeleteISCSICredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ID == "" {
		jsonErr(w, http.StatusBadRequest, "id is required")
		return
	}

	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Check in-use.
	for _, share := range cfg.ISCSI.Shares {
		for _, cid := range share.HostCreds {
			if cid == req.ID {
				jsonErr(w, http.StatusConflict, "credential is in use by share "+share.IQN)
				return
			}
		}
	}

	creds := cfg.ISCSI.Credentials[:0]
	found := false
	for _, c := range cfg.ISCSI.Credentials {
		if c.ID != req.ID {
			creds = append(creds, c)
		} else {
			found = true
		}
	}
	if !found {
		jsonErr(w, http.StatusNotFound, "credential not found")
		return
	}
	cfg.ISCSI.Credentials = creds

	if err := config.SaveAppConfig(cfg); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionDeleteISCSICredential,
		Target: req.ID,
		Result: audit.ResultOK,
	})

	jsonOK(w, map[string]string{"message": "credential deleted"})
}
