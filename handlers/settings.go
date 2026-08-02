package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"

	"github.com/gorilla/mux"
)

// HandleGetSettings returns current application settings.
func HandleGetSettings(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		theme := appCfg.LoginTheme
		if theme == "" {
			theme = "dark"
		}
		composeImg := appCfg.ComposeBaseImage
		if composeImg == "" {
			composeImg = "debian"
		}
		jsonOK(w, map[string]interface{}{
			"port":                       appCfg.Port,
			"bind_port_443":              appCfg.BindPort443,
			"compose_base_image":         composeImg,
			"storage_unit":               appCfg.StorageUnit,
			"login_theme":                theme,
			"live_update_enabled":        appCfg.LiveUpdateEnabled,
			"max_smbd_processes":         appCfg.MaxSmbdProcesses,
			"web_session":                appCfg.WebSession,
			"docker_detect_vms":          appCfg.DockerDetectVMsOn(),
			"docker_detect_containers":   appCfg.DockerDetectContainersOn(),
		})
	}
}

// HandleUpdateSettings updates application settings (admin only).
func HandleUpdateSettings(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Port              *int    `json:"port"`
			BindPort443       *bool   `json:"bind_port_443"`
			ComposeBaseImage  *string `json:"compose_base_image"`
			StorageUnit       *string `json:"storage_unit"`
			LoginTheme        *string `json:"login_theme"`
			LiveUpdateEnabled *bool   `json:"live_update_enabled"`
			MaxSmbdProcesses  *int    `json:"max_smbd_processes"`
			WebSession        *config.WebSessionPolicy `json:"web_session"`
			DockerDetectVMs        *bool `json:"docker_detect_vms"`
			DockerDetectContainers *bool `json:"docker_detect_containers"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}

		changed := false
		if req.Port != nil {
			if *req.Port <= 1024 || *req.Port > 65535 {
				jsonErr(w, http.StatusBadRequest, "port must be between 1025 and 65535")
				return
			}
			appCfg.Port = *req.Port
			changed = true
		}
		if req.BindPort443 != nil {
			appCfg.BindPort443 = *req.BindPort443
			changed = true
		}
		if req.ComposeBaseImage != nil {
			switch *req.ComposeBaseImage {
			case "alpine", "debian", "ubuntu":
			default:
				jsonErr(w, http.StatusBadRequest, "compose_base_image must be 'alpine', 'debian', or 'ubuntu'")
				return
			}
			appCfg.ComposeBaseImage = *req.ComposeBaseImage
			changed = true
		}
		if req.StorageUnit != nil {
			if *req.StorageUnit != "gb" && *req.StorageUnit != "gib" {
				jsonErr(w, http.StatusBadRequest, "storage_unit must be 'gb' or 'gib'")
				return
			}
			appCfg.StorageUnit = *req.StorageUnit
			changed = true
		}
		if req.LoginTheme != nil {
			switch *req.LoginTheme {
			case "dark", "light", "auto":
			default:
				jsonErr(w, http.StatusBadRequest, "login_theme must be 'dark', 'light', or 'auto'")
				return
			}
			appCfg.LoginTheme = *req.LoginTheme
			changed = true
		}
		if req.LiveUpdateEnabled != nil {
			appCfg.LiveUpdateEnabled = *req.LiveUpdateEnabled
			changed = true
		}
		if req.MaxSmbdProcesses != nil {
			if *req.MaxSmbdProcesses < 1 || *req.MaxSmbdProcesses > 10000 {
				jsonErr(w, http.StatusBadRequest, "max_smbd_processes must be between 1 and 10000")
				return
			}
			appCfg.MaxSmbdProcesses = *req.MaxSmbdProcesses
			changed = true
		}
		if req.DockerDetectVMs != nil {
			appCfg.DockerDetectVMs = req.DockerDetectVMs
			changed = true
		}
		if req.DockerDetectContainers != nil {
			appCfg.DockerDetectContainers = req.DockerDetectContainers
			changed = true
		}
		if req.WebSession != nil {
			// Reject unknown modes outright (don't silently fall back to default)
			// so the UI surfaces the validation error instead of pretending
			// it saved a typo'd value.
			if req.WebSession.Mode != config.WebSessionModeDefault &&
				req.WebSession.Mode != config.WebSessionModeInactivity {
				jsonErr(w, http.StatusBadRequest, "web_session.mode must be 'default' or 'inactivity'")
				return
			}
			if req.WebSession.Mode == config.WebSessionModeInactivity {
				if req.WebSession.IdleTimeoutMinutes < config.WebSessionMinIdleMinutes ||
					req.WebSession.IdleTimeoutMinutes > config.WebSessionMaxIdleMinutes {
					jsonErr(w, http.StatusBadRequest,
						"web_session.idle_timeout_minutes must be between 5 and 10080 (5 minutes .. 7 days)")
					return
				}
			}
			appCfg.WebSession = *req.WebSession
			config.NormaliseWebSession(&appCfg.WebSession)
			changed = true
		}

		if changed {
			if err := config.SaveAppConfig(appCfg); err != nil {
				jsonErr(w, http.StatusInternalServerError, "failed to save settings")
				return
			}
			// Apply Samba global parameters and reload if Samba is installed.
			if req.MaxSmbdProcesses != nil && system.IsSambaInstalled() {
				if err := system.ApplySmbGlobal(config.Dir(), appCfg.MaxSmbdProcesses, appCfg.SMBWorkgroup, appCfg.SMBCustomGlobal, appCfg.SMBHomeDataset, smbHomeUsernames(), appCfg.SMBCleanDefaults, appCfg.SMBSocketOptions); err != nil {
					log.Printf("settings: ApplySmbGlobal: %v", err)
				} else if err := system.ReloadSamba(); err != nil {
					log.Printf("settings: ReloadSamba: %v", err)
				}
			}
			sess := MustSession(r)
			audit.Log(audit.Entry{
				User:    sess.Username,
				Role:    sess.Role,
				Action:  audit.ActionUpdateSettings,
				Result:  audit.ResultOK,
				Details: "settings updated",
			})
		}

		jsonOK(w, map[string]string{"message": "settings saved — restart required for port change"})
	}
}

// apiKeyResponse is returned for list — omits the full key, shows only a prefix.
type apiKeyResponse struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	KeyPrefix  string    `json:"key_prefix"` // first 8 chars + "…"
	CreatedAt  time.Time `json:"created_at"`
	PoolTarget string    `json:"pool_target"` // "" = default (first zpool)
}

// HandleListAPIKeys returns all API keys with masked values (admin only).
func HandleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := config.LoadAPIKeys()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load keys")
		return
	}
	out := make([]apiKeyResponse, len(keys))
	for i, k := range keys {
		prefix := k.Key
		if len(prefix) > 8 {
			prefix = prefix[:8] + "…"
		}
		out[i] = apiKeyResponse{ID: k.ID, Name: k.Name, KeyPrefix: prefix, CreatedAt: k.CreatedAt, PoolTarget: k.PoolTarget}
	}
	jsonOK(w, out)
}

// HandleCreateAPIKey generates a new named API key and returns the full value once (admin only).
func HandleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		jsonErr(w, http.StatusBadRequest, "name is required")
		return
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to generate key")
		return
	}
	key := hex.EncodeToString(buf)

	idBuf := make([]byte, 8)
	rand.Read(idBuf)
	id := hex.EncodeToString(idBuf)

	entry := config.APIKeyEntry{
		ID:        id,
		Name:      req.Name,
		Key:       key,
		CreatedAt: time.Now(),
	}

	keys, err := config.LoadAPIKeys()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load keys")
		return
	}
	keys = append(keys, entry)
	if err := config.SaveAPIKeys(keys); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save key")
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionUpdateSettings,
		Result:  audit.ResultOK,
		Details: "API key created: " + req.Name,
	})
	// Return full key — this is the only time it is sent to the client.
	jsonOK(w, map[string]string{"id": id, "name": req.Name, "key": key})
}

// HandleDeleteAPIKey removes an API key by ID (admin only).
func HandleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	keys, err := config.LoadAPIKeys()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load keys")
		return
	}
	found := false
	filtered := keys[:0]
	for _, k := range keys {
		if k.ID == id {
			found = true
		} else {
			filtered = append(filtered, k)
		}
	}
	if !found {
		jsonErr(w, http.StatusNotFound, "key not found")
		return
	}
	if err := config.SaveAPIKeys(filtered); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save keys")
		return
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionUpdateSettings,
		Result: audit.ResultOK,
		Details: "API key deleted: " + id,
	})
	jsonOK(w, map[string]string{"message": "deleted"})
}

// poolTargetOption is one selectable capacity target for the homepage widget.
type poolTargetOption struct {
	Value string `json:"value"` // "zfs:<name>" | "mergerfs:<name>"
	Label string `json:"label"`
	Kind  string `json:"kind"` // "zfs" | "mergerfs"
}

// availablePoolTargetNames returns the current zpool and MergerFS pool names,
// used both to build the picker and to validate a submitted selection.
func availablePoolTargetNames(appCfg *config.AppConfig) (zpools, mergerfs []string) {
	if pools, err := system.GetAllPools(); err == nil {
		for _, p := range pools {
			zpools = append(zpools, p.Name)
		}
	}
	for _, p := range appCfg.MergerFS.Pools {
		mergerfs = append(mergerfs, p.Name)
	}
	return zpools, mergerfs
}

// HandleListPoolTargets returns the pools selectable as a homepage capacity
// target (zpools + MergerFS unions), for the gear picker (admin only).
func HandleListPoolTargets(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zpools, mergerfs := availablePoolTargetNames(appCfg)
		out := make([]poolTargetOption, 0, len(zpools)+len(mergerfs))
		for _, n := range zpools {
			out = append(out, poolTargetOption{Value: "zfs:" + n, Label: n + " (ZFS pool)", Kind: "zfs"})
		}
		for _, n := range mergerfs {
			out = append(out, poolTargetOption{Value: "mergerfs:" + n, Label: n + " (MergerFS)", Kind: "mergerfs"})
		}
		jsonOK(w, out)
	}
}

// HandleSetAPIKeyPoolTarget updates a key's homepage capacity target (admin only).
// An empty pool_target resets the key to the default (first zpool).
func HandleSetAPIKeyPoolTarget(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		var req struct {
			PoolTarget string `json:"pool_target"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		req.PoolTarget = strings.TrimSpace(req.PoolTarget)

		zpools, mergerfs := availablePoolTargetNames(appCfg)
		if err := validatePoolTarget(req.PoolTarget, zpools, mergerfs); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}

		keys, err := config.LoadAPIKeys()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to load keys")
			return
		}
		found := false
		for i := range keys {
			if keys[i].ID == id {
				keys[i].PoolTarget = req.PoolTarget
				found = true
				break
			}
		}
		if !found {
			jsonErr(w, http.StatusNotFound, "key not found")
			return
		}
		if err := config.SaveAPIKeys(keys); err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to save keys")
			return
		}
		sess := MustSession(r)
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionUpdateSettings,
			Result:  audit.ResultOK,
			Details: "API key capacity target set: " + id + " → " + orDefaultLabel(req.PoolTarget),
		})
		jsonOK(w, map[string]string{"message": "saved"})
	}
}

func orDefaultLabel(v string) string {
	if v == "" {
		return "default (first zpool)"
	}
	return v
}

// HandleGetTimezone returns the current timezone and the full list of available timezones.
func HandleGetTimezone(w http.ResponseWriter, r *http.Request) {
	tzs, err := system.ListTimezones()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to list timezones")
		return
	}
	jsonOK(w, map[string]interface{}{
		"timezone":  system.GetTimezone(),
		"timezones": tzs,
	})
}

// HandleSetTimezone sets the system timezone.
func HandleSetTimezone(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Timezone string `json:"timezone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Timezone = strings.TrimSpace(req.Timezone)
	if req.Timezone == "" {
		jsonErr(w, http.StatusBadRequest, "timezone is required")
		return
	}
	if err := system.SetTimezone(req.Timezone); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionUpdateSettings,
		Result:  audit.ResultOK,
		Details: "timezone set to " + req.Timezone,
	})
	jsonOK(w, map[string]string{"timezone": req.Timezone})
}
