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
		jsonOK(w, map[string]interface{}{
			"port":                 appCfg.Port,
			"storage_unit":         appCfg.StorageUnit,
			"live_update_enabled":  appCfg.LiveUpdateEnabled,
			"max_smbd_processes":   appCfg.MaxSmbdProcesses,
		})
	}
}

// HandleUpdateSettings updates application settings (admin only).
func HandleUpdateSettings(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Port              *int    `json:"port"`
			StorageUnit       *string `json:"storage_unit"`
			LiveUpdateEnabled *bool   `json:"live_update_enabled"`
			MaxSmbdProcesses  *int    `json:"max_smbd_processes"`
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
		if req.StorageUnit != nil {
			if *req.StorageUnit != "gb" && *req.StorageUnit != "gib" {
				jsonErr(w, http.StatusBadRequest, "storage_unit must be 'gb' or 'gib'")
				return
			}
			appCfg.StorageUnit = *req.StorageUnit
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

		if changed {
			if err := config.SaveAppConfig(appCfg); err != nil {
				jsonErr(w, http.StatusInternalServerError, "failed to save settings")
				return
			}
			// Apply Samba global parameters and reload if Samba is installed.
			if req.MaxSmbdProcesses != nil && system.IsSambaInstalled() {
				if err := system.ApplySmbGlobal(appCfg.MaxSmbdProcesses); err != nil {
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
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	KeyPrefix string    `json:"key_prefix"` // first 8 chars + "…"
	CreatedAt time.Time `json:"created_at"`
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
		out[i] = apiKeyResponse{ID: k.ID, Name: k.Name, KeyPrefix: prefix, CreatedAt: k.CreatedAt}
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
