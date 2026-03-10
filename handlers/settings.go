package handlers

import (
	"encoding/json"
	"net/http"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
)

// HandleGetSettings returns current application settings.
func HandleGetSettings(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]interface{}{
			"port":                appCfg.Port,
			"storage_unit":        appCfg.StorageUnit,
			"live_update_enabled": appCfg.LiveUpdateEnabled,
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

		if changed {
			if err := config.SaveAppConfig(appCfg); err != nil {
				jsonErr(w, http.StatusInternalServerError, "failed to save settings")
				return
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
