package handlers

import (
	"encoding/json"
	"net/http"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"
)

// HandleGetSystemPower returns current system power config + availability.
// GET /api/system/power
func HandleGetSystemPower(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		avail := system.GetSystemPowerAvailability()
		// Prefer stored config over live-read (live read shows current kernel state,
		// but the stored config is what the admin intentionally set)
		avail.Current = appCfg.SystemPower
		jsonOK(w, avail)
	}
}

// HandleUpdateSystemPower saves and applies system power settings.
// PUT /api/system/power
func HandleUpdateSystemPower(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg config.SystemPowerConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Validate governor
		validGovernors := map[string]bool{
			"":             true,
			"performance":  true,
			"powersave":    true,
			"ondemand":     true,
			"conservative": true,
			"schedutil":    true,
		}
		if !validGovernors[cfg.CPUGovernor] {
			jsonErr(w, http.StatusBadRequest, "invalid cpu_governor value")
			return
		}

		// Validate power profile
		validProfiles := map[string]bool{
			"":            true,
			"performance": true,
			"balanced":    true,
			"power-saver": true,
		}
		if !validProfiles[cfg.PowerProfile] {
			jsonErr(w, http.StatusBadRequest, "invalid power_profile value")
			return
		}

		// Validate PCIe ASPM
		validASPM := map[string]bool{
			"":               true,
			"default":        true,
			"performance":    true,
			"powersave":      true,
			"powersupersave": true,
		}
		if !validASPM[cfg.PCIeASPM] {
			jsonErr(w, http.StatusBadRequest, "invalid pcie_aspm value")
			return
		}

		if err := system.ApplySystemPowerConfig(cfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		appCfg.SystemPower = cfg
		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		sess := MustSession(r)
		audit.Log(audit.Entry{
			User:   sess.Username,
			Role:   sess.Role,
			Action: audit.ActionUpdateSettings,
			Result: audit.ResultOK,
			Target: "system_power",
		})
		jsonOK(w, map[string]bool{"ok": true})
	}
}
