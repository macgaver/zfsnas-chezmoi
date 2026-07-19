package handlers

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"strconv"
	"zfsnas/internal/audit"
	"zfsnas/internal/capacityrrd"
	"zfsnas/internal/config"
	"zfsnas/system"
)

// HandleGetUPSStatus returns the current UPS status.
// GET /api/ups/status
// When NUT is not installed but a battery is detected in /sys/class/power_supply,
// the response is served from sysfs directly (battery_source=true).
func HandleGetUPSStatus(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !system.UPSPrereqsInstalled() {
			// Fall back to sysfs battery if present.
			if bat := system.QuerySysBattery(); bat != nil {
				jsonOK(w, map[string]interface{}{
					"installed":      false,
					"enabled":        true,
					"battery_source": true,
					"status":         bat,
				})
				return
			}
			jsonOK(w, map[string]interface{}{"installed": false})
			return
		}
		mode := appCfg.UPS.Mode
		if mode == "" {
			mode = "standalone"
		}
		noDevice := appCfg.UPS.UPSName == "" && (mode == "standalone" || mode == "network_server")
		noRemote := mode == "network_client" && (appCfg.UPS.NUTClient == nil || appCfg.UPS.NUTClient.Host == "")
		if !appCfg.UPS.Enabled || noDevice || noRemote {
			jsonOK(w, map[string]interface{}{"installed": true, "enabled": false})
			return
		}
		var status *system.UPSStatus
		var err error
		switch mode {
		case "network_client":
			if appCfg.UPS.NUTClient != nil {
				status, err = system.QueryUPSClient(appCfg.UPS.NUTClient)
			}
		default:
			status, err = system.QueryUPS(appCfg.UPS.UPSName)
		}
		if err != nil {
			jsonOK(w, map[string]interface{}{
				"installed": true,
				"enabled":   true,
				"error":     err.Error(),
			})
			return
		}
		jsonOK(w, map[string]interface{}{
			"installed": true,
			"enabled":   true,
			"status":    status,
		})
	}
}

// HandleGetUPSConfig returns the UPS configuration.
// GET /api/ups/config
func HandleGetUPSConfig(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, appCfg.UPS)
	}
}

// HandleUpdateUPSConfig updates and applies the UPS configuration.
// PUT /api/ups/config
func HandleUpdateUPSConfig(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg config.UPSConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Validate trigger type
		if cfg.ShutdownPolicy.Enabled {
			switch cfg.ShutdownPolicy.TriggerType {
			case "time", "percent", "both":
			default:
				jsonErr(w, http.StatusBadRequest, "trigger_type must be time, percent, or both")
				return
			}
			if cfg.ShutdownPolicy.PercentThreshold < 0 || cfg.ShutdownPolicy.PercentThreshold > 100 {
				jsonErr(w, http.StatusBadRequest, "percent_threshold must be 0-100")
				return
			}
			if cfg.ShutdownPolicy.RuntimeThreshold < 0 || cfg.ShutdownPolicy.RuntimeThreshold > 3600 {
				jsonErr(w, http.StatusBadRequest, "runtime_threshold must be 0-3600 seconds")
				return
			}
		}

		// Preserve fields the frontend never sends back.
		cfg.MonitorPassword = appCfg.UPS.MonitorPassword
		cfg.NominalPowerW = appCfg.UPS.NominalPowerW
		cfg.CostCentsPerKWh = appCfg.UPS.CostCentsPerKWh
		if cfg.UPSName == "" {
			cfg.UPSName = appCfg.UPS.UPSName
		}
		if cfg.Driver == "" {
			cfg.Driver = appCfg.UPS.Driver
		}
		if cfg.Port == "" {
			cfg.Port = appCfg.UPS.Port
		}

		// Validate required fields per mode and rewrite NUT config files.
		mode := cfg.Mode
		if mode == "" {
			mode = "standalone"
		}
		switch mode {
		case "standalone", "network_server":
			if cfg.UPSName == "" {
				jsonErr(w, http.StatusBadRequest, "UPS name is required — run Re-scan to detect your UPS first")
				return
			}
			if cfg.MonitorPassword == "" {
				jsonErr(w, http.StatusBadRequest, "monitor password missing — run Re-scan to regenerate NUT config")
				return
			}
		case "network_client":
			if cfg.NUTClient == nil || cfg.NUTClient.Host == "" {
				jsonErr(w, http.StatusBadRequest, "remote host is required for network client mode")
				return
			}
			if cfg.NUTClient.UPSName == "" {
				jsonErr(w, http.StatusBadRequest, "remote UPS name is required for network client mode")
				return
			}
		default:
			jsonErr(w, http.StatusBadRequest, "mode must be standalone, network_server, or network_client")
			return
		}

		// Map our mode names to NUT's MODE values
		nutModeMap := map[string]string{
			"standalone":     "standalone",
			"network_server": "netserver",
			"network_client": "netclient",
		}
		nutMode := nutModeMap[mode]
		if err := system.ApplyNUTConf(nutMode); err != nil {
			jsonErr(w, http.StatusInternalServerError, "apply nut.conf: "+err.Error())
			return
		}

		switch mode {
		case "standalone":
			// Lock upsd back to localhost — prevents remote access if switching from network_server.
			localhostSrv := &config.NUTServerConfig{ListenIP: "127.0.0.1", ListenPort: 3493}
			if err := system.ApplyNUTUpsdConf(localhostSrv); err != nil {
				jsonErr(w, http.StatusInternalServerError, "apply upsd.conf: "+err.Error())
				return
			}
			// Restore upsd.users to local-only (removes any remote user entries).
			if err := system.ApplyNUTUpsdUsers(cfg.MonitorPassword, nil); err != nil {
				jsonErr(w, http.StatusInternalServerError, "apply upsd.users: "+err.Error())
				return
			}
			if err := system.ApplyUPSMonConfig(cfg.UPSName, cfg.MonitorPassword); err != nil {
				jsonErr(w, http.StatusInternalServerError, "apply upsmon.conf: "+err.Error())
				return
			}
		case "network_server":
			if cfg.NUTServer != nil {
				if err := system.ApplyNUTUpsdConf(cfg.NUTServer); err != nil {
					jsonErr(w, http.StatusInternalServerError, "apply upsd.conf: "+err.Error())
					return
				}
				if err := system.ApplyNUTUpsdUsers(cfg.MonitorPassword, cfg.NUTServer.RemoteUsers); err != nil {
					jsonErr(w, http.StatusInternalServerError, "apply upsd.users: "+err.Error())
					return
				}
			}
			if err := system.ApplyUPSMonConfig(cfg.UPSName, cfg.MonitorPassword); err != nil {
				jsonErr(w, http.StatusInternalServerError, "apply upsmon.conf: "+err.Error())
				return
			}
		case "network_client":
			if cfg.NUTClient != nil && cfg.NUTClient.Host != "" {
				if err := system.ApplyUPSMonConfigClient(cfg.NUTClient); err != nil {
					jsonErr(w, http.StatusInternalServerError, "apply upsmon.conf: "+err.Error())
					return
				}
			}
		}

		system.RestartNUTServices()

		appCfg.UPS = cfg
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
			Target: "ups",
		})

		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleDetectUPS re-runs nut-scanner and reconfigures NUT config files.
// POST /api/ups/detect
func HandleDetectUPS(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		detected, err := system.DetectAndConfigureUPS(appCfg.UPS.MonitorPassword)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "detect failed: "+err.Error())
			return
		}
		// Always persist the password; update device info if found.
		appCfg.UPS.MonitorPassword = detected.MonitorPassword
		if detected.Name != "" {
			appCfg.UPS.UPSName = detected.Name
			appCfg.UPS.Driver = detected.Driver
			appCfg.UPS.Port = detected.Port
			appCfg.UPS.RawUPSConf = detected.ScannerOutput
			appCfg.UPS.Enabled = true
		}
		_ = config.SaveAppConfig(appCfg)
		jsonOK(w, map[string]interface{}{"detected": detected})
	}
}

// HandleInstallUPS installs nut and nut-client via apt-get.
// POST /api/ups/install
func HandleInstallUPS(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		out, err := exec.Command("sudo", "apt-get", "install", "-y", "-q", "nut", "nut-client").CombinedOutput()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, string(out))
			return
		}
		// Do NOT set UPS.Enabled here — the package being installed doesn't mean
		// a UPS is configured. Enabled is set by HandleUpdateUPSConfig once a
		// device/mode is actually chosen; flipping it at install time made the
		// persisted config disagree with the runtime status (which gates on a
		// configured device) and left a stale Enabled=true after uninstall.
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionInstallPrereqs,
			Result:  audit.ResultOK,
			Details: "installed: nut, nut-client",
		})
		jsonOK(w, map[string]string{"message": "nut installed"})
	}
}

// HandleSetNominalPower stores the user-supplied nominal power rating.
// PUT /api/ups/nominal-power  Body: {"watts": 1500}
func HandleSetNominalPower(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Watts *int `json:"watts"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.Watts != nil && *req.Watts < 0 {
			jsonErr(w, http.StatusBadRequest, "watts must be >= 0")
			return
		}
		appCfg.UPS.NominalPowerW = req.Watts
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
			Target: "ups_nominal_power",
		})
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleSetCostPerKWh stores the user's electricity rate in integer cents
// per kWh. Combined with NominalPowerW and the live load %, the UI uses
// it to surface a $/Year estimate. Storing nil clears the override.
// PUT /api/ups/cost-per-kwh  Body: {"cents": 12}
func HandleSetCostPerKWh(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Cents *int `json:"cents"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.Cents != nil && *req.Cents < 0 {
			jsonErr(w, http.StatusBadRequest, "cents must be >= 0")
			return
		}
		appCfg.UPS.CostCentsPerKWh = req.Cents
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
			Target: "ups_cost_per_kwh",
		})
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleSaveShutdownPolicy saves only the UPS shutdown policy without touching
// NUT config files. Used when monitoring a sysfs battery (no NUT installed).
// PUT /api/ups/shutdown-policy
func HandleSaveShutdownPolicy(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ShutdownPolicy config.UPSShutdownPolicy `json:"shutdown_policy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		p := req.ShutdownPolicy
		if p.Enabled {
			switch p.TriggerType {
			case "time", "percent", "both":
			default:
				jsonErr(w, http.StatusBadRequest, "trigger_type must be time, percent, or both")
				return
			}
			if p.PercentThreshold < 0 || p.PercentThreshold > 100 {
				jsonErr(w, http.StatusBadRequest, "percent_threshold must be 0-100")
				return
			}
			if p.RuntimeThreshold < 0 || p.RuntimeThreshold > 3600 {
				jsonErr(w, http.StatusBadRequest, "runtime_threshold must be 0-3600 seconds")
				return
			}
		}
		appCfg.UPS.ShutdownPolicy = p
		appCfg.UPS.Enabled = true
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
			Target: "ups_shutdown_policy",
		})
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleUPSPerfData returns time-series RRD data for the UPS battery tab.
// GET /api/ups/perf/data?tier=0&since=1234567890
func HandleUPSPerfData(w http.ResponseWriter, r *http.Request) {
	db := system.GetUPSRRD()
	if db == nil {
		jsonOK(w, map[string]interface{}{"tier": 0, "series": map[string]interface{}{}})
		return
	}
	tier, _ := strconv.Atoi(r.URL.Query().Get("tier"))
	if tier < 0 || tier > 2 {
		tier = 0
	}
	var since int64
	if s := r.URL.Query().Get("since"); s != "" {
		since, _ = strconv.ParseInt(s, 10, 64)
	}
	keys := []string{"ups:charge_pct", "ups:runtime_secs", "ups:load_pct"}
	result := make(map[string][]capacityrrd.CapSample, len(keys))
	for _, key := range keys {
		samples := db.Query(tier, key)
		if since > 0 {
			cut := len(samples)
			for i, s := range samples {
				if s.TS >= since {
					cut = i
					break
				}
			}
			samples = samples[cut:]
		}
		if samples == nil {
			samples = []capacityrrd.CapSample{}
		}
		result[key] = samples
	}
	jsonOK(w, map[string]interface{}{"tier": tier, "series": result})
}

// HandleUPSPerfOldest returns the oldest Tier0 timestamp in the UPS RRD.
// GET /api/ups/perf/oldest
func HandleUPSPerfOldest(w http.ResponseWriter, r *http.Request) {
	db := system.GetUPSRRD()
	var oldest int64
	if db != nil {
		oldest = db.OldestTS()
	}
	jsonOK(w, map[string]int64{"oldest_ts": oldest})
}

// HandleUPSService starts/stops/restarts nut-server.
// POST /api/ups/service
func HandleUPSService(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	switch req.Action {
	case "start", "stop", "restart":
	default:
		jsonErr(w, http.StatusBadRequest, "action must be start, stop, or restart")
		return
	}
	if err := system.UPSServiceAction(req.Action); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// HandleUPSCalibrate starts a battery runtime-calibration test on the local UPS.
// Only valid in standalone / network-server mode (this host owns the UPS); a
// network client must run it on the server that owns the UPS.
// POST /api/ups/calibrate
func HandleUPSCalibrate(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !system.UPSPrereqsInstalled() {
			jsonErr(w, http.StatusBadRequest, "NUT is not installed")
			return
		}
		mode := appCfg.UPS.Mode
		if mode == "" {
			mode = "standalone"
		}
		if mode == "network_client" {
			jsonErr(w, http.StatusBadRequest, "Calibration must be run on the NUT server that owns the UPS, not a network client.")
			return
		}
		if appCfg.UPS.UPSName == "" {
			jsonErr(w, http.StatusBadRequest, "no local UPS configured")
			return
		}
		if err := system.RunUPSCalibration(appCfg.UPS.UPSName, appCfg.UPS.MonitorPassword); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		sess := MustSession(r)
		audit.Log(audit.Entry{
			User:   sess.Username,
			Role:   sess.Role,
			Action: audit.ActionUpdateSettings,
			Result: audit.ResultOK,
			Target: "ups:calibrate",
		})
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleTestNUTClient tests connectivity to a remote NUT server.
// POST /api/ups/test-client
func HandleTestNUTClient(w http.ResponseWriter, r *http.Request) {
	var req config.NUTClientConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Host == "" || req.UPSName == "" {
		jsonErr(w, http.StatusBadRequest, "host and ups_name are required")
		return
	}
	if req.Port == 0 {
		req.Port = 3493
	}
	status, err := system.QueryUPSClient(&req)
	if err != nil {
		jsonOK(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "status": status})
}
