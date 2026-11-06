package handlers

// HTTP handlers for the Virtualization settings tab and the per-instance
// Monitor tab.
//
//   GET  /api/lxd/global-config        — current LXD global config
//   PUT  /api/lxd/global-config        — write a subset; returns changed keys
//   POST /api/lxd/metrics-toggle       — flip the LXD Prometheus endpoint
//                                        + portal scraper on/off in lockstep
//   GET  /api/lxd/metrics-status       — live scraper status (for the badge)
//   GET  /api/lxd/instance-perf        — historical RRD samples for one instance
//   GET  /api/lxd/instance-realtime    — single live snapshot for the realtime row

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"zfsnas/internal/audit"
	"zfsnas/internal/capacityrrd"
	"zfsnas/internal/config"
	"zfsnas/system"
)

// HandleGetLXDGlobalConfig returns the current LXD daemon-global config.
func HandleGetLXDGlobalConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := system.GetLXDGlobalConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "load lxd global config: "+err.Error())
		return
	}
	jsonOK(w, cfg)
}

// HandleSetLXDGlobalConfig writes the requested subset of LXD global keys.
// Returns 200 with the list of keys that actually changed; 400 on validation
// failure; 500 on lxc errors. Empty values unset the key.
func HandleSetLXDGlobalConfig(w http.ResponseWriter, r *http.Request) {
	var want system.LXDGlobalConfig
	if err := json.NewDecoder(r.Body).Decode(&want); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	cur, err := system.GetLXDGlobalConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "load current config: "+err.Error())
		return
	}
	changed, err := system.SetLXDGlobalConfig(cur, &want)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(changed) > 0 {
		sess := MustSession(r)
		audit.Log(audit.Entry{
			User:   sess.Username,
			Role:   sess.Role,
			Action: audit.ActionLXDGlobalConfigEdit,
			Target: strings.Join(changed, ","),
			Result: audit.ResultOK,
		})
	}
	jsonOK(w, map[string]any{"changed": changed})
}

// HandleLXDMetricsToggle flips the metrics feature on or off as a single
// atomic operation: LXD listener + portal scraper + persisted config flag.
//
// Body: { "enabled": true|false, "force": true|false }
//
// Conflict path: when enabling and core.metrics_address is already set to a
// non-loopback address (admin had wired up an external Prometheus), the
// handler returns 409 with code "external_metrics_listener" + the current
// value, so the frontend can show the warning modal. Re-posting with
// force:true overrides.
func HandleLXDMetricsToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
		Force   bool `json:"force"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	appCfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "load app config: "+err.Error())
		return
	}

	if req.Enabled {
		if !req.Force {
			cur, err := system.GetLXDGlobalConfig()
			if err == nil && cur.MetricsAddress != "" && cur.MetricsAddress != system.LXDMetricsAddress {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]any{
					"error":   "core.metrics_address is already set to " + cur.MetricsAddress,
					"code":    "external_metrics_listener",
					"current": cur.MetricsAddress,
				})
				return
			}
		}
		if _, _, err := system.EnableLXDMetricsListener(); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		appCfg.LXDMetricsEnabled = true
	} else {
		if err := system.DisableLXDMetricsListener(); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		appCfg.LXDMetricsEnabled = false
	}
	if err := config.SaveAppConfig(appCfg); err != nil {
		jsonErr(w, http.StatusInternalServerError, "save app config: "+err.Error())
		return
	}
	sess := MustSession(r)
	result := "off"
	if req.Enabled {
		result = "on"
	}
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionLXDMetricsToggle,
		Target: result,
		Result: audit.ResultOK,
	})
	jsonOK(w, system.GetLXDMetricsStatus(appCfg.LXDMetricsEnabled))
}

// HandleLXDMetricsStatus returns the live scraper status for the UI badge.
func HandleLXDMetricsStatus(w http.ResponseWriter, r *http.Request) {
	appCfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "load app config: "+err.Error())
		return
	}
	jsonOK(w, system.GetLXDMetricsStatus(appCfg.LXDMetricsEnabled))
}

// HandleLXDInstancePerf serves the historical RRD samples for one instance.
// Same response shape as /api/perf/pool-data: { instance, tier, series }.
// Returns 404 when no per-instance file exists yet.
func HandleLXDInstancePerf(w http.ResponseWriter, r *http.Request) {
	instance := strings.TrimSpace(r.URL.Query().Get("instance"))
	if instance == "" {
		jsonErr(w, http.StatusBadRequest, "instance parameter required")
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

	db := system.GetLXDInstanceMetricsDB(instance)
	if db == nil {
		jsonErr(w, http.StatusNotFound, "no metrics history for "+instance)
		return
	}
	keys := db.Keys()
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
	jsonOK(w, map[string]any{
		"instance": instance,
		"tier":     tier,
		"series":   result,
	})
}

// HandleLXDInstanceRealtime returns a single live snapshot from
// /1.0/instances/<name>/state. The frontend polls this every 3 s while the
// Monitor tab is on screen.
func HandleLXDInstanceRealtime(w http.ResponseWriter, r *http.Request) {
	instance := strings.TrimSpace(r.URL.Query().Get("instance"))
	if instance == "" {
		jsonErr(w, http.StatusBadRequest, "instance parameter required")
		return
	}
	rt, err := system.GetLXDInstanceRealtime(instance)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, rt)
}
