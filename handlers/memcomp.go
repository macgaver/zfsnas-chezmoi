package handlers

// HTTP surface for memory compression (zram-tools).
//
// Three endpoints, all admin-only:
//   GET  /api/memcomp/status              live status + config
//   PUT  /api/memcomp/config              apply (enable / disable / reconfigure)
//   POST /api/memcomp/install-prereqs     async install via WebSocket stream

import (
	"encoding/json"
	"fmt"
	"net/http"

	"zfsnas/internal/audit"
	"zfsnas/system"
)

// HandleMemCompStatus returns the current zram-tools state and live counters.
// GET /api/memcomp/status
func HandleMemCompStatus(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, system.GetMemCompStatus())
}

// HandleMemCompConfig applies a new configuration. The request body is the
// MemCompConfig struct in system/memcomp.go.
//
// Three response shapes:
//   - 200 + status snapshot — applied live (Outcome.Status="applied").
//   - 200 + outcome JSON    — saved for next reboot (Outcome.Status="deferred",
//     requested by the UI with Mode="defer").
//   - 409 + outcome JSON    — needs_decision: too much data is currently
//     held in zram to safely shrink it now. The body
//     carries OrigDataBytes/HeadroomBytes so the UI
//     can show the user the breakdown and offer the
//     "wait & retry" or "apply on next reboot" paths.
//
// Hard errors (validation, systemctl) still return 500/400 with {error: …}.
// PUT /api/memcomp/config
func HandleMemCompConfig(w http.ResponseWriter, r *http.Request) {
	var cfg system.MemCompConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	sess := MustSession(r)
	prev := system.GetMemCompStatus()

	outcome, err := system.ApplyMemCompConfig(cfg)
	if err != nil {
		audit.Log(audit.Entry{
			User: sess.Username, Role: sess.Role,
			Action: audit.ActionMemCompConfig, Result: audit.ResultError,
			Details: err.Error(),
		})
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if outcome.Status == "needs_decision" {
		// 409 Conflict — the UI shows its 3-button modal and re-calls this
		// endpoint with Mode="defer" or after the user has freed memory.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(outcome)
		return
	}

	// Pick the right audit action so the audit log differentiates between
	// "first turn-on", "shut off", and "tweak in place" — and tag deferred
	// applies so an admin grepping the log can see why a host's live state
	// disagrees with its on-disk config until the next reboot.
	action := audit.ActionMemCompConfig
	switch {
	case cfg.Enabled && !prev.Enabled:
		action = audit.ActionMemCompEnable
	case !cfg.Enabled && prev.Enabled:
		action = audit.ActionMemCompDisable
	}
	audit.Log(audit.Entry{
		User: sess.Username, Role: sess.Role,
		Action: action, Result: audit.ResultOK,
		Details: fmt.Sprintf("enabled=%v percent_ram=%d algorithm=%s mode=%s",
			cfg.Enabled, cfg.PercentRAM, cfg.Algorithm, outcome.Status),
	})

	if outcome.Status == "deferred" {
		jsonOK(w, outcome)
		return
	}
	jsonOK(w, system.GetMemCompStatus())
}

// HandleMemCompInstallPrereqs upgrades to a WebSocket and streams `apt-get
// install -y zram-tools` output, mirroring the pattern in HandleInstallPrereqs.
// POST /api/memcomp/install-prereqs
func HandleMemCompInstallPrereqs(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	send := func(line string) {
		conn.WriteMessage(1, mustJSON(map[string]interface{}{"line": line})) //nolint:errcheck
	}
	done := func(success bool, msg string) {
		conn.WriteMessage(1, mustJSON(map[string]interface{}{ //nolint:errcheck
			"done": true, "success": success, "message": msg,
		}))
	}

	sess := MustSession(r)
	send("Running: sudo apt-get install -y zram-tools")
	send("─────────────────────────────────────────")

	// Serialise against other apt operations using the existing mutex.
	aptInstallMu.Lock()
	defer aptInstallMu.Unlock()

	if err := system.InstallMemCompPrereqs(send); err != nil {
		send("Error: " + err.Error())
		audit.Log(audit.Entry{
			User: sess.Username, Role: sess.Role,
			Action: audit.ActionMemCompInstall, Result: audit.ResultError,
			Details: err.Error(),
		})
		done(false, err.Error())
		return
	}
	send("─────────────────────────────────────────")
	send("Installation completed successfully.")
	audit.Log(audit.Entry{
		User: sess.Username, Role: sess.Role,
		Action: audit.ActionMemCompInstall, Result: audit.ResultOK,
		Details: "installed: zram-tools",
	})
	done(true, "zram-tools installed")
}
