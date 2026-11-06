package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"
)

// sudoersCurrentContent returns the current file content, falling back to the
// last-applied content when the file is root-readable only (hardened sudoers mode).
// Returns ("", false) when the file has never been applied.
func sudoersCurrentContent(appCfg *config.AppConfig) (content string, fromCache bool) {
	content, _ = system.GetCurrentSudoersContent()
	if content != "" {
		return content, false
	}
	// File unreadable — use the exact content we last wrote, stored in config.
	// This is correct across template changes (new builds): the stored content
	// reflects what is actually on disk, so the diff only shows genuinely new
	// commands rather than re-flagging everything already approved.
	if appCfg.SudoersAppliedContent != "" {
		return appCfg.SudoersAppliedContent, true
	}
	// Legacy fallback: re-derive from hash (pre-upgrade configs without stored content).
	if appCfg.SudoersAppliedHash != "" {
		required := system.RequiredSudoersContent()
		expected := system.BuildSudoersContent(required, appCfg.SudoersSilencedMissing, appCfg.SudoersSilencedExtra)
		if system.SudoersContentHash(expected) == appCfg.SudoersAppliedHash {
			return expected, true
		}
	}
	return "", false
}

// HandleSudoersStatus returns the availability and current state of Sudoers Hardening.
// GET /api/sudoers/status
func HandleSudoersStatus(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sudo := system.CheckSudoAccess()
		available := system.CanManageSudoers(sudo)

		missingCount, extraCount, silencedCount := 0, 0, 0
		upToDate := true
		var pendingMissingLines []string

		if appCfg.SudoersHardeningEnabled {
			current, _ := sudoersCurrentContent(appCfg)
			diff := system.ComputeSudoersDiff(current, system.RequiredSudoersContent(), appCfg.SudoersSilencedLines)
			upToDate = diff.UpToDate
			for _, d := range diff.MissingLines {
				if d.Silenced {
					silencedCount++
				} else {
					missingCount++
					pendingMissingLines = append(pendingMissingLines, d.Line)
				}
			}
			for _, d := range diff.ExtraLines {
				if d.Silenced {
					silencedCount++
				} else {
					extraCount++
				}
			}
		}
		if pendingMissingLines == nil {
			pendingMissingLines = []string{}
		}

		jsonOK(w, map[string]interface{}{
			"available":             available,
			"sudo_type":             sudo.Type,
			"enabled":               appCfg.SudoersHardeningEnabled,
			"up_to_date":            upToDate,
			"missing_count":         missingCount,
			"extra_count":           extraCount,
			"silenced_count":        silencedCount,
			"pending_missing_lines": pendingMissingLines,
		})
	}
}

// HandleSudoersDiff returns the full diff between the installed and required sudoers.
// GET /api/sudoers/diff
func HandleSudoersDiff(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		current, fromCache := sudoersCurrentContent(appCfg)
		diff := system.ComputeSudoersDiff(current, system.RequiredSudoersContent(), appCfg.SudoersSilencedLines)

		// When using cached content, cross-check effectiveness via sudo -l.
		// If sudo reports commands that should be covered by the template as missing,
		// the file likely has a syntax error — warn the user to re-apply.
		cacheWarning := ""
		if fromCache && diff.UpToDate {
			sudo := system.CheckSudoAccess()
			if sudo.Type == "hardened" && len(sudo.MissingCommands) > 0 {
				cacheWarning = "The sudoers file cannot be read directly. " +
					"The file content appears correct but sudo reports some commands as unavailable, " +
					"which usually means a syntax error in the file. " +
					"Click Apply to rewrite the file and clear the issue."
			}
		}

		type diffResp struct {
			system.SudoersDiff
			FromCache    bool   `json:"from_cache"`
			CacheWarning string `json:"cache_warning,omitempty"`
		}
		jsonOK(w, diffResp{diff, fromCache, cacheWarning})
	}
}

// HandleEnableSudoersHardening enables or disables sudoers hardening monitoring.
// POST /api/sudoers/enable
// Body: { "enabled": true | false, "remove_write_access": false }
// When enabled=false and remove_write_access=true, the handler also rewrites the
// sudoers file removing the "tee /etc/sudoers.d/zfsnas" entry (write access) while
// keeping the "cat /etc/sudoers.d/zfsnas" entry (read access for the diff view).
func HandleEnableSudoersHardening(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Enabled           bool `json:"enabled"`
			RemoveWriteAccess bool `json:"remove_write_access"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}

		action := "enabled"
		details := "sudoers hardening: enabled"

		if req.Enabled {
			// On first enable, write the complete required template with all lines
			// approved so the Review UI opens showing everything as matched rather
			// than pending. Clear any previously silenced lines.
			required := system.RequiredSudoersContent()
			if err := system.ApplySudoers(required, nil, nil); err != nil {
				jsonErr(w, http.StatusInternalServerError, "could not apply sudoers: "+err.Error())
				return
			}
			content := system.BuildSudoersContent(required, nil, nil)
			appCfg.SudoersAppliedHash = system.SudoersContentHash(content)
			appCfg.SudoersAppliedContent = content
			appCfg.SudoersSilencedMissing = []string{}
			appCfg.SudoersSilencedExtra = []string{}
			appCfg.SudoersSilencedLines = []string{}
			details = "sudoers hardening: enabled; full template applied (all lines approved)"
		}

		appCfg.SudoersHardeningEnabled = req.Enabled
		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		if !req.Enabled {
			if req.RemoveWriteAccess {
				if err := system.RemoveSudoersWriteAccess(); err != nil {
					jsonErr(w, http.StatusInternalServerError, "sudoers write-access removal failed: "+err.Error())
					return
				}
				action = "disabled (write access removed from sudoers)"
				details = "sudoers hardening: disabled; tee entry removed from /etc/sudoers.d/zfsnas"
			} else {
				action = "disabled (sudoers unchanged)"
				details = "sudoers hardening: disabled; sudoers file left as-is"
			}
		}
		_ = action

		sess := MustSession(r)
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionUpdateSudoers,
			Result:  audit.ResultOK,
			Details: details,
		})

		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleApplySudoAll writes a minimal "sudo all" sudoers entry and disables hardening.
// POST /api/sudoers/apply-sudo-all
func HandleApplySudoAll(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := system.ApplySudoAll(); err != nil {
			jsonErr(w, http.StatusInternalServerError, "apply sudo-all failed: "+err.Error())
			return
		}

		appCfg.SudoersHardeningEnabled = false
		appCfg.SudoersAppliedContent = system.SudoAllContent()
		appCfg.SudoersAppliedHash = ""
		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		sess := MustSession(r)
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionUpdateSudoers,
			Result:  audit.ResultOK,
			Details: fmt.Sprintf("sudoers replaced with unrestricted sudo-all by %s", sess.Username),
		})

		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleApplySudoers assembles and writes the sudoers file from approved changes.
// POST /api/sudoers/apply
// Body: { "silenced_missing": [...], "silenced_extra": [...], "pending_missing": [...], "pending_extra": [...] }
//
// silenced_* lines are excluded from the file AND persisted so they stay silenced next run.
// pending_* lines are excluded from the file but NOT persisted — they show as "New" next run.
func HandleApplySudoers(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SilencedMissing []string `json:"silenced_missing"`
			SilencedExtra   []string `json:"silenced_extra"`
			PendingMissing  []string `json:"pending_missing"`
			PendingExtra    []string `json:"pending_extra"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.SilencedMissing == nil {
			req.SilencedMissing = []string{}
		}
		if req.SilencedExtra == nil {
			req.SilencedExtra = []string{}
		}
		if req.PendingMissing == nil {
			req.PendingMissing = []string{}
		}
		if req.PendingExtra == nil {
			req.PendingExtra = []string{}
		}

		// Forced lines (needed by the Sudoers UI itself) can never be excluded —
		// silently drop them from any exclusion list the client may have sent.
		req.SilencedMissing = system.FilterForcedLines(req.SilencedMissing)
		req.PendingMissing = system.FilterForcedLines(req.PendingMissing)

		required := system.RequiredSudoersContent()

		// For the file write, pending lines are also excluded/kept — they just aren't persisted.
		allExcludedMissing := append(req.SilencedMissing, req.PendingMissing...)
		allKeptExtra := append(req.SilencedExtra, req.PendingExtra...)

		// Count what will actually be added/removed for the audit log.
		current, _ := sudoersCurrentContent(appCfg)
		diff := system.ComputeSudoersDiff(current, required, nil)

		excludeSet := make(map[string]bool, len(allExcludedMissing))
		for _, s := range allExcludedMissing {
			excludeSet[s] = true
		}
		keptSet := make(map[string]bool, len(allKeptExtra))
		for _, s := range allKeptExtra {
			keptSet[s] = true
		}
		addedCount, removedCount := 0, 0
		for _, d := range diff.MissingLines {
			if !excludeSet[d.Line] {
				addedCount++
			}
		}
		for _, d := range diff.ExtraLines {
			if !keptSet[d.Line] {
				removedCount++
			}
		}
		silencedCount := len(req.SilencedMissing) + len(req.SilencedExtra)

		if err := system.ApplySudoers(required, allExcludedMissing, allKeptExtra); err != nil {
			sess := MustSession(r)
			audit.Log(audit.Entry{
				User:    sess.Username,
				Role:    sess.Role,
				Action:  audit.ActionUpdateSudoers,
				Result:  audit.ResultError,
				Details: "sudoers apply failed: " + err.Error(),
			})
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Persist only the explicitly silenced decisions (not pending/new).
		// Store the full written content so the diff fallback (when the file is
		// root-readable only) always knows exactly what is installed — even after
		// the template changes in a new build.
		content := system.BuildSudoersContent(required, allExcludedMissing, allKeptExtra)
		appCfg.SudoersAppliedHash = system.SudoersContentHash(content)
		appCfg.SudoersAppliedContent = content
		appCfg.SudoersSilencedMissing = req.SilencedMissing
		appCfg.SudoersSilencedExtra = req.SilencedExtra
		appCfg.SudoersSilencedLines = append(req.SilencedMissing, req.SilencedExtra...)
		config.SaveAppConfig(appCfg)

		sess := MustSession(r)
		audit.Log(audit.Entry{
			User:   sess.Username,
			Role:   sess.Role,
			Action: audit.ActionUpdateSudoers,
			Result: audit.ResultOK,
			Details: fmt.Sprintf("sudoers apply: %d lines added, %d lines removed, %d silenced",
				addedCount, removedCount, silencedCount),
		})

		jsonOK(w, map[string]interface{}{
			"added":   addedCount,
			"removed": removedCount,
			"message": "sudoers file updated successfully",
		})
	}
}
