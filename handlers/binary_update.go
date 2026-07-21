package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/updater"
	"zfsnas/internal/version"
	"zfsnas/system"

	"github.com/gorilla/websocket"
)

// semverGreater returns true only if a is strictly newer than b.
// Supports major.minor.patch and major.minor.patch-build (e.g. 6.3.24-1).
func semverGreater(a, b string) bool {
	pa := parseSemver(a)
	pb := parseSemver(b)
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

// parseSemver parses a version string into [major, minor, patch, build].
// The build component comes from an optional "-N" suffix on the patch segment
// (e.g. "6.3.24-1" → [6, 3, 24, 1]). Missing components default to 0.
func parseSemver(v string) [4]int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	var out [4]int
	for i, p := range parts {
		if i >= 3 {
			break
		}
		if i == 2 {
			// patch may carry a "-build" suffix
			if idx := strings.IndexByte(p, '-'); idx >= 0 {
				out[3], _ = strconv.Atoi(p[idx+1:])
				p = p[:idx]
			}
		}
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

// versionCheckTTL returns the cache TTL for the given interval setting.
// Empty / unknown defaults to daily.
func versionCheckTTL(interval string) time.Duration {
	switch interval {
	case "weekly":
		return 7 * 24 * time.Hour
	case "monthly":
		return 30 * 24 * time.Hour
	case "manual":
		// Very large sentinel — effectively never auto-refresh.
		return 100 * 365 * 24 * time.Hour
	default: // "daily" or ""
		return 24 * time.Hour
	}
}

// HandleCheckBinaryUpdate checks GitHub for a newer release and verifies its signature.
// Results are cached server-side according to the configured VersionCheckInterval.
// Pass ?force=true to bypass the cache and always hit GitHub.
// Version checking is always allowed regardless of LiveUpdateEnabled.
// GET /api/binary-update/check
func HandleCheckBinaryUpdate(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		force := r.URL.Query().Get("force") == "true"
		cached := appCfg.VersionCheckCache
		interval := appCfg.VersionCheckInterval

		ttl := versionCheckTTL(interval)
		now := time.Now().Unix()

		// Return cached result if still fresh and not forced.
		if !force && cached != nil && (now-cached.CheckedAt) < int64(ttl.Seconds()) {
			// Recompute update_available against the *live* running version
			// rather than trusting the boolean stored at cache time. After an
			// Instant Update the process restarts on the new version, so the
			// stored flag (computed against the old version) would otherwise
			// keep claiming an update is available — latest == current — until
			// the cache expires or the user forces a re-check. The expensive
			// GitHub lookup stays cached; only the cheap comparison is redone.
			updateAvailable := semverGreater(cached.Latest, version.Version)
			jsonOK(w, map[string]interface{}{
				"current":           version.Version,
				"latest":            cached.Latest,
				"update_available":  updateAvailable,
				"download_url":      cached.DownloadURL,
				"sig_valid":         cached.SigValid,
				"sig_error":         cached.SigError,
				"service_installed": system.IsServiceInstalled(),
				"cached":            true,
				"checked_at":        cached.CheckedAt,
			})
			return
		}

		info, err := updater.CheckLatest()
		if err != nil {
			if system.DebugMode {
				log.Printf("[debug] binary-update/check: CheckLatest error: %v", err)
			}
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		latest := strings.TrimPrefix(info.Tag, "v")
		current := version.Version
		updateAvailable := semverGreater(latest, current)

		// Verify the release signature (downloads two tiny files: .sha256 + .sig).
		sigValid := false
		sigError := ""
		if valid, err := updater.VerifyRelease(info); err != nil {
			sigError = err.Error()
			if system.DebugMode {
				log.Printf("[debug] binary-update/check: VerifyRelease error: %v", err)
			}
		} else {
			sigValid = valid
		}

		if system.DebugMode {
			log.Printf("[debug] binary-update/check: current=%s latest=%s update_available=%v sig_valid=%v",
				current, latest, updateAvailable, sigValid)
		}

		svcInstalled := system.IsServiceInstalled()

		// Persist the result in the server-side cache.
		appCfg.VersionCheckCache = &config.VersionCacheEntry{
			CheckedAt:        now,
			Latest:           latest,
			UpdateAvailable:  updateAvailable,
			SigValid:         sigValid,
			SigError:         sigError,
			DownloadURL:      info.DownloadURL,
			ServiceInstalled: svcInstalled,
		}
		if err := config.SaveAppConfig(appCfg); err != nil {
			log.Printf("[binary-update] failed to persist version cache: %v", err)
		}

		jsonOK(w, map[string]interface{}{
			"current":           current,
			"latest":            latest,
			"update_available":  updateAvailable,
			"download_url":      info.DownloadURL,
			"sig_valid":         sigValid,
			"sig_error":         sigError,
			"service_installed": svcInstalled,
			"cached":            false,
			"checked_at":        now,
		})
	}
}

// HandleGetBinaryUpdateSettings returns current version-check and auto-update settings.
// GET /api/binary-update/settings
func HandleGetBinaryUpdateSettings(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		interval := appCfg.VersionCheckInterval
		cached := appCfg.VersionCheckCache
		if interval == "" {
			interval = "daily"
		}
		autoHour := appCfg.AutoUpdateHour
		if autoHour == 0 && !appCfg.AutoUpdateEnabled {
			autoHour = 3 // sensible default shown in UI before first save
		}
		var checkedAt int64
		if cached != nil {
			checkedAt = cached.CheckedAt
		}
		jsonOK(w, map[string]interface{}{
			"interval":            interval,
			"checked_at":          checkedAt,
			"auto_update_enabled": appCfg.AutoUpdateEnabled,
			"auto_update_hour":    autoHour,
		})
	}
}

// HandleSaveBinaryUpdateSettings saves the version-check interval and auto-update config.
// Clears the server-side version cache so the new interval takes effect immediately.
// PUT /api/binary-update/settings
func HandleSaveBinaryUpdateSettings(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Interval          string `json:"interval"`
			AutoUpdateEnabled bool   `json:"auto_update_enabled"`
			AutoUpdateHour    int    `json:"auto_update_hour"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		switch body.Interval {
		case "daily", "weekly", "monthly", "manual":
		default:
			jsonErr(w, http.StatusBadRequest, "interval must be daily, weekly, monthly, or manual")
			return
		}
		if body.AutoUpdateHour < 0 || body.AutoUpdateHour > 23 {
			jsonErr(w, http.StatusBadRequest, "auto_update_hour must be 0–23")
			return
		}
		appCfg.VersionCheckInterval = body.Interval
		// Manual Only disables auto-update regardless of what the client sent.
		if body.Interval == "manual" {
			appCfg.AutoUpdateEnabled = false
		} else {
			appCfg.AutoUpdateEnabled = body.AutoUpdateEnabled
		}
		appCfg.AutoUpdateHour = body.AutoUpdateHour
		// Clear the cache so the next check honours the new interval.
		appCfg.VersionCheckCache = nil
		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, map[string]interface{}{"ok": true})
	}
}

// doAutoUpdate performs a full update cycle without a WebSocket connection.
// Called by the scheduler goroutine at the configured hour.
func doAutoUpdate(appCfg *config.AppConfig) {
	interval := appCfg.VersionCheckInterval
	if interval == "" {
		interval = "daily"
	}
	// Manual Only means no automatic anything — guard here as well as in the scheduler.
	if interval == "manual" {
		log.Printf("[auto-update] skipping — interval is Manual Only")
		return
	}

	// Honour the interval TTL: only run if enough time has passed since the last check.
	ttl := versionCheckTTL(interval)
	if appCfg.VersionCheckCache != nil {
		elapsed := time.Since(time.Unix(appCfg.VersionCheckCache.CheckedAt, 0))
		if elapsed < ttl {
			log.Printf("[auto-update] skipping — interval not yet elapsed (%.1fh of %.1fh)", elapsed.Hours(), ttl.Hours())
			return
		}
	}

	log.Printf("[auto-update] scheduled check starting (hour=%d, interval=%s)", appCfg.AutoUpdateHour, interval)

	if !system.IsServiceInstalled() {
		log.Printf("[auto-update] skipping — ZNAS is not running as a systemd service")
		return
	}

	info, err := updater.CheckLatest()
	if err != nil {
		log.Printf("[auto-update] CheckLatest failed: %v", err)
		return
	}
	latest := strings.TrimPrefix(info.Tag, "v")
	if !semverGreater(latest, version.Version) {
		log.Printf("[auto-update] already up to date (v%s)", version.Version)
		// Refresh the server-side cache even on no-update.
		now := time.Now().Unix()
		appCfg.VersionCheckCache = &config.VersionCacheEntry{
			CheckedAt:        now,
			Latest:           latest,
			UpdateAvailable:  false,
			SigValid:         true,
			DownloadURL:      info.DownloadURL,
			ServiceInstalled: true,
		}
		config.SaveAppConfig(appCfg)
		return
	}

	log.Printf("[auto-update] new version v%s available — verifying signature…", latest)
	if valid, err := updater.VerifyRelease(info); err != nil || !valid {
		log.Printf("[auto-update] signature verification failed (%v) — aborting", err)
		return
	}

	exePath, err := updater.ExePath()
	if err != nil {
		log.Printf("[auto-update] cannot determine executable path: %v", err)
		return
	}
	destDir := filepath.Dir(exePath)

	log.Printf("[auto-update] downloading v%s…", latest)
	tmpPath, err := updater.Download(info.DownloadURL, destDir)
	if err != nil {
		log.Printf("[auto-update] download failed: %v", err)
		return
	}

	if info.SigURL != "" {
		if err := updater.VerifyDownloadedBinary(tmpPath, info.SigURL); err != nil {
			os.Remove(tmpPath)
			log.Printf("[auto-update] binary verification failed: %v", err)
			return
		}
	}

	log.Printf("[auto-update] replacing binary at %s…", exePath)
	if err := updater.Replace(tmpPath, exePath); err != nil {
		log.Printf("[auto-update] replace failed: %v", err)
		return
	}

	audit.Log(audit.Entry{
		User:    "system",
		Role:    "admin",
		Action:  audit.ActionSoftwareUpdate,
		Result:  audit.ResultOK,
		Details: "auto-updated from v" + version.Version + " to v" + latest,
	})

	// Clear the cached version so the next session sees fresh data.
	appCfg.VersionCheckCache = nil
	config.SaveAppConfig(appCfg)

	log.Printf("[auto-update] updated to v%s — restarting process", latest)
	if err := updater.Restart(exePath); err != nil {
		log.Printf("[auto-update] syscall.Exec failed (%v) — exiting for systemd restart", err)
		os.Exit(1)
	}
}

// StartAutoUpdateScheduler ticks every minute and triggers doAutoUpdate when
// the current hour matches the configured AutoUpdateHour and AutoUpdateEnabled is true.
func StartAutoUpdateScheduler(appCfg *config.AppConfig) {
	go func() {
		for {
			now := time.Now()
			// Sleep until the top of the next minute.
			next := now.Truncate(time.Minute).Add(time.Minute)
			time.Sleep(time.Until(next))

			if !appCfg.AutoUpdateEnabled || appCfg.VersionCheckInterval == "manual" {
				continue
			}
			t := time.Now()
			if t.Hour() == appCfg.AutoUpdateHour && t.Minute() == 0 {
				doAutoUpdate(appCfg)
			}
		}
	}()
}

// HandleListReleases returns the last 5 stable GitHub releases with tag, name, body, and assets.
// Pre-releases are always excluded.
// GET /api/binary-update/releases
func HandleListReleases(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		releases, err := updater.CheckReleases(5)
		if err != nil {
			jsonErr(w, http.StatusBadGateway, err.Error())
			return
		}
		jsonOK(w, releases)
	}
}

// HandleBinaryUpdateApply streams the update progress over WebSocket, verifies
// the binary hash, then atomically replaces the binary and calls syscall.Exec to restart.
// An optional ?tag= query parameter targets a specific release (used for downgrade).
// WS /ws/binary-update-apply
func HandleBinaryUpdateApply(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		send := func(line string) {
			conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]interface{}{
				"line": line,
			}))
		}
		done := func(success bool, msg string) {
			conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]interface{}{
				"done":    true,
				"success": success,
				"message": msg,
			}))
		}

		// If a specific tag is requested, target that release instead of latest.
		targetTag := strings.TrimSpace(r.URL.Query().Get("tag"))
		var info updater.ReleaseInfo
		if targetTag != "" {
			send("Step 1/5: Fetching release info for " + targetTag + " from GitHub…")
			info, err = updater.CheckRelease(targetTag)
		} else {
			send("Step 1/5: Fetching release info from GitHub…")
			info, err = updater.CheckLatest()
		}
		if err != nil {
			done(false, "fetch release info failed: "+err.Error())
			return
		}
		latest := strings.TrimPrefix(info.Tag, "v")
		// Skip the "already up to date" guard when a specific tag is requested
		// (user is intentionally downgrading to that version).
		if targetTag == "" && !semverGreater(latest, version.Version) {
			done(true, "already up to date (v"+version.Version+")")
			return
		}
		send("Target release: v" + latest + "  (current: v" + version.Version + ")")

		// Older releases may not have a .sig asset. For targeted downgrades we
		// skip both signature steps gracefully; for normal updates a missing sig
		// is still treated as a hard failure.
		hasSig := info.SigURL != ""

		send("Step 2/5: Verifying release signature…")
		if hasSig {
			if valid, err := updater.VerifyRelease(info); err != nil {
				done(false, "signature verification failed: "+err.Error())
				return
			} else if !valid {
				done(false, "signature verification failed: signature does not match release key")
				return
			}
			send("Signature valid")
		} else if targetTag != "" {
			send("No signature asset for " + targetTag + " — skipping (pre-signing release)")
		} else {
			done(false, "signature verification failed: release has no signature asset")
			return
		}

		exePath, err := updater.ExePath()
		if err != nil {
			done(false, "cannot determine executable path: "+err.Error())
			return
		}
		destDir := filepath.Dir(exePath)

		send("Step 3/5: Downloading binary to " + destDir + "…")
		tmpPath, err := updater.Download(info.DownloadURL, destDir)
		if err != nil {
			done(false, "download failed: "+err.Error())
			return
		}

		send("Step 4/5: Verifying binary signature…")
		if hasSig {
			if err := updater.VerifyDownloadedBinary(tmpPath, info.SigURL); err != nil {
				os.Remove(tmpPath)
				done(false, "signature verification failed: "+err.Error())
				return
			}
			send("Signature verified")
		} else {
			send("No signature asset — skipping post-download verification")
		}

		send("Step 5/5: Replacing binary at " + exePath + "…")
		if err := updater.Replace(tmpPath, exePath); err != nil {
			done(false, "replace failed: "+err.Error())
			return
		}

		sess := MustSession(r)
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionSoftwareUpdate,
			Result:  audit.ResultOK,
			Details: "updated from v" + version.Version + " to v" + latest,
		})

		send("Restarting process…")
		conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]interface{}{
			"done":    true,
			"success": true,
			"message": "binary replaced — restarting now",
		}))
		conn.Close()

		// Preferred path: replace process image in-place (same PID, no systemd restart event).
		if err := updater.Restart(exePath); err != nil {
			// syscall.Exec can fail on some systems (thread state, security policies, etc.).
			// Fall back to a clean exit so systemd (Restart=on-failure or Restart=always)
			// relaunches the service and picks up the new binary already on disk.
			log.Printf("[updater] syscall.Exec failed (%v) — exiting so systemd restarts with new binary", err)
			os.Exit(1)
		}
	}
}
