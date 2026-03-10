package handlers

import (
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"zfsnas/internal/config"
	"zfsnas/internal/updater"
	"zfsnas/internal/version"
	"zfsnas/system"

	"github.com/gorilla/websocket"
)

// semverGreater returns true only if a is strictly newer than b (major.minor.patch).
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

func parseSemver(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	var out [3]int
	for i, p := range parts {
		if i >= 3 {
			break
		}
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

// HandleCheckBinaryUpdate checks GitHub for a newer release.
// Version checking is always allowed regardless of LiveUpdateEnabled.
// GET /api/binary-update/check
func HandleCheckBinaryUpdate(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag, dlURL, err := updater.CheckLatest()
		if err != nil {
			if system.DebugMode {
				log.Printf("[debug] binary-update/check: CheckLatest error: %v", err)
			}
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		latest := strings.TrimPrefix(tag, "v")
		current := version.Version
		updateAvailable := semverGreater(latest, current)
		if system.DebugMode {
			log.Printf("[debug] binary-update/check: current=%s latest=%s update_available=%v download_url=%q",
				current, latest, updateAvailable, dlURL)
		}
		jsonOK(w, map[string]interface{}{
			"current":          current,
			"latest":           latest,
			"update_available": updateAvailable,
			"download_url":     dlURL,
		})
	}
}

// HandleBinaryUpdateApply streams the update progress over WebSocket, then
// atomically replaces the binary and calls syscall.Exec to restart in-place.
// WS /ws/binary-update-apply
func HandleBinaryUpdateApply(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !appCfg.LiveUpdateEnabled {
			jsonErr(w, http.StatusForbidden, "live binary update is disabled")
			return
		}

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

		send("Step 1/4: Fetching release info from GitHub…")
		tag, dlURL, err := updater.CheckLatest()
		if err != nil {
			done(false, "fetch release info failed: "+err.Error())
			return
		}
		latest := strings.TrimPrefix(tag, "v")
		if !semverGreater(latest, version.Version) {
			done(true, "already up to date (v"+version.Version+")")
			return
		}
		send("Latest release: v" + latest + "  (current: v" + version.Version + ")")

		exePath, err := updater.ExePath()
		if err != nil {
			done(false, "cannot determine executable path: "+err.Error())
			return
		}
		destDir := filepath.Dir(exePath)

		send("Step 2/4: Downloading binary to " + destDir + "…")
		tmpPath, err := updater.Download(dlURL, destDir)
		if err != nil {
			done(false, "download failed: "+err.Error())
			return
		}

		send("Step 3/4: Replacing binary at " + exePath + "…")
		if err := updater.Replace(tmpPath, exePath); err != nil {
			done(false, "replace failed: "+err.Error())
			return
		}

		send("Step 4/4: Restarting process…")
		conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]interface{}{
			"done":    true,
			"success": true,
			"message": "binary replaced — restarting now",
		}))
		conn.Close()

		// Replace process image; under systemd this keeps the service alive.
		_ = updater.Restart(exePath)
	}
}
