package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/system"
)

// smtpPasswordMask is the sentinel returned by GET and recognised by PUT to mean
// "secret already set — keep existing value unchanged". It is reused for every
// notification secret (SMTP password, ntfy/gotify tokens, pushover keys) so a
// non-admin who can read the alert config never receives any secret in cleartext.
const smtpPasswordMask = "••••••••"

// maskSecret replaces a non-empty secret with the mask sentinel.
func maskSecret(s string) string {
	if s != "" {
		return smtpPasswordMask
	}
	return ""
}

// unmaskSecret returns existing when the caller sent the mask sentinel back
// (meaning "leave unchanged"), otherwise the new value as supplied.
func unmaskSecret(supplied, existing string) string {
	if supplied == smtpPasswordMask {
		return existing
	}
	return supplied
}

// HandleGetAlerts returns the current alert configuration with all notification
// secrets masked (never returned in cleartext, regardless of caller role).
func HandleGetAlerts(w http.ResponseWriter, r *http.Request) {
	cfg, err := alerts.Load()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load alert config")
		return
	}
	cfg.Email.SMTP.Password = maskSecret(cfg.Email.SMTP.Password)
	cfg.Ntfy.Token = maskSecret(cfg.Ntfy.Token)
	cfg.Gotify.Token = maskSecret(cfg.Gotify.Token)
	cfg.Pushover.UserKey = maskSecret(cfg.Pushover.UserKey)
	cfg.Pushover.APIToken = maskSecret(cfg.Pushover.APIToken)
	jsonOK(w, cfg)
}

// HandleUpdateAlerts saves the alert configuration (admin only).
func HandleUpdateAlerts(w http.ResponseWriter, r *http.Request) {
	var cfg alerts.AlertConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Preserve existing secrets when the UI sends back the mask sentinel
	// (the GET handler masks every secret, so an unchanged form round-trips
	// the mask rather than the real value).
	if existing, err := alerts.Load(); err == nil {
		cfg.Email.SMTP.Password = unmaskSecret(cfg.Email.SMTP.Password, existing.Email.SMTP.Password)
		cfg.Ntfy.Token = unmaskSecret(cfg.Ntfy.Token, existing.Ntfy.Token)
		cfg.Gotify.Token = unmaskSecret(cfg.Gotify.Token, existing.Gotify.Token)
		cfg.Pushover.UserKey = unmaskSecret(cfg.Pushover.UserKey, existing.Pushover.UserKey)
		cfg.Pushover.APIToken = unmaskSecret(cfg.Pushover.APIToken, existing.Pushover.APIToken)
	} else {
		// Can't load existing values; never persist the mask sentinel as a secret.
		cfg.Email.SMTP.Password = unmaskSecret(cfg.Email.SMTP.Password, "")
		cfg.Ntfy.Token = unmaskSecret(cfg.Ntfy.Token, "")
		cfg.Gotify.Token = unmaskSecret(cfg.Gotify.Token, "")
		cfg.Pushover.UserKey = unmaskSecret(cfg.Pushover.UserKey, "")
		cfg.Pushover.APIToken = unmaskSecret(cfg.Pushover.APIToken, "")
	}
	if err := alerts.Save(&cfg); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save alert config")
		return
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionUpdateSettings,
		Result:  audit.ResultOK,
		Details: "notification settings updated",
	})
	jsonOK(w, map[string]string{"message": "notification settings saved"})
}

// HandleTestAlert sends a test alert to all currently enabled targets.
func HandleTestAlert(w http.ResponseWriter, r *http.Request) {
	if err := alerts.Send(
		alerts.EventTest,
		"Test Alert",
		"Manual Test",
		"This is a test alert from the ZFS NAS management portal.",
	); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to dispatch test alerts: "+err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "test alert dispatched to all enabled targets"})
}

// HandleTestAlertEmail sends a test email regardless of the enabled flag.
func HandleTestAlertEmail(w http.ResponseWriter, r *http.Request) {
	if err := alerts.TestEmail(); err != nil {
		jsonErr(w, http.StatusBadGateway, "failed to send test email: "+err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "test email sent"})
}

// HandleTestAlertNtfy sends a test ntfy notification.
func HandleTestAlertNtfy(w http.ResponseWriter, r *http.Request) {
	if err := alerts.TestNtfy(); err != nil {
		jsonErr(w, http.StatusBadGateway, "failed to send test ntfy notification: "+err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "test ntfy notification sent"})
}

// HandleTestAlertGotify sends a test Gotify notification.
func HandleTestAlertGotify(w http.ResponseWriter, r *http.Request) {
	if err := alerts.TestGotify(); err != nil {
		jsonErr(w, http.StatusBadGateway, "failed to send test Gotify notification: "+err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "test Gotify notification sent"})
}

// HandleTestAlertPushover sends a test Pushover notification.
func HandleTestAlertPushover(w http.ResponseWriter, r *http.Request) {
	if err := alerts.TestPushover(); err != nil {
		jsonErr(w, http.StatusBadGateway, "failed to send test Pushover notification: "+err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "test Pushover notification sent"})
}

// HandleTestAlertSyslog sends a test syslog message.
func HandleTestAlertSyslog(w http.ResponseWriter, r *http.Request) {
	if err := alerts.TestSyslog(); err != nil {
		jsonErr(w, http.StatusBadGateway, "failed to send test syslog message: "+err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "test syslog message sent"})
}

// HandleTestAlertWebSocket broadcasts a test notification to all connected browser sessions.
func HandleTestAlertWebSocket(w http.ResponseWriter, r *http.Request) {
	alerts.TestWebSocket()
	jsonOK(w, map[string]string{"message": "test in-app notification broadcast"})
}

// HandleAlertsWS upgrades the connection and registers it with the AlertsHub.
// The session role is captured so role-scoped broadcasts (e.g.,
// interlink-relay-forwarded alerts → admins only) can target appropriately.
//
// Server-to-server interlink-relay subscriber connections (identified by the
// X-Interlink-Relay-User header) register with role "interlink" so the local
// BroadcastJSONToAdmins fan-out does NOT echo back to the originating peer —
// that would create a feedback loop between the two hubs.
func HandleAlertsWS(w http.ResponseWriter, r *http.Request) {
	hub := alerts.GetHub()
	if hub == nil {
		jsonErr(w, http.StatusServiceUnavailable, "alerts websocket hub not initialised")
		return
	}
	sess := MustSession(r)
	role := sess.Role
	if r.Header.Get("X-Interlink-Relay-User") != "" {
		role = "interlink"
	}
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	hub.Register(conn, role)
}

const alertDedup = 24 * time.Hour

// BroadcastAlertJSON pushes a custom payload to every connected
// /ws/alerts session. Used by the incus health watchdog to ship a
// `{kind:"incus_stuck", persistent:true, …}` envelope the frontend
// promotes to a persistent red banner (instead of an auto-dismiss
// toast). Returns silently if the hub isn't initialised yet — startup
// race shouldn't crash the watchdog.
func BroadcastAlertJSON(v any) {
	if hub := alerts.GetHub(); hub != nil {
		hub.BroadcastJSON(v)
	}
}

// HandleIncusHealth serves the current daemon health state. The browser
// hits this on page load so the persistent banner can rehydrate after a
// hard refresh — without it, the user would need to wait up to 30 s for
// the next watcher tick to learn the daemon is stuck.
// GET /api/incus/health
func HandleIncusHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, system.IncusHealth())
}

// isSmartUnsupported returns true when a disk has no genuine SMART failure.
func isSmartUnsupported(msg string) bool {
	switch msg {
	case "", "Not supported", "smartctl unavailable", "parse error":
		return true
	}
	return false
}

// isBadPoolHealth returns true for pool states that represent a problem.
func isBadPoolHealth(h string) bool {
	switch h {
	case "DEGRADED", "FAULTED", "SUSPENDED", "UNAVAIL", "REMOVED":
		return true
	}
	return false
}

// ── Shared health-event state ─────────────────────────────────────────────────

var (
	healthEvMu             sync.Mutex
	healthEvPoolStates     = map[string]string{}
	healthEvMemberStates   = map[string][]string{}
	lastNotifiedPoolHealth = map[string]string{} // pool name → health at last notification send
	healthStatePath        string                // set by StartHealthPoller
)

type persistedHealthState struct {
	PoolStates     map[string]string   `json:"pool_states"`
	MemberStates   map[string][]string `json:"member_states"`
	NotifiedHealth map[string]string   `json:"notified_health"`
}

func loadHealthState(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return // file doesn't exist yet — start fresh
	}
	var s persistedHealthState
	if err := json.Unmarshal(data, &s); err != nil {
		log.Printf("alerts: failed to parse health state: %v", err)
		return
	}
	if s.PoolStates != nil {
		healthEvPoolStates = s.PoolStates
	}
	if s.MemberStates != nil {
		healthEvMemberStates = s.MemberStates
	}
	if s.NotifiedHealth != nil {
		lastNotifiedPoolHealth = s.NotifiedHealth
	}
}

// saveHealthState writes the current health maps to disk. Must be called under healthEvMu.
func saveHealthState() {
	if healthStatePath == "" {
		return
	}
	s := persistedHealthState{
		PoolStates:     healthEvPoolStates,
		MemberStates:   healthEvMemberStates,
		NotifiedHealth: lastNotifiedPoolHealth,
	}
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	tmp := healthStatePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, healthStatePath)
}

// LogPoolHealthEvents checks for pool/disk state changes and writes audit entries.
func LogPoolHealthEvents(pool *system.Pool) {
	if pool == nil {
		return
	}
	healthEvMu.Lock()
	defer healthEvMu.Unlock()

	prevHealth := healthEvPoolStates[pool.Name]
	currHealth := pool.Health
	currBad    := isBadPoolHealth(currHealth)
	prevBad    := isBadPoolHealth(prevHealth)

	if currBad && prevHealth != currHealth {
		audit.Log(audit.Entry{
			User:    "system",
			Role:    "system",
			Action:  audit.ActionPoolProblem,
			Target:  pool.Name,
			Result:  audit.ResultError,
			Details: "pool health: " + currHealth,
		})
	} else if !currBad && prevBad {
		audit.Log(audit.Entry{
			User:    "system",
			Role:    "system",
			Action:  audit.ActionPoolRecovered,
			Target:  pool.Name,
			Result:  audit.ResultOK,
			Details: "pool health restored: " + currHealth,
		})
		// Re-arm notification so the next degradation triggers a fresh alert.
		delete(lastNotifiedPoolHealth, pool.Name)
	}
	healthEvPoolStates[pool.Name] = currHealth

	prevStatuses := healthEvMemberStates[pool.Name]
	for i, currStatus := range pool.MemberStatuses {
		var prevStatus string
		if i < len(prevStatuses) {
			prevStatus = prevStatuses[i]
		}
		dev := ""
		if i < len(pool.MemberDevices) && pool.MemberDevices[i] != "" {
			dev = pool.MemberDevices[i]
		} else if i < len(pool.Members) {
			dev = pool.Members[i]
		}
		currDiskBad := currStatus != "ONLINE"
		prevDiskBad := prevStatus != "ONLINE" && prevStatus != ""

		if currDiskBad && prevStatus != currStatus {
			audit.Log(audit.Entry{
				User:    "system",
				Role:    "system",
				Action:  audit.ActionDiskProblem,
				Target:  pool.Name,
				Result:  audit.ResultError,
				Details: dev + " status: " + currStatus,
			})
		} else if !currDiskBad && prevDiskBad {
			audit.Log(audit.Entry{
				User:    "system",
				Role:    "system",
				Action:  audit.ActionDiskRecovered,
				Target:  pool.Name,
				Result:  audit.ResultOK,
				Details: dev + " recovered: ONLINE",
			})
		}
	}
	healthEvMemberStates[pool.Name] = append([]string{}, pool.MemberStatuses...)
	saveHealthState()
}

// StartHealthPoller launches a background goroutine that checks pool health
// and disk wearout every 5 minutes and dispatches alerts to all enabled targets.
func StartHealthPoller(configDir string) {
	healthEvMu.Lock()
	healthStatePath = configDir + "/health_state.json"
	loadHealthState(healthStatePath)
	healthEvMu.Unlock()

	go func() {
		lastWearoutAlerted  := map[string]time.Time{}
		lastSmartAlerted    := map[string]time.Time{}
		lastScrubState      := map[string]string{}   // pool → last seen scrub state
		lastPoolDataErrors  := map[string]bool{}     // pool → had permanent data errors last poll
		lastSecUpdatesCheck := time.Time{}
		secUpdatesArmed     := true // fires on first occurrence; re-arms once updates are gone

		time.Sleep(30 * time.Second)
		runHealthCheck(lastWearoutAlerted, lastSmartAlerted, lastScrubState, lastPoolDataErrors, &lastSecUpdatesCheck, &secUpdatesArmed, configDir)

		tick := time.NewTicker(5 * time.Minute)
		defer tick.Stop()
		for range tick.C {
			runHealthCheck(lastWearoutAlerted, lastSmartAlerted, lastScrubState, lastPoolDataErrors, &lastSecUpdatesCheck, &secUpdatesArmed, configDir)
		}
	}()
}

// anyTargetWantsEvent returns true if at least one enabled target subscribes to
// the event. Delegates to the alerts package so every EventKey is covered — a
// local copy of the matching switch only knew smart_error/wearout_exceeded,
// which silently disabled the scrub-errors and security-updates polling gates.
func anyTargetWantsEvent(cfg *alerts.AlertConfig, key alerts.EventKey) bool {
	return alerts.AnyTargetWants(cfg, key)
}

func runHealthCheck(
	lastWearoutAlerted  map[string]time.Time,
	lastSmartAlerted    map[string]time.Time,
	lastScrubState      map[string]string,
	lastPoolDataErrors  map[string]bool,
	lastSecUpdatesCheck *time.Time,
	secUpdatesArmed     *bool,
	configDir string,
) {
	cfg, err := alerts.Load()
	if err != nil {
		log.Printf("alerts: failed to load config: %v", err)
		return
	}

	// --- Pool health ---
	pools, err := system.GetAllPools()
	if err == nil {
		for _, pool := range pools {
			healthEvMu.Lock()
			prevNotified := lastNotifiedPoolHealth[pool.Name]
			healthEvMu.Unlock()

			LogPoolHealthEvents(pool)

			if isBadPoolHealth(pool.Health) && prevNotified != pool.Health {
				healthEvMu.Lock()
				lastNotifiedPoolHealth[pool.Name] = pool.Health
				saveHealthState()
				healthEvMu.Unlock()
				name, h := pool.Name, pool.Health
				go func() {
					alerts.Send(
						alerts.EventPoolDegraded,
						"Pool health: "+h,
						"Pool Health Degraded",
						fmt.Sprintf("Pool '%s' is in state: %s", name, h),
					)
				}()
			}
		}
	}

	// --- Disk SMART + wearout ---
	checkSmart   := anyTargetWantsEvent(cfg, alerts.EventSmartError)
	checkWearout := anyTargetWantsEvent(cfg, alerts.EventWearoutExceeded)
	_, wearThr   := alerts.MinWearoutThreshold(cfg)

	if checkSmart || checkWearout {
		disks, diskErr := system.ListDisks(configDir)
		if diskErr != nil {
			return
		}
		now := time.Now()

		for _, d := range disks {
			if checkSmart && !d.SmartOK && !isSmartUnsupported(d.SmartMsg) {
				if last, seen := lastSmartAlerted[d.Name]; !seen || now.Sub(last) >= alertDedup {
					lastSmartAlerted[d.Name] = now
					name, msg := d.Name, d.SmartMsg
					go func() {
						alerts.Send(
							alerts.EventSmartError,
							"SMART error on "+name,
							"SMART Error Detected",
							fmt.Sprintf("Disk %s reports a SMART error: %s", name, msg),
						)
					}()
				}
			} else if d.SmartOK {
				delete(lastSmartAlerted, d.Name)
			}

			if checkWearout && wearThr > 0 && d.WearoutPct != nil {
				if *d.WearoutPct >= wearThr {
					if last, seen := lastWearoutAlerted[d.Name]; !seen || now.Sub(last) >= alertDedup {
						lastWearoutAlerted[d.Name] = now
						name, pct := d.Name, *d.WearoutPct
						go func() {
							alerts.Send(
								alerts.EventWearoutExceeded,
								fmt.Sprintf("Disk wearout: %s at %d%%", name, pct),
								"Disk Wearout Threshold Exceeded",
								fmt.Sprintf("Disk %s has reached %d%% wearout (threshold: %d%%)", name, pct, wearThr),
							)
						}()
					}
				} else {
					delete(lastWearoutAlerted, d.Name)
				}
			}
		}
	}

	// --- Failed login threshold ---
	enabled, threshold := alerts.MinFailedLoginThreshold(cfg)
	if enabled && threshold > 0 {
		count := alerts.FailedLoginCount()
		if count >= int64(threshold) {
			alerts.ResetFailedLogins()
			go func(n int64) {
				alerts.Send(
					alerts.EventFailedLogin,
					fmt.Sprintf("Failed logins: %d attempts", n),
					"Failed Login Threshold Exceeded",
					fmt.Sprintf("%d failed login attempts were detected since the last reset.", n),
				)
			}(count)
		}
	}

	// --- Permanent data errors — a pool that is ONLINE yet has lost file data ---
	//
	// Unlike scrub_errors this is a CONDITION, not an event: it persists until
	// the user repairs it. So an unknown → true transition (the first poll after
	// startup) fires too. A restart re-alerting on a still-present fault is
	// correct — the absence of that is why a real incident sat unnoticed for
	// eight days while the pool showed ONLINE and green.
	if anyTargetWantsEvent(cfg, alerts.EventPoolDataErrors) {
		pools, err := system.GetAllPools()
		if err == nil {
			for _, pool := range pools {
				prev, seen := lastPoolDataErrors[pool.Name]
				lastPoolDataErrors[pool.Name] = pool.DataErrors
				switch {
				case pool.DataErrors && (!seen || !prev):
					name, n := pool.Name, pool.DataErrorCount
					files := pool.DataErrorFiles
					go func() {
						detail := ""
						for i, f := range files {
							if i == 5 {
								detail += fmt.Sprintf("\n… and %d more", len(files)-5)
								break
							}
							detail += "\n" + f
						}
						alerts.Send(
							alerts.EventPoolDataErrors,
							fmt.Sprintf("Permanent data errors on pool %s", name),
							"ZFS Pool Has Permanent Data Errors",
							fmt.Sprintf("Pool '%s' reports %d permanent data error(s). These blocks cannot be "+
								"repaired by scrub, resilver or 'zpool clear' — the affected files must be "+
								"restored. Open the Pool Fixer for the affected file list and recovery "+
								"steps.%s", name, n, detail),
						)
					}()
				case !pool.DataErrors && seen && prev:
					name := pool.Name
					go func() {
						alerts.Send(
							alerts.EventPoolDataErrors,
							fmt.Sprintf("Data errors cleared on pool %s", name),
							"ZFS Pool Data Errors Cleared",
							fmt.Sprintf("Pool '%s' no longer reports permanent data errors.", name),
						)
					}()
				}
			}
		}
	}

	// --- Scrub errors — detect transition from running → finished with errors > 0 ---
	if anyTargetWantsEvent(cfg, alerts.EventScrubErrors) {
		pools, err := system.GetAllPools()
		if err == nil {
			for _, pool := range pools {
				info, err := system.GetScrubStatus(pool.Name)
				if err != nil || info == nil {
					continue
				}
				prev := lastScrubState[pool.Name]
				lastScrubState[pool.Name] = info.State
				if prev == "running" && info.State == "finished" && info.Errors > 0 {
					name, errs := pool.Name, info.Errors
					go func() {
						alerts.Send(
							alerts.EventScrubErrors,
							fmt.Sprintf("Scrub errors on pool %s", name),
							"ZFS Scrub Completed With Errors",
							fmt.Sprintf("Pool '%s' scrub finished with %d error(s). Run 'zpool status %s' for details.", name, errs, name),
						)
					}()
				}
			}
		}
	}

	// --- Security updates — daily check; fires once, re-arms only when updates clear ---
	if anyTargetWantsEvent(cfg, alerts.EventSecurityUpdates) && time.Since(*lastSecUpdatesCheck) >= 24*time.Hour {
		*lastSecUpdatesCheck = time.Now()
		out, err := exec.Command("apt-get", "--simulate", "upgrade").Output()
		if err == nil {
			var secPkgs []string
			scanner := bufio.NewScanner(strings.NewReader(string(out)))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "Inst ") && strings.Contains(line, "-security") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						secPkgs = append(secPkgs, parts[1])
					}
				}
			}
			if len(secPkgs) > 0 {
				// Only notify if armed (i.e. we haven't already fired for this batch).
				if *secUpdatesArmed {
					*secUpdatesArmed = false
					count := len(secPkgs)
					list := strings.Join(secPkgs, ", ")
					go func() {
						alerts.Send(
							alerts.EventSecurityUpdates,
							fmt.Sprintf("%d security update(s) available", count),
							"OS Security Updates Available",
							fmt.Sprintf("%d security package(s) have updates available: %s", count, list),
						)
					}()
				}
			} else {
				// No pending security updates — re-arm so the next occurrence fires.
				*secUpdatesArmed = true
			}
		}
	}
}
