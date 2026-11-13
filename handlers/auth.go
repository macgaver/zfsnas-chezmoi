package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"strings"
	"time"
	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/session"
	"zfsnas/internal/totp"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"zfsnas/system"
)

// HandleSetupPage serves the first-run setup HTML page.
func HandleSetupPage(staticContent func(name string) ([]byte, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If users already exist, redirect to login.
		users, _ := config.LoadUsers()
		if len(users) > 0 {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// A USB stick whose settings were moved to an internal disk: never
		// offer a fresh setup (it would look like a reset), say where they went.
		if system.ApplianceMode() && system.PersistStatus() == "moved" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			w.Write([]byte(settingsMovedPage(system.ApplianceMediumInfo().MovedTo)))
			return
		}
		data, err := staticContent("setup.html")
		if err != nil {
			http.Error(w, "setup page not found", http.StatusInternalServerError)
			return
		}
		// SSH for the first admin is on by default only on the appliance,
		// where SSH is otherwise locked; on a regular server the owner
		// already has shell access and opts in.
		sshDefault := ""
		if system.ApplianceMode() {
			sshDefault = "checked"
		}
		data = bytes.ReplaceAll(data, []byte("{{SSH_LOGIN_DEFAULT}}"), []byte(sshDefault))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(data)
	}
}

// HandleLoginPage serves the login HTML page.
func HandleLoginPage(staticContent func(name string) ([]byte, error), appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If already logged in, redirect to app.
		if _, ok := SessionFromRequest(r); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		// First start, no account yet: there is nobody to sign in as, so send
		// the visitor to /setup (they reach / → /login without having read
		// the docs). A users.json that can't be read is not "no users".
		if users, err := config.LoadUsers(); err == nil && len(users) == 0 {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		data, err := staticContent("login.html")
		if err != nil {
			http.Error(w, "login page not found", http.StatusInternalServerError)
			return
		}
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "localhost"
		}
		title := "ZNAS - " + strings.ToUpper(hostname)
		data = bytes.Replace(data, []byte("<title>ZFS NAS — Sign In</title>"), []byte("<title>"+title+"</title>"), 1)
		theme := appCfg.LoginTheme
		if theme == "" {
			theme = "dark"
		}
		data = bytes.Replace(data, []byte("localStorage.getItem('login_theme') || 'dark'"), []byte("'"+theme+"'"), 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(data)
	}
}

// HandleSetup processes first-run admin account creation.
func HandleSetup(w http.ResponseWriter, r *http.Request) {
	if system.ApplianceMode() && system.PersistStatus() == "moved" {
		jsonErr(w, http.StatusConflict, "this USB stick's settings were moved to an internal disk: start the server from that disk")
		return
	}
	users, err := config.LoadUsers()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load users")
		return
	}
	if len(users) > 0 {
		jsonErr(w, http.StatusForbidden, "setup already completed")
		return
	}

	var req struct {
		Username        string `json:"username"`
		Email           string `json:"email"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
		// SSHLogin also creates a Linux account with this name and password so
		// the first admin can reach a shell. On the USB appliance that is the
		// only way in besides the portal, which is why the wizard ticks it.
		SSHLogin bool `json:"ssh_login"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)

	if req.Username == "" || req.Email == "" || req.Password == "" {
		jsonErr(w, http.StatusBadRequest, "username, email, and password are required")
		return
	}
	if req.Password != req.ConfirmPassword {
		jsonErr(w, http.StatusBadRequest, "passwords do not match")
		return
	}
	if len(req.Password) < 8 {
		jsonErr(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	user := config.User{
		ID:           newID(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hash),
		Role:         config.RoleAdmin,
		CreatedAt:    time.Now(),
	}

	if err := config.SaveUsers([]config.User{user}); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save user")
		return
	}

	audit.Log(audit.Entry{
		User:    req.Username,
		Role:    config.RoleAdmin,
		Action:  audit.ActionSetupAdmin,
		Target:  req.Username,
		Result:  audit.ResultOK,
		Details: "first admin account created",
	})

	msg := "admin account created"
	if req.SSHLogin {
		// Best-effort: the portal account is already created and usable, so a
		// failure here must not fail setup — report it instead of rolling back
		// an account the user just typed a password for.
		if err := system.EnsureShellUser(req.Username, req.Password); err != nil {
			msg += " (SSH login could not be enabled: " + err.Error() + ")"
		} else {
			msg += "; SSH login enabled"
			// This account is an admin by definition, and on the appliance it
			// is the only way into a shell — so give it the sudo group and a
			// working `sudo -s` (prompting for its own password). Best-effort
			// like the rest of this block: never fail a completed setup.
			if err := system.EnsureSudoAccess(req.Username); err != nil {
				msg += " (sudo access could not be granted: " + err.Error() + ")"
			} else {
				msg += " with sudo access"
			}
		}
	}
	jsonOK(w, map[string]string{"message": msg})
}

// sessionDurationsFor turns the configured WebSessionPolicy into the
// (hard cap, idle timeout) pair the session.Store wants. In default
// mode idle timeout is 0 (only the hard cap applies); in inactivity
// mode the hard cap is a very long fallback (30 days) so an actively
// used session can't drift forever.
func sessionDurationsFor(p config.WebSessionPolicy) (time.Duration, time.Duration) {
	if p.Mode == config.WebSessionModeInactivity {
		return session.InactivityHardCap, time.Duration(p.IdleTimeoutMinutes) * time.Minute
	}
	return session.DefaultSessionDuration, 0
}

// HandleLogin authenticates a user and creates a session.
func HandleLogin(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)

		// Rate limit check — before any DB access so brute-force is cheap to block.
		if locked, retryAfter := loginLimiter.check(ip); locked {
			secs := int(retryAfter.Seconds()) + 1
			w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
			jsonErr(w, http.StatusTooManyRequests,
				fmt.Sprintf("too many failed attempts — try again in %d seconds", secs))
			return
		}

		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}

		users, err := config.LoadUsers()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to load users")
			return
		}

		user := config.FindUserByUsername(users, strings.TrimSpace(req.Username))
		if user == nil || user.Role == config.RoleSMBOnly {
			loginLimiter.recordFailure(ip)
			alerts.RecordFailedLogin()
			audit.Log(audit.Entry{
				User:    req.Username,
				Action:  audit.ActionLoginFailed,
				Result:  audit.ResultError,
				Details: "user not found or SMB-only account (from " + ip + ")",
			})
			jsonErr(w, http.StatusUnauthorized, "invalid username or password")
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
			loginLimiter.recordFailure(ip)
			alerts.RecordFailedLogin()
			audit.Log(audit.Entry{
				User:    req.Username,
				Role:    user.Role,
				Action:  audit.ActionLoginFailed,
				Result:  audit.ResultError,
				Details: "incorrect password (from " + ip + ")",
			})
			jsonErr(w, http.StatusUnauthorized, "invalid username or password")
			return
		}

		// If TOTP is enabled, return a short-lived pending token instead of a full session.
		if user.TOTPEnabled {
			pendingToken, err := session.CreatePendingTOTP(user.ID, user.Username, user.Role)
			if err != nil {
				jsonErr(w, http.StatusInternalServerError, "failed to create pending session")
				return
			}
			// Password was correct — reset failure count so TOTP step starts clean.
			loginLimiter.recordSuccess(ip)
			alerts.ResetFailedLogins()
			jsonOK(w, map[string]interface{}{
				"totp_required": true,
				"pending_token": pendingToken,
			})
			return
		}

		hardCap, idle := sessionDurationsFor(appCfg.WebSession)
		sess, err := session.Default.Create(user.ID, user.Username, user.Role, hardCap, idle)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to create session")
			return
		}

		loginLimiter.recordSuccess(ip)
		alerts.ResetFailedLogins()
		audit.Log(audit.Entry{
			User:    user.Username,
			Role:    user.Role,
			Action:  audit.ActionLogin,
			Result:  audit.ResultOK,
			Details: "from " + ip,
		})

		SetSessionCookie(w, sess.Token, hardCap)
		jsonOK(w, map[string]interface{}{
			"username": user.Username,
			"role":     user.Role,
		})
	}
}

// HandleTOTPLogin completes two-step login by verifying a TOTP code.
func HandleTOTPLogin(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)

		if locked, retryAfter := loginLimiter.check(ip); locked {
			secs := int(retryAfter.Seconds()) + 1
			w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
			jsonErr(w, http.StatusTooManyRequests,
				fmt.Sprintf("too many failed attempts — try again in %d seconds", secs))
			return
		}

		var req struct {
			PendingToken string `json:"pending_token"`
			Code         string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}

		pending, ok := session.ConsumePendingTOTP(req.PendingToken)
		if !ok {
			jsonErr(w, http.StatusUnauthorized, "invalid or expired session")
			return
		}

		// Load user to get TOTP secret.
		users, err := config.LoadUsers()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to load users")
			return
		}
		user := config.FindUserByID(users, pending.UserID)
		if user == nil || !user.TOTPEnabled {
			jsonErr(w, http.StatusUnauthorized, "invalid session")
			return
		}

		if !totp.Verify(user.TOTPSecret, strings.TrimSpace(req.Code)) {
			loginLimiter.recordFailure(ip)
			audit.Log(audit.Entry{
				User:    pending.Username,
				Role:    pending.Role,
				Action:  audit.ActionLoginFailed,
				Result:  audit.ResultError,
				Details: "invalid TOTP code (from " + ip + ")",
			})
			jsonErr(w, http.StatusUnauthorized, "invalid authentication code")
			return
		}

		hardCap, idle := sessionDurationsFor(appCfg.WebSession)
		sess, err := session.Default.Create(user.ID, user.Username, user.Role, hardCap, idle)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to create session")
			return
		}

		loginLimiter.recordSuccess(ip)
		audit.Log(audit.Entry{
			User:    user.Username,
			Role:    user.Role,
			Action:  audit.ActionLogin,
			Result:  audit.ResultOK,
			Details: "2FA verified, from " + ip,
		})

		SetSessionCookie(w, sess.Token, hardCap)
		jsonOK(w, map[string]interface{}{
			"username": user.Username,
			"role":     user.Role,
		})
	}
}

// HandleTOTPSetup generates a new TOTP secret and URI for setup — does NOT save yet.
// The user must confirm with HandleTOTPConfirm before the secret is persisted.
func HandleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	secret, err := totp.GenerateSecret()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to generate TOTP secret")
		return
	}
	uri := totp.OTPAuthURI(secret, sess.Username, "ZFS NAS")
	jsonOK(w, map[string]string{
		"secret": secret,
		"uri":    uri,
	})
}

// HandleTOTPConfirm verifies the user's TOTP code and saves the secret if correct.
// Body: {"secret": "BASE32...", "code": "123456"}
func HandleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	var req struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Secret = strings.TrimSpace(req.Secret)
	req.Code = strings.TrimSpace(req.Code)
	if req.Secret == "" || req.Code == "" {
		jsonErr(w, http.StatusBadRequest, "secret and code are required")
		return
	}

	if !totp.Verify(req.Secret, req.Code) {
		jsonErr(w, http.StatusBadRequest, "invalid code — please try again")
		return
	}

	if err := config.UpdateUserByID(sess.UserID, func(u *config.User) error {
		u.TOTPSecret = req.Secret
		u.TOTPEnabled = true
		return nil
	}); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save user")
		return
	}

	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.Action2FAEnabled,
		Target: sess.Username,
		Result: audit.ResultOK,
	})

	jsonOK(w, map[string]string{"message": "2FA enabled"})
}

// HandleLogout invalidates the current session.
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	sess, ok := SessionFromRequest(r)
	if ok {
		audit.Log(audit.Entry{
			User:   sess.Username,
			Role:   sess.Role,
			Action: audit.ActionLogout,
			Result: audit.ResultOK,
		})
		session.Default.Delete(sess.Token)
	}
	ClearSessionCookie(w)
	jsonOK(w, map[string]string{"message": "logged out"})
}

// HandleListSessions returns all active sessions (admin only).
func HandleListSessions(w http.ResponseWriter, r *http.Request) {
	sessions := session.Default.List()
	jsonOK(w, sessions)
}

// HandleKillSession terminates a session by token prefix (admin only).
func HandleKillSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]

	sessions := session.Default.List()
	found := false
	for _, s := range sessions {
		if s.Token == token {
			session.Default.Delete(token)
			adminSess := MustSession(r)
			audit.Log(audit.Entry{
				User:    adminSess.Username,
				Role:    adminSess.Role,
				Action:  audit.ActionKillSession,
				Target:  s.Username,
				Result:  audit.ResultOK,
				Details: "session terminated by admin",
			})
			found = true
			break
		}
	}

	if !found {
		jsonErr(w, http.StatusNotFound, "session not found")
		return
	}
	jsonOK(w, map[string]string{"message": "session terminated"})
}

// HandleMe returns the current user's info including their stored preferences.
func HandleMe(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	users, _ := config.LoadUsers()
	user := config.FindUserByID(users, sess.UserID)
	prefs := config.UserPreferences{}
	var totpEnabled bool
	var standardPerms *config.StandardPermissions
	if user != nil {
		prefs = user.Preferences
		totpEnabled = user.TOTPEnabled
		standardPerms = user.StandardPerms
	}
	// Include relay state so the browser can restore the relay banner on page refresh.
	var relayActive bool
	var relayHostname string
	if cookie, cookieErr := r.Cookie("zfsnas_session"); cookieErr == nil {
		if rs := session.GetRelay(cookie.Value); rs != nil {
			relayActive = true
			relayHostname = rs.Hostname
		}
	}

	jsonOK(w, map[string]interface{}{
		"user_id":        sess.UserID,
		"username":       sess.Username,
		"role":           sess.Role,
		"totp_enabled":   totpEnabled,
		"preferences":    prefs,
		"standard_perms": standardPerms,
		"relay_active":   relayActive,
		"relay_hostname": relayHostname,
	})
}

// HandleUpdatePrefs saves the current user's UI preferences.
// The incoming JSON is merged on top of the existing preferences so that a
// partial body (e.g. only activity_bar_collapsed) cannot wipe other fields.
func HandleUpdatePrefs(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var saved config.UserPreferences
	if err := config.UpdateUserByID(sess.UserID, func(u *config.User) error {
		// Map-typed fields MERGE under a plain unmarshal (existing keys can
		// never be removed). map_pins needs REPLACE semantics — un-pinning a
		// topology node / "Reset placement" must be able to delete entries —
		// so when the body carries the key, drop the old map first.
		var probe struct {
			MapPins json.RawMessage `json:"map_pins"`
		}
		if json.Unmarshal(raw, &probe) == nil && probe.MapPins != nil {
			u.Preferences.MapPins = nil
		}
		// Unmarshal onto the existing prefs struct — absent fields keep their
		// current value, present fields are overwritten.
		if err := json.Unmarshal(raw, &u.Preferences); err != nil {
			return fmt.Errorf("invalid prefs: %w", err)
		}
		saved = u.Preferences
		return nil
	}); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save preferences")
		return
	}
	jsonOK(w, saved)
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// settingsMovedPage replaces /setup on a USB stick whose settings were moved
// to an internal disk (zfsnas-install-disk relabels its store ZFSNAS-MOVED).
func settingsMovedPage(movedTo string) string {
	detail := ""
	if movedTo != "" {
		detail = "<p class=\"d\">" + html.EscapeString(movedTo) + "</p>"
	}
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZNAS: settings moved</title><style>
:root{--bg:#f5f5f7;--card:#fff;--text:#1d1d1f;--sub:#6e6e73;--accent:#0a84ff}
@media (prefers-color-scheme:dark){:root{--bg:#000;--card:#1c1c1e;--text:#f5f5f7;--sub:#a1a1a6}}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;padding:16px;box-sizing:border-box}
.c{max-width:520px;background:var(--card);border-radius:14px;padding:28px 30px;box-shadow:0 8px 30px rgba(0,0,0,.12)}
h1{font-size:20px;margin:0 0 12px}p{margin:0 0 12px;color:var(--sub)}.d{font-family:ui-monospace,monospace;font-size:13px;color:var(--text)}
</style></head><body><div class="c"><h1>This USB stick's settings were moved</h1>
<p>ZNAS was moved to an internal disk, and its settings went with it.</p>` + detail + `
<p>Remove this USB stick and start the server again: it then starts from the internal disk. If it still starts from the stick, choose the internal disk first in the firmware boot order.</p>
<p>Nothing was changed on this stick's settings; they are kept but not used.</p></div></body></html>`
}
