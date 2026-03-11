package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/session"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"

	"crypto/rand"
	"encoding/hex"
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
		data, err := staticContent("setup.html")
		if err != nil {
			http.Error(w, "setup page not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	}
}

// HandleLoginPage serves the login HTML page.
func HandleLoginPage(staticContent func(name string) ([]byte, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If already logged in, redirect to app.
		if _, ok := SessionFromRequest(r); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		data, err := staticContent("login.html")
		if err != nil {
			http.Error(w, "login page not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	}
}

// HandleSetup processes first-run admin account creation.
func HandleSetup(w http.ResponseWriter, r *http.Request) {
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

	jsonOK(w, map[string]string{"message": "admin account created"})
}

// HandleLogin authenticates a user and creates a session.
func HandleLogin(w http.ResponseWriter, r *http.Request) {
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

	ip := clientIP(r)
	user := config.FindUserByUsername(users, strings.TrimSpace(req.Username))
	if user == nil || user.Role == config.RoleSMBOnly {
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

	sess, err := session.Default.Create(user.ID, user.Username, user.Role)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	alerts.ResetFailedLogins()
	audit.Log(audit.Entry{
		User:    user.Username,
		Role:    user.Role,
		Action:  audit.ActionLogin,
		Result:  audit.ResultOK,
		Details: "from " + ip,
	})

	SetSessionCookie(w, sess.Token)
	jsonOK(w, map[string]interface{}{
		"username": user.Username,
		"role":     user.Role,
	})
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
	if user != nil {
		prefs = user.Preferences
	}
	jsonOK(w, map[string]interface{}{
		"user_id":     sess.UserID,
		"username":    sess.Username,
		"role":        sess.Role,
		"preferences": prefs,
	})
}

// HandleUpdatePrefs saves the current user's UI preferences.
func HandleUpdatePrefs(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	var prefs config.UserPreferences
	if err := json.NewDecoder(r.Body).Decode(&prefs); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	users, err := config.LoadUsers()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load users")
		return
	}
	user := config.FindUserByID(users, sess.UserID)
	if user == nil {
		jsonErr(w, http.StatusNotFound, "user not found")
		return
	}
	user.Preferences = prefs
	if err := config.SaveUsers(users); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save preferences")
		return
	}
	jsonOK(w, prefs)
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
