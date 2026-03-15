package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// HandleDisableTOTP removes 2FA from a user.
// Admins can disable 2FA for any user; non-admins can only disable their own.
func HandleDisableTOTP(w http.ResponseWriter, r *http.Request) {
	id   := mux.Vars(r)["id"]
	sess := MustSession(r)

	// Non-admins may only affect their own account.
	if sess.Role != config.RoleAdmin && sess.UserID != id {
		jsonErr(w, http.StatusForbidden, "forbidden")
		return
	}

	users, err := config.LoadUsers()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load users")
		return
	}
	user := config.FindUserByID(users, id)
	if user == nil {
		jsonErr(w, http.StatusNotFound, "user not found")
		return
	}

	user.TOTPEnabled = false
	user.TOTPSecret  = ""

	if err := config.SaveUsers(users); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save user")
		return
	}

	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.Action2FADisabled,
		Target: user.Username,
		Result: audit.ResultOK,
	})

	jsonOK(w, map[string]string{"message": "2FA disabled"})
}

// HandleListUsers returns all users (admin: all fields; others: sanitized).
func HandleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := config.LoadUsers()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load users")
		return
	}

	type safeUser struct {
		ID          string    `json:"id"`
		Username    string    `json:"username"`
		Email       string    `json:"email"`
		Role        string    `json:"role"`
		CreatedAt   time.Time `json:"created_at"`
		TOTPEnabled bool      `json:"totp_enabled"`
	}

	out := make([]safeUser, len(users))
	for i, u := range users {
		out[i] = safeUser{
			ID:          u.ID,
			Username:    u.Username,
			Email:       u.Email,
			Role:        u.Role,
			CreatedAt:   u.CreatedAt,
			TOTPEnabled: u.TOTPEnabled,
		}
	}
	jsonOK(w, out)
}

// HandleCreateUser creates a new user (admin only).
func HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	req.Role = strings.TrimSpace(req.Role)

	if req.Username == "" {
		jsonErr(w, http.StatusBadRequest, "username is required")
		return
	}
	if req.Role != config.RoleAdmin && req.Role != config.RoleReadOnly && req.Role != config.RoleSMBOnly {
		jsonErr(w, http.StatusBadRequest, "role must be admin, read-only, or smb-only")
		return
	}
	if req.Role != config.RoleSMBOnly && len(req.Password) < 8 {
		jsonErr(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	users, err := config.LoadUsers()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load users")
		return
	}

	if config.FindUserByUsername(users, req.Username) != nil {
		jsonErr(w, http.StatusConflict, "username already exists")
		return
	}

	var passwordHash string
	if req.Role != config.RoleSMBOnly {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		passwordHash = string(hash)
	}

	user := config.User{
		ID:           newID(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: passwordHash,
		Role:         req.Role,
		CreatedAt:    time.Now(),
	}
	users = append(users, user)

	if err := config.SaveUsers(users); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save user")
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionCreateUser,
		Target:  req.Username,
		Result:  audit.ResultOK,
		Details: "role: " + req.Role,
	})

	jsonCreated(w, map[string]string{"id": user.ID, "username": user.Username})
}

// HandleUpdateUser updates a user's email, password, or role (admin only).
func HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	users, err := config.LoadUsers()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load users")
		return
	}

	user := config.FindUserByID(users, id)
	if user == nil {
		jsonErr(w, http.StatusNotFound, "user not found")
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email != "" {
		user.Email = strings.TrimSpace(req.Email)
	}
	if req.Role != "" {
		if req.Role != config.RoleAdmin && req.Role != config.RoleReadOnly && req.Role != config.RoleSMBOnly {
			jsonErr(w, http.StatusBadRequest, "invalid role")
			return
		}
		user.Role = req.Role
	}
	if req.Password != "" {
		if len(req.Password) < 8 {
			jsonErr(w, http.StatusBadRequest, "password must be at least 8 characters")
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		user.PasswordHash = string(hash)
	}

	if err := config.SaveUsers(users); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save users")
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionUpdateUser,
		Target: user.Username,
		Result: audit.ResultOK,
	})

	jsonOK(w, map[string]string{"message": "user updated"})
}

// HandleDeleteUser removes a user by ID (admin only).
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	sess := MustSession(r)

	users, err := config.LoadUsers()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load users")
		return
	}

	user := config.FindUserByID(users, id)
	if user == nil {
		jsonErr(w, http.StatusNotFound, "user not found")
		return
	}

	// Prevent deleting yourself.
	if user.ID == sess.UserID {
		jsonErr(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}

	// Ensure at least one admin remains.
	if user.Role == config.RoleAdmin {
		adminCount := 0
		for _, u := range users {
			if u.Role == config.RoleAdmin {
				adminCount++
			}
		}
		if adminCount <= 1 {
			jsonErr(w, http.StatusBadRequest, "cannot delete the last admin account")
			return
		}
	}

	username := user.Username
	filtered := make([]config.User, 0, len(users)-1)
	for _, u := range users {
		if u.ID != id {
			filtered = append(filtered, u)
		}
	}

	if err := config.SaveUsers(filtered); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save users")
		return
	}

	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionDeleteUser,
		Target: username,
		Result: audit.ResultOK,
	})

	jsonOK(w, map[string]string{"message": "user deleted"})
}
