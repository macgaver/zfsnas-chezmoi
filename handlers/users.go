package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// HandleDisableTOTP removes 2FA from a user.
// Admins can disable 2FA for any user; non-admins can only disable their own.
func HandleDisableTOTP(w http.ResponseWriter, r *http.Request) {
	id   := mux.Vars(r)["id"]
	sess := MustSession(r)

	// Non-admins (including standard users) may only affect their own account.
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

	// Non-admins reach this only to build a name list (e.g. a standard user
	// with manage_smb populating an SMB share's valid-users picker). They get
	// id+username ONLY — never email, role, 2FA status, created-at, or
	// permissions. Exposing those to any authenticated user leaked PII and
	// told an attacker which accounts are admin / lack 2FA. Admins still get
	// the full records for the Users settings page.
	sess := MustSession(r)
	if sess.Role != config.RoleAdmin {
		type minimalUser struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		}
		out := make([]minimalUser, len(users))
		for i, u := range users {
			out[i] = minimalUser{ID: u.ID, Username: u.Username}
		}
		jsonOK(w, out)
		return
	}

	type safeUser struct {
		ID            string                      `json:"id"`
		Username      string                      `json:"username"`
		Email         string                      `json:"email"`
		Role          string                      `json:"role"`
		CreatedAt     time.Time                   `json:"created_at"`
		TOTPEnabled   bool                        `json:"totp_enabled"`
		SMBHomeFolder bool                        `json:"smb_home_folder"`
		StandardPerms *config.StandardPermissions `json:"standard_perms,omitempty"`
	}

	out := make([]safeUser, len(users))
	for i, u := range users {
		out[i] = safeUser{
			ID:            u.ID,
			Username:      u.Username,
			Email:         u.Email,
			Role:          u.Role,
			CreatedAt:     u.CreatedAt,
			TOTPEnabled:   u.TOTPEnabled,
			SMBHomeFolder: u.SMBHomeFolder,
			StandardPerms: u.StandardPerms,
		}
	}
	jsonOK(w, out)
}

// HandleCreateUser creates a new user (admin only).
func HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username                 string                      `json:"username"`
		Email                    string                      `json:"email"`
		Password                 string                      `json:"password"`
		SMBPassword              string                      `json:"smb_password"`
		Role                     string                      `json:"role"`
		SMBHomeFolder            bool                        `json:"smb_home_folder"`
		UID                      *int                        `json:"uid"`
		GID                      *int                        `json:"gid"`
		StandardPerms            *config.StandardPermissions `json:"standard_perms"`
		ApproveExistingSystemUser bool                       `json:"approve_existing_system_user"`
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
	if req.Role != config.RoleAdmin && req.Role != config.RoleReadOnly && req.Role != config.RoleSMBOnly && req.Role != config.RoleStandard {
		jsonErr(w, http.StatusBadRequest, "role must be admin, read-only, smb-only, or standard")
		return
	}
	if req.Role == config.RoleSMBOnly && len(req.SMBPassword) < 8 {
		jsonErr(w, http.StatusBadRequest, "SMB password must be at least 8 characters")
		return
	}
	if req.Role != config.RoleSMBOnly && len(req.Password) < 8 {
		jsonErr(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if req.UID != nil && *req.UID < 1000 {
		jsonErr(w, http.StatusBadRequest, "UID must be 1000 or higher")
		return
	}
	if req.GID != nil && *req.GID < 1000 {
		jsonErr(w, http.StatusBadRequest, "GID must be 1000 or higher")
		return
	}

	config.LockUsers()
	defer config.UnlockUsers()

	users, err := config.LoadUsers()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load users")
		return
	}

	if config.FindUserByUsername(users, req.Username) != nil {
		jsonErr(w, http.StatusConflict, "username already exists")
		return
	}

	// Reject system usernames (UID < 1000 — root, system service accounts) outright.
	// Regular OS users (UID >= 1000) may be reused if the admin explicitly approves:
	// the response carries the existing UID/GID so the frontend can prompt before
	// re-submitting with approve_existing_system_user=true.
	osUID, osGID, osExists, err := system.LookupSystemUser(req.Username)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to check OS username: "+err.Error())
		return
	}
	reuseSystemUser := false
	if osExists {
		if osUID < 1000 {
			jsonErr(w, http.StatusConflict, fmt.Sprintf("username '%s' is a system account (UID %d) and cannot be reused", req.Username, osUID))
			return
		}
		if !req.ApproveExistingSystemUser {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]any{
				"error":    fmt.Sprintf("username '%s' already exists on the system (UID %d, GID %d)", req.Username, osUID, osGID),
				"code":     "system_user_exists",
				"username": req.Username,
				"uid":      osUID,
				"gid":      osGID,
			})
			return
		}
		// Approved: adopt the existing UID/GID; subsequent UID/GID-in-use checks
		// must skip these specific values since reuse is intentional.
		req.UID = &osUID
		req.GID = &osGID
		reuseSystemUser = true
	}

	// Check that the requested UID/GID are not already in use — first in portal
	// users, then in the system /etc/passwd and /etc/group. When reusing an
	// existing OS account, the system-side check is skipped because the UID/GID
	// collision with that account is the whole point.
	if req.UID != nil {
		for _, u := range users {
			if u.UID != nil && *u.UID == *req.UID {
				jsonErr(w, http.StatusConflict, fmt.Sprintf("UID %d is already in use by user '%s'", *req.UID, u.Username))
				return
			}
		}
		if !reuseSystemUser {
			if taken, err := system.UIDExistsOnSystem(*req.UID); err != nil {
				jsonErr(w, http.StatusInternalServerError, "failed to check UID: "+err.Error())
				return
			} else if taken {
				jsonErr(w, http.StatusConflict, fmt.Sprintf("UID %d is already in use by a system account", *req.UID))
				return
			}
		}
	}
	if req.GID != nil {
		for _, u := range users {
			if u.GID != nil && *u.GID == *req.GID {
				jsonErr(w, http.StatusConflict, fmt.Sprintf("GID %d is already in use by user '%s'", *req.GID, u.Username))
				return
			}
		}
		if !reuseSystemUser {
			if taken, err := system.GIDExistsOnSystem(*req.GID); err != nil {
				jsonErr(w, http.StatusInternalServerError, "failed to check GID: "+err.Error())
				return
			} else if taken {
				jsonErr(w, http.StatusConflict, fmt.Sprintf("GID %d is already in use by a system group", *req.GID))
				return
			}
		}
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

	var stdPerms *config.StandardPermissions
	if req.Role == config.RoleStandard {
		if req.StandardPerms != nil {
			stdPerms = req.StandardPerms
		} else {
			stdPerms = &config.StandardPermissions{}
		}
	}
	user := config.User{
		ID:            newID(),
		Username:      req.Username,
		Email:         req.Email,
		PasswordHash:  passwordHash,
		Role:          req.Role,
		CreatedAt:     time.Now(),
		SMBHomeFolder: req.SMBHomeFolder,
		UID:           req.UID,
		GID:           req.GID,
		StandardPerms: stdPerms,
	}
	users = append(users, user)

	if err := config.SaveUsers(users); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save user")
		return
	}

	// Always create the Linux system account and set the SMB password.
	// For smb-only users the dedicated smb_password field is used; for all
	// other roles the portal password doubles as the SMB password.
	smbPw := req.SMBPassword
	if smbPw == "" {
		smbPw = req.Password
	}
	if err := system.EnsureSambaUser(req.Username, smbPw, req.UID, req.GID); err != nil {
		log.Printf("users: EnsureSambaUser for %s: %v", req.Username, err)
	}

	// Create SMB home directory and update smb.conf valid users if applicable.
	if appCfg, err := config.LoadAppConfig(); err == nil && appCfg.SMBHomeDataset != "" {
		if req.SMBHomeFolder {
			if err := system.EnsureSMBHomeDir(appCfg.SMBHomeDataset, req.Username); err != nil {
				log.Printf("users: EnsureSMBHomeDir for %s: %v", req.Username, err)
			}
		}
		if system.IsSambaInstalled() {
			if err := system.ApplySmbGlobal(config.Dir(), appCfg.MaxSmbdProcesses, appCfg.SMBWorkgroup, appCfg.SMBCustomGlobal, appCfg.SMBHomeDataset, smbHomeUsernames(), appCfg.SMBCleanDefaults, appCfg.SMBSocketOptions); err != nil {
				log.Printf("users: ApplySmbGlobal: %v", err)
			} else {
				_ = system.ReloadSamba()
			}
		}
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
	go alerts.Send(
		alerts.EventUserCreated,
		"User created: "+req.Username,
		"User Account Created",
		"User '"+req.Username+"' (role: "+req.Role+") was created by "+sess.Username+".",
	)

	jsonCreated(w, map[string]string{"id": user.ID, "username": user.Username})
}

// HandleUpdateUser updates a user's details.
// Admins can update any user's email, password, role, and permissions.
// Non-admins can only update their own password.
func HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id   := mux.Vars(r)["id"]
	sess := MustSession(r)
	isAdmin := sess.Role == config.RoleAdmin
	isSelf  := sess.UserID == id

	// Non-admins can only update their own account.
	if !isAdmin && !isSelf {
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionForbidden,
			Target:  r.Method + " " + r.URL.Path,
			Result:  audit.ResultError,
			Details: "attempted to edit another user's account",
		})
		jsonErr(w, http.StatusForbidden, "forbidden")
		return
	}

	config.LockUsers()
	defer config.UnlockUsers()

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
		Email         string                      `json:"email"`
		Password      string                      `json:"password"`
		Role          string                      `json:"role"`
		SMBHomeFolder *bool                       `json:"smb_home_folder"`
		StandardPerms *config.StandardPermissions `json:"standard_perms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Non-admins may only change their own password — all other fields are ignored.
	if !isAdmin {
		if req.Password == "" {
			jsonErr(w, http.StatusBadRequest, "password is required")
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
		user.PasswordHash = string(hash)
		if err := config.SaveUsers(users); err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to save users")
			return
		}
		if err := system.EnsureSambaUser(user.Username, req.Password, user.UID, user.GID); err != nil {
			log.Printf("users: EnsureSambaUser (password sync) for %s: %v", user.Username, err)
		}
		audit.Log(audit.Entry{
			User:   sess.Username,
			Role:   sess.Role,
			Action: audit.ActionUpdateUser,
			Target: user.Username,
			Result: audit.ResultOK,
		})
		jsonOK(w, map[string]string{"message": "password updated"})
		return
	}

	if req.Email != "" {
		user.Email = strings.TrimSpace(req.Email)
	}
	if req.Role != "" {
		if req.Role != config.RoleAdmin && req.Role != config.RoleReadOnly && req.Role != config.RoleSMBOnly && req.Role != config.RoleStandard {
			jsonErr(w, http.StatusBadRequest, "invalid role")
			return
		}
		user.Role = req.Role
	}
	// Sync StandardPerms with role.
	if user.Role == config.RoleStandard {
		if req.StandardPerms != nil {
			user.StandardPerms = req.StandardPerms
		} else if user.StandardPerms == nil {
			user.StandardPerms = &config.StandardPermissions{}
		}
	} else {
		user.StandardPerms = nil
	}
	passwordChanged := false
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
		passwordChanged = true
	}

	enabledHome := false
	disabledHome := false
	if req.SMBHomeFolder != nil {
		wasEnabled := user.SMBHomeFolder
		user.SMBHomeFolder = *req.SMBHomeFolder
		enabledHome = *req.SMBHomeFolder && !wasEnabled
		disabledHome = !*req.SMBHomeFolder && wasEnabled
	}

	if err := config.SaveUsers(users); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save users")
		return
	}

	// Create or remove SMB home directory when the flag changes.
	if req.SMBHomeFolder != nil {
		if appCfg, err := config.LoadAppConfig(); err == nil && appCfg.SMBHomeDataset != "" {
			if enabledHome {
				if err := system.EnsureSMBHomeDir(appCfg.SMBHomeDataset, user.Username); err != nil {
					log.Printf("users: EnsureSMBHomeDir for %s: %v", user.Username, err)
				}
			} else if disabledHome {
				if err := system.RemoveSMBHomeDirIfEmpty(appCfg.SMBHomeDataset, user.Username); err != nil {
					log.Printf("users: RemoveSMBHomeDirIfEmpty for %s: %v", user.Username, err)
				}
			}
			if system.IsSambaInstalled() {
				if err := system.ApplySmbGlobal(config.Dir(), appCfg.MaxSmbdProcesses, appCfg.SMBWorkgroup, appCfg.SMBCustomGlobal, appCfg.SMBHomeDataset, smbHomeUsernames(), appCfg.SMBCleanDefaults, appCfg.SMBSocketOptions); err != nil {
					log.Printf("users: ApplySmbGlobal: %v", err)
				} else {
					_ = system.ReloadSamba()
				}
			}
		}
	}

	// Sync the SMB password whenever the portal password is changed.
	if passwordChanged {
		if err := system.EnsureSambaUser(user.Username, req.Password, user.UID, user.GID); err != nil {
			log.Printf("users: EnsureSambaUser (password sync) for %s: %v", user.Username, err)
		}
	}

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

	config.LockUsers()
	defer config.UnlockUsers()

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
	hadHomeFolder := user.SMBHomeFolder
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

	// If the user had an SMB home folder, remove the directory if it is empty.
	if hadHomeFolder {
		if appCfg, err := config.LoadAppConfig(); err == nil && appCfg.SMBHomeDataset != "" {
			if err := system.RemoveSMBHomeDirIfEmpty(appCfg.SMBHomeDataset, username); err != nil {
				log.Printf("users: RemoveSMBHomeDirIfEmpty for %s: %v", username, err)
			}
		}
	}

	// Remove the Samba password entry and Linux system account.
	if err := system.DeleteSambaUser(username); err != nil {
		log.Printf("users: DeleteSambaUser for %s: %v", username, err)
	}

	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionDeleteUser,
		Target: username,
		Result: audit.ResultOK,
	})
	go alerts.Send(
		alerts.EventUserCreated,
		"User deleted: "+username,
		"User Account Deleted",
		"User '"+username+"' was deleted by "+sess.Username+".",
	)

	jsonOK(w, map[string]string{"message": "user deleted"})
}
