package handlers

import (
	"context"
	"crypto/subtle"
	"net/http"
	"sync/atomic"
	"strings"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/session"

	"github.com/gorilla/mux"
)

type contextKey string

const sessionKey contextKey = "session"

// SessionFromRequest extracts the session from the request cookie.
func SessionFromRequest(r *http.Request) (*session.Session, bool) {
	cookie, err := r.Cookie("zfsnas_session")
	if err != nil {
		return nil, false
	}
	return session.Default.Get(cookie.Value)
}

// RequireAuth rejects unauthenticated requests with 401.
// For browser requests (no Accept: application/json), redirects to /login.
// Also accepts relay-injected sessions (set by RelayAuthMiddleware on Server B).
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for a relay-injected synthetic session first (Server B relay path).
		if injected, ok := r.Context().Value(relaySessionKey).(*session.Session); ok && injected != nil {
			ctx := context.WithValue(r.Context(), sessionKey, injected)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// Normal cookie-based auth.
		sess, ok := SessionFromRequest(r)
		if !ok {
			// Service-proxy traffic always gets a clean 401, never a redirect.
			// These requests are an app's own documents and sub-resources
			// (JS/CSS/XHR/WebSocket) inside a sandboxed frame: answering a
			// script fetch with a 303 to the HTML login page would corrupt the
			// proxied app instead of failing honestly. A uniform 401 also means
			// the response is identical whether or not the service id exists,
			// so the endpoint can't be used to enumerate services, and it is
			// what lets the panel show its "session expired" overlay.
			// See PLANS/plan-version-6.8.1.md §2.8.
			if isBrowser(r) && !strings.HasPrefix(r.URL.Path, "/s/") {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			jsonErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		// Bump the last-activity timestamp so the inactivity timer
		// resets on each authenticated request. In-memory only —
		// disk flush is debounced (see internal/session/persist.go).
		session.Default.Touch(sess.Token)
		ctx := context.WithValue(r.Context(), sessionKey, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin rejects non-admin requests with 403.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		if sess.Role != config.RoleAdmin {
			audit.Log(audit.Entry{
				User:    sess.Username,
				Role:    sess.Role,
				Action:  audit.ActionForbidden,
				Target:  r.Method + " " + r.URL.Path,
				Result:  audit.ResultError,
				Details: "admin access required",
			})
			jsonErr(w, http.StatusForbidden, "admin access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePermission passes if the session user is admin, or if the session user
// is "standard" and their StandardPerms field named by perm is true.
// perm must be a json key of StandardPermissions (e.g. "terminal").
func RequirePermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := MustSession(r)
			if sess.Role == config.RoleAdmin {
				next.ServeHTTP(w, r)
				return
			}
			if sess.Role == config.RoleStandard {
				users, _ := config.LoadUsers()
				u := config.FindUserByID(users, sess.UserID)
				if u != nil && u.StandardPerms != nil && permEnabled(u.StandardPerms, perm) {
					next.ServeHTTP(w, r)
					return
				}
			}
			// Only log write attempts — GET/HEAD are background polls and would spam the log.
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				audit.Log(audit.Entry{
					User:    sess.Username,
					Role:    sess.Role,
					Action:  audit.ActionForbidden,
					Target:  r.Method + " " + r.URL.Path,
					Result:  audit.ResultError,
					Details: "permission denied: " + perm,
				})
			}
			jsonErr(w, http.StatusForbidden, "permission denied")
		})
	}
}

func permEnabled(p *config.StandardPermissions, perm string) bool {
	switch perm {
	case "terminal":            return p.Terminal
	case "review_sudoers":      return p.ReviewSudoers
	case "browse_files":        return p.BrowseFiles
	case "manage_pool_dataset": return p.ManagePoolDataset
	case "manage_smb":          return p.ManageSMB
	case "manage_nfs":          return p.ManageNFS
	case "manage_iscsi":        return p.ManageISCSI
	case "manage_protection":   return p.ManageProtection
	case "manage_snapshots":    return p.ManageSnapshots
	case "edit_settings":       return p.EditSettings
	case "manage_interlink":    return p.ManageInterlink
	case "manage_docker_detect": return p.ManageDockerDetect
	case "manage_networking":   return p.ManageNetworking
	case "view_virtualization":     return p.ViewVirtualization
	case "create_vm":               return p.CreateVM
	case "create_container":        return p.CreateContainer
	case "edit_instances":          return p.EditInstances
	case "control_instances":       return p.ControlInstances
	case "delete_instances":        return p.DeleteInstances
	case "manage_instance_backups": return p.ManageInstanceBackups
	case "view_networking":         return p.ViewNetworking
	case "view_services":           return p.ViewServices
	case "manage_services":         return p.ManageServices
	}
	return false
}

// standardPermsForSession returns the StandardPermissions of the request's
// session user when that user has the "standard" role, or nil otherwise
// (admin / read-only / smb-only — none are subject to granular gating).
func standardPermsForSession(r *http.Request) *config.StandardPermissions {
	sess, ok := r.Context().Value(sessionKey).(*session.Session)
	if !ok || sess == nil || sess.Role != config.RoleStandard {
		return nil
	}
	users, _ := config.LoadUsers()
	u := config.FindUserByID(users, sess.UserID)
	if u == nil {
		return nil
	}
	return u.StandardPerms
}

// RequireVirtView gates the read-only virtualization endpoints. Admin and
// read-only users keep their existing access; a standard user is allowed
// only when granted the view_virtualization capability.
func RequireVirtView(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := standardPermsForSession(r); p != nil && !p.ViewVirtualization {
			jsonErr(w, http.StatusForbidden, "permission denied")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireNetView is the networking counterpart of RequireVirtView.
func RequireNetView(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := standardPermsForSession(r); p != nil && !p.ViewNetworking {
			jsonErr(w, http.StatusForbidden, "permission denied")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireInstancePerm wraps RequirePermission and additionally enforces the
// standard user's InstanceVisibilityRegex against the {name} path variable —
// so a whitelisted-by-regex user can neither see nor act on an instance
// outside their allowed set, even by guessing its name.
func RequireInstancePerm(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		guard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p := standardPermsForSession(r); p != nil {
				if name := mux.Vars(r)["name"]; name != "" && !p.InstanceVisible(name) {
					jsonErr(w, http.StatusForbidden, "permission denied")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
		return RequirePermission(perm)(guard)
	}
}

// RequireWriteAccess rejects read-only and smb-only users.
func RequireWriteAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		if sess.Role == config.RoleReadOnly || sess.Role == config.RoleSMBOnly {
			audit.Log(audit.Entry{
				User:    sess.Username,
				Role:    sess.Role,
				Action:  audit.ActionForbidden,
				Target:  r.Method + " " + r.URL.Path,
				Result:  audit.ResultError,
				Details: "write access required",
			})
			jsonErr(w, http.StatusForbidden, "write access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// MustSession retrieves the session from context (panics if missing — should only
// be called inside RequireAuth-protected handlers).
func MustSession(r *http.Request) *session.Session {
	return r.Context().Value(sessionKey).(*session.Session)
}

// SetSessionCookie writes the session token as a secure HttpOnly cookie.
// MaxAge mirrors the server-side session lifetime so the browser deletes
// the cookie at roughly the same moment the server invalidates the
// session — keeps the SPA from polling with a known-stale cookie.
func SetSessionCookie(w http.ResponseWriter, token string, lifetime time.Duration) {
	maxAge := int(lifetime.Seconds())
	if maxAge <= 0 {
		maxAge = 86400
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "zfsnas_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// ClearSessionCookie removes the session cookie.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "zfsnas_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
	})
}

// RequireAuthOrAPIKey allows requests that have either a valid session cookie
// or a valid "Authorization: Bearer <api_key>" header. Used for the
// TrueNAS-compatible /api/v2.0/ endpoints consumed by the homepage widget.
func RequireAuthOrAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try session first.
		if _, ok := SessionFromRequest(r); ok {
			next.ServeHTTP(w, r)
			return
		}
		// Try API key.
		auth := r.Header.Get("Authorization")
		if len(auth) > 7 && auth[:7] == "Bearer " {
			token := auth[7:]
			keys, _ := config.LoadAPIKeys()
			for _, k := range keys {
				if subtle.ConstantTimeCompare([]byte(k.Key), []byte(token)) == 1 {
					// Carry the matched key so capacity handlers can honor its
					// per-key PoolTarget selection.
					next.ServeHTTP(w, withAPIKey(r, k))
					return
				}
			}
		}
		jsonErr(w, http.StatusUnauthorized, "authentication required")
	})
}

// SecurityHeaders sets defensive HTTP response headers on every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Service-proxy responses are framed BY the portal. X-Frame-Options
		// cannot express "allow that specific other origin" (ALLOW-FROM is
		// dead), and when the dedicated proxy port is in use the framing page
		// is a different origin than the framed one — so SAMEORIGIN blocks it
		// just as surely as DENY. We therefore omit XFO for /s/ entirely and
		// express the policy with CSP frame-ancestors below, which does support
		// naming an exact origin. Isolation for these frames comes from the
		// iframe sandbox, not from XFO (spec §2.1).
		if !strings.HasPrefix(r.URL.Path, "/s/") {
			w.Header().Set("X-Frame-Options", "DENY")
		}
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Content-Security-Policy: defense-in-depth against XSS/exfiltration.
		// The SPA relies on inline scripts/handlers and inline styles, so
		// 'unsafe-inline' is required for script-src/style-src; all script files
		// are self-hosted (/static/vendor/*), only Google Fonts is external.
		// frame-ancestors is 'self' (not 'none') because the VGA console and file
		// previewer are framed same-origin (they override X-Frame-Options to
		// SAMEORIGIN). object-src 'none' + base-uri 'self' close common bypasses.
		if w.Header().Get("Content-Security-Policy") == "" {
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self' 'unsafe-inline' 'unsafe-eval'; "+
					"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
					"font-src 'self' https://fonts.gstatic.com; "+
					"img-src 'self' data: blob:; "+
					"media-src 'self' blob:; "+
					"connect-src 'self'; "+
					// v6.8.1 — the Services panel frames proxied apps. Normally
					// they come from our own origin ('self'); when the dedicated
					// proxy port is enabled they come from that port instead,
					// which is a DIFFERENT origin and must be named explicitly.
					"frame-src 'self'; "+
					"worker-src 'self' blob:; "+
					"object-src 'none'; "+
					"base-uri 'self'; "+
					serviceFrameAncestors(r)+
					"form-action 'self'")
		}
		next.ServeHTTP(w, r)
	})
}

// EnforceOrigin rejects cross-origin state-changing requests (POST/PUT/DELETE/PATCH).
// Requests without an Origin header (curl, scripts, API keys) are always allowed —
// only browsers send Origin, and only for cross-origin requests.
func EnforceOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
			// The service proxy (/s/{id}/…) is deliberately exempt. Its frames
			// are sandboxed WITHOUT allow-same-origin, so the browser gives them
			// an opaque origin and every POST they make carries `Origin: null` —
			// which the check below would reject, breaking the login form of
			// every proxied app. That prefix is protected instead by (a) a
			// mandatory session on every request and (b) SameSite=Lax on
			// zfsnas_session, which withholds the cookie from a third-party
			// site trying to drive an authenticated POST through the proxy.
			// CSRF *inside* the proxied app remains that app's own business.
			// See PLANS/plan-version-6.8.1.md §2.8.
			if strings.HasPrefix(r.URL.Path, "/s/") {
				break
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				if !strings.HasSuffix(origin, "://"+r.Host) {
					jsonErr(w, http.StatusForbidden, "cross-origin request rejected")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isBrowser returns true if the request likely comes from a browser.
func isBrowser(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return accept == "" || containsHTML(accept)
}

func containsHTML(s string) bool {
	for i := 0; i+4 <= len(s); i++ {
		if s[i:i+4] == "html" {
			return true
		}
	}
	return false
}




// portalPort records the port the main portal listens on, so proxy responses
// can name it as an allowed framing ancestor.
var portalPort atomic.Int32

// SetPortalPort is called once at startup.
func SetPortalPort(p int) { portalPort.Store(int32(p)) }

// serviceFrameAncestors builds the frame-ancestors directive.
//
// Portal pages keep the strict 'self'. Service-proxy responses must additionally
// permit the PORTAL origin to frame them: with the dedicated proxy port enabled
// the app is served from https://host:<proxyPort> while the portal that frames
// it is https://host:<portalPort> — a different origin, which plain 'self'
// rejects. That mismatch silently blanked every embedded app.
func serviceFrameAncestors(r *http.Request) string {
	// Both the portal and the service proxy are served from the same origin, so
	// 'self' is sufficient everywhere.
	return "frame-ancestors 'self'; "
}


