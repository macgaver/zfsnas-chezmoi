package handlers

import (
	"context"
	"net/http"
	"zfsnas/internal/config"
	"zfsnas/internal/session"
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
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := SessionFromRequest(r)
		if !ok {
			if isBrowser(r) {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			jsonErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin rejects non-admin requests with 403.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		if sess.Role != config.RoleAdmin {
			jsonErr(w, http.StatusForbidden, "admin access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireWriteAccess rejects read-only and smb-only users.
func RequireWriteAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		if sess.Role == config.RoleReadOnly || sess.Role == config.RoleSMBOnly {
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
func SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "zfsnas_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 24 hours
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
				if k.Key == token {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		jsonErr(w, http.StatusUnauthorized, "authentication required")
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
