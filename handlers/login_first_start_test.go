package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"zfsnas/internal/config"
)

// TestLoginRedirectsToSetupWithoutUsers: on a first start (no account yet)
// /login — where / and every deep link send an anonymous browser — must
// forward to /setup; once an account exists it serves the login page.
func TestLoginRedirectsToSetupWithoutUsers(t *testing.T) {
	if err := config.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	page := func(string) ([]byte, error) { return []byte("<title>ZFS NAS — Sign In</title>"), nil }
	h := HandleLoginPage(page, &config.AppConfig{})

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/setup" {
		t.Fatalf("no users: got %d → %q, want 303 → /setup", rec.Code, rec.Header().Get("Location"))
	}

	if err := config.SaveUsers([]config.User{{Username: "admin"}}); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("with a user: got %d (Location %q), want 200 login page", rec.Code, rec.Header().Get("Location"))
	}
}
