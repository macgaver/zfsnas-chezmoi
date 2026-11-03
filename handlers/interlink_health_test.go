package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"zfsnas/internal/config"
	"zfsnas/internal/session"
	"zfsnas/system"

	"github.com/gorilla/mux"
)

// The bug behind "account does not exist": relinking one side left the other
// with its old secret, because accept-link answered OK without taking the new.
func TestFindAcceptedLink(t *testing.T) {
	links := []config.LinkedServer{
		{ID: "a", URL: "https://10.0.0.1:8443", RemoteID: "x"},
		{ID: "b", URL: "https://10.0.0.2:8443", RemoteID: "y"},
	}
	for name, c := range map[string]struct {
		req  system.AcceptLinkRequest
		want int
	}{
		"repair, reached under another name": {system.AcceptLinkRequest{CallerURL: "https://z1.example.com", CallerID: "y"}, 1},
		"relink with a new id":               {system.AcceptLinkRequest{CallerURL: "https://10.0.0.1:8443", CallerID: "new"}, 0},
		"unknown":                            {system.AcceptLinkRequest{CallerURL: "https://10.0.0.9:8443", CallerID: "new"}, -1},
	} {
		if got := findAcceptedLink(links, c.req); got != c.want {
			t.Errorf("%s: got %d", name, got)
		}
	}
}

func TestInterlinkClockInRange(t *testing.T) {
	for skew, want := range map[int]bool{0: true, 20: true, 26: false, -3: true, -6: false} {
		if got := interlinkClockInRange(skew); got != want {
			t.Errorf("%d: got %v", skew, got)
		}
	}
}

// A signature made with another secret must be told apart from "no account".
func TestPeerHealth_RefusesWrongSecret(t *testing.T) {
	cfg := &config.AppConfig{InterLink: []config.LinkedServer{{ID: "a", SharedSecret: "aabb"}}}
	req := system.PeerHealthRequest{Username: "u", Timestamp: time.Now().Unix(), Nonce: "n"}
	req.HMAC = system.PeerHealthHMAC("ccdd", req.Username, req.Timestamp, req.Nonce)
	b, _ := json.Marshal(req)
	w := httptest.NewRecorder()
	HandleInterlinkPeerHealth(cfg)(w, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
	err := &system.InterlinkHTTPError{Status: w.Code, Body: w.Body.String()}
	if got := system.ClassifyInterlinkErr(err); got != "secret_mismatch" {
		t.Fatalf("classified %q", got)
	}
}

func TestAcceptAccount_RefusesBadInput(t *testing.T) {
	for name, req := range map[string]system.AcceptAccountRequest{
		"smb-only":  {Username: "x", Role: config.RoleSMBOnly},
		"no name":   {Role: config.RoleAdmin},
		"bad hash":  {Username: "x", Role: config.RoleAdmin, PasswordHash: "plain"},
		"weak hash": {Username: "x", Role: config.RoleAdmin, PasswordHash: "$2a$04$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234"},
	} {
		b, _ := json.Marshal(req)
		w := httptest.NewRecorder()
		HandleInterlinkAcceptAccount(w, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b)))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, w.Code)
		}
	}
}

// A pair this server is not part of: the repair runs on the server that holds
// the broken link, and link_id must not be able to reach any other endpoint.
func TestRepairPeer_ForwardsToTheLinkOnThatServer(t *testing.T) {
	var path, raw, user string
	var got map[string]string
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, raw, user = r.URL.Path, r.URL.EscapedPath(), r.Header.Get("X-Interlink-Relay-User")
		json.NewDecoder(r.Body).Decode(&got) //nolint:errcheck
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
	}))
	defer peer.Close()
	cfg := &config.AppConfig{InterLink: []config.LinkedServer{{ID: "b", URL: peer.URL, Hostname: "b", SharedSecret: "s"}}}
	call := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/interlink/b/repair-peer", bytes.NewBufferString(body))
		r = mux.SetURLVars(r, map[string]string{"id": "b"})
		r = r.WithContext(context.WithValue(r.Context(), sessionKey, &session.Session{Username: "demo", Role: config.RoleAdmin}))
		w := httptest.NewRecorder()
		HandleInterlinkRepairPeer(cfg)(w, r)
		return w
	}

	if w := call(`{"link_id":"c1","username":"root","password":"pw","totp":"123"}`); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if path != "/api/interlink/c1/repair-link" || user != "demo" {
		t.Fatalf("forwarded to %q as %q", path, user)
	}
	if got["username"] != "root" || got["password"] != "pw" || got["totp"] != "123" || got["link_id"] != "" {
		t.Fatalf("forwarded body %v", got)
	}

	if w := call(`{"link_id":"x/../../users","username":"root","password":"pw"}`); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	} else if raw != "/api/interlink/x%2F..%2F..%2Fusers/repair-link" {
		t.Fatalf("link_id escaped the path: %q", raw)
	}

	path = ""
	if w := call(`{"username":"root","password":"pw"}`); w.Code != http.StatusBadRequest || path != "" {
		t.Fatalf("no link_id: status %d, forwarded to %q", w.Code, path)
	}
}
