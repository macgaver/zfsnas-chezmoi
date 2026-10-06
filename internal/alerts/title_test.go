package alerts

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNotifTitle(t *testing.T) {
	if got := notifTitle("nas01", "Pool degraded"); got != "[nas01 ZNAS] Pool degraded" {
		t.Errorf("got %q", got)
	}
	if got := notifTitle("", "Pool degraded"); got != "[ZNAS] Pool degraded" {
		t.Errorf("no hostname: got %q", got)
	}
}

func TestSendersUseHostTitleWithoutHostLine(t *testing.T) {
	var gotTitle, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotTitle = r.Header.Get("X-Title")
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			var m map[string]any
			json.Unmarshal(b, &m)
			gotTitle, _ = m["title"].(string)
			gotBody, _ = m["message"].(string)
		}
	}))
	defer srv.Close()

	if err := sendNtfy(NtfyTarget{URL: srv.URL}, "Pool degraded", "pool_degraded", "tank is DEGRADED", "nas01"); err != nil {
		t.Fatal(err)
	}
	if gotTitle != "[nas01 ZNAS] Pool degraded" || strings.Contains(gotBody, "Host:") {
		t.Errorf("ntfy: title %q body %q", gotTitle, gotBody)
	}
	if err := sendGotify(GotifyTarget{URL: srv.URL, Token: "x"}, "Pool degraded", "pool_degraded", "tank is DEGRADED", "nas01"); err != nil {
		t.Fatal(err)
	}
	if gotTitle != "[nas01 ZNAS] Pool degraded" || strings.Contains(gotBody, "Host:") {
		t.Errorf("gotify: title %q body %q", gotTitle, gotBody)
	}
}
