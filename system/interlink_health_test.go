package system

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClassifyInterlinkErr(t *testing.T) {
	for want, err := range map[string]error{
		"secret_mismatch": &InterlinkHTTPError{Status: 401, Body: `{"error":"invalid HMAC"}`},
		"clock":           &InterlinkHTTPError{Status: 401, Body: `{"error":"request timestamp out of range"}`},
		"needs_update":    &InterlinkHTTPError{Status: 404, Body: "404 page not found"},
		"error":           &InterlinkHTTPError{Status: 500, Body: "boom"},
		"cert_changed":    errors.New("Post x: interlink: TLS certificate fingerprint mismatch (want a…, got b…)"),
		"unreachable":     errors.New("dial tcp: i/o timeout"),
		"ok":              nil,
	} {
		if got := ClassifyInterlinkErr(err); got != want {
			t.Errorf("%v: got %q want %q", err, got, want)
		}
	}
}

// A refused link must reach the caller as a refusal, not as "no account".
func TestCheckUser_KeepsRefusalReason(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"invalid HMAC"}`))
	}))
	defer s.Close()
	_, err := CheckUserOnRemote(s.URL, "aabb", "u", "")
	if ClassifyInterlinkErr(err) != "secret_mismatch" {
		t.Fatalf("got %v", err)
	}
	if st := TestInterlink("i", s.URL, "h", "aabb", ""); st.Status != "secret_mismatch" {
		t.Fatalf("test: %+v", st)
	}
}

// The remote answers 200 even when it did not recognise the signature.
func TestSendRemoteUnlink_ReportsNotRemoved(t *testing.T) {
	for body, want := range map[string]bool{`{"removed":false}`: false, `{"removed":true}`: true, `{"message":"ok"}`: true} {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		got, err := SendRemoteUnlink(s.URL, "aabb", "id", "")
		s.Close()
		if err != nil || got != want {
			t.Errorf("%s: got %v %v", body, got, err)
		}
	}
}

func TestInterlinkErrorMessage(t *testing.T) {
	if got := InterlinkErrorMessage(&InterlinkHTTPError{Status: 409, Body: `{"error":"username already exists"}`}); got != "username already exists" {
		t.Fatal(got)
	}
	if got := InterlinkErrorMessage(errors.New("dial failed")); got != "dial failed" {
		t.Fatal(got)
	}
}
