package system

// InterLink health: what the two ends of a link can prove to each other, for
// the health view of Manage InterLink and the reason shown when a switch fails.

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// interlinkClientWithin is interlinkClientFor with a shorter deadline.
func interlinkClientWithin(tlsFP string, d time.Duration) *http.Client {
	c := interlinkClientFor(tlsFP)
	c.Timeout = d
	return c
}

// InterlinkHTTPError is a refusal by the peer, as opposed to no answer.
type InterlinkHTTPError struct {
	What   string
	Status int
	Body   string
}

func (e *InterlinkHTTPError) Error() string {
	return fmt.Sprintf("%s returned status %d: %s", e.What, e.Status, e.Body)
}

func interlinkHTTPErr(what string, resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return &InterlinkHTTPError{What: what, Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
}

// InterlinkErrorMessage is what the peer said, without the transport around it.
func InterlinkErrorMessage(err error) string {
	var he *InterlinkHTTPError
	if errors.As(err, &he) {
		var b struct {
			Error string `json:"error"`
		}
		if json.Unmarshal([]byte(he.Body), &b) == nil && b.Error != "" {
			return b.Error
		}
	}
	return err.Error()
}

// ClassifyInterlinkErr names why a signed request failed: secret_mismatch,
// clock, cert_changed, needs_update (the peer has no such endpoint),
// unreachable or error.
func ClassifyInterlinkErr(err error) string {
	var he *InterlinkHTTPError
	if errors.As(err, &he) {
		switch {
		case strings.Contains(he.Body, "invalid HMAC"):
			return "secret_mismatch"
		case strings.Contains(he.Body, "timestamp out of range"):
			return "clock"
		case he.Status == http.StatusNotFound:
			return "needs_update"
		}
		return "error"
	}
	if err != nil && strings.Contains(err.Error(), "fingerprint mismatch") {
		return "cert_changed"
	}
	if err != nil {
		return "unreachable"
	}
	return "ok"
}

// InterlinkProbe is a ping that does not care about the certificate, so a
// changed certificate cannot pass for a dead server.
type InterlinkProbe struct {
	Hostname  string
	Version   string
	ClockSkew int // seconds the peer is ahead of us
}

func ProbeInterlink(url string) (InterlinkProbe, error) {
	var p InterlinkProbe
	resp, err := interlinkClientWithin("", 6*time.Second).Get(url + "/api/interlink/ping")
	if err != nil {
		return p, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return p, interlinkHTTPErr("ping", resp)
	}
	var pr InterlinkPingResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return p, err
	}
	p.Hostname, p.Version = pr.Hostname, pr.Version
	if t, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		p.ClockSkew = int(time.Until(t).Round(time.Second) / time.Second)
	}
	return p, nil
}

// InterlinkLinkTest is one link tried with a real signed request.
type InterlinkLinkTest struct {
	ID       string `json:"id,omitempty"`
	URL      string `json:"url"`
	Hostname string `json:"hostname"`
	Status   string `json:"status"` // ok, or a ClassifyInterlinkErr reason
	Detail   string `json:"detail,omitempty"`
}

// TestInterlink tries a link. check-user answers for any name, so "ok" says
// only that the peer can be reached and accepted the signature.
func TestInterlink(id, url, hostname, secret, tlsFP string) InterlinkLinkTest {
	t := InterlinkLinkTest{ID: id, URL: url, Hostname: hostname, Status: "ok"}
	if _, err := checkUserVia(interlinkClientWithin(tlsFP, 5*time.Second), url, secret, ""); err != nil {
		t.Status, t.Detail = ClassifyInterlinkErr(err), err.Error()
	}
	return t
}

// InterlinkUser is an account as other servers may see it (no secrets).
type InterlinkUser struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

// PeerHealthRequest asks a peer how the link looks from its side.
type PeerHealthRequest struct {
	Username  string `json:"username"`
	Cluster   bool   `json:"cluster"` // also test all of the peer's links
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// PeerHealthResponse is the peer's side.
type PeerHealthResponse struct {
	Hostname     string              `json:"hostname"`
	LinkID       string              `json:"link_id"`        // its ID for this link
	LinkRemoteID string              `json:"link_remote_id"` // what it holds as our ID
	AccountRole  string              `json:"account_role"`   // "" when the asked user has none
	Back         InterlinkLinkTest   `json:"back"`           // it, trying to reach us
	Links        []InterlinkLinkTest `json:"links,omitempty"`
	Users        []InterlinkUser     `json:"users,omitempty"`
}

// PeerHealthHMAC signs a peer-health request.
func PeerHealthHMAC(sharedSecret, username string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("peer-health|" + username + "|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// AskPeerHealth calls POST <url>/api/interlink/peer-health.
func AskPeerHealth(url, secret, username, tlsFP string, cluster bool) (*PeerHealthResponse, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	req := PeerHealthRequest{Username: username, Cluster: cluster, Timestamp: time.Now().Unix(), Nonce: hex.EncodeToString(nonce)}
	req.HMAC = PeerHealthHMAC(secret, username, req.Timestamp, req.Nonce)
	body, _ := json.Marshal(req)
	resp, err := interlinkClientWithin(tlsFP, 15*time.Second).Post(url+"/api/interlink/peer-health", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, interlinkHTTPErr("peer-health", resp)
	}
	var r PeerHealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// AcceptAccountRequest creates an account on a peer, authorised by that
// peer's admin. It carries a bcrypt hash, never a password.
type AcceptAccountRequest struct {
	AdminUsername string          `json:"admin_username"`
	AdminPassword string          `json:"admin_password"`
	AdminTOTP     string          `json:"admin_totp,omitempty"`
	Username      string          `json:"username"`
	Email         string          `json:"email,omitempty"`
	Role          string          `json:"role"`
	PasswordHash  string          `json:"password_hash"`
	StandardPerms json.RawMessage `json:"standard_perms,omitempty"`
}

// AcceptAccountResponse: TOTPNeeded asks for the peer admin's 2FA code.
type AcceptAccountResponse struct {
	OK         bool `json:"ok"`
	TOTPNeeded bool `json:"totp_needed,omitempty"`
}

// SendAcceptAccount calls POST <url>/api/interlink/accept-account.
func SendAcceptAccount(url, tlsFP string, req AcceptAccountRequest) (*AcceptAccountResponse, error) {
	body, _ := json.Marshal(req)
	resp, err := interlinkClientWithin(tlsFP, 15*time.Second).Post(url+"/api/interlink/accept-account", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, interlinkHTTPErr("accept-account", resp)
	}
	var r AcceptAccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}
