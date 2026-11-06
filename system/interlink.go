package system

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// interlinkClientFor returns an HTTP client for inter-server communication.
// When tlsFP is empty the client accepts any self-signed cert (used for initial
// discovery / link setup — TOFU phase). When tlsFP is a hex SHA-256 fingerprint
// the client verifies that the server presents exactly that certificate, rejecting
// anything else — this pins the connection after the first contact.
func interlinkClientFor(tlsFP string) *http.Client {
	tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	if tlsFP != "" {
		pinned := tlsFP
		tlsConf.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("interlink: server presented no TLS certificate")
			}
			h := sha256.Sum256(cs.PeerCertificates[0].Raw)
			got := hex.EncodeToString(h[:])
			if got != pinned {
				return fmt.Errorf("interlink: TLS certificate fingerprint mismatch (want %s…, got %s…)",
					pinned[:16], got[:16])
			}
			return nil
		}
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConf},
	}
}

// captureCertFingerprint returns the SHA-256 fingerprint of the TLS leaf cert
// at url without verifying the certificate chain.
func captureCertFingerprint(url string) string {
	var fp string
	tlsConf := &tls.Config{ //nolint:gosec
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 {
				h := sha256.Sum256(cs.PeerCertificates[0].Raw)
				fp = hex.EncodeToString(h[:])
			}
			return nil
		},
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConf},
	}
	resp, err := client.Get(url + "/api/interlink/ping")
	if err != nil {
		return ""
	}
	resp.Body.Close()
	return fp
}

// CaptureTLSFingerprint returns the SHA-256 fingerprint of the TLS certificate
// presented by url. Used to record a peer's fingerprint for TOFU pinning.
func CaptureTLSFingerprint(url string) string {
	return captureCertFingerprint(url)
}

// InterlinkPingResponse is what /api/interlink/ping returns.
type InterlinkPingResponse struct {
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	OK       bool   `json:"ok"`
}

// PingServer calls GET <url>/api/interlink/ping and returns the remote hostname + version.
// tlsFP is the expected SHA-256 certificate fingerprint for pinning; pass "" on first contact
// (TOFU) to accept any certificate.
func PingServer(url, tlsFP string) (hostname, version string, err error) {
	resp, err := interlinkClientFor(tlsFP).Get(url + "/api/interlink/ping")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("ping returned status %d", resp.StatusCode)
	}
	var p InterlinkPingResponse
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return "", "", err
	}
	return p.Hostname, p.Version, nil
}

// AcceptLinkRequest is the payload sent to the remote server during linking.
type AcceptLinkRequest struct {
	CallerURL      string `json:"caller_url"`
	CallerHostname string `json:"caller_hostname"`
	CallerID       string `json:"caller_id"`
	SharedSecret   string `json:"shared_secret"`
	AdminUsername  string `json:"admin_username"`
	AdminPassword  string `json:"admin_password"`
	AdminTOTP      string `json:"admin_totp,omitempty"`
}

// AcceptLinkResponse is what the remote server returns.
//
// ExistingPeers (v6.5.42) carries the remote's current InterLink list at
// accept time (URL + Hostname only — no secrets, no IDs). The caller uses
// it to auto-propagate the link to the rest of the remote's cluster:
// when admin A links to B and B already knows {C, D, E}, A iterates this
// list and runs accept-link against each peer too, so A ends up linked to
// every member of the cluster in one operation. Skipped if the remote
// pre-dates this field (omitempty + nil-safe iteration on the caller).
type AcceptLinkResponse struct {
	RemoteID      string       `json:"remote_id"`
	Hostname      string       `json:"hostname"`
	TOTPNeeded    bool         `json:"totp_needed"`
	ExistingPeers []LinkedPeer `json:"existing_peers,omitempty"`
}

// LinkedPeer is the lightweight "this is who I know" entry returned in
// AcceptLinkResponse.ExistingPeers. Only the URL is operationally useful
// (the caller pings it to capture a TLS fingerprint, then opens an
// accept-link of its own); Hostname is included so the UI can display a
// friendly name in the cluster-propagation summary without a second
// round-trip per peer.
type LinkedPeer struct {
	URL      string `json:"url"`
	Hostname string `json:"hostname"`
}

// SendAcceptLink calls POST <url>/api/interlink/accept-link.
// tlsFP pins the TLS certificate; pass "" on first contact (TOFU).
func SendAcceptLink(url, tlsFP string, req AcceptLinkRequest) (*AcceptLinkResponse, error) {
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(url+"/api/interlink/accept-link", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		var e struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&e) //nolint:errcheck
		if e.Error != "" {
			return nil, fmt.Errorf("remote rejected credentials: %s", e.Error)
		}
		return nil, fmt.Errorf("remote rejected credentials")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("accept-link returned status %d", resp.StatusCode)
	}
	var r AcceptLinkResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// CheckUserRequest is the HMAC-signed payload for /api/interlink/check-user.
type CheckUserRequest struct {
	Username  string `json:"username"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// CheckUserResponse is what the remote server returns.
type CheckUserResponse struct {
	Exists bool `json:"exists"`
}

// CheckUserOnRemote calls POST <url>/api/interlink/check-user, signing with sharedSecret.
// tlsFP pins the TLS certificate of the remote server.
func CheckUserOnRemote(remoteURL, sharedSecret, username, tlsFP string) (*CheckUserResponse, error) {
	return checkUserVia(interlinkClientFor(tlsFP), remoteURL, sharedSecret, username)
}

func checkUserVia(client *http.Client, remoteURL, sharedSecret, username string) (*CheckUserResponse, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	req := CheckUserRequest{
		Username:  username,
		Timestamp: time.Now().Unix(),
		Nonce:     hex.EncodeToString(nonce),
	}
	// HMAC payload: "<username>|<timestamp>|<nonce>"
	req.HMAC = checkUserHMAC(sharedSecret, req.Username, req.Timestamp, req.Nonce)

	body, _ := json.Marshal(req)
	resp, err := client.Post(remoteURL+"/api/interlink/check-user", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, interlinkHTTPErr("check-user", resp)
	}
	var r CheckUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// CheckUserHMAC computes the HMAC for a check-user request.
// Exported so handlers/interlink.go can verify inbound requests.
func CheckUserHMAC(sharedSecret, username string, timestamp int64, nonce string) string {
	return checkUserHMAC(sharedSecret, username, timestamp, nonce)
}

func checkUserHMAC(sharedSecret, username string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte(username + "|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// relayClientCache caches one HTTP client per TLS fingerprint so all relay
// requests to the same server reuse a single connection pool instead of
// opening a new TCP connection per request.
var (
	relayClientMu    sync.Mutex
	relayClientCache = map[string]*http.Client{}
)

// InterlinkClientForRelay returns a cached HTTP client suitable for relay
// proxying.  Clients are keyed by TLS fingerprint and created once.
func InterlinkClientForRelay(tlsFP string) *http.Client {
	relayClientMu.Lock()
	c, ok := relayClientCache[tlsFP]
	if !ok {
		c = interlinkRelayClientFor(tlsFP)
		relayClientCache[tlsFP] = c
	}
	relayClientMu.Unlock()
	// Return a shallow COPY: the Transport (and thus the connection pool) is
	// shared via its pointer, but Timeout is a value field — so a caller that
	// sets its own Timeout can't poison the shared client for everyone else.
	// (This bit us once: an aggregate set Timeout=3s, capping /api/updates/check
	// relays at 3s → "the peer took too long to respond".)
	cp := *c
	return &cp
}

// interlinkRelayClientFor builds the HTTP client used for relay PROXYING.
// Unlike interlinkClientFor — a fixed 30s *total* deadline, fine for the tiny
// ping/link/check-user calls — relayed requests can wrap genuinely slow remote
// handlers (e.g. /api/updates/check runs `apt-get update` on the peer, routinely
// well over 30s). A hard client Timeout aborts those mid-flight with the classic
// "context deadline exceeded (Client.Timeout exceeded while awaiting headers)".
//
// So this client carries NO total Timeout; the caller bounds each request with a
// per-endpoint context deadline instead (generous for the slow ones). To still
// fail FAST when a peer is genuinely unreachable, the connection-level timeouts
// (dial + TLS handshake) stay tight — a dead host errors in ~8s regardless of
// how long the per-request budget is.
func interlinkRelayClientFor(tlsFP string) *http.Client {
	return &http.Client{
		Timeout: 0, // no total deadline — the request context bounds each call
		Transport: &http.Transport{
			TLSClientConfig:       InterlinkTLSConfigForRelay(tlsFP),
			DialContext:           (&net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   8 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
}

// InterlinkTLSConfigForRelay returns the TLS config used for relay connections.
// Used by the WebSocket dialer in the relay proxy.
func InterlinkTLSConfigForRelay(tlsFP string) *tls.Config {
	tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	if tlsFP != "" {
		pinned := tlsFP
		tlsConf.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("interlink: server presented no TLS certificate")
			}
			h := sha256.Sum256(cs.PeerCertificates[0].Raw)
			got := hex.EncodeToString(h[:])
			if got != pinned {
				return fmt.Errorf("interlink: TLS certificate fingerprint mismatch (want %s…, got %s…)",
					pinned[:16], got[:16])
			}
			return nil
		}
	}
	return tlsConf
}

// RelayForwardHMAC signs an outbound relay-proxy request.
// The "relay|" prefix is distinct from all other interlink HMAC prefixes,
// preventing cross-endpoint HMAC reuse.
func RelayForwardHMAC(sharedSecret, username string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("relay|" + username + "|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// GenerateSharedSecret creates a random 32-byte hex secret.
func GenerateSharedSecret() string {
	b := make([]byte, 32)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

// RemoteUnlinkRequest is the HMAC-signed payload for /api/interlink/remote-unlink.
// RemoteID is our local ID as known by the receiving server.
type RemoteUnlinkRequest struct {
	RemoteID  string `json:"remote_id"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// RemoteUnlinkHMAC computes the HMAC for a remote-unlink request.
func RemoteUnlinkHMAC(sharedSecret, remoteID string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("unlink|" + remoteID + "|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// SendRemoteUnlink calls POST <url>/api/interlink/remote-unlink, asking the remote
// server to remove us from its linked-server list. Errors are ignored (best-effort).
// tlsFP pins the TLS certificate of the remote server.
// removed says whether the remote really removed the link: it answers 200 even
// when the signature did not match. A version that does not report it counts as removed.
func SendRemoteUnlink(remoteURL, sharedSecret, remoteID, tlsFP string) (removed bool, err error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	req := RemoteUnlinkRequest{
		RemoteID:  remoteID,
		Timestamp: ts,
		Nonce:     hex.EncodeToString(nonce),
		HMAC:      RemoteUnlinkHMAC(sharedSecret, remoteID, ts, hex.EncodeToString(nonce)),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientWithin(tlsFP, 8*time.Second).Post(remoteURL+"/api/interlink/remote-unlink", "application/json", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("remote-unlink returned status %d", resp.StatusCode)
	}
	var r struct {
		Removed *bool `json:"removed"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&r)
	return r.Removed == nil || *r.Removed, nil
}
