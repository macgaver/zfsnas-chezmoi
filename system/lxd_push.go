package system

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/config"
	"zfsnas/internal/pushinterlink"
)

// lxdConfigDir returns the directory where the incus CLI stores its config
// and remote-server certs. Incus on Debian is deb-only (no snap variant), so
// the path is always ~/.config/incus/.
func lxdConfigDir() string {
	u, _ := user.Lookup("zfsnas")
	home := "/home/zfsnas"
	if u != nil {
		home = u.HomeDir
	}
	return filepath.Join(home, ".config", "incus")
}

// LXDEnsureClientCert ensures a client cert/key exist in the lxc config dir.
// For snap LXD, the snap generates its own cert on first use — this is a no-op
// if the cert already exists. Only generates a new one for non-snap installs.
func LXDEnsureClientCert() error {
	dir := lxdConfigDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")

	if _, err := os.Stat(certPath); err == nil {
		return nil // already exists (snap or prior run)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir lxc config: %w", err)
	}

	// Look up zfsnas uid/gid for ownership.
	u, _ := user.Lookup("zfsnas")
	var uid, gid int
	if u != nil {
		fmt.Sscanf(u.Uid, "%d", &uid)
		fmt.Sscanf(u.Gid, "%d", &gid)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "znas"
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "znas-lxc-" + hostname,
			Organization: []string{"ZNAS"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	// Write cert
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("open cert file: %w", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		certFile.Close()
		return fmt.Errorf("write cert: %w", err)
	}
	certFile.Close()

	// Write key
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open key file: %w", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}); err != nil {
		keyFile.Close()
		return fmt.Errorf("write key: %w", err)
	}
	keyFile.Close()

	// Fix ownership if we know the zfsnas user.
	if u != nil {
		os.Lchown(dir, uid, gid)      //nolint:errcheck
		os.Lchown(certPath, uid, gid) //nolint:errcheck
		os.Lchown(keyPath, uid, gid)  //nolint:errcheck
	}

	return nil
}

// LXDGetLocalCertPEM reads and returns the local lxc client certificate PEM.
func LXDGetLocalCertPEM() (string, error) {
	certPath := filepath.Join(lxdConfigDir(), "client.crt")
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("read lxc client cert: %w", err)
	}
	return string(data), nil
}

// lxdCertFingerprint returns the SHA-256 fingerprint of a PEM certificate,
// formatted as colon-separated hex pairs (the format lxc trust remove expects).
func lxdCertFingerprint(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	fp := sha256.Sum256(cert.Raw)
	parts := make([]string, len(fp))
	for i, b := range fp {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

// LXDRegisterPeerCert registers a peer's lxc client certificate in the local
// LXD trust store. Works with both LXD 4.x (lxc config trust add) and
// LXD 5.x (lxc config trust add-certificate [--name]).
func LXDRegisterPeerCert(peerCertPEM, peerID string) error {
	tmp, err := os.CreateTemp("", "znas-peer-*.pem")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.WriteString(peerCertPEM); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	// Remove any existing cert for this peer (by fingerprint, works in all versions).
	if fp := lxdCertFingerprint(peerCertPEM); fp != "" {
		exec.Command("incus", "config", "trust", "remove", fp).Run() //nolint:errcheck
	}
	// Also try removing by name (LXD 5.x).
	exec.Command("incus", "config", "trust", "remove", "znas-interlink-"+peerID).Run() //nolint:errcheck

	// Try LXD 5.x syntax with --name first.
	name := "znas-interlink-" + peerID
	out, err := exec.Command("incus", "config", "trust", "add-certificate", tmpPath, "--name", name).CombinedOutput()
	if err == nil {
		return nil
	}
	outStr := strings.TrimSpace(string(out))

	// Fall back to add-certificate without --name (LXD 5.x, older patch).
	if strings.Contains(outStr, "--name") || strings.Contains(outStr, "unknown flag") {
		out, err = exec.Command("incus", "config", "trust", "add-certificate", tmpPath).CombinedOutput()
		if err == nil {
			return nil
		}
		outStr = strings.TrimSpace(string(out))
	}

	// Fall back to legacy LXD 4.x syntax.
	if strings.Contains(outStr, "add-certificate") || strings.Contains(outStr, "unknown command") || strings.Contains(outStr, "unknown sub") {
		out, err = exec.Command("incus", "config", "trust", "add", tmpPath).CombinedOutput()
		if err != nil {
			errOut := strings.TrimSpace(string(out))
			if strings.Contains(errOut, "already") || strings.Contains(errOut, "trust store") {
				return nil // already trusted — idempotent
			}
			return fmt.Errorf("lxc config trust add: %w — %s", err, errOut)
		}
		return nil
	}

	// Any variant that says the cert is already present is a success.
	if strings.Contains(outStr, "already") || strings.Contains(outStr, "trust store") {
		return nil
	}

	return fmt.Errorf("lxc config trust add-certificate: %w — %s", err, outStr)
}

// LXDEnsurePeerRemote adds or updates an lxc remote for a peer server so that
// lxc copy can reach it. remoteName is "znas-<serverID>", addr is "https://<ip>:8444".
// Writes directly to the lxc config.yml to avoid the interactive password prompt
// that `lxc remote add` always triggers regardless of cert pre-trust.
func LXDEnsurePeerRemote(serverID, addr string) error {
	remoteName := "znas-" + serverID

	// Check if remote already exists (lxc remote list reads the config file).
	out, _ := exec.Command("incus", "remote", "list", "--format", "json").Output()
	var rawRemotes map[string]struct {
		Addr string `json:"addr"`
	}
	json.Unmarshal(out, &rawRemotes) //nolint:errcheck
	if existing, ok := rawRemotes[remoteName]; ok {
		if existing.Addr == addr {
			return nil
		}
		if err := exec.Command("incus", "remote", "set-url", remoteName, addr).Run(); err != nil {
			return fmt.Errorf("lxc remote set-url: %w", err)
		}
		return nil
	}

	// Write the remote directly to ~/.config/lxc/config.yml.
	// `lxc remote add --auth-type tls` always prompts for an admin password/token
	// interactively (via stdin), even when the cert is pre-trusted, so we bypass it.
	return lxdWriteRemoteConfig(remoteName, addr)
}

// lxdWriteRemoteConfig adds a TLS remote entry directly to the lxc config.yml.
func lxdWriteRemoteConfig(remoteName, addr string) error {
	configPath := filepath.Join(lxdConfigDir(), "config.yml")

	var lines []string
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		// Minimal config matching snap lxd's default format.
		lines = []string{
			"default-remote: local",
			"remotes:",
			"  local:",
			"    addr: unix://",
			"    public: false",
			"aliases: {}",
			"",
		}
	} else if err != nil {
		return fmt.Errorf("read lxc config: %w", err)
	} else {
		lines = strings.Split(string(data), "\n")
	}

	// Minimal TLS remote entry. skip_tls_verify because the peer uses a
	// self-signed cert; trust is established by the cert exchange via HMAC.
	entry := []string{
		"  " + remoteName + ":",
		"    addr: " + addr,
		"    auth_type: tls",
		"    public: false",
		"    skip_tls_verify: true",
	}

	// Find the existing remote block (if any) so we can replace it.
	remoteHeaderLine := "  " + remoteName + ":"
	start, end := -1, -1
	for i, l := range lines {
		if l == remoteHeaderLine {
			start = i
			continue
		}
		if start >= 0 && end < 0 {
			// Sub-fields are 4-space indented; the block ends at the next 2-space or
			// 0-space line (next remote name or top-level key).
			if !strings.HasPrefix(l, "    ") {
				end = i
				break
			}
		}
	}
	if start >= 0 && end < 0 {
		end = len(lines)
	}

	var out []string
	if start >= 0 {
		// Replace existing entry.
		out = append(out, lines[:start]...)
		out = append(out, entry...)
		out = append(out, lines[end:]...)
	} else {
		// Find "remotes:" and insert after it.
		inserted := false
		for _, l := range lines {
			out = append(out, l)
			if l == "remotes:" && !inserted {
				out = append(out, entry...)
				inserted = true
			}
		}
		if !inserted {
			out = append(out, "remotes:")
			out = append(out, entry...)
		}
	}

	content := []byte(strings.Join(out, "\n"))
	if err := os.WriteFile(configPath, content, 0600); err != nil {
		return fmt.Errorf("write lxc config: %w", err)
	}

	// Fix ownership so the zfsnas user can read it.
	u, _ := user.Lookup("zfsnas")
	if u != nil {
		var uid, gid int
		fmt.Sscanf(u.Uid, "%d", &uid)
		fmt.Sscanf(u.Gid, "%d", &gid)
		os.Lchown(configPath, uid, gid) //nolint:errcheck
	}
	return nil
}

// ── HMAC helpers for LXD interlink cert exchange ──────────────────────────────

// LXDInterlinkCertHMAC signs a request to fetch the peer's lxc client cert.
func LXDInterlinkCertHMAC(sharedSecret string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("lxd-cert|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// LXDInterlinkTrustHMAC signs a request to register a cert in the peer's LXD.
func LXDInterlinkTrustHMAC(sharedSecret, certPEM string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("lxd-trust|" + certPEM + "|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// LXDInterlinkCertRequest is the HMAC-signed POST /api/incus/interlink-cert payload.
type LXDInterlinkCertRequest struct {
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// LXDInterlinkCertResponse is returned by POST /api/incus/interlink-cert.
type LXDInterlinkCertResponse struct {
	CertPEM string `json:"cert_pem"`
}

// LXDInterlinkTrustRequest is the HMAC-signed POST /api/incus/interlink-trust payload.
type LXDInterlinkTrustRequest struct {
	CertPEM   string `json:"cert_pem"`
	PeerID    string `json:"peer_id"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// GetRemoteLXDCert fetches the lxc client cert PEM from a peer ZNAS server.
func GetRemoteLXDCert(remoteURL, sharedSecret, tlsFP string) (string, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := LXDInterlinkCertRequest{
		Timestamp: ts,
		Nonce:     nh,
		HMAC:      LXDInterlinkCertHMAC(sharedSecret, ts, nh),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/incus/interlink-cert", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("interlink-cert returned status %d", resp.StatusCode)
	}
	var r LXDInterlinkCertResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	return r.CertPEM, nil
}

// SendLXDCertToRemote posts our lxc client cert to a peer ZNAS server so it
// can register it in its local LXD trust store.
// ourID is our local LinkedServer.ID as known by the remote (ls.RemoteID).
func SendLXDCertToRemote(remoteURL, sharedSecret, tlsFP, certPEM, ourID string) error {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := LXDInterlinkTrustRequest{
		CertPEM:   certPEM,
		PeerID:    ourID,
		Timestamp: ts,
		Nonce:     nh,
		HMAC:      LXDInterlinkTrustHMAC(sharedSecret, certPEM, ts, nh),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/incus/interlink-trust", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("interlink-trust returned status %d", resp.StatusCode)
	}
	return nil
}

// LXDSyncInterlinkTrustForPeer performs a bidirectional LXD certificate
// exchange with a single linked server. Self-heals on every call:
//   - regenerates our own LXD server cert if it lacks public-IP SANs
//   - pins the listener address to <publicIP>:8444 so migration peers don't
//     try unreachable internal-bridge addresses first
//   - exchanges and registers each side's lxc CLI client cert (legacy)
//   - fetches the peer's server cert and pins it in
//     <lxd-config-dir>/servercerts/<remote>.crt so the lxc CLI accepts the
//     self-signed cert (modern LXD ignores skip_tls_verify)
//   - also adds the peer's server cert to our local LXD trust store so
//     daemon-to-daemon migration transfers authenticate
//
// Returns error if either CLI-cert direction fails. Server-cert work is
// best-effort — it logs warnings rather than failing the whole sync because
// older LXD installs without the SAN/pinning issue don't need it.
func LXDSyncInterlinkTrustForPeer(ls config.LinkedServer, _ string) error {
	// Step 0 — self-heal our own server cert + listener address.
	if err := LXDEnsureServerCertSAN(); err != nil {
		fmt.Printf("lxd interlink: ensure own server cert SAN: %v\n", err)
	}
	LXDPinSelfHTTPSAddress()

	if err := LXDEnsureClientCert(); err != nil {
		return fmt.Errorf("ensure local cert: %w", err)
	}

	ourCert, err := LXDGetLocalCertPEM()
	if err != nil {
		return fmt.Errorf("read local cert: %w", err)
	}

	// Fetch the remote's lxc CLI cert (HMAC-authenticated portal endpoint).
	peerCert, err := GetRemoteLXDCert(ls.URL, ls.SharedSecret, ls.TLSFingerprint)
	if err != nil {
		return fmt.Errorf("fetch peer cert: %w", err)
	}

	// Register their cert in our LXD.
	if err := LXDRegisterPeerCert(peerCert, ls.ID); err != nil {
		return fmt.Errorf("register peer cert: %w", err)
	}

	// Send our cert to the remote BEFORE adding the lxc remote.
	// lxc remote add connects to peer LXD and must authenticate; the peer
	// must trust our cert at that point or it falls back to password prompt.
	if err := SendLXDCertToRemote(ls.URL, ls.SharedSecret, ls.TLSFingerprint, ourCert, ls.RemoteID); err != nil {
		return fmt.Errorf("send cert to remote: %w", err)
	}

	// Step 1.5 — fetch peer's SERVER cert via TLS handshake and pin it. Without
	// this the lxc CLI rejects the connection with "unknown authority" because
	// modern LXD ignores skip_tls_verify in the remote's config. Also add it
	// to our LXD trust store so daemon-to-daemon migration transfers work.
	peerIP := extractHost(ls.URL)
	if peerServerCert, fetchErr := LXDFetchPeerServerCert(peerIP); fetchErr == nil {
		remoteName := "znas-" + ls.ID
		if err := LXDPinPeerServerCert(remoteName, peerServerCert); err != nil {
			fmt.Printf("lxd interlink: pin peer server cert: %v\n", err)
		}
		// Use the SHA-256 fingerprint as the trust-store name; LXDRegisterPeerCert
		// already de-dupes by fingerprint and tolerates re-runs.
		if err := LXDRegisterPeerCert(peerServerCert, ls.ID+"-server"); err != nil {
			fmt.Printf("lxd interlink: register peer server cert in trust: %v\n", err)
		}
	} else {
		fmt.Printf("lxd interlink: fetch peer server cert: %v\n", fetchErr)
	}

	// Now add the lxc remote — peer trusts our cert so no password is needed.
	peerLXDAddr := "https://" + peerIP + ":8444"
	if err := LXDEnsurePeerRemote(ls.ID, peerLXDAddr); err != nil {
		return fmt.Errorf("add lxc remote: %w", err)
	}

	return nil
}

// LXDSyncInterlinkTrust triggers bidirectional cert exchange with all linked
// peers that have LXD available. Non-fatal per-peer. Should be called from a goroutine.
func LXDSyncInterlinkTrust(appCfg *config.AppConfig) {
	if !LXDAvailable() {
		return
	}
	for _, ls := range appCfg.InterLink {
		ls := ls
		if !RemotePingHasLXD(ls.URL, ls.TLSFingerprint) {
			continue
		}
		if err := LXDSyncInterlinkTrustForPeer(ls, ls.ID); err != nil {
			fmt.Printf("lxd interlink sync: peer %s (%s): %v\n", ls.Hostname, ls.ID, err)
		}
	}
}

// extractHost parses a URL and returns host without port.
func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	h := u.Hostname()
	if h == "" {
		return rawURL
	}
	return h
}

// ── LXD peer remote status ────────────────────────────────────────────────────

// LXDPeerStatus describes the lxc remote + trust state for one linked server.
type LXDPeerStatus struct {
	RemoteRegistered bool `json:"remote_registered"`
	CertRegistered   bool `json:"cert_registered"`
}

// LXDGetPeerStatus returns LXD connection status for all linked servers.
func LXDGetPeerStatus(interlinks []config.LinkedServer) map[string]LXDPeerStatus {
	result := make(map[string]LXDPeerStatus, len(interlinks))

	// List existing remotes.
	remoteOut, _ := exec.Command("incus", "remote", "list", "--format", "json").Output()
	var rawRemotes map[string]interface{}
	json.Unmarshal(remoteOut, &rawRemotes) //nolint:errcheck

	// List existing trust certs.
	trustOut, _ := exec.Command("incus", "config", "trust", "list", "--format", "json").Output()
	var rawTrust []struct {
		Name string `json:"name"`
	}
	json.Unmarshal(trustOut, &rawTrust) //nolint:errcheck
	trustedNames := map[string]bool{}
	for _, t := range rawTrust {
		trustedNames[t.Name] = true
	}

	for _, ls := range interlinks {
		remoteName := "znas-" + ls.ID
		trustName := "znas-interlink-" + ls.ID
		result[ls.ID] = LXDPeerStatus{
			RemoteRegistered: rawRemotes != nil && rawRemotes[remoteName] != nil,
			CertRegistered:   trustedNames[trustName],
		}
	}
	return result
}

// ── VM Push job ───────────────────────────────────────────────────────────────

// LXDPushVMRequest describes a VM migration request.
type LXDPushVMRequest struct {
	VMName          string            `json:"vm_name"`
	DestName        string            `json:"dest_name"`
	DestDescription string            `json:"dest_description"`
	ServerID        string            `json:"server_id"`
	StoragePool     string            `json:"storage_pool"`
	NICMap          map[string]string `json:"nic_map"` // local-device-name → remote-bridge-name
}

// sanitizeLXDName strips whitespace and replaces any character not allowed in
// LXD instance names (lowercase letters, digits, hyphens) with a hyphen, then
// trims leading/trailing hyphens.
func sanitizeLXDName(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// LXDPushVM runs a VM migration to a remote LXD server in a background job.
// Must be called as a goroutine. ctx is derived from the job cancel function.
func LXDPushVM(ctx context.Context, req LXDPushVMRequest, job *pushinterlink.Job, ls config.LinkedServer) {
	// Ensure the destination name is a valid LXD instance name.
	if req.DestName == "" {
		req.DestName = req.VMName
	}
	req.DestName = sanitizeLXDName(req.DestName)
	if req.DestName == "" {
		pushinterlink.Default.Finish(job.ID, fmt.Errorf("invalid destination name"))
		return
	}

	remoteName := "znas-" + req.ServerID
	destRef := remoteName + ":" + req.DestName

	remoteExists := func() bool {
		out, _ := exec.Command("incus", "remote", "list", "--format", "json").Output()
		var m map[string]interface{}
		json.Unmarshal(out, &m) //nolint:errcheck
		return m != nil && m[remoteName] != nil
	}

	// Pre-flight, part 1: make sure the lxc remote exists. The full bidirectional
	// sync also handles the CLI-cert exchange the first time around.
	if !remoteExists() {
		if syncErr := LXDSyncInterlinkTrustForPeer(ls, ls.ID); syncErr != nil {
			pushinterlink.Default.Finish(job.ID, fmt.Errorf("LXD peer trust not configured and auto-sync failed: %v", syncErr))
			return
		}
	}

	// Pre-flight, part 2: ALWAYS refresh the pinned destination server cert.
	// This is the step that prevents the recurring
	//   "x509: certificate signed by unknown authority … candidate authority <peer>"
	// failure that happens when the destination's Incus daemon cert was
	// regenerated (cert SAN self-heal, reinstall, …) after this remote was first
	// added. We call the standalone re-pin rather than the full sync because the
	// full sync can error on its HMAC/CLI-cert steps and return BEFORE reaching
	// its own pin — which is exactly why the stale cert kept slipping through.
	// Best-effort: if the destination is unreachable the copy will fail anyway,
	// and the TLS-error retry below gives a second chance.
	if repinErr := LXDRepinPeerServerCert(ls); repinErr != nil {
		fmt.Printf("lxd push: re-pin %s server cert warned (continuing): %v\n", ls.Hostname, repinErr)
	}

	pushinterlink.Default.SetRunning(job.ID, 0)

	// Progress poller runs until copy finishes.
	var stopOnce sync.Once
	stopCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			case <-ticker.C:
				pollLXDCopyProgress(job)
			}
		}
	}()

	// Collect disconnected NIC configs from the source before the copy so we can
	// re-attach them on the destination after lxc copy (lxc copy copies the
	// user.disconnected_nics.* config keys but NOT the missing device entries).
	disconnNICs := lxdGetDisconnectedNICConfigs(req.VMName)

	copyErr := lxdCopyWithCompatStrip(ctx, req.VMName, destRef, req.StoragePool)
	// Auto-recover from a stale destination server cert: if the copy failed TLS
	// verification, re-pin the peer's current cert and retry once. The pre-sync
	// above normally prevents this, but the cert could rotate between sync and
	// copy, or a partial pin could leave the old cert in place.
	if copyErr != nil && ctx.Err() == nil && isLXDTLSTrustError(copyErr) {
		fmt.Printf("lxd push: copy hit a TLS trust error, re-pinning %s server cert and retrying: %v\n", ls.Hostname, copyErr)
		if repinErr := LXDRepinPeerServerCert(ls); repinErr != nil {
			fmt.Printf("lxd push: re-pin failed: %v\n", repinErr)
		} else {
			copyErr = lxdCopyWithCompatStrip(ctx, req.VMName, destRef, req.StoragePool)
		}
	}
	stopOnce.Do(func() { close(stopCh) })
	if copyErr != nil {
		if ctx.Err() != nil {
			pushinterlink.Default.Finish(job.ID, ctx.Err())
		} else {
			pushinterlink.Default.Finish(job.ID, copyErr)
		}
		return
	}

	// UEFI/TPM repairs only apply to virtual machines. Containers share the host
	// kernel and have no NVRAM or swtpm state, so skip these remote round-trips
	// for them (they would otherwise log misleading "failed" warnings).
	if lxdInstanceIsVM(req.VMName) {
		// Repair UEFI boot on the destination: reset NVRAM + fix EFI fallback boot
		// path.  Required after cross-version migration (e.g. LXD 6.7 → 5.0) where
		// NVRAM device-path entries are stale and EFI/BOOT/grub.cfg may be absent.
		if repairErr := ResetRemoteVMNVRAM(ls.URL, ls.SharedSecret, ls.TLSFingerprint, req.DestName); repairErr != nil {
			fmt.Printf("lxd push: EFI boot repair on remote failed (non-fatal): %v\n", repairErr)
		}

		// Clear swtpm state on the destination.  The state file copied from the source
		// is tied to the source OVMF session; using it on a different OVMF build
		// causes QEMU to exit with a TPM fatal error on every cold start.
		if tpmErr := ClearRemoteTPMState(ls.URL, ls.SharedSecret, ls.TLSFingerprint, req.DestName); tpmErr != nil {
			fmt.Printf("lxd push: TPM state clear on remote failed (non-fatal): %v\n", tpmErr)
		}
	}

	// Apply NIC overrides on destination.
	for nicDevice, remoteBridge := range req.NICMap {
		if remoteBridge == "" {
			continue
		}
		if conf, wasDisconnected := disconnNICs[nicDevice]; wasDisconnected {
			// NIC was disconnected on the source — it has no device entry, only a
			// user.disconnected_nics.* config key. Add it as a real device on the
			// destination with the remapped bridge.
			args := []string{"config", "device", "add", destRef, nicDevice,
				"type=nic", "nictype=bridged", "parent=" + remoteBridge}
			if conf.MAC != "" {
				args = append(args, "hwaddr="+conf.MAC)
			}
			if out, err := exec.CommandContext(ctx, "incus", args...).CombinedOutput(); err != nil {
				fmt.Printf("lxd push: add disconnected nic %s → %s: %v — %s\n",
					nicDevice, remoteBridge, err, strings.TrimSpace(string(out)))
			} else {
				// Remove the stale disconnected-NIC marker from the destination.
				exec.CommandContext(ctx, "incus", "config", "unset", destRef,
					"user.disconnected_nics."+nicDevice).Run() //nolint:errcheck
			}
		} else {
			// NIC exists as an active device — just override the bridge parent.
			overrideArgs := []string{"config", "device", "set", destRef, nicDevice, "parent=" + remoteBridge}
			if out, err := exec.CommandContext(ctx, "incus", overrideArgs...).CombinedOutput(); err != nil {
				fmt.Printf("lxd push nic override %s → %s: %v — %s\n",
					nicDevice, remoteBridge, err, strings.TrimSpace(string(out)))
			}
		}
	}

	// Set the destination VM's description (user-supplied, falling back to the name).
	desc := req.DestDescription
	if desc == "" {
		desc = req.DestName
	}
	exec.CommandContext(ctx, "incus", "config", "set", destRef, "description", desc).Run() //nolint:errcheck

	pushinterlink.Default.Finish(job.ID, nil)
}

// LXDRepinPeerServerCert fetches the peer's CURRENT LXD/Incus server cert over
// a fresh TLS handshake and overwrites the pinned servercerts/<remote>.crt that
// the local `incus` CLI checks the destination against. This is deliberately
// standalone — unlike LXDSyncInterlinkTrustForPeer it does NOT depend on the
// HMAC portal round-trips or the CLI-cert exchange, which can fail and abort
// that function before it ever reaches its pin step (leaving a stale cert in
// place). Healing the pin here is what fixes the recurring
//
//	"x509: certificate signed by unknown authority … candidate authority <peer>"
//
// copy failure after the destination's daemon cert rotates.
func LXDRepinPeerServerCert(ls config.LinkedServer) error {
	peerIP := extractHost(ls.URL)
	cert, err := LXDFetchPeerServerCert(peerIP)
	if err != nil {
		return fmt.Errorf("fetch peer server cert: %w", err)
	}
	if err := LXDPinPeerServerCert("znas-"+ls.ID, cert); err != nil {
		return err
	}
	// Best-effort: also (re)register in the local trust store for the
	// daemon-to-daemon transfer leg. De-dupes by fingerprint, tolerates re-runs.
	if regErr := LXDRegisterPeerCert(cert, ls.ID+"-server"); regErr != nil {
		fmt.Printf("lxd push: register peer server cert in trust: %v\n", regErr)
	}
	return nil
}

// isLXDTLSTrustError reports whether an lxc copy error is a destination-cert
// trust failure — the signature of a stale pinned server cert that a trust
// re-sync can heal. Matched on the daemon's error text since the copy runs as
// an external `incus`/`lxc` process and only surfaces a string.
func isLXDTLSTrustError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "certificate signed by unknown authority") ||
		strings.Contains(s, "tls: failed to verify certificate") ||
		strings.Contains(s, "x509:")
}

// lxdCopyWithCompatStrip runs lxc copy and retries automatically when LXD
// rejects unknown config keys, invalid device options, or devices referencing
// missing storage pools.  Offending keys/options are temporarily stripped on
// the source for the duration of the copy and restored afterwards.
func lxdCopyWithCompatStrip(ctx context.Context, vmName, destRef, storagePool string) error {
	type kv struct{ key, val string }
	type devKV struct{ devName, key, val string }
	type dev struct {
		name   string
		config map[string]string
	}
	var stripped []kv
	var strippedDevOpts []devKV
	var strippedDevs []dev

	defer func() {
		for _, item := range stripped {
			if item.val != "" {
				exec.Command("incus", "config", "set", vmName, item.key, item.val).Run() //nolint:errcheck
			} else {
				exec.Command("incus", "config", "unset", vmName, item.key).Run() //nolint:errcheck
			}
		}
		for _, item := range strippedDevOpts {
			exec.Command("incus", "config", "device", "set", vmName, item.devName, item.key+"="+item.val).Run() //nolint:errcheck
		}
		for _, d := range strippedDevs {
			args := []string{"config", "device", "add", vmName, d.name}
			for k, v := range d.config {
				args = append(args, k+"="+v)
			}
			exec.Command("incus", args...).Run() //nolint:errcheck
		}
	}()

	// --mode push: source initiates the data connection to the destination.
	// The default (pull) requires the destination daemon to dial back to the
	// source, which fails when the source's server cert SAN does not include
	// its public IP. Push only needs the destination's cert to be valid.
	args := []string{"copy", vmName, destRef, "--storage", storagePool, "--mode", "push"}

	// lxc copy --storage only remaps the root disk to the destination pool;
	// non-root disks keep their source pool name. When the destination doesn't
	// have a pool with that name, the create fails with "Storage pool not
	// found". Pre-emptively rewrite each non-root disk device's pool to the
	// destination pool via --device <name>,pool=<storagePool> so the data is
	// copied across instead of dropped.
	for _, devName := range lxdNonRootDiskDevices(vmName) {
		args = append(args, "--device", devName+",pool="+storagePool)
	}

	// Custom-volume disks (source=<volname>, no path) are not copied by
	// "lxc copy" — only the instance's own root + state are transferred.
	// Pre-copy each referenced custom volume so the destination has the
	// volume the disk device will attach to. Best-effort: if a volume
	// already exists on the destination we ignore the conflict.
	for _, vol := range lxdCustomVolumesForVM(vmName) {
		copyArgs := []string{"storage", "volume", "copy",
			vol + "@" + storagePool + "→" + storagePool, // placeholder; actual args below
		}
		_ = copyArgs
		srcRef := storagePool + "/" + vol
		dstRef := destRef[:strings.Index(destRef, ":")] + ":" + storagePool + "/" + vol
		out, err := exec.CommandContext(ctx, "incus", "storage", "volume", "copy",
			srcRef, dstRef, "--mode", "push").CombinedOutput()
		if err != nil {
			outStr := strings.TrimSpace(string(out))
			// "already exists" is fine — the volume is already on the destination.
			if !strings.Contains(outStr, "already exists") {
				fmt.Printf("lxd push: pre-copy custom volume %q: %v — %s\n", vol, err, outStr)
			}
		}
	}

	for attempt := 0; attempt < 20; attempt++ {
		out, err := exec.CommandContext(ctx, "incus", args...).CombinedOutput()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		outStr := strings.TrimSpace(string(out))

		// Handle devices referencing storage pools that don't exist on the destination.
		if devName := lxdMissingPoolDevice(outStr); devName != "" {
			devCfg := lxdGetDeviceConfig(vmName, devName)
			if out2, err2 := exec.Command("incus", "config", "device", "remove", vmName, devName).CombinedOutput(); err2 != nil {
				return fmt.Errorf("lxc copy failed (cannot strip device %s): %w — %s", devName, err, strings.TrimSpace(string(out2)))
			}
			strippedDevs = append(strippedDevs, dev{devName, devCfg})
			fmt.Printf("lxd push: destination lacks pool for device %q — stripped for copy, will restore on source\n", devName)
			continue
		}

		// Handle device options not supported by the destination LXD version.
		// Error: Device validation failed for "<dev>": Invalid device option "<key>"
		if devName, optKey := lxdInvalidDeviceOption(outStr); devName != "" {
			valOut, _ := exec.Command("incus", "config", "device", "get", vmName, devName, optKey).Output()
			val := strings.TrimSpace(string(valOut))
			if out2, err2 := exec.Command("incus", "config", "device", "unset", vmName, devName, optKey).CombinedOutput(); err2 != nil {
				return fmt.Errorf("lxc copy failed (cannot strip device option %s.%s): %w — %s", devName, optKey, err, strings.TrimSpace(string(out2)))
			}
			strippedDevOpts = append(strippedDevOpts, devKV{devName, optKey, val})
			fmt.Printf("lxd push: destination does not support device option %q on %q — stripped for copy\n", optKey, devName)
			continue
		}

		key := lxdUnknownConfigKey(outStr)
		if key == "" {
			return fmt.Errorf("lxc copy failed: %w — %s", err, outStr)
		}
		// Fetch current value so we can restore it afterwards.
		valOut, _ := exec.Command("incus", "config", "get", vmName, key).Output()
		val := strings.TrimSpace(string(valOut))
		if err2 := exec.Command("incus", "config", "unset", vmName, key).Run(); err2 != nil {
			return fmt.Errorf("lxc copy failed (cannot strip %s): %w — %s", key, err, outStr)
		}
		stripped = append(stripped, kv{key, val})
		fmt.Printf("lxd push: destination does not support config key %q — stripped for copy\n", key)
	}
	return fmt.Errorf("lxc copy failed: too many retries (stripped keys: %d, stripped device opts: %d, stripped devices: %d)",
		len(stripped), len(strippedDevOpts), len(strippedDevs))
}

// lxdMissingPoolDevice parses LXD's "Storage pool not found" device validation
// error and returns the device name, or "" if the error is a different type.
// The actual error format includes a quoted pool name between the device name
// and "Storage pool not found", so we use .*? rather than [^"]* to span it:
//
//	Failed add validation for device "disk1": Failed to get storage pool "zfspool": Storage pool not found
func lxdMissingPoolDevice(output string) string {
	re := regexp.MustCompile(`Failed add validation for device "([^"]+)".*?Storage pool not found`)
	m := re.FindStringSubmatch(output)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// lxdNonRootDiskDevices returns the names of non-root disk devices on a VM that
// reference a storage pool. The root disk is excluded because lxc copy --storage
// already remaps it to the destination pool.
func lxdNonRootDiskDevices(vmName string) []string {
	out, err := exec.Command("incus", "query", "/1.0/instances/"+vmName).Output()
	if err != nil {
		return nil
	}
	var inst struct {
		Devices         map[string]map[string]string `json:"devices"`
		ExpandedDevices map[string]map[string]string `json:"expanded_devices"`
	}
	if err := json.Unmarshal(out, &inst); err != nil {
		return nil
	}
	// Only consider instance-local devices — profile-inherited disks are handled
	// by the destination's own profile and should not be overridden by the copy.
	var names []string
	for name, cfg := range inst.Devices {
		if cfg["type"] != "disk" {
			continue
		}
		if cfg["path"] == "/" {
			continue // root disk; --storage handles it
		}
		if cfg["pool"] == "" {
			continue // bind-mount / external source — no pool to remap
		}
		names = append(names, name)
	}
	return names
}

// lxdCustomVolumesForVM returns the volume names referenced by non-root disk
// devices on a VM. These are custom storage volumes (source=<volname>) that
// must be pre-copied to the destination before the instance copy, because
// "lxc copy" does not transfer custom volumes — it only copies the instance's
// own root and state.
func lxdCustomVolumesForVM(vmName string) []string {
	out, err := exec.Command("incus", "query", "/1.0/instances/"+vmName).Output()
	if err != nil {
		return nil
	}
	var inst struct {
		Devices map[string]map[string]string `json:"devices"`
	}
	if err := json.Unmarshal(out, &inst); err != nil {
		return nil
	}
	var vols []string
	seen := map[string]bool{}
	for _, cfg := range inst.Devices {
		if cfg["type"] != "disk" {
			continue
		}
		if cfg["path"] == "/" {
			continue
		}
		// A custom volume disk references the volume by name in "source".
		// Bind-mounts use a path (starts with "/") which we skip.
		src := cfg["source"]
		if src == "" || strings.HasPrefix(src, "/") {
			continue
		}
		if !seen[src] {
			seen[src] = true
			vols = append(vols, src)
		}
	}
	return vols
}

// lxdInstanceIsVM reports whether an instance is a virtual-machine (as opposed
// to a container). Used to gate the UEFI-NVRAM / swtpm post-copy repair steps,
// which are meaningless for containers. Defaults to false (container) on error
// so a probe failure can't trigger VM-only remote operations.
func lxdInstanceIsVM(name string) bool {
	out, err := exec.Command("incus", "query", "/1.0/instances/"+name).Output()
	if err != nil {
		return false
	}
	var inst struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(out, &inst); err != nil {
		return false
	}
	return inst.Type == "virtual-machine"
}

// lxdGetDeviceConfig returns the config map for a single device on a VM by
// querying the LXD REST API. Returns an empty map on any error.
func lxdGetDeviceConfig(vmName, devName string) map[string]string {
	out, err := exec.Command("incus", "query", "/1.0/instances/"+vmName).Output()
	if err != nil {
		return map[string]string{}
	}
	var inst struct {
		Devices map[string]map[string]string `json:"devices"`
	}
	if err := json.Unmarshal(out, &inst); err != nil {
		return map[string]string{}
	}
	if cfg, ok := inst.Devices[devName]; ok {
		return cfg
	}
	return map[string]string{}
}

// lxdInvalidDeviceOption parses LXD's "Invalid device option" error and returns
// the device name and option key, or ("", "") if the error is a different type.
// Example: Device validation failed for "root": Invalid device option "io.bus"
func lxdInvalidDeviceOption(output string) (devName, optKey string) {
	re := regexp.MustCompile(`Device validation failed for "([^"]+)"[^"]*Invalid device option "([^"]+)"`)
	m := re.FindStringSubmatch(output)
	if len(m) < 3 {
		return "", ""
	}
	return m[1], m[2]
}

// lxdUnknownConfigKey extracts the key name from LXD's "Unknown configuration key: <key>" error.
func lxdUnknownConfigKey(output string) string {
	const prefix = "Unknown configuration key: "
	idx := strings.Index(output, prefix)
	if idx < 0 {
		return ""
	}
	rest := output[idx+len(prefix):]
	if nl := strings.IndexAny(rest, "\n\r"); nl >= 0 {
		rest = rest[:nl]
	}
	return strings.TrimSpace(rest)
}

// pollLXDCopyProgress queries the local LXD operations API to extract migration progress.
func pollLXDCopyProgress(job *pushinterlink.Job) {
	out, err := exec.Command("incus", "query", "/1.0/operations?recursion=1").Output()
	if err != nil {
		return
	}

	type opItem struct {
		Status   string                 `json:"status"`
		Metadata map[string]interface{} `json:"metadata"`
	}

	var all []opItem

	// LXD 6.x groups operations by status: {"running":[...], "success":[...], ...}.
	// Older LXD returns a flat array [...].
	var grouped map[string]json.RawMessage
	if json.Unmarshal(out, &grouped) == nil && len(grouped) > 0 {
		for _, raw := range grouped {
			var items []opItem
			if json.Unmarshal(raw, &items) == nil {
				all = append(all, items...)
			}
		}
	} else {
		json.Unmarshal(out, &all) //nolint:errcheck
	}

	for _, op := range all {
		if op.Status != "Running" || op.Metadata == nil {
			continue
		}
		progressStr, _ := op.Metadata["download_progress"].(string)
		if progressStr == "" {
			continue
		}
		pct, total := parseMigrationProgress(progressStr)
		if total > 0 {
			sent := int64(float64(total) * float64(pct) / 100)
			pushinterlink.Default.SetRunning(job.ID, total)
			pushinterlink.Default.UpdateProgress(job.ID, sent)
		} else if pct > 0 {
			pushinterlink.Default.SetPercent(job.ID, pct)
		}
		return
	}
}

// parseMigrationProgress parses strings like "50% (3.00GB)" → percent, totalBytes.
func parseMigrationProgress(s string) (pct int, totalBytes int64) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0
	}
	idx := strings.Index(s, "%")
	if idx < 0 {
		return 0, 0
	}
	pStr := strings.TrimSpace(s[:idx])
	fmt.Sscanf(pStr, "%d", &pct)
	if start := strings.Index(s, "("); start >= 0 {
		if end := strings.Index(s[start:], ")"); end >= 0 {
			sizeStr := strings.TrimSpace(s[start+1 : start+end])
			totalBytes = parseSizeStr(sizeStr)
		}
	}
	return
}

func parseSizeStr(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	var val float64
	var unit string
	fmt.Sscanf(s, "%f%s", &val, &unit)
	unit = strings.ToUpper(strings.TrimSpace(unit))
	switch unit {
	case "B":
		return int64(val)
	case "KB", "KIB":
		return int64(val * 1024)
	case "MB", "MIB":
		return int64(val * 1024 * 1024)
	case "GB", "GIB":
		return int64(val * 1024 * 1024 * 1024)
	case "TB", "TIB":
		return int64(val * 1024 * 1024 * 1024 * 1024)
	}
	return 0
}

// ── Remote LXD info proxied via HMAC ─────────────────────────────────────────

// LXDStoragePoolsHMAC signs a request to list remote LXD storage pools.
func LXDStoragePoolsHMAC(sharedSecret string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("lxd-storage|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// LXDStoragePoolsRequest is the HMAC-signed payload for /api/lxd/storage-pools-remote.
type LXDStoragePoolsRequest struct {
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// GetRemoteLXDStoragePools fetches storage pool names from a peer ZNAS LXD.
func GetRemoteLXDStoragePools(remoteURL, sharedSecret, tlsFP string) ([]string, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := LXDStoragePoolsRequest{
		Timestamp: ts,
		Nonce:     nh,
		HMAC:      LXDStoragePoolsHMAC(sharedSecret, ts, nh),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/incus/storage-pools-remote", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("storage-pools-remote returned status %d", resp.StatusCode)
	}
	var r struct {
		Pools []string `json:"pools"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return r.Pools, nil
}

// LXDBridgesHMAC signs a request to list remote LXD bridge networks.
func LXDBridgesHMAC(sharedSecret string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("lxd-bridges|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// LXDBridgesRequest is the HMAC-signed payload for /api/lxd/bridges-remote.
type LXDBridgesRequest struct {
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// GetRemoteLXDBridges fetches bridge network infos from a peer ZNAS LXD.
func GetRemoteLXDBridges(remoteURL, sharedSecret, tlsFP string) ([]LXDNetworkInfo, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := LXDBridgesRequest{
		Timestamp: ts,
		Nonce:     nh,
		HMAC:      LXDBridgesHMAC(sharedSecret, ts, nh),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/incus/bridges-remote", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bridges-remote returned status %d", resp.StatusCode)
	}
	var r struct {
		Bridges []LXDNetworkInfo `json:"bridges"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return r.Bridges, nil
}

// ── Remote instance list ───────────────────────────────────────────────────────

// LXDInstanceSummary is a minimal instance record used for push-target
// validation AND (v6.5.30+) by the consolidated terminal-multi page to
// list all reachable VMs / containers across linked peers. Type + State
// were added so callers can filter to running instances and label each
// row with the right icon.
type LXDInstanceSummary struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type,omitempty"`  // "virtual-machine" | "container"
	State       string `json:"state,omitempty"` // "Running" | "Stopped" | "Frozen" | ...
	IPv4        string `json:"ipv4,omitempty"`  // best global IPv4 of the guest, when running
}

// LXDInstancesHMAC signs a request to list remote LXD instances.
func LXDInstancesHMAC(sharedSecret string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("lxd-instances|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// LXDInstancesRequest is the HMAC-signed payload for /api/lxd/instances-remote.
type LXDInstancesRequest struct {
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// LXDListInstanceSummaries returns name+description+type+state for every
// local LXD instance. Type + State are needed by the terminal-multi page
// so it can filter peers' instance lists to "Running" and pick the right
// icon (VM vs CT) per row.
func LXDListInstanceSummaries() ([]LXDInstanceSummary, error) {
	out, err := exec.Command("incus", "list", "--format", "json").Output()
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Name            string                       `json:"name"`
		Description     string                       `json:"description"`
		Type            string                       `json:"type"`
		Status          string                       `json:"status"`
		ExpandedDevices map[string]map[string]string `json:"expanded_devices"`
		ExpandedConfig  map[string]string            `json:"expanded_config"`
		State           *struct {
			Network map[string]lxdStateNetwork `json:"network"`
		} `json:"state"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	result := make([]LXDInstanceSummary, len(raw))
	for i, r := range raw {
		ip := ""
		if r.State != nil {
			ip = lxdPickBestIP(r.ExpandedDevices, r.ExpandedConfig, r.State.Network)
		}
		result[i] = LXDInstanceSummary{
			Name: r.Name, Description: r.Description,
			Type: r.Type, State: r.Status, IPv4: ip,
		}
	}
	return result, nil
}

// GetRemoteLXDInstances fetches instance summaries from a peer ZNAS LXD server.
func GetRemoteLXDInstances(remoteURL, sharedSecret, tlsFP string) ([]LXDInstanceSummary, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := LXDInstancesRequest{
		Timestamp: ts,
		Nonce:     nh,
		HMAC:      LXDInstancesHMAC(sharedSecret, ts, nh),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/incus/instances-remote", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("instances-remote returned status %d", resp.StatusCode)
	}
	var r struct {
		Instances []LXDInstanceSummary `json:"instances"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return r.Instances, nil
}

// ── NVRAM reset (fixes UEFI boot after cross-version VM push) ────────────────

// LXDClearTPMState deletes the swtpm persistent state file for a local VM so
// that swtpm initialises a fresh TPM on next boot.  This is required after a
// cross-host push: the state copied from the source platform is tied to the
// source OVMF/TPM session and causes QEMU to exit with a TPM fatal error when
// OVMF sends boot-measurement commands against the foreign state.
func LXDClearTPMState(vmName string) error {
	// Incus stores VM state under /var/lib/incus. We probe both the legacy
	// flat virtual-machines/<name>/ path and the per-pool layout, since
	// older Incus versions used the flat form.
	globs := []string{
		"/var/lib/incus/storage-pools/*/virtual-machines/" + vmName + "/tpm.tpm/tpm2-00.permall",
		"/var/lib/incus/virtual-machines/" + vmName + "/tpm.tpm/tpm2-00.permall",
	}
	for _, g := range globs {
		// Use shell glob expansion via /bin/sh so we don't need filepath.Glob
		// (which can't traverse root-owned dirs from the zfsnas user).
		exec.Command("sudo", "/bin/sh", "-c", "rm -f "+g).Run() //nolint:errcheck
	}
	fmt.Printf("lxd push: TPM state cleared for %s\n", vmName)
	return nil
}

// LXDTPMClearRequest is the HMAC-signed payload for POST /api/incus/vm-tpm-clear.
type LXDTPMClearRequest struct {
	VMName    string `json:"vm_name"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// LXDTPMClearHMAC signs a TPM clear request.
func LXDTPMClearHMAC(sharedSecret, vmName string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("lxd-tpm-clear|" + vmName + "|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// ClearRemoteTPMState sends an HMAC-signed request to a peer ZNAS server to
// delete the swtpm state for the named VM. Non-fatal if the remote doesn't
// support the endpoint (old version).
func ClearRemoteTPMState(remoteURL, sharedSecret, tlsFP, vmName string) error {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := LXDTPMClearRequest{
		VMName:    vmName,
		Timestamp: ts,
		Nonce:     nh,
		HMAC:      LXDTPMClearHMAC(sharedSecret, vmName, ts, nh),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/incus/vm-tpm-clear", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vm-tpm-clear returned status %d", resp.StatusCode)
	}
	return nil
}

// LXDNVRAMResetRequest is the HMAC-signed payload for POST /api/incus/vm-nvram-reset.
type LXDNVRAMResetRequest struct {
	VMName    string `json:"vm_name"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// LXDNVRAMResetHMAC signs a NVRAM reset request.
func LXDNVRAMResetHMAC(sharedSecret, vmName string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("lxd-nvram-reset|" + vmName + "|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// LXDResetVMNVRAM deletes the EFI variable store for a local Incus VM so
// that OVMF regenerates it from scratch on next boot.
//
// IMPORTANT: the Incus state directories (e.g. /var/lib/incus/virtual-machines/)
// are root-owned and not traversable by the zfsnas user, so os.Stat cannot be
// used to check file existence.  We run sudo rm -f unconditionally on every
// candidate path — rm -f exits 0 whether the file existed or not.
func LXDResetVMNVRAM(vmName string) error {
	paths := []string{
		"/var/lib/incus/virtual-machines/" + vmName + "/qemu.nvram",
		"/var/lib/incus/storage-pools/*/virtual-machines/" + vmName + "/qemu.nvram",
	}
	for _, p := range paths {
		// Shell out to expand the per-pool glob path; sudo+rm is no-op when no match.
		if strings.Contains(p, "*") {
			exec.Command("sudo", "/bin/sh", "-c", "rm -f "+p).Run() //nolint:errcheck
		} else {
			exec.Command("sudo", "/usr/bin/rm", "-f", p).Run() //nolint:errcheck
		}
	}
	fmt.Printf("incus push: NVRAM reset attempted for %s\n", vmName)
	return nil
}

// LXDRepairVMBoot performs a full UEFI boot repair for a VM after a cross-version
// migration.  It combines two steps:
//
//  1. NVRAM reset — deletes qemu.nvram so OVMF starts with a blank variable store
//     and re-discovers the EFI System Partition (fixes stale device-path entries
//     from the source LXD version).
//
//  2. EFI fallback repair — mounts the VM's ZVol, copies EFI/<distro>/grub.cfg
//     to EFI/BOOT/grub.cfg so that after OVMF boots the fallback binary
//     (EFI/BOOT/BOOTX64.EFI / shimx64.efi) GRUB can find its configuration
//     without needing the distro-specific NVRAM boot entry.
//
// All operations are non-fatal — failures are logged but the function always
// returns so the caller can still mark the job as succeeded.
func LXDRepairVMBoot(vmName string) {
	// ── Step 1: NVRAM reset ────────────────────────────────────────────────
	LXDResetVMNVRAM(vmName) //nolint:errcheck

	// ── Step 2: EFI fallback repair via ZVol mount ─────────────────────────
	// Find the storage pool backing the VM's root disk.
	poolOut, err := exec.Command("incus", "config", "device", "get", vmName, "root", "pool").Output()
	if err != nil {
		fmt.Printf("lxd repair: cannot get root disk pool for %s: %v\n", vmName, err)
		return
	}
	pool := strings.TrimSpace(string(poolOut))
	if pool == "" {
		fmt.Printf("lxd repair: root disk pool empty for %s\n", vmName)
		return
	}

	// Get the ZFS dataset backing this LXD pool.
	poolDataset := getLXDPoolSource(pool)
	if poolDataset == "" {
		fmt.Printf("lxd repair: pool %s is not backed by ZFS, skipping EFI repair\n", pool)
		return
	}

	// LXD names VM zvols as "<vmname>.block" inside virtual-machines/.
	zvolDataset := poolDataset + "/virtual-machines/" + vmName + ".block"

	// Snapshot existing /dev/zdN (base block devices, no partition suffixes).
	zdRe := regexp.MustCompile(`^zd\d+$`)
	beforeZDs := map[string]bool{}
	if entries, _ := os.ReadDir("/dev"); entries != nil {
		for _, e := range entries {
			if zdRe.MatchString(e.Name()) {
				beforeZDs[e.Name()] = true
			}
		}
	}

	if err := exec.Command("sudo", "/usr/sbin/zfs", "set", "volmode=dev", zvolDataset).Run(); err != nil {
		fmt.Printf("lxd repair: zfs set volmode=dev %s: %v\n", zvolDataset, err)
		return
	}
	defer exec.Command("sudo", "/usr/sbin/zfs", "set", "volmode=none", zvolDataset).Run() //nolint:errcheck

	// Poll up to 10 s for the new /dev/zdN device to appear.
	blockDev := ""
	for i := 0; i < 100 && blockDev == ""; i++ {
		time.Sleep(100 * time.Millisecond)
		entries, _ := os.ReadDir("/dev")
		for _, e := range entries {
			if zdRe.MatchString(e.Name()) && !beforeZDs[e.Name()] {
				blockDev = "/dev/" + e.Name()
				break
			}
		}
	}
	if blockDev == "" {
		fmt.Printf("lxd repair: no /dev/zdX appeared for %s — EFI repair skipped\n", zvolDataset)
		return
	}
	fmt.Printf("lxd repair: using block device %s for EFI repair\n", blockDev)
	fixUEFIGrub(blockDev, func(s string) { fmt.Println(s) })
}

// ResetRemoteVMNVRAM sends an HMAC-signed request to a peer ZNAS server to
// delete the NVRAM for the named VM. Non-fatal if the remote doesn't support
// the endpoint (old version) — we just log and continue.
func ResetRemoteVMNVRAM(remoteURL, sharedSecret, tlsFP, vmName string) error {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := LXDNVRAMResetRequest{
		VMName:    vmName,
		Timestamp: ts,
		Nonce:     nh,
		HMAC:      LXDNVRAMResetHMAC(sharedSecret, vmName, ts, nh),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/incus/vm-nvram-reset", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vm-nvram-reset returned status %d", resp.StatusCode)
	}
	return nil
}

// RemotePingHasLXD pings a remote ZNAS server and returns true if it reports lxd_enabled.
func RemotePingHasLXD(remoteURL, tlsFP string) bool {
	resp, err := interlinkClientFor(tlsFP).Get(remoteURL + "/api/interlink/ping")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var p struct {
		LXDEnabled bool `json:"lxd_enabled"`
	}
	json.NewDecoder(resp.Body).Decode(&p) //nolint:errcheck
	return p.LXDEnabled
}

// ── NIC enumeration ────────────────────────────────────────────────────────────

// LXDNICInfo describes one NIC device on an LXD instance.
type LXDNICInfo struct {
	DeviceName        string `json:"device_name"`
	Bridge            string `json:"bridge"`
	BridgeDescription string `json:"bridge_description"`
	// Disconnected is true when the NIC was removed from the device list by ZNAS
	// (via the disconnect-NIC feature) and its config persists only in the
	// user.disconnected_nics.<name> config key. The push flow re-attaches it on
	// the destination with the user-selected remote bridge.
	Disconnected bool `json:"disconnected,omitempty"`
}

// lxdDisconnNICConf is the JSON stored in user.disconnected_nics.<name>.
type lxdDisconnNICConf struct {
	Bridge string `json:"bridge"`
	MAC    string `json:"mac"`
	VLAN   string `json:"vlan"`
}

// LXDInstanceDeviceInfo is the full response from GET /api/lxd/instances/{name}/nics.
type LXDInstanceDeviceInfo struct {
	NICs   []LXDNICInfo `json:"nics"`
	HasTPM bool         `json:"has_tpm"`
}

// LXDGetNICsForVM returns the NIC device names, their bridge parent + description,
// and whether the instance has a TPM device.
func LXDGetNICsForVM(name string) (LXDInstanceDeviceInfo, error) {
	// Build a description lookup map for local bridges first.
	bridgeDesc := map[string]string{}
	if nets, err := LXDListNetworkInfos(); err == nil {
		for _, n := range nets {
			bridgeDesc[n.Name] = n.Description
		}
	}

	// Primary: REST API via lxc query. expanded_devices merges profile +
	// instance-level devices. We use json.RawMessage at two levels so that
	// nested objects (LXD 6.x expands managed-network references) don't
	// cause the entire device to be dropped.
	info, _ := lxdGetNICsViaQuery(name, bridgeDesc)

	// Fallback: YAML output of `lxc config show --expanded`. This is the most
	// reliable source when the REST response omits or mis-encodes managed NICs.
	if len(info.NICs) == 0 {
		if fb := lxdGetNICsViaExpandedShow(name, bridgeDesc); len(fb) > 0 {
			info.NICs = fb
		}
	}

	return info, nil
}

// lxdGetDisconnectedNICConfigs returns configs for NICs that ZNAS disconnected
// (stored in user.disconnected_nics.<name> config keys) on the given VM.
func lxdGetDisconnectedNICConfigs(vmName string) map[string]lxdDisconnNICConf {
	out, err := exec.Command("incus", "query", "/1.0/instances/"+vmName).Output()
	if err != nil {
		return nil
	}
	var inst struct {
		Config map[string]string `json:"config"`
	}
	if err := json.Unmarshal(out, &inst); err != nil {
		return nil
	}
	const prefix = "user.disconnected_nics."
	result := map[string]lxdDisconnNICConf{}
	for k, v := range inst.Config {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		devName := k[len(prefix):]
		var conf lxdDisconnNICConf
		if err := json.Unmarshal([]byte(v), &conf); err != nil {
			continue
		}
		result[devName] = conf
	}
	return result
}

// lxdGetNICsViaQuery parses the LXD REST response for an instance.
func lxdGetNICsViaQuery(name string, bridgeDesc map[string]string) (LXDInstanceDeviceInfo, error) {
	out, err := exec.Command("incus", "query", "/1.0/instances/"+name).Output()
	if err != nil {
		return LXDInstanceDeviceInfo{}, fmt.Errorf("lxc query instance: %w", err)
	}
	var raw struct {
		Config          map[string]string          `json:"config"`
		Devices         map[string]json.RawMessage `json:"devices"`
		ExpandedDevices map[string]json.RawMessage `json:"expanded_devices"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return LXDInstanceDeviceInfo{}, fmt.Errorf("parse instance: %w", err)
	}

	// Decode each device field-by-field so that non-string values (nested
	// objects from LXD network expansion) are skipped without dropping the
	// whole device.
	decodeDeviceMap := func(src map[string]json.RawMessage) map[string]map[string]string {
		result := make(map[string]map[string]string, len(src))
		for devName, rawDev := range src {
			var fields map[string]json.RawMessage
			if json.Unmarshal(rawDev, &fields) != nil {
				continue
			}
			props := make(map[string]string, len(fields))
			for k, v := range fields {
				var s string
				if json.Unmarshal(v, &s) == nil {
					props[k] = s
				}
			}
			if len(props) > 0 {
				result[devName] = props
			}
		}
		return result
	}

	expanded := decodeDeviceMap(raw.ExpandedDevices)
	devices := decodeDeviceMap(raw.Devices)

	isNIC := func(props map[string]string) bool {
		t := props["type"]
		if t == "nic" {
			return true
		}
		if props["nictype"] != "" {
			return true
		}
		if t != "disk" && t != "tpm" && t != "usb" && t != "pci" && t != "gpu" &&
			t != "unix-char" && t != "unix-block" && t != "proxy" && t != "infiniband" {
			if props["parent"] != "" || props["network"] != "" {
				return true
			}
		}
		return false
	}

	var info LXDInstanceDeviceInfo
	seen := map[string]bool{}
	addNIC := func(devName string, props map[string]string) {
		if seen[devName] {
			return
		}
		seen[devName] = true
		bridge := props["parent"]
		if bridge == "" {
			bridge = props["network"]
		}
		info.NICs = append(info.NICs, LXDNICInfo{
			DeviceName:        devName,
			Bridge:            bridge,
			BridgeDescription: bridgeDesc[bridge],
		})
	}

	for devName, props := range expanded {
		if isNIC(props) {
			addNIC(devName, props)
		} else if props["type"] == "tpm" {
			info.HasTPM = true
		}
	}
	// Instance-level fallback if expanded_devices had no NICs.
	if len(info.NICs) == 0 {
		for devName, props := range devices {
			if isNIC(props) {
				addNIC(devName, props)
			}
		}
	}

	// Also surface NICs that ZNAS disconnected (removed from device list) whose
	// config is stored in user.disconnected_nics.<devName>. These are real NICs
	// that the user expects to remap when pushing to another server.
	const disconnPrefix = "user.disconnected_nics."
	for k, v := range raw.Config {
		if !strings.HasPrefix(k, disconnPrefix) {
			continue
		}
		devName := k[len(disconnPrefix):]
		if seen[devName] {
			continue // NIC is active — already handled above.
		}
		var conf lxdDisconnNICConf
		if err := json.Unmarshal([]byte(v), &conf); err != nil {
			continue
		}
		seen[devName] = true
		bridge := conf.Bridge
		info.NICs = append(info.NICs, LXDNICInfo{
			DeviceName:        devName,
			Bridge:            bridge,
			BridgeDescription: bridgeDesc[bridge],
			Disconnected:      true,
		})
	}

	return info, nil
}

// lxdGetNICsViaExpandedShow parses `lxc config show --expanded <name>` YAML output.
// This bypasses all JSON parsing and is a reliable fallback when the REST API
// returns an unexpected format for NIC devices in expanded_devices.
func lxdGetNICsViaExpandedShow(name string, bridgeDesc map[string]string) []LXDNICInfo {
	out, err := exec.Command("incus", "config", "show", "--expanded", name).Output()
	if err != nil {
		return nil
	}

	lines := strings.Split(string(out), "\n")
	inSection := false
	currentDev := ""
	currentProps := map[string]string{}
	var nics []LXDNICInfo

	flush := func() {
		if currentDev == "" {
			return
		}
		t := currentProps["type"]
		if t == "nic" || currentProps["nictype"] != "" {
			bridge := currentProps["parent"]
			if bridge == "" {
				bridge = currentProps["network"]
			}
			nics = append(nics, LXDNICInfo{
				DeviceName:        currentDev,
				Bridge:            bridge,
				BridgeDescription: bridgeDesc[bridge],
			})
		}
		currentDev = ""
		currentProps = map[string]string{}
	}

	for _, line := range lines {
		// Find the expanded_devices section.
		if !inSection {
			if strings.TrimSpace(line) == "expanded_devices:" {
				inSection = true
			}
			continue
		}

		if line == "" {
			continue
		}

		trimmed := strings.TrimLeft(line, " ")
		indent := len(line) - len(trimmed)

		switch {
		case indent == 0:
			// New top-level key — expanded_devices section ended.
			flush()
			return nics
		case indent == 2:
			// "  devicename:" — start of a new device block.
			flush()
			currentDev = strings.TrimSuffix(trimmed, ":")
		case indent >= 4 && currentDev != "":
			// "    key: value" — device property.
			if idx := strings.Index(trimmed, ": "); idx > 0 {
				currentProps[trimmed[:idx]] = trimmed[idx+2:]
			}
		}
	}
	flush()
	return nics
}
