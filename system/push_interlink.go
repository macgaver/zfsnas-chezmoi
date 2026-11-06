package system

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// GetProcessUser returns the OS username of the current process.
func GetProcessUser() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}

// EnsureSSHKey generates ~/.ssh/id_ed25519 for the current process user if it
// does not already exist, then returns the public key string.
func EnsureSSHKey() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("cannot determine current user: %w", err)
	}
	sshDir := filepath.Join(u.HomeDir, ".ssh")
	keyPath := filepath.Join(sshDir, "id_ed25519")
	pubPath := keyPath + ".pub"

	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return "", fmt.Errorf("cannot create .ssh dir: %w", err)
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		out, kerr := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath, "-C", "zfsnas-interlink").CombinedOutput()
		if kerr != nil {
			return "", fmt.Errorf("ssh-keygen failed: %v — %s", kerr, strings.TrimSpace(string(out)))
		}
	}
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		return "", fmt.Errorf("cannot read public key: %w", err)
	}
	return strings.TrimSpace(string(pub)), nil
}

// AddSSHAuthorizedKey idempotently appends pubKey to ~/.ssh/authorized_keys.
func AddSSHAuthorizedKey(pubKey string) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	sshDir := filepath.Join(u.HomeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return err
	}
	authKeys := filepath.Join(sshDir, "authorized_keys")
	key := strings.TrimSpace(pubKey)
	if data, err := os.ReadFile(authKeys); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == key {
				return nil // already present
			}
		}
	}
	f, err := os.OpenFile(authKeys, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, key)
	return err
}

// ── SSH key exchange (HMAC-auth) ──────────────────────────────────────────────

// PushSSHKeyRequest is the HMAC-signed payload for POST /api/interlink/push-ssh-key.
type PushSSHKeyRequest struct {
	PublicKey   string `json:"public_key"`
	ProcessUser string `json:"process_user"` // caller's OS username; remote grants ZFS access to this user
	Timestamp   int64  `json:"timestamp"`
	Nonce       string `json:"nonce"`
	HMAC        string `json:"hmac"`
}

// PushSSHKeyHMAC computes the HMAC for a push-ssh-key request.
func PushSSHKeyHMAC(sharedSecret, publicKey, processUser string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("push-ssh-key|" + publicKey + "|" + processUser + "|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// SendPushSSHKey sends our SSH public key and process username to a remote server over HMAC-auth.
// The remote will add the key to authorized_keys and grant ZFS interlink permissions to our process user.
// tlsFP pins the TLS certificate of the remote server.
func SendPushSSHKey(remoteURL, sharedSecret, publicKey, tlsFP string) error {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	pu := GetProcessUser()
	req := PushSSHKeyRequest{
		PublicKey:   publicKey,
		ProcessUser: pu,
		Timestamp:   ts,
		Nonce:       nh,
		HMAC:        PushSSHKeyHMAC(sharedSecret, publicKey, pu, ts, nh),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/interlink/push-ssh-key", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("push-ssh-key returned status %d", resp.StatusCode)
	}
	return nil
}

// ── ZFS permissions ───────────────────────────────────────────────────────────

// v6.5.19: added `hold,release` because syncoid (used for VM backup
// pull/push) takes a ZFS hold on the snapshot for the duration of the
// transfer. Without hold permission, "zfs send" reports
// "cannot hold: permission denied" and the transfer fails immediately.
// v6.6.13: added `destroy` because on an INCREMENTAL push syncoid prunes its
// own previous sync snapshot on the DESTINATION (`zfs destroy <dst>@syncoid_*`).
// Without destroy delegation the remote zfsnas user hits "cannot destroy
// snapshots: permission denied" and stale syncoid_* snapshots accumulate on
// the peer forever (each fire leaves another orphan), eventually bloating the
// destination and confusing the incremental anchor bookkeeping.
const zfsInterlinkPerms = "snapshot,send,receive,create,mount,hold,release,destroy"

// GrantLocalZFSAccess grants the required interlink ZFS permissions to the current
// process user on all local pools. Skipped when running as root (already has full access).
func GrantLocalZFSAccess() error {
	username := GetProcessUser()
	if username == "" {
		return fmt.Errorf("cannot determine current user")
	}
	if username == "root" {
		return nil // root has full ZFS access without delegation
	}
	pools, err := GetAllPools()
	if err != nil {
		return fmt.Errorf("cannot list pools: %w", err)
	}
	var errs []string
	for _, p := range pools {
		out, err := exec.Command("sudo", "zfs", "allow", username, zfsInterlinkPerms, p.Name).CombinedOutput()
		if err != nil {
			errs = append(errs, fmt.Sprintf("pool %s: %v — %s", p.Name, err, strings.TrimSpace(string(out))))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("zfs allow errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// CheckLocalZFSAccess reports whether the current process user has all required interlink
// ZFS permissions on at least one local pool. Always returns true for root.
func CheckLocalZFSAccess() bool {
	username := GetProcessUser()
	if username == "root" {
		return true // root always has full ZFS access
	}
	if username == "" {
		return false
	}
	pools, err := GetAllPools()
	if err != nil || len(pools) == 0 {
		return false
	}
	// destroy is required so an existing peer granted before v6.6.13 (without
	// destroy) fails this check and gets re-granted the fuller permission set
	// the next time EnsureRemoteZFSAccess runs — self-healing the syncoid
	// destination-prune "permission denied" on incremental backups.
	required := []string{"snapshot", "send", "receive", "create", "mount", "destroy"}
	for _, p := range pools {
		out, err := exec.Command("zfs", "allow", p.Name).Output()
		if err != nil {
			continue
		}
		if zfsHasAllPerms(string(out), username, required) {
			return true
		}
	}
	return false
}

// zfsHasAllPerms parses the output of "zfs allow <pool>" and checks
// whether username has all required permissions.
func zfsHasAllPerms(allowOutput, username string, required []string) bool {
	found := make(map[string]bool)
	for _, line := range strings.Split(allowOutput, "\n") {
		fields := strings.Fields(line)
		// Output lines look like: "user <username> perm,perm,..."
		if len(fields) >= 3 && fields[0] == "user" && fields[1] == username {
			for _, p := range strings.Split(fields[2], ",") {
				found[strings.TrimSpace(p)] = true
			}
		}
	}
	for _, p := range required {
		if !found[p] {
			return false
		}
	}
	return true
}

// ── ZFS access check (HMAC-auth) ──────────────────────────────────────────────

// CheckZFSAccessRequest is the HMAC-signed payload for POST /api/interlink/check-zfs-access.
// The remote server checks its own process user — no username parameter needed.
type CheckZFSAccessRequest struct {
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// CheckZFSAccessHMAC computes the HMAC for a check-zfs-access request.
func CheckZFSAccessHMAC(sharedSecret string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("check-zfs-access|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// GetRemoteZFSAccess asks a linked remote server whether its own process user has the
// required ZFS permissions on its pools (i.e. whether zfs recv will succeed).
// tlsFP pins the TLS certificate of the remote server.
func GetRemoteZFSAccess(remoteURL, sharedSecret, tlsFP string) (bool, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := CheckZFSAccessRequest{
		Timestamp: ts,
		Nonce:     nh,
		HMAC:      CheckZFSAccessHMAC(sharedSecret, ts, nh),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/interlink/check-zfs-access", "application/json", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("check-zfs-access returned status %d", resp.StatusCode)
	}
	var r struct {
		HasAccess bool `json:"has_access"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return false, err
	}
	return r.HasAccess, nil
}

// ── ZFS access grant (HMAC-auth) ─────────────────────────────────────────────

// GrantZFSAccessHMAC computes the HMAC for a grant-zfs-access request.
func GrantZFSAccessHMAC(sharedSecret string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("grant-zfs-access|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// EnsureRemoteZFSAccess asks the remote server to run zfs allow on all its pools.
// Called before each push so newly-created pools on the target are always covered.
// tlsFP pins the TLS certificate of the remote server.
func EnsureRemoteZFSAccess(remoteURL, sharedSecret, tlsFP string) error {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := CheckZFSAccessRequest{ // same fields, different HMAC prefix
		Timestamp: ts,
		Nonce:     nh,
		HMAC:      GrantZFSAccessHMAC(sharedSecret, ts, nh),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/interlink/grant-zfs-access", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var r struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&r) //nolint:errcheck
		if r.Error != "" {
			return fmt.Errorf("grant-zfs-access: %s", r.Error)
		}
		return fmt.Errorf("grant-zfs-access returned status %d", resp.StatusCode)
	}
	return nil
}

// ── Remote pools (HMAC-auth) ──────────────────────────────────────────────────

// RemotePoolsRequest is the HMAC-signed payload for POST /api/interlink/remote-pools.
type RemotePoolsRequest struct {
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// RemotePool carries the name and available bytes of a remote pool.
type RemotePool struct {
	Name      string `json:"name"`
	Available int64  `json:"available"`
}

// RemotePoolsResponse is what the remote server returns.
type RemotePoolsResponse struct {
	Pools       []RemotePool `json:"pools"`
	ProcessUser string       `json:"process_user"`
	// SSHHosts (v6.5.19+) — the peer's own non-loopback IP addresses,
	// most-routable first. The InterLink URL is an HTTPS endpoint that
	// may sit behind a reverse proxy / load balancer (e.g.
	// "z1.example.com" → proxy), so it's NOT a reliable SSH transport
	// for syncoid. The peer reports the addresses ON ITSELF; the caller
	// SSH-probes each and uses the first that authenticates. Empty on
	// peers running a pre-v6.5.19 binary — callers fall back to the
	// URL hostname in that case.
	SSHHosts []string `json:"ssh_hosts,omitempty"`
	// SSHHostKeys (v6.6.13+) — this peer's SSH host PUBLIC keys, read from
	// /etc/ssh/ssh_host_*_key.pub (each entry "<type> <base64> [comment]").
	// The caller pins these into a managed known_hosts file used only for
	// InterLink syncoid transfers, so the host key is verified out-of-band
	// over the already-authenticated (HMAC + TLS-pinned) InterLink channel
	// instead of blind TOFU. This also self-heals backups after a peer is
	// reinstalled / re-keyed: accept-new refuses a CHANGED key, which used to
	// break every backup to that peer until known_hosts was hand-edited.
	// Empty on peers running an older binary — callers fall back to the
	// legacy accept-new behaviour against the default known_hosts.
	SSHHostKeys []string `json:"ssh_host_keys,omitempty"`
}

// LocalSSHHostKeys returns this host's SSH host public keys (the contents of
// /etc/ssh/ssh_host_*_key.pub, one trimmed line each). Advertised to InterLink
// peers so they can pin our identity for syncoid SSH transfers.
func LocalSSHHostKeys() []string {
	matches, _ := filepath.Glob("/etc/ssh/ssh_host_*_key.pub")
	var keys []string
	for _, f := range matches {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		// A .pub file is a single line: "<type> <base64> [comment]". Keep the
		// type + base64; the comment is cosmetic.
		fields := strings.Fields(strings.TrimSpace(string(b)))
		if len(fields) >= 2 {
			keys = append(keys, fields[0]+" "+fields[1])
		}
	}
	return keys
}

// LocalSSHHosts returns this host's non-loopback IPv4 addresses, primary
// (default-route) address first. Used to populate RemotePoolsResponse so a
// peer initiating a syncoid transfer can reach us directly even when the
// InterLink URL points at a reverse proxy.
func LocalSSHHosts() []string {
	seen := map[string]bool{}
	var hosts []string
	// Primary outbound IP first (the interface that reaches the internet
	// — usually the LAN address peers can also reach).
	if c, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
		if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
			ip := ua.IP.String()
			if ip != "" && !seen[ip] {
				hosts = append(hosts, ip)
				seen[ip] = true
			}
		}
		c.Close()
	}
	// Then every other non-loopback IPv4 on the box.
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			s := ip.String()
			if !seen[s] {
				hosts = append(hosts, s)
				seen[s] = true
			}
		}
	}
	return hosts
}

// RemotePoolsHMAC computes the HMAC for a remote-pools request.
func RemotePoolsHMAC(sharedSecret string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("remote-pools|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// GetRemotePools fetches pool names and the process user from a linked remote server.
// A 5-second context deadline is applied so a down server fails fast.
// tlsFP pins the TLS certificate of the remote server.
func GetRemotePools(remoteURL, sharedSecret, tlsFP string) (*RemotePoolsResponse, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := RemotePoolsRequest{
		Timestamp: ts,
		Nonce:     nh,
		HMAC:      RemotePoolsHMAC(sharedSecret, ts, nh),
	}
	body, _ := json.Marshal(req)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, "POST", remoteURL+"/api/interlink/remote-pools", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := interlinkClientFor(tlsFP).Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("remote-pools returned status %d", resp.StatusCode)
	}
	var r RemotePoolsResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ── Remote folders (HMAC-auth) ────────────────────────────────────────────────

// RemoteFoldersRequest is the HMAC-signed payload for POST /api/interlink/remote-folders.
type RemoteFoldersRequest struct {
	Pool      string `json:"pool"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// RemoteFoldersResponse lists the dataset paths under a pool on the peer (excluding the pool itself).
type RemoteFoldersResponse struct {
	Folders []string `json:"folders"`
}

// RemoteFoldersHMAC computes the HMAC for a remote-folders request.
func RemoteFoldersHMAC(sharedSecret, pool string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("remote-folders|" + pool + "|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// GetRemoteFolders fetches the dataset folder paths under the given pool from a linked remote server.
func GetRemoteFolders(remoteURL, sharedSecret, tlsFP, pool string) (*RemoteFoldersResponse, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := RemoteFoldersRequest{
		Pool:      pool,
		Timestamp: ts,
		Nonce:     nh,
		HMAC:      RemoteFoldersHMAC(sharedSecret, pool, ts, nh),
	}
	body, _ := json.Marshal(req)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, "POST", remoteURL+"/api/interlink/remote-folders", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := interlinkClientFor(tlsFP).Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("remote-folders returned status %d", resp.StatusCode)
	}
	var r RemoteFoldersResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ── ZFS push over SSH ─────────────────────────────────────────────────────────

// datasetIsEncrypted reports whether the ZFS dataset (or the dataset that owns
// a snapshot) has encryption enabled.  Used to decide whether to add -w to
// zfs send so encrypted blocks are transferred as raw ciphertext.
func datasetIsEncrypted(datasetOrSnap string) bool {
	// Strip snapshot suffix if present.
	ds := datasetOrSnap
	if i := strings.LastIndex(ds, "@"); i >= 0 {
		ds = ds[:i]
	}
	val := strings.TrimSpace(GetEncryptionStatus(ds))
	return val != "" && val != "off"
}

// GetSnapshotSize returns an estimated byte size for a snapshot via zfs send -nP,
// falling back to the snapshot's refer property if the dry-run flag is unavailable.
func GetSnapshotSize(snapshot string) int64 {
	args := []string{"send", "-nP"}
	if datasetIsEncrypted(snapshot) {
		args = append(args, "-w")
	}
	args = append(args, snapshot)
	out, err := exec.Command("zfs", args...).Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "size") {
				if n, err2 := strconv.ParseInt(strings.Fields(line)[1], 10, 64); err2 == nil && n > 0 {
					return n
				}
			}
		}
	}
	// Fallback: refer property of the snapshot.
	out2, err2 := exec.Command("zfs", "get", "-H", "-p", "-o", "value", "refer", snapshot).Output()
	if err2 == nil {
		if n, err3 := strconv.ParseInt(strings.TrimSpace(string(out2)), 10, 64); err3 == nil {
			return n
		}
	}
	return 0
}

// countingReader wraps an io.Reader and calls cb with the running byte count.
type countingReader struct {
	r    io.Reader
	cb   func(int64)
	sent int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		cr.sent += int64(n)
		if cr.cb != nil {
			cr.cb(cr.sent)
		}
	}
	return n, err
}

// RunZFSPush performs: zfs send <snapshot> | ssh <remoteUser>@<remoteHost> zfs recv -F <destDataset>
// totalBytes is used only for progress reporting (pass 0 if unknown).
// progressCb receives running byte-sent counts as data flows through the pipe.
func RunZFSPush(ctx context.Context, snapshot, remoteHost, remoteUser, destDataset string, totalBytes int64, progressCb func(bytesSent int64)) error {
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("cannot determine current user: %w", err)
	}
	keyPath := filepath.Join(u.HomeDir, ".ssh", "id_ed25519")

	sendArgs := []string{"send"}
	if datasetIsEncrypted(snapshot) {
		sendArgs = append(sendArgs, "-w")
	}
	sendArgs = append(sendArgs, snapshot)
	sendCmd := exec.CommandContext(ctx, "zfs", sendArgs...)
	recvCmd := exec.CommandContext(ctx, "ssh",
		"-i", keyPath,
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=15",
		// Detect dead connections: send keepalive every 10s, give up after 6 missed replies (60s).
		"-o", "ServerAliveInterval=10",
		"-o", "ServerAliveCountMax=6",
		remoteUser+"@"+remoteHost,
		"sudo", "zfs", "recv", "-F", destDataset,
	)

	pr, pw := io.Pipe()
	sendCmd.Stdout = pw

	var sendStderr, recvStderr bytes.Buffer
	sendCmd.Stderr = &sendStderr
	recvCmd.Stderr = &recvStderr
	recvCmd.Stdin = &countingReader{r: pr, cb: progressCb}

	if err := sendCmd.Start(); err != nil {
		return fmt.Errorf("zfs send start: %w", err)
	}
	if err := recvCmd.Start(); err != nil {
		sendCmd.Process.Kill() //nolint:errcheck
		return fmt.Errorf("ssh start: %w", err)
	}

	sendDone := make(chan error, 1)
	go func() {
		sendDone <- sendCmd.Wait()
		pw.Close()
	}()

	recvErr := recvCmd.Wait()
	// Close pw immediately so zfs send gets SIGPIPE / unblocks if recv exited early.
	pw.Close()
	sendErr := <-sendDone

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if recvErr != nil {
		if msg := strings.TrimSpace(recvStderr.String()); msg != "" {
			return fmt.Errorf("zfs recv: %w — %s", recvErr, msg)
		}
		return fmt.Errorf("zfs recv: %w", recvErr)
	}
	if sendErr != nil {
		if msg := strings.TrimSpace(sendStderr.String()); msg != "" {
			return fmt.Errorf("zfs send: %w — %s", sendErr, msg)
		}
		return fmt.Errorf("zfs send: %w", sendErr)
	}
	return nil
}

// DestroyRemoteSnapshot runs "sudo zfs destroy <snapshot>" on the remote host via SSH.
// Used to clean up the landing snapshot on the target after a successful dataset push.
func DestroyRemoteSnapshot(ctx context.Context, snapshot, remoteHost, remoteUser string) error {
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("cannot determine current user: %w", err)
	}
	keyPath := filepath.Join(u.HomeDir, ".ssh", "id_ed25519")

	out, err := exec.CommandContext(ctx, "ssh",
		"-i", keyPath,
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=15",
		"-o", "ServerAliveInterval=10",
		"-o", "ServerAliveCountMax=6",
		remoteUser+"@"+remoteHost,
		"sudo", "zfs", "destroy", snapshot,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("zfs destroy remote snapshot: %w — %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
