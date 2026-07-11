package system

// Cross-server backup helpers (v6.5.19+).
//
// These functions extend the existing HMAC-signed peer plumbing already used
// by push-interlink:
//
//   • InterlinkRemotePoolSource — fetches the ZFS source path for one
//     remote Incus storage pool, so the local backup orchestrator can
//     compute the destination dataset path before launching syncoid.
//
//   • InterlinkRemoteVMBackups   — fetches the list of bkup--* instances
//     that exist on a peer, with their snapshots. Used by the Backups
//     dropdown (per-VM filter) and the Datastores → Backups page.
//
//   • InterlinkRemoteBackupAll   — same as InterlinkRemoteVMBackups but
//     without a per-VM filter; used by the cross-server aggregator.
//
// Each pair (sender helper + HMAC payload) mirrors the pattern of
// GetRemoteLXDStoragePools / LXDStoragePoolsHMAC.

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ── /api/lxd/interlink-pool-source ─────────────────────────────────────────

// LXDPoolSourceHMAC signs a request for one pool's ZFS source.
func LXDPoolSourceHMAC(sharedSecret string, timestamp int64, nonce, pool string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("lxd-pool-source|" + strconv.FormatInt(timestamp, 10) + "|" + nonce + "|" + pool))
	return hex.EncodeToString(h.Sum(nil))
}

// LXDPoolSourceRequest is the HMAC-signed payload for /api/lxd/interlink-pool-source.
type LXDPoolSourceRequest struct {
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Pool      string `json:"pool"`
	HMAC      string `json:"hmac"`
}

// InterlinkRemotePoolSource asks a peer for the zfs-source of one of its
// Incus storage pools (e.g. "bk-cold" → "tank/incus-nas2"). Used to compose
// the remote backup destination dataset path before launching syncoid.
func InterlinkRemotePoolSource(remoteURL, sharedSecret, tlsFP, pool string) (string, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := LXDPoolSourceRequest{
		Timestamp: ts,
		Nonce:     nh,
		Pool:      pool,
		HMAC:      LXDPoolSourceHMAC(sharedSecret, ts, nh, pool),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/incus/interlink-pool-source", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("interlink-pool-source returned status %d", resp.StatusCode)
	}
	var r struct {
		Source string `json:"source"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	return r.Source, nil
}

// ── /api/lxd/interlink-zfs-pools ───────────────────────────────────────────

// LXDZFSPoolsHMAC signs a request for the peer's ZFS pool list. This is
// distinct from the existing LXDStoragePools call (which lists Incus pools)
// — peers used as backup-only targets may not have Incus installed.
func LXDZFSPoolsHMAC(sharedSecret string, timestamp int64, nonce string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("lxd-zfs-pools|" + strconv.FormatInt(timestamp, 10) + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// LXDZFSPoolsRequest is the HMAC-signed payload for /api/lxd/interlink-zfs-pools.
type LXDZFSPoolsRequest struct {
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// LXDRemoteZFSPoolInfo describes one ZFS pool on a peer along with the
// Incus storage-pool (if any) that uses it as its source. Used by the
// Backup Schedule destination dropdown to show both the ZFS pool name AND
// the Incus datastore name, and to mark ZFS pools with no associated
// Incus datastore so the user knows instant-restore (Incus-side) isn't
// available there.
type LXDRemoteZFSPoolInfo struct {
	ZFSPool        string `json:"zfs_pool"`
	IncusDatastore string `json:"incus_datastore"` // "" when no Incus pool sources from this ZFS pool
}

// InterlinkRemoteZFSPools asks a peer for its ZFS pool list along with the
// Incus storage-pool (if any) backed by each. Used to populate the Backup
// Schedule destination dropdown with rich rows that show both names.
func InterlinkRemoteZFSPools(remoteURL, sharedSecret, tlsFP string) ([]LXDRemoteZFSPoolInfo, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := LXDZFSPoolsRequest{
		Timestamp: ts,
		Nonce:     nh,
		HMAC:      LXDZFSPoolsHMAC(sharedSecret, ts, nh),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/incus/interlink-zfs-pools", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("interlink-zfs-pools returned status %d", resp.StatusCode)
	}
	// Decode the rich shape; fall back to a plain string list for
	// backwards-compat with peers running an older binary.
	var r struct {
		Pools     []LXDRemoteZFSPoolInfo `json:"pools"`
		PoolsFlat []string               `json:"pools_flat,omitempty"`
	}
	bodyBytes := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, _ := resp.Body.Read(buf)
		if n > 0 {
			bodyBytes = append(bodyBytes, buf[:n]...)
		}
		if n < len(buf) {
			break
		}
	}
	// Try the new shape first.
	if err := json.Unmarshal(bodyBytes, &r); err == nil && len(r.Pools) > 0 {
		// Check first entry shape: if it's an object (has zfs_pool key
		// after unmarshal), good. If decode succeeded but Pools is an
		// array of objects, we're done.
		if r.Pools[0].ZFSPool != "" {
			return r.Pools, nil
		}
	}
	// Fallback: older peer returns {"pools": ["nvmepool", ...]}.
	var oldShape struct {
		Pools []string `json:"pools"`
	}
	if err := json.Unmarshal(bodyBytes, &oldShape); err == nil {
		out := make([]LXDRemoteZFSPoolInfo, 0, len(oldShape.Pools))
		for _, p := range oldShape.Pools {
			out = append(out, LXDRemoteZFSPoolInfo{ZFSPool: p})
		}
		return out, nil
	}
	return nil, fmt.Errorf("interlink-zfs-pools: unable to decode response")
}

// ── /api/lxd/interlink-prep-workload ──────────────────────────────────────

// LXDPrepWorkloadHMAC signs an ensure-workload-parent request. Fields are
// folded in so a replay against a different (pool, kind, compression)
// triple is rejected.
func LXDPrepWorkloadHMAC(sharedSecret string, timestamp int64, nonce, pool, kind, compression string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("lxd-prep-workload|" + strconv.FormatInt(timestamp, 10) + "|" + nonce + "|" + pool + "|" + kind + "|" + compression))
	return hex.EncodeToString(h.Sum(nil))
}

// LXDPrepWorkloadRequest is the HMAC-signed payload for
// /api/lxd/interlink-prep-workload — asks a peer to create the
// "<pool>/ZNAS-Backups-Workload/<kind>" parent dataset with the supplied
// compression property.
type LXDPrepWorkloadRequest struct {
	Timestamp   int64  `json:"timestamp"`
	Nonce       string `json:"nonce"`
	Pool        string `json:"pool"`
	Kind        string `json:"kind"`
	Compression string `json:"compression"`
	HMAC        string `json:"hmac"`
}

// InterlinkRemotePrepWorkload asks a peer to ensure its workload parent
// dataset exists with the chosen compression. Idempotent.
func InterlinkRemotePrepWorkload(remoteURL, sharedSecret, tlsFP, pool, kind, compression string) error {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := LXDPrepWorkloadRequest{
		Timestamp:   ts,
		Nonce:       nh,
		Pool:        pool,
		Kind:        kind,
		Compression: compression,
		HMAC:        LXDPrepWorkloadHMAC(sharedSecret, ts, nh, pool, kind, compression),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/incus/interlink-prep-workload", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var r struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&r)
		if r.Error != "" {
			return fmt.Errorf("%s", r.Error)
		}
		return fmt.Errorf("interlink-prep-workload returned status %d", resp.StatusCode)
	}
	return nil
}

// ── /api/lxd/interlink-prep-chain ─────────────────────────────────────────

// LXDPrepChainHMAC signs an "ask peer to wipe its backup dataset(s) if the
// chain is broken" request. Source server is about to syncoid-send the
// VM's workload datasets; if there's no shared snapshot, the peer wipes
// so the next send becomes a clean full send.
func LXDPrepChainHMAC(sharedSecret string, timestamp int64, nonce, pool, vm string, shared []string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	body := "lxd-prep-chain|" + strconv.FormatInt(timestamp, 10) + "|" + nonce + "|" + pool + "|" + vm + "|" + strings.Join(shared, ",")
	h.Write([]byte(body))
	return hex.EncodeToString(h.Sum(nil))
}

// LXDPrepChainRequest is the HMAC-signed payload for /api/lxd/interlink-prep-chain.
// SharedSnapshots is the snapshot-name list the source CURRENTLY HAS. The
// peer compares against its own destination snapshots; if none overlaps,
// the chain is broken and the destination is wiped.
type LXDPrepChainRequest struct {
	Timestamp       int64    `json:"timestamp"`
	Nonce           string   `json:"nonce"`
	Pool            string   `json:"pool"`
	VM              string   `json:"vm"`
	SharedSnapshots []string `json:"shared_snapshots"`
	HMAC            string   `json:"hmac"`
}

// LXDPrepChainResponse reports what the peer did.
type LXDPrepChainResponse struct {
	Wiped      bool     `json:"wiped"`
	WipedPaths []string `json:"wiped_paths,omitempty"`
}

// InterlinkRemotePrepChain asks a peer to check whether the chain for
// bkup--<vm> on its `pool` shares any snapshot with the supplied list,
// and to destroy the destination if not. Lets the source self-heal a
// chain that the user broke by deleting source snapshots.
func InterlinkRemotePrepChain(remoteURL, sharedSecret, tlsFP, pool, vm string, srcSnapshots []string) (*LXDPrepChainResponse, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := LXDPrepChainRequest{
		Timestamp:       ts,
		Nonce:           nh,
		Pool:            pool,
		VM:              vm,
		SharedSnapshots: srcSnapshots,
		HMAC:            LXDPrepChainHMAC(sharedSecret, ts, nh, pool, vm, srcSnapshots),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/incus/interlink-prep-chain", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("interlink-prep-chain returned status %d", resp.StatusCode)
	}
	var r LXDPrepChainResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ── /api/lxd/interlink-prune-retention ──────────────────────────────────────

// LXDPruneRetentionHMAC signs a "prune old backup snapshots" request. All
// retention parameters are folded in so a replay can't be redirected at a
// different backup or with a looser policy.
func LXDPruneRetentionHMAC(sharedSecret string, timestamp int64, nonce, pool, vm, kind string, count int, cutoffUnix int64) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("lxd-prune-retention|" + strconv.FormatInt(timestamp, 10) + "|" + nonce + "|" +
		pool + "|" + vm + "|" + kind + "|" + strconv.Itoa(count) + "|" + strconv.FormatInt(cutoffUnix, 10)))
	return hex.EncodeToString(h.Sum(nil))
}

// LXDPruneRetentionRequest is the HMAC-signed payload for
// /api/lxd/interlink-prune-retention — asks a peer to apply the sender's
// backup-retention policy to the workload backup of VM on Pool. Kind is
// "count" (keep the newest Count snapshots) or "age" (destroy snapshots
// older than CutoffUnix; the peer always keeps the newest snapshot as the
// next incremental's anchor).
type LXDPruneRetentionRequest struct {
	Timestamp  int64  `json:"timestamp"`
	Nonce      string `json:"nonce"`
	Pool       string `json:"pool"`
	VM         string `json:"vm"`
	Kind       string `json:"kind"`
	Count      int    `json:"count,omitempty"`
	CutoffUnix int64  `json:"cutoff_unix,omitempty"`
	HMAC       string `json:"hmac"`
}

// LXDPruneRetentionResponse lists the snapshot names the peer destroyed.
type LXDPruneRetentionResponse struct {
	Pruned []string `json:"pruned"`
}

// InterlinkRemotePruneRetention asks a peer to prune old snapshots of one
// workload backup according to the schedule's retention policy. The remote
// counterpart of the local applyBackupRetention.
func InterlinkRemotePruneRetention(remoteURL, sharedSecret, tlsFP, pool, vm, kind string, count int, cutoffUnix int64) (*LXDPruneRetentionResponse, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := LXDPruneRetentionRequest{
		Timestamp:  ts,
		Nonce:      nh,
		Pool:       pool,
		VM:         vm,
		Kind:       kind,
		Count:      count,
		CutoffUnix: cutoffUnix,
		HMAC:       LXDPruneRetentionHMAC(sharedSecret, ts, nh, pool, vm, kind, count, cutoffUnix),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/incus/interlink-prune-retention", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var r struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&r)
		if r.Error != "" {
			return nil, fmt.Errorf("%s", r.Error)
		}
		return nil, fmt.Errorf("interlink-prune-retention returned status %d", resp.StatusCode)
	}
	var out LXDPruneRetentionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ── /api/lxd/interlink-backups ──────────────────────────────────────────────

// RemoteBackupRecord describes one bkup--<vm> instance on a peer.
type RemoteBackupRecord struct {
	VMID           string                   `json:"vm_id"`
	BackupInstance string                   `json:"backup_instance"`
	Type           string                   `json:"type"` // "virtual-machine" | "container"
	Datastore      string                   `json:"datastore"`
	UsedBytes      int64                    `json:"used_bytes"` // total on-disk size of the backup on the peer
	Snapshots      []map[string]interface{} `json:"snapshots"`
}

// LXDBackupsHMAC signs a list-backups request.
func LXDBackupsHMAC(sharedSecret string, timestamp int64, nonce, vm string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("lxd-backups|" + strconv.FormatInt(timestamp, 10) + "|" + nonce + "|" + vm))
	return hex.EncodeToString(h.Sum(nil))
}

// LXDBackupsRequest is the HMAC-signed payload for /api/lxd/interlink-backups.
// VM may be empty — in that case the peer returns every bkup--* instance.
type LXDBackupsRequest struct {
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	VM        string `json:"vm"` // empty = list all
	HMAC      string `json:"hmac"`
}

// InterlinkRemoteVMBackups fetches the backup list for a single VM from a
// peer. Pass vm="" to retrieve all backup instances on the peer.
func InterlinkRemoteVMBackups(remoteURL, sharedSecret, tlsFP, vm string) ([]RemoteBackupRecord, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := LXDBackupsRequest{
		Timestamp: ts,
		Nonce:     nh,
		VM:        vm,
		HMAC:      LXDBackupsHMAC(sharedSecret, ts, nh, vm),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/incus/interlink-backups", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("interlink-backups returned status %d", resp.StatusCode)
	}
	var r struct {
		Backups []RemoteBackupRecord `json:"backups"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return r.Backups, nil
}

// InterlinkRemoteBackupDatastores fetches the storage-pool list from a peer
// so we can populate the Backup Schedule destination dropdown. Wraps the
// existing /api/lxd/storage-pools-remote — separate name kept for readability.
func InterlinkRemoteBackupDatastores(remoteURL, sharedSecret, tlsFP string) ([]string, error) {
	return GetRemoteLXDStoragePools(remoteURL, sharedSecret, tlsFP)
}

// ── /api/lxd/interlink-backup-delete ───────────────────────────────────────

// LXDBackupDeleteHMAC signs a backup-delete request. The body fields are
// folded into the HMAC payload so a peer that replays the message with a
// different vm/datastore is rejected.
func LXDBackupDeleteHMAC(sharedSecret string, timestamp int64, nonce, vm, datastore, snap string) string {
	key, _ := hex.DecodeString(sharedSecret)
	if len(key) == 0 {
		key = []byte(sharedSecret)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("lxd-backup-delete|" + strconv.FormatInt(timestamp, 10) + "|" + nonce + "|" + vm + "|" + datastore + "|" + snap))
	return hex.EncodeToString(h.Sum(nil))
}

// LXDBackupDeleteRequest is the HMAC-signed payload for
// /api/lxd/interlink-backup-delete. SnapshotName empty deletes the whole
// bkup--<vm> dataset on `Datastore`.
type LXDBackupDeleteRequest struct {
	Timestamp    int64  `json:"timestamp"`
	Nonce        string `json:"nonce"`
	VM           string `json:"vm"`
	Datastore    string `json:"datastore"`
	SnapshotName string `json:"snapshot_name"`
	HMAC         string `json:"hmac"`
}

// InterlinkRemoteDeleteBackup asks a peer to destroy one of its bkup--<vm>
// datasets (or one snapshot of it when snapshotName is non-empty).
func InterlinkRemoteDeleteBackup(remoteURL, sharedSecret, tlsFP, vm, datastore, snapshotName string) error {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	ts := time.Now().Unix()
	nh := hex.EncodeToString(nonce)
	req := LXDBackupDeleteRequest{
		Timestamp:    ts,
		Nonce:        nh,
		VM:           vm,
		Datastore:    datastore,
		SnapshotName: snapshotName,
		HMAC:         LXDBackupDeleteHMAC(sharedSecret, ts, nh, vm, datastore, snapshotName),
	}
	body, _ := json.Marshal(req)
	resp, err := interlinkClientFor(tlsFP).Post(remoteURL+"/api/incus/interlink-backup-delete", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var r struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&r)
		msg := r.Error
		if msg == "" {
			msg = fmt.Sprintf("interlink-backup-delete returned status %d", resp.StatusCode)
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// InterlinkRemoteHostName returns the hostname portion of a linked-server URL,
// for activity-bar labels. Kept in this file because all callers are 6.5.19+.
func InterlinkRemoteHostName(remoteURL string) string {
	u, err := url.Parse(remoteURL)
	if err != nil {
		return remoteURL
	}
	return u.Hostname()
}
