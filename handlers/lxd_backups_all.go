package handlers

// Datastores → Backups page handlers + Restore actions (v6.5.19+).
//
// This file plays two roles:
//   • Cross-server backup aggregator used by the Backups page and the per-VM
//     dropdown (the dropdown calls the same endpoint with a vm filter
//     applied client-side).
//   • Restore endpoints (instant rename + clone via syncoid).
//
// Plus the peer-side HMAC handlers that other ZNAS hosts call to read this
// host's backups + pool sources.

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"
)

// HandleListAllBackups returns every backup known to this host AND every
// linked InterLink peer. Used by the Datastores → Backups page.
// GET /api/incus/backups
func HandleListAllBackups(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []map[string]interface{}{}
		// Local workload backups (v6.5.19+ canonical layout).
		if workload, err := system.ListWorkloadBackupInstances(); err == nil {
			for _, w := range workload {
				vmID := strings.TrimPrefix(w.Name, system.LXDBackupPrefix)
				snaps := system.ListWorkloadBackupSnapshots(w.Dataset)
				snapList := make([]map[string]interface{}, 0, len(snaps))
				for _, s := range snaps {
					snapList = append(snapList, map[string]interface{}{
						"name":       s.Name,
						"created_at": s.CreatedAt,
						"used":       s.Used,
						"written":    s.Written,
					})
				}
				out = append(out, map[string]interface{}{
					"vm_id":           vmID,
					"type":            w.Type,
					"scope":           "local",
					"hostname":        "",
					"server_id":       "",
					"datastore":       w.ZFSPool,
					"backup_instance": w.Name,
					"used_bytes":      w.UsedBytes,
					"snapshots":       snapList,
					// Instances running off a ZFS clone of this backup (Instant
					// Independent Restores). Non-empty → backup can't be deleted.
					"dependents": system.BackupDependents(w.ZFSPool, vmID),
				})
			}
		}
		// Legacy local Incus-pool backups (pre-v6.5.19).
		local, _ := system.LXDListAllBackupInstances()
		for _, inst := range local {
			vmID := strings.TrimPrefix(inst.Name, system.LXDBackupPrefix)
			snaps := system.LXDListBackupSnapshots(inst.Name, inst.RootPool)
			snapList := make([]map[string]interface{}, 0, len(snaps))
			for _, s := range snaps {
				snapList = append(snapList, map[string]interface{}{
					"name":       s.Name,
					"created_at": s.CreatedAt,
					"used":       s.Used,
					"written":    s.Written,
				})
			}
			out = append(out, map[string]interface{}{
				"vm_id":           vmID,
				"type":            inst.Type,
				"scope":           "local",
				"hostname":        "",
				"server_id":       "",
				"datastore":       inst.RootPool,
				"backup_instance": inst.Name,
				"snapshots":       snapList,
			})
		}
		// Remote: fan out to every linked peer. 4 s budget per peer.
		// v6.5.19+: don't gate on LXDTrusted — backups land in plain
		// "<pool>/ZNAS-Backups-Workload/..." datasets, no Incus required
		// on the peer, so the LXD-cert exchange isn't a prerequisite.
		var wg sync.WaitGroup
		var mu sync.Mutex
		for i := range appCfg.InterLink {
			ls := appCfg.InterLink[i]
			wg.Add(1)
			go func(ls config.LinkedServer) {
				defer wg.Done()
				records, err := system.InterlinkRemoteVMBackups(ls.URL, ls.SharedSecret, ls.TLSFingerprint, "")
				if err != nil {
					return
				}
				for _, rec := range records {
					mu.Lock()
					out = append(out, map[string]interface{}{
						"vm_id":           rec.VMID,
						"type":            rec.Type,
						"scope":           "remote",
						"hostname":        ls.Hostname,
						"server_id":       ls.ID,
						"datastore":       rec.Datastore,
						"backup_instance": rec.BackupInstance,
						"used_bytes":      rec.UsedBytes,
						"snapshots":       rec.Snapshots,
					})
					mu.Unlock()
				}
			}(ls)
		}
		// Bound the wait.
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		jsonOK(w, out)
	}
}

// HandleListAggregatedBackupsForVM is the per-VM version called by the
// per-instance Backups dropdown. Same fan-out as HandleListAllBackups but
// filtered to a single vm_id.
// GET /api/incus/instances/{name}/backups-aggregate
func HandleListAggregatedBackupsForVM(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vmID := mux.Vars(r)["name"]
		local := listLocalBackupsForVM(vmID)
		remote := []map[string]interface{}{}
		var wg sync.WaitGroup
		var mu sync.Mutex
		for i := range appCfg.InterLink {
			ls := appCfg.InterLink[i]
			// v6.5.19+: do NOT gate on LXDTrusted. Backups live in plain
			// "<pool>/ZNAS-Backups-Workload/..." datasets — a peer hosting
			// them needs no Incus and no LXD-cert trust. The cross-server
			// Backups page (HandleListAllBackups) already dropped this
			// gate; this per-VM dropdown aggregator must match it,
			// otherwise a backup on a non-LXD-trusted peer shows in the
			// table but not in the per-VM Backups dropdown.
			wg.Add(1)
			go func(ls config.LinkedServer) {
				defer wg.Done()
				records, err := system.InterlinkRemoteVMBackups(ls.URL, ls.SharedSecret, ls.TLSFingerprint, vmID)
				if err != nil {
					return
				}
				for _, rec := range records {
					mu.Lock()
					remote = append(remote, map[string]interface{}{
						"server_id":       ls.ID,
						"hostname":        ls.Hostname,
						"datastore":       rec.Datastore,
						"backup_instance": rec.BackupInstance,
						"used_bytes":      rec.UsedBytes,
						"snapshots":       rec.Snapshots,
					})
					mu.Unlock()
				}
			}(ls)
		}
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		jsonOK(w, map[string]interface{}{
			"instance": vmID,
			"local":    local,
			"remote":   remote,
		})
	}
}

// HandleListBackupDatastores returns every datastore reachable from this
// host that is a viable backup destination — every local Incus storage
// pool plus every remote pool on every LXD-trusted peer.
// GET /api/incus/backup-datastores
func HandleListBackupDatastores(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries := []map[string]interface{}{}
		// v6.5.19+: backups (local + remote) all live in the workload
		// layout under "<zfs-pool>/ZNAS-Backups-Workload/...". The
		// destination picker therefore lists ZFS pool names directly —
		// no Incus storage-pool indirection. We also surface the local
		// Incus datastore name (if any) backed by each pool so the UI
		// can show "<zfs-pool>  (Incus datastore: <name>)".
		localPools, _ := system.ListLocalZFSPools()
		incusPools, _ := system.LXDListStoragePools()
		bySource := map[string]string{}
		for _, ip := range incusPools {
			src := system.LXDStoragePoolSource(ip)
			if src == "" {
				continue
			}
			root := src
			if i := strings.IndexByte(src, '/'); i > 0 {
				root = src[:i]
			}
			bySource[strings.ToLower(root)] = ip
		}
		for _, p := range localPools {
			entries = append(entries, map[string]interface{}{
				"kind":            "local",
				"server_id":       "",
				"hostname":        "",
				"datastore":       p,
				"incus_datastore": bySource[strings.ToLower(p)],
			})
		}
		// Remote (parallel, 4 s budget per peer). v6.5.19+: peers expose
		// their ZFS pools annotated with the Incus storage-pool (if any)
		// that uses each as source. The frontend renders rows showing
		// both — and clearly marks ZFS pools without an Incus datastore.
		var wg sync.WaitGroup
		var mu sync.Mutex
		for i := range appCfg.InterLink {
			ls := appCfg.InterLink[i]
			wg.Add(1)
			go func(ls config.LinkedServer) {
				defer wg.Done()
				pools, err := system.InterlinkRemoteZFSPools(ls.URL, ls.SharedSecret, ls.TLSFingerprint)
				if err != nil {
					return
				}
				for _, p := range pools {
					mu.Lock()
					entries = append(entries, map[string]interface{}{
						"kind":            "remote",
						"server_id":       ls.ID,
						"hostname":        ls.Hostname,
						"datastore":       p.ZFSPool, // ZFS pool name on peer (used as DestPool in policies)
						"incus_datastore": p.IncusDatastore,
					})
					mu.Unlock()
				}
			}(ls)
		}
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		jsonOK(w, entries)
	}
}

// HandleDeleteBackup deletes a backup. When `snapshot_name` is provided the
// single snapshot is destroyed; otherwise the entire bkup--<vm> dataset
// (and its .block sibling, plus any custom-volume datasets) is destroyed.
// Local-only — remote backups are deleted on the peer via a separate path.
// POST /api/incus/backups/delete
func HandleDeleteBackup(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		var req struct {
			VMID         string `json:"vm_id"`
			Scope        string `json:"scope"`     // "local" | "remote"
			ServerID     string `json:"server_id"` // when remote
			Datastore    string `json:"datastore"`
			SnapshotName string `json:"snapshot_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.VMID == "" || req.Datastore == "" {
			jsonErr(w, http.StatusBadRequest, "vm_id and datastore are required")
			return
		}
		if req.Scope == "remote" {
			ls := getLinkedServer(appCfg, req.ServerID)
			if ls == nil {
				jsonErr(w, http.StatusBadRequest, "linked server not found")
				return
			}
			target := fmt.Sprintf("%s on %s (%s)", system.LXDBackupPrefix+req.VMID, req.Datastore, ls.Hostname)
			if req.SnapshotName != "" {
				target += " @ " + req.SnapshotName
			}
			if err := system.InterlinkRemoteDeleteBackup(ls.URL, ls.SharedSecret, ls.TLSFingerprint, req.VMID, req.Datastore, req.SnapshotName); err != nil {
				audit.Log(audit.Entry{
					User: sess.Username, Role: sess.Role,
					Action:  "lxd_backup_delete",
					Target:  target,
					Result:  audit.ResultError,
					Details: err.Error(),
				})
				jsonErr(w, http.StatusBadGateway, err.Error())
				return
			}
			audit.Log(audit.Entry{
				User: sess.Username, Role: sess.Role,
				Action: "lxd_backup_delete",
				Target: target,
				Result: audit.ResultOK,
			})
			jsonOK(w, map[string]bool{"ok": true})
			return
		}
		target := fmt.Sprintf("%s on %s", system.LXDBackupPrefix+req.VMID, req.Datastore)
		if req.SnapshotName != "" {
			target += " @ " + req.SnapshotName
		}
		// Try workload-layout delete first (v6.5.19+ canonical). Fall
		// back to legacy Incus-pool delete if the workload version
		// reports "not found" — preserves compatibility with pre-v6.5.19
		// backup data still living under <pool>/virtual-machines/.
		var dErr error
		if werr := system.DeleteWorkloadBackup(req.Datastore, req.VMID, req.SnapshotName); werr != nil {
			if strings.Contains(werr.Error(), "not found") {
				dErr = system.DeleteLocalBackup(req.VMID, req.Datastore, req.SnapshotName)
			} else {
				dErr = werr
			}
		}
		if err := dErr; err != nil {
			audit.Log(audit.Entry{
				User: sess.Username, Role: sess.Role,
				Action:  "lxd_backup_delete",
				Target:  target,
				Result:  audit.ResultError,
				Details: err.Error(),
			})
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		audit.Log(audit.Entry{
			User: sess.Username, Role: sess.Role,
			Action: "lxd_backup_delete",
			Target: target,
			Result: audit.ResultOK,
		})
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleInstantRestoreBackup turns bkup--<vm> into a regular Incus instance
// in place. Local-only — the backup must live on this host. v6.5.19+: the
// optional `datastore` field is the ZFS pool name hosting the backup; when
// omitted the system function scans every imported ZFS pool for a match.
// POST /api/incus/backups/restore-instant
func HandleInstantRestoreBackup(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	var req struct {
		VMID         string `json:"vm_id"`
		NewName      string `json:"new_name"`
		Datastore    string `json:"datastore"`     // ZFS pool name (e.g. "BIGRAID5"); optional
		SnapshotName string `json:"snapshot_name"` // optional point-in-time; "" = latest
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := system.LXDInstantRestoreBackup(req.VMID, req.NewName, req.Datastore, req.SnapshotName); err != nil {
		audit.Log(audit.Entry{
			User: sess.Username, Role: sess.Role,
			Action:  audit.ActionLXDBackupRestore,
			Target:  req.VMID + " → " + req.NewName,
			Result:  audit.ResultError,
			Details: err.Error(),
		})
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	audit.Log(audit.Entry{
		User: sess.Username, Role: sess.Role,
		Action: audit.ActionLXDBackupRestore,
		Target: req.VMID + " → " + req.NewName,
		Result: audit.ResultOK,
	})
	jsonOK(w, map[string]bool{"ok": true})
}

// HandleBackupDependency reports whether an instance is running off a backup
// clone (an Instant Independent Restore) and, if so, which backup it pins.
// GET /api/lxd/instances/{name}/backup-dependency
func HandleBackupDependency(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	origins, err := system.LXDInstanceBackupOrigins(name)
	if err != nil {
		jsonOK(w, map[string]interface{}{"dependent": false})
		return
	}
	resp := map[string]interface{}{"dependent": len(origins) > 0, "origins": origins}
	if len(origins) > 0 {
		resp["backup_vm_id"] = origins[0].BackupVMID
		resp["datastore"] = origins[0].BackupPool
		resp["snapshot"] = origins[0].Snapshot
	}
	jsonOK(w, resp)
}

// HandlePromoteFullCopy promotes a backup-dependent instance to an independent
// full copy on the chosen datastore (frees the backup). Runs as a background
// restore job; progress via /api/lxd/restore-jobs/{id}/progress.
// POST /api/lxd/instances/{name}/promote-full-copy   body {datastore}
func HandlePromoteFullCopy(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		name := mux.Vars(r)["name"]
		var req struct {
			Datastore string `json:"datastore"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Datastore == "" {
			jsonErr(w, http.StatusBadRequest, "datastore is required")
			return
		}
		if !system.SyncoidPrereqsInstalled() {
			jsonErr(w, http.StatusBadRequest, "syncoid is not installed (Prerequisites → ZFS Replication)")
			return
		}
		if origins, _ := system.LXDInstanceBackupOrigins(name); len(origins) == 0 {
			jsonErr(w, http.StatusBadRequest, name+" is not running off a backup clone — nothing to promote")
			return
		}
		if st, err := system.LXDGetStatus(name); err == nil && !strings.EqualFold(st, "Stopped") {
			jsonErr(w, http.StatusBadRequest, name+" must be Stopped before promoting to a Full Copy (current: "+st+")")
			return
		}

		id := fmt.Sprintf("brj-%d", time.Now().UnixNano())
		ctx, cancel := context.WithCancel(context.Background())
		job := &lxdRestoreJob{Status: "running", VMID: name, CloneName: name, StartedAt: time.Now(), cancelFn: cancel}
		lxdRestoreJobs.Store(id, job)

		go func() {
			err := system.LXDPromoteToFullCopy(ctx, name, req.Datastore, job.appendLine)
			job.mu.Lock()
			if err != nil && err != context.Canceled && job.Status != "canceled" {
				job.Status = "error"
				job.Error = err.Error()
			} else if job.Status != "canceled" {
				job.Status = "done"
			}
			job.mu.Unlock()
			result := audit.ResultOK
			details := ""
			if err != nil && err != context.Canceled {
				result = audit.ResultError
				details = err.Error()
			}
			audit.Log(audit.Entry{
				User: sess.Username, Role: sess.Role,
				Action:  audit.ActionLXDBackupPromote,
				Target:  name + " → Full Copy (" + req.Datastore + ")",
				Result:  result,
				Details: details,
			})
		}()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"job_id": id})
	}
}

// --- Clone-restore (background job) ---

type lxdRestoreJob struct {
	mu        sync.Mutex
	Status    string    `json:"status"`
	Error     string    `json:"error,omitempty"`
	Lines     []string  `json:"lines"`
	VMID      string    `json:"vm_id"`
	CloneName string    `json:"clone_name"`
	StartedAt time.Time `json:"started_at"`
	Progress  int       `json:"progress"` // 0–100 for the current part (pv %)
	Phase     string    `json:"phase"`    // which dataset is transferring now
	cancelFn  context.CancelFunc
}

func (j *lxdRestoreJob) appendLine(line string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.Lines) > 4000 {
		j.Lines = j.Lines[len(j.Lines)-3000:]
	}
	j.Lines = append(j.Lines, line)
	// Live progress for the activity bar. Restore prints "Pulling <src> -> <dst>"
	// before each dataset; pv's percentage drives the bar within a part.
	if strings.HasPrefix(line, "Pulling ") {
		j.Phase = "pull"
		j.Progress = 0
	} else if pct, ok := system.ParseSyncoidPercent(line); ok {
		j.Progress = pct
	}
}

func (j *lxdRestoreJob) cancel() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.Status == "queued" || j.Status == "running" {
		j.Status = "canceled"
		if j.cancelFn != nil {
			j.cancelFn()
		}
	}
}

var lxdRestoreJobs sync.Map // job_id → *lxdRestoreJob

// HandleCloneRestoreBackup starts a syncoid-driven clone-restore from a
// (local or remote) backup into a chosen local datastore.
// POST /api/incus/backups/restore-clone
func HandleCloneRestoreBackup(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		var req struct {
			VMID         string `json:"vm_id"`
			Scope        string `json:"scope"`         // "local" | "remote"
			ServerID     string `json:"server_id"`     // when scope=="remote"
			SrcDatastore string `json:"src_datastore"` // pool name on source host
			CloneName    string `json:"clone_name"`
			DstDatastore string `json:"dst_datastore"` // local pool only
			// SnapshotName — optional. Empty = restore latest. When set, the
			// cloned dataset is rolled back (`zfs rollback -r`) to this
			// snapshot after syncoid finishes, so the resulting instance is
			// the VM state at exactly that point in time. The Backups page
			// passes this from the per-snapshot Restore buttons.
			SnapshotName string `json:"snapshot_name"`
			// Type — "virtual-machine" | "container". Needed for the
			// remote restore path to compose the correct workload kind
			// segment ("virtual-machines" vs "containers"). Defaults to
			// "virtual-machine" when omitted for backwards-compat.
			Type string `json:"type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if !system.SyncoidPrereqsInstalled() {
			jsonErr(w, http.StatusBadRequest, "syncoid is not installed (Prerequisites → ZFS Replication)")
			return
		}
		if req.VMID == "" || req.CloneName == "" || req.DstDatastore == "" {
			jsonErr(w, http.StatusBadRequest, "vm_id, clone_name, dst_datastore are required")
			return
		}

		id := fmt.Sprintf("brj-%d", time.Now().UnixNano())
		ctx, cancel := context.WithCancel(context.Background())
		job := &lxdRestoreJob{
			Status:    "running",
			VMID:      req.VMID,
			CloneName: req.CloneName,
			StartedAt: time.Now(),
			cancelFn:  cancel,
		}
		lxdRestoreJobs.Store(id, job)

		go func() {
			var err error
			if req.Scope == "remote" {
				ls := getLinkedServer(appCfg, req.ServerID)
				if ls == nil {
					err = fmt.Errorf("linked server %q not found", req.ServerID)
				} else {
					var u *url.URL
					u, err = url.Parse(ls.URL)
					if err == nil {
						// v6.5.19+: remote backups live at the well-known
						// workload path on the peer's ZFS pool. SrcDatastore
						// is the peer's ZFS POOL name. No Incus required.
						kind := "virtual-machines"
						if req.Type == "container" {
							kind = "containers"
						}
						srcDataset := system.LXDWorkloadBackupDataset(req.SrcDatastore, kind, req.VMID)
						pubKey, kerr := system.EnsureSSHKey()
						if kerr != nil {
							err = kerr
						} else {
							// SSH key push is idempotent — a prior backup/restore to
							// this peer already placed it. A transient failure here
							// (overloaded peer) is non-fatal; syncoid surfaces a clear
							// publickey error later if the key is genuinely absent.
							if perr := system.SendPushSSHKey(ls.URL, ls.SharedSecret, pubKey, ls.TLSFingerprint); perr != nil {
								job.appendLine("warning: could not refresh SSH key on peer (" + perr.Error() + ") — continuing.")
							}
							remoteInfo, rerr := system.GetRemotePools(ls.URL, ls.SharedSecret, ls.TLSFingerprint)
							if rerr != nil || remoteInfo == nil {
								err = fmt.Errorf("cannot reach remote server")
							} else if zerr := system.EnsureRemoteZFSAccess(ls.URL, ls.SharedSecret, ls.TLSFingerprint); zerr != nil {
								err = zerr
							} else {
								// Resolve a direct SSH transport — the InterLink URL may be a
								// reverse proxy that forwards only HTTPS. The peer advertises
								// its real IPs; probe each, fall back to the URL host.
								// Pin the peer's advertised SSH host keys (verified over the
								// authenticated channel) so the pull self-heals after a re-key.
								knownHosts := system.WriteInterlinkKnownHosts(
									append(append([]string{}, remoteInfo.SSHHosts...), u.Hostname()),
									remoteInfo.SSHHostKeys)
								if knownHosts != "" {
									defer os.Remove(knownHosts)
								}
								sshHost := system.PickReachableSSHHost(remoteInfo.SSHHosts, u.Hostname(), remoteInfo.ProcessUser, knownHosts)
								if sshHost == "" {
									err = fmt.Errorf("no SSH-reachable address for peer %s (tried %v and %s) — the InterLink URL may point at a reverse proxy that doesn't forward SSH", ls.Hostname, remoteInfo.SSHHosts, u.Hostname())
								} else {
									job.appendLine("SSH transport to peer: " + sshHost)
									err = system.LXDCloneRestoreRemote(ctx, sshHost, remoteInfo.ProcessUser, srcDataset, req.DstDatastore, req.CloneName, req.SnapshotName, req.VMID, knownHosts, job.appendLine)
								}
							}
						}
					}
				}
			} else {
				err = system.LXDCloneRestoreLocal(ctx, req.VMID, req.SrcDatastore, req.DstDatastore, req.CloneName, req.SnapshotName, job.appendLine)
			}

			job.mu.Lock()
			if err != nil && err != context.Canceled && job.Status != "canceled" {
				job.Status = "error"
				job.Error = err.Error()
			} else if job.Status != "canceled" {
				job.Status = "done"
			}
			job.mu.Unlock()

			result := audit.ResultOK
			details := ""
			if err != nil && err != context.Canceled {
				result = audit.ResultError
				details = err.Error()
			}
			audit.Log(audit.Entry{
				User: sess.Username, Role: sess.Role,
				Action:  audit.ActionLXDBackupCloneRestore,
				Target:  req.VMID + " → " + req.CloneName + " (" + req.DstDatastore + ")",
				Result:  result,
				Details: details,
			})
		}()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"job_id": id})
	}
}

// HandleRestoreCloneProgress returns the running log + status of a clone-restore job.
// GET /api/incus/restore-jobs/{job_id}/progress
func HandleRestoreCloneProgress(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["job_id"]
	v, ok := lxdRestoreJobs.Load(id)
	if !ok {
		jsonErr(w, http.StatusNotFound, "job not found")
		return
	}
	j := v.(*lxdRestoreJob)
	j.mu.Lock()
	defer j.mu.Unlock()
	jsonOK(w, map[string]interface{}{
		"status":     j.Status,
		"error":      j.Error,
		"lines":      j.Lines,
		"vm_id":      j.VMID,
		"clone_name": j.CloneName,
		"started_at": j.StartedAt,
		"progress":   j.Progress,
		"phase":      j.Phase,
	})
}

// HandleListRestoreJobs returns all clone-restore jobs the server knows about
// (running/queued + recently finished), so the activity bar can rediscover an
// in-flight restore after a reload or from another browser/tab.
// GET /api/incus/restore-jobs
func HandleListRestoreJobs(w http.ResponseWriter, r *http.Request) {
	out := []map[string]interface{}{}
	lxdRestoreJobs.Range(func(k, v interface{}) bool {
		id := k.(string)
		j := v.(*lxdRestoreJob)
		j.mu.Lock()
		keep := j.Status == "running" || j.Status == "queued" ||
			time.Since(j.StartedAt) < 5*time.Minute
		if keep {
			out = append(out, map[string]interface{}{
				"job_id":     id,
				"status":     j.Status,
				"vm_id":      j.VMID,
				"clone_name": j.CloneName,
				"started_at": j.StartedAt,
				"progress":   j.Progress,
				"phase":      j.Phase,
			})
		}
		j.mu.Unlock()
		return true
	})
	sort.Slice(out, func(a, b int) bool {
		return out[a]["started_at"].(time.Time).After(out[b]["started_at"].(time.Time))
	})
	jsonOK(w, map[string]interface{}{"jobs": out})
}

// HandleRestoreCloneCancel cancels a running clone-restore job.
// POST /api/incus/restore-jobs/{job_id}/cancel
func HandleRestoreCloneCancel(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["job_id"]
	v, ok := lxdRestoreJobs.Load(id)
	if !ok {
		jsonErr(w, http.StatusNotFound, "job not found")
		return
	}
	v.(*lxdRestoreJob).cancel()
	jsonOK(w, map[string]bool{"ok": true})
}

// --- Peer-side HMAC handlers ---

// HandleInterlinkPoolSource handles POST /api/lxd/interlink-pool-source — HMAC-authenticated.
// Returns the ZFS source for one local Incus pool to a peer server.
func HandleInterlinkPoolSource(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDPoolSourceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		matched := false
		for _, ls := range appCfg.InterLink {
			expected := system.LXDPoolSourceHMAC(ls.SharedSecret, req.Timestamp, req.Nonce, req.Pool)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		src := system.LXDStoragePoolSource(req.Pool)
		jsonOK(w, map[string]string{"source": src})
	}
}

// HandleInterlinkBackupDelete handles POST /api/lxd/interlink-backup-delete —
// HMAC-authenticated. Destroys a backup that lives on this host on behalf
// of a peer (the user is initiating from the peer's UI). Empty SnapshotName
// deletes the whole bkup--<vm> dataset; otherwise just that snapshot.
//
// v6.5.19+: `Datastore` is the local ZFS pool name (workload layout). The
// handler prefers workload-style deletion and falls back to the legacy
// Incus-pool path so pre-existing Incus-registered backups still respond.
func HandleInterlinkBackupDelete(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDBackupDeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		matched := false
		var ls config.LinkedServer
		for _, l := range appCfg.InterLink {
			expected := system.LXDBackupDeleteHMAC(l.SharedSecret, req.Timestamp, req.Nonce, req.VM, req.Datastore, req.SnapshotName)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				ls = l
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		if req.VM == "" || req.Datastore == "" {
			jsonErr(w, http.StatusBadRequest, "vm and datastore are required")
			return
		}
		target := fmt.Sprintf("%s on %s", system.LXDBackupPrefix+req.VM, req.Datastore)
		if req.SnapshotName != "" {
			target += " @ " + req.SnapshotName
		}
		// Try workload-style delete first (v6.5.19+). If the workload
		// path doesn't exist on the named pool, fall back to the legacy
		// Incus-pool delete so older backups still respond.
		var dErr error
		if werr := system.DeleteWorkloadBackup(req.Datastore, req.VM, req.SnapshotName); werr != nil {
			// "not found" → try legacy.
			if strings.Contains(werr.Error(), "not found") {
				dErr = system.DeleteLocalBackup(req.VM, req.Datastore, req.SnapshotName)
			} else {
				dErr = werr
			}
		}
		if err := dErr; err != nil {
			audit.Log(audit.Entry{
				User:    "interlink:" + ls.Hostname,
				Role:    "interlink",
				Action:  "lxd_backup_delete",
				Target:  target,
				Result:  audit.ResultError,
				Details: err.Error(),
			})
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		audit.Log(audit.Entry{
			User:   "interlink:" + ls.Hostname,
			Role:   "interlink",
			Action: "lxd_backup_delete",
			Target: target,
			Result: audit.ResultOK,
		})
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleInterlinkListLocalBackups handles POST /api/lxd/interlink-backups —
// HMAC-authenticated. Returns this host's bkup--* instances (optionally
// filtered to one VM) to a peer.
func HandleInterlinkListLocalBackups(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDBackupsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		matched := false
		for _, ls := range appCfg.InterLink {
			expected := system.LXDBackupsHMAC(ls.SharedSecret, req.Timestamp, req.Nonce, req.VM)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		records := []system.RemoteBackupRecord{}
		// Workload-style backups (the v6.5.19+ convention used by every
		// remote target — peer doesn't need Incus). Scanned via plain
		// `zfs list` on every imported pool.
		workload, _ := system.ListWorkloadBackupInstances()
		for _, w := range workload {
			vm := strings.TrimPrefix(w.Name, system.LXDBackupPrefix)
			if req.VM != "" && vm != req.VM {
				continue
			}
			snaps := system.ListWorkloadBackupSnapshots(w.Dataset)
			snapList := make([]map[string]interface{}, 0, len(snaps))
			for _, s := range snaps {
				snapList = append(snapList, map[string]interface{}{
					"name":       s.Name,
					"created_at": s.CreatedAt,
					"used":       s.Used,
					"written":    s.Written,
				})
			}
			records = append(records, system.RemoteBackupRecord{
				VMID:           vm,
				BackupInstance: w.Name,
				Type:           w.Type,
				Datastore:      w.ZFSPool, // expose the ZFS pool name as the "datastore"
				UsedBytes:      w.UsedBytes,
				Snapshots:      snapList,
			})
		}
		// Legacy: Incus-registered bkup--* instances (kept so existing
		// deployments that pre-date the workload layout still surface
		// their backups). When Incus isn't installed this returns empty.
		local, _ := system.LXDListAllBackupInstances()
		for _, inst := range local {
			vm := strings.TrimPrefix(inst.Name, system.LXDBackupPrefix)
			if req.VM != "" && vm != req.VM {
				continue
			}
			snaps := system.LXDListBackupSnapshots(inst.Name, inst.RootPool)
			snapList := make([]map[string]interface{}, 0, len(snaps))
			for _, s := range snaps {
				snapList = append(snapList, map[string]interface{}{
					"name":       s.Name,
					"created_at": s.CreatedAt,
					"used":       s.Used,
					"written":    s.Written,
				})
			}
			records = append(records, system.RemoteBackupRecord{
				VMID:           vm,
				BackupInstance: inst.Name,
				Type:           inst.Type,
				Datastore:      inst.RootPool,
				Snapshots:      snapList,
			})
		}
		jsonOK(w, map[string]interface{}{"backups": records})
	}
}

// HandleInterlinkPrepChain handles POST /api/lxd/interlink-prep-chain —
// HMAC-authenticated. Peer checks whether any of `SharedSnapshots` exist on
// its bkup--<vm> dataset(s); if none do, the destination is destroyed so
// the imminent syncoid pull can do a clean full send. This is the remote
// counterpart to PrepLocalBackupChain.
func HandleInterlinkPrepChain(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDPrepChainRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		matched := false
		for _, ls := range appCfg.InterLink {
			expected := system.LXDPrepChainHMAC(ls.SharedSecret, req.Timestamp, req.Nonce, req.Pool, req.VM, req.SharedSnapshots)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		if req.Pool == "" || req.VM == "" {
			jsonErr(w, http.StatusBadRequest, "pool and vm required")
			return
		}
		// Walk the destination's root-fs and .block datasets. Wipe each
		// when its snapshot set has no overlap with the source's.
		parent := system.LXDWorkloadBackupParent(req.Pool)
		bkup := system.LXDBackupPrefix + req.VM
		srcSet := map[string]bool{}
		for _, s := range req.SharedSnapshots {
			srcSet[s] = true
		}
		wiped := []string{}
		check := func(ds string) {
			if !system.DatasetExistsForBackups(ds) {
				return
			}
			dstSet := system.SnapshotNameSetForBackups(ds)
			for n := range dstSet {
				if srcSet[n] {
					return // chain still intact
				}
			}
			if err := system.DestroyDatasetRecursive(ds); err == nil {
				wiped = append(wiped, ds)
			}
		}
		check(parent + "/virtual-machines/" + bkup)
		check(parent + "/virtual-machines/" + bkup + ".block")
		check(parent + "/containers/" + bkup)
		jsonOK(w, system.LXDPrepChainResponse{
			Wiped:      len(wiped) > 0,
			WipedPaths: wiped,
		})
	}
}

// HandleInterlinkPruneRetention handles POST /api/lxd/interlink-prune-retention
// — HMAC-authenticated. Applies the sender's backup-retention policy to the
// workload backup of VM on Pool: every dataset part (root fs, VM .block
// sibling, custom volumes) keeps only the newest Count snapshots ("count")
// or drops snapshots older than CutoffUnix ("age"; the newest always
// survives as the incremental anchor). The remote counterpart of the local
// applyBackupRetention.
func HandleInterlinkPruneRetention(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDPruneRetentionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		matched := false
		for _, ls := range appCfg.InterLink {
			expected := system.LXDPruneRetentionHMAC(ls.SharedSecret, req.Timestamp, req.Nonce,
				req.Pool, req.VM, req.Kind, req.Count, req.CutoffUnix)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		if req.Pool == "" || req.VM == "" {
			jsonErr(w, http.StatusBadRequest, "pool and vm required")
			return
		}
		// Same snapshot names exist on the root-fs and .block parts, so
		// dedupe for the response — the caller logs these verbatim.
		pruned := []string{}
		seen := map[string]bool{}
		for _, ds := range system.WorkloadBackupPartDatasets(req.Pool, req.VM) {
			var names []string
			switch req.Kind {
			case "count":
				if req.Count > 0 {
					names, _ = system.LXDPruneRetentionByCount(ds, "", req.Count)
				}
			case "age":
				if req.CutoffUnix > 0 {
					names, _ = system.LXDPruneRetentionByAge(ds, "", time.Unix(req.CutoffUnix, 0))
				}
			}
			for _, n := range names {
				if !seen[n] {
					seen[n] = true
					pruned = append(pruned, n)
				}
			}
		}
		jsonOK(w, system.LXDPruneRetentionResponse{Pruned: pruned})
	}
}

// HandleInterlinkPrepWorkload handles POST /api/lxd/interlink-prep-workload —
// HMAC-authenticated. Ensures the workload parent dataset exists with the
// requested compression on this host so the peer's syncoid push will land
// in a properly-tuned location.
func HandleInterlinkPrepWorkload(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDPrepWorkloadRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		matched := false
		for _, ls := range appCfg.InterLink {
			expected := system.LXDPrepWorkloadHMAC(ls.SharedSecret, req.Timestamp, req.Nonce, req.Pool, req.Kind, req.Compression)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		if req.Pool == "" || req.Kind == "" {
			jsonErr(w, http.StatusBadRequest, "pool and kind are required")
			return
		}
		if err := system.EnsureWorkloadParent(req.Pool, req.Kind, req.Compression); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleInterlinkZFSPools handles POST /api/lxd/interlink-zfs-pools —
// HMAC-authenticated. Returns this host's ZFS pool list so peers can pick
// a backup destination even when Incus isn't installed on the local box.
func HandleInterlinkZFSPools(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDZFSPoolsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		matched := false
		for _, ls := range appCfg.InterLink {
			expected := system.LXDZFSPoolsHMAC(ls.SharedSecret, req.Timestamp, req.Nonce)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		pools, err := system.ListLocalZFSPools()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Map each ZFS pool to the Incus storage-pool (if any) that uses
		// it as `source`. Lets the caller's dropdown show both the ZFS
		// pool name and a friendly Incus datastore label. Best-effort —
		// if Incus isn't installed on this peer, every pool is reported
		// with an empty IncusDatastore.
		incusPools, _ := system.LXDListStoragePools()
		bySource := map[string]string{}
		for _, ip := range incusPools {
			src := system.LXDStoragePoolSource(ip)
			if src == "" {
				continue
			}
			// `source` may be like "<zfs-pool>/<incus-dataset>"; the ZFS pool
			// portion is everything before the first slash.
			root := src
			if i := strings.IndexByte(src, '/'); i > 0 {
				root = src[:i]
			}
			// Lowercase compare — Incus often reports pool names with
			// mixed case while `zpool list` returns the canonical case.
			bySource[strings.ToLower(root)] = ip
		}
		entries := make([]system.LXDRemoteZFSPoolInfo, 0, len(pools))
		for _, p := range pools {
			entries = append(entries, system.LXDRemoteZFSPoolInfo{
				ZFSPool:        p,
				IncusDatastore: bySource[strings.ToLower(p)],
			})
		}
		jsonOK(w, map[string]interface{}{"pools": entries})
	}
}
