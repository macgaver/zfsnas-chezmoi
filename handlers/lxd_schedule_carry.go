package handlers

// lxd_schedule_carry.go — per-instance schedules follow the instance.
//
// Snapshot and backup schedules are keyed by instance name on the server
// that holds them. Pushing an instance to an InterLink peer copies only the
// instance, and deleting the original afterwards left its schedules behind:
// every interval the old server fired against a ghost ("Failed to fetch
// instance … Instance not found"). Now:
//   - a successful push sends the schedules to the destination
//     (carrySchedulesToPeer → /api/lxd/interlink-import-schedules);
//   - deleting an instance removes its schedules (RemoveLXDInstanceSchedules);
//   - the schedulers drop a schedule whose instance is gone (self-heal for
//     instances removed outside the portal and for existing leftovers).

import (
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"
)

// Seams for tests (Incus and zpool are not available there).
var (
	lxdStatusFn   = func(name string) error { _, err := system.LXDGetStatus(name); return err }
	lxdMissingFn  = system.LXDInstanceMissing
	zpoolExistsFn = system.ZPoolExists
)

// RemoveLXDInstanceSchedules drops the snapshot, backup and compose update
// schedules of an instance. Returns the kinds removed.
func RemoveLXDInstanceSchedules(appCfg *config.AppConfig, name string) []string {
	var removed []string

	snapSchedMu.Lock()
	keptS := appCfg.LXDSnapshotPolicies[:0]
	for _, p := range appCfg.LXDSnapshotPolicies {
		if p.Instance == name {
			removed = append(removed, "snapshot")
			continue
		}
		keptS = append(keptS, p)
	}
	appCfg.LXDSnapshotPolicies = keptS
	snapSchedMu.Unlock()

	backupSchedMu.Lock()
	keptB := appCfg.LXDBackupPolicies[:0]
	for _, p := range appCfg.LXDBackupPolicies {
		if p.Instance == name {
			removed = append(removed, "backup")
			continue
		}
		keptB = append(keptB, p)
	}
	appCfg.LXDBackupPolicies = keptB
	backupSchedMu.Unlock()

	if len(removed) > 0 {
		_ = config.SaveAppConfig(appCfg)
	}
	if RemoveComposeUpdatePolicy(appCfg, name) { // saves on its own
		removed = append(removed, "compose update")
	}
	return removed
}

// lxdInstanceGone confirms with Incus that the instance no longer exists.
// The scheduler error alone is not enough: a stopped or restarting Incus
// daemon fails differently and must never cost the user their schedules.
func lxdInstanceGone(name string, err error) bool {
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "not found") {
		return false
	}
	return lxdMissingFn(name)
}

// dropOrphanSchedules is the scheduler self-heal: called when a scheduled
// run failed because the instance is gone.
func dropOrphanSchedules(appCfg *config.AppConfig, name, who string) {
	removed := RemoveLXDInstanceSchedules(appCfg, name)
	if len(removed) == 0 {
		return
	}
	log.Printf("[%s] %s no longer exists on this server — removed its %s schedule(s)", who, name, strings.Join(removed, " + "))
	audit.Log(audit.Entry{
		User: "system", Role: "system",
		Action: audit.ActionDeleteSchedule, Target: name,
		Result:  audit.ResultOK,
		Details: "auto-removed " + strings.Join(removed, " + ") + " schedule(s): the instance no longer exists on this server (moved or deleted)",
	})
}

// carrySchedulesToPeer sends the source instance's schedules to the server it
// was pushed to, under its destination name. Returns a one-line summary for
// the audit log ("" when the instance had no schedules).
func carrySchedulesToPeer(appCfg *config.AppConfig, ls config.LinkedServer, srcName, destName string) string {
	pl := system.LXDImportSchedulesPayload{Instance: destName}
	pl.SourceHost = system.GetHostname()

	snapSchedMu.Lock()
	for _, p := range appCfg.LXDSnapshotPolicies {
		if p.Instance == srcName {
			cp := p
			pl.Snapshot = &cp
		}
	}
	snapSchedMu.Unlock()
	backupSchedMu.Lock()
	for _, p := range appCfg.LXDBackupPolicies {
		if p.Instance == srcName {
			cp := p
			pl.Backup = &cp
		}
	}
	backupSchedMu.Unlock()
	if pl.Snapshot == nil && pl.Backup == nil {
		return ""
	}
	if b := pl.Backup; b != nil && b.DestKind == "remote" {
		if b.DestServerID == ls.ID {
			pl.BackupDestIsPeer = true
		} else if dst := getLinkedServer(appCfg, b.DestServerID); dst != nil {
			pl.BackupDestURL = dst.URL
		}
	}

	resp, err := system.InterlinkImportSchedules(ls.URL, ls.SharedSecret, ls.TLSFingerprint, pl)
	if err != nil {
		log.Printf("[lxd-push] carry schedules of %s to %s: %v", srcName, ls.Hostname, err)
		return "schedules NOT carried to " + ls.Hostname + ": " + err.Error()
	}
	var parts []string
	if resp.Snapshot != "" {
		parts = append(parts, "snapshot schedule "+resp.Snapshot)
	}
	if resp.Backup != "" {
		parts = append(parts, "backup schedule "+resp.Backup)
	}
	msg := strings.Join(parts, ", ") + " on " + ls.Hostname
	if resp.Note != "" {
		msg += " (" + resp.Note + ")"
	}
	return msg
}

// HandleInterlinkImportSchedules handles POST /api/lxd/interlink-import-schedules
// — HMAC-authenticated. Installs the schedules of an instance a peer just
// pushed here. Backup destinations are re-checked on this side: a local pool
// that does not exist here, an InterLink server this host is not linked to,
// or this very host as the target imports the schedule disabled, with the
// reason in its last error so the Schedules UI shows what to fix.
func HandleInterlinkImportSchedules(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDImportSchedulesRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
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
			expected := system.LXDImportSchedulesHMAC(ls.SharedSecret, req.Timestamp, req.Nonce, req.Payload)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		var pl system.LXDImportSchedulesPayload
		if err := json.Unmarshal(req.Payload, &pl); err != nil || pl.Instance == "" {
			jsonErr(w, http.StatusBadRequest, "invalid payload")
			return
		}
		if err := lxdStatusFn(pl.Instance); err != nil {
			jsonErr(w, http.StatusNotFound, "instance "+pl.Instance+" does not exist on this server")
			return
		}
		from := pl.SourceHost
		if from == "" {
			from = "the source server"
		}
		var out system.LXDImportSchedulesResponse

		if s := pl.Snapshot; s != nil {
			p := *s
			p.Instance = pl.Instance
			p.LastRun, p.LastStatus, p.LastError, p.LastSnap = time.Time{}, "", "", ""
			snapSchedMu.Lock()
			replaced := false
			for i := range appCfg.LXDSnapshotPolicies {
				if appCfg.LXDSnapshotPolicies[i].Instance == p.Instance {
					appCfg.LXDSnapshotPolicies[i] = p
					replaced = true
				}
			}
			if !replaced {
				appCfg.LXDSnapshotPolicies = append(appCfg.LXDSnapshotPolicies, p)
			}
			snapSchedMu.Unlock()
			out.Snapshot = "imported"
		}

		if b := pl.Backup; b != nil {
			p := *b
			p.Instance = pl.Instance
			p.LastRun, p.LastStatus, p.LastError, p.LastBytes = time.Time{}, "", "", 0
			problem := ""
			switch p.DestKind {
			case "local":
				if !zpoolExistsFn(p.DestPool) {
					problem = fmt.Sprintf("its destination pool %q does not exist on this server", p.DestPool)
				}
			case "remote":
				switch {
				case pl.BackupDestIsPeer:
					problem = "it backed up to this server, where the instance now lives"
				default:
					p.DestServerID = ""
					for _, ls := range appCfg.InterLink {
						if pl.BackupDestURL != "" && system.SameInterlinkHost(ls.URL, pl.BackupDestURL) {
							p.DestServerID = ls.ID
							break
						}
					}
					if p.DestServerID == "" {
						problem = "this server is not linked to its destination server"
					}
				}
			}
			if problem != "" && p.Enabled {
				p.Enabled = false
				p.LastStatus = "error"
				p.LastError = "Moved from " + from + " and turned off: " + problem + ". Edit the schedule to pick a destination."
				out.Note = problem
				out.Backup = "imported but turned off"
			} else {
				out.Backup = "imported"
			}
			backupSchedMu.Lock()
			replaced := false
			for i := range appCfg.LXDBackupPolicies {
				if appCfg.LXDBackupPolicies[i].Instance == p.Instance {
					appCfg.LXDBackupPolicies[i] = p
					replaced = true
				}
			}
			if !replaced {
				appCfg.LXDBackupPolicies = append(appCfg.LXDBackupPolicies, p)
			}
			backupSchedMu.Unlock()
		}

		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, "save config: "+err.Error())
			return
		}
		details := []string{}
		if out.Snapshot != "" {
			details = append(details, "snapshot "+out.Snapshot)
		}
		if out.Backup != "" {
			details = append(details, "backup "+out.Backup)
		}
		if out.Note != "" {
			details = append(details, out.Note)
		}
		audit.Log(audit.Entry{
			User: "interlink", Role: "system",
			Action: audit.ActionUpdateSchedule, Target: pl.Instance,
			Result:  audit.ResultOK,
			Details: "schedules received from " + from + ": " + strings.Join(details, "; "),
		})
		jsonOK(w, out)
	}
}
