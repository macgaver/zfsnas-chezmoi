package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/scheduler"
	"zfsnas/system"

	"github.com/gorilla/mux"
)

// policyWithNext is the API response shape — policy + computed next_run.
type policyWithNext struct {
	scheduler.Policy
	NextRun time.Time `json:"next_run,omitempty"`
}

// HandleListSchedules returns all snapshot policies with their next run time.
func HandleListSchedules(w http.ResponseWriter, r *http.Request) {
	policies, err := scheduler.LoadPolicies()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now()
	result := make([]policyWithNext, len(policies))
	for i, p := range policies {
		result[i] = policyWithNext{Policy: p, NextRun: scheduler.NextRun(p, now)}
	}
	jsonOK(w, result)
}

// HandleCreateSchedule creates a new snapshot policy.
func HandleCreateSchedule(w http.ResponseWriter, r *http.Request) {
	var p scheduler.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if p.Dataset == "" {
		jsonErr(w, http.StatusBadRequest, "dataset is required")
		return
	}
	if p.Frequency == "" {
		p.Frequency = "daily"
	}
	if p.Retention < 1 {
		p.Retention = 7
	}
	if p.Label == "" {
		p.Label = "auto"
	}
	p.ID = newID()

	policies, err := scheduler.LoadPolicies()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	policies = append(policies, p)
	if err := scheduler.SavePolicies(policies); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionCreateSchedule,
		Target:  p.Dataset,
		Result:  audit.ResultOK,
		Details: fmt.Sprintf("%s, retain %d", p.Frequency, p.Retention),
	})
	jsonCreated(w, p)
}

// HandleUpdateSchedule replaces a snapshot policy by ID.
func HandleUpdateSchedule(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var p scheduler.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p.ID = id
	if p.Retention < 1 {
		p.Retention = 1
	}
	if p.Label == "" {
		p.Label = "auto"
	}

	policies, err := scheduler.LoadPolicies()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	found := false
	for i, existing := range policies {
		if existing.ID == id {
			// Preserve all runtime state — only config fields come from the request.
			p.LastRun = existing.LastRun
			p.LastStatus = existing.LastStatus
			p.LastError = existing.LastError
			p.LastDetails = existing.LastDetails
			p.LastRepStatus = existing.LastRepStatus
			p.LastRepError = existing.LastRepError
			p.LastRepLog = existing.LastRepLog
			p.LastRepSnap = existing.LastRepSnap
			p.LastLocalReplStatus = existing.LastLocalReplStatus
			p.LastLocalReplError = existing.LastLocalReplError
			p.LastLocalReplSnap = existing.LastLocalReplSnap
			policies[i] = p
			found = true
			break
		}
	}
	if !found {
		jsonErr(w, http.StatusNotFound, "schedule not found")
		return
	}
	if err := scheduler.SavePolicies(policies); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionUpdateSchedule,
		Target: p.Dataset,
		Result: audit.ResultOK,
	})
	jsonOK(w, p)
}

// HandleDeleteSchedule removes a snapshot policy by ID.
func HandleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	policies, err := scheduler.LoadPolicies()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	newPolicies := policies[:0]
	var target string
	for _, p := range policies {
		if p.ID == id {
			target = p.Dataset
			continue
		}
		newPolicies = append(newPolicies, p)
	}
	if target == "" {
		jsonErr(w, http.StatusNotFound, "schedule not found")
		return
	}
	if err := scheduler.SavePolicies(newPolicies); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionDeleteSchedule,
		Target: target,
		Result: audit.ResultOK,
	})
	jsonOK(w, map[string]string{"message": "schedule deleted"})
}

// HandleRunScheduleNow manually triggers a snapshot policy immediately.
func HandleRunScheduleNow(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		policies, err := scheduler.LoadPolicies()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		idx := -1
		for i := range policies {
			if policies[i].ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			jsonErr(w, http.StatusNotFound, "schedule not found")
			return
		}
		if err := execScheduledSnapshot(&policies[idx], appCfg); err != nil {
			_ = scheduler.SavePolicies(policies)
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = scheduler.SavePolicies(policies)
		jsonOK(w, map[string]string{"message": "snapshot created"})
	}
}

// StartScheduler launches a background goroutine that fires due policies every minute.
func StartScheduler(appCfg *config.AppConfig) {
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for now := range tick.C {
			tickPolicies(now, appCfg)
		}
	}()
}

func tickPolicies(now time.Time, appCfg *config.AppConfig) {
	policies, err := scheduler.LoadPolicies()
	if err != nil {
		log.Printf("[scheduler] load error: %v", err)
		return
	}
	changed := false
	for i := range policies {
		p := &policies[i]
		if !p.Enabled || !scheduler.IsDue(*p, now) {
			continue
		}
		if err := execScheduledSnapshot(p, appCfg); err != nil {
			log.Printf("[scheduler] policy %s (%s) failed: %v", p.ID, p.Dataset, err)
		}
		changed = true
	}
	if changed {
		_ = scheduler.SavePolicies(policies)
	}
}

func execScheduledSnapshot(p *scheduler.Policy, appCfg *config.AppConfig) error {
	label := p.Label
	if label == "" {
		label = "auto"
	}
	name, err := system.CreateSnapshot(p.Dataset, label)
	p.LastRun = time.Now()
	if err != nil {
		p.LastStatus = "error"
		p.LastError = err.Error()
		audit.Log(audit.Entry{
			Action:  audit.ActionCreateSnapshot,
			Target:  p.Dataset,
			Result:  audit.ResultError,
			Details: fmt.Sprintf("scheduler %s: %v", p.ID, err),
		})
		go alerts.Send(
			alerts.EventSnapshotFailure,
			"Snapshot failed: "+p.Dataset,
			"Scheduled Snapshot Failed",
			fmt.Sprintf("Scheduled snapshot for dataset '%s' (policy %s) failed: %v", p.Dataset, p.ID, err),
		)
		return err
	}
	p.LastStatus = "ok"
	p.LastError = ""
	p.LastDetails = "Snapshot: " + name
	audit.Log(audit.Entry{
		Action:  audit.ActionCreateSnapshot,
		Target:  name,
		Result:  audit.ResultOK,
		Details: fmt.Sprintf("scheduled policy %s", p.ID),
	})
	if p.Retention > 0 {
		pruneSnapshots(p.Dataset, label, p.Retention)
	}

	// Run local replication if configured for this policy.
	if p.LocalReplEnabled && p.LocalReplDataset != "" {
		var localLogBuf strings.Builder
		var afterSep bool
		collectLocal := func(line string) {
			log.Printf("[local-replication] %s: %s", p.ID, line)
			if strings.Contains(line, "─────") {
				afterSep = true
				return
			}
			if afterSep {
				localLogBuf.WriteString(line)
				localLogBuf.WriteByte('\n')
			}
		}
		if localSnap, localErr := system.RunLocalReplication(p.Dataset, name, p.LocalReplDataset, p.LastLocalReplSnap, p.LocalReplRecursive, p.LocalReplCompressed, collectLocal); localErr != nil {
			log.Printf("[local-replication] policy %s failed: %v", p.ID, localErr)
			p.LastDetails = "Snapshot ok · Local replication failed: " + localErr.Error()
			p.LastLocalReplStatus = "error"
			p.LastLocalReplError = localErr.Error()
			audit.Log(audit.Entry{
				Action:  audit.ActionRunReplication,
				Target:  p.Dataset,
				Result:  audit.ResultError,
				Details: fmt.Sprintf("→ %s (local): %s", p.LocalReplDataset, localErr.Error()),
			})
			go alerts.Send(
				alerts.EventReplicationFailure,
				"Replication failed: "+p.Dataset,
				"Scheduled Local Replication Failed",
				fmt.Sprintf("Local replication for dataset '%s' → '%s' (policy %s) failed: %v", p.Dataset, p.LocalReplDataset, p.ID, localErr),
			)
		} else {
			p.LastDetails = "Snapshot: " + name + " · Local replication: ok"
			p.LastLocalReplStatus = "ok"
			p.LastLocalReplError = ""
			p.LastLocalReplSnap = localSnap
			audit.Log(audit.Entry{
				Action:  audit.ActionRunReplication,
				Target:  p.Dataset,
				Result:  audit.ResultOK,
				Details: fmt.Sprintf("→ %s (local)", p.LocalReplDataset),
			})
		}
	}

	// Run remote replication if configured for this policy.
	if p.ReplicationEnabled && p.ReplicationHost != "" && p.ReplicationDataset != "" {
		// If the remote host belongs to a linked InterLink server, set up SSH keys and
		// ZFS permissions just like Push InterLink does before every transfer.
		if ls := findLinkedServerByHost(appCfg, p.ReplicationHost); ls != nil {
			if pubKey, keyErr := system.EnsureSSHKey(); keyErr == nil {
				if err := system.SendPushSSHKey(ls.URL, ls.SharedSecret, pubKey, ls.TLSFingerprint); err != nil {
					log.Printf("[replication] policy %s: push SSH key to IL server: %v", p.ID, err)
				}
			}
			if err := system.GrantLocalZFSAccess(); err != nil {
				log.Printf("[replication] policy %s: local zfs allow: %v", p.ID, err)
			}
			if err := system.EnsureRemoteZFSAccess(ls.URL, ls.SharedSecret, ls.TLSFingerprint); err != nil {
				log.Printf("[replication] policy %s: remote zfs allow: %v", p.ID, err)
			}
		}
		task := &config.ReplicationTask{
			ID:            p.ID + "-rep",
			Name:          p.Dataset + " → " + p.ReplicationHost,
			SourceDataset: p.Dataset,
			RemoteHost:    p.ReplicationHost,
			RemoteUser:    p.ReplicationUser,
			RemoteDataset: p.ReplicationDataset,
			Recursive:     p.ReplicationRecursive,
			Compressed:    p.ReplicationCompressed,
			LastSnap:      p.LastRepSnap, // enables incremental send on subsequent runs
		}
		var repLogBuf strings.Builder
		var afterSep bool
		collectLine := func(line string) {
			log.Printf("[replication] %s: %s", p.ID, line)
			if strings.Contains(line, "─────") {
				afterSep = true
				return
			}
			if afterSep {
				repLogBuf.WriteString(line)
				repLogBuf.WriteByte('\n')
			}
		}
		if repSnap, repErr := system.RunReplication(task, collectLine, name); repErr != nil {
			log.Printf("[replication] policy %s replication failed: %v", p.ID, repErr)
			p.LastDetails = "Snapshot ok · Replication failed: " + repErr.Error()
			p.LastRepStatus = "error"
			p.LastRepError = repErr.Error()
			p.LastRepLog = repLogBuf.String()
			p.LastRepSnap = "" // reset so next run does a full send instead of retrying a stale base
			audit.Log(audit.Entry{
				Action:  audit.ActionRunReplication,
				Target:  p.Dataset,
				Result:  audit.ResultError,
				Details: fmt.Sprintf("→ %s: %s", p.ReplicationHost, repErr.Error()),
			})
			go alerts.Send(
				alerts.EventReplicationFailure,
				"Replication failed: "+p.Dataset,
				"Scheduled Remote Replication Failed",
				fmt.Sprintf("Remote replication for dataset '%s' → %s:%s (policy %s) failed: %v", p.Dataset, p.ReplicationHost, p.ReplicationDataset, p.ID, repErr),
			)
		} else {
			p.LastDetails = "Snapshot: " + name + " · Replication: ok"
			p.LastRepStatus = "ok"
			p.LastRepError = ""
			p.LastRepLog = repLogBuf.String()
			p.LastRepSnap = repSnap // persist for incremental send next time
			audit.Log(audit.Entry{
				Action:  audit.ActionRunReplication,
				Target:  p.Dataset,
				Result:  audit.ResultOK,
				Details: fmt.Sprintf("→ %s", p.ReplicationHost),
			})
		}
	}

	return nil
}

func pruneSnapshots(dataset, labelPrefix string, keep int) {
	snaps, err := system.ListSnapshots(dataset)
	if err != nil {
		return
	}
	var ours []system.Snapshot
	for _, s := range snaps {
		if s.Dataset == dataset &&
			(strings.HasPrefix(s.SnapName, labelPrefix+"-") || s.SnapName == labelPrefix) {
			ours = append(ours, s)
		}
	}
	if len(ours) <= keep {
		return
	}
	sort.Slice(ours, func(i, j int) bool {
		return ours[i].Creation.Before(ours[j].Creation)
	})
	for _, s := range ours[:len(ours)-keep] {
		if err := system.DestroySnapshot(s.Name); err != nil {
			log.Printf("[scheduler] prune %s: %v", s.Name, err)
		}
	}
}

// findLinkedServerByHost returns the LinkedServer whose URL hostname matches host,
// or nil if none match. Used to detect IL-backed replication targets at runtime.
func findLinkedServerByHost(appCfg *config.AppConfig, host string) *config.LinkedServer {
	if appCfg == nil || host == "" {
		return nil
	}
	for i := range appCfg.InterLink {
		ls := &appCfg.InterLink[i]
		if parsed, err := url.Parse(ls.URL); err == nil && parsed.Hostname() == host {
			return ls
		}
	}
	return nil
}
