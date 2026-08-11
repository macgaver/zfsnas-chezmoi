package handlers

// jobboard.go — the fleet-wide view of every background job.
//
// Rule: a background job is visible from EVERY web session and every interlink
// server, never only the tab that started it. See system/jobboard.go for why a
// single board beats a list+aggregate endpoint per job type.
//
// This file holds the providers for the registries that live in package
// handlers, plus the two endpoints every session polls.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/config"
	"zfsnas/system"
)

func init() {
	// Keys below must match the activity-bar keys the per-type pollers already
	// use ("bkj-", "brj-", "dmv-", "pool-create"), so a session that started the
	// job keeps its own row instead of gaining a duplicate from discovery.

	system.RegisterJobProvider("lxd-backup", func() []system.JobSummary {
		out := []system.JobSummary{}
		lxdBackupJobs.Range(func(k, v interface{}) bool {
			id, _ := k.(string)
			j, ok := v.(*lxdBackupJob)
			if !ok {
				return true
			}
			j.mu.Lock()
			defer j.mu.Unlock()
			dest := j.DestPool
			if j.DestKind == "remote" && j.DestHost != "" {
				dest = j.DestHost + ":" + j.DestPool
			}
			base := "/api/incus/backup-jobs/" + id
			out = append(out, system.JobSummary{
				Key: "bkj-" + id, ID: id, Kind: "backup",
				Label:       "Backup " + j.Instance + " → " + dest,
				Status:      j.Status,
				Progress:    float64(j.Progress),
				StartedAt:   j.StartedAt,
				ProgressURL: base + "/progress",
				CancelURL:   base + "/cancel",
				LocalOnly:   true, // backup/restore are local-origin (#7)
			})
			return true
		})
		return out
	})

	system.RegisterJobProvider("lxd-restore", func() []system.JobSummary {
		out := []system.JobSummary{}
		lxdRestoreJobs.Range(func(k, v interface{}) bool {
			id, _ := k.(string)
			j, ok := v.(*lxdRestoreJob)
			if !ok {
				return true
			}
			j.mu.Lock()
			defer j.mu.Unlock()
			base := "/api/incus/restore-jobs/" + id
			out = append(out, system.JobSummary{
				Key: "brj-" + id, ID: id, Kind: "restore",
				Label:       "Restore " + j.VMID + " → " + j.CloneName,
				Status:      j.Status,
				Progress:    float64(j.Progress),
				StartedAt:   j.StartedAt,
				ProgressURL: base + "/progress",
				CancelURL:   base + "/cancel",
				LocalOnly:   true,
			})
			return true
		})
		return out
	})

	system.RegisterJobProvider("lxd-disk-move", func() []system.JobSummary {
		out := []system.JobSummary{}
		dmvJobs.Range(func(k, v interface{}) bool {
			id, _ := k.(string)
			j, ok := v.(*dmvJob)
			if !ok {
				return true
			}
			j.mu.Lock()
			defer j.mu.Unlock()
			// This one is keyed by instance AND job id in its URLs.
			base := "/api/incus/instances/" + j.Instance + "/disk-move"
			q := "?job_id=" + id
			out = append(out, system.JobSummary{
				Key: "dmv-" + id, ID: id, Kind: "disk-move",
				Label:       "Moving disk " + j.DiskName + " (" + j.Instance + ") → " + j.Target,
				Status:      j.Status,
				ProgressURL: base + "/progress" + q,
				CancelURL:   base + "/cancel" + q,
				LocalOnly:   true,
			})
			return true
		})
		return out
	})

	system.RegisterJobProvider("pool-create", func() []system.JobSummary {
		out := []system.JobSummary{}
		poolCreateJobs.Range(func(k, v interface{}) bool {
			id, _ := k.(string)
			j, ok := v.(*poolCreateJob)
			if !ok {
				return true
			}
			j.mu.Lock()
			defer j.mu.Unlock()
			name := "ZFS pool"
			if j.Pool != nil && j.Pool.Name != "" {
				name = j.Pool.Name
			}
			out = append(out, system.JobSummary{
				// The client tracks pool creation under this fixed key.
				Key: "pool-create", ID: id, Kind: "pool-create",
				Label:       "Creating " + name + "…",
				Status:      j.Status,
				ProgressURL: "/api/pool/create-status?id=" + id,
				LocalOnly:   true, // a pool exists only on the host creating it
			})
			return true
		})
		return out
	})
}

// HandleJobs — GET /api/jobs
// Every background job this server knows about, in one uniform shape.
func HandleJobs(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, localJobSummaries())
}

func localJobSummaries() []system.JobSummary {
	hostname, _ := os.Hostname()
	jobs := system.AllJobs()
	for i := range jobs {
		if jobs[i].System == "" {
			jobs[i].System = hostname
		}
	}
	return jobs
}

// HandleJobsAggregate — GET /api/jobs/aggregate
// This server's jobs merged with every interlink peer's, each stamped with the
// originating hostname. One fan-out covers every job type, so a session sees
// the whole fleet's running work without N round-trips per job type.
func HandleJobsAggregate(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all := localJobSummaries()
		var (
			mu sync.Mutex
			wg sync.WaitGroup
		)
		for i := range appCfg.InterLink {
			ls := appCfg.InterLink[i]
			if ls.URL == "" || ls.LinkedBy == "" {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				remote, err := fetchPeerJobs(ls)
				if err != nil {
					return
				}
				for j := range remote {
					if remote[j].System == "" {
						remote[j].System = ls.Hostname
					}
				}
				mu.Lock()
				all = append(all, remote...)
				mu.Unlock()
			}()
		}
		wg.Wait()
		jsonOK(w, all)
	}
}

// fetchPeerJobs dials a peer's /api/jobs with the standard X-Interlink-Relay-*
// HMAC headers (same pattern as fetchPeerRsyncJobs).
func fetchPeerJobs(ls config.LinkedServer) ([]system.JobSummary, error) {
	ts := time.Now().Unix()
	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonceHex := hex.EncodeToString(nonceBytes)
	sig := system.RelayForwardHMAC(ls.SharedSecret, ls.LinkedBy, ts, nonceHex)

	req, err := http.NewRequest("GET", strings.TrimRight(ls.URL, "/")+"/api/jobs", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Interlink-Relay-User", ls.LinkedBy)
	req.Header.Set("X-Interlink-Relay-TS", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Interlink-Relay-Nonce", nonceHex)
	req.Header.Set("X-Interlink-Relay-HMAC", sig)

	client := system.InterlinkClientForRelay(ls.TLSFingerprint)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var out []system.JobSummary
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
