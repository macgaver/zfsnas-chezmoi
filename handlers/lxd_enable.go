package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"zfsnas/internal/audit"
	"zfsnas/system"
)

var lxdEnableJobs sync.Map // job_id → *system.LXDEnableJob

func newEnableJobID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

// HandleLXDEnablePrereqs returns the four prerequisite check results.
// GET /api/lxd/enable/prereqs
func HandleLXDEnablePrereqs(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, system.LXDEnableCheckPrereqs())
}

// HandleLXDEnableStatus returns whether LXD is currently enabled.
// GET /api/lxd/enable/status
func HandleLXDEnableStatus(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]bool{"enabled": isLXDAvailable()})
}

// HandleLXDEnableStart kicks off the LXD enablement job.
// POST /api/lxd/enable/start   body: {"storage_pool":"tank"}
func HandleLXDEnableStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		StoragePool string `json:"storage_pool"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.StoragePool == "" {
		jsonErr(w, http.StatusBadRequest, "storage_pool required")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	job := system.NewLXDEnableJob(cancel)
	jobID := newEnableJobID()
	lxdEnableJobs.Store(jobID, job)

	go func() {
		system.LXDEnableFeature(ctx, req.StoragePool, job)
		snap := job.Snapshot()
		if snap.Status == "done" {
			v := system.LXDAvailable()
			SetLXDAvailable(v)
			audit.Log(audit.Entry{Action: audit.ActionLXDEnable, User: "system", Details: "VMs & Containers feature enabled on pool " + req.StoragePool})
			// #15: when the non-root service account still can't reach the daemon
			// directly (its incus-admin group membership won't apply until a fresh
			// systemd start re-runs initgroups), restart so the "incus CLI not
			// answering" banner clears without a manual service restart.
			if !v && system.IncusInstalled() {
				system.ScheduleServiceRestartForIncus()
			}
		}
	}()

	w.WriteHeader(http.StatusAccepted)
	jsonOK(w, map[string]string{"job_id": jobID})
}

// HandleLXDEnableNetConfig returns the primary interface's current address /
// gateway / DNS to pre-fill the "Configure Static IP" popup.
// GET /api/lxd/enable/netconfig
func HandleLXDEnableNetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := system.GetEnableNetConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, cfg)
}

// HandleLXDEnableStaticIP pins the primary interface to a static address (the
// values confirmed in the popup) so the netplan→ifupdown migration and the
// vmbr0 bridge inherit a stable IP. Returns the re-evaluated prerequisites so
// the UI can refresh the row without a second GET.
// POST /api/lxd/enable/static-ip  body: {iface, address, gateway, dns:[]}
func HandleLXDEnableStaticIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Iface   string   `json:"iface"`
		Address string   `json:"address"`
		Gateway string   `json:"gateway"`
		DNS     []string `json:"dns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := system.SetEnableStaticIP(req.Iface, req.Address, req.Gateway, req.DNS); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	audit.Log(audit.Entry{Action: audit.ActionLXDEnable, User: "system", Details: "Static IP configured on " + req.Iface + " (" + req.Address + ") for virtualization enable"})
	jsonOK(w, system.LXDEnableCheckPrereqs())
}

// HandleLXDEnableProgress returns the current state of an enable job.
// GET /api/lxd/enable/progress?job_id=<id>
func HandleLXDEnableProgress(w http.ResponseWriter, r *http.Request) {
	jobID := r.URL.Query().Get("job_id")
	v, ok := lxdEnableJobs.Load(jobID)
	if !ok {
		jsonErr(w, http.StatusNotFound, "job not found")
		return
	}
	jsonOK(w, v.(*system.LXDEnableJob).Snapshot())
}

// HandleLXDUninstallCheck returns the deployed-instance counts so the
// UI can decide whether to enable the Uninstall button. CanUninstall is
// true when both counts are zero.
// GET /api/lxd/uninstall/check
func HandleLXDUninstallCheck(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, system.LXDCountInstances())
}

// HandleLXDUninstallStart kicks off an async uninstall job. The pre-flight
// is enforced server-side (regardless of the UI check) so a stale UI can
// never cause data loss. Returns the job ID; progress is polled via
// /api/lxd/enable/progress (same job structure).
// POST /api/lxd/uninstall/start
func HandleLXDUninstallStart(w http.ResponseWriter, r *http.Request) {
	counts := system.LXDCountInstances()
	if !counts.CanUninstall {
		jsonErr(w, http.StatusConflict, fmt.Sprintf(
			"cannot uninstall: %d VM(s) and %d container(s) are still deployed — delete them first",
			counts.VMCount, counts.ContainerCount))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	job := system.NewLXDEnableJob(cancel)
	jobID := newEnableJobID()
	lxdEnableJobs.Store(jobID, job)

	go func() {
		system.LXDUninstallFeature(ctx, job)
		snap := job.Snapshot()
		if snap.Status == "done" {
			// Re-probe so /api/lxd/status flips to "unavailable" without
			// requiring a service restart.
			SetLXDAvailable(system.LXDAvailable())
			audit.Log(audit.Entry{
				Action:  audit.ActionLXDUninstall,
				User:    "system",
				Details: "VMs & Containers feature uninstalled (network bridges + chrony preserved)",
			})
		}
	}()

	w.WriteHeader(http.StatusAccepted)
	jsonOK(w, map[string]string{"job_id": jobID})
}

// HandleLXDEnableCancel cancels a running enable job.
// POST /api/lxd/enable/cancel?job_id=<id>
func HandleLXDEnableCancel(w http.ResponseWriter, r *http.Request) {
	jobID := r.URL.Query().Get("job_id")
	v, ok := lxdEnableJobs.Load(jobID)
	if !ok {
		jsonErr(w, http.StatusNotFound, "job not found")
		return
	}
	v.(*system.LXDEnableJob).Cancel()
	jsonOK(w, map[string]bool{"cancelled": true})
}

// HandleLXDMigrateNetplan runs the netplan→ifupdown migration over a
// WebSocket so the user sees live progress (apt output, generated
// interfaces file, success/rollback verdict). On the closing frame we
// embed the freshly re-evaluated prereq result so the UI doesn't need a
// second GET to refresh the row icons.
//
// WS /ws/incus/enable/migrate-netplan
func HandleLXDMigrateNetplan(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	send := func(line string) {
		conn.WriteMessage(1, mustJSON(map[string]interface{}{"line": line})) //nolint:errcheck
	}
	done := func(success bool, msg string) {
		conn.WriteMessage(1, mustJSON(map[string]interface{}{ //nolint:errcheck
			"done":    true,
			"success": success,
			"message": msg,
			"prereqs": system.LXDEnableCheckPrereqs(),
		}))
	}

	sess := MustSession(r)
	send("Starting netplan → ifupdown migration…")
	send("─────────────────────────────────────────")

	if err := system.MigrateNetplanToIfupdown(send); err != nil {
		send("Error: " + err.Error())
		audit.Log(audit.Entry{
			User: sess.Username, Role: sess.Role,
			Action: audit.ActionNetworkMigrate, Result: audit.ResultError,
			Details: err.Error(),
		})
		done(false, err.Error())
		return
	}

	send("─────────────────────────────────────────")
	send("Migration completed successfully.")
	audit.Log(audit.Entry{
		User: sess.Username, Role: sess.Role,
		Action: audit.ActionNetworkMigrate, Result: audit.ResultOK,
		Details: "from=netplan to=ifupdown",
	})
	done(true, "migration complete")
}
