package handlers

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"net/http"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/pushinterlink"
	"zfsnas/system"

	"github.com/gorilla/mux"
)

// ── HMAC-authenticated LXD cert endpoints (called by peer servers) ─────────────

// HandleLXDInterlinkCert handles POST /api/lxd/interlink-cert — HMAC-authenticated.
// Returns the local lxc client certificate PEM.
func HandleLXDInterlinkCert(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDInterlinkCertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		var matched bool
		for _, ls := range appCfg.InterLink {
			expected := system.LXDInterlinkCertHMAC(ls.SharedSecret, req.Timestamp, req.Nonce)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		// Auto-generate the cert if it doesn't exist yet (servers that had LXD
		// enabled before v6.4.25 won't have it from the enable wizard).
		if err := system.LXDEnsureClientCert(); err != nil {
			jsonErr(w, http.StatusServiceUnavailable, "cannot generate lxc client cert: "+err.Error())
			return
		}
		certPEM, err := system.LXDGetLocalCertPEM()
		if err != nil {
			jsonErr(w, http.StatusServiceUnavailable, "lxc client cert not available: "+err.Error())
			return
		}
		jsonOK(w, system.LXDInterlinkCertResponse{CertPEM: certPEM})
	}
}

// HandleLXDInterlinkTrust handles POST /api/lxd/interlink-trust — HMAC-authenticated.
// Registers the caller's lxc client certificate in the local LXD trust store.
func HandleLXDInterlinkTrust(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDInterlinkTrustRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		var matched bool
		for _, ls := range appCfg.InterLink {
			expected := system.LXDInterlinkTrustHMAC(ls.SharedSecret, req.CertPEM, req.Timestamp, req.Nonce)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		if req.CertPEM == "" || req.PeerID == "" {
			jsonErr(w, http.StatusBadRequest, "cert_pem and peer_id are required")
			return
		}
		if err := system.LXDRegisterPeerCert(req.CertPEM, req.PeerID); err != nil {
			jsonErr(w, http.StatusInternalServerError, "register cert failed: "+err.Error())
			return
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleLXDRemoteStoragePools handles POST /api/lxd/storage-pools-remote — HMAC-authenticated.
// Returns local LXD storage pool names to a peer server.
func HandleLXDRemoteStoragePools(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDStoragePoolsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		var matched bool
		for _, ls := range appCfg.InterLink {
			expected := system.LXDStoragePoolsHMAC(ls.SharedSecret, req.Timestamp, req.Nonce)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		pools, err := system.LXDListStoragePools()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "cannot list storage pools: "+err.Error())
			return
		}
		jsonOK(w, map[string][]string{"pools": pools})
	}
}

// HandleLXDRemoteBridges handles POST /api/lxd/bridges-remote — HMAC-authenticated.
// Returns local LXD bridge network infos to a peer server.
func HandleLXDRemoteBridges(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDBridgesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		var matched bool
		for _, ls := range appCfg.InterLink {
			expected := system.LXDBridgesHMAC(ls.SharedSecret, req.Timestamp, req.Nonce)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		bridges, err := system.LXDListNetworkInfos()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "cannot list bridges: "+err.Error())
			return
		}
		jsonOK(w, map[string]interface{}{"bridges": bridges})
	}
}

// HandleLXDRemoteInstances handles POST /api/lxd/instances-remote — HMAC-authenticated.
// Returns local LXD instance name+description pairs to a peer server for push validation.
func HandleLXDRemoteInstances(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDInstancesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		var matched bool
		for _, ls := range appCfg.InterLink {
			expected := system.LXDInstancesHMAC(ls.SharedSecret, req.Timestamp, req.Nonce)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		instances, err := system.LXDListInstanceSummaries()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "cannot list instances: "+err.Error())
			return
		}
		jsonOK(w, map[string]interface{}{"instances": instances})
	}
}

// ── Session-authenticated endpoints ────────────────────────────────────────────

// HandleLXDInterlinkSyncTrust handles POST /api/lxd/interlink-sync-trust/{server_id} (admin).
// Runs the full bidirectional LXD cert exchange with one linked server.
func HandleLXDInterlinkSyncTrust(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["server_id"]
		var ls *config.LinkedServer
		for i := range appCfg.InterLink {
			if appCfg.InterLink[i].ID == id {
				ls = &appCfg.InterLink[i]
				break
			}
		}
		if ls == nil {
			jsonErr(w, http.StatusNotFound, "linked server not found")
			return
		}
		if err := system.LXDSyncInterlinkTrustForPeer(*ls, ls.ID); err != nil {
			jsonErr(w, http.StatusBadGateway, "sync failed: "+err.Error())
			return
		}
		// Persist the trust state so the warning doesn't reappear after restart.
		ls.LXDTrusted = true
		if err := config.SaveAppConfig(appCfg); err != nil {
			// Non-fatal — trust did succeed, just couldn't persist the flag.
			_ = err
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleLXDInterlinkStatus handles GET /api/lxd/interlink-lxd-status (session auth).
// Returns per-peer LXD trust state from config (set when sync completes successfully).
func HandleLXDInterlinkStatus(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := make(map[string]system.LXDPeerStatus, len(appCfg.InterLink))
		for _, ls := range appCfg.InterLink {
			result[ls.ID] = system.LXDPeerStatus{
				RemoteRegistered: ls.LXDTrusted,
				CertRegistered:   ls.LXDTrusted,
			}
		}
		jsonOK(w, result)
	}
}

// HandleLXDResetNVRAMLocal handles POST /api/lxd/instances/{name}/reset-nvram (admin, session auth).
// Performs a full UEFI boot repair (NVRAM reset + EFI fallback grub.cfg) in the background.
// Fixes "UEFI cannot find a boot target" after cross-version VM migration.
func HandleLXDResetNVRAMLocal(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if name == "" {
		jsonErr(w, http.StatusBadRequest, "instance name required")
		return
	}
	go system.LXDRepairVMBoot(name)
	jsonOK(w, map[string]bool{"ok": true})
}

// HandleLXDGetVMNICs handles GET /api/lxd/instances/{name}/nics (session auth).
// Returns the NIC devices and their bridge parent for a VM.
func HandleLXDGetVMNICs(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	nics, err := system.LXDGetNICsForVM(name)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "cannot get NICs: "+err.Error())
		return
	}
	jsonOK(w, nics)
}

// ── VM push job endpoints ───────────────────────────────────────────────────────

// HandleLXDPushVMStart handles POST /api/lxd/push-interlink/start (admin).
func HandleLXDPushVMStart(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		var req system.LXDPushVMRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.VMName == "" || req.ServerID == "" || req.StoragePool == "" {
			jsonErr(w, http.StatusBadRequest, "vm_name, server_id and storage_pool are required")
			return
		}
		if req.DestName == "" {
			req.DestName = req.VMName
		}

		var ls *config.LinkedServer
		for i := range appCfg.InterLink {
			if appCfg.InterLink[i].ID == req.ServerID {
				ls = &appCfg.InterLink[i]
				break
			}
		}
		if ls == nil {
			jsonErr(w, http.StatusNotFound, "linked server not found")
			return
		}

		username := sess.Username
		role := sess.Role
		lsCopy := *ls

		ctx, cancel := context.WithCancel(context.Background())
		job := pushinterlink.Default.Register(
			"vm:"+req.VMName, req.DestName, ls.Hostname, username, cancel)

		go func() {
			system.LXDPushVM(ctx, req, job, lsCopy)

			result, details := audit.ResultOK, ""
			j := pushinterlink.Default.List()
			for _, jj := range j {
				if jj.ID == job.ID {
					if jj.ErrorMsg != "" {
						result = audit.ResultError
						details = jj.ErrorMsg
					}
					break
				}
			}
			// The instance's snapshot/backup schedules move with it.
			if result == audit.ResultOK && ctx.Err() == nil {
				details = carrySchedulesToPeer(appCfg, lsCopy, req.VMName, system.SanitizeLXDName(req.DestName))
			}
			audit.Log(audit.Entry{
				User:    username,
				Role:    role,
				Action:  audit.ActionPushInterlink,
				Target:  req.VMName + " → " + ls.Hostname,
				Result:  result,
				Details: details,
			})
		}()

		jsonOK(w, map[string]interface{}{
			"job_id": job.ID,
			"ok":     true,
		})
	}
}

// HandleLXDVMNVRAMReset handles POST /api/lxd/vm-nvram-reset — HMAC-authenticated.
// Performs a full UEFI boot repair: NVRAM reset + EFI fallback grub.cfg installation.
// Responds immediately (200) and runs the repair in a background goroutine because
// the ZVol mount step can take several seconds.
func HandleLXDVMNVRAMReset(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDNVRAMResetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		var matched bool
		for _, ls := range appCfg.InterLink {
			expected := system.LXDNVRAMResetHMAC(ls.SharedSecret, req.VMName, req.Timestamp, req.Nonce)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		if req.VMName == "" {
			jsonErr(w, http.StatusBadRequest, "vm_name is required")
			return
		}
		go system.LXDRepairVMBoot(req.VMName)
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleLXDVMTPMClear handles POST /api/lxd/vm-tpm-clear — HMAC-authenticated.
// Deletes the swtpm persistent state for a VM so the TPM initialises fresh on
// next boot. Required after a cross-host push (source TPM state is bound to the
// source OVMF session and causes QEMU to crash on the destination).
func HandleLXDVMTPMClear(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.LXDTPMClearRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		var matched bool
		for _, ls := range appCfg.InterLink {
			expected := system.LXDTPMClearHMAC(ls.SharedSecret, req.VMName, req.Timestamp, req.Nonce)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		if req.VMName == "" {
			jsonErr(w, http.StatusBadRequest, "vm_name is required")
			return
		}
		system.LXDClearTPMState(req.VMName) //nolint:errcheck
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleLXDPushVMCancel handles POST /api/lxd/push-interlink/cancel/{id} (admin).
func HandleLXDPushVMCancel(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_, ok := pushinterlink.Default.ForceCancel(id)
	if !ok {
		jsonErr(w, http.StatusNotFound, "job not found or already finished")
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}
