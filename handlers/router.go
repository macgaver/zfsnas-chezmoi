package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"zfsnas/internal/config"

	"github.com/gorilla/mux"
)

// serveSPAHTML writes the single-page-app HTML with a revalidation policy so a
// freshly deployed binary is never masked by a stale browser cache. The SPA is
// served with no cache headers historically, which let browsers heuristically
// cache it — so after every binary update users kept seeing the OLD UI until a
// manual hard-refresh. `Cache-Control: no-cache` forces the browser to
// revalidate on each load; a content ETag lets that revalidation return 304
// when nothing changed, so we don't re-ship the ~2.8 MB document needlessly.
func serveSPAHTML(w http.ResponseWriter, req *http.Request, data []byte) {
	sum := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", etag)
	if req.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(data) //nolint:errcheck
}

// incusPathAliases maps every Incus-canonical URL prefix to the legacy LXD
// prefix that the route table actually mounts. Set in v6.5.2 so the canonical
// API surface is /api/incus/* (and /ws/incus-*, /incus-console/*) while the
// /api/lxd/* form keeps working unchanged. Removed in 6.5.5 — external
// scripts hitting /api/lxd/* should switch to /api/incus/* by then.
//
// We rewrite Incus → LXD (not the other way) because the route table still
// uses /api/lxd/* internally; flipping the table would touch ~85 routes for
// no behavioural gain. This is purely an alias layer.
var incusPathAliases = map[string]string{
	"/api/incus/":         "/api/lxd/",
	"/ws/incus-console":   "/ws/lxd-console",
	"/ws/incus-vga":       "/ws/lxd-vga",
	"/incus-console/":     "/lxd-console/",
	"/incus-vga-console/": "/lxd-vga-console/",
}

// IncusPathAliasMiddleware rewrites Incus-canonical URLs (/api/incus/*) to the
// legacy LXD-prefixed routes the router actually mounts. The router sees the
// LXD path; the client sees the Incus path. WebSocket upgrades continue to
// work because the rewrite happens before mux dispatch.
//
// Deprecation telemetry: requests that arrive on the legacy /api/lxd/* form
// log a one-line warning. Browsers running an older static bundle (before the
// frontend was refreshed to /api/incus/*) will trigger these on every page
// load — that's expected and harmless. The warning is a sweep tool, not a
// blocker.
func IncusPathAliasMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for incusPrefix, lxdPrefix := range incusPathAliases {
			if strings.HasPrefix(path, incusPrefix) {
				r.URL.Path = lxdPrefix + path[len(incusPrefix):]
				break
			}
		}
		// Soft-deprecation warning: hits on the legacy /api/lxd/* form after
		// the canonical name became /api/incus/* in v6.5.2. The frontend
		// shipped in this release uses the canonical paths, so warnings here
		// indicate a stale browser cache or an external API consumer.
		if strings.HasPrefix(path, "/api/lxd/") {
			log.Printf("WARNING: deprecated /api/lxd/* path %q — switch to /api/incus/* (will be removed in 6.5.5)", path)
		}
		next.ServeHTTP(w, r)
	})
}

// NewRouter builds and returns the application router.
// staticFS is the embedded (or disk) filesystem rooted at the static/ directory.
// readFile is a helper to read a named file from staticFS (e.g. "index.html").
// appCfg is a pointer to the loaded application config (for settings handlers).
func NewRouter(staticFS fs.FS, readFile func(string) ([]byte, error), appCfg *config.AppConfig) http.Handler {
	r := mux.NewRouter()
	r.Use(SecurityHeaders)
	r.Use(EnforceOrigin)
	// RelayAuthMiddleware runs early (Server B): validates relay headers and injects
	// a synthetic session so RequireAuth works without a browser cookie.
	r.Use(func(next http.Handler) http.Handler { return RelayAuthMiddleware(appCfg, next) })
	// Gzip text responses (the ~1.5 MB SPA, CSS, API JSON) for clients that
	// accept it — the main win for the portal over a slow remote VPN.
	r.Use(GzipResponses)

	// --- Static assets ---
	r.PathPrefix("/static/").Handler(
		http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))),
	)

	// --- iOS / PWA home-screen icon (no auth needed — iOS fetches before login) ---
	r.HandleFunc("/apple-touch-icon.png", HandleAppleTouchIcon(readFile)).Methods("GET")
	r.HandleFunc("/apple-touch-icon-precomposed.png", HandleAppleTouchIcon(readFile)).Methods("GET")

	// --- Pre-auth pages ---
	r.HandleFunc("/setup", HandleSetupPage(readFile)).Methods("GET")
	r.HandleFunc("/login", HandleLoginPage(readFile, appCfg)).Methods("GET")

	// --- Root: serve SPA (requires auth, redirects to /login otherwise) ---
	r.Handle("/", RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		data, err := readFile("index.html")
		if err != nil {
			http.Error(w, "app not found", http.StatusInternalServerError)
			return
		}
		serveSPAHTML(w, req, data)
	}))).Methods("GET")

	// --- Auth API ---
	r.HandleFunc("/api/auth/setup", HandleSetup).Methods("POST")
	r.HandleFunc("/api/auth/login", HandleLogin(appCfg)).Methods("POST")
	r.HandleFunc("/api/auth/totp", HandleTOTPLogin(appCfg)).Methods("POST")
	r.HandleFunc("/api/auth/logout", HandleLogout).Methods("POST")
	r.Handle("/api/auth/me", RequireAuth(http.HandlerFunc(HandleMe))).Methods("GET")
	r.Handle("/api/prefs", RequireAuth(http.HandlerFunc(HandleUpdatePrefs))).Methods("PUT")

	// --- TOTP setup (own account) ---
	r.Handle("/api/auth/totp/setup",
		RequireAuth(http.HandlerFunc(HandleTOTPSetup))).Methods("POST")
	r.Handle("/api/auth/totp/confirm",
		RequireAuth(http.HandlerFunc(HandleTOTPConfirm))).Methods("POST")

	// Sessions (admin only)
	r.Handle("/api/auth/sessions",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleListSessions)))).Methods("GET")
	r.Handle("/api/auth/sessions/{token}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleKillSession)))).Methods("DELETE")

	// --- Users (admin only) ---
	r.Handle("/api/users",
		RequireAuth(http.HandlerFunc(HandleListUsers))).Methods("GET")
	r.Handle("/api/users",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateUser)))).Methods("POST")
	r.Handle("/api/users/{id}",
		RequireAuth(http.HandlerFunc(HandleUpdateUser))).Methods("PUT")
	r.Handle("/api/users/{id}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteUser)))).Methods("DELETE")
	r.Handle("/api/users/{id}/totp",
		RequireAuth(http.HandlerFunc(HandleDisableTOTP))).Methods("DELETE")

	// --- Audit log ---
	r.Handle("/api/audit",
		RequireAuth(http.HandlerFunc(HandleAuditLog))).Methods("GET")
	r.Handle("/api/audit/by-target",
		RequireAuth(http.HandlerFunc(HandleAuditByTarget))).Methods("GET")
	// Multi-host aggregate (v6.4.28): merges local + every InterLink peer.
	r.Handle("/api/audit/aggregate",
		RequireAuth(HandleAuditAggregate(appCfg))).Methods("GET")
	// HMAC-authenticated peer endpoint — invoked by other ZNAS servers
	// when they aggregate; not for browser use.
	r.HandleFunc("/api/audit/peer-list", HandleAuditPeerList(appCfg)).Methods("POST")

	// --- System journal viewer (Activity & Events > journal tabs) -----------
	// Availability probe is auth-only (returns available=false for non-admins);
	// the log read itself is admin-only since system logs are sensitive.
	r.Handle("/api/journal/available",
		RequireAuth(http.HandlerFunc(HandleJournalAvailable))).Methods("GET")
	r.Handle("/api/journal",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleJournal)))).Methods("GET")

	// --- Live alerts (server-side mirror of the browser's registry, for
	//     interlink aggregation across servers in relay mode) ---
	r.Handle("/api/live-alerts",
		RequireAuth(HandleLiveAlerts(appCfg))).Methods("GET")
	r.Handle("/api/live-alerts/aggregate",
		RequireAuth(HandleLiveAlertsAggregate(appCfg))).Methods("GET")

	// --- Pool ---
	r.Handle("/api/pools",
		RequireAuth(http.HandlerFunc(HandleGetPools))).Methods("GET")
	r.Handle("/api/pool",
		RequireAuth(http.HandlerFunc(HandleGetPool))).Methods("GET")
	r.Handle("/api/pool",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleCreatePool)))).Methods("POST")
	r.Handle("/api/pool/create-status",
		RequireAuth(http.HandlerFunc(HandlePoolCreateStatus))).Methods("GET")
	r.Handle("/api/pool/detect",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleDetectPools)))).Methods("GET")
	r.Handle("/api/pool/import",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleImportPool)))).Methods("POST")
	r.Handle("/api/pool/status",
		RequireAuth(http.HandlerFunc(HandlePoolStatus))).Methods("GET")
	r.Handle("/api/pool/zfs-version",
		RequireAuth(http.HandlerFunc(HandleGetZFSVersion))).Methods("GET")
	r.Handle("/api/pool/grow",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleGrowPool)))).Methods("POST")
	r.Handle("/api/pool/export",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleExportPool)))).Methods("POST")
	r.Handle("/api/pool/destroy",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleDestroyPool)))).Methods("POST")
	r.Handle("/api/pool/upgrade",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleUpgradePool)))).Methods("POST")
	r.Handle("/api/pool/cache",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleAddPoolCache)))).Methods("POST")
	r.Handle("/api/pool/cache",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleRemovePoolCache)))).Methods("DELETE")
	r.Handle("/api/pool/spare",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleAddPoolSpare)))).Methods("POST")
	r.Handle("/api/pool/spare",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleRemovePoolSpare)))).Methods("DELETE")
	r.Handle("/api/pool/attach-disk",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleAttachPoolDisk)))).Methods("POST")
	r.Handle("/api/pool/detach-disk",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleDetachPoolDisk)))).Methods("POST")
	r.Handle("/api/pool/replace-disk",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleReplacePoolDisk)))).Methods("POST")
	r.Handle("/api/pool/clear",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleClearPool)))).Methods("POST")
	r.Handle("/api/pool/fixer/online",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandlePoolFixerOnline)))).Methods("POST")
	r.Handle("/api/pool/fixer/replace",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandlePoolFixerReplace)))).Methods("POST")
	r.Handle("/api/pool/disk/offline",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleDiskOffline)))).Methods("POST")
	r.Handle("/api/pool/disk/online",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleDiskOnline)))).Methods("POST")
	r.Handle("/api/pool/settings",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleSetPoolProperties)))).Methods("PUT")
	r.Handle("/api/pool/load-key",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleLoadPoolKey)))).Methods("POST")
	r.Handle("/api/pool/unload-key",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleUnloadPoolKey)))).Methods("POST")
	r.Handle("/api/pool/arc",
		RequireAuth(http.HandlerFunc(HandleGetARC))).Methods("GET")
	r.Handle("/api/pool/arc",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleSetARC)))).Methods("PUT")

	// --- Encryption key management (admin only) ---
	r.Handle("/api/encryption/keys",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleListKeys)))).Methods("GET")
	r.Handle("/api/encryption/keys",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleGenerateKey)))).Methods("POST")
	r.Handle("/api/encryption/keys/import",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleImportKey)))).Methods("POST")
	r.Handle("/api/encryption/keys/usage",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleKeyUsage)))).Methods("GET")
	r.Handle("/api/encryption/keys/{id}/export",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleExportKey)))).Methods("GET")
	r.Handle("/api/encryption/keys/{id}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteKey)))).Methods("DELETE")

	// --- ZVols ---
	r.Handle("/api/zvols",
		RequireAuth(http.HandlerFunc(HandleListZVols))).Methods("GET")
	r.Handle("/api/zvol/create",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleCreateZVol)))).Methods("POST")
	r.Handle("/api/zvol/edit",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleEditZVol)))).Methods("POST")
	r.Handle("/api/zvol/delete",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleDeleteZVol)))).Methods("POST")

	// --- Datasets ---
	r.Handle("/api/datasets",
		RequireAuth(http.HandlerFunc(HandleListDatasets))).Methods("GET")
	r.Handle("/api/datasets",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleCreateDataset)))).Methods("POST")
	r.Handle("/api/datasets/rename",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleRenameDataset)))).Methods("POST")
	r.Handle("/api/datasets/{path:.+}/load-key",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleLoadDatasetKey)))).Methods("POST")
	r.Handle("/api/datasets/{path:.+}/unload-key",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleUnloadDatasetKey)))).Methods("POST")
	r.Handle("/api/datasets/{path:.+}/unlock-passphrase",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleUnlockDatasetPassphrase)))).Methods("POST")
	r.Handle("/api/datasets/{path:.+}/key-info",
		RequireAuth(http.HandlerFunc(HandleGetDatasetKeyInfo))).Methods("GET")
	r.Handle("/api/datasets/{path:.+}/key-source",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleSetDatasetKeySource)))).Methods("PUT")
	r.Handle("/api/datasets/{path:.+}",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleUpdateDataset)))).Methods("PUT")
	r.Handle("/api/datasets/{path:.+}",
		RequireAuth(RequirePermission("manage_pool_dataset")(http.HandlerFunc(HandleDeleteDataset)))).Methods("DELETE")

	// --- Snapshots ---
	r.Handle("/api/snapshots",
		RequireAuth(http.HandlerFunc(HandleListSnapshots))).Methods("GET")
	r.Handle("/api/snapshots",
		RequireAuth(RequirePermission("manage_snapshots")(http.HandlerFunc(HandleCreateSnapshot)))).Methods("POST")
	r.Handle("/api/snapshots/restore",
		RequireAuth(RequirePermission("manage_snapshots")(http.HandlerFunc(HandleRestoreSnapshot)))).Methods("POST")
	r.Handle("/api/snapshots/clone",
		RequireAuth(RequirePermission("manage_snapshots")(http.HandlerFunc(HandleCloneSnapshot)))).Methods("POST")
	r.Handle("/api/snapshots/delete",
		RequireAuth(RequirePermission("manage_snapshots")(http.HandlerFunc(HandleDeleteSnapshot)))).Methods("POST")
	r.Handle("/api/snapshots/delete-all",
		RequireAuth(RequirePermission("manage_snapshots")(http.HandlerFunc(HandleDeleteAllSnapshots)))).Methods("POST")

	// --- Disks ---
	r.Handle("/api/disks",
		RequireAuth(http.HandlerFunc(HandleListDisks))).Methods("GET")
	r.Handle("/api/disks/scan",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleScanDisks)))).Methods("POST")
	r.Handle("/api/disks/refresh",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleRefreshDisks)))).Methods("POST")
	r.Handle("/api/disks/wipe",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleWipeDisk)))).Methods("POST")
	r.Handle("/api/disks/power",
		RequireAuth(RequireAdmin(HandleGetDiskPower(appCfg)))).Methods("GET")
	r.Handle("/api/disks/power",
		RequireAuth(RequireAdmin(HandleUpdateDiskPower(appCfg)))).Methods("PUT")
	r.Handle("/api/disks/power/install",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleInstallHdparm)))).Methods("POST")

	// --- SMB Shares ---
	r.Handle("/api/smb/global-config",
		RequireAuth(http.HandlerFunc(HandleGetSMBGlobalConfig(appCfg)))).Methods("GET")
	r.Handle("/api/smb/global-config",
		RequireAuth(RequirePermission("manage_smb")(http.HandlerFunc(HandleUpdateSMBGlobalConfig(appCfg))))).Methods("PUT")
	r.Handle("/api/shares/status",
		RequireAuth(http.HandlerFunc(HandleSMBStatus))).Methods("GET")
	r.Handle("/api/shares/service",
		RequireAuth(RequirePermission("manage_smb")(http.HandlerFunc(HandleSMBService)))).Methods("POST")
	r.Handle("/api/shares/set-password",
		RequireAuth(RequirePermission("manage_smb")(http.HandlerFunc(HandleSetSMBPassword)))).Methods("POST")
	r.Handle("/api/shares",
		RequireAuth(http.HandlerFunc(HandleListShares))).Methods("GET")
	r.Handle("/api/shares",
		RequireAuth(RequirePermission("manage_smb")(http.HandlerFunc(HandleCreateShare)))).Methods("POST")
	r.Handle("/api/shares/sessions",
		RequireAuth(http.HandlerFunc(HandleGetSMBSessions))).Methods("GET")
	r.Handle("/api/shares/{name}",
		RequireAuth(RequirePermission("manage_smb")(http.HandlerFunc(HandleUpdateShare)))).Methods("PUT")
	r.Handle("/api/shares/{name}",
		RequireAuth(RequirePermission("manage_smb")(http.HandlerFunc(HandleDeleteShare)))).Methods("DELETE")
	r.Handle("/api/shares/{name}/clean-recycle",
		RequireAuth(RequirePermission("manage_smb")(http.HandlerFunc(HandleCleanShareRecycleBin)))).Methods("POST")
	r.Handle("/api/shares/vss-snapshot",
		RequireAuth(RequirePermission("manage_smb")(http.HandlerFunc(HandleCreateVSSSnapshot)))).Methods("POST")

	// --- Prerequisites & systemd service (admin only) ---
	r.Handle("/api/prereqs",
		RequireAuth(http.HandlerFunc(HandleCheckPrereqs))).Methods("GET")
	r.Handle("/api/prereqs/install-service",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleInstallService)))).Methods("POST")

	// --- Sudoers Hardening (admin only) ---
	r.Handle("/api/sudoers/status",
		RequireAuth(RequirePermission("review_sudoers")(HandleSudoersStatus(appCfg)))).Methods("GET")
	r.Handle("/api/sudoers/diff",
		RequireAuth(RequirePermission("review_sudoers")(HandleSudoersDiff(appCfg)))).Methods("GET")
	r.Handle("/api/sudoers/enable",
		RequireAuth(RequireAdmin(HandleEnableSudoersHardening(appCfg)))).Methods("POST")
	r.Handle("/api/sudoers/apply",
		RequireAuth(RequireAdmin(HandleApplySudoers(appCfg)))).Methods("POST")
	r.Handle("/api/sudoers/apply-sudo-all",
		RequireAuth(RequireAdmin(HandleApplySudoAll(appCfg)))).Methods("POST")

	// WebSocket: stream apt-get install output (admin only)
	r.Handle("/ws/prereqs-install",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleInstallPrereqs)))).Methods("GET")

	// --- Memory Compression (zram-tools), v6.5.3+ ---
	// Status is read by Settings → Virtualization (admin) and the topbar
	// gauge / dashboard chart (every authenticated user sees the live
	// counters; we keep status auth-only, no admin gate).
	r.Handle("/api/system/swappiness",
		RequireAuth(http.HandlerFunc(HandleSwappinessStatus))).Methods("GET")
	r.Handle("/api/system/swappiness",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetSwappiness)))).Methods("PUT")
	r.Handle("/api/memcomp/status",
		RequireAuth(http.HandlerFunc(HandleMemCompStatus))).Methods("GET")
	r.Handle("/api/memcomp/config",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleMemCompConfig)))).Methods("PUT")
	r.Handle("/ws/memcomp-install",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleMemCompInstallPrereqs)))).Methods("GET")

	// WebSocket: interactive PTY terminal
	r.Handle("/ws/terminal",
		RequireAuth(RequirePermission("terminal")(http.HandlerFunc(HandleTerminal)))).Methods("GET")

	// WebSocket: interactive OS package upgrade in a PTY (admin-only — it runs
	// apt-get dist-upgrade then a shell).
	r.Handle("/ws/updater",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpdaterTerminal)))).Methods("GET")

	// --- OS Updates (admin only) ---
	r.Handle("/api/os-info",
		RequireAuth(http.HandlerFunc(HandleOSInfo))).Methods("GET")
	r.Handle("/api/updates/check",
		RequireAuth(RequireAdmin(HandleCheckUpdates(appCfg)))).Methods("GET")
	r.Handle("/api/updates/cache",
		RequireAuth(RequireAdmin(HandleGetUpdateCache(appCfg)))).Methods("GET")
	r.Handle("/api/updates/upgrade-status",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpgradeStatus)))).Methods("GET")
	r.Handle("/ws/updates-apply",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleApplyUpdates)))).Methods("GET")
	r.Handle("/api/updates/unattended-status",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUnattendedStatus)))).Methods("GET")
	r.Handle("/api/updates/unattended",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUnattendedSet)))).Methods("POST")

	// --- Settings ---
	r.Handle("/api/settings",
		RequireAuth(http.HandlerFunc(HandleGetSettings(appCfg)))).Methods("GET")
	r.Handle("/api/settings",
		RequireAuth(RequirePermission("edit_settings")(http.HandlerFunc(HandleUpdateSettings(appCfg))))).Methods("PUT")
	r.Handle("/api/settings/timezone",
		RequireAuth(http.HandlerFunc(HandleGetTimezone))).Methods("GET")
	r.Handle("/api/settings/timezone",
		RequireAuth(RequirePermission("edit_settings")(http.HandlerFunc(HandleSetTimezone)))).Methods("PUT")
	r.Handle("/api/settings/ntp/status",
		RequireAuth(http.HandlerFunc(HandleNTPStatus))).Methods("GET")
	r.Handle("/api/settings/ntp/servers",
		RequireAuth(http.HandlerFunc(HandleGetNTPServers))).Methods("GET")
	r.Handle("/api/settings/ntp/servers",
		RequireAuth(RequirePermission("edit_settings")(http.HandlerFunc(HandleSetNTPServers)))).Methods("PUT")

	// --- Scrub ---
	r.Handle("/api/pool/scrub/status",
		RequireAuth(http.HandlerFunc(HandleScrubStatus))).Methods("GET")
	r.Handle("/api/pool/scrub/start",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleStartScrub)))).Methods("POST")
	r.Handle("/api/pool/scrub/stop",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleStopScrub)))).Methods("POST")
	r.Handle("/api/pool/scrub/schedule",
		RequireAuth(http.HandlerFunc(HandleGetScrubSchedule(appCfg)))).Methods("GET")
	r.Handle("/api/pool/scrub/schedule",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleSetScrubSchedule(appCfg))))).Methods("PUT")
	r.Handle("/api/treemap/schedule",
		RequireAuth(http.HandlerFunc(HandleGetTreeMapSchedule(appCfg)))).Methods("GET")
	r.Handle("/api/treemap/schedule",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleSetTreeMapSchedule(appCfg))))).Methods("PUT")

	// --- Snapshot schedules ---
	r.Handle("/api/snapshot-schedules",
		RequireAuth(http.HandlerFunc(HandleListSchedules))).Methods("GET")
	r.Handle("/api/snapshot-schedules",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleCreateSchedule)))).Methods("POST")
	r.Handle("/api/snapshot-schedules/{id}",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleUpdateSchedule)))).Methods("PUT")
	r.Handle("/api/snapshot-schedules/{id}",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleDeleteSchedule)))).Methods("DELETE")
	r.Handle("/api/snapshot-schedules/{id}/run-now",
		RequireAuth(RequirePermission("manage_protection")(HandleRunScheduleNow(appCfg)))).Methods("POST")

	// --- External storage + Filesystem rsync (v6.7.7) ---
	r.Handle("/api/extstorage",
		RequireAuth(http.HandlerFunc(HandleExtStorageList(appCfg)))).Methods("GET")
	r.Handle("/api/extstorage",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleExtStorageCreate(appCfg))))).Methods("POST")
	r.Handle("/api/extstorage/prereqs",
		RequireAuth(http.HandlerFunc(HandleExtStoragePrereqs))).Methods("GET")
	r.Handle("/api/extstorage/install",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleExtStorageInstall)))).Methods("POST")
	r.Handle("/api/extstorage/test",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleExtStorageTest(appCfg))))).Methods("POST")
	r.Handle("/api/extstorage/{id}",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleExtStorageUpdate(appCfg))))).Methods("PUT")
	r.Handle("/api/extstorage/{id}",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleExtStorageDelete(appCfg))))).Methods("DELETE")
	r.Handle("/api/extstorage/{id}/mount",
		RequireAuth(http.HandlerFunc(HandleExtStorageMount(appCfg)))).Methods("POST")
	r.Handle("/api/extstorage/{id}/unmount",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleExtStorageUnmount(appCfg))))).Methods("POST")
	r.Handle("/api/extstorage/{id}/browse",
		RequireAuth(http.HandlerFunc(HandleExtStorageBrowse(appCfg)))).Methods("GET")
	r.Handle("/api/extstorage/{id}/rsync",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleExtStorageSetRsync(appCfg))))).Methods("PUT")
	r.Handle("/api/extstorage/{id}/rsync/run",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleExtStorageRunRsync(appCfg))))).Methods("POST")
	r.Handle("/api/extstorage/{id}/rsync/log",
		RequireAuth(http.HandlerFunc(HandleExtStorageRsyncLog(appCfg)))).Methods("GET")
	// Unified job board: every background job type, one endpoint pair, one
	// interlink fan-out. This is what makes a running job visible from every web
	// session and every linked server rather than only the tab that started it.
	r.Handle("/api/jobs",
		RequireAuth(http.HandlerFunc(HandleJobs))).Methods("GET")
	r.Handle("/api/jobs/aggregate",
		RequireAuth(http.HandlerFunc(HandleJobsAggregate(appCfg)))).Methods("GET")
	r.Handle("/api/rsync-jobs",
		RequireAuth(http.HandlerFunc(HandleRsyncJobs))).Methods("GET")
	r.Handle("/api/rsync-jobs/aggregate",
		RequireAuth(http.HandlerFunc(HandleRsyncJobsAggregate(appCfg)))).Methods("GET")
	r.Handle("/api/rsync-jobs/{id}/progress",
		RequireAuth(http.HandlerFunc(HandleRsyncJobProgress))).Methods("GET")
	r.Handle("/api/rsync-jobs/{id}/cancel",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleRsyncJobCancel)))).Methods("POST")

	// --- iSCSI sharing ---
	r.Handle("/api/iscsi/status",
		RequireAuth(http.HandlerFunc(HandleISCSIStatus(appCfg)))).Methods("GET")
	r.Handle("/api/iscsi/service",
		RequireAuth(RequirePermission("manage_iscsi")(http.HandlerFunc(HandleISCSIServiceAction)))).Methods("POST")
	r.Handle("/api/iscsi/config",
		RequireAuth(http.HandlerFunc(HandleGetISCSIConfig))).Methods("GET")
	r.Handle("/api/iscsi/config",
		RequireAuth(RequirePermission("manage_iscsi")(http.HandlerFunc(HandleSaveISCSIConfig)))).Methods("POST")
	r.Handle("/api/iscsi/hosts",
		RequireAuth(http.HandlerFunc(HandleListISCSIHosts))).Methods("GET")
	r.Handle("/api/iscsi/host",
		RequireAuth(RequirePermission("manage_iscsi")(http.HandlerFunc(HandleSaveISCSIHost)))).Methods("POST")
	r.Handle("/api/iscsi/host/delete",
		RequireAuth(RequirePermission("manage_iscsi")(http.HandlerFunc(HandleDeleteISCSIHost)))).Methods("POST")
	r.Handle("/api/iscsi/shares",
		RequireAuth(http.HandlerFunc(HandleListISCSIShares))).Methods("GET")
	r.Handle("/api/iscsi/share/create",
		RequireAuth(RequirePermission("manage_iscsi")(http.HandlerFunc(HandleCreateISCSIShare)))).Methods("POST")
	r.Handle("/api/iscsi/share/edit",
		RequireAuth(RequirePermission("manage_iscsi")(http.HandlerFunc(HandleEditISCSIShare)))).Methods("POST")
	r.Handle("/api/iscsi/share/delete",
		RequireAuth(RequirePermission("manage_iscsi")(http.HandlerFunc(HandleDeleteISCSIShare)))).Methods("POST")
	r.Handle("/api/iscsi/credentials",
		RequireAuth(http.HandlerFunc(HandleListISCSICredentials))).Methods("GET")
	r.Handle("/api/iscsi/credential",
		RequireAuth(RequirePermission("manage_iscsi")(http.HandlerFunc(HandleSaveISCSICredential)))).Methods("POST")
	r.Handle("/api/iscsi/credential/delete",
		RequireAuth(RequirePermission("manage_iscsi")(http.HandlerFunc(HandleDeleteISCSICredential)))).Methods("POST")
	r.Handle("/api/iscsi/sessions",
		RequireAuth(http.HandlerFunc(HandleGetISCSISessions))).Methods("GET")

	// --- Replication tasks ---
	r.Handle("/api/replication",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleListReplicationTasks)))).Methods("GET")
	r.Handle("/api/replication",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleCreateReplicationTask)))).Methods("POST")
	r.Handle("/api/replication/{id}",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleEditReplicationTask)))).Methods("PUT")
	r.Handle("/api/replication/{id}",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleDeleteReplicationTask)))).Methods("DELETE")
	r.Handle("/ws/replication/{id}/run",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleRunReplicationTask)))).Methods("GET")

	// --- Prerequisites: install optional packages (admin only) ---
	r.Handle("/api/prereqs/op-status",
		RequireAuth(http.HandlerFunc(HandleOpStatus))).Methods("GET")
	r.Handle("/api/prereqs/install",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleInstallPackage(appCfg))))).Methods("POST")
	r.Handle("/api/prereqs/uninstall",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUninstallPackage(appCfg))))).Methods("POST")

	// --- MinIO / S3 Object Server ---
	r.Handle("/api/minio/status",
		RequireAuth(http.HandlerFunc(HandleMinIOStatus(appCfg)))).Methods("GET")
	r.Handle("/api/minio/service",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleMinIOServiceAction(appCfg))))).Methods("POST")
	r.Handle("/api/minio/config",
		RequireAuth(http.HandlerFunc(HandleGetMinIOConfig(appCfg)))).Methods("GET")
	r.Handle("/api/minio/config",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSaveMinIOConfig(appCfg))))).Methods("POST")
	r.Handle("/api/minio/users",
		RequireAuth(http.HandlerFunc(HandleListS3Users(appCfg)))).Methods("GET")
	r.Handle("/api/minio/user/create",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateS3User(appCfg))))).Methods("POST")
	r.Handle("/api/minio/user/delete",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteS3User(appCfg))))).Methods("POST")
	r.Handle("/api/minio/user/status",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetS3UserStatus(appCfg))))).Methods("POST")
	r.Handle("/api/minio/user/password",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetS3UserPassword(appCfg))))).Methods("POST")
	r.Handle("/api/minio/buckets",
		RequireAuth(http.HandlerFunc(HandleListS3Buckets(appCfg)))).Methods("GET")
	r.Handle("/api/minio/bucket/create",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateS3Bucket(appCfg))))).Methods("POST")
	r.Handle("/api/minio/bucket/delete",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteS3Bucket(appCfg))))).Methods("POST")
	r.Handle("/api/minio/bucket/edit",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleEditS3Bucket(appCfg))))).Methods("POST")

	// --- NFS shares ---
	r.Handle("/api/nfs/status",
		RequireAuth(http.HandlerFunc(HandleNFSStatus))).Methods("GET")
	r.Handle("/api/nfs/service",
		RequireAuth(RequirePermission("manage_nfs")(http.HandlerFunc(HandleNFSService)))).Methods("POST")
	r.Handle("/api/nfs/shares",
		RequireAuth(http.HandlerFunc(HandleListNFSShares))).Methods("GET")
	r.Handle("/api/nfs/shares",
		RequireAuth(RequirePermission("manage_nfs")(http.HandlerFunc(HandleCreateNFSShare)))).Methods("POST")
	r.Handle("/api/nfs/shares/{id}",
		RequireAuth(RequirePermission("manage_nfs")(http.HandlerFunc(HandleUpdateNFSShare)))).Methods("PUT")
	r.Handle("/api/nfs/shares/{id}",
		RequireAuth(RequirePermission("manage_nfs")(http.HandlerFunc(HandleDeleteNFSShare)))).Methods("DELETE")
	r.Handle("/api/nfs/sessions",
		RequireAuth(http.HandlerFunc(HandleGetNFSSessions))).Methods("GET")

	// --- Alerts ---
	// GET is admin-only: the alert config (recipients, server URLs, event
	// subscriptions) is administrative, the editor UI is admin-only, and the
	// PUT below is already admin-gated. Secrets are masked in the response
	// regardless, but there's no reason a read-only/standard user should read
	// the notification configuration at all.
	r.Handle("/api/alerts",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleGetAlerts)))).Methods("GET")
	r.Handle("/api/alerts",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpdateAlerts)))).Methods("PUT")
	r.Handle("/api/alerts/test",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleTestAlert)))).Methods("POST")
	r.Handle("/api/alerts/test/email",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleTestAlertEmail)))).Methods("POST")
	r.Handle("/api/alerts/test/ntfy",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleTestAlertNtfy)))).Methods("POST")
	r.Handle("/api/alerts/test/gotify",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleTestAlertGotify)))).Methods("POST")
	r.Handle("/api/alerts/test/pushover",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleTestAlertPushover)))).Methods("POST")
	r.Handle("/api/alerts/test/syslog",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleTestAlertSyslog)))).Methods("POST")
	r.Handle("/api/alerts/test/websocket",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleTestAlertWebSocket)))).Methods("POST")

	// WebSocket: real-time in-app alert notifications
	r.Handle("/ws/alerts",
		RequireAuth(http.HandlerFunc(HandleAlertsWS))).Methods("GET")
	// Incus daemon health snapshot — used by the persistent-banner
	// hydration on page load (v6.5.26).
	r.Handle("/api/lxd/health",
		RequireAuth(http.HandlerFunc(HandleIncusHealth))).Methods("GET")

	// --- Disk I/O metrics ---
	r.Handle("/api/sysinfo/diskio",
		RequireAuth(http.HandlerFunc(HandleGetDiskIO))).Methods("GET")

	// --- Per-process CPU metrics ---
	r.Handle("/api/sysinfo/cpu-procs",
		RequireAuth(http.HandlerFunc(HandleGetCpuProcs))).Methods("GET")

	// --- Per-process memory metrics ---
	r.Handle("/api/sysinfo/mem-procs",
		RequireAuth(http.HandlerFunc(HandleGetMemProcs))).Methods("GET")

	// --- Hardware info ---
	r.Handle("/api/sysinfo/hardware",
		RequireAuth(http.HandlerFunc(HandleGetHardwareInfo))).Methods("GET")
	r.Handle("/api/sysinfo/hardware-detailed",
		RequireAuth(http.HandlerFunc(HandleGetDetailedSystemInfo))).Methods("GET")

	// --- Version ---
	r.Handle("/api/version",
		RequireAuth(http.HandlerFunc(HandleGetVersion))).Methods("GET")

	// --- Dashboard metrics (RRD) ---
	r.Handle("/api/dashboard/metrics",
		RequireAuth(http.HandlerFunc(HandleGetDashboardMetrics))).Methods("GET")

	// --- Global system performance (multi-tier RRD) ---
	r.Handle("/api/perf/global-data",
		RequireAuth(http.HandlerFunc(HandleGetGlobalPerfData))).Methods("GET")
	r.Handle("/api/perf/global-oldest",
		RequireAuth(http.HandlerFunc(HandleGetGlobalPerfOldest))).Methods("GET")

	// --- Per-pool disk performance (multi-tier RRD) ---
	r.Handle("/api/perf/pools",
		RequireAuth(http.HandlerFunc(HandleGetPoolPerfPools))).Methods("GET")
	r.Handle("/api/perf/pool-data",
		RequireAuth(http.HandlerFunc(HandleGetPoolPerfData))).Methods("GET")
	r.Handle("/api/perf/pool-oldest",
		RequireAuth(http.HandlerFunc(HandleGetPoolPerfOldest))).Methods("GET")

	// --- Capacity Trend (multi-resolution RRD) ---
	r.Handle("/api/capacity/series",
		RequireAuth(http.HandlerFunc(HandleCapacitySeries))).Methods("GET")
	r.Handle("/api/capacity/data",
		RequireAuth(http.HandlerFunc(HandleCapacityData))).Methods("GET")
	r.Handle("/api/capacity/oldest",
		RequireAuth(http.HandlerFunc(HandleCapacityOldest))).Methods("GET")

	// --- Live Storage Map (topology) ---
	r.Handle("/api/map/topology",
		RequireAuth(http.HandlerFunc(HandleMapTopology(appCfg)))).Methods("GET")
	r.Handle("/api/map/instance-metrics",
		RequireAuth(http.HandlerFunc(HandleMapInstanceMetrics))).Methods("GET")
	r.Handle("/ws/zpool-iostat",
		RequireAuth(http.HandlerFunc(HandleZpoolIostatWS))).Methods("GET")

	// --- Folder Usage (Dataset Tree) ---
	r.Handle("/api/capacity/folder-usage",
		RequireAuth(http.HandlerFunc(HandleGetFolderUsage(appCfg)))).Methods("GET")
	r.Handle("/api/capacity/folder-usage/refresh",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleRefreshFolderUsage(appCfg))))).Methods("POST")

	// --- Network interface info ---
	r.Handle("/api/net/ifaces",
		RequireAuth(http.HandlerFunc(HandleGetNetIfaces))).Methods("GET")

	// --- System power (admin only) ---
	r.Handle("/api/system/reboot",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleReboot)))).Methods("POST")
	r.Handle("/api/system/shutdown",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleShutdown)))).Methods("POST")
	r.Handle("/api/system/restart-portal",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleRestartPortal)))).Methods("POST")
	r.Handle("/api/system/power",
		RequireAuth(RequireAdmin(HandleGetSystemPower(appCfg)))).Methods("GET")
	r.Handle("/api/system/power",
		RequireAuth(RequireAdmin(HandleUpdateSystemPower(appCfg)))).Methods("PUT")

	// --- Binary self-update (admin only) ---
	r.Handle("/api/binary-update/check",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCheckBinaryUpdate(appCfg))))).Methods("GET")
	r.Handle("/api/binary-update/releases",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleListReleases(appCfg))))).Methods("GET")
	r.Handle("/api/binary-update/settings",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleGetBinaryUpdateSettings(appCfg))))).Methods("GET")
	r.Handle("/api/binary-update/settings",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSaveBinaryUpdateSettings(appCfg))))).Methods("PUT")
	r.Handle("/ws/binary-update-apply",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleBinaryUpdateApply(appCfg))))).Methods("GET")

	// --- UPS Management ---
	r.Handle("/api/ups/status",
		RequireAuth(http.HandlerFunc(HandleGetUPSStatus(appCfg)))).Methods("GET")
	r.Handle("/api/ups/config",
		RequireAuth(http.HandlerFunc(HandleGetUPSConfig(appCfg)))).Methods("GET")
	r.Handle("/api/ups/config",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpdateUPSConfig(appCfg))))).Methods("PUT")
	r.Handle("/api/ups/install",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleInstallUPS(appCfg))))).Methods("POST")
	r.Handle("/api/ups/service",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUPSService)))).Methods("POST")
	r.Handle("/api/ups/detect",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDetectUPS(appCfg))))).Methods("POST")
	r.Handle("/api/ups/nominal-power",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetNominalPower(appCfg))))).Methods("PUT")
	r.Handle("/api/ups/cost-per-kwh",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetCostPerKWh(appCfg))))).Methods("PUT")
	r.Handle("/api/ups/perf/data",
		RequireAuth(http.HandlerFunc(HandleUPSPerfData))).Methods("GET")
	r.Handle("/api/ups/perf/oldest",
		RequireAuth(http.HandlerFunc(HandleUPSPerfOldest))).Methods("GET")
	r.Handle("/api/ups/test-client",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleTestNUTClient)))).Methods("POST")
	r.Handle("/api/ups/calibrate",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUPSCalibrate(appCfg))))).Methods("POST")
	r.Handle("/api/ups/shutdown-policy",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSaveShutdownPolicy(appCfg))))).Methods("PUT")

	// --- Certificate Management ---
	r.Handle("/api/certs",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleListCerts(appCfg))))).Methods("GET")
	r.Handle("/api/certs/upload",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUploadCert(appCfg))))).Methods("POST")
	r.Handle("/api/certs/restart",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCertRestart(appCfg))))).Methods("POST")
	r.Handle("/api/certs/{name}/export",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleExportCert(appCfg))))).Methods("GET")
	r.Handle("/api/certs/{name}/activate",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleActivateCert(appCfg))))).Methods("POST")
	r.Handle("/api/certs/{name}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteCert(appCfg))))).Methods("DELETE")

	// --- InterLink (server federation + SSO switching) ---
	// Public endpoints — called by remote ZNAS servers or browser redirects (no session auth).
	r.HandleFunc("/api/interlink/ping", HandleInterlinkPing).Methods("GET")
	r.HandleFunc("/api/interlink/accept-link", HandleInterlinkAcceptLink(appCfg)).Methods("POST")
	r.HandleFunc("/api/interlink/check-user", HandleInterlinkCheckUser(appCfg)).Methods("POST")
	r.HandleFunc("/api/interlink/remote-unlink", HandleInterlinkRemoteUnlink(appCfg)).Methods("POST")
	r.HandleFunc("/api/interlink/remote-pools", HandleInterlinkRemotePools(appCfg)).Methods("POST")
	r.HandleFunc("/api/interlink/remote-folders", HandleInterlinkRemoteFolders(appCfg)).Methods("POST")
	r.HandleFunc("/api/interlink/push-ssh-key", HandleInterlinkPushSSHKey(appCfg)).Methods("POST")
	r.HandleFunc("/api/interlink/check-zfs-access", HandleInterlinkCheckZFSAccess(appCfg)).Methods("POST")
	r.HandleFunc("/api/interlink/grant-zfs-access", HandleInterlinkGrantZFSAccess(appCfg)).Methods("POST")
	r.HandleFunc("/interlink-login", HandleInterlinkLogin(appCfg)).Methods("GET")
	// Authenticated endpoints — called by the local portal UI.
	r.Handle("/api/interlink/servers/fast",
		RequireAuth(http.HandlerFunc(HandleInterlinkListFast(appCfg)))).Methods("GET")
	r.Handle("/api/interlink/servers",
		RequireAuth(http.HandlerFunc(HandleInterlinkList(appCfg)))).Methods("GET")
	r.Handle("/api/interlink/link",
		RequireAuth(RequirePermission("manage_interlink")(http.HandlerFunc(HandleInterlinkLink(appCfg))))).Methods("POST")
	r.Handle("/api/interlink/switch",
		RequireAuth(http.HandlerFunc(HandleInterlinkSwitch(appCfg)))).Methods("POST")
	r.Handle("/api/interlink/relay-exit",
		RequireAuth(http.HandlerFunc(HandleInterlinkRelayExit))).Methods("POST")
	r.Handle("/api/interlink/relay-mode",
		RequireAuth(http.HandlerFunc(HandleInterlinkGetRelayMode(appCfg)))).Methods("GET")
	r.Handle("/api/interlink/relay-mode",
		RequireAuth(RequirePermission("manage_interlink")(http.HandlerFunc(HandleInterlinkSetRelayMode(appCfg))))).Methods("PUT")
	r.Handle("/api/interlink/{id}",
		RequireAuth(RequirePermission("manage_interlink")(http.HandlerFunc(HandleInterlinkUnlink(appCfg))))).Methods("DELETE")
	r.Handle("/api/interlink/remote-pools/{server_id}",
		RequireAuth(http.HandlerFunc(HandlePushInterlinkGetRemotePools(appCfg)))).Methods("GET")
	r.Handle("/api/interlink/remote-folders/{server_id}",
		RequireAuth(http.HandlerFunc(HandlePushInterlinkGetRemoteFolders(appCfg)))).Methods("GET")
	r.Handle("/api/interlink/remote-lxd-storage/{server_id}",
		RequireAuth(http.HandlerFunc(HandleInterlinkRemoteLXDStorage(appCfg)))).Methods("GET")
	r.Handle("/api/interlink/remote-lxd-bridges/{server_id}",
		RequireAuth(http.HandlerFunc(HandleInterlinkRemoteLXDBridges(appCfg)))).Methods("GET")
	r.Handle("/api/interlink/remote-lxd-instances/{server_id}",
		RequireAuth(http.HandlerFunc(HandleInterlinkRemoteLXDInstances(appCfg)))).Methods("GET")
	// Push InterLink job endpoints.
	// v6.6.22 — the eligible push-target list. Mirrors /api/interlink/servers but
	// lives under /api/push-interlink/ so it FORWARDS to the viewed peer in relay
	// mode (the switcher's /api/interlink/servers stays local). This is what makes
	// the Push-InterLink dataset/snapshot modals list the viewed server's peers
	// (incl. the home server) rather than the home server's peers.
	r.Handle("/api/push-interlink/servers",
		RequireAuth(http.HandlerFunc(HandleInterlinkList(appCfg)))).Methods("GET")
	r.Handle("/api/push-interlink/start",
		RequireAuth(RequirePermission("manage_interlink")(http.HandlerFunc(HandlePushInterlinkStart(appCfg)))))
	r.Handle("/api/push-interlink/start-dataset",
		RequireAuth(RequirePermission("manage_interlink")(http.HandlerFunc(HandlePushInterlinkStartDataset(appCfg))))).Methods("POST").Methods("POST")
	r.Handle("/api/push-interlink/jobs",
		RequireAuth(http.HandlerFunc(HandlePushInterlinkJobs))).Methods("GET")
	r.Handle("/api/push-interlink/cancel/{id}",
		RequireAuth(RequirePermission("manage_interlink")(http.HandlerFunc(HandlePushInterlinkCancel)))).Methods("POST")

	// --- File Browser ---
	r.Handle("/api/files/list",
		RequireAuth(RequirePermission("browse_files")(http.HandlerFunc(HandleFileBrowserList)))).Methods("GET")
	r.Handle("/api/files/users-groups",
		RequireAuth(RequirePermission("browse_files")(http.HandlerFunc(HandleFileBrowserUsersGroups)))).Methods("GET")
	r.Handle("/api/files/chown",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleFileBrowserChown)))).Methods("POST")
	r.Handle("/api/files/chmod",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleFileBrowserChmod)))).Methods("POST")
	// v6.5.29 — full file browser:
	r.Handle("/api/files/roots",
		RequireAuth(RequirePermission("browse_files")(http.HandlerFunc(HandleFileBrowserRoots)))).Methods("GET")
	r.Handle("/api/files/tree",
		RequireAuth(RequirePermission("browse_files")(http.HandlerFunc(HandleFileBrowserTree)))).Methods("GET")
	r.Handle("/api/files/raw",
		RequireAuth(RequirePermission("browse_files")(http.HandlerFunc(HandleFileBrowserRaw)))).Methods("GET")
	r.Handle("/api/files/download",
		RequireAuth(RequirePermission("browse_files")(http.HandlerFunc(HandleFileBrowserDownload)))).Methods("GET")
	r.Handle("/api/files/mkdir",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleFileBrowserMkdir)))).Methods("POST")
	r.Handle("/api/files/upload",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleFileBrowserUpload)))).Methods("POST")
	r.Handle("/api/files/delete",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleFileBrowserDelete)))).Methods("POST")
	r.Handle("/api/files/move",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleFileBrowserMove)))).Methods("POST")
	r.Handle("/api/files/rename",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleFileBrowserRename)))).Methods("POST")
	r.Handle("/api/files/copy",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleFileBrowserCopy)))).Methods("POST")
	// Copy/move of anything large runs as a background job; these drive the
	// progress popup and its Cancel button. Discovery across sessions and
	// servers is handled by the shared job board (/api/jobs), which every
	// transfer registers with.
	r.Handle("/api/files/transfers/{id}/progress",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleFbTransferProgress)))).Methods("GET")
	r.Handle("/api/files/transfers/{id}/cancel",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleFbTransferCancel)))).Methods("POST")

	// --- LXD VM & Container management (experimental) ---
	// /api/lxd/status and /api/lxd/enable/* are always registered so the frontend
	// can probe availability and drive the Optional Features enablement flow even
	// before LXD is installed.
	r.Handle("/api/lxd/status",
		RequireAuth(http.HandlerFunc(HandleLXDStatus))).Methods("GET")
	r.Handle("/api/lxd/enable/prereqs",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDEnablePrereqs)))).Methods("GET")
	r.Handle("/api/lxd/enable/status",
		RequireAuth(http.HandlerFunc(HandleLXDEnableStatus))).Methods("GET")
	r.Handle("/api/lxd/enable/start",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDEnableStart)))).Methods("POST")
	r.Handle("/api/lxd/enable/progress",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDEnableProgress)))).Methods("GET")
	r.Handle("/api/lxd/enable/cancel",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDEnableCancel)))).Methods("POST")
	r.Handle("/api/lxd/enable/netconfig",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDEnableNetConfig)))).Methods("GET")
	r.Handle("/api/lxd/enable/static-ip",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDEnableStaticIP)))).Methods("POST")
	// Uninstall flow: count check + async purge job. The progress is
	// observable through the same /api/lxd/enable/progress endpoint
	// because the underlying job structure is shared.
	r.Handle("/api/lxd/uninstall/check",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDUninstallCheck)))).Methods("GET")
	r.Handle("/api/lxd/uninstall/start",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDUninstallStart)))).Methods("POST")
	r.Handle("/ws/lxd-migrate-netplan",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDMigrateNetplan)))).Methods("GET")
	r.Handle("/api/lxd/refresh-status",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDRefreshStatus)))).Methods("POST")

	// Virtualization settings tab + per-instance Monitor tab (v6.4.28).
	r.Handle("/api/lxd/global-config",
		RequireAuth(http.HandlerFunc(HandleGetLXDGlobalConfig))).Methods("GET")
	r.Handle("/api/lxd/global-config",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetLXDGlobalConfig)))).Methods("PUT")
	r.Handle("/api/lxd/metrics-toggle",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDMetricsToggle)))).Methods("POST")
	r.Handle("/api/lxd/metrics-status",
		RequireAuth(http.HandlerFunc(HandleLXDMetricsStatus))).Methods("GET")
	r.Handle("/api/lxd/instance-perf",
		RequireAuth(http.HandlerFunc(HandleLXDInstancePerf))).Methods("GET")
	// Workload tab — aggregator over every per-instance RRD; returns
	// cpu/mem/net_rx/net_tx/disk_r/disk_w per instance so the frontend
	// can render top-N stacked charts without N HTTP requests.
	r.Handle("/api/lxd/workload-perf",
		RequireAuth(http.HandlerFunc(HandleLXDWorkloadPerf))).Methods("GET")
	// VM/Container table metric columns — latest-sample rollup per instance
	// (cpu%/mem%/top-fs%/net Mb-s/disk-IO MB-s) in one request.
	r.Handle("/api/lxd/instances-metrics",
		RequireAuth(http.HandlerFunc(HandleLXDInstancesMetrics))).Methods("GET")
	r.Handle("/api/lxd/instance-realtime",
		RequireAuth(http.HandlerFunc(HandleLXDInstanceRealtime))).Methods("GET")
	r.Handle("/api/lxd/instances",
		RequireAuth(RequireVirtView(http.HandlerFunc(HandleListInstances)))).Methods("GET")
	// VM/Container tags (v6.6.19). Registry read is view-gated (so non-admin
	// instance editors aren't 403'd on relay); membership edit + recolor need
	// edit_instances.
	r.Handle("/api/lxd/tags",
		RequireAuth(RequireVirtView(http.HandlerFunc(HandleLXDTags)))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/tags",
		RequireAuth(RequireInstancePerm("edit_instances")(http.HandlerFunc(HandleLXDSetInstanceTags)))).Methods("PUT")
	r.Handle("/api/lxd/tags/{tag}/color",
		RequireAuth(RequirePermission("edit_instances")(http.HandlerFunc(HandleLXDSetTagColor)))).Methods("PUT")
	r.Handle("/api/lxd/instances/{name}/stats",
		RequireAuth(http.HandlerFunc(HandleLXDInstanceStats))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/status",
		RequireAuth(http.HandlerFunc(HandleLXDInstanceStatus))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/logs",
		RequireAuth(http.HandlerFunc(HandleLXDInstanceLogs))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/log-files",
		RequireAuth(http.HandlerFunc(HandleLXDInstanceLogFiles))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/console-log",
		RequireAuth(http.HandlerFunc(HandleLXDInstanceConsoleLog))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/snapshots",
		RequireAuth(http.HandlerFunc(HandleLXDListSnapshots))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/snapshots",
		RequireAuth(RequireInstancePerm("manage_instance_backups")(http.HandlerFunc(HandleLXDCreateSnapshot)))).Methods("POST")
	r.Handle("/api/lxd/instances/{name}/snapshots/{snap}/restore",
		RequireAuth(RequireInstancePerm("manage_instance_backups")(http.HandlerFunc(HandleLXDRestoreSnapshot)))).Methods("POST")
	r.Handle("/api/lxd/instances/{name}/snapshots/{snap}/clone",
		RequireAuth(RequireInstancePerm("manage_instance_backups")(http.HandlerFunc(HandleLXDCloneFromSnapshot)))).Methods("POST")
	r.Handle("/api/lxd/instances/{name}/clone",
		RequireAuth(RequireInstancePerm("manage_instance_backups")(http.HandlerFunc(HandleLXDCloneInstance)))).Methods("POST")
	r.Handle("/api/lxd/instances/{name}/move-storage",
		RequireAuth(RequireInstancePerm("edit_instances")(http.HandlerFunc(HandleLXDMoveStorage)))).Methods("POST")
	// Per-disk move (v6.5.37) — Related Objects burger menu. Independent
	// of /move-storage (which moves the whole instance) because the user
	// picks one disk row. Backend dispatches root vs custom-volume on the
	// disk's actual config.
	//
	// Routes are registered under /api/lxd/* (the post-alias-rewrite path)
	// even though the frontend calls /api/incus/*: IncusPathAliasMiddleware
	// rewrites every /api/incus/* URL to /api/lxd/* BEFORE mux dispatch,
	// so a route registered at /api/incus/* would never match. The
	// existing proxmox-import + every other "new" endpoint follows the
	// same pattern. v6.5.40 fixed a regression where the first cut of
	// this route was registered under /api/incus/* and quietly returned
	// 405 because nothing matched the rewritten path.
	r.Handle("/api/lxd/instances/{name}/disk-move/start",
		RequireAuth(RequireInstancePerm("edit_instances")(http.HandlerFunc(HandleDiskMoveStart)))).Methods("POST")
	r.Handle("/api/lxd/instances/{name}/disk-move/progress",
		RequireAuth(RequireInstancePerm("edit_instances")(http.HandlerFunc(HandleDiskMoveProgress)))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/disk-move/cancel",
		RequireAuth(RequireInstancePerm("edit_instances")(http.HandlerFunc(HandleDiskMoveCancel)))).Methods("POST")
	r.Handle("/api/lxd/instances/{name}/snapshots/{snap}",
		RequireAuth(RequireInstancePerm("manage_instance_backups")(http.HandlerFunc(HandleLXDDeleteSnapshot)))).Methods("DELETE")
	r.Handle("/api/lxd/instances/{name}/start",
		RequireAuth(RequireInstancePerm("control_instances")(http.HandlerFunc(HandleLXDStart)))).Methods("POST")
	r.Handle("/api/lxd/instances/{name}/stop",
		RequireAuth(RequireInstancePerm("control_instances")(http.HandlerFunc(HandleLXDStop)))).Methods("POST")
	r.Handle("/api/lxd/instances/{name}/restart",
		RequireAuth(RequireInstancePerm("control_instances")(http.HandlerFunc(HandleLXDRestart)))).Methods("POST")
	r.Handle("/api/lxd/instances/{name}/reset",
		RequireAuth(RequireInstancePerm("control_instances")(http.HandlerFunc(HandleLXDReset)))).Methods("POST")
	r.Handle("/api/lxd/instances/{name}/config",
		RequireAuth(http.HandlerFunc(HandleLXDGetConfig))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/config",
		RequireAuth(RequireInstancePerm("edit_instances")(http.HandlerFunc(HandleLXDSetConfig)))).Methods("PUT")
	r.Handle("/api/lxd/instances/{name}",
		RequireAuth(RequireInstancePerm("delete_instances")(http.HandlerFunc(HandleLXDDelete)))).Methods("DELETE")
	r.Handle("/api/lxd/vms",
		RequireAuth(RequirePermission("create_vm")(http.HandlerFunc(HandleCreateVM)))).Methods("POST")
	r.Handle("/api/lxd/containers",
		RequireAuth(RequirePermission("create_container")(http.HandlerFunc(HandleCreateContainer)))).Methods("POST")
	r.Handle("/api/lxd/compose-stacks",
		RequireAuth(RequirePermission("create_container")(http.HandlerFunc(HandleCreateComposeStack(appCfg))))).Methods("POST")
	// v6.6.22 — deploy-target chooser: list docker/podman targets (#2),
	// deploy into an existing instance (#2), create a fresh compose VM (#3).
	r.Handle("/api/lxd/compose-targets",
		RequireAuth(RequireVirtView(http.HandlerFunc(HandleComposeTargets)))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/compose-deploy",
		RequireAuth(RequireInstancePerm("create_container")(http.HandlerFunc(HandleComposeDeploy)))).Methods("POST")
	r.Handle("/api/lxd/compose-vms",
		RequireAuth(RequirePermission("create_vm")(http.HandlerFunc(HandleCreateComposeVM)))).Methods("POST")
	r.Handle("/api/lxd/compose-stacks/{name}",
		RequireAuth(http.HandlerFunc(HandleComposeStackGet(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/compose-stacks/{name}",
		RequireAuth(RequireInstancePerm("edit_instances")(http.HandlerFunc(HandleComposeRedeploy)))).Methods("PUT")
	r.Handle("/api/lxd/compose-stacks/{name}/containers",
		RequireAuth(http.HandlerFunc(HandleComposeStackContainers))).Methods("GET")
	r.Handle("/api/lxd/compose-stacks/{name}/containers/{container}/logs",
		RequireAuth(http.HandlerFunc(HandleComposeContainerLogs))).Methods("GET")
	r.Handle("/api/lxd/compose-stacks/{name}/containers/{container}/inspect",
		RequireAuth(http.HandlerFunc(HandleComposeContainerInspect))).Methods("GET")
	r.Handle("/api/lxd/compose-stacks/{name}/container-action",
		RequireAuth(RequireInstancePerm("edit_instances")(http.HandlerFunc(HandleComposeContainerAction)))).Methods("POST")
	r.Handle("/api/lxd/compose-stacks/{name}/update",
		RequireAuth(RequireInstancePerm("edit_instances")(http.HandlerFunc(HandleComposeStackUpdate)))).Methods("POST")
	r.Handle("/api/lxd/compose-stacks/{name}/schedule",
		RequireAuth(http.HandlerFunc(HandleComposeGetSchedule(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/compose-stacks/{name}/schedule",
		RequireAuth(RequireInstancePerm("edit_instances")(http.HandlerFunc(HandleComposePutSchedule(appCfg))))).Methods("PUT")
	r.Handle("/api/lxd/compose-stacks/{name}/schedule",
		RequireAuth(RequireInstancePerm("edit_instances")(http.HandlerFunc(HandleComposeDeleteSchedule(appCfg))))).Methods("DELETE")
	r.Handle("/api/lxd/create-progress",
		RequireAuth(http.HandlerFunc(HandleLXDCreateProgress))).Methods("GET")
	r.Handle("/api/lxd/remotes",
		RequireAuth(http.HandlerFunc(HandleListRemotes))).Methods("GET")
	r.Handle("/api/lxd/images",
		RequireAuth(http.HandlerFunc(HandleListImages))).Methods("GET")
	r.Handle("/api/lxd/profiles",
		RequireAuth(http.HandlerFunc(HandleListProfiles))).Methods("GET")
	r.Handle("/api/lxd/storage-pools",
		RequireAuth(http.HandlerFunc(HandleListStoragePools))).Methods("GET")
	r.Handle("/api/lxd/storage-pools-detail",
		RequireAuth(http.HandlerFunc(HandleListStoragePoolInfos))).Methods("GET")
	r.Handle("/api/lxd/storage-pools-detail",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateStoragePool)))).Methods("POST")
	r.Handle("/api/lxd/storage-pools/{name}",
		RequireAuth(http.HandlerFunc(HandleGetStoragePool))).Methods("GET")
	r.Handle("/api/lxd/storage-pools/{name}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleEditStoragePool)))).Methods("PUT")
	r.Handle("/api/lxd/storage-pools/{name}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteStoragePool)))).Methods("DELETE")
	r.Handle("/api/lxd/storage-pools/{name}/members",
		RequireAuth(http.HandlerFunc(HandleGetStoragePoolMembers))).Methods("GET")
	r.Handle("/api/lxd/storage-pools/{name}/vdisks",
		RequireAuth(http.HandlerFunc(HandleDatastoreVDisks))).Methods("GET")
	r.Handle("/api/lxd/free-zvols",
		RequireAuth(http.HandlerFunc(HandleListFreeZVols))).Methods("GET")
	r.Handle("/api/lxd/networks",
		RequireAuth(http.HandlerFunc(HandleListNetworks))).Methods("GET")
	r.Handle("/api/lxd/bridges",
		RequireAuth(http.HandlerFunc(HandleListBridges))).Methods("GET")
	r.Handle("/api/lxd/network-bridges",
		RequireAuth(RequireNetView(http.HandlerFunc(HandleListLXDNetworks)))).Methods("GET")
	r.Handle("/api/lxd/network-bridges",
		RequireAuth(RequirePermission("manage_networking")(http.HandlerFunc(HandleCreateLXDNetwork)))).Methods("POST")
	r.Handle("/api/lxd/network-bridges/{name}",
		RequireAuth(http.HandlerFunc(HandleGetLXDNetwork))).Methods("GET")
	r.Handle("/api/lxd/network-bridges/{name}",
		RequireAuth(RequirePermission("manage_networking")(http.HandlerFunc(HandleEditLXDNetwork)))).Methods("PUT")
	r.Handle("/api/lxd/network-bridges/{name}",
		RequireAuth(RequirePermission("manage_networking")(http.HandlerFunc(HandleDeleteLXDNetwork)))).Methods("DELETE")
	r.Handle("/api/lxd/network-bridges/{name}/members",
		RequireAuth(http.HandlerFunc(HandleGetBridgeMembers))).Methods("GET")
	r.Handle("/api/lxd/network-bridges/{name}/stats",
		RequireAuth(http.HandlerFunc(HandleGetBridgeStats))).Methods("GET")
	r.Handle("/api/lxd/vlan-interface/{name}",
		RequireAuth(RequirePermission("manage_networking")(http.HandlerFunc(HandleDeleteVLANInterface)))).Methods("DELETE")
	r.Handle("/api/lxd/host-interfaces",
		RequireAuth(http.HandlerFunc(HandleListPhysicalInterfaces))).Methods("GET")
	r.Handle("/api/lxd/host-interfaces/{name}/mtu",
		RequireAuth(RequirePermission("manage_networking")(http.HandlerFunc(HandleSetInterfaceMTU)))).Methods("PUT")
	r.Handle("/api/lxd/usb-devices",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleListUSB)))).Methods("GET")
	r.Handle("/api/lxd/pci-devices",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleListPCI)))).Methods("GET")
	r.Handle("/api/lxd/cpu-topology",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDCPUTopology)))).Methods("GET")
	r.Handle("/api/lxd/machine-versions",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDMachineVersions)))).Methods("GET")
	r.Handle("/ws/lxd-console",
		RequireAuth(RequirePermission("terminal")(http.HandlerFunc(HandleLXDConsole)))).Methods("GET")
	r.Handle("/lxd-console/{name}",
		RequireAuth(http.HandlerFunc(ServeLXDConsolePage))).Methods("GET")
	// v6.5.30 — persistent terminal sessions + consolidated multi-tab popup.
	r.Handle("/api/terminal-sessions",
		RequireAuth(RequirePermission("terminal")(http.HandlerFunc(HandleListTerminalSessions)))).Methods("GET")
	r.Handle("/api/terminal-sessions/aggregate",
		RequireAuth(RequirePermission("terminal")(http.HandlerFunc(HandleListTerminalSessionsAggregate(appCfg))))).Methods("GET")
	r.Handle("/api/terminal-sessions/{id}/close",
		RequireAuth(RequirePermission("terminal")(http.HandlerFunc(HandleCloseTerminalSession)))).Methods("POST")
	r.Handle("/terminal-multi",
		RequireAuth(RequirePermission("terminal")(http.HandlerFunc(ServeTerminalMultiPage)))).Methods("GET")
	// Public icon — needs to be reachable by iPadOS before the user has
	// authenticated (the "Add to Home Screen" flow fetches it through a
	// background loader that does not carry the session cookie). iOS
	// requires PNG for apple-touch-icon; SVG is served alongside for
	// browser-tab favicons where it stays crisp at any size.
	r.HandleFunc("/icons/z-terminals.png", ServeZTerminalsIcon).Methods("GET")
	r.HandleFunc("/icons/z-terminals.svg", ServeZTerminalsIconSVG).Methods("GET")
	r.Handle("/ws/interlink-terminal",
		RequireAuth(RequirePermission("terminal")(http.HandlerFunc(HandleInterlinkTerminalProxyWS(appCfg))))).Methods("GET")
	r.Handle("/api/interlink/terminal-sessions/{server_id}/{id}/close",
		RequireAuth(RequirePermission("terminal")(http.HandlerFunc(HandleCloseRemoteTerminalSession(appCfg))))).Methods("POST")
	r.Handle("/ws/compose-logs",
		RequireAuth(http.HandlerFunc(HandleComposeLogsWS))).Methods("GET")
	r.Handle("/ws/compose-console",
		RequireAuth(RequirePermission("terminal")(http.HandlerFunc(HandleComposeConsoleWS)))).Methods("GET")
	r.Handle("/compose-console/{stack}/{container}",
		RequireAuth(http.HandlerFunc(ServeComposeConsolePage))).Methods("GET")
	// v6.5.26 — Docker Detection inside user-managed VMs/LXCs.
	r.Handle("/api/lxd/instances/{name}/docker/probe",
		RequireAuth(http.HandlerFunc(HandleDockerProbe(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/docker/containers",
		RequireAuth(http.HandlerFunc(HandleDockerListContainers(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/docker/containers/{id}/logs",
		RequireAuth(http.HandlerFunc(HandleDockerContainerLogs(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/docker/containers/{id}/inspect",
		RequireAuth(http.HandlerFunc(HandleDockerContainerInspect(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/docker/compose-file",
		RequireAuth(http.HandlerFunc(HandleDockerGetComposeFile(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/docker/compose-file",
		RequireAuth(RequirePermission("manage_docker_detect")(http.HandlerFunc(HandleDockerPutComposeFile(appCfg))))).Methods("PUT")
	r.Handle("/api/lxd/instances/{name}/docker/compose-action",
		RequireAuth(RequirePermission("manage_docker_detect")(http.HandlerFunc(HandleDockerComposeAction(appCfg))))).Methods("POST")
	r.Handle("/api/lxd/instances/{name}/docker/container-action",
		RequireAuth(RequirePermission("manage_docker_detect")(http.HandlerFunc(HandleDockerContainerAction(appCfg))))).Methods("POST")
	// v6.6.22 §6 — delete a detected compose project (down + rm -rf /opt/<name>).
	r.Handle("/api/lxd/instances/{name}/docker/compose-project",
		RequireAuth(RequirePermission("manage_docker_detect")(http.HandlerFunc(HandleDeleteComposeProject)))).Methods("DELETE")
	r.Handle("/ws/docker-console",
		RequireAuth(RequirePermission("terminal")(http.HandlerFunc(HandleDockerConsoleWS(appCfg))))).Methods("GET")
	r.Handle("/docker-console/{instance}/{container}",
		RequireAuth(http.HandlerFunc(ServeDockerConsolePage))).Methods("GET")
	r.Handle("/ws/lxd-vga",
		RequireAuth(http.HandlerFunc(HandleLXDVGAConsole))).Methods("GET")
	r.Handle("/lxd-vga-console/{name}",
		RequireAuth(http.HandlerFunc(ServeLXDVGAPage))).Methods("GET")
	// Generic per-peer forwarder: everything after /interlink-relay/<id> is
	// proxied (HTTP) or bridged (WS) to that linked server. Used by embedded
	// peer VGA console tabs so their API + SPICE calls reach the peer without
	// entering global relay mode. PathPrefix (no Methods) so it also catches
	// the /ws/ upgrade and POST power/CD-ROM actions.
	r.PathPrefix("/interlink-relay/{server_id}/").Handler(
		RequireAuth(http.HandlerFunc(HandleInterlinkRelay(appCfg))))
	r.Handle("/api/lxd/proxmox-import/tools-status",
		RequireAuth(http.HandlerFunc(HandleProxmoxImportToolsStatus))).Methods("GET")
	r.Handle("/api/lxd/proxmox-import/list",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleProxmoxImportList)))).Methods("POST")
	r.Handle("/api/lxd/proxmox-import/start",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleProxmoxImportStart)))).Methods("POST")
	r.Handle("/api/lxd/proxmox-import/progress",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleProxmoxImportProgress)))).Methods("GET")
	r.Handle("/api/lxd/proxmox-import/cancel",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleProxmoxImportCancel)))).Methods("POST")
	// ISO management
	// Listing ISOs is read-only and needed by the VM create/edit CDROM picker,
	// so it's gated on virtualization ACCESS (view_virtualization), not full
	// admin — otherwise a non-admin instance editor (incl. a relayed user whose
	// role on the peer isn't admin) can edit a VM but gets an empty ISO list for
	// its CDROM. The mutating ISO endpoints (upload/delete/fetch) stay admin-only.
	r.Handle("/api/lxd/isos",
		RequireAuth(RequirePermission("view_virtualization")(http.HandlerFunc(HandleListISOs)))).Methods("GET")
	r.Handle("/api/lxd/isos/upload",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUploadISO)))).Methods("POST")
	// ISO fetch from URL: server-side download into the pool's .isos
	// directory. Validates ISO 9660 magic before publishing the file.
	r.Handle("/api/lxd/isos/fetch",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleFetchISOStart)))).Methods("POST")
	r.Handle("/api/lxd/isos/fetch/progress",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleFetchISOProgress)))).Methods("GET")
	r.Handle("/api/lxd/isos/{filename}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteISO)))).Methods("DELETE")
	// VGA-console drive picker: list configured CDROMs + ISOs available in the
	// VM's pool, and swap the first drive without leaving the console.
	r.Handle("/api/lxd/instances/{name}/cdroms",
		RequireAuth(http.HandlerFunc(HandleLXDListCDROMs))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/cdroms/swap",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDSwapCDROM)))).Methods("POST")

	// --- LXD InterLink push (HMAC-authenticated peer endpoints) ---
	r.HandleFunc("/api/lxd/interlink-cert", HandleLXDInterlinkCert(appCfg)).Methods("POST")
	r.HandleFunc("/api/lxd/interlink-trust", HandleLXDInterlinkTrust(appCfg)).Methods("POST")
	r.HandleFunc("/api/lxd/storage-pools-remote", HandleLXDRemoteStoragePools(appCfg)).Methods("POST")
	r.HandleFunc("/api/lxd/bridges-remote", HandleLXDRemoteBridges(appCfg)).Methods("POST")
	r.HandleFunc("/api/lxd/instances-remote", HandleLXDRemoteInstances(appCfg)).Methods("POST")
	r.HandleFunc("/api/lxd/vm-nvram-reset", HandleLXDVMNVRAMReset(appCfg)).Methods("POST")
	r.HandleFunc("/api/lxd/vm-tpm-clear", HandleLXDVMTPMClear(appCfg)).Methods("POST")
	// Session-authenticated LXD InterLink push endpoints.
	r.Handle("/api/lxd/interlink-sync-trust/{server_id}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDInterlinkSyncTrust(appCfg))))).Methods("POST")
	r.Handle("/api/lxd/interlink-lxd-status",
		RequireAuth(http.HandlerFunc(HandleLXDInterlinkStatus(appCfg)))).Methods("GET")
	// Relay-aware mirrors of the interlink push-target lookups. The VM Push
	// modal calls these via /api/incus/… so that — unlike the bypassed
	// /api/interlink/* forms — they are forwarded to the relay target when
	// relay mode is active. That makes the modal's server list, storage,
	// bridges and instance lookups come from the SAME server that runs the
	// push (the one hosting the VM), using that server's interlink IDs.
	// Served locally with an identical result when relay is off.
	r.Handle("/api/lxd/interlink/servers",
		RequireAuth(http.HandlerFunc(HandleInterlinkList(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/interlink/remote-lxd-storage/{server_id}",
		RequireAuth(http.HandlerFunc(HandleInterlinkRemoteLXDStorage(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/interlink/remote-lxd-bridges/{server_id}",
		RequireAuth(http.HandlerFunc(HandleInterlinkRemoteLXDBridges(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/interlink/remote-lxd-instances/{server_id}",
		RequireAuth(http.HandlerFunc(HandleInterlinkRemoteLXDInstances(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/nics",
		RequireAuth(http.HandlerFunc(HandleLXDGetVMNICs))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/reset-nvram",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDResetNVRAMLocal)))).Methods("POST")
	// VM push job management.
	r.Handle("/api/lxd/push-interlink/start",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDPushVMStart(appCfg))))).Methods("POST")
	r.Handle("/api/lxd/push-interlink/cancel/{id}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLXDPushVMCancel)))).Methods("POST")

	// ── v6.5.19 — VM/Container snapshot & backup feature ────────────────────
	// Per-instance snapshot schedule.
	r.Handle("/api/lxd/instances/{name}/snapshot-schedule",
		RequireAuth(http.HandlerFunc(HandleGetLXDSnapPolicy(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/snapshot-schedule",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandlePutLXDSnapPolicy(appCfg))))).Methods("PUT")
	r.Handle("/api/lxd/instances/{name}/snapshot-schedule",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleDeleteLXDSnapPolicy(appCfg))))).Methods("DELETE")
	// Per-instance backups: list, schedule, now, progress.
	r.Handle("/api/lxd/instances/{name}/backups",
		RequireAuth(http.HandlerFunc(HandleListInstanceBackups))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/backups-aggregate",
		RequireAuth(http.HandlerFunc(HandleListAggregatedBackupsForVM(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/backup-schedule",
		RequireAuth(http.HandlerFunc(HandleGetLXDBackupPolicy(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/backup-schedule",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandlePutLXDBackupPolicy(appCfg))))).Methods("PUT")
	r.Handle("/api/lxd/instances/{name}/backup-schedule",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleDeleteLXDBackupPolicy(appCfg))))).Methods("DELETE")
	r.Handle("/api/lxd/instances/{name}/backup-now",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleLXDBackupNow(appCfg))))).Methods("POST")
	r.Handle("/api/lxd/backup-jobs",
		RequireAuth(http.HandlerFunc(HandleListBackupJobs))).Methods("GET")
	r.Handle("/api/lxd/backup-jobs/{job_id}/progress",
		RequireAuth(http.HandlerFunc(HandleLXDBackupProgress))).Methods("GET")
	r.Handle("/api/lxd/backup-jobs/{job_id}/cancel",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleLXDBackupCancel)))).Methods("POST")
	// Cross-server Backups page (Datastores → Backups).
	r.Handle("/api/lxd/backups",
		RequireAuth(http.HandlerFunc(HandleListAllBackups(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/backup-datastores",
		RequireAuth(http.HandlerFunc(HandleListBackupDatastores(appCfg)))).Methods("GET")
	r.Handle("/api/lxd/backups/restore-instant",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleInstantRestoreBackup)))).Methods("POST")
	r.Handle("/api/lxd/backups/delete",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleDeleteBackup(appCfg))))).Methods("POST")
	r.Handle("/api/lxd/backups/restore-clone",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleCloneRestoreBackup(appCfg))))).Methods("POST")
	// Instant Independent Restore dependency + promote-to-full-copy (v6.6.15).
	r.Handle("/api/lxd/instances/{name}/backup-dependency",
		RequireAuth(http.HandlerFunc(HandleBackupDependency))).Methods("GET")
	r.Handle("/api/lxd/instances/{name}/promote-full-copy",
		RequireAuth(RequirePermission("manage_protection")(HandlePromoteFullCopy(appCfg)))).Methods("POST")
	r.Handle("/api/lxd/restore-jobs",
		RequireAuth(http.HandlerFunc(HandleListRestoreJobs))).Methods("GET")
	r.Handle("/api/lxd/restore-jobs/{job_id}/progress",
		RequireAuth(http.HandlerFunc(HandleRestoreCloneProgress))).Methods("GET")
	r.Handle("/api/lxd/restore-jobs/{job_id}/cancel",
		RequireAuth(RequirePermission("manage_protection")(http.HandlerFunc(HandleRestoreCloneCancel)))).Methods("POST")
	// HMAC peer endpoints (no session auth — authenticated by request HMAC).
	r.HandleFunc("/api/lxd/interlink-pool-source", HandleInterlinkPoolSource(appCfg)).Methods("POST")
	r.HandleFunc("/api/lxd/interlink-backups", HandleInterlinkListLocalBackups(appCfg)).Methods("POST")
	r.HandleFunc("/api/lxd/interlink-backup-delete", HandleInterlinkBackupDelete(appCfg)).Methods("POST")
	r.HandleFunc("/api/lxd/interlink-zfs-pools", HandleInterlinkZFSPools(appCfg)).Methods("POST")
	r.HandleFunc("/api/lxd/interlink-prep-workload", HandleInterlinkPrepWorkload(appCfg)).Methods("POST")
	r.HandleFunc("/api/lxd/interlink-prep-chain", HandleInterlinkPrepChain(appCfg)).Methods("POST")
	r.HandleFunc("/api/lxd/interlink-prune-retention", HandleInterlinkPruneRetention(appCfg)).Methods("POST")
	// Syncoid install entry (admin-only; reused by Prerequisites page).
	r.Handle("/api/prerequisites/install-syncoid",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleInstallSyncoid)))).Methods("POST")
	r.Handle("/api/prerequisites/syncoid-status",
		RequireAuth(http.HandlerFunc(HandleSyncoidStatus))).Methods("GET")

	// --- MergerFS (v6.7.13, optional feature) ---
	r.Handle("/api/mergerfs/status",
		RequireAuth(HandleMergerFSStatus(appCfg))).Methods("GET")
	r.Handle("/api/prerequisites/install-mergerfs",
		RequireAuth(RequireAdmin(HandleInstallMergerFS(appCfg)))).Methods("POST")
	r.Handle("/api/prerequisites/uninstall-mergerfs",
		RequireAuth(RequireAdmin(HandleUninstallMergerFS(appCfg)))).Methods("POST")
	r.Handle("/api/mergerfs/enable",
		RequireAuth(RequireAdmin(HandleMergerFSEnable(appCfg)))).Methods("PUT")
	r.Handle("/api/mergerfs/pools",
		RequireAuth(HandleListMergerFSPools(appCfg))).Methods("GET")
	r.Handle("/api/mergerfs/pools",
		RequireAuth(RequirePermission("manage_pool_dataset")(HandleCreateMergerFSPool(appCfg)))).Methods("POST")
	r.Handle("/api/mergerfs/pools/{name}/status",
		RequireAuth(HandleMergerFSPoolStatus(appCfg))).Methods("GET")
	r.Handle("/api/mergerfs/pools/{name}",
		RequireAuth(RequirePermission("manage_pool_dataset")(HandleUpdateMergerFSPool(appCfg)))).Methods("PUT")
	r.Handle("/api/mergerfs/pools/{name}",
		RequireAuth(RequirePermission("manage_pool_dataset")(HandleDeleteMergerFSPool(appCfg)))).Methods("DELETE")
	// Coordinated global snapshots (all-ZFS unions).
	r.Handle("/api/mergerfs/pools/{name}/snapshots",
		RequireAuth(HandleMergerFSSnapshots(appCfg))).Methods("GET")
	r.Handle("/api/mergerfs/pools/{name}/snapshots",
		RequireAuth(RequirePermission("manage_snapshots")(HandleMergerFSSnapDelete(appCfg)))).Methods("DELETE")
	r.Handle("/api/mergerfs/pools/{name}/snap-now",
		RequireAuth(RequirePermission("manage_snapshots")(HandleMergerFSSnapNow(appCfg)))).Methods("POST")
	r.Handle("/api/mergerfs/pools/{name}/snap-restore",
		RequireAuth(RequirePermission("manage_snapshots")(HandleMergerFSSnapRestore(appCfg)))).Methods("POST")
	r.Handle("/api/mergerfs/pools/{name}/snap-schedule",
		RequireAuth(HandleGetMergerFSSnapSchedule(appCfg))).Methods("GET")
	r.Handle("/api/mergerfs/pools/{name}/snap-schedule",
		RequireAuth(RequirePermission("manage_snapshots")(HandlePutMergerFSSnapSchedule(appCfg)))).Methods("PUT")
	r.Handle("/api/mergerfs/pools/{name}/snap-schedule",
		RequireAuth(RequirePermission("manage_snapshots")(HandleDeleteMergerFSSnapSchedule(appCfg)))).Methods("DELETE")

	// --- Homepage widget API keys (admin only) ---
	r.Handle("/api/settings/api-keys",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleListAPIKeys)))).Methods("GET")
	r.Handle("/api/settings/api-keys",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateAPIKey)))).Methods("POST")
	r.Handle("/api/settings/api-keys/{id}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteAPIKey)))).Methods("DELETE")
	r.Handle("/api/settings/api-keys/pool-targets",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleListPoolTargets(appCfg))))).Methods("GET")
	r.Handle("/api/settings/api-keys/{id}/pool-target",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetAPIKeyPoolTarget(appCfg))))).Methods("PUT")

	// --- Services (v6.8.1) ---
	r.Handle("/api/services",
		RequireAuth(RequirePermission("view_services")(http.HandlerFunc(HandleListServices(appCfg))))).Methods("GET")
	r.Handle("/api/services/refresh",
		RequireAuth(RequirePermission("view_services")(http.HandlerFunc(HandleRefreshServices(appCfg))))).Methods("POST")
	r.Handle("/api/services",
		RequireAuth(RequirePermission("manage_services")(http.HandlerFunc(HandleCreateService(appCfg))))).Methods("POST")
	r.Handle("/api/services/{id}",
		RequireAuth(RequirePermission("manage_services")(http.HandlerFunc(HandleUpdateService(appCfg))))).Methods("PUT")
	r.Handle("/api/services/{id}",
		RequireAuth(RequirePermission("manage_services")(http.HandlerFunc(HandleDeleteService(appCfg))))).Methods("DELETE")
	r.Handle("/api/services/{id}/action",
		RequireAuth(RequirePermission("manage_services")(http.HandlerFunc(HandleServiceAction(appCfg))))).Methods("POST")
	r.Handle("/api/services/{id}/icon",
		RequireAuth(RequirePermission("view_services")(http.HandlerFunc(HandleServiceIcon(appCfg))))).Methods("GET")

	// The service reverse proxy. RequireAuth + RequirePermission are mandatory
	// here — an unauthenticated proxy would be an open relay into the LAN
	// (PLANS/plan-version-6.8.1.md §2.8). Registered before the SPA catch-all.
	r.PathPrefix("/s/{id}/").Handler(
		RequireAuth(RequirePermission("view_services")(http.HandlerFunc(HandleServiceProxy(appCfg)))))

	r.Handle("/api/settings/services",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleGetServiceSettings(appCfg))))).Methods("GET")
	r.Handle("/api/settings/services",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetServiceSettings(appCfg))))).Methods("PUT")

	// --- TrueNAS-compatible read-only REST API (v2.0) ---
	// Accepts session cookie OR Authorization: Bearer <api_key>
	for path, h := range map[string]http.HandlerFunc{
		"/api/v2.0/alert/list":        HandleHomepageAlertList,
		"/api/v2.0/system/info":       HandleHomepageSystemInfo,
		"/api/v2.0/system/version":    HandleHomepageSystemVersion,
		"/api/v2.0/pool":              HandleHomepagePools(appCfg),
		"/api/v2.0/pool/dataset":      HandleHomepageDatasets(appCfg),
		"/api/v2.0/pool/snapshottask": HandleHomepageSnapshotTasks,
		"/api/v2.0/snapshot":          HandleHomepageSnapshots,
		"/api/v2.0/disk":              HandleHomepageDisks,
		"/api/v2.0/sharing/smb":       HandleHomepageSMBShares,
		"/api/v2.0/sharing/nfs":       HandleHomepageNFSShares,
		"/api/v2.0/service":           HandleHomepageServices,
	} {
		r.Handle(path, RequireAuthOrAPIKey(http.HandlerFunc(h))).Methods("GET")
	}

	// Catch-all for SPA deep links: serve index.html for any unknown GET that
	// doesn't start with /api/ or /static/.
	r.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if len(req.URL.Path) > 4 && req.URL.Path[:5] == "/api/" {
			jsonErr(w, http.StatusNotFound, "not found")
			return
		}
		// For unknown browser routes, serve the SPA.
		if _, ok := SessionFromRequest(req); !ok {
			http.Redirect(w, req, "/login", http.StatusSeeOther)
			return
		}
		data, err := readFile("index.html")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		serveSPAHTML(w, req, data)
	}).Methods("GET")

	// RelayMiddleware wraps the completed mux router (Server A outbound proxy):
	// intercepts requests for relay-active sessions and forwards them to the remote.
	// IncusPathAliasMiddleware runs first so /api/incus/* gets rewritten to the
	// internally-mounted /api/lxd/* before the relay decision is made — the
	// relay forwards the rewritten path to the peer (who will also be 6.5.2+
	// and has the same alias).
	return IncusPathAliasMiddleware(RelayMiddleware(appCfg, r))
}
