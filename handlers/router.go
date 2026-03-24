package handlers

import (
	"io/fs"
	"net/http"
	"zfsnas/internal/config"

	"github.com/gorilla/mux"
)

// NewRouter builds and returns the application router.
// staticFS is the embedded (or disk) filesystem rooted at the static/ directory.
// readFile is a helper to read a named file from staticFS (e.g. "index.html").
// appCfg is a pointer to the loaded application config (for settings handlers).
func NewRouter(staticFS fs.FS, readFile func(string) ([]byte, error), appCfg *config.AppConfig) *mux.Router {
	r := mux.NewRouter()
	r.Use(SecurityHeaders)
	r.Use(EnforceOrigin)

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
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	}))).Methods("GET")

	// --- Auth API ---
	r.HandleFunc("/api/auth/setup", HandleSetup).Methods("POST")
	r.HandleFunc("/api/auth/login", HandleLogin).Methods("POST")
	r.HandleFunc("/api/auth/totp", HandleTOTPLogin).Methods("POST")
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
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpdateUser)))).Methods("PUT")
	r.Handle("/api/users/{id}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteUser)))).Methods("DELETE")
	r.Handle("/api/users/{id}/totp",
		RequireAuth(http.HandlerFunc(HandleDisableTOTP))).Methods("DELETE")

	// --- Audit log ---
	r.Handle("/api/audit",
		RequireAuth(http.HandlerFunc(HandleAuditLog))).Methods("GET")

	// --- Pool ---
	r.Handle("/api/pools",
		RequireAuth(http.HandlerFunc(HandleGetPools))).Methods("GET")
	r.Handle("/api/pool",
		RequireAuth(http.HandlerFunc(HandleGetPool))).Methods("GET")
	r.Handle("/api/pool",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreatePool)))).Methods("POST")
	r.Handle("/api/pool/create-status",
		RequireAuth(http.HandlerFunc(HandlePoolCreateStatus))).Methods("GET")
	r.Handle("/api/pool/detect",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDetectPools)))).Methods("GET")
	r.Handle("/api/pool/import",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleImportPool)))).Methods("POST")
	r.Handle("/api/pool/status",
		RequireAuth(http.HandlerFunc(HandlePoolStatus))).Methods("GET")
	r.Handle("/api/pool/zfs-version",
		RequireAuth(http.HandlerFunc(HandleGetZFSVersion))).Methods("GET")
	r.Handle("/api/pool/grow",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleGrowPool)))).Methods("POST")
	r.Handle("/api/pool/export",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleExportPool)))).Methods("POST")
	r.Handle("/api/pool/destroy",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDestroyPool)))).Methods("POST")
	r.Handle("/api/pool/upgrade",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpgradePool)))).Methods("POST")
	r.Handle("/api/pool/cache",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleAddPoolCache)))).Methods("POST")
	r.Handle("/api/pool/cache",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleRemovePoolCache)))).Methods("DELETE")
	r.Handle("/api/pool/clear",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleClearPool)))).Methods("POST")
	r.Handle("/api/pool/fixer/online",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandlePoolFixerOnline)))).Methods("POST")
	r.Handle("/api/pool/fixer/replace",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandlePoolFixerReplace)))).Methods("POST")
	r.Handle("/api/pool/disk/offline",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDiskOffline)))).Methods("POST")
	r.Handle("/api/pool/disk/online",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDiskOnline)))).Methods("POST")
	r.Handle("/api/pool/settings",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetPoolProperties)))).Methods("PUT")
	r.Handle("/api/pool/load-key",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLoadPoolKey)))).Methods("POST")
	r.Handle("/api/pool/unload-key",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUnloadPoolKey)))).Methods("POST")
	r.Handle("/api/pool/arc",
		RequireAuth(http.HandlerFunc(HandleGetARC))).Methods("GET")
	r.Handle("/api/pool/arc",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetARC)))).Methods("PUT")

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
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateZVol)))).Methods("POST")
	r.Handle("/api/zvol/edit",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleEditZVol)))).Methods("POST")
	r.Handle("/api/zvol/delete",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteZVol)))).Methods("POST")

	// --- Datasets ---
	r.Handle("/api/datasets",
		RequireAuth(http.HandlerFunc(HandleListDatasets))).Methods("GET")
	r.Handle("/api/datasets",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateDataset)))).Methods("POST")
	r.Handle("/api/datasets/{path:.+}/load-key",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleLoadDatasetKey)))).Methods("POST")
	r.Handle("/api/datasets/{path:.+}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpdateDataset)))).Methods("PUT")
	r.Handle("/api/datasets/{path:.+}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteDataset)))).Methods("DELETE")

	// --- Snapshots ---
	r.Handle("/api/snapshots",
		RequireAuth(http.HandlerFunc(HandleListSnapshots))).Methods("GET")
	r.Handle("/api/snapshots",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateSnapshot)))).Methods("POST")
	r.Handle("/api/snapshots/restore",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleRestoreSnapshot)))).Methods("POST")
	r.Handle("/api/snapshots/clone",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCloneSnapshot)))).Methods("POST")
	r.Handle("/api/snapshots/delete",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteSnapshot)))).Methods("POST")
	r.Handle("/api/snapshots/delete-all",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteAllSnapshots)))).Methods("POST")

	// --- Disks ---
	r.Handle("/api/disks",
		RequireAuth(http.HandlerFunc(HandleListDisks))).Methods("GET")
	r.Handle("/api/disks/scan",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleScanDisks)))).Methods("POST")
	r.Handle("/api/disks/refresh",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleRefreshDisks)))).Methods("POST")
	r.Handle("/api/disks/wipe",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleWipeDisk)))).Methods("POST")

	// --- SMB Shares ---
	r.Handle("/api/smb/global-config",
		RequireAuth(http.HandlerFunc(HandleGetSMBGlobalConfig(appCfg)))).Methods("GET")
	r.Handle("/api/smb/global-config",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpdateSMBGlobalConfig(appCfg))))).Methods("PUT")
	r.Handle("/api/shares/status",
		RequireAuth(http.HandlerFunc(HandleSMBStatus))).Methods("GET")
	r.Handle("/api/shares/service",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSMBService)))).Methods("POST")
	r.Handle("/api/shares/set-password",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetSMBPassword)))).Methods("POST")
	r.Handle("/api/shares",
		RequireAuth(http.HandlerFunc(HandleListShares))).Methods("GET")
	r.Handle("/api/shares",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateShare)))).Methods("POST")
	r.Handle("/api/shares/sessions",
		RequireAuth(http.HandlerFunc(HandleGetSMBSessions))).Methods("GET")
	r.Handle("/api/shares/{name}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpdateShare)))).Methods("PUT")
	r.Handle("/api/shares/{name}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteShare)))).Methods("DELETE")
	r.Handle("/api/shares/{name}/clean-recycle",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCleanShareRecycleBin)))).Methods("POST")

	// --- Prerequisites & systemd service (admin only) ---
	r.Handle("/api/prereqs",
		RequireAuth(http.HandlerFunc(HandleCheckPrereqs))).Methods("GET")
	r.Handle("/api/prereqs/install-service",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleInstallService)))).Methods("POST")

	// WebSocket: stream apt-get install output (admin only)
	r.Handle("/ws/prereqs-install",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleInstallPrereqs)))).Methods("GET")

	// WebSocket: interactive PTY terminal (admin only)
	r.Handle("/ws/terminal",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleTerminal)))).Methods("GET")

	// --- OS Updates (admin only) ---
	r.Handle("/api/os-info",
		RequireAuth(http.HandlerFunc(HandleOSInfo))).Methods("GET")
	r.Handle("/api/updates/check",
		RequireAuth(RequireAdmin(HandleCheckUpdates(appCfg)))).Methods("GET")
	r.Handle("/api/updates/cache",
		RequireAuth(RequireAdmin(HandleGetUpdateCache(appCfg)))).Methods("GET")
	r.Handle("/ws/updates-apply",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleApplyUpdates)))).Methods("GET")

	// --- Settings (admin only) ---
	r.Handle("/api/settings",
		RequireAuth(http.HandlerFunc(HandleGetSettings(appCfg)))).Methods("GET")
	r.Handle("/api/settings",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpdateSettings(appCfg))))).Methods("PUT")
	r.Handle("/api/settings/timezone",
		RequireAuth(http.HandlerFunc(HandleGetTimezone))).Methods("GET")
	r.Handle("/api/settings/timezone",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetTimezone)))).Methods("PUT")

	// --- Scrub ---
	r.Handle("/api/pool/scrub/status",
		RequireAuth(http.HandlerFunc(HandleScrubStatus))).Methods("GET")
	r.Handle("/api/pool/scrub/start",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleStartScrub)))).Methods("POST")
	r.Handle("/api/pool/scrub/stop",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleStopScrub)))).Methods("POST")
	r.Handle("/api/pool/scrub/schedule",
		RequireAuth(http.HandlerFunc(HandleGetScrubSchedule(appCfg)))).Methods("GET")
	r.Handle("/api/pool/scrub/schedule",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetScrubSchedule(appCfg))))).Methods("PUT")
	r.Handle("/api/treemap/schedule",
		RequireAuth(http.HandlerFunc(HandleGetTreeMapSchedule(appCfg)))).Methods("GET")
	r.Handle("/api/treemap/schedule",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetTreeMapSchedule(appCfg))))).Methods("PUT")

	// --- Snapshot schedules ---
	r.Handle("/api/snapshot-schedules",
		RequireAuth(http.HandlerFunc(HandleListSchedules))).Methods("GET")
	r.Handle("/api/snapshot-schedules",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateSchedule)))).Methods("POST")
	r.Handle("/api/snapshot-schedules/{id}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpdateSchedule)))).Methods("PUT")
	r.Handle("/api/snapshot-schedules/{id}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteSchedule)))).Methods("DELETE")
	r.Handle("/api/snapshot-schedules/{id}/run-now",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleRunScheduleNow)))).Methods("POST")

	// --- iSCSI sharing ---
	r.Handle("/api/iscsi/status",
		RequireAuth(http.HandlerFunc(HandleISCSIStatus(appCfg)))).Methods("GET")
	r.Handle("/api/iscsi/service",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleISCSIServiceAction)))).Methods("POST")
	r.Handle("/api/iscsi/config",
		RequireAuth(http.HandlerFunc(HandleGetISCSIConfig))).Methods("GET")
	r.Handle("/api/iscsi/config",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSaveISCSIConfig)))).Methods("POST")
	r.Handle("/api/iscsi/hosts",
		RequireAuth(http.HandlerFunc(HandleListISCSIHosts))).Methods("GET")
	r.Handle("/api/iscsi/host",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSaveISCSIHost)))).Methods("POST")
	r.Handle("/api/iscsi/host/delete",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteISCSIHost)))).Methods("POST")
	r.Handle("/api/iscsi/shares",
		RequireAuth(http.HandlerFunc(HandleListISCSIShares))).Methods("GET")
	r.Handle("/api/iscsi/share/create",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateISCSIShare)))).Methods("POST")
	r.Handle("/api/iscsi/share/edit",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleEditISCSIShare)))).Methods("POST")
	r.Handle("/api/iscsi/share/delete",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteISCSIShare)))).Methods("POST")
	r.Handle("/api/iscsi/credentials",
		RequireAuth(http.HandlerFunc(HandleListISCSICredentials))).Methods("GET")
	r.Handle("/api/iscsi/credential",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSaveISCSICredential)))).Methods("POST")
	r.Handle("/api/iscsi/credential/delete",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteISCSICredential)))).Methods("POST")
	r.Handle("/api/iscsi/sessions",
		RequireAuth(http.HandlerFunc(HandleGetISCSISessions))).Methods("GET")

	// --- Replication tasks (admin only) ---
	r.Handle("/api/replication",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleListReplicationTasks)))).Methods("GET")
	r.Handle("/api/replication",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateReplicationTask)))).Methods("POST")
	r.Handle("/api/replication/{id}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleEditReplicationTask)))).Methods("PUT")
	r.Handle("/api/replication/{id}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteReplicationTask)))).Methods("DELETE")
	r.Handle("/ws/replication/{id}/run",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleRunReplicationTask)))).Methods("GET")

	// --- Prerequisites: install optional packages (admin only) ---
	r.Handle("/api/prereqs/op-status",
		RequireAuth(http.HandlerFunc(HandleOpStatus))).Methods("GET")
	r.Handle("/api/prereqs/install",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleInstallPackage(appCfg))))).Methods("POST")
	r.Handle("/api/prereqs/uninstall",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUninstallPackage(appCfg))))).Methods("POST")
	r.Handle("/api/prereqs/feature-nav",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleSetFeatureNavVisibility(appCfg))))).Methods("POST")

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
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleNFSService)))).Methods("POST")
	r.Handle("/api/nfs/shares",
		RequireAuth(http.HandlerFunc(HandleListNFSShares))).Methods("GET")
	r.Handle("/api/nfs/shares",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateNFSShare)))).Methods("POST")
	r.Handle("/api/nfs/shares/{id}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpdateNFSShare)))).Methods("PUT")
	r.Handle("/api/nfs/shares/{id}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteNFSShare)))).Methods("DELETE")
	r.Handle("/api/nfs/sessions",
		RequireAuth(http.HandlerFunc(HandleGetNFSSessions))).Methods("GET")

	// --- Alerts ---
	r.Handle("/api/alerts",
		RequireAuth(http.HandlerFunc(HandleGetAlerts))).Methods("GET")
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

	// --- Disk I/O metrics ---
	r.Handle("/api/sysinfo/diskio",
		RequireAuth(http.HandlerFunc(HandleGetDiskIO))).Methods("GET")

	// --- Hardware info ---
	r.Handle("/api/sysinfo/hardware",
		RequireAuth(http.HandlerFunc(HandleGetHardwareInfo))).Methods("GET")

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

	// --- Binary self-update (admin only) ---
	r.Handle("/api/binary-update/check",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCheckBinaryUpdate(appCfg))))).Methods("GET")
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
	r.Handle("/api/ups/perf/data",
		RequireAuth(http.HandlerFunc(HandleUPSPerfData))).Methods("GET")
	r.Handle("/api/ups/perf/oldest",
		RequireAuth(http.HandlerFunc(HandleUPSPerfOldest))).Methods("GET")

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

	// --- Homepage widget API keys (admin only) ---
	r.Handle("/api/settings/api-keys",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleListAPIKeys)))).Methods("GET")
	r.Handle("/api/settings/api-keys",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateAPIKey)))).Methods("POST")
	r.Handle("/api/settings/api-keys/{id}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteAPIKey)))).Methods("DELETE")

	// --- TrueNAS-compatible read-only REST API (v2.0) ---
	// Accepts session cookie OR Authorization: Bearer <api_key>
	for path, h := range map[string]http.HandlerFunc{
		"/api/v2.0/alert/list":       HandleHomepageAlertList,
		"/api/v2.0/system/info":      HandleHomepageSystemInfo,
		"/api/v2.0/system/version":   HandleHomepageSystemVersion,
		"/api/v2.0/pool":             HandleHomepagePools,
		"/api/v2.0/pool/dataset":     HandleHomepageDatasets,
		"/api/v2.0/pool/snapshottask": HandleHomepageSnapshotTasks,
		"/api/v2.0/snapshot":         HandleHomepageSnapshots,
		"/api/v2.0/disk":             HandleHomepageDisks,
		"/api/v2.0/sharing/smb":      HandleHomepageSMBShares,
		"/api/v2.0/sharing/nfs":      HandleHomepageNFSShares,
		"/api/v2.0/service":          HandleHomepageServices,
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
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	}).Methods("GET")

	return r
}
