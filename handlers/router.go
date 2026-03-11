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

	// --- Static assets ---
	r.PathPrefix("/static/").Handler(
		http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))),
	)

	// --- iOS / PWA home-screen icon (no auth needed — iOS fetches before login) ---
	r.HandleFunc("/apple-touch-icon.png", HandleAppleTouchIcon).Methods("GET")
	r.HandleFunc("/apple-touch-icon-precomposed.png", HandleAppleTouchIcon).Methods("GET")

	// --- Pre-auth pages ---
	r.HandleFunc("/setup", HandleSetupPage(readFile)).Methods("GET")
	r.HandleFunc("/login", HandleLoginPage(readFile)).Methods("GET")

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
	r.HandleFunc("/api/auth/logout", HandleLogout).Methods("POST")
	r.Handle("/api/auth/me", RequireAuth(http.HandlerFunc(HandleMe))).Methods("GET")
	r.Handle("/api/prefs", RequireAuth(http.HandlerFunc(HandleUpdatePrefs))).Methods("PUT")

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

	// --- Audit log ---
	r.Handle("/api/audit",
		RequireAuth(http.HandlerFunc(HandleAuditLog))).Methods("GET")

	// --- Pool ---
	r.Handle("/api/pool",
		RequireAuth(http.HandlerFunc(HandleGetPool))).Methods("GET")
	r.Handle("/api/pool",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreatePool)))).Methods("POST")
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
	r.Handle("/api/pool/destroy",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDestroyPool)))).Methods("POST")
	r.Handle("/api/pool/upgrade",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpgradePool)))).Methods("POST")

	// --- Datasets ---
	r.Handle("/api/datasets",
		RequireAuth(http.HandlerFunc(HandleListDatasets))).Methods("GET")
	r.Handle("/api/datasets",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCreateDataset)))).Methods("POST")
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

	// --- Disks ---
	r.Handle("/api/disks",
		RequireAuth(http.HandlerFunc(HandleListDisks))).Methods("GET")
	r.Handle("/api/disks/scan",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleScanDisks)))).Methods("POST")
	r.Handle("/api/disks/refresh",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleRefreshDisks)))).Methods("POST")

	// --- SMB Shares ---
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
	r.Handle("/api/shares/{name}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpdateShare)))).Methods("PUT")
	r.Handle("/api/shares/{name}",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleDeleteShare)))).Methods("DELETE")

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
	r.Handle("/api/updates/check",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCheckUpdates)))).Methods("GET")
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

	// --- Alerts ---
	r.Handle("/api/alerts",
		RequireAuth(http.HandlerFunc(HandleGetAlerts))).Methods("GET")
	r.Handle("/api/alerts",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleUpdateAlerts)))).Methods("PUT")
	r.Handle("/api/alerts/test",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleTestAlert)))).Methods("POST")

	// --- Disk I/O metrics ---
	r.Handle("/api/sysinfo/diskio",
		RequireAuth(http.HandlerFunc(HandleGetDiskIO))).Methods("GET")

	// --- Version ---
	r.Handle("/api/version",
		RequireAuth(http.HandlerFunc(HandleGetVersion))).Methods("GET")

	// --- Dashboard metrics (RRD) ---
	r.Handle("/api/dashboard/metrics",
		RequireAuth(http.HandlerFunc(HandleGetDashboardMetrics))).Methods("GET")

	// --- System power (admin only) ---
	r.Handle("/api/system/reboot",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleReboot)))).Methods("POST")
	r.Handle("/api/system/shutdown",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleShutdown)))).Methods("POST")

	// --- Binary self-update (admin only) ---
	r.Handle("/api/binary-update/check",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleCheckBinaryUpdate(appCfg))))).Methods("GET")
	r.Handle("/ws/binary-update-apply",
		RequireAuth(RequireAdmin(http.HandlerFunc(HandleBinaryUpdateApply(appCfg))))).Methods("GET")

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
