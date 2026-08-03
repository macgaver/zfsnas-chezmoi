package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"zfsnas/handlers"
	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/internal/certgen"
	"zfsnas/internal/config"
	"zfsnas/internal/keystore"
	"zfsnas/internal/scheduler"
	"zfsnas/internal/session"
	"zfsnas/internal/termsessions"
	"zfsnas/internal/version"
	"zfsnas/system"
)

//go:embed static
var embeddedStatic embed.FS

// tlsNoiseFilterWriter drops the frequent `http: TLS handshake error …` lines
// (LAN health-check probes, cert scanners connecting with plain TCP or an
// untrusted cert) that otherwise emit one journal line every few minutes and
// bury real server errors. Everything else passes through to stderr unchanged.
type tlsNoiseFilterWriter struct{}

func (tlsNoiseFilterWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "TLS handshake error") {
		return len(p), nil // swallow, but report success so the logger is happy
	}
	return os.Stderr.Write(p)
}

func main() {
	// ===== Flags =====
	devMode := flag.Bool("dev", false, "Serve static files from disk (development mode)")
	debugMode := flag.Bool("debug", false, "Enable verbose debug logging (lsblk details, etc.)")
	configDir := flag.String("config", "./config", "Path to config directory")
	setHTTPSPort := flag.Int("set-https-port", 0, "Persist a new HTTPS port to config and use it this run (1–65535)")
	experimentalMode := flag.Bool("experimental", false, "Enable experimental features (e.g. LXD VM/container management)")
	flag.Parse()

	// ===== Sudo check =====
	sudoStatus := system.CheckSudoAccess()
	if sudoStatus.Type == "none" {
		fmt.Fprintln(os.Stderr, "ERROR: zfsnas requires sudo access.")
		fmt.Fprintln(os.Stderr, "       See SECURITY.md for the recommended hardened sudoers configuration,")
		fmt.Fprintln(os.Stderr, "       or grant full passwordless access with:")
		fmt.Fprintln(os.Stderr, "         <your-user> ALL=(ALL) NOPASSWD: ALL")
		os.Exit(1)
	}
	if sudoStatus.Type == "hardened" && len(sudoStatus.MissingCommands) > 0 {
		fmt.Fprintf(os.Stderr, "WARNING: hardened sudo is configured but %d command(s) are missing from the sudoers rules: %s\n",
			len(sudoStatus.MissingCommands), strings.Join(sudoStatus.MissingCommands, ", "))
		fmt.Fprintln(os.Stderr, "         Some features may not work. See SECURITY.md for the full sudoers template.")
	}

	system.DebugMode = *debugMode
	if *debugMode {
		log.Println("Debug mode enabled — verbose logging active")
	}

	// Keep RSS close to the real working set: return the large one-shot slack
	// left by parsing all RRD JSON at startup, and keep steady-state heap
	// slack modest. No feature impact; tunable via GOGC env.
	startMemoryGovernor()

	// ===== Config directory =====
	absConfig, err := filepath.Abs(*configDir)
	if err != nil {
		log.Fatalf("invalid config path: %v", err)
	}
	if err := config.Init(absConfig); err != nil {
		log.Fatalf("failed to init config dir %s: %v", absConfig, err)
	}
	log.Printf("Config directory: %s", absConfig)

	// ===== Encryption keystore =====
	if err := keystore.Init(absConfig); err != nil {
		log.Fatalf("failed to init keystore: %v", err)
	}

	// ===== Audit log =====
	audit.Init(absConfig)

	// ===== Alerts =====
	alerts.Init(absConfig)
	alertsHub := alerts.NewAlertsHub()
	alerts.SetWSHub(alertsHub)

	// ===== Scheduler =====
	scheduler.Init(absConfig)

	// ===== App config =====
	appCfg, err := config.LoadAppConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	appCfg.ConfigDir = absConfig

	// ===== Persistent session store =====
	// Rehydrate any sessions persisted from a previous run so users
	// stay logged in across `systemctl restart zfsnas`. Failures are
	// non-fatal — if the file is missing or corrupted the session map
	// just starts empty and the user logs in once.
	if loaded, err := session.Default.BindPersistence(absConfig); err != nil {
		log.Printf("[sessions] persistence init failed: %v — sessions will not survive restart", err)
	} else if loaded > 0 {
		log.Printf("[sessions] restored %d session(s) from disk", loaded)
	}

	// Terminal sessions die when their owning web session does.
	termsessions.Default.Configure(appCfg.TerminalScrollbackKB, appCfg.TerminalMaxSessionsPerUser)
	session.Default.OnEvict(func(userID, reason string) {
		termsessions.Default.TerminateUser(userID, termsessions.ReasonSessionExpire)
	})

	// ===== --set-https-port override =====
	if *setHTTPSPort != 0 {
		if *setHTTPSPort < 1 || *setHTTPSPort > 65535 {
			fmt.Fprintf(os.Stderr, "ERROR: --set-https-port must be between 1 and 65535 (got %d)\n", *setHTTPSPort)
			os.Exit(1)
		}
		appCfg.Port = *setHTTPSPort
		if err := config.SaveAppConfig(appCfg); err != nil {
			log.Fatalf("failed to save config with new port: %v", err)
		}
		log.Printf("HTTPS port updated to %d and saved to config.", *setHTTPSPort)
	}

	// ===== TLS certificates =====
	certsDir := filepath.Join(absConfig, "certs")
	if err := os.MkdirAll(certsDir, 0750); err != nil {
		log.Fatalf("failed to create certs directory: %v", err)
	}

	// Migrate legacy server.crt/server.key → self-signed.crt/self-signed.key
	legacyCert := filepath.Join(certsDir, "server.crt")
	legacyKey := filepath.Join(certsDir, "server.key")
	selfCert := filepath.Join(certsDir, "self-signed.crt")
	selfKey := filepath.Join(certsDir, "self-signed.key")
	if certgen.Exists(legacyCert, legacyKey) && !certgen.Exists(selfCert, selfKey) {
		log.Println("Migrating server.crt/server.key → self-signed.crt/self-signed.key")
		os.Rename(legacyCert, selfCert)
		os.Rename(legacyKey, selfKey)
	}

	if !certgen.Exists(selfCert, selfKey) {
		log.Println("Generating self-signed TLS certificate…")
		if err := certgen.Generate(selfCert, selfKey); err != nil {
			log.Fatalf("failed to generate TLS cert: %v", err)
		}
		log.Printf("TLS certificate written to %s", certsDir)
	}

	// Determine active cert
	activeName := appCfg.ActiveCertName
	if activeName == "" {
		activeName = "self-signed"
	}
	certFile := filepath.Join(certsDir, activeName+".crt")
	keyFile := filepath.Join(certsDir, activeName+".key")
	if !certgen.Exists(certFile, keyFile) {
		log.Printf("WARNING: active cert %q not found, falling back to self-signed", activeName)
		certFile = selfCert
		keyFile = selfKey
	}

	// ===== Disk I/O poller (5-second samples for live charts) =====
	system.StartDiskIOPoller()

	// ===== Per-process CPU poller (3-second samples for top-bar gauge) =====
	system.StartCpuProcsPoller()

	// ===== Per-process memory poller (5-second samples for top-bar MEM gauge) =====
	system.StartMemProcsPoller()

	// ===== Metrics collector (5-minute samples for 24h RRD charts) =====
	system.StartMetricsCollector(absConfig)

	// ===== Capacity collector (5-minute samples, 3-tier RRD up to 5 years) =====
	system.StartCapacityCollector(absConfig)

	// ===== Wear-out collector (daily per-SSD SMART wear-out %, long-term RRD;
	//       not graphed — for later SSD end-of-life estimation) =====
	system.StartWearoutCollector(absConfig)

	// ===== Global performance collector (CPU/mem/net/disk, 3-tier RRD up to 5 years) =====
	system.StartGlobalPerfCollector(absConfig)

	// ===== Pool performance collector (per-pool disk I/O, 3-tier RRD up to 5 years) =====
	system.StartPoolPerfCollector(absConfig)

	// ===== LXD VM/Container metrics collector (v6.4.28; gated by LXDMetricsEnabled) =====
	// Always start the goroutine; on each tick it consults getEnabled() to
	// decide whether to actually scrape. This lets the user flip the
	// Virtualization toggle at runtime without restarting the service.
	system.StartLXDMetricsCollector(absConfig, func() bool {
		c, _ := config.LoadAppConfig()
		return c != nil && c.LXDMetricsEnabled && system.LXDAvailable()
	})
	// Initial orphan sweep — catches RRD files for instances that were
	// deleted while the portal was offline.
	go func() {
		time.Sleep(10 * time.Second)
		if system.LXDAvailable() {
			system.SweepOrphanLXDMetrics()
		}
	}()

	// ===== LXD VM/Container state watcher (v6.5.3) =====
	// Polls instance statuses every 10s and writes an audit-log entry whenever
	// a VM or container changes state, including out-of-band changes (CLI
	// shutdown, qemu crash, host reboot recovery, autostart on boot). Costs
	// nothing on hosts that haven't enabled the feature — the loop short-
	// circuits when LXDAvailable() is false.
	//
	// Wire the alerts.Send dispatch for "VM stopped unexpectedly" — the
	// callback lives on the system package so we don't create an import
	// cycle (alerts already imports system via the interlink relay sub).
	system.OnVMUnexpectedStop = func(name, details, cause string) {
		subject := "[ZFS NAS] " + name + " stopped unexpectedly"
		body := "Instance: " + name + "\nState change: " + details + "\nDetected cause: " + cause + "\n"
		if err := alerts.Send(alerts.EventVMUnexpectedStop, subject, "vm_unexpected_stop", body); err != nil {
			log.Printf("[alerts] vm_unexpected_stop send failed for %s: %v", name, err)
		}
	}
	system.StartLXDStateWatcher()

	// Pre-shutdown UPS notice. Gated on the SAME subscription as the other UPS
	// notifications (ups_power_changed), so turning UPS alerts on for a target
	// covers "AC lost", "AC restored" and "shutting down now" as one decision.
	//
	// SendSync, not Send: Send returns while its goroutines are still talking to
	// SMTP/ntfy, and the caller halts the machine the moment we return here.
	// Partial delivery counts as success — one target through is what matters
	// when the battery is nearly flat.
	system.OnUPSShutdown = func(upsName, summary, details string) error {
		subject := "[ZFS NAS] UPS shutdown: " + upsName
		body := "The server is shutting down because " + summary + ".\n\n" +
			"UPS: " + upsName + "\n" + details + "\n\n" +
			"This is the last message before the machine halts.\n"
		attempted, delivered, err := alerts.SendSync(
			alerts.EventUPSPowerChanged, subject, "ups_shutdown", body, 10*time.Second)
		if delivered > 0 {
			log.Printf("[alerts] ups_shutdown delivered to %d/%d target(s)", delivered, attempted)
			return nil
		}
		if attempted == 0 {
			return nil // nobody subscribed to UPS notifications — nothing to wait for
		}
		return err
	}

	// ===== Daily SMART refresh goroutine =====
	handlers.StartDailySmartRefresh()

	// ===== Health alert poller =====
	handlers.StartHealthPoller(absConfig)

	// ===== InterLink peer connectivity watcher (5-min ping + down/up alerts) =====
	handlers.StartInterlinkWatcher(appCfg)

	// ===== Auto-load encryption keys for encrypted pools =====
	autoLoadEncryptionKeys(absConfig)

	// ===== Snapshot scheduler =====
	handlers.StartScheduler(appCfg)

	// ===== External storage rsync scheduler + mount janitor (v6.7.7) =====
	handlers.StartRsyncScheduler(appCfg)
	go func() {
		// Re-mount persistent external storages after boot; a dead remote
		// only logs, it must never block startup.
		for id, err := range system.MountAllPersistent(absConfig, appCfg.ExternalStorages) {
			log.Printf("[extstorage] persistent mount %s failed: %v", id, err)
		}
	}()

	// ===== LXD snapshot + backup schedulers (v6.5.19+) =====
	handlers.StartLXDSnapshotScheduler(appCfg)
	handlers.StartLXDBackupScheduler(appCfg)

	// ===== Compose stack auto-update scheduler =====
	handlers.StartComposeAutoUpdater(appCfg)

	// v6.7.13 — coordinated ZFS snapshots for all-ZFS MergerFS unions.
	handlers.StartMergerFSSnapshotScheduler(appCfg)

	// ===== Scrub scheduler =====
	handlers.StartScrubScheduler(appCfg)

	// ===== TreeMap scheduler =====
	handlers.StartTreeMapScheduler(appCfg)

	// ===== Auto-update scheduler =====
	handlers.StartAutoUpdateScheduler(appCfg)

	// ===== Recycle bin nightly cleaner =====
	system.StartRecycleCleaner(absConfig)

	// ===== One-time smb.conf deduplication (cleans up duplicate managed sections
	//       that may have been written by older versions of the software) =====
	if err := system.DeduplicateSMBConf(); err != nil {
		log.Printf("WARNING: smb.conf deduplication: %v", err)
	}

	// ===== Repair smb.conf files written by v6.7.15–v6.7.22, which reference
	//       the zfsacl VFS module. That module does not exist on Debian or
	//       Ubuntu, so smbd refused every connection to the affected shares.
	//       The managed block below is regenerated anyway; this also cleans
	//       copies sitting outside the managed markers. =====
	if err := system.RepairSMBConfZfsacl(); err != nil {
		log.Printf("WARNING: smb.conf zfsacl repair: %v", err)
	}

	// ===== Reapply smb.conf and /etc/exports from JSON on startup =====
	// This keeps the config files in sync with the JSON store even if a
	// previous write was interrupted or the binary was updated.
	if shares, err := system.ListSMBShares(absConfig); err == nil {
		if err := system.SaveSMBShares(absConfig, shares); err != nil {
			log.Printf("WARNING: startup smb.conf reapply: %v", err)
		}
	}
	if nfsShares, err := system.ListNFSShares(absConfig); err == nil {
		if err := system.SaveNFSShares(absConfig, nfsShares); err != nil {
			log.Printf("WARNING: startup /etc/exports reapply: %v", err)
		}
	}

	// ===== UPS RRD collector (5-min battery/runtime/load samples) =====
	system.StartUPSRRDCollector(absConfig, appCfg)

	// ===== UPS shutdown watcher =====
	go system.StartUPSShutdownWatcher(appCfg)

	// ===== UPS power-transition notification watcher =====
	handlers.StartUPSPowerWatcher(appCfg)

	// ===== Services discovery (v6.8.1) =====
	// Gated internally on appCfg.ServiceDiscoveryOn(), so toggling the setting
	// takes effect on the next tick without a restart.
	handlers.StartServiceDiscovery(appCfg)

	handlers.SetPortalPort(appCfg.Port)

	// ===== Session cleanup goroutine =====
	go func() {
		t := time.NewTicker(30 * time.Minute)
		defer t.Stop()
		for range t.C {
			session.Default.CleanExpired()
		}
	}()

	// ===== Experimental features =====
	//
	// CRITICAL: the LXD probe + helpers below must NOT block the main
	// goroutine. They shell out to `incus list`, `sudo ln -sf`, and
	// InterLink peers — any of which can wedge for minutes on a sick
	// daemon, a stuck sudoers prompt, or a network-isolated peer. If
	// that happens before line 357's listener setup, the HTTPS server
	// never opens its socket; systemd sees the process running, the
	// log shows "Experimental mode enabled" + maybe a sudo call, but
	// the user can't reach :8443. Moving everything into a goroutine
	// lets the listener come up immediately and the LXD bits fill in
	// asynchronously. (6.5.26 fix.)
	// The --experimental flag is legacy as of 6.6.26 — VMs & Containers is now a
	// first-class feature on every install. We still honour the flag for the
	// /api/version "experimental_mode" field, but it no longer gates anything.
	if *experimentalMode {
		version.SetExperimental(true)
		log.Println("Experimental mode enabled (note: no longer required — VMs & Containers is available on all installs).")
	}

	// VMs & Containers detection. Driven purely by whether the `incus` binary is
	// present — NOT by --experimental (6.6.26 unlock). On a host with no Incus
	// installed we skip the whole block so a fresh box never probes a
	// non-existent daemon or shows the "Incus daemon not responding" banner.
	// Without this, a non-experimental host with Incus installed/enabled left
	// the cached lxdAvailable=false, so /api/lxd/status and the enable status
	// reported "not available" even though Incus was running.
	if system.IncusInstalled() {
		// Health watchdog runs even if the first probe in the goroutine
		// below fails — that's the whole point: we want the UI to
		// recover automatically when the daemon comes back, without
		// needing a portal restart.
		system.StartIncusHealthWatcher(func(s system.IncusHealthState) {
			payload := map[string]any{
				"kind":       "incus_stuck",
				"persistent": true,
				"stuck":      s.Stuck,
				"subject":    "Incus daemon not responding",
				"details":    "ZNAS' `incus` commands are timing out. VMs & Containers actions will hang until the daemon recovers.",
				"docs_url":   "https://linuxcontainers.org/incus/docs/main/howto/troubleshoot/",
				"time":       s.ChangedAt.Format(time.RFC3339),
			}
			if !s.Stuck {
				payload["subject"] = "Incus daemon recovered"
				payload["details"] = "`incus` commands are responding again."
			}
			handlers.BroadcastAlertJSON(payload)
		})
		go func() {
			if !system.LXDAvailableTimeout(8 * time.Second) {
				log.Println("WARNING: Incus not accessible. Ensure the ZNAS user is in the '" + system.HVUserGroup + "' group. VMs & Containers feature disabled.")
				return
			}
			log.Println("Incus detected and accessible — VMs & Containers feature enabled.")
			handlers.SetLXDAvailable(true)
			// Ensure cross-distro OVMF firmware symlinks exist (Ubuntu ↔ Debian naming).
			system.EnsureOVMFCompat()
			// Sync Incus trust with all InterLink peers that don't have it
			// confirmed yet. (Field name kept as LXDTrusted for config-file
			// backwards compat with 6.5.1 and earlier installs.)
			for i := range appCfg.InterLink {
				ls := &appCfg.InterLink[i]
				if ls.LXDTrusted {
					continue
				}
				if err := system.LXDSyncInterlinkTrustForPeer(*ls, ls.ID); err != nil {
					log.Printf("Incus trust auto-sync for %s: %v", ls.Hostname, err)
					continue
				}
				ls.LXDTrusted = true
				config.SaveAppConfig(appCfg) //nolint:errcheck
				log.Printf("Incus trust auto-synced for %s", ls.Hostname)
			}
		}()
	}

	// ===== Static file system =====
	var staticFS fs.FS
	var readFile func(string) ([]byte, error)

	if *devMode {
		log.Println("Dev mode: serving static files from disk")
		staticFS = os.DirFS("static")
		readFile = func(name string) ([]byte, error) {
			return os.ReadFile(filepath.Join("static", name))
		}
	} else {
		sub, err := fs.Sub(embeddedStatic, "static")
		if err != nil {
			log.Fatalf("failed to create static sub-fs: %v", err)
		}
		staticFS = sub
		readFile = func(name string) ([]byte, error) {
			return embeddedStatic.ReadFile("static/" + name)
		}
	}

	// ===== Router =====
	router := handlers.NewRouter(staticFS, readFile, appCfg)

	// ===== First-run check =====
	users, err := config.LoadUsers()
	if err != nil {
		log.Fatalf("failed to load users: %v", err)
	}
	ip := localIP()
	if len(users) == 0 {
		log.Println("No users found — first-run setup required.")
		log.Printf("Open https://%s:%d/setup in your browser.", ip, appCfg.Port)
	} else {
		log.Printf("Loaded %d user(s).", len(users))
		log.Printf("Open https://%s:%d in your browser.", ip, appCfg.Port)
	}

	// ===== Interlink relay-mode notification subscribers =====
	// When global relay mode is enabled, dial /ws/alerts on every linked
	// server so admins on this box see in-app toasts from across the fleet.
	alerts.ReconcileLinkedServerSubscribers(appCfg)

	// ===== HTTP Server =====
	// Route http.Server's internal error logging through a filter that drops
	// the noisy "TLS handshake error" probe lines (keeps real errors).
	httpErrLog := log.New(tlsNoiseFilterWriter{}, "", log.LstdFlags)
	addr := fmt.Sprintf(":%d", appCfg.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ErrorLog:          httpErrLog,
		ReadHeaderTimeout: 15 * time.Second,
		WriteTimeout:      300 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Optional second listener on the standard HTTPS port 443 — Settings →
	// Server Port → "Also bind port 443". Binding a privileged port from the
	// non-root service account requires CAP_NET_BIND_SERVICE (granted to the
	// systemd unit via AmbientCapabilities). If that capability is missing the
	// bind fails; we log a clear warning and leave the primary listener up.
	var srv443 *http.Server
	if appCfg.BindPort443 && appCfg.Port != 443 {
		srv443 = &http.Server{
			Addr:              ":443",
			Handler:           router,
			ErrorLog:          httpErrLog,
			ReadHeaderTimeout: 15 * time.Second,
			WriteTimeout:      300 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			log.Printf("HTTPS server also listening on :443")
			if err := srv443.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Printf("WARNING: could not bind port 443 (%v) — the zfsnas.service unit may be missing AmbientCapabilities=CAP_NET_BIND_SERVICE; the portal stays reachable on :%d", err, appCfg.Port)
			}
		}()
	}

	// Graceful shutdown on SIGINT / SIGTERM.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("HTTPS server listening on %s", addr)
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-stop
	log.Println("Shutting down…")
	// Flush the latest session activity heartbeats to disk before exit so
	// a clean restart doesn't lose the LastActivityAt timestamps the
	// inactivity-timeout enforcement depends on.
	session.Default.FlushNow()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	if srv443 != nil {
		srv443.Shutdown(ctx)
	}
	log.Println("Server stopped.")
}

// autoLoadEncryptionKeys scans all pools and datasets, loads any managed
// encryption key whose keystatus is "unavailable", then mounts the dataset.
// It also mounts any encrypted dataset whose key is already available but not yet mounted.
func autoLoadEncryptionKeys(configDir string) {
	// --- Pass 1: load managed keys for locked datasets ---
	keys, _ := config.LoadEncryptionKeys()
	if len(keys) > 0 {
		keyMap := make(map[string]string, len(keys))
		for _, k := range keys {
			keyMap[k.ID] = keystore.KeyFilePath(k.ID)
		}

		type target struct{ name string }
		var targets []target
		pools, _ := system.GetAllPools()
		for _, p := range pools {
			if p.Encrypted && p.KeyLocked {
				targets = append(targets, target{p.Name})
			}
		}
		datasets, _ := system.ListAllDatasets()
		for _, d := range datasets {
			if d.Encrypted && d.KeyLocked {
				targets = append(targets, target{d.Name})
			}
		}
		for _, t := range targets {
			loc := system.GetKeyLocation(t.name)
			if !strings.HasPrefix(loc, "file://") {
				continue
			}
			base := filepath.Base(strings.TrimPrefix(loc, "file://"))
			id := strings.TrimSuffix(base, ".key")
			keyPath, ok := keyMap[id]
			if !ok || !keystore.Exists(id) {
				log.Printf("encryption: key %s for %s not found — will remain locked", id, t.name)
				continue
			}
			if err := system.LoadPoolKey(t.name, keyPath); err != nil {
				log.Printf("encryption: failed to load key for %s: %v", t.name, err)
				continue
			}
			log.Printf("encryption: loaded key for %s", t.name)
			if err := system.MountDataset(t.name); err != nil {
				log.Printf("encryption: mount %s: %v", t.name, err)
			}
		}
	}

	// --- Pass 2: mount any encrypted dataset whose key is available but not yet mounted ---
	// Runs regardless of managed keys — handles pools imported with their own keylocation.
	datasets, _ := system.ListAllDatasets()
	for _, d := range datasets {
		if d.Encrypted && !d.KeyLocked && !d.Mounted &&
			d.Mountpoint != "none" && d.Mountpoint != "legacy" && d.CanMount != "off" {
			log.Printf("encryption: mounting unlocked-but-unmounted dataset %s", d.Name)
			if err := system.MountDataset(d.Name); err != nil {
				log.Printf("encryption: mount %s: %v", d.Name, err)
			}
		}
	}
}

// localIP returns the primary non-loopback IPv4 address of the host.
// Falls back to "localhost" if none can be determined.
func localIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "localhost"
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)
	return addr.IP.String()
}
