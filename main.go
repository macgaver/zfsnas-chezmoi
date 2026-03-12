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
	"strings"
	"path/filepath"
	"syscall"
	"time"
	"zfsnas/handlers"
	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/internal/scheduler"
	"zfsnas/internal/certgen"
	"zfsnas/internal/config"
	"zfsnas/internal/session"
	"zfsnas/system"
)

//go:embed static
var embeddedStatic embed.FS

func main() {
	// ===== Flags =====
	devMode   := flag.Bool("dev", false, "Serve static files from disk (development mode)")
	debugMode := flag.Bool("debug", false, "Enable verbose debug logging (lsblk details, etc.)")
	configDir := flag.String("config", "./config", "Path to config directory")
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

	// ===== Config directory =====
	absConfig, err := filepath.Abs(*configDir)
	if err != nil {
		log.Fatalf("invalid config path: %v", err)
	}
	if err := config.Init(absConfig); err != nil {
		log.Fatalf("failed to init config dir %s: %v", absConfig, err)
	}
	log.Printf("Config directory: %s", absConfig)

	// ===== Audit log =====
	audit.Init(absConfig)

	// ===== Alerts =====
	alerts.Init(absConfig)

	// ===== Scheduler =====
	scheduler.Init(absConfig)

	// ===== App config =====
	appCfg, err := config.LoadAppConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// ===== TLS certificates =====
	certsDir := filepath.Join(absConfig, "certs")
	if err := os.MkdirAll(certsDir, 0750); err != nil {
		log.Fatalf("failed to create certs directory: %v", err)
	}
	certFile := filepath.Join(certsDir, "server.crt")
	keyFile  := filepath.Join(certsDir, "server.key")

	if !certgen.Exists(certFile, keyFile) {
		log.Println("Generating self-signed TLS certificate…")
		if err := certgen.Generate(certFile, keyFile); err != nil {
			log.Fatalf("failed to generate TLS cert: %v", err)
		}
		log.Printf("TLS certificate written to %s", certsDir)
	}

	// ===== Disk I/O poller (5-second samples for live charts) =====
	system.StartDiskIOPoller()

	// ===== Metrics collector (5-minute samples for 24h RRD charts) =====
	system.StartMetricsCollector(absConfig)

	// ===== Daily SMART refresh goroutine =====
	handlers.StartDailySmartRefresh()

	// ===== Health alert poller =====
	handlers.StartHealthPoller(absConfig)

	// ===== Snapshot scheduler =====
	handlers.StartScheduler()

	// ===== Scrub scheduler =====
	handlers.StartScrubScheduler(appCfg)

	// ===== Recycle bin nightly cleaner =====
	system.StartRecycleCleaner(absConfig)

	// ===== Session cleanup goroutine =====
	go func() {
		t := time.NewTicker(30 * time.Minute)
		defer t.Stop()
		for range t.C {
			session.Default.CleanExpired()
		}
	}()

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

	// ===== HTTP Server =====
	addr := fmt.Sprintf(":%d", appCfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	log.Println("Server stopped.")
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
