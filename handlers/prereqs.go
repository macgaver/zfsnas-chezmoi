package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"

	"github.com/gorilla/websocket"
)

// aptInstallMu serialises all apt-get/binary installations so that two
// concurrent requests cannot run package managers at the same time.
var aptInstallMu sync.Mutex

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // non-browser clients (curl, etc.)
		}
		return strings.HasSuffix(origin, "://"+r.Host)
	},
}

// HandleCheckPrereqs returns the status of all required packages and the systemd service.
func HandleCheckPrereqs(w http.ResponseWriter, r *http.Request) {
	pkgs := system.CheckPackages()

	// Flag zfsutils-linux if its version is below 2.3
	zfsWarn := false
	for _, p := range pkgs {
		if p.Name == "zfsutils-linux" && p.Installed && p.Version != "" {
			zfsWarn = system.ZfsutilsBelowMinVersion(p.Version, 2, 3)
			break
		}
	}

	// Warn if zfsutils-linux is installed but the kernel module is not loaded.
	zfsModuleWarn := false
	for _, p := range pkgs {
		if p.Name == "zfsutils-linux" && p.Installed {
			zfsModuleWarn = !system.ZfsModuleLoaded()
			break
		}
	}

	jsonOK(w, map[string]interface{}{
		"packages":          pkgs,
		"service_installed": system.IsServiceInstalled(),
		"zfsutils_warn":     zfsWarn,
		"zfs_module_warn":   zfsModuleWarn,
		"sudo_access":       system.CheckSudoAccess(),
	})
}

// HandleOpStatus returns whether a package install/uninstall is currently running.
// The frontend polls this after a page refresh to show a "running" indicator.
func HandleOpStatus(w http.ResponseWriter, r *http.Request) {
	locked := !aptInstallMu.TryLock()
	if !locked {
		aptInstallMu.Unlock()
	}
	jsonOK(w, map[string]bool{"running": locked})
}

// HandleInstallPrereqs upgrades the HTTP connection to WebSocket and streams
// the output of `sudo apt-get install` for missing packages.
func HandleInstallPrereqs(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	send := func(line string) {
		conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]interface{}{
			"line": line,
		}))
	}
	done := func(success bool, msg string) {
		conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]interface{}{
			"done":    true,
			"success": success,
			"message": msg,
		}))
	}

	pkgs := system.CheckPackages()
	missing := system.MissingPackages(pkgs)
	if len(missing) == 0 {
		send("All packages are already installed.")
		done(true, "nothing to do")
		return
	}

	// Track whether zfsutils-linux is being freshly installed.
	zfsWasInstalled := false
	for _, m := range missing {
		if m == "zfsutils-linux" {
			zfsWasInstalled = true
			break
		}
	}

	send(fmt.Sprintf("Running: sudo apt-get install -y %s", strings.Join(missing, " ")))
	send("─────────────────────────────────────────")

	aptInstallMu.Lock()
	defer aptInstallMu.Unlock()

	args := append([]string{"apt-get", "install", "-y", "-q"}, missing...)
	cmd := exec.Command("sudo", args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")

	// Pipe both stdout and stderr to the client.
	pr, pw, err := os.Pipe()
	if err != nil {
		done(false, "failed to create pipe")
		return
	}
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		pw.Close()
		pr.Close()
		send("Error: " + err.Error())
		done(false, err.Error())
		return
	}
	pw.Close()

	buf := make([]byte, 4096)
	for {
		n, err := pr.Read(buf)
		if n > 0 {
			lines := strings.Split(string(buf[:n]), "\n")
			for _, l := range lines {
				if l != "" {
					send(l)
				}
			}
		}
		if err != nil {
			break
		}
	}

	cmdErr := cmd.Wait()
	send("─────────────────────────────────────────")

	sess := MustSession(r)
	if cmdErr != nil {
		send("Installation failed: " + cmdErr.Error())
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionInstallPrereqs,
			Result:  audit.ResultError,
			Details: cmdErr.Error(),
		})
		done(false, cmdErr.Error())
		return
	}

	send("Installation completed successfully.")

	// If zfsutils-linux was just installed, attempt to load the kernel module.
	if zfsWasInstalled {
		send("─────────────────────────────────────────")
		send("Loading ZFS kernel module (modprobe zfs)…")
		if out, err := system.LoadZfsModule(); err != nil {
			send("Warning: could not load ZFS module automatically: " + err.Error())
			if out != "" {
				send(out)
			}
			send("A reboot is recommended to activate the ZFS kernel module.")
		} else {
			send("ZFS kernel module loaded successfully.")
		}
	}
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionInstallPrereqs,
		Result:  audit.ResultOK,
		Details: "installed: " + strings.Join(missing, ", "),
	})
	done(true, "packages installed")
}

// HandleInstallService registers and enables the zfsnas systemd service.
func HandleInstallService(w http.ResponseWriter, r *http.Request) {
	// Resolve the current binary path.
	execPath, err := os.Executable()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "cannot resolve binary path: "+err.Error())
		return
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "cannot resolve symlink: "+err.Error())
		return
	}
	workDir := filepath.Dir(execPath)

	// Current OS user.
	currentUser, err := user.Current()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "cannot get current user: "+err.Error())
		return
	}

	unit := fmt.Sprintf(`[Unit]
Description=ZFS NAS Management Portal
After=network.target

[Service]
Type=simple
User=%s
WorkingDirectory=%s
ExecStart=%s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`, currentUser.Username, workDir, execPath)

	// Write the unit file via sudo tee.
	tee := exec.Command("sudo", "tee", "/etc/systemd/system/zfsnas.service")
	tee.Stdin = strings.NewReader(unit)
	if out, err := tee.CombinedOutput(); err != nil {
		jsonErr(w, http.StatusInternalServerError,
			"failed to write unit file: "+string(out))
		return
	}

	// Reload and enable.
	if out, err := exec.Command("sudo", "systemctl", "daemon-reload").CombinedOutput(); err != nil {
		jsonErr(w, http.StatusInternalServerError,
			"daemon-reload failed: "+string(out))
		return
	}
	if out, err := exec.Command("sudo", "systemctl", "enable", "zfsnas").CombinedOutput(); err != nil {
		jsonErr(w, http.StatusInternalServerError,
			"systemctl enable failed: "+string(out))
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionInstallService,
		Result:  audit.ResultOK,
		Details: fmt.Sprintf("unit: %s, user: %s", execPath, currentUser.Username),
	})

	jsonOK(w, map[string]string{
		"message": fmt.Sprintf("Service installed and enabled. ZFS NAS will start on boot as user %s.", currentUser.Username),
	})
}

// HandleInstallPackage installs a single optional package from an allowlist.
// Body: { "package": "targetcli-fb" }
// The allowlist prevents arbitrary package installation.
func HandleInstallPackage(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Package string `json:"package"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		req.Package = strings.TrimSpace(req.Package)

		allowlist := map[string]bool{
			"targetcli-fb":         true,
			"minio":                true,
			"nut":                  true,
			"hdparm":               true,
			"proxmox-import-tools": true,
		}
		if !allowlist[req.Package] {
			jsonErr(w, http.StatusBadRequest, "package not in allowlist")
			return
		}

		sess := MustSession(r)

		// Serialise all installs — prevents concurrent apt/binary operations.
		aptInstallMu.Lock()
		defer aptInstallMu.Unlock()

		// MinIO uses a custom binary installation (not apt-get).
		if req.Package == "minio" {
			if err := system.InstallMinIO(); err != nil {
				jsonErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			appCfg.MinIO.HideNav = false
			_ = config.SaveAppConfig(appCfg)
			audit.Log(audit.Entry{
				User:    sess.Username,
				Role:    sess.Role,
				Action:  audit.ActionInstallPrereqs,
				Result:  audit.ResultOK,
				Details: "installed: minio, mc",
			})
			jsonOK(w, map[string]string{"message": "minio installed"})
			return
		}

		if req.Package == "nut" {
			// Pre-create /etc/nut/nut.conf with MODE=none before apt-get so that
			// NUT's post-install scripts do not attempt to start the daemon (which
			// would block the request while systemd waits for a non-existent UPS).
			exec.Command("sudo", "mkdir", "-p", "/etc/nut").Run()
			nutConf := "MODE=none\n"
			preConf := exec.Command("sudo", "tee", "/etc/nut/nut.conf")
			preConf.Stdin = strings.NewReader(nutConf)
			preConf.Run()

			nutCmd := exec.Command("sudo",
				"apt-get", "install", "-y", "-q",
				"-o", "Dpkg::Options::=--force-confold",
				"nut", "nut-client")
			nutCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
			out, err := nutCmd.CombinedOutput()
			if err != nil {
				jsonErr(w, http.StatusInternalServerError, string(out))
				return
			}
			// Reset to a clean slate — ensures no stale shutdown policy or device
			// settings from a previous install survive a reinstall.
			appCfg.UPS = config.UPSConfig{Enabled: true}

			// Auto-detect and configure an attached UPS across all bus types.
			detected, detErr := system.DetectAndConfigureUPS("")
			detMsg := ""
			// Always save the generated monitor password.
			appCfg.UPS.MonitorPassword = detected.MonitorPassword
			if detErr != nil {
				detMsg = "installed (detection error: " + detErr.Error() + ")"
			} else if detected.Name != "" {
				appCfg.UPS.UPSName = detected.Name
				appCfg.UPS.Driver = detected.Driver
				appCfg.UPS.Port = detected.Port
				appCfg.UPS.RawUPSConf = detected.ScannerOutput
				detMsg = fmt.Sprintf("detected: %s (%s @ %s)", detected.Name, detected.Driver, detected.Port)
			} else {
				detMsg = "installed (no UPS detected on any bus — infrastructure configured)"
			}

			if err := config.SaveAppConfig(appCfg); err != nil {
				jsonErr(w, http.StatusInternalServerError, "save config: "+err.Error())
				return
			}
			audit.Log(audit.Entry{
				User:    sess.Username,
				Role:    sess.Role,
				Action:  audit.ActionInstallPrereqs,
				Result:  audit.ResultOK,
				Details: "installed: nut, nut-client; " + detMsg,
			})
			resp := map[string]interface{}{
				"message":  "nut installed",
				"detected": detected,
			}
			jsonOK(w, resp)
			return
		}

		// Proxmox import tools installs four packages together: sshpass and
		// qemu-utils handle the SSH+image conversion pipeline; ntfs-3g and
		// python3-hivex are used by fixUEFIWindows() after the disk lands to
		// clear the NTFS dirty bit and patch BCD so imported Windows guests
		// don't boot-loop into Windows RE every other start (v6.5.2+).
		if req.Package == "proxmox-import-tools" {
			pkgCmd := exec.Command("sudo", "apt-get", "install", "-y", "-q",
				"sshpass", "qemu-utils", "ntfs-3g", "python3-hivex")
			pkgCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
			out, err := pkgCmd.CombinedOutput()
			if err != nil {
				jsonErr(w, http.StatusInternalServerError, string(out))
				return
			}
			audit.Log(audit.Entry{
				User:    sess.Username,
				Role:    sess.Role,
				Action:  audit.ActionInstallPrereqs,
				Result:  audit.ResultOK,
				Details: "installed: sshpass, qemu-utils, ntfs-3g, python3-hivex",
			})
			jsonOK(w, map[string]string{"message": "proxmox-import-tools installed"})
			return
		}

		pkgCmd := exec.Command("sudo", "apt-get", "install", "-y", "-q", req.Package)
		pkgCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		out, err := pkgCmd.CombinedOutput()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, string(out))
			return
		}

		if req.Package == "targetcli-fb" {
			appCfg.ISCSI.HideNav = false
			_ = config.SaveAppConfig(appCfg)
			_ = system.StartISCSIService()
		}

		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionInstallPrereqs,
			Result:  audit.ResultOK,
			Details: "installed: " + req.Package,
		})

		jsonOK(w, map[string]string{"message": req.Package + " installed"})
	}
}

// HandleUninstallPackage stops and removes an optional feature from an allowlist.
// Body: { "package": "targetcli-fb" | "minio" }
func HandleUninstallPackage(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if applianceBlock(w) {
			return
		}
		var req struct {
			Package string `json:"package"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		req.Package = strings.TrimSpace(req.Package)

		sess := MustSession(r)

		aptInstallMu.Lock()
		defer aptInstallMu.Unlock()

		switch req.Package {
		case "minio":
			if err := system.UninstallMinIO(); err != nil {
				jsonErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			appCfg.MinIO.Enabled = false
			appCfg.MinIO.TLS = false
			// Re-hide the nav entry so an uninstalled feature doesn't linger in
			// the sidebar; install sets HideNav=false to reveal it.
			appCfg.MinIO.HideNav = true
			_ = config.SaveAppConfig(appCfg)
			audit.Log(audit.Entry{
				User:    sess.Username,
				Role:    sess.Role,
				Action:  audit.ActionInstallPrereqs,
				Result:  audit.ResultOK,
				Details: "uninstalled: minio, mc",
			})
		case "targetcli-fb":
			if err := system.UninstallISCSI(); err != nil {
				jsonErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			appCfg.ISCSI.Enabled = false
			// Re-hide the nav entry so an uninstalled feature doesn't linger in
			// the sidebar; install sets HideNav=false to reveal it.
			appCfg.ISCSI.HideNav = true
			_ = config.SaveAppConfig(appCfg)
			audit.Log(audit.Entry{
				User:    sess.Username,
				Role:    sess.Role,
				Action:  audit.ActionInstallPrereqs,
				Result:  audit.ResultOK,
				Details: "uninstalled: targetcli-fb",
			})
		case "nut":
			if err := system.UninstallNUT(); err != nil {
				jsonErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			appCfg.UPS = config.UPSConfig{}
			if err := config.SaveAppConfig(appCfg); err != nil {
				jsonErr(w, http.StatusInternalServerError, "save config: "+err.Error())
				return
			}
			audit.Log(audit.Entry{
				User:    sess.Username,
				Role:    sess.Role,
				Action:  audit.ActionInstallPrereqs,
				Result:  audit.ResultOK,
				Details: "uninstalled: nut, nut-client; /etc/nut removed",
			})
		case "hdparm":
			out, err := exec.Command("sudo", "apt-get", "remove", "-y", "hdparm").CombinedOutput()
			if err != nil {
				jsonErr(w, http.StatusInternalServerError, string(out))
				return
			}
			system.ForgetBinaryPresence("hdparm")
			audit.Log(audit.Entry{
				User:    sess.Username,
				Role:    sess.Role,
				Action:  audit.ActionInstallPrereqs,
				Result:  audit.ResultOK,
				Details: "uninstalled: hdparm",
			})
		default:
			jsonErr(w, http.StatusBadRequest, "package not in allowlist")
			return
		}

		jsonOK(w, map[string]string{"message": req.Package + " uninstalled"})
	}
}

// mustJSON marshals v to JSON, panics on error (only for internal use).
func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}
