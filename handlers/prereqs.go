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
	"zfsnas/internal/audit"
	"zfsnas/system"

	"github.com/gorilla/websocket"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
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

	args := append([]string{"apt-get", "install", "-y", "-q"}, missing...)
	cmd := exec.Command("sudo", args...)

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
			send("⚠ Could not load ZFS module automatically: " + err.Error())
			if out != "" {
				send(out)
			}
			send("A reboot is recommended to activate the ZFS kernel module.")
		} else {
			send("✓ ZFS kernel module loaded successfully.")
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

// mustJSON marshals v to JSON, panics on error (only for internal use).
func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}
