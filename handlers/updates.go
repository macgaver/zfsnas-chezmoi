package handlers

import (
	"bufio"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"zfsnas/internal/audit"

	"github.com/gorilla/websocket"
)

// HandleCheckUpdates runs `apt-get update` then returns the list of packages
// that would be upgraded by `apt-get upgrade` (excludes kept-back packages).
func HandleCheckUpdates(w http.ResponseWriter, r *http.Request) {
	// Refresh package index.
	exec.Command("sudo", "apt-get", "update", "-qq").Run()

	// Use --simulate to find what apt-get upgrade would actually install.
	// Kept-back packages (those requiring full-upgrade) are excluded.
	out, err := exec.Command("apt-get", "--simulate", "upgrade").Output()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "apt-get simulate failed: "+err.Error())
		return
	}

	var pkgs []map[string]string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		// Only "Inst" lines represent packages that will be installed/upgraded.
		// Format: Inst pkg-name [old-ver] (new-ver suite)
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		name := parts[1]
		// Extract new version from parentheses, e.g. "(1.2.3 suite)"
		version := ""
		for _, p := range parts[2:] {
			if strings.HasPrefix(p, "(") {
				version = strings.TrimPrefix(p, "(")
				break
			}
		}
		pkgs = append(pkgs, map[string]string{"name": name, "version": version})
	}
	if pkgs == nil {
		pkgs = []map[string]string{}
	}

	jsonOK(w, map[string]interface{}{
		"count":    len(pkgs),
		"packages": pkgs,
	})
}

// HandleApplyUpdates upgrades the HTTP connection to WebSocket and streams
// the output of `sudo apt-get upgrade -y`.
func HandleApplyUpdates(w http.ResponseWriter, r *http.Request) {
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

	send("Running: sudo apt-get upgrade -y")
	send("─────────────────────────────────────────")

	cmd := exec.Command("sudo", "apt-get", "upgrade", "-y")
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")

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
		done(false, err.Error())
		return
	}
	pw.Close()

	buf := make([]byte, 4096)
	for {
		n, readErr := pr.Read(buf)
		if n > 0 {
			lines := strings.Split(string(buf[:n]), "\n")
			for _, l := range lines {
				if strings.TrimSpace(l) != "" {
					send(l)
				}
			}
		}
		if readErr != nil {
			break
		}
	}

	cmdErr := cmd.Wait()
	send("─────────────────────────────────────────")

	sess := MustSession(r)
	if cmdErr != nil {
		send("Upgrade failed: " + cmdErr.Error())
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionApplyUpdates,
			Result:  audit.ResultError,
			Details: cmdErr.Error(),
		})
		done(false, cmdErr.Error())
		return
	}

	send("System upgraded successfully.")
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionApplyUpdates,
		Result: audit.ResultOK,
	})
	done(true, "upgrade complete")
}
