package handlers

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"

	"github.com/gorilla/websocket"
)

// HandleOSInfo reads /etc/os-release and returns the NAME and VERSION fields,
// plus the running kernel release (uname -r, from /proc/sys/kernel/osrelease).
func HandleOSInfo(w http.ResponseWriter, r *http.Request) {
	// Kernel release is independent of /etc/os-release — read it first so it's
	// reported even on the os-release-missing fallback path.
	kernel := ""
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(b))
	}
	f, err := os.Open("/etc/os-release")
	if err != nil {
		jsonOK(w, map[string]string{"name": "Linux", "version": "", "kernel": kernel})
		return
	}
	defer f.Close()
	fields := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := line[:idx]
		val := strings.Trim(line[idx+1:], `"`)
		fields[key] = val
	}
	// DEBIAN_VERSION_FULL only exists on Debian's os-release. Ubuntu (and other
	// derivatives) don't ship it, so fall back to VERSION (e.g. "26.04 LTS (Noble
	// Numbat)") and finally VERSION_ID so the platform page shows a version+update
	// level for Ubuntu too, not a blank.
	version := fields["DEBIAN_VERSION_FULL"]
	if version == "" {
		version = fields["VERSION"]
	}
	if version == "" {
		version = fields["VERSION_ID"]
	}
	jsonOK(w, map[string]string{
		"name":    fields["NAME"],
		"version": version,
		"kernel":  kernel,
	})
}

// unattendedAutoUpgradesPath is the apt periodic config the portal manages to
// turn automatic background OS upgrades on or off. This is the same file
// `dpkg-reconfigure unattended-upgrades` writes.
const unattendedAutoUpgradesPath = "/etc/apt/apt.conf.d/20auto-upgrades"

// aptPeriodicValue returns the effective value of an APT::Periodic::* key by
// asking apt-config, which merges every file under apt.conf.d. Missing keys
// come back as "" (apt-config omits them from the dump).
func aptPeriodicValue(key string) string {
	out, err := exec.Command("apt-config", "dump", key).Output()
	if err != nil {
		return ""
	}
	// Output line looks like: APT::Periodic::Unattended-Upgrade "1";
	line := strings.TrimSpace(string(out))
	i := strings.IndexByte(line, '"')
	if i < 0 {
		return ""
	}
	rest := line[i+1:]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// HandleUnattendedStatus reports whether the unattended-upgrades package is
// installed and whether automatic background OS upgrades are currently enabled.
func HandleUnattendedStatus(w http.ResponseWriter, r *http.Request) {
	installed := false
	if _, err := os.Stat("/usr/bin/unattended-upgrade"); err == nil {
		installed = true
	}
	unattended := aptPeriodicValue("APT::Periodic::Unattended-Upgrade")
	updateLists := aptPeriodicValue("APT::Periodic::Update-Package-Lists")
	jsonOK(w, map[string]interface{}{
		"installed":    installed,
		"enabled":      installed && unattended == "1",
		"update_lists": updateLists == "1",
	})
}

// HandleUnattendedSet enables or disables automatic background OS upgrades by
// rewriting /etc/apt/apt.conf.d/20auto-upgrades — the same knob
// `dpkg-reconfigure unattended-upgrades` toggles. Admin only.
func HandleUnattendedSet(w http.ResponseWriter, r *http.Request) {
	if applianceBlock(w) {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Enabling automatic upgrades requires the unattended-upgrades package.
	// Without /usr/bin/unattended-upgrade the apt config is inert and the
	// status endpoint (which gates enabled on the binary's presence) would
	// report enabled:false — contradicting a success response here and
	// leaving a stale "1" that silently activates if the package is later
	// installed out-of-band. Refuse enable when it isn't installed. Disable
	// always proceeds so a stale config can be cleared regardless.
	if body.Enabled {
		if _, err := os.Stat("/usr/bin/unattended-upgrade"); err != nil {
			jsonErr(w, http.StatusBadRequest, "unattended-upgrades is not installed — install it first")
			return
		}
	}

	val := "0"
	if body.Enabled {
		val = "1"
	}
	content := "APT::Periodic::Update-Package-Lists \"" + val + "\";\n" +
		"APT::Periodic::Unattended-Upgrade \"" + val + "\";\n"

	cmd := exec.Command("sudo", "/usr/bin/tee", unattendedAutoUpgradesPath)
	cmd.Stdin = strings.NewReader(content)
	if out, err := cmd.CombinedOutput(); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to write apt config: "+strings.TrimSpace(string(out)))
		return
	}

	sess := MustSession(r)
	state := "disabled"
	if body.Enabled {
		state = "enabled"
	}
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionUpdateSettings,
		Result:  audit.ResultOK,
		Details: "automatic OS upgrades (unattended-upgrades) " + state,
	})
	jsonOK(w, map[string]interface{}{"ok": true, "enabled": body.Enabled})
}

type updateCacheFile struct {
	CheckedAt time.Time           `json:"checked_at"`
	Packages  []map[string]string `json:"packages"`
}

// zfsnasPrefixes lists package name prefixes (or exact names) that belong to the
// ZFS / NAS stack this portal depends on.
var zfsnasPrefixes = []string{
	// ZFS
	"zfs", "libzfs", "libzpool", "libnvpair", "libuutil", "libzutil",
	// Samba / SMB
	"samba", "libsamba", "libsmb", "smbclient", "winbind", "libnss-winbind", "libpam-winbind", "libwbclient",
	// NFS
	"nfs-", "libnfs", "rpcbind", "libnfsidmap", "libtirpc",
	// iSCSI / targetcli
	"targetcli", "python3-rtslib", "python3-configshell", "open-iscsi",
	// SMART
	"smartmontools",
}

// isZFSNASPackage returns true when the package name belongs to the ZFS/NAS stack.
func isZFSNASPackage(name string) bool {
	for _, prefix := range zfsnasPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// parseUpgradePackages parses apt-get --simulate upgrade output into a package list.
func parseUpgradePackages(out []byte) []map[string]string {
	var pkgs []map[string]string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		// Format: Inst pkg-name [old-ver] (new-ver suite [arch])
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		name := parts[1]
		currentVersion := ""
		newVersion := ""
		// Scan tokens left to right; stop at "(" so we never read "[arch])" after it.
		for _, p := range parts[2:] {
			if strings.HasPrefix(p, "(") {
				newVersion = strings.TrimPrefix(p, "(")
				break
			}
			if strings.HasPrefix(p, "[") {
				currentVersion = strings.Trim(p, "[]")
			}
		}
		secType := "regular"
		if strings.Contains(line, "-security") {
			secType = "security"
		} else if isZFSNASPackage(name) {
			secType = "zfsnas"
		}
		pkgs = append(pkgs, map[string]string{
			"name":            name,
			"current_version": currentVersion,
			"version":         newVersion,
			"type":            secType,
		})
	}
	if pkgs == nil {
		pkgs = []map[string]string{}
	}
	return pkgs
}

func saveUpdateCache(configDir string, pkgs []map[string]string) {
	path := filepath.Join(configDir, "updates_cache.json")
	b, err := json.MarshalIndent(updateCacheFile{CheckedAt: time.Now(), Packages: pkgs}, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(path, b, 0600)
}

// HandleCheckUpdates runs `apt-get update` then returns the list of packages
// that would be upgraded by `apt-get upgrade` (excludes kept-back packages).
// Results are persisted to config/updates_cache.json.
func HandleCheckUpdates(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Refresh package index.
		exec.Command("sudo", "apt-get", "update", "-qq").Run()

		out, err := exec.Command("apt-get", "--simulate", "upgrade").CombinedOutput()

		// Collect E: lines regardless of exit code — apt-get --simulate sometimes
		// exits 0 even when dpkg is in a broken state (interrupted configure).
		var aptErrors []string
		for _, line := range strings.Split(string(out), "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "E:") {
				aptErrors = append(aptErrors, t)
			}
		}
		if len(aptErrors) > 0 {
			jsonErr(w, http.StatusInternalServerError, strings.Join(aptErrors, " "))
			return
		}
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		pkgs := parseUpgradePackages(out)
		saveUpdateCache(appCfg.ConfigDir, pkgs)

		jsonOK(w, map[string]interface{}{
			"count":    len(pkgs),
			"packages": pkgs,
		})
	}
}

// HandleGetUpdateCache returns the last persisted update check results.
func HandleGetUpdateCache(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join(appCfg.ConfigDir, "updates_cache.json")
		b, err := os.ReadFile(path)
		if err != nil {
			// No cache yet — return empty result.
			jsonOK(w, map[string]interface{}{"count": 0, "packages": []map[string]string{}, "checked_at": nil})
			return
		}
		var cache updateCacheFile
		if err := json.Unmarshal(b, &cache); err != nil {
			jsonOK(w, map[string]interface{}{"count": 0, "packages": []map[string]string{}, "checked_at": nil})
			return
		}
		jsonOK(w, map[string]interface{}{
			"count":      len(cache.Packages),
			"packages":   cache.Packages,
			"checked_at": cache.CheckedAt,
		})
	}
}

// upgradeJob holds the state of the background OS upgrade so that it survives
// WebSocket disconnects. Only one upgrade can run at a time.
type upgradeJob struct {
	mu      sync.Mutex
	running bool
	lines   []string
	done    bool
	success bool
	message string
}

// start marks the job as running and resets all state.
// Returns true if the caller should start a new upgrade; false if one is already running.
func (j *upgradeJob) start() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.running {
		return false
	}
	j.running = true
	j.lines = nil
	j.done = false
	j.success = false
	j.message = ""
	return true
}

func (j *upgradeJob) addLine(line string) {
	j.mu.Lock()
	j.lines = append(j.lines, line)
	j.mu.Unlock()
}

func (j *upgradeJob) finish(success bool, msg string) {
	j.mu.Lock()
	j.running = false
	j.done = true
	j.success = success
	j.message = msg
	j.mu.Unlock()
}

// snapshot returns a copy of all buffered lines plus current status flags.
func (j *upgradeJob) snapshot() (lines []string, running bool, done bool, success bool, message string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	cp := make([]string, len(j.lines))
	copy(cp, j.lines)
	return cp, j.running, j.done, j.success, j.message
}

// activeUpgradeJob is the singleton background upgrade state.
var activeUpgradeJob upgradeJob

// HandleUpgradeStatus returns the current background upgrade state so the
// frontend can detect an in-progress upgrade after the user navigates away.
// GET /api/updates/upgrade-status
func HandleUpgradeStatus(w http.ResponseWriter, r *http.Request) {
	lines, running, done, success, message := activeUpgradeJob.snapshot()
	if lines == nil {
		lines = []string{}
	}
	jsonOK(w, map[string]interface{}{
		"running": running,
		"done":    done,
		"success": success,
		"message": message,
		"lines":   lines,
	})
}

// HandleApplyUpdates upgrades the HTTP connection to WebSocket and streams
// the output of `sudo apt-get upgrade -y`.
//
// The upgrade runs in a detached goroutine so that closing the WebSocket
// (e.g. the user navigates away) does not interrupt it.  A reconnecting
// client is fast-forwarded through the buffered output and then receives
// new lines live until the job finishes.
func HandleApplyUpdates(w http.ResponseWriter, r *http.Request) {
	if applianceBlock(w) {
		return
	}
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	send := func(line string) bool {
		return conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]interface{}{
			"line": line,
		})) == nil
	}
	sendDone := func(success bool, msg string) {
		conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]interface{}{
			"done":    true,
			"success": success,
			"message": msg,
		}))
	}

	sess := MustSession(r)

	// Try to claim a new job. Returns false if one is already running (reconnect case).
	isNewJob := activeUpgradeJob.start()

	if isNewJob {
		go func() {
			addLine := activeUpgradeJob.addLine
			addLine("Running: sudo apt-get upgrade -y")
			addLine("─────────────────────────────────────────")

			// DEBIAN_FRONTEND=noninteractive sends debconf straight to its
			// Noninteractive frontend. Without it, the unattended run (piped, no
			// controlling TTY) makes debconf try Dialog→Readline→Teletype first,
			// printing a wall of "unable to initialize frontend … falling back"
			// warnings before it finally settles on Noninteractive. The env is
			// passed via `env` (not sudo's env, which it resets) so it reaches the
			// apt/dpkg/debconf chain; the matching sudoers entry is in ZFSNAS_APT.
			cmd := exec.Command("sudo", "/usr/bin/env", "DEBIAN_FRONTEND=noninteractive",
				"apt-get", "upgrade", "-y",
				"-o", "Dpkg::Use-Pty=0",
				"-o", "Dpkg::Options::=--force-confold")

			pr, pw, err := os.Pipe()
			if err != nil {
				activeUpgradeJob.finish(false, "failed to create pipe")
				return
			}
			cmd.Stdout = pw
			cmd.Stderr = pw

			if err := cmd.Start(); err != nil {
				pw.Close()
				pr.Close()
				activeUpgradeJob.finish(false, err.Error())
				return
			}
			pw.Close()

			buf := make([]byte, 4096)
			for {
				n, readErr := pr.Read(buf)
				if n > 0 {
					for _, l := range strings.Split(string(buf[:n]), "\n") {
						if strings.TrimSpace(l) != "" {
							addLine(l)
						}
					}
				}
				if readErr != nil {
					break
				}
			}

			cmdErr := cmd.Wait()
			addLine("─────────────────────────────────────────")

			if cmdErr != nil {
				addLine("Upgrade failed: " + cmdErr.Error())
				audit.Log(audit.Entry{
					User:    sess.Username,
					Role:    sess.Role,
					Action:  audit.ActionApplyUpdates,
					Result:  audit.ResultError,
					Details: cmdErr.Error(),
				})
				activeUpgradeJob.finish(false, cmdErr.Error())
			} else {
				addLine("System upgraded successfully.")
				audit.Log(audit.Entry{
					User:   sess.Username,
					Role:   sess.Role,
					Action: audit.ActionApplyUpdates,
					Result: audit.ResultOK,
				})
				activeUpgradeJob.finish(true, "upgrade complete")
			}
		}()
	}

	// Attach to the running job: stream buffered lines then tail new ones.
	sent := 0
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(2 * time.Hour)
	defer deadline.Stop()

	for {
		select {
		case <-deadline.C:
			send("[upgrade timed out — check system logs]")
			return
		case <-ticker.C:
			lines, _, isDone, success, message := activeUpgradeJob.snapshot()
			for sent < len(lines) {
				if !send(lines[sent]) {
					return // client disconnected — upgrade keeps running
				}
				sent++
			}
			if isDone {
				sendDone(success, message)
				return
			}
		}
	}
}
