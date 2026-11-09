// Move the USB appliance OS to an internal disk
// (PLANS/plan-appliance-internal-disk.md). Web page only: the erase needs an
// admin session, the typed disk name and the admin password again (+2FA),
// and is refused when the request comes through InterLink from another
// server. The work itself is zfsnas-install-disk, run in its own transient
// unit so it survives a portal restart (it stops the portal for the copy).
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/session"
	"zfsnas/internal/totp"
	"zfsnas/system"
)

var (
	applianceInstallScript  = "/usr/local/sbin/zfsnas-install-disk"
	applianceTargetsScript  = "/usr/lib/zfsnas/disk-targets.py"
	applianceInstallUnit    = "zfsnas-install-disk"
	applianceInstallRunDir  = "/run/zfsnas-install"
	applianceInstallStepRe  = regexp.MustCompile(`^STEP (\d+) (\S+)$`)
	applianceDiskNameRe     = regexp.MustCompile(`^[a-z][a-z0-9]{1,15}$`)
	applianceInstallUnitRun = func() bool {
		return exec.Command("systemctl", "is-active", "--quiet", applianceInstallUnit).Run() == nil
	}
)

// applianceInstallState is what the wizard's progress view shows.
type applianceInstallState struct {
	Phase string   `json:"phase"` // idle | running | done | failed
	Step  string   `json:"step,omitempty"`
	Steps []string `json:"steps"` // steps reached, in order
	Log   []string `json:"log"`
	Disk  string   `json:"disk,omitempty"`
	Err   string   `json:"error,omitempty"`
}

// parseApplianceInstallLog splits the installer's output into display lines
// and the "STEP <n> <name>" markers it prints before each step.
func parseApplianceInstallLog(s string) (lines, steps []string) {
	steps = []string{}
	lines = []string{}
	for _, l := range strings.Split(s, "\n") {
		parts := strings.Split(l, "\r") // dd redraws with \r
		l = strings.TrimSpace(parts[len(parts)-1])
		if l == "" {
			continue
		}
		if m := applianceInstallStepRe.FindStringSubmatch(l); m != nil {
			steps = append(steps, m[2])
			continue
		}
		lines = append(lines, l)
	}
	return lines, steps
}

func readApplianceInstallState() applianceInstallState {
	st := applianceInstallState{Phase: "idle", Steps: []string{}, Log: []string{}}
	logB, err := os.ReadFile(filepath.Join(applianceInstallRunDir, "log"))
	if err != nil {
		return st
	}
	st.Log, st.Steps = parseApplianceInstallLog(string(logB))
	if n := len(st.Steps); n > 0 {
		st.Step = st.Steps[n-1]
	}
	st.Disk = readTrim(filepath.Join(applianceInstallRunDir, "disk"))
	rc := readTrim(filepath.Join(applianceInstallRunDir, "rc"))
	switch {
	case rc == "0":
		st.Phase = "done"
	case applianceInstallUnitRun():
		st.Phase = "running"
	case rc == "running" || rc == "":
		st.Phase = "failed"
		st.Err = "the move stopped unexpectedly — the USB stick is unchanged and still boots; you can run it again"
	default:
		st.Phase = "failed"
		st.Err = lastNonEmpty(st.Log)
		for i := len(st.Log) - 1; i >= 0; i-- {
			if strings.HasPrefix(st.Log[i], "error: ") {
				st.Err = strings.TrimPrefix(st.Log[i], "error: ")
				break
			}
		}
	}
	return st
}

// ApplianceInstallActive blocks reboot/shutdown while the move runs.
func ApplianceInstallActive() bool {
	return system.ApplianceMode() && readApplianceInstallState().Phase == "running"
}

// HandleApplianceWhere: GET /api/appliance/where — what ZNAS runs from.
func HandleApplianceWhere(w http.ResponseWriter, r *http.Request) {
	if !system.ApplianceMode() {
		jsonOK(w, map[string]any{"appliance": false})
		return
	}
	m := system.ApplianceMediumInfo()
	jsonOK(w, map[string]any{
		"appliance": true, "medium": m, "install": readApplianceInstallState(),
		"relayed": isRelayedRequest(r),
	})
}

// HandleApplianceInstallTargets: GET /api/appliance/install-targets
func HandleApplianceInstallTargets(w http.ResponseWriter, r *http.Request) {
	if !system.ApplianceMode() {
		jsonErr(w, http.StatusNotFound, "only on the USB appliance")
		return
	}
	out, err := exec.Command("python3", "-I", applianceTargetsScript).Output()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "could not list the disks: "+err.Error())
		return
	}
	var v map[string]any
	if json.Unmarshal(out, &v) != nil {
		jsonErr(w, http.StatusInternalServerError, "could not read the disk list")
		return
	}
	jsonOK(w, v)
}

type applianceInstallRequest struct {
	Disk     string `json:"disk"`
	Confirm  string `json:"confirm"`
	Password string `json:"password"`
	TOTP     string `json:"totp"`
	Pool     string `json:"pool"` // "" = no pool
}

var appliancePoolNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{0,63}$`)

// checkApplianceInstallRequest validates the request shape (not the disk:
// the installer re-checks eligibility right before it erases anything).
func checkApplianceInstallRequest(req applianceInstallRequest) string {
	switch {
	case !applianceDiskNameRe.MatchString(req.Disk):
		return "choose a disk"
	case req.Confirm != req.Disk:
		return "type the disk name exactly (" + req.Disk + ") to confirm"
	case req.Pool != "" && !appliancePoolNameRe.MatchString(req.Pool):
		return "invalid pool name"
	case req.Password == "":
		return "enter your password"
	}
	return ""
}

func isRelayedRequest(r *http.Request) bool {
	s, ok := r.Context().Value(relaySessionKey).(*session.Session)
	return ok && s != nil
}

// HandleApplianceInstallStart: POST /api/appliance/install-disk
func HandleApplianceInstallStart(w http.ResponseWriter, r *http.Request) {
	if !system.ApplianceMode() {
		jsonErr(w, http.StatusNotFound, "only on the USB appliance")
		return
	}
	if isRelayedRequest(r) {
		jsonErr(w, http.StatusForbidden, "erasing a disk can't be done through InterLink: log in to this server directly")
		return
	}
	var req applianceInstallRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if msg := checkApplianceInstallRequest(req); msg != "" {
		jsonErr(w, http.StatusBadRequest, msg)
		return
	}
	sess := MustSession(r)
	users, err := config.LoadUsers()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load users")
		return
	}
	u := config.FindUserByUsername(users, sess.Username)
	if u == nil || u.Role != config.RoleAdmin || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: "appliance_install_disk", Target: req.Disk, Result: audit.ResultError, Details: "wrong password"})
		jsonErr(w, http.StatusUnauthorized, "wrong password")
		return
	}
	if u.TOTPEnabled {
		if strings.TrimSpace(req.TOTP) == "" {
			jsonOK(w, map[string]any{"totp_needed": true})
			return
		}
		if !totp.Verify(u.TOTPSecret, strings.TrimSpace(req.TOTP)) {
			jsonErr(w, http.StatusUnauthorized, "invalid 2FA code")
			return
		}
	}
	if ApplianceImageWriteActive() || readApplianceInstallState().Phase == "running" {
		jsonErr(w, http.StatusConflict, "an image write or a move is already running")
		return
	}
	if err := startApplianceInstall(req); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: "appliance_install_disk", Target: req.Disk, Result: audit.ResultOK,
		Details: "moving the appliance OS to " + req.Disk + " (pool " + map[bool]string{true: "none", false: req.Pool}[req.Pool == ""] + ")"})
	jsonOK(w, map[string]any{"started": true})
}

func applianceInstallArgs(req applianceInstallRequest) []string {
	args := []string{"--install", req.Disk, "--confirm", req.Confirm}
	if req.Pool == "" {
		return append(args, "--no-pool")
	}
	return append(args, "--pool", req.Pool)
}

func startApplianceInstall(req applianceInstallRequest) error {
	if _, err := os.Stat(applianceInstallScript); err != nil {
		return fmt.Errorf("%s is missing from this image: upgrade the appliance image first", applianceInstallScript)
	}
	if err := os.MkdirAll(applianceInstallRunDir, 0755); err != nil {
		return err
	}
	logPath := filepath.Join(applianceInstallRunDir, "log")
	for _, f := range []string{"log", "rc", "disk"} {
		os.Remove(filepath.Join(applianceInstallRunDir, f))
	}
	if err := os.WriteFile(logPath, nil, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(applianceInstallRunDir, "rc"), []byte("running\n"), 0644); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "reset-failed", applianceInstallUnit).Run()
	args := append([]string{"--unit=" + applianceInstallUnit, "--collect", "--quiet",
		"-p", "StandardOutput=append:" + logPath, "-p", "StandardError=append:" + logPath,
		applianceInstallScript}, applianceInstallArgs(req)...)
	out, err := exec.Command("systemd-run", args...).CombinedOutput()
	if err != nil {
		os.Remove(logPath)
		return fmt.Errorf("could not start the move: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// HandleApplianceInstallStatus: GET /api/appliance/install-disk/status
func HandleApplianceInstallStatus(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, readApplianceInstallState())
}
