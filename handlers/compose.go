package handlers

// Compose stack management — view containers, edit the compose file / .env,
// run updates (podman-compose pull + up -d), and schedule auto-updates.
//
// A "Compose stack" is an Incus LXC tagged user.zfsnas.compose=true that runs
// Podman + podman-compose with a docker-compose file under /opt/stack.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
	"zfsnas/internal/termsessions"

	"github.com/creack/pty"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"
)

// composeLastUpdateKey is the Incus config key that records the last time a
// stack was updated (RFC3339). It travels with the instance.
const composeLastUpdateKey = "user.zfsnas.compose.last_update"

// composeSchedMu guards in-memory edits of AppConfig.ComposeUpdatePolicies.
var composeSchedMu sync.Mutex

// composeUpdateJobByStack maps an Incus stack name to the in-flight update
// jobId, so a second click on "Update now" (or a scheduled auto-update that
// fires while a manual one is still running) can attach to the existing job
// instead of launching a competing `podman-compose pull`.
var composeUpdateJobByStack sync.Map // string -> string

// requireComposeStack confirms the named instance exists and is a Compose
// stack. Returns false (and writes the error) when it is not.
func requireComposeStack(w http.ResponseWriter, name string) bool {
	if system.ComposeGetConfigKey(name, "user.zfsnas.compose") != "true" {
		jsonErr(w, http.StatusBadRequest, "not a Compose stack")
		return false
	}
	return true
}

// HandleComposeStackGet returns everything the stack detail view needs:
// the compose file, the .env, the live container list, and update state.
// GET /api/incus/compose-stacks/{name}
func HandleComposeStackGet(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := mux.Vars(r)["name"]
		if !requireComposeStack(w, name) {
			return
		}
		// File reads now work on stopped containers (incus file pull),
		// so this no longer errors when the user opens the detail view
		// on a halted stack — we just surface empty data + a status.
		composeYAML, composeEnv, _ := system.ComposeStackFiles(name)
		containers, cErr := system.ComposeStackContainers(name)
		if cErr != nil {
			containers = []system.ComposeContainer{}
		}
		// status lets the frontend pick the right empty state (stopped
		// stack → friendly "stack is offline" card, running stack with
		// zero matching containers → "podman has no containers" hint).
		status := "stopped"
		if statusOut, err := exec.Command("incus", "list", name, "-c", "s", "--format", "csv").Output(); err == nil {
			s := strings.ToLower(strings.TrimSpace(string(statusOut)))
			if s == "running" {
				status = "running"
			}
		}
		resp := map[string]interface{}{
			"status":       status,
			"compose_yaml": composeYAML,
			"env":          composeEnv,
			"containers":   containers,
			"last_update":  system.ComposeGetConfigKey(name, composeLastUpdateKey),
		}
		composeSchedMu.Lock()
		for _, p := range appCfg.ComposeUpdatePolicies {
			if p.Instance == name {
				pp := p
				resp["schedule"] = pp
				resp["schedule_exists"] = true
				resp["next_run"] = composeNextRun(pp, time.Now())
				break
			}
		}
		composeSchedMu.Unlock()
		jsonOK(w, resp)
	}
}

// HandleComposeStackContainers returns just the live container list — the
// stack detail card polls this.
// GET /api/incus/compose-stacks/{name}/containers
func HandleComposeStackContainers(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if !requireComposeStack(w, name) {
		return
	}
	containers, err := system.ComposeStackContainers(name)
	if err != nil {
		containers = []system.ComposeContainer{}
	}
	jsonOK(w, map[string]interface{}{"containers": containers})
}

// HandleComposeContainerLogs returns the last N lines of podman logs for
// one container in a compose stack as plain text. Used by the "Last
// Outputs" action in the Stack Containers card burger menu.
// GET /api/incus/compose-stacks/{name}/containers/{container}/logs?tail=100
func HandleComposeContainerLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]
	container := vars["container"]
	if !requireComposeStack(w, name) {
		return
	}
	tail := 100
	if t := r.URL.Query().Get("tail"); t != "" {
		fmt.Sscanf(t, "%d", &tail)
	}
	out, err := system.ComposeContainerLogs(name, container, tail)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(out)) //nolint:errcheck
}

// HandleComposeContainerInspect returns the raw `podman inspect` JSON
// for one container in a stack. The response body is the podman array
// (single element) sent unmodified — the frontend renders pretty
// sections from it client-side so we stay decoupled from podman's
// version-to-version field churn.
// GET /api/lxd/compose-stacks/{name}/containers/{container}/inspect
func HandleComposeContainerInspect(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]
	container := vars["container"]
	if !requireComposeStack(w, name) {
		return
	}
	out, err := system.ComposeContainerInspect(name, container)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(out)) //nolint:errcheck
}

// HandleComposeContainerAction runs start/stop/restart/update on one
// container of a stack.
// POST /api/incus/compose-stacks/{name}/container-action
func HandleComposeContainerAction(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if !requireComposeStack(w, name) {
		return
	}
	var req struct {
		Container string `json:"container"`
		Service   string `json:"service"`
		Action    string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Container = strings.TrimSpace(req.Container)
	if req.Container == "" {
		jsonErr(w, http.StatusBadRequest, "container is required")
		return
	}
	switch req.Action {
	case "start", "stop", "restart", "update":
	default:
		jsonErr(w, http.StatusBadRequest, "action must be start|stop|restart|update")
		return
	}
	err := system.ComposeContainerAction(name, req.Container, req.Service, req.Action)
	sess := MustSession(r)
	result, details := audit.ResultOK, req.Action+" "+req.Container
	if err != nil {
		result = audit.ResultError
		details = err.Error()
	}
	audit.Log(audit.Entry{
		User: sess.Username, Role: sess.Role,
		Action: audit.ActionComposeAction, Target: "compose:" + name,
		Result: result, Details: details,
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// HandleComposeStackUpdate runs podman-compose pull + up -d as a progress job.
// If an update for this stack is already in flight, returns 409 with the
// existing job_id so the client can reattach instead of starting a second
// concurrent pull (which would have podman fight itself over the registry
// connection and the compose state).
// POST /api/incus/compose-stacks/{name}/update
func HandleComposeStackUpdate(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if !requireComposeStack(w, name) {
		return
	}
	sess := MustSession(r)
	jobID := fmt.Sprintf("%d", time.Now().UnixNano())
	job := &lxdJob{Status: "running"}

	// Per-stack mutex: LoadOrStore wins atomically.
	if existing, loaded := composeUpdateJobByStack.LoadOrStore(name, jobID); loaded {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"error":  "update already in progress",
			"job_id": existing.(string),
		})
		return
	}
	lxdJobs.Store(jobID, job)

	go func() {
		defer composeUpdateJobByStack.Delete(name)
		logCh := make(chan string, 64)
		go func() {
			for line := range logCh {
				job.mu.Lock()
				job.Lines = append(job.Lines, line)
				job.mu.Unlock()
			}
		}()
		err := system.ComposeStackUpdate(name, logCh)
		close(logCh)
		if err == nil {
			system.ComposeSetConfigKey(name, composeLastUpdateKey, time.Now().Format(time.RFC3339)) //nolint:errcheck
		}
		job.mu.Lock()
		if err != nil {
			job.Status, job.Error = "error", err.Error()
		} else {
			job.Status = "done"
		}
		job.mu.Unlock()
		result, details := audit.ResultOK, ""
		if err != nil {
			result, details = audit.ResultError, err.Error()
		}
		audit.Log(audit.Entry{
			User: sess.Username, Role: sess.Role,
			Action: audit.ActionComposeUpdate, Target: "compose:" + name,
			Result: result, Details: details,
		})
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID}) //nolint:errcheck
}

// HandleComposeRedeploy rewrites the compose file / .env and re-applies the
// stack (podman-compose up -d). Runs as a progress job.
// PUT /api/incus/compose-stacks/{name}
func HandleComposeRedeploy(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if !requireComposeStack(w, name) {
		return
	}
	var req struct {
		ComposeYAML string `json:"compose_yaml"`
		Env         string `json:"env"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.ComposeYAML) == "" {
		jsonErr(w, http.StatusBadRequest, "docker-compose content is required")
		return
	}
	sess := MustSession(r)
	jobID := fmt.Sprintf("%d", time.Now().UnixNano())
	job := &lxdJob{Status: "running"}
	lxdJobs.Store(jobID, job)

	go func() {
		logCh := make(chan string, 64)
		go func() {
			for line := range logCh {
				job.mu.Lock()
				job.Lines = append(job.Lines, line)
				job.mu.Unlock()
			}
		}()
		err := system.ComposeRedeploy(name, req.ComposeYAML, req.Env, logCh)
		close(logCh)
		job.mu.Lock()
		if err != nil {
			job.Status, job.Error = "error", err.Error()
		} else {
			job.Status = "done"
		}
		job.mu.Unlock()
		result, details := audit.ResultOK, ""
		if err != nil {
			result, details = audit.ResultError, err.Error()
		}
		audit.Log(audit.Entry{
			User: sess.Username, Role: sess.Role,
			Action: audit.ActionComposeRedeploy, Target: "compose:" + name,
			Result: result, Details: details,
		})
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID}) //nolint:errcheck
}

// HandleComposeGetSchedule returns the saved auto-update policy for a stack.
// GET /api/incus/compose-stacks/{name}/schedule
func HandleComposeGetSchedule(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := mux.Vars(r)["name"]
		composeSchedMu.Lock()
		defer composeSchedMu.Unlock()
		for _, p := range appCfg.ComposeUpdatePolicies {
			if p.Instance == name {
				jsonOK(w, map[string]interface{}{"exists": true, "policy": p, "next_run": composeNextRun(p, time.Now())})
				return
			}
		}
		jsonOK(w, map[string]interface{}{
			"exists": false,
			"policy": config.ComposeUpdatePolicy{Instance: name, EveryN: 1, Unit: "day", HourOfDay: 3},
		})
	}
}

// HandleComposePutSchedule saves (or replaces) the auto-update policy.
// PUT /api/incus/compose-stacks/{name}/schedule
func HandleComposePutSchedule(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := mux.Vars(r)["name"]
		if !requireComposeStack(w, name) {
			return
		}
		sess := MustSession(r)
		var p config.ComposeUpdatePolicy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		p.Instance = name
		if err := validateSnapInterval(p.Unit, p.EveryN); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if p.HourOfDay < 0 || p.HourOfDay > 23 {
			p.HourOfDay = 0
		}
		if p.MinuteOfHour < 0 || p.MinuteOfHour > 59 {
			p.MinuteOfHour = 0
		}
		if p.Weekday < 0 || p.Weekday > 6 {
			p.Weekday = 0
		}
		if p.DayOfMonth < 1 || p.DayOfMonth > 31 {
			p.DayOfMonth = 1
		}

		composeSchedMu.Lock()
		replaced := false
		for i := range appCfg.ComposeUpdatePolicies {
			if appCfg.ComposeUpdatePolicies[i].Instance == name {
				p.LastRun = appCfg.ComposeUpdatePolicies[i].LastRun
				appCfg.ComposeUpdatePolicies[i] = p
				replaced = true
				break
			}
		}
		if !replaced {
			appCfg.ComposeUpdatePolicies = append(appCfg.ComposeUpdatePolicies, p)
		}
		err := config.SaveAppConfig(appCfg)
		composeSchedMu.Unlock()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		audit.Log(audit.Entry{
			User: sess.Username, Role: sess.Role,
			Action: audit.ActionUpdateSchedule, Target: "compose-update-schedule:" + name,
			Result: audit.ResultOK,
			Details: fmt.Sprintf("every %d %s (%s)", p.EveryN, p.Unit,
				map[bool]string{true: "enabled", false: "disabled"}[p.Enabled]),
		})
		jsonOK(w, map[string]interface{}{"ok": true, "next_run": composeNextRun(p, time.Now())})
	}
}

// HandleComposeDeleteSchedule turns off scheduled auto-updates.
// RemoveComposeUpdatePolicy drops the auto-update schedule for the named
// compose stack (if any) and persists the config. Returns true when a policy
// was actually removed. Exported so the instance-delete and stack-push flows
// can clean up a stack's schedule when the stack leaves this host — otherwise
// the scheduler keeps firing against an instance that no longer exists and
// spams the log with "Instance not found" (observed after a stack was pushed
// from one server to another). Takes composeSchedMu itself, so never call it
// while that lock is held.
func RemoveComposeUpdatePolicy(appCfg *config.AppConfig, name string) bool {
	composeSchedMu.Lock()
	defer composeSchedMu.Unlock()
	kept := appCfg.ComposeUpdatePolicies[:0]
	removed := false
	for _, p := range appCfg.ComposeUpdatePolicies {
		if p.Instance == name {
			removed = true
			continue
		}
		kept = append(kept, p)
	}
	if !removed {
		return false
	}
	appCfg.ComposeUpdatePolicies = kept
	_ = config.SaveAppConfig(appCfg)
	return true
}

// DELETE /api/incus/compose-stacks/{name}/schedule
func HandleComposeDeleteSchedule(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := mux.Vars(r)["name"]
		sess := MustSession(r)
		removed := RemoveComposeUpdatePolicy(appCfg, name)
		if removed {
			audit.Log(audit.Entry{
				User: sess.Username, Role: sess.Role,
				Action: audit.ActionDeleteSchedule, Target: "compose-update-schedule:" + name,
				Result: audit.ResultOK,
			})
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// ── scheduler ────────────────────────────────────────────────────────────────

// composeUpdateDue reuses the snapshot-schedule cadence logic by adapting the
// shared scheduling fields onto an LXDSnapshotPolicy.
func composeUpdateDue(p config.ComposeUpdatePolicy, now time.Time) bool {
	return lxdSnapDue(config.LXDSnapshotPolicy{
		EveryN: p.EveryN, Unit: p.Unit, HourOfDay: p.HourOfDay,
		MinuteOfHour: p.MinuteOfHour, Weekday: p.Weekday, DayOfMonth: p.DayOfMonth,
	}, now)
}

func composeNextRun(p config.ComposeUpdatePolicy, from time.Time) time.Time {
	return lxdSnapNextRun(config.LXDSnapshotPolicy{
		EveryN: p.EveryN, Unit: p.Unit, HourOfDay: p.HourOfDay,
		MinuteOfHour: p.MinuteOfHour, Weekday: p.Weekday, DayOfMonth: p.DayOfMonth,
	}, from)
}

// composeErrInstanceGone reports whether an update error means the target
// instance no longer exists on this host (Incus phrases it "Instance not
// found" / "Failed to fetch instance …"). Used to auto-remove orphaned
// schedules rather than retry them forever.
func composeErrInstanceGone(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "instance not found") ||
		strings.Contains(m, "failed to fetch instance") ||
		strings.Contains(m, "not found in project")
}

// StartComposeAutoUpdater kicks off the per-minute compose auto-update loop.
func StartComposeAutoUpdater(appCfg *config.AppConfig) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for now := range t.C {
			tickComposeUpdatePolicies(now, appCfg)
		}
	}()
}

func tickComposeUpdatePolicies(now time.Time, appCfg *config.AppConfig) {
	composeSchedMu.Lock()
	policies := make([]config.ComposeUpdatePolicy, len(appCfg.ComposeUpdatePolicies))
	copy(policies, appCfg.ComposeUpdatePolicies)
	composeSchedMu.Unlock()

	for i := range policies {
		p := policies[i]
		if !p.Enabled || !composeUpdateDue(p, now) {
			continue
		}
		go runComposeUpdatePolicy(p, appCfg)
	}
}

func runComposeUpdatePolicy(p config.ComposeUpdatePolicy, appCfg *config.AppConfig) {
	now := time.Now()
	// Don't fight a manual update for the same stack — if one is in flight,
	// skip this scheduled tick rather than running two pulls in parallel.
	schedJobID := fmt.Sprintf("sched-%d", now.UnixNano())
	if _, loaded := composeUpdateJobByStack.LoadOrStore(p.Instance, schedJobID); loaded {
		audit.Log(audit.Entry{
			User: "system", Role: "system",
			Action: audit.ActionComposeUpdate, Target: "compose:" + p.Instance,
			Result: audit.ResultOK, Details: "scheduled run skipped — manual update already in progress",
		})
		return
	}
	defer composeUpdateJobByStack.Delete(p.Instance)

	err := system.ComposeStackUpdate(p.Instance, nil)

	// Self-heal orphan schedules: if the instance no longer exists on this host
	// (e.g. the stack was pushed/moved to another server, or deleted outside
	// the schedule UI), drop the policy so the scheduler stops firing against a
	// ghost instance every interval. Without this the log fills with
	// "Failed to fetch instance … Instance not found" forever and a failure
	// alert is sent on every tick.
	if err != nil && composeErrInstanceGone(err) {
		if RemoveComposeUpdatePolicy(appCfg, p.Instance) {
			log.Printf("[compose-auto-update] %s no longer exists — removed its orphaned auto-update schedule", p.Instance)
			audit.Log(audit.Entry{
				User: "system", Role: "system",
				Action: audit.ActionDeleteSchedule, Target: "compose-update-schedule:" + p.Instance,
				Result: audit.ResultOK, Details: "auto-removed: instance no longer exists on this host",
			})
		}
		return
	}

	if err == nil {
		system.ComposeSetConfigKey(p.Instance, composeLastUpdateKey, now.Format(time.RFC3339)) //nolint:errcheck
	}
	updateComposePolicyStatus(appCfg, p.Instance, now, err)

	if err != nil {
		log.Printf("[compose-auto-update] %s: %v", p.Instance, err)
		audit.Log(audit.Entry{
			User: "system", Role: "system",
			Action: audit.ActionComposeUpdate, Target: "compose:" + p.Instance,
			Result: audit.ResultError, Details: err.Error(),
		})
		go alerts.Send(alerts.EventComposeUpdateFailure, //nolint:errcheck
			"Compose stack auto-update failed: "+p.Instance,
			"compose_update_failure",
			fmt.Sprintf("Scheduled auto-update of Compose stack %q failed:\n\n%v", p.Instance, err))
		return
	}
	audit.Log(audit.Entry{
		User: "system", Role: "system",
		Action: audit.ActionComposeUpdate, Target: "compose:" + p.Instance,
		Result: audit.ResultOK, Details: "scheduled auto-update",
	})
}

func updateComposePolicyStatus(appCfg *config.AppConfig, instance string, runAt time.Time, err error) {
	composeSchedMu.Lock()
	defer composeSchedMu.Unlock()
	for i := range appCfg.ComposeUpdatePolicies {
		if appCfg.ComposeUpdatePolicies[i].Instance != instance {
			continue
		}
		appCfg.ComposeUpdatePolicies[i].LastRun = runAt
		if err != nil {
			appCfg.ComposeUpdatePolicies[i].LastStatus = "error"
			appCfg.ComposeUpdatePolicies[i].LastError = err.Error()
		} else {
			appCfg.ComposeUpdatePolicies[i].LastStatus = "ok"
			appCfg.ComposeUpdatePolicies[i].LastError = ""
		}
		_ = config.SaveAppConfig(appCfg)
		return
	}
}

// ── live logs + per-container terminal ──────────────────────────────────────

// ansiEscapeRE strips standard CSI colour sequences (`\x1b[…m`) from
// podman-compose output so the plain-text Output pane renders cleanly. We
// don't run xterm here — the pane is a raw <pre>.
var ansiEscapeRE = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")

func stripANSI(s string) string {
	return ansiEscapeRE.ReplaceAllString(s, "")
}

// termMsg duplicates the message shape used by the LXD console WS so the
// resize JSON frame from xterm.js is understood by both endpoints.
type composeTermMsg struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// HandleComposeLogsWS streams `podman-compose logs -f` for a stack to the
// browser. One process per viewer connection — killed as soon as the WS
// closes, so nothing keeps running while no Output tab is open.
// WS /ws/compose-logs?stack=<name>
func HandleComposeLogsWS(w http.ResponseWriter, r *http.Request) {
	stack := r.URL.Query().Get("stack")
	if stack == "" {
		http.Error(w, "stack required", http.StatusBadRequest)
		return
	}
	if system.ComposeGetConfigKey(stack, "user.zfsnas.compose") != "true" {
		http.Error(w, "not a compose stack", http.StatusBadRequest)
		return
	}
	conn, err := lxdConsoleUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// Stacks that pre-date the docker-compose runtime need a one-time
	// install before the logs command works; the call is idempotent so
	// it's effectively free on already-migrated stacks.
	system.EnsureDockerComposeInStack(stack)

	cmd := exec.Command("incus", "exec", stack,
		"--env", "DOCKER_HOST=unix:///run/podman/podman.sock",
		"--cwd", system.ComposeStackDir(stack), "--",
		"docker-compose", "logs", "--tail=500", "-f")
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	// Merge stdout + stderr through a single pipe so the scanner gets one
	// ordered text stream.
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("failed to start log stream: "+err.Error()+"\n"))
		return
	}
	go func() {
		cmd.Wait()
		pw.Close()
	}()

	done := make(chan struct{})
	var once sync.Once
	closeDone := func() { once.Do(func() { close(done) }) }

	// Reader: forward lines to the WS.
	go func() {
		scanner := bufio.NewScanner(pr)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := stripANSI(scanner.Text())
			if err := conn.WriteMessage(websocket.TextMessage, []byte(line+"\n")); err != nil {
				break
			}
		}
		closeDone()
	}()

	// Client-close detector: any read error (including a normal close) tears
	// the process down so we don't leak `incus exec` children.
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				closeDone()
				return
			}
		}
	}()

	<-done
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
}

// HandleComposeConsoleWS attaches to a persistent terminal session for one
// podman container inside a compose stack. The PTY survives WS disconnect
// — see termsessions.Default for lifetime.
// WS /ws/compose-console?stack=<stack>&container=<container>[&session_id=<id>]
func HandleComposeConsoleWS(w http.ResponseWriter, r *http.Request) {
	stack := r.URL.Query().Get("stack")
	container := r.URL.Query().Get("container")
	if stack == "" || container == "" {
		http.Error(w, "stack and container required", http.StatusBadRequest)
		return
	}
	if system.ComposeGetConfigKey(stack, "user.zfsnas.compose") != "true" {
		http.Error(w, "not a compose stack", http.StatusBadRequest)
		return
	}
	conn, err := lxdConsoleUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	sess := MustSession(r)
	target := stack + ":" + container
	title := container + " — " + stack
	wsAttachOrCreate(conn, r, sess.UserID, termsessions.KindCompose, target, title, func() (*exec.Cmd, *os.File, error) {
		// Probe for bash; fall back to /bin/sh.
		shell := "/bin/sh"
		if exec.Command("incus", "exec", stack, "--",
			"podman", "exec", container, "which", "bash").Run() == nil {
			shell = "/bin/bash"
		}
		cmd := exec.Command("incus", "exec", stack, "--",
			"podman", "exec", "-it", container, shell)
		cmd.Env = append(os.Environ(), "TERM=xterm-256color")
		ptmx, err := pty.Start(cmd)
		return cmd, ptmx, err
	})
}

// ServeComposeConsolePage serves a full-page xterm.js console targeting one
// podman container inside a stack. Used by "New Tab" / "New Window" terminal
// menu items.
// GET /compose-console/{stack}/{container}
func ServeComposeConsolePage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stack := vars["stack"]
	container := vars["container"]
	if stack == "" || container == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprintf(w, composeConsolePageHTML, container+" — "+stack, stack, container)
}

const composeConsolePageHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>%s</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css">
<style>
* { margin:0; padding:0; box-sizing:border-box; }
html, body { width:100%%; height:100%%; background:#0d1117; overflow:hidden; }
#term { width:100%%; height:100%%; }
</style>
</head>
<body>
<div id="term"></div>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
<script>
const stack = %q;
const container = %q;
const term = new Terminal({ cursorBlink: true, fontSize: 14, theme: { background: '#0d1117' } });
const fitAddon = new FitAddon.FitAddon();
term.loadAddon(fitAddon);
term.open(document.getElementById('term'));
fitAddon.fit();

const proto = location.protocol === 'https:' ? 'wss' : 'ws';
const ws = new WebSocket(proto + '://' + location.host + '/ws/compose-console?stack=' + encodeURIComponent(stack) + '&container=' + encodeURIComponent(container));
ws.binaryType = 'arraybuffer';

ws.onopen = () => {
  term.focus();
  ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
};
ws.onmessage = (ev) => {
  if (ev.data instanceof ArrayBuffer) {
    term.write(new Uint8Array(ev.data));
  } else {
    term.write(ev.data);
  }
};
ws.onclose = () => term.write('\r\n\x1b[33m[session ended]\x1b[0m\r\n');
term.onData(d => ws.send(d));
window.addEventListener('resize', () => {
  fitAddon.fit();
  if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
});
</script>
</body>
</html>`
