package system

// Docker Detection (v6.5.26) — read-side + management helpers for Docker
// containers/stacks deployed *inside* a user-managed VM or LXC.
//
// Everything reaches the guest through `incus exec <name> -- …`, never
// SSH-into-guest or socket-pass-through. That gives us:
//   - no sudoers changes (`incus exec *` is already allow-listed),
//   - no agent install (LXC always works when running; VMs need the
//     incus-agent the user already needs for the LXD Terminal button),
//   - one path that's identical to the existing compose-stack code.
//
// Compose verbs always run with `--cwd <dir of YAML file>` (and we pass
// `-f <basename>` rather than the absolute path) so that relative paths
// inside the compose file — build contexts, env_file, secrets, bind-mount
// volumes written as `./data:/…` — resolve the same way `docker compose`
// would when the user invokes it themselves from that directory. It also
// keeps the default project name (the parent dir's basename) stable,
// which is what `com.docker.compose.project` records in the labels we
// group on.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// composeStackNameRe validates a stack name used as a filesystem folder under
// /opt and as the compose project name. Letters, digits, hyphen, underscore;
// must start alphanumeric. Mirrors the frontend check.
var composeStackNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// ComposeTarget is one instance that can host a new compose stack (#2).
type ComposeTarget struct {
	Name    string `json:"name"`
	Type    string `json:"type"`    // "container" | "virtual-machine"
	Status  string `json:"status"`  // "Running" | ...
	Runtime string `json:"runtime"` // "docker" | "podman"
}

// DockerContainer is one entry rendered into the Docker card.
type DockerContainer struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Image       string   `json:"image"`
	State       string   `json:"state"`        // "running" | "exited" | …
	Status      string   `json:"status"`       // human text
	Ports       string   `json:"ports"`        // formatted
	Project     string   `json:"project"`      // com.docker.compose.project — empty = individual
	Service     string   `json:"service"`      // com.docker.compose.service
	WorkingDir  string   `json:"working_dir"`  // com.docker.compose.project.working_dir
	ConfigFiles []string `json:"config_files"` // com.docker.compose.project.config_files (split on comma)
	// Labels is the container's full label map, retained for service discovery
	// (znas.service.port / homepage.port). Excluded from JSON: the Docker card
	// does not read labels, and some images carry a great many of them.
	Labels map[string]string `json:"-"`
}

// DockerProbeResult tells the frontend whether to render the Docker card.
// `Available` is the single bit the UI conditions on; the rest is
// diagnostic so we can be helpful when the user wonders why nothing shows.
type DockerProbeResult struct {
	Available  bool   `json:"available"`
	AgentOK    bool   `json:"agent_ok"`              // false on a VM whose incus-agent isn't responding
	Runtime    string `json:"runtime,omitempty"`     // "docker" | "podman" | ""
	ComposeCLI string `json:"compose_cli,omitempty"` // "docker compose" | "docker-compose"
	Reason     string `json:"reason,omitempty"`
}

// dockerCLI is the per-instance choice of compose runtime (v2 plugin
// `docker compose` vs legacy `docker-compose`), cached for 60 s so each
// burger-menu click doesn't re-probe. Concurrency-safe.
type dockerCLI struct {
	useV2    bool // true → `docker compose`, false → `docker-compose`
	cachedAt time.Time
}

var (
	dockerCLICache   = map[string]dockerCLI{}
	dockerCLICacheMu sync.Mutex
)

const dockerCLITTL = 60 * time.Second

// DockerProbe runs a cheap two-step probe inside the instance:
//  1. `incus exec` succeeds (LXC always; VM only when agent is up)
//  2. `docker info --format {{.ServerVersion}}` returns non-empty
//
// Anything else → Available=false with a short Reason. Never an error
// the caller is supposed to surface; this is purely a "should we paint
// the card?" decision.
func DockerProbe(instance string) DockerProbeResult {
	// Step 1 — agent reachability. We pick `true` (the busybox/coreutils
	// `/bin/true`) because every guest has it and it returns instantly.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "incus", "exec", instance, "--", "true").Run(); err != nil {
		// `incus exec` against a VM without the agent fails with a
		// recognisable error; rather than parse it we just report
		// agent_ok=false uniformly and let the UI stay quiet.
		return DockerProbeResult{Available: false, AgentOK: false, Reason: "instance not reachable (stopped, or incus-agent not running)"}
	}
	// Step 2 — a container runtime is up. Prefer Docker; fall back to Podman.
	rt, cli := detectRuntime(instance)
	if rt == "" {
		return DockerProbeResult{Available: false, AgentOK: true, Reason: "no docker or podman runtime running"}
	}
	return DockerProbeResult{Available: true, AgentOK: true, Runtime: rt, ComposeCLI: cli}
}

// detectRuntime probes for a container runtime inside the instance and returns
// ("docker"|"podman"|"", composeCLI). It tries Docker first (`docker info`),
// then Podman (`podman info`). composeCLI is the verb head the deploy/action
// paths should use: "docker compose" when the v2 plugin is present, else
// "docker-compose" (the standalone v2 binary we install for Podman talks to
// Podman's Docker-compat socket, so the same `docker-compose` head works).
func detectRuntime(instance string) (runtime, composeCLI string) {
	run := func(timeout time.Duration, args ...string) bool {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, "incus", append([]string{"exec", instance, "--"}, args...)...).Output()
		return err == nil && strings.TrimSpace(string(out)) != ""
	}
	if run(5*time.Second, "docker", "info", "--format", "{{.ServerVersion}}") {
		cli := "docker-compose"
		if dockerComposeV2(instance) {
			cli = "docker compose"
		}
		return "docker", cli
	}
	if run(5*time.Second, "podman", "info", "--format", "{{.Version.Version}}") {
		return "podman", "docker-compose"
	}
	return "", ""
}

// DockerListContainers returns every container (running or not) the
// in-guest docker daemon knows about. Two-step:
//  1. `docker ps -a --no-trunc --format '{{json .}}'` for IDs + names
//  2. `docker inspect <id…>` to pull structured label maps (the ps
//     output flattens labels into a "k=v,k=v" string which is lossy
//     when a value itself contains commas — common in
//     `com.docker.compose.project.config_files`).
//
// Grouping is the caller's job.
func DockerListContainers(instance string) ([]DockerContainer, error) {
	// Podman instances expose a JSON `podman ps` that already carries the
	// compose labels, so we parse that directly rather than the two-step
	// docker ps + inspect dance (podman's inspect schema differs from Docker's).
	if rt, _ := detectRuntime(instance); rt == "podman" {
		return podmanListContainers(instance)
	}
	// Step 1 — gather IDs.
	psOut, err := exec.Command("incus", "exec", instance, "--",
		"docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}}").Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}
	ids := []string{}
	for _, line := range strings.Split(strings.TrimSpace(string(psOut)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			ids = append(ids, line)
		}
	}
	if len(ids) == 0 {
		return []DockerContainer{}, nil
	}
	// Step 2 — full inspect of all IDs at once. `docker inspect` returns
	// a single JSON array. We forward IDs as separate argv elements so
	// no quoting headaches.
	inspArgs := append([]string{"exec", instance, "--", "docker", "inspect", "--format", "{{json .}}"}, ids...)
	inspOut, err := exec.Command("incus", inspArgs...).Output()
	if err != nil {
		return nil, fmt.Errorf("docker inspect: %w", err)
	}
	containers := make([]DockerContainer, 0, len(ids))
	scanner := bufio.NewScanner(strings.NewReader(string(inspOut)))
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var raw struct {
			ID    string `json:"Id"`
			Name  string `json:"Name"`
			Image string `json:"Image"`
			State struct {
				Status     string `json:"Status"`
				StartedAt  string `json:"StartedAt"`
				FinishedAt string `json:"FinishedAt"`
				ExitCode   int    `json:"ExitCode"`
				Health     *struct {
					Status string `json:"Status"`
				} `json:"Health,omitempty"`
			} `json:"State"`
			Config struct {
				Image  string            `json:"Image"`
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
			NetworkSettings struct {
				Ports map[string][]struct {
					HostIP   string `json:"HostIp"`
					HostPort string `json:"HostPort"`
				} `json:"Ports"`
			} `json:"NetworkSettings"`
		}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue // skip malformed entries rather than failing the whole list
		}
		health := ""
		if raw.State.Health != nil {
			health = raw.State.Health.Status
		}
		c := DockerContainer{
			ID:     raw.ID,
			Name:   strings.TrimPrefix(raw.Name, "/"),
			Image:  firstNonEmpty(raw.Config.Image, raw.Image),
			State:  raw.State.Status,
			Status: dockerStatusText(raw.State.Status, raw.State.StartedAt, raw.State.FinishedAt, raw.State.ExitCode, health),
		}
		if c.ID != "" && len(c.ID) > 12 {
			c.ID = c.ID[:12] // short ID for the UI; the long one is still on c by way of Name
		}
		if raw.Config.Labels != nil {
			c.Labels = raw.Config.Labels
			c.Project = raw.Config.Labels["com.docker.compose.project"]
			c.Service = raw.Config.Labels["com.docker.compose.service"]
			c.WorkingDir = raw.Config.Labels["com.docker.compose.project.working_dir"]
			if cf := raw.Config.Labels["com.docker.compose.project.config_files"]; cf != "" {
				for _, part := range strings.Split(cf, ",") {
					p := strings.TrimSpace(part)
					if p != "" {
						c.ConfigFiles = append(c.ConfigFiles, p)
					}
				}
			}
		}
		// Format ports like docker ps does.
		var ports []string
		for spec, bindings := range raw.NetworkSettings.Ports {
			if len(bindings) == 0 {
				continue
			}
			for _, b := range bindings {
				hip := b.HostIP
				if hip == "" {
					hip = "0.0.0.0"
				}
				ports = append(ports, fmt.Sprintf("%s:%s->%s", hip, b.HostPort, spec))
			}
		}
		c.Ports = strings.Join(ports, ", ")
		containers = append(containers, c)
	}
	return containers, nil
}

// DockerReadComposeFile pulls the YAML at `path` out of the instance
// using `incus file pull`. The path is validated by the caller against
// the project's config_files set so this helper never reads arbitrary
// guest paths just because the URL had a tempting query string.
func DockerReadComposeFile(instance, path string) (string, error) {
	tmp, err := os.CreateTemp("", "znas-docker-compose-*.yml")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpName)
	if out, err := exec.Command("incus", "file", "pull",
		instance+path, tmpName).CombinedOutput(); err != nil {
		return "", fmt.Errorf("incus file pull %s: %s", path, strings.TrimSpace(string(out)))
	}
	b, err := os.ReadFile(tmpName)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DockerWriteComposeFile pushes `content` back to `path` inside the
// instance. Used by Save & Apply in the edit modal.
func DockerWriteComposeFile(instance, path, content string) error {
	tmp, err := os.CreateTemp("", "znas-docker-compose-*.yml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	if out, err := exec.Command("incus", "file", "push",
		"--mode=0644", tmpName, instance+path).CombinedOutput(); err != nil {
		return fmt.Errorf("incus file push %s: %s", path, strings.TrimSpace(string(out)))
	}
	return nil
}

// DockerDeleteFile removes one file inside the guest via `incus exec`.
// Used by the edit-compose modal when the user blanks the sidekick
// .env editor → remove the file rather than leave a whitespace-only
// .env on disk that docker compose would still source. A non-existent
// target is not an error (rm -f).
func DockerDeleteFile(instance, path string) error {
	if path == "" || path[0] != '/' {
		return fmt.Errorf("file path must be absolute, got %q", path)
	}
	out, err := exec.Command("incus", "exec", instance, "--", "rm", "-f", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rm -f %s: %s", path, strings.TrimSpace(string(out)))
	}
	return nil
}

// DockerComposeAction runs `docker compose <verb…>` for the project at
// configFile. `verb` is the *full* sub-command — caller passes
// {"up","-d"} or {"pull"} or {"down","-t","10"} etc.
//
// IMPORTANT: this is where the "run from the folder where the
// docker-compose YAML lives" promise is kept. We:
//   - cd into filepath.Dir(configFile) via `incus exec --cwd <dir>`
//   - pass `-f <basename>` rather than the absolute path
//
// so any `./...` reference inside the YAML — build contexts, env_files,
// bind-mount volumes — resolves the same as it would when the user runs
// the same command from a shell in that directory.
func DockerComposeAction(instance, configFile string, verb []string, logCh chan<- string) error {
	if configFile == "" || configFile[0] != '/' {
		return fmt.Errorf("compose file path must be absolute, got %q", configFile)
	}
	dir := filepath.Dir(configFile)
	base := filepath.Base(configFile)
	useV2 := dockerComposeV2(instance)
	var cliHead []string
	if useV2 {
		cliHead = []string{"docker", "compose", "-f", base}
	} else {
		cliHead = []string{"docker-compose", "-f", base}
	}
	cmdArgs := []string{"exec", instance, "--cwd", dir, "--"}
	cmdArgs = append(cmdArgs, cliHead...)
	cmdArgs = append(cmdArgs, verb...)
	return runIncusStreamed("docker compose "+strings.Join(verb, " "), cmdArgs, logCh)
}

// DockerContainerAction runs `docker <verb> <id>` for the per-row
// Start / Stop / Restart menu. `update` is a special two-step:
//   - `docker pull <image>` to refresh the image tag
//   - `docker restart <id>` to bounce the container onto the new layer
//
// The Update mode only works for containers whose creation args we can
// safely reconstruct, which in practice means containers managed by
// docker compose (the caller routes "individual" containers to a
// disabled menu item — see frontend).
func DockerContainerAction(instance, id, verb string, logCh chan<- string) error {
	switch verb {
	case "start", "stop", "restart":
		args := []string{"exec", instance, "--", "docker", verb, id}
		return runIncusStreamed("docker "+verb+" "+id, args, logCh)
	case "update":
		// Pull the image this container was started from, then recreate.
		// We resolve the image via `docker inspect` rather than the
		// shorter docker ps output so we get the digest-resolved name
		// the daemon actually uses.
		out, err := exec.Command("incus", "exec", instance, "--",
			"docker", "inspect", "--format", "{{.Config.Image}}", id).Output()
		if err != nil {
			return fmt.Errorf("inspect %s: %w", id, err)
		}
		img := strings.TrimSpace(string(out))
		if img == "" {
			return fmt.Errorf("could not resolve image for %s", id)
		}
		if err := runIncusStreamed("docker pull "+img,
			[]string{"exec", instance, "--", "docker", "pull", img}, logCh); err != nil {
			return err
		}
		return runIncusStreamed("docker restart "+id,
			[]string{"exec", instance, "--", "docker", "restart", id}, logCh)
	}
	return fmt.Errorf("unsupported verb: %s", verb)
}

// DockerContainerLogs returns the last `tail` lines of one container's log.
// Used by the row-level "Last Outputs" menu item.
func DockerContainerLogs(instance, id string, tail int) (string, error) {
	if tail < 1 {
		tail = 200
	}
	if tail > 10000 {
		tail = 10000
	}
	out, err := exec.Command("incus", "exec", instance, "--",
		"docker", "logs", "--tail", fmt.Sprintf("%d", tail), id).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker logs %s: %w", id, err)
	}
	return string(out), nil
}

// DockerContainerInspect returns the raw JSON `docker inspect` produces
// for one container. Caller pretty-prints / scrolls in a modal.
func DockerContainerInspect(instance, id string) (string, error) {
	out, err := exec.Command("incus", "exec", instance, "--",
		"docker", "inspect", id).Output()
	if err != nil {
		return "", fmt.Errorf("docker inspect %s: %w", id, err)
	}
	return string(out), nil
}

// dockerComposeV2 probes whether the v2 plugin is available inside the
// instance. Cached per-instance for dockerCLITTL so a chatty burger-menu
// session doesn't re-probe on every click.
func dockerComposeV2(instance string) bool {
	dockerCLICacheMu.Lock()
	if e, ok := dockerCLICache[instance]; ok && time.Since(e.cachedAt) < dockerCLITTL {
		dockerCLICacheMu.Unlock()
		return e.useV2
	}
	dockerCLICacheMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := exec.CommandContext(ctx, "incus", "exec", instance, "--",
		"docker", "compose", "version").Run()
	useV2 := err == nil
	dockerCLICacheMu.Lock()
	dockerCLICache[instance] = dockerCLI{useV2: useV2, cachedAt: time.Now()}
	dockerCLICacheMu.Unlock()
	return useV2
}

// runIncusStreamed is a docker-flavoured cousin of runIncusComposeStreamed
// for compose-stack LXCs. Streams stdout+stderr through logCh after
// stripping ANSI; on failure includes the last ~30 output lines.
//
// `label` is what we put in the wrapping error so the caller can tell
// which command failed (the argv is mostly `incus exec …` noise).
func runIncusStreamed(label string, args []string, logCh chan<- string) error {
	cmd := exec.Command("incus", args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	errCh := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		pw.Close()
		errCh <- err
	}()
	scanner := bufio.NewScanner(pr)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var tail []string
	for scanner.Scan() {
		line := strings.TrimRight(composeAnsiRE.ReplaceAllString(scanner.Text(), ""), " \t\r")
		if line == "" {
			continue
		}
		if logCh != nil {
			logCh <- line
		}
		tail = append(tail, line)
		if len(tail) > 30 {
			tail = tail[1:]
		}
	}
	if err := <-errCh; err != nil {
		return fmt.Errorf("%s: %s", label, strings.Join(tail, " | "))
	}
	return nil
}

// dockerStatusText synthesises the same human-friendly status string
// `docker ps` shows ("Up 2 minutes", "Exited (137) 5 min ago", …) from
// the structured fields `docker inspect` returns. Match docker's own
// formatter closely so the cell reads identically to a CLI user's
// expectation, including healthcheck suffix when present.
func dockerStatusText(state, startedAt, finishedAt string, exitCode int, health string) string {
	switch strings.ToLower(state) {
	case "running":
		s := "Up " + dockerDurSince(startedAt)
		switch strings.ToLower(health) {
		case "healthy":
			s += " (healthy)"
		case "unhealthy":
			s += " (unhealthy)"
		case "starting":
			s += " (health: starting)"
		}
		return s
	case "restarting":
		// `docker ps` shows "Restarting (N) X ago" using FinishedAt.
		return fmt.Sprintf("Restarting (%d) %s ago", exitCode, dockerDurSince(finishedAt))
	case "exited":
		return fmt.Sprintf("Exited (%d) %s ago", exitCode, dockerDurSince(finishedAt))
	case "dead":
		return "Dead"
	case "created":
		return "Created"
	case "paused":
		return "Up " + dockerDurSince(startedAt) + " (Paused)"
	default:
		if state == "" {
			return ""
		}
		// Title-case it so an unknown state still looks intentional.
		return strings.ToUpper(state[:1]) + state[1:]
	}
}

// dockerDurSince mirrors go-units' HumanDuration that docker uses on
// the CLI: rounded buckets at second / minute / hour / day / week / month
// / year granularity, no decimals, e.g. "37 seconds", "5 minutes",
// "About a minute", "About an hour", "3 days", "2 weeks", "5 months",
// "2 years". Returns "Less than a second" when the timestamp is in the
// future (clock skew) or unreadable.
func dockerDurSince(ts string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil || t.IsZero() || t.Year() < 2 {
		return "Less than a second"
	}
	d := time.Since(t)
	if d < 0 {
		return "Less than a second"
	}
	sec := int(d.Seconds())
	if sec < 1 {
		return "Less than a second"
	}
	if sec < 60 {
		return fmt.Sprintf("%d seconds", sec)
	}
	min := sec / 60
	if min == 1 {
		return "About a minute"
	}
	if min < 60 {
		return fmt.Sprintf("%d minutes", min)
	}
	hr := min / 60
	if hr == 1 {
		return "About an hour"
	}
	if hr < 48 {
		return fmt.Sprintf("%d hours", hr)
	}
	days := hr / 24
	if days < 7*2 {
		return fmt.Sprintf("%d days", days)
	}
	if days < 30*2 {
		return fmt.Sprintf("%d weeks", days/7)
	}
	if days < 365*2 {
		return fmt.Sprintf("%d months", days/30)
	}
	return fmt.Sprintf("%d years", days/365)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// podmanListContainers lists containers in a Podman instance for the Docker
// card, mapping `podman ps -a --format json` (which carries the compose labels)
// onto the DockerContainer shape used by the grouping/render code.
func podmanListContainers(instance string) ([]DockerContainer, error) {
	out, err := exec.Command("incus", "exec", instance, "--",
		"podman", "ps", "-a", "--format", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("podman ps: %w", err)
	}
	var raw []struct {
		Id     string            `json:"Id"`
		Names  []string          `json:"Names"`
		Image  string            `json:"Image"`
		State  string            `json:"State"`
		Status string            `json:"Status"`
		Labels map[string]string `json:"Labels"`
		Ports  []struct {
			HostIP        string `json:"host_ip"`
			ContainerPort int    `json:"container_port"`
			HostPort      int    `json:"host_port"`
			Protocol      string `json:"protocol"`
		} `json:"Ports"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("podman ps parse: %w", err)
	}
	containers := make([]DockerContainer, 0, len(raw))
	for _, r := range raw {
		c := DockerContainer{ID: r.Id, Image: r.Image, State: r.State, Status: r.Status}
		if len(r.Names) > 0 {
			c.Name = r.Names[0]
		}
		if r.Labels != nil {
			c.Labels = r.Labels
			c.Project = r.Labels["com.docker.compose.project"]
			c.Service = r.Labels["com.docker.compose.service"]
			c.WorkingDir = r.Labels["com.docker.compose.project.working_dir"]
			if cf := r.Labels["com.docker.compose.project.config_files"]; cf != "" {
				c.ConfigFiles = strings.Split(cf, ",")
			}
		}
		var ports []string
		for _, p := range r.Ports {
			if p.HostPort == 0 {
				continue
			}
			hip := p.HostIP
			if hip == "" {
				hip = "0.0.0.0"
			}
			ports = append(ports, fmt.Sprintf("%s:%d->%d/%s", hip, p.HostPort, p.ContainerPort, p.Protocol))
		}
		c.Ports = strings.Join(ports, ", ")
		containers = append(containers, c)
	}
	return containers, nil
}

// ListComposeTargets probes every Running instance for a Docker or Podman
// runtime, concurrently, and returns those that can host a new compose stack
// (option #2). A bounded worker pool keeps the fan-out cheap even on hosts
// with many instances; each probe inherits DockerProbe's per-step timeouts.
func ListComposeTargets() ([]ComposeTarget, error) {
	insts, err := listLXDInstancesImpl()
	if err != nil {
		return nil, err
	}
	type result struct {
		t  ComposeTarget
		ok bool
	}
	sem := make(chan struct{}, 6)
	results := make([]result, len(insts))
	var wg sync.WaitGroup
	for i := range insts {
		inst := insts[i]
		if inst.Status != "Running" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, name, typ, status string) {
			defer wg.Done()
			defer func() { <-sem }()
			pr := DockerProbe(name)
			if pr.Available && pr.Runtime != "" {
				results[idx] = result{ComposeTarget{Name: name, Type: typ, Status: status, Runtime: pr.Runtime}, true}
			}
		}(i, inst.Name, inst.Type, inst.Status)
	}
	wg.Wait()
	out := []ComposeTarget{}
	for _, r := range results {
		if r.ok {
			out = append(out, r.t)
		}
	}
	return out, nil
}

// DeployComposeToInstance drops a new compose stack into an existing instance
// (option #2): /opt/<stackName>/{docker-compose.yml,.env}, then `up -d` with the
// instance's detected runtime. The runtime is re-probed here (never trusted from
// the client). Refuses to overwrite an existing stack folder.
func DeployComposeToInstance(instance, stackName, composeYAML, composeEnv string, logCh chan<- string) error {
	log := func(s string) {
		if logCh != nil {
			logCh <- s
		}
	}
	if !composeStackNameRe.MatchString(stackName) {
		return fmt.Errorf("invalid stack name %q (letters, digits, hyphen, underscore)", stackName)
	}
	probe := DockerProbe(instance)
	if !probe.Available || probe.Runtime == "" {
		return fmt.Errorf("no Docker or Podman runtime detected in %s", instance)
	}
	dir := "/opt/" + stackName
	// Refuse to clobber an existing stack folder.
	if exec.Command("incus", "exec", instance, "--", "test", "-e", dir).Run() == nil {
		return fmt.Errorf("a stack folder already exists at %s in %s — pick another name", dir, instance)
	}

	composeYAML = sanitizeComposeContent(composeYAML)
	composeEnv = sanitizeComposeContent(composeEnv)
	log("Creating " + dir + " in " + instance + "…")
	if out, err := exec.Command("incus", "exec", instance, "--", "mkdir", "-p", dir).CombinedOutput(); err != nil {
		return fmt.Errorf("mkdir %s: %s", dir, strings.TrimSpace(string(out)))
	}
	log("Writing docker-compose.yml…")
	if err := lxdWriteFileInside(instance, dir+"/docker-compose.yml", composeYAML); err != nil {
		return err
	}
	if strings.TrimSpace(composeEnv) != "" {
		log("Writing .env…")
		if err := lxdWriteFileInside(instance, dir+"/.env", composeEnv); err != nil {
			return err
		}
	}

	log("Starting the stack (compose up -d)…")
	if probe.Runtime == "podman" {
		// Make sure docker-compose + the Docker-compat socket exist, then drive
		// compose over DOCKER_HOST exactly like a dedicated podman stack.
		EnsureDockerComposeInStack(instance)
		a := []string{"exec", instance,
			"--env", "DOCKER_HOST=unix:///run/podman/podman.sock",
			"--cwd", dir, "--", "docker-compose", "up", "-d"}
		if err := runIncusStreamed("docker-compose up", a, logCh); err != nil {
			// Files are deployed; only the stack didn't start. Phase 1: report
			// as a job error so the output stays visible and the failure
			// persists. Fix the file and redeploy from the instance.
			log("✗ 'compose up' failed — the stack files were written but the stack did not start.")
			return fmt.Errorf("compose deployment failed: %v", err)
		}
	} else {
		// Real Docker engine — DockerComposeAction picks `docker compose`/`docker-compose`.
		if err := DockerComposeAction(instance, dir+"/docker-compose.yml", []string{"up", "-d"}, logCh); err != nil {
			log("✗ 'compose up' failed — the stack files were written but the stack did not start.")
			return fmt.Errorf("compose deployment failed: %v", err)
		}
	}
	log("✓ Stack is up.")
	return nil
}

// DeleteComposeProject tears down a detected compose project and removes its
// on-disk folder (§6). configFile is the absolute path to the project's compose
// file (from the com.docker.compose.project.config_files label); workingDir is
// the project working dir to rm. The rm is hard-guarded to paths under /opt/.
func DeleteComposeProject(instance, configFile, workingDir string, removeVolumes bool, logCh chan<- string) error {
	log := func(s string) {
		if logCh != nil {
			logCh <- s
		}
	}
	if configFile == "" || configFile[0] != '/' {
		return fmt.Errorf("compose file path must be absolute, got %q", configFile)
	}
	// Validate the rm target up-front (before `down`) so a bad path fails fast
	// without side effects.
	var rmDir string
	if workingDir != "" {
		rmDir = filepath.Clean(workingDir)
		if !strings.HasPrefix(rmDir, "/opt/") || rmDir == "/opt" || rmDir == "/opt/" {
			return fmt.Errorf("refusing to remove %q — only stack folders under /opt/ may be deleted", workingDir)
		}
	}
	verb := []string{"down"}
	if removeVolumes {
		verb = append(verb, "-v")
	}
	log("Stopping stack (compose down" + map[bool]string{true: " -v", false: ""}[removeVolumes] + ")…")
	if err := DockerComposeAction(instance, configFile, verb, logCh); err != nil {
		// Don't abort the folder removal on a down error (the stack may already
		// be partly gone); surface it as a warning and continue.
		log("WARNING: compose down reported an error: " + err.Error())
	}
	if rmDir != "" {
		log("Removing " + rmDir + "…")
		if out, err := exec.Command("incus", "exec", instance, "--", "rm", "-rf", rmDir).CombinedOutput(); err != nil {
			return fmt.Errorf("rm -rf %s: %s", rmDir, strings.TrimSpace(string(out)))
		}
	}
	log("Stack deleted.")
	return nil
}
