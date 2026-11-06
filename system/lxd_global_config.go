package system

// Read/write helpers for the LXD daemon-global config keys exposed by the
// Virtualization settings tab. The set of keys is allow-listed so the UI
// can't accidentally write somewhere it shouldn't (defense in depth, not
// a privilege boundary — `lxc config set` is already gated by the lxd
// group).

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// LXDGlobalConfig holds the keys the Virtualization tab can read or write.
// Pointer-bool fields use nil to mean "key absent / use LXD default" and
// an explicit *bool to mean "set to that value"; this matters when the
// user clears a checkbox vs. never having set it.
type LXDGlobalConfig struct {
	// Listener / API
	HTTPSAddress    string `json:"https_address"`    // core.https_address
	ShutdownTimeout string `json:"shutdown_timeout"` // core.shutdown_timeout
	// Outbound proxy
	ProxyHTTPS       string `json:"proxy_https"`        // core.proxy_https
	ProxyHTTP        string `json:"proxy_http"`         // core.proxy_http
	ProxyIgnoreHosts string `json:"proxy_ignore_hosts"` // core.proxy_ignore_hosts
	// Images
	AutoUpdateInterval string `json:"auto_update_interval"` // images.auto_update_interval (hours; "0" disables)
	AutoUpdateCached   *bool  `json:"auto_update_cached"`   // images.auto_update_cached
	RemoteCacheExpiry  string `json:"remote_cache_expiry"`  // images.remote_cache_expiry (days)
	CompressionAlgo    string `json:"compression_algo"`     // images.compression_algorithm
	// Backups
	BackupCompression string `json:"backup_compression"` // backups.compression_algorithm
	// Metrics — managed by the toggle, included here for read-only display
	MetricsAddress string `json:"metrics_address"`        // core.metrics_address
	MetricsAuth    *bool  `json:"metrics_authentication"` // core.metrics_authentication
}

// lxdConfigKeys maps each JSON field on LXDGlobalConfig to its underlying
// LXD config key. Order matters for SetLXDGlobalConfig (we apply them
// deterministically so audit logs are stable).
var lxdConfigKeys = []struct {
	field string // matches the json tag root, used in audit details
	key   string // LXD config key
	bool  bool   // true if the value is a boolean
}{
	{"https_address", "core.https_address", false},
	{"shutdown_timeout", "core.shutdown_timeout", false},
	{"proxy_https", "core.proxy_https", false},
	{"proxy_http", "core.proxy_http", false},
	{"proxy_ignore_hosts", "core.proxy_ignore_hosts", false},
	{"auto_update_interval", "images.auto_update_interval", false},
	{"auto_update_cached", "images.auto_update_cached", true},
	{"remote_cache_expiry", "images.remote_cache_expiry", false},
	{"compression_algo", "images.compression_algorithm", false},
	{"backup_compression", "backups.compression_algorithm", false},
	{"metrics_address", "core.metrics_address", false},
	{"metrics_authentication", "core.metrics_authentication", true},
}

// GetLXDGlobalConfig fetches the current values for every allow-listed key.
// Missing keys come back as empty strings / nil booleans.
//
// Tries plain `incus query` first (fast path once the service has the
// `incus-admin` group); falls back to `sudo incus query` so the call
// still works inside the enable wizard, where `usermod -a -G incus-admin
// zfsnas` was just run but the service hasn't re-execed and so doesn't
// yet have the new group membership in its kernel-side credentials.
func GetLXDGlobalConfig() (*LXDGlobalConfig, error) {
	out, err := exec.Command("incus", "query", "/1.0").Output()
	if err != nil {
		if out2, err2 := exec.Command("sudo", "incus", "query", "/1.0").Output(); err2 == nil {
			out = out2
		} else {
			return nil, fmt.Errorf("lxc query /1.0: %w", err)
		}
	}
	var resp struct {
		Config map[string]string `json:"config"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("parse /1.0: %w", err)
	}
	if resp.Config == nil {
		resp.Config = map[string]string{}
	}
	cfg := &LXDGlobalConfig{
		HTTPSAddress:       resp.Config["core.https_address"],
		ShutdownTimeout:    resp.Config["core.shutdown_timeout"],
		ProxyHTTPS:         resp.Config["core.proxy_https"],
		ProxyHTTP:          resp.Config["core.proxy_http"],
		ProxyIgnoreHosts:   resp.Config["core.proxy_ignore_hosts"],
		AutoUpdateInterval: resp.Config["images.auto_update_interval"],
		RemoteCacheExpiry:  resp.Config["images.remote_cache_expiry"],
		CompressionAlgo:    resp.Config["images.compression_algorithm"],
		BackupCompression:  resp.Config["backups.compression_algorithm"],
		MetricsAddress:     resp.Config["core.metrics_address"],
	}
	if v, ok := resp.Config["images.auto_update_cached"]; ok {
		b := strings.EqualFold(v, "true")
		cfg.AutoUpdateCached = &b
	}
	if v, ok := resp.Config["core.metrics_authentication"]; ok {
		b := strings.EqualFold(v, "true")
		cfg.MetricsAuth = &b
	}
	return cfg, nil
}

// SetLXDGlobalConfig writes the requested keys. For each field:
//   - empty string / nil bool → unset the key (let LXD use its default)
//   - non-empty string / explicit bool → set
//
// Returns the list of keys that actually changed (for audit logging).
func SetLXDGlobalConfig(cur, want *LXDGlobalConfig) ([]string, error) {
	if cur == nil {
		c, err := GetLXDGlobalConfig()
		if err != nil {
			return nil, err
		}
		cur = c
	}
	var changed []string

	apply := func(key, oldVal, newVal string) error {
		if oldVal == newVal {
			return nil
		}
		var args []string
		if newVal == "" {
			args = []string{"config", "unset", key}
		} else {
			args = []string{"config", "set", key, newVal}
		}
		out, err := exec.Command("incus", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %s", key, strings.TrimSpace(string(out)))
		}
		changed = append(changed, key)
		return nil
	}
	applyBool := func(key string, oldVal, newVal *bool) error {
		ov, nv := "", ""
		if oldVal != nil {
			ov = boolStr(*oldVal)
		}
		if newVal != nil {
			nv = boolStr(*newVal)
		}
		return apply(key, ov, nv)
	}

	if err := apply("core.https_address", cur.HTTPSAddress, want.HTTPSAddress); err != nil {
		return changed, err
	}
	if err := apply("core.shutdown_timeout", cur.ShutdownTimeout, want.ShutdownTimeout); err != nil {
		return changed, err
	}
	if err := apply("core.proxy_https", cur.ProxyHTTPS, want.ProxyHTTPS); err != nil {
		return changed, err
	}
	if err := apply("core.proxy_http", cur.ProxyHTTP, want.ProxyHTTP); err != nil {
		return changed, err
	}
	if err := apply("core.proxy_ignore_hosts", cur.ProxyIgnoreHosts, want.ProxyIgnoreHosts); err != nil {
		return changed, err
	}
	if err := apply("images.auto_update_interval", cur.AutoUpdateInterval, want.AutoUpdateInterval); err != nil {
		return changed, err
	}
	if err := applyBool("images.auto_update_cached", cur.AutoUpdateCached, want.AutoUpdateCached); err != nil {
		return changed, err
	}
	if err := apply("images.remote_cache_expiry", cur.RemoteCacheExpiry, want.RemoteCacheExpiry); err != nil {
		return changed, err
	}
	if err := apply("images.compression_algorithm", cur.CompressionAlgo, want.CompressionAlgo); err != nil {
		return changed, err
	}
	if err := apply("backups.compression_algorithm", cur.BackupCompression, want.BackupCompression); err != nil {
		return changed, err
	}
	// metrics_address / metrics_authentication are typically managed by the
	// toggle, but allow direct edits too for power users.
	if err := apply("core.metrics_address", cur.MetricsAddress, want.MetricsAddress); err != nil {
		return changed, err
	}
	if err := applyBool("core.metrics_authentication", cur.MetricsAuth, want.MetricsAuth); err != nil {
		return changed, err
	}
	return changed, nil
}

// EnableLXDMetricsListener flips on LXD's Prometheus endpoint on the
// loopback address LXDMetricsAddress. No-op if it's already set there;
// returns ("external", currentVal, nil) if it's set to something else
// so the handler can present the conflict warning to the admin.
func EnableLXDMetricsListener() (status, currentVal string, err error) {
	cur, err := GetLXDGlobalConfig()
	if err != nil {
		return "error", "", err
	}
	if cur.MetricsAddress != "" && cur.MetricsAddress != LXDMetricsAddress {
		return "external", cur.MetricsAddress, nil
	}
	if cur.MetricsAddress == LXDMetricsAddress {
		return "ok", LXDMetricsAddress, nil
	}
	if out, err := incusConfigSet("core.metrics_address", LXDMetricsAddress); err != nil {
		return "error", "", fmt.Errorf("set core.metrics_address: %s", strings.TrimSpace(string(out)))
	}
	// Loopback-only listener — disable mTLS so the portal can scrape without
	// also issuing a client cert. Safe because nothing off-host can reach it.
	_, _ = incusConfigSet("core.metrics_authentication", "false")
	return "ok", LXDMetricsAddress, nil
}

// incusConfigSet runs `incus config set <key> <value>`, falling back to
// the sudo form when the bare invocation fails with a permission error.
// This is the same group-lag dance GetLXDGlobalConfig uses (see comment
// there) — keeps the metrics-listener step working inside the enable
// wizard without forcing every other call site through sudo.
func incusConfigSet(key, value string) ([]byte, error) {
	out, err := exec.Command("incus", "config", "set", key, value).CombinedOutput()
	if err == nil {
		return out, nil
	}
	out2, err2 := exec.Command("sudo", "incus", "config", "set", key, value).CombinedOutput()
	if err2 == nil {
		return out2, nil
	}
	return out, err
}

// DisableLXDMetricsListener removes core.metrics_address and metrics_auth.
// No-op when already absent.
func DisableLXDMetricsListener() error {
	exec.Command("incus", "config", "unset", "core.metrics_authentication").Run() //nolint:errcheck
	out, err := exec.Command("incus", "config", "unset", "core.metrics_address").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "not set") {
		return fmt.Errorf("unset core.metrics_address: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ── Realtime per-instance state ─────────────────────────────────────────────

// LXDInstanceRealtime is a single live snapshot for one instance. Cumulative
// fields (cpu_pct, disk_*, net_*) are derived as rates between this poll
// and the previous one held in lxdRealtimeCache; the first poll for any
// instance returns null rates and is discarded by the frontend.
type LXDInstanceRealtime struct {
	TS        int64    `json:"ts"`        // unix millis
	CPUPct    *float64 `json:"cpu_pct"`   // 0–100×vCPUs
	MemUsed   int64    `json:"mem_used"`  // bytes
	MemTotal  int64    `json:"mem_total"` // bytes
	DiskRead  *float64 `json:"disk_r"`    // bytes/s, summed across disks
	DiskWrite *float64 `json:"disk_w"`    // bytes/s, summed across disks
	NetRX     *float64 `json:"net_rx"`    // bytes/s, summed across nics
	NetTX     *float64 `json:"net_tx"`    // bytes/s, summed across nics
	Status    string   `json:"status"`    // "Running" | "Stopped" | etc.
}

// realtimeSnapshot caches the previous tick's cumulative counters so the
// next poll can produce a rate. Keyed by instance name.
//
// All counters come from LXD's Prometheus endpoint (cumulative seconds /
// bytes since boot). The /state endpoint was tried first but reports zero
// for CPU/memory/disk on VMs without lxd-agent inside the guest — the
// metrics endpoint sources from cgroup + the host-side QEMU blockio
// counters and works uniformly for VMs and containers.
type realtimeSnapshot struct {
	ts time.Time
	// Per-metric change-based rate state, keyed "cpu"/"netrx"/"nettx"/
	// "diskr"/"diskw". Each tracks the cumulative value at the last observed
	// CHANGE plus the rate computed then, so we can hold a steady rate across
	// the ~8 s Incus metrics-cache gaps instead of emitting a zero/spike
	// sawtooth against a 3 s poll. See deriveRate.
	states map[string]*rateState
	// lastResult is the LXDInstanceRealtime returned by the most recent
	// non-throttled call. Returned again for any call that arrives
	// within realtimeReuseWindow of `ts` so two concurrent pollers
	// (Live Info card + Monitor tab) for the same instance don't
	// alternate between "real rate" and "≈0" by clobbering each
	// other's baseline 100 ms apart.
	lastResult *LXDInstanceRealtime
}

// rateState holds the change-based baseline for one cumulative counter.
type rateState struct {
	baseVal  float64   // cumulative value at the last observed change
	baseTS   time.Time // time of that change
	lastRate float64   // rate computed at the last change (held across cache gaps)
	haveRate bool
}

// rateStaleAfter is how long deriveRate keeps holding the last computed rate
// while the counter is unchanged (an Incus metrics-cache gap). It must exceed
// the cache interval (~8 s) plus a poll period; once a counter stays flat
// longer than this we assume the activity genuinely stopped and report 0.
const rateStaleAfter = 15 * time.Second

// deriveRate turns a cumulative counter into a smooth instantaneous rate that
// survives Incus's metrics cache. Incus refreshes the Prometheus counters only
// every ~8 s, so a naive (now-prev)/dt over a 3 s poll yields 0 for the polls
// inside a cache gap and a 2-3× spike on the poll that catches the jump.
// Instead we measure each rate over the interval since the counter last
// CHANGED, and between changes we hold that rate (until rateStaleAfter, after
// which we decay to 0 so a stopped workload doesn't read busy forever).
// Returns nil on the first sample / after a counter reset (frontend discards).
func deriveRate(st *rateState, cur float64, now time.Time, scale float64) *float64 {
	if st.baseTS.IsZero() {
		st.baseVal, st.baseTS = cur, now
		return nil // first sample — no baseline yet
	}
	switch {
	case cur > st.baseVal: // counter advanced — rate over the real interval
		dt := now.Sub(st.baseTS).Seconds()
		if dt <= 0 {
			return nil
		}
		r := (cur - st.baseVal) / dt * scale
		st.baseVal, st.baseTS, st.lastRate, st.haveRate = cur, now, r, true
		return &r
	case cur < st.baseVal: // counter reset (instance restarted) — rebaseline
		st.baseVal, st.baseTS, st.haveRate = cur, now, false
		return nil
	default: // unchanged: hold the last rate across the cache gap, else 0
		if st.haveRate && now.Sub(st.baseTS) <= rateStaleAfter {
			r := st.lastRate
			return &r
		}
		z := 0.0
		return &z
	}
}

// realtimeReuseWindow throttles repeated GetLXDInstanceRealtime calls
// for the same instance: if a second caller arrives within this window,
// it gets the previous call's result verbatim and the cumulative
// baseline is NOT updated, so the next non-throttled caller still has
// a meaningful dt to diff against. 1 s is well below the 3-s polling
// cadence the frontend uses on either tab.
const realtimeReuseWindow = 1 * time.Second

var (
	lxdRealtimeMu    sync.Mutex
	lxdRealtimeCache = map[string]realtimeSnapshot{}
)

// GetLXDInstanceRealtime scrapes LXD's Prometheus metrics endpoint, filters
// for one instance, computes rates against the last poll's cumulative
// counters, and returns the snapshot for the front-end. Works for both
// containers AND VMs (the prom endpoint sources from the host's view of
// each instance, which is the only way to see CPU/disk for KVM VMs that
// don't run lxd-agent inside the guest).
//
// The first poll for any instance returns null rates because there's no
// baseline to diff against — the front-end discards that sample.
func GetLXDInstanceRealtime(instance string) (*LXDInstanceRealtime, error) {
	if instance == "" {
		return nil, fmt.Errorf("instance name required")
	}

	// Throttle: if another caller computed a result for this instance
	// in the last realtimeReuseWindow, hand the same value back without
	// touching the cumulative baseline. This is what keeps the Monitor
	// tab graphs steady when the Live Info card poller and the Monitor
	// poller fire close together — without it, whichever ran second
	// saw a tiny dt and emitted a near-zero rate.
	lxdRealtimeMu.Lock()
	if prev, ok := lxdRealtimeCache[instance]; ok && prev.lastResult != nil &&
		time.Since(prev.ts) < realtimeReuseWindow {
		cached := prev.lastResult
		lxdRealtimeMu.Unlock()
		return cached, nil
	}
	lxdRealtimeMu.Unlock()

	body, err := fetchLXDMetricsBody()
	if err != nil {
		return nil, fmt.Errorf("fetch metrics: %w", err)
	}
	samples := parsePromText(body)

	var (
		cpuTotal, netRX, netTX, diskR, diskW  float64
		memActiveAnon, memAvail, memTotalProm float64
		found                                 bool
		status                                string
	)
	for _, s := range samples {
		if s.labels["name"] != instance {
			continue
		}
		found = true
		if status == "" {
			// type label is virtual-machine or container; we don't surface
			// that, but the presence of any sample means "Running".
			status = "Running"
		}
		switch s.metric {
		case "lxd_cpu_seconds_total":
			// Exclude idle/steal — they grow at ~1 sec/sec/vCPU
			// independent of actual guest load, which would peg the
			// derived %CPU at vCPU_count × 100 forever.
			if m := s.labels["mode"]; m == "idle" || m == "steal" {
				continue
			}
			cpuTotal += s.value
		case "lxd_memory_Active_anon_bytes":
			if s.value > memActiveAnon {
				memActiveAnon = s.value
			}
		case "lxd_memory_MemAvailable_bytes":
			if s.value > memAvail {
				memAvail = s.value
			}
		case "lxd_memory_MemTotal_bytes":
			if s.value > memTotalProm {
				memTotalProm = s.value
			}
		case "lxd_disk_read_bytes_total":
			diskR += s.value
		case "lxd_disk_written_bytes_total":
			diskW += s.value
		case "lxd_network_receive_bytes_total":
			netRX += s.value
		case "lxd_network_transmit_bytes_total":
			netTX += s.value
		}
	}

	// Memory derivation is the load-bearing fix for VMs:
	//
	//   Active_anon  — anonymous RSS, only populated when lxd-agent is
	//                  reporting from inside the guest. 0 for VMs without
	//                  the agent.
	//   MemTotal     — exposed by LXD for both containers (cgroup view)
	//                  AND VMs (QEMU's configured limits + balloon
	//                  driver's reading). Always real.
	//   MemAvailable — same source as MemTotal, real for both.
	//
	// "used" = MemTotal − MemAvailable when both are non-zero. Falls back
	// to Active_anon for the (rare) case where the prom endpoint hasn't
	// yet populated MemTotal — e.g., very early in instance lifetime.
	memUsed := memActiveAnon
	if memTotalProm > 0 && memAvail > 0 && memTotalProm > memAvail {
		if v := memTotalProm - memAvail; v > memUsed {
			memUsed = v
		}
	}
	memTotal := int64(memTotalProm)
	if memTotal == 0 {
		memTotal = lxdInstanceMemoryTotal(instance, int64(memUsed+memAvail))
	}

	now := time.Now()
	rt := &LXDInstanceRealtime{
		TS:       now.UnixMilli(),
		MemUsed:  int64(memUsed),
		MemTotal: memTotal,
		Status:   status,
	}
	if !found {
		// The instance isn't currently exporting metrics — typically it's
		// stopped. Return zeros + Stopped status; the frontend renders the
		// readouts as "—" / 0 sparkline, which is correct.
		rt.Status = "Stopped"
		return rt, nil
	}

	lxdRealtimeMu.Lock()
	defer lxdRealtimeMu.Unlock()
	prev, hadPrev := lxdRealtimeCache[instance]
	states := prev.states
	// Fresh start: first ever poll, or the page was paused long enough that
	// an old baseline would yield a bogus rate — rebuild empty state.
	if !hadPrev || states == nil || now.Sub(prev.ts) > 30*time.Second {
		states = map[string]*rateState{
			"cpu": {}, "netrx": {}, "nettx": {}, "diskr": {}, "diskw": {},
		}
	}
	// CPU: seconds-of-CPU per second → % of one host CPU (scale 100). The rest
	// are bytes/s (scale 1). deriveRate smooths over the Incus cache gaps.
	rt.CPUPct = deriveRate(states["cpu"], cpuTotal, now, 100)
	rt.NetRX = deriveRate(states["netrx"], netRX, now, 1)
	rt.NetTX = deriveRate(states["nettx"], netTX, now, 1)
	rt.DiskRead = deriveRate(states["diskr"], diskR, now, 1)
	rt.DiskWrite = deriveRate(states["diskw"], diskW, now, 1)
	lxdRealtimeCache[instance] = realtimeSnapshot{ts: now, states: states, lastResult: rt}
	return rt, nil
}

// lxdInstanceMemoryTotal returns the total memory the instance is configured
// with, in bytes. Falls back to the metrics-derived "used + available" when
// limits.memory isn't set. The metric endpoint exposes memory bytes but no
// "total" — for VMs the QEMU process can grow up to the configured limit;
// for containers the cgroup tracks the host's total RAM unless capped.
func lxdInstanceMemoryTotal(instance string, fallback int64) int64 {
	out, err := exec.Command("incus", "config", "get", instance, "limits.memory").Output()
	if err == nil {
		if v := parseLXDMemorySize(strings.TrimSpace(string(out))); v > 0 {
			return v
		}
	}
	// Fall back to expanded config (catches values inherited from a profile).
	out, err = exec.Command("incus", "query", "/1.0/instances/"+instance).Output()
	if err == nil {
		var inst struct {
			ExpandedConfig map[string]string `json:"expanded_config"`
		}
		if json.Unmarshal(out, &inst) == nil {
			if v := parseLXDMemorySize(strings.TrimSpace(inst.ExpandedConfig["limits.memory"])); v > 0 {
				return v
			}
		}
	}
	if fallback > 0 {
		return fallback
	}
	return 0
}

// parseLXDMemorySize parses LXD's limits.memory value: bytes, KB/MB/GB
// (1000-base, the LXD default), or KiB/MiB/GiB (1024-base), or "<n>%".
// Returns 0 on parse failure or for percentage values (we'd need host
// total RAM to resolve those, and the realtime UI works fine without it).
func parseLXDMemorySize(s string) int64 {
	if s == "" || strings.HasSuffix(s, "%") {
		return 0
	}
	for _, suf := range []struct {
		s    string
		mult int64
	}{
		{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
		{"TB", 1_000_000_000_000}, {"GB", 1_000_000_000}, {"MB", 1_000_000}, {"KB", 1_000},
		{"B", 1},
	} {
		if strings.HasSuffix(s, suf.s) {
			num := strings.TrimSuffix(s, suf.s)
			num = strings.TrimSpace(num)
			var f float64
			if _, err := fmt.Sscanf(num, "%f", &f); err == nil {
				return int64(f * float64(suf.mult))
			}
			return 0
		}
	}
	// Bare integer: bytes.
	var n int64
	fmt.Sscanf(s, "%d", &n)
	return n
}

// _suppressUnused keeps the compiler happy if a build tag ever excludes the
// HTTPS scrape path (it imports tls). Safe no-op.
var _ = tls.Config{}
var _ = http.StatusOK
