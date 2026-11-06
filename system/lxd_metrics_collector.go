package system

// LXD VM/Container performance collector.
//
// When the user toggles "Enable VM and Container Capacity & Performance" in
// the Virtualization settings tab, the portal flips on LXD's built-in
// Prometheus endpoint (bound to 127.0.0.1:9101 — loopback only, no auth
// tokens to manage) and starts the goroutine in this file. Every 5 minutes
// we GET the endpoint, parse the Prometheus text format, fan out by
// instance name, and record the per-instance time series into a
// capacityrrd.DB stored at config/lxd_metrics/<instance>.rrd.json.
//
// One file per instance, intentionally:
//   - Deleting an instance becomes a single os.Remove of a known path.
//   - Each file stays small (~200 KB/year for a typical instance).
//   - The orphan sweep can compare the directory listing against `lxc list`
//     and prune anything LXD no longer knows about — covers deletions that
//     happened from a host shell or while the portal was offline.

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"zfsnas/internal/capacityrrd"
)

// LXDMetricsAddress is the loopback host:port the portal asks LXD to bind
// its Prometheus endpoint to when the toggle is ON. Not user-configurable
// in 6.4.28; promote to AppConfig if a future release needs it.
const LXDMetricsAddress = "127.0.0.1:9101"
const lxdMetricsURL = "https://" + LXDMetricsAddress + "/1.0/metrics"

var (
	lxdMetricsMu  sync.Mutex
	lxdMetricsDBs = map[string]*capacityrrd.DB{}
	lxdMetricsDir string

	// Cumulative counter cache. Key = "<instance>|<series>". Value = the last
	// observed counter value. Rates are derived as (now - prev)/dt.
	lxdMetricsPrev   = map[string]float64{}
	lxdMetricsPrevTS time.Time

	// Status fields exposed via /api/lxd/metrics-status.
	lxdMetricsStatusMu      sync.Mutex
	lxdMetricsLastScrapeTS  time.Time
	lxdMetricsLastScrapeErr string
	lxdMetricsLastInstances int
	lxdMetricsLastSeries    int

	// HTTP client for the metrics endpoint. The endpoint is loopback-only
	// and uses LXD's self-signed cert; skipping verification is the
	// documented LXD pattern for local scraping.
	lxdMetricsHTTPClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
)

// LXDMetricsDir returns the directory holding per-instance RRD files.
// Empty string if the collector hasn't been started yet.
func LXDMetricsDir() string { return lxdMetricsDir }

// LXDMetricsStatus is the live status of the scraper, used by
// /api/lxd/metrics-status to drive the UI badge.
type LXDMetricsStatus struct {
	Enabled       bool   `json:"enabled"`
	Endpoint      string `json:"endpoint"`
	LastScrapeTS  int64  `json:"last_scrape_ts"`
	LastScrapeErr string `json:"last_scrape_error,omitempty"`
	LastInstances int    `json:"last_instances"`
	LastSeries    int    `json:"last_series"`
}

// GetLXDMetricsStatus returns a snapshot of the collector's last-tick state.
func GetLXDMetricsStatus(enabled bool) LXDMetricsStatus {
	lxdMetricsStatusMu.Lock()
	defer lxdMetricsStatusMu.Unlock()
	var ts int64
	if !lxdMetricsLastScrapeTS.IsZero() {
		ts = lxdMetricsLastScrapeTS.Unix()
	}
	return LXDMetricsStatus{
		Enabled:       enabled,
		Endpoint:      lxdMetricsURL,
		LastScrapeTS:  ts,
		LastScrapeErr: lxdMetricsLastScrapeErr,
		LastInstances: lxdMetricsLastInstances,
		LastSeries:    lxdMetricsLastSeries,
	}
}

// GetLXDInstanceMetricsDB returns the per-instance RRD, opening it if needed.
// Returns nil if the collector hasn't been started yet, or if open fails.
func GetLXDInstanceMetricsDB(instance string) *capacityrrd.DB {
	if lxdMetricsDir == "" || instance == "" {
		return nil
	}
	lxdMetricsMu.Lock()
	defer lxdMetricsMu.Unlock()
	if db, ok := lxdMetricsDBs[instance]; ok {
		return db
	}
	path := filepath.Join(lxdMetricsDir, sanitizeInstanceForFilename(instance)+".rrd.json")
	db, err := capacityrrd.Open(path)
	if err != nil {
		log.Printf("lxd metrics: open %s: %v", path, err)
		return nil
	}
	lxdMetricsDBs[instance] = db
	return db
}

// ListLXDMetricInstances returns the names of every LXD instance that has a
// per-instance RRD on disk. Combines the in-memory open-DB cache with a
// scan of lxd_metrics/*.rrd.json so we don't miss instances whose DB
// hasn't been opened in this process yet.
func ListLXDMetricInstances() []string {
	seen := map[string]struct{}{}
	lxdMetricsMu.Lock()
	for name := range lxdMetricsDBs {
		seen[name] = struct{}{}
	}
	dir := lxdMetricsDir
	lxdMetricsMu.Unlock()
	if dir != "" {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				n := e.Name()
				if !strings.HasSuffix(n, ".rrd.json") {
					continue
				}
				name := strings.TrimSuffix(n, ".rrd.json")
				if name == "" {
					continue
				}
				seen[name] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// DeleteLXDInstanceMetrics removes the per-instance RRD file and drops the
// in-memory DB handle. Idempotent — no error if the file is already absent.
// Called from the DeleteInstance handler after a successful lxc delete; the
// caller treats any error as non-fatal so losing history can never block
// instance deletion itself.
func DeleteLXDInstanceMetrics(instance string) error {
	if lxdMetricsDir == "" || instance == "" {
		return nil
	}
	lxdMetricsMu.Lock()
	delete(lxdMetricsDBs, instance)
	lxdMetricsMu.Unlock()

	// Drop counter-cache entries for this instance so a re-creation under
	// the same name doesn't see a stale baseline.
	prefix := instance + "|"
	for k := range lxdMetricsPrev {
		if strings.HasPrefix(k, prefix) {
			delete(lxdMetricsPrev, k)
		}
	}

	path := filepath.Join(lxdMetricsDir, sanitizeInstanceForFilename(instance)+".rrd.json")
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// SweepOrphanLXDMetrics removes RRD files for instances LXD no longer knows
// about. Called at boot and on a daily ticker. Conservative: skipped if the
// LXD query itself fails (e.g. LXD restarting), so a transient error never
// causes mass deletion.
func SweepOrphanLXDMetrics() {
	if lxdMetricsDir == "" {
		return
	}
	live, err := listLXDInstanceNames()
	if err != nil {
		// LXD unreachable — leave files alone.
		return
	}
	liveSet := map[string]bool{}
	for _, name := range live {
		liveSet[name] = true
	}

	entries, err := os.ReadDir(lxdMetricsDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".rrd.json") {
			continue
		}
		instance := strings.TrimSuffix(name, ".rrd.json")
		if liveSet[instance] {
			continue
		}
		if err := DeleteLXDInstanceMetrics(instance); err == nil {
			log.Printf("lxd metrics: pruned orphan %s", instance)
		}
	}
}

// listLXDInstanceNames returns names of all LXD instances (any state). Uses
// `lxc list --format json -c n` which is the cheapest available query.
func listLXDInstanceNames() ([]string, error) {
	out, err := exec.Command("incus", "list", "--format", "csv", "-c", "n").Output()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			names = append(names, line)
		}
	}
	return names, nil
}

// StartLXDMetricsCollector creates config/lxd_metrics/ and runs a 5-minute
// scrape loop. Pure no-op on each tick when getEnabled() returns false; we
// don't tear down the goroutine because the toggle is expected to flip
// during normal operation.
//
// Series naming inside each per-instance file (no instance prefix — the
// file path already encodes it):
//
//	cpu                   — % of one host CPU (sum across cpu/mode pairs)
//	mem                   — bytes (Active_anon, the LXD-recommended "used")
//	mem_avail             — bytes (MemAvailable)
//	net_rx:<device>       — bytes/s
//	net_tx:<device>       — bytes/s
//	disk_r:<device>       — bytes/s
//	disk_w:<device>       — bytes/s
func StartLXDMetricsCollector(configDir string, getEnabled func() bool) {
	dir := filepath.Join(configDir, "lxd_metrics")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("lxd metrics: mkdir %s: %v", dir, err)
		return
	}
	lxdMetricsDir = dir

	go func() {
		runScrape := func(now time.Time) {
			if !getEnabled() {
				return
			}
			if err := scrapeLXDMetricsOnce(now); err != nil {
				lxdMetricsStatusMu.Lock()
				lxdMetricsLastScrapeErr = err.Error()
				lxdMetricsStatusMu.Unlock()
				log.Printf("lxd metrics: scrape: %v", err)
			}
		}

		// Kick off an immediate scrape so the UI badge leaves "… starting"
		// within seconds of boot rather than waiting the full 5-min tick.
		// Counter-derived series (cpu, net, disk) still need the next tick
		// for a rate baseline; gauges (memory) populate right away.
		runScrape(time.Now())

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		// Periodic orphan sweep (~every 2h) regardless of scrape success.
		sweepTicks := 0
		for now := range ticker.C {
			runScrape(now)
			sweepTicks++
			if sweepTicks >= 24 { // ~2h
				sweepTicks = 0
				SweepOrphanLXDMetrics()
			}
		}
	}()
}

// scrapeLXDMetricsOnce performs a single GET → parse → record cycle.
func scrapeLXDMetricsOnce(now time.Time) error {
	body, err := fetchLXDMetricsBody()
	if err != nil {
		return err
	}
	samples := parsePromText(body)

	// Group samples by instance name and convert to records.
	type seriesKey struct {
		instance  string
		series    string
		isCounter bool
	}
	type rec struct {
		key   seriesKey
		value float64
	}
	var recs []rec

	dt := 0.0
	if !lxdMetricsPrevTS.IsZero() {
		dt = now.Sub(lxdMetricsPrevTS).Seconds()
	}

	cpuSums := map[string]float64{} // instance → cumulative cpu seconds (summed across cpu+mode)
	// Memory needs a tiny per-tick buffer per instance because we record a
	// derived value (MemTotal - MemAvailable). Active_anon is kept as a
	// fallback for the case where MemTotal hasn't been populated yet.
	memActiveAnon := map[string]float64{}
	memAvail := map[string]float64{}
	memTotal := map[string]float64{}
	// Per-filesystem usage, keyed "instance|mountpoint". Real disk filesystems
	// only — pseudo mounts (tmpfs, overlay, squashfs/loop, proc/sys, lxcfs…) are
	// dropped so they never enter the RRD or the % chart.
	fsSize := map[string]float64{}
	fsAvail := map[string]float64{}
	fsFree := map[string]float64{}
	// Per-instance mountpoint sets used to prune stale pseudo-FS series an older
	// collector may have stored (tmpfs/loop/dm/flash …). allFsMounts = every
	// mountpoint reported this scrape; realFsMounts = those that passed the
	// real-FS filter. The difference is definitively pseudo → DeleteKey.
	allFsMounts := map[string]map[string]bool{}
	realFsMounts := map[string]map[string]bool{}
	for _, s := range samples {
		instance := s.labels["name"]
		if instance == "" {
			continue
		}
		switch s.metric {
		case "lxd_cpu_seconds_total":
			// Sum only "busy" CPU modes. idle and steal grow at ~1 sec
			// per real second per vCPU regardless of guest load, so
			// including them pegs the rate at vCPU_count × 100% and
			// flattens the chart.
			if m := s.labels["mode"]; m == "idle" || m == "steal" {
				continue
			}
			cpuSums[instance] += s.value
		case "lxd_memory_Active_anon_bytes":
			if s.value > memActiveAnon[instance] {
				memActiveAnon[instance] = s.value
			}
		case "lxd_memory_MemAvailable_bytes":
			if s.value > memAvail[instance] {
				memAvail[instance] = s.value
			}
		case "lxd_memory_MemTotal_bytes":
			if s.value > memTotal[instance] {
				memTotal[instance] = s.value
			}
		case "lxd_network_receive_bytes_total":
			if dev := s.labels["device"]; dev != "" {
				recs = append(recs, rec{seriesKey{instance, "net_rx:" + dev, true}, s.value})
			}
		case "lxd_network_transmit_bytes_total":
			if dev := s.labels["device"]; dev != "" {
				recs = append(recs, rec{seriesKey{instance, "net_tx:" + dev, true}, s.value})
			}
		case "lxd_disk_read_bytes_total":
			if dev := s.labels["device"]; dev != "" {
				recs = append(recs, rec{seriesKey{instance, "disk_r:" + dev, true}, s.value})
			}
		case "lxd_disk_written_bytes_total":
			if dev := s.labels["device"]; dev != "" {
				recs = append(recs, rec{seriesKey{instance, "disk_w:" + dev, true}, s.value})
			}
		case "lxd_filesystem_size_bytes", "lxd_filesystem_avail_bytes", "lxd_filesystem_free_bytes":
			mp := s.labels["mountpoint"]
			if mp != "" {
				if allFsMounts[instance] == nil {
					allFsMounts[instance] = map[string]bool{}
				}
				allFsMounts[instance][mp] = true
			}
			if !isRealGuestFilesystem(s.labels["device"], s.labels["fstype"], mp) {
				continue
			}
			if realFsMounts[instance] == nil {
				realFsMounts[instance] = map[string]bool{}
			}
			realFsMounts[instance][mp] = true
			k := instance + "|" + mp
			switch s.metric {
			case "lxd_filesystem_size_bytes":
				if s.value > fsSize[k] {
					fsSize[k] = s.value
				}
			case "lxd_filesystem_avail_bytes":
				fsAvail[k] = s.value
			default: // lxd_filesystem_free_bytes
				fsFree[k] = s.value
			}
		}
	}
	// Memory: compute derived "used" so VMs without lxd-agent still get
	// real values. Active_anon is a fallback when MemTotal is missing.
	memInstances := map[string]bool{}
	for k := range memActiveAnon {
		memInstances[k] = true
	}
	for k := range memAvail {
		memInstances[k] = true
	}
	for k := range memTotal {
		memInstances[k] = true
	}
	for instance := range memInstances {
		used := memActiveAnon[instance]
		if t := memTotal[instance]; t > 0 {
			if a := memAvail[instance]; t > a {
				if v := t - a; v > used {
					used = v
				}
			}
		}
		recs = append(recs, rec{seriesKey{instance, "mem", false}, used})
		recs = append(recs, rec{seriesKey{instance, "mem_avail", false}, memAvail[instance]})
		if t := memTotal[instance]; t > 0 {
			recs = append(recs, rec{seriesKey{instance, "mem_total", false}, t})
		}
	}
	// Fold the per-instance CPU totals in as a counter; rate becomes %CPU.
	for instance, total := range cpuSums {
		recs = append(recs, rec{seriesKey{instance, "cpu", true}, total})
	}
	// Per-filesystem: record used + total bytes (gauges). The frontend graphs
	// the % (used/total) and shows used-vs-total in the hover popup.
	for k, size := range fsSize {
		if size <= 0 {
			continue
		}
		avail := fsAvail[k]
		if avail == 0 {
			avail = fsFree[k] // fall back to total-free when avail isn't emitted
		}
		used := size - avail
		if used < 0 {
			used = 0
		}
		instance, mp, ok := strings.Cut(k, "|")
		if !ok {
			continue
		}
		recs = append(recs, rec{seriesKey{instance, "fs_used:" + mp, false}, used})
		recs = append(recs, rec{seriesKey{instance, "fs_size:" + mp, false}, size})
	}

	instanceSet := map[string]bool{}
	seriesCount := 0
	for _, r := range recs {
		instanceSet[r.key.instance] = true
		ckey := r.key.instance + "|" + r.key.series
		var val float64
		if r.key.isCounter {
			prev, hadPrev := lxdMetricsPrev[ckey]
			lxdMetricsPrev[ckey] = r.value
			if !hadPrev || dt <= 0 {
				continue // first sample for this counter — skip
			}
			delta := r.value - prev
			if delta < 0 {
				continue // counter reset (LXD restarted) — skip this sample
			}
			val = delta / dt
			if r.key.series == "cpu" {
				// Convert seconds-of-CPU/sec → % of one host CPU.
				val *= 100
			}
		} else {
			val = r.value
		}
		db := GetLXDInstanceMetricsDB(r.key.instance)
		if db == nil {
			continue
		}
		db.Record(r.key.series, val, now)
		seriesCount++
	}

	// Prune pseudo-FS series an older collector recorded. A mountpoint reported
	// this scrape but rejected by isRealGuestFilesystem is definitively pseudo
	// (tmpfs/loop/dm/flash/snap …) — drop its fs_used/fs_size history so it
	// disappears from BOTH the table popup and the Monitor chart. Only mounts
	// actually seen this scrape are touched, so a transiently-absent real disk
	// is never deleted.
	for instance, mounts := range allFsMounts {
		var db *capacityrrd.DB
		for mp := range mounts {
			if realFsMounts[instance][mp] {
				continue
			}
			if db == nil {
				if db = GetLXDInstanceMetricsDB(instance); db == nil {
					break
				}
			}
			db.DeleteKey("fs_used:" + mp)
			db.DeleteKey("fs_size:" + mp)
		}
	}

	// Flush every dirty DB. Iterate the map under the lock.
	lxdMetricsMu.Lock()
	dbsCopy := make([]*capacityrrd.DB, 0, len(lxdMetricsDBs))
	for _, db := range lxdMetricsDBs {
		dbsCopy = append(dbsCopy, db)
	}
	lxdMetricsMu.Unlock()
	for _, db := range dbsCopy {
		if err := db.Flush(); err != nil {
			log.Printf("lxd metrics: flush: %v", err)
		}
	}

	lxdMetricsPrevTS = now
	lxdMetricsStatusMu.Lock()
	lxdMetricsLastScrapeTS = now
	lxdMetricsLastScrapeErr = ""
	lxdMetricsLastInstances = len(instanceSet)
	lxdMetricsLastSeries = seriesCount
	lxdMetricsStatusMu.Unlock()
	return nil
}

// fetchLXDMetricsBody retrieves the prometheus text. Tries the loopback
// HTTPS endpoint first (the path the toggle enables) and falls back to
// `lxc query /1.0/metrics` if the HTTPS path fails — that fallback works
// when the user has already configured the metrics listener on a
// non-loopback address externally.
func fetchLXDMetricsBody() (string, error) {
	resp, err := lxdMetricsHTTPClient.Get(lxdMetricsURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			b, rerr := io.ReadAll(resp.Body)
			if rerr == nil {
				return string(b), nil
			}
		}
	}
	// Fallback via the lxc CLI / unix socket.
	out, qerr := exec.Command("incus", "query", "/1.0/metrics").Output()
	if qerr != nil {
		if err != nil {
			return "", fmt.Errorf("https %s: %v; lxc query: %v", lxdMetricsURL, err, qerr)
		}
		return "", fmt.Errorf("lxc query: %v", qerr)
	}
	return string(out), nil
}

// promSample is one line of parsed Prometheus text output.
type promSample struct {
	metric string
	labels map[string]string
	value  float64
}

// parsePromText is a minimal Prometheus text-format parser. LXD/Incus
// output is exposition-format-compliant but simple (no histograms we care
// about, no exemplars), so we skip the official client_model dependency
// and parse a single sample per non-comment line. Lines that fail to
// parse are silently dropped — partial output is better than no output.
//
// Metric-name normalization (added in v6.5.27 after the .5 host running
// Incus 6.0.5 reported empty graphs): when LXD was forked into Incus,
// the Prometheus metric prefix changed from `lxd_*` to `incus_*`. Ubuntu
// 26.04 ships Incus 6.0.5, which emits `incus_cpu_seconds_total`,
// `incus_memory_Active_anon_bytes`, etc. — none of which matched our
// `lxd_*` switch cases, so every sample was silently dropped and the
// per-instance RRD files never got created. Normalizing here means the
// rest of the collector (this file + lxd_global_config.go realtime path)
// switches on the canonical `lxd_*` names and works uniformly on both
// stacks without any per-call-site `if HasPrefix` branches.
func parsePromText(body string) []promSample {
	var out []promSample
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// metric_name{label="v",label="v"} 0.123 [timestamp]
		// metric_name 0.123
		nameEnd := strings.IndexAny(line, "{ ")
		if nameEnd < 0 {
			continue
		}
		name := line[:nameEnd]
		if strings.HasPrefix(name, "incus_") {
			name = "lxd_" + name[len("incus_"):]
		}
		s := promSample{metric: name, labels: map[string]string{}}
		rest := strings.TrimSpace(line[nameEnd:])
		if strings.HasPrefix(rest, "{") {
			// Find matching '}' (labels never contain unescaped '}').
			end := strings.IndexByte(rest, '}')
			if end < 0 {
				continue
			}
			parseLabels(rest[1:end], s.labels)
			rest = strings.TrimSpace(rest[end+1:])
		}
		// rest is now "value [timestamp]"; we ignore the timestamp.
		valStr := rest
		if i := strings.IndexAny(rest, " \t"); i >= 0 {
			valStr = rest[:i]
		}
		v, err := strconv.ParseFloat(valStr, 64)
		if err != nil {
			continue
		}
		s.value = v
		out = append(out, s)
	}
	return out
}

// pseudoFstypes are virtual/in-memory filesystems that must never enter the
// per-instance filesystem RRD or % chart — they aren't real disk capacity.
var pseudoFstypes = map[string]bool{
	"tmpfs": true, "devtmpfs": true, "ramfs": true, "overlay": true, "overlayfs": true,
	"squashfs": true, "proc": true, "sysfs": true, "cgroup": true, "cgroup2": true,
	"devpts": true, "mqueue": true, "hugetlbfs": true, "debugfs": true, "tracefs": true,
	"securityfs": true, "selinuxfs": true, "pstore": true, "bpf": true, "configfs": true,
	"fusectl": true, "binfmt_misc": true, "autofs": true, "nsfs": true, "efivarfs": true,
	"rpc_pipefs": true, "fuse.lxcfs": true,
}

// isRealGuestFilesystem reports whether a filesystem metric describes a real
// disk-backed mount of the instance (ext4/xfs/btrfs/zfs/vfat/…) rather than a
// pseudo mount we want excluded (tmpfs, overlay, squashfs over loop devices,
// proc/sys/cgroup, lxcfs, etc.).
func isRealGuestFilesystem(device, fstype, mountpoint string) bool {
	if mountpoint == "" {
		return false
	}
	// Pseudo mount trees. tmpfs/ramfs/proc/sysfs live here, and Incus sometimes
	// reports them with an opaque hex statfs magic (e.g. "0x-7a7ba70a") instead
	// of a name, so a fstype-name denylist alone misses them — match by path too.
	for _, pre := range []string{"/proc", "/sys", "/dev", "/run"} {
		if mountpoint == pre || strings.HasPrefix(mountpoint, pre+"/") {
			return false
		}
	}
	// snap/loop-squashfs and other container-runtime pseudo trees by mountpoint.
	for _, pre := range []string{"/snap", "/var/snap", "/var/lib/docker", "/var/lib/lxcfs"} {
		if mountpoint == pre || strings.HasPrefix(mountpoint, pre+"/") {
			return false
		}
	}
	if pseudoFstypes[fstype] || strings.HasPrefix(fstype, "fuse.") {
		return false
	}
	// Device-name denylist. Normalize a leading /dev/ so both "loop0" and
	// "/dev/loop0" match. Excludes loopback, device-mapper / LVM (dm-*,
	// /dev/mapper/*), QEMU firmware flash (system.flash*), overlay, none.
	base := strings.TrimPrefix(strings.ToLower(device), "/dev/")
	if strings.Contains(base, "loop") ||
		strings.HasPrefix(base, "dm-") ||
		strings.HasPrefix(base, "mapper/") || strings.Contains(base, "/mapper/") ||
		strings.Contains(base, "flash") ||
		base == "overlay" || base == "none" {
		return false
	}
	return true
}

// parseLabels parses the inside of a {…} label set: name="value",name="value".
// Supports the standard escapes \\, \", \n.
func parseLabels(s string, out map[string]string) {
	i := 0
	for i < len(s) {
		// Skip whitespace and commas.
		for i < len(s) && (s[i] == ',' || s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			return
		}
		// label name
		nameStart := i
		for i < len(s) && s[i] != '=' {
			i++
		}
		if i >= len(s) {
			return
		}
		name := s[nameStart:i]
		i++ // skip '='
		if i >= len(s) || s[i] != '"' {
			return
		}
		i++ // skip opening quote
		var b strings.Builder
		for i < len(s) {
			c := s[i]
			if c == '"' {
				i++
				break
			}
			if c == '\\' && i+1 < len(s) {
				switch s[i+1] {
				case '\\':
					b.WriteByte('\\')
				case '"':
					b.WriteByte('"')
				case 'n':
					b.WriteByte('\n')
				default:
					b.WriteByte(s[i+1])
				}
				i += 2
				continue
			}
			b.WriteByte(c)
			i++
		}
		out[name] = b.String()
	}
}

// sanitizeInstanceForFilename replaces filesystem-unfriendly characters
// in an instance name. LXD's allowed alphabet is [a-zA-Z0-9-] but be
// defensive: anything outside that becomes '_'.
func sanitizeInstanceForFilename(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
