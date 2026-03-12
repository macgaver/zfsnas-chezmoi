package system

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ── Pool ──────────────────────────────────────────────────────────────────────

// Pool represents a ZFS pool.
type Pool struct {
	Name        string   `json:"name"`
	Size        uint64   `json:"size"`         // raw physical size (zpool list)
	Alloc       uint64   `json:"alloc"`        // allocated bytes (zpool list)
	Free        uint64   `json:"free"`         // free raw bytes (zpool list)
	UsableSize  uint64   `json:"usable_size"`  // usable = root used + root avail (zfs list)
	UsableUsed  uint64   `json:"usable_used"`  // root dataset used (zfs list)
	UsableAvail uint64   `json:"usable_avail"` // root dataset avail (zfs list)
	Health      string   `json:"health"`
	Members     []string `json:"members"`    // physical device paths in the pool
	VdevType    string   `json:"vdev_type"`  // "stripe" | "mirror" | "raidz1" | "raidz2"
	Operation   string   `json:"operation"`  // "" | "scrubbing" | "resilvering" | "expanding"
	SizeStr     string   `json:"size_str"`
	AllocStr    string   `json:"alloc_str"`
	FreeStr     string   `json:"free_str"`
}

// GetPool returns the single imported pool, or nil if none exists.
func GetPool() (*Pool, error) {
	out, err := exec.Command("sudo", "zpool", "list", "-Hp",
		"-o", "name,size,alloc,free,health").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return nil, nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return nil, nil
	}
	p, err := parsePool(lines[0])
	if err != nil {
		return nil, err
	}
	// Populate usable capacity from `zfs list` (root dataset used + avail).
	p.UsableUsed, p.UsableAvail = poolRootUsage(p.Name)
	p.UsableSize = p.UsableUsed + p.UsableAvail
	// Populate member devices from `zpool status -P`.
	p.Members    = poolMembers(p.Name)
	p.VdevType   = poolVdevType(p.Name)
	p.Operation  = poolOperation(p.Name)
	return p, nil
}

func parsePool(line string) (*Pool, error) {
	f := strings.Split(line, "\t")
	if len(f) < 5 {
		return nil, fmt.Errorf("unexpected zpool output: %q", line)
	}
	size, _ := strconv.ParseUint(f[1], 10, 64)
	alloc, _ := strconv.ParseUint(f[2], 10, 64)
	free, _ := strconv.ParseUint(f[3], 10, 64)
	return &Pool{
		Name:     f[0],
		Size:     size,
		Alloc:    alloc,
		Free:     free,
		Health:   strings.TrimSpace(f[4]),
		SizeStr:  formatBytes(size),
		AllocStr: formatBytes(alloc),
		FreeStr:  formatBytes(free),
	}, nil
}

// poolRootUsage returns the used and avail bytes for the pool's root dataset.
func poolRootUsage(poolName string) (used, avail uint64) {
	out, err := exec.Command("sudo", "zfs", "list", "-Hp",
		"-o", "used,avail", poolName).Output()
	if err != nil {
		return 0, 0
	}
	f := strings.Fields(strings.TrimSpace(string(out)))
	if len(f) >= 2 {
		used, _ = strconv.ParseUint(f[0], 10, 64)
		avail, _ = strconv.ParseUint(f[1], 10, 64)
	}
	return
}

// poolMembers parses `zpool status -P` to return physical device paths.
func poolMembers(poolName string) []string {
	out, err := exec.Command("sudo", "zpool", "status", "-P", poolName).Output()
	if err != nil {
		return nil
	}
	var members []string
	inConfig := false
	validStates := map[string]bool{
		"ONLINE": true, "DEGRADED": true, "FAULTED": true,
		"OFFLINE": true, "REMOVED": true, "UNAVAIL": true,
	}
	skipPrefixes := []string{"raidz", "mirror-", "spare-", "log-", "cache-", "NAME"}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "config:") {
			inConfig = true
			continue
		}
		if !inConfig || trimmed == "" || strings.HasPrefix(trimmed, "errors:") {
			if strings.HasPrefix(trimmed, "errors:") {
				break
			}
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		name, state := fields[0], fields[1]
		if !validStates[state] {
			continue
		}
		if name == poolName {
			continue
		}
		skip := false
		for _, pfx := range skipPrefixes {
			if strings.HasPrefix(name, pfx) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		members = append(members, resolveDevPath(name))
	}
	return members
}

// resolveDevPath resolves symlinks (e.g. /dev/disk/by-id/... or
// /dev/disk/by-uuid/...) to their canonical /dev/sdX path.
// Returns the original path unchanged if resolution fails or the result
// does not look like a block device.
func resolveDevPath(p string) string {
	real, err := filepath.EvalSymlinks(p)
	if err != nil || !strings.HasPrefix(real, "/dev/") {
		return p
	}
	return real
}

// CreatePool creates a new ZFS pool.
// layout: "stripe" | "mirror" | "raidz1" | "raidz2"
// ashift: 9, 12, or 13
// compression: "off" | "lz4" | "zstd"
func CreatePool(name, layout string, ashift int, compression string, devices []string) error {
	args := []string{"zpool", "create",
		"-o", fmt.Sprintf("ashift=%d", ashift),
		"-O", "atime=off",
	}
	if compression != "off" {
		args = append(args, "-O", "compression="+compression)
	}
	args = append(args, name)
	if layout == "mirror" || layout == "raidz1" || layout == "raidz2" {
		args = append(args, layout)
	}
	args = append(args, devices...)
	debugLog("zpool create: %v", args)
	out, err := exec.Command("sudo", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ImportablePool is a pool found by `zpool import` scan.
type ImportablePool struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	State string `json:"state"`
}

// DetectImportablePools scans for pools that can be imported.
func DetectImportablePools() ([]ImportablePool, error) {
	out, _ := exec.Command("sudo", "zpool", "import").CombinedOutput()
	return parseImportOutput(string(out)), nil
}

func parseImportOutput(output string) []ImportablePool {
	var pools []ImportablePool
	var cur *ImportablePool
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pool:") {
			if cur != nil {
				pools = append(pools, *cur)
			}
			cur = &ImportablePool{Name: strings.TrimSpace(strings.TrimPrefix(line, "pool:"))}
		} else if cur != nil {
			if strings.HasPrefix(line, "id:") {
				cur.ID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			} else if strings.HasPrefix(line, "state:") {
				cur.State = strings.TrimSpace(strings.TrimPrefix(line, "state:"))
			}
		}
	}
	if cur != nil {
		pools = append(pools, *cur)
	}
	return pools
}

// ── Scrub ─────────────────────────────────────────────────────────────────────

// ScrubInfo holds the parsed state of a ZFS pool scrub.
type ScrubInfo struct {
	State       string  `json:"state"`                 // idle | running | finished | canceled
	ProgressPct float64 `json:"progress_pct,omitempty"`
	TimeLeft    string  `json:"time_left,omitempty"`
	Duration    string  `json:"duration,omitempty"`
	Errors      int64   `json:"errors"`
	StartTime   string  `json:"start_time,omitempty"`
	FinishTime  string  `json:"finish_time,omitempty"`
}

// GetScrubStatus parses `zpool status` to extract scrub information.
func GetScrubStatus(poolName string) (*ScrubInfo, error) {
	out, err := exec.Command("sudo", "zpool", "status", poolName).CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("zpool status: %w", err)
	}
	return parseScrubInfo(string(out)), nil
}

func parseScrubInfo(output string) *ScrubInfo {
	info := &ScrubInfo{State: "idle"}
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "scan:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "scan:"))

		switch {
		case rest == "none requested" || rest == "":
			info.State = "idle"

		case strings.HasPrefix(rest, "scrub in progress"):
			info.State = "running"
			// e.g. "scrub in progress since Sun Mar  9 02:00:00 2026"
			if idx := strings.Index(rest, "since "); idx >= 0 {
				info.StartTime = strings.TrimSpace(rest[idx+6:])
			}
			// Next line: "  9.99% done, 0 days 00:15:00 to go"
			if i+1 < len(lines) {
				next := strings.TrimSpace(lines[i+1])
				if pctIdx := strings.Index(next, "% done"); pctIdx > 0 {
					pctStr := strings.TrimSpace(next[:pctIdx])
					// might be "  9.99" — take last word
					parts := strings.Fields(pctStr)
					if len(parts) > 0 {
						fmt.Sscanf(parts[len(parts)-1], "%f", &info.ProgressPct)
					}
				}
				if toGoIdx := strings.Index(next, " to go"); toGoIdx > 0 {
					// extract between ", " and " to go"
					commaIdx := strings.LastIndex(next[:toGoIdx], ", ")
					if commaIdx >= 0 {
						info.TimeLeft = strings.TrimSpace(next[commaIdx+2 : toGoIdx])
					}
				}
			}

		case strings.HasPrefix(rest, "scrub repaired") || strings.HasPrefix(rest, "scrub canceled"):
			if strings.HasPrefix(rest, "scrub canceled") {
				info.State = "canceled"
			} else {
				info.State = "finished"
			}
			// e.g. "scrub repaired 0B in 00:01:23 with 0 errors on Sun Mar  9 02:00:05 2026"
			if idx := strings.Index(rest, " in "); idx > 0 {
				after := rest[idx+4:]
				// duration is up to " with"
				if wIdx := strings.Index(after, " with "); wIdx > 0 {
					info.Duration = strings.TrimSpace(after[:wIdx])
					errPart := after[wIdx+6:] // "0 errors on ..."
					fmt.Sscanf(errPart, "%d", &info.Errors)
				}
			}
			if idx := strings.Index(rest, " on "); idx > 0 {
				info.FinishTime = strings.TrimSpace(rest[idx+4:])
			}
		}
		break
	}
	return info
}

// StartScrub initiates a scrub on the given pool.
func StartScrub(poolName string) error {
	out, err := exec.Command("sudo", "zpool", "scrub", poolName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("zpool scrub: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// StopScrub pauses/cancels a running scrub.
func StopScrub(poolName string) error {
	out, err := exec.Command("sudo", "zpool", "scrub", "-s", poolName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("zpool scrub -s: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// GetPoolStatus returns the raw output of `zpool status`.
func GetPoolStatus() (string, error) {
	out, err := exec.Command("sudo", "zpool", "status").CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", fmt.Errorf("zpool status: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// GetZFSVersion returns the major, minor, patch version of the ZFS userland tools.
// It parses output of `zfs version` which typically contains a string like "zfs-2.1.5-...".
func GetZFSVersion() (major, minor, patch int, err error) {
	out, _ := exec.Command("zfs", "version").CombinedOutput()
	re := regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)
	m := re.FindStringSubmatch(string(out))
	if len(m) < 3 {
		return 0, 0, 0, fmt.Errorf("could not parse zfs version from: %q", strings.TrimSpace(string(out)))
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	if len(m) >= 4 {
		patch, _ = strconv.Atoi(m[3])
	}
	return
}

// poolVdevType inspects `zpool status` and returns the top-level vdev type:
// "raidz1", "raidz2", "mirror", or "stripe" (default when no named vdev is found).
func poolVdevType(poolName string) string {
	out, err := exec.Command("sudo", "zpool", "status", poolName).Output()
	if err != nil {
		return "stripe"
	}
	inConfig := false
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "config:") {
			inConfig = true
			continue
		}
		if !inConfig {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if strings.HasPrefix(name, "raidz2") {
			return "raidz2"
		}
		if strings.HasPrefix(name, "raidz") { // raidz or raidz1
			return "raidz1"
		}
		if strings.HasPrefix(name, "mirror") {
			return "mirror"
		}
	}
	return "stripe"
}

// poolOperation returns the current background operation on the pool:
// "scrubbing", "resilvering", "expanding", or "" when idle.
func poolOperation(poolName string) string {
	out, err := exec.Command("sudo", "zpool", "status", poolName).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "scan:") {
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "scan:"))
			if strings.HasPrefix(rest, "scrub in progress") {
				return "scrubbing"
			}
			if strings.HasPrefix(rest, "resilver in progress") {
				return "resilvering"
			}
		}
		// RAIDZ expansion shows as "expanding" in the config section.
		if strings.Contains(trimmed, "expanding") {
			return "expanding"
		}
	}
	return ""
}

// getRaidzVdev returns the first raidz vdev name (e.g. "raidz1-0") from the
// pool config, or an empty string if the pool is a stripe.
func getRaidzVdev(poolName string) string {
	out, err := exec.Command("sudo", "zpool", "status", poolName).CombinedOutput()
	if err != nil {
		return ""
	}
	inConfig := false
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "config:") {
			inConfig = true
			continue
		}
		if !inConfig {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 1 && strings.HasPrefix(fields[0], "raidz") {
			return fields[0]
		}
	}
	return ""
}

// GrowPoolRaidz adds devices to the pool's raidz vdev using `zpool attach`
// (OpenZFS 2.4+ RAIDZ expansion). Falls back to zpool add for stripe pools.
func GrowPoolRaidz(name string, devices []string) error {
	vdev := getRaidzVdev(name)
	if vdev == "" {
		// Stripe pool — fall through to the regular add path.
		return GrowPool(name, devices)
	}
	for _, dev := range devices {
		args := []string{"zpool", "attach", "-f", name, vdev, dev}
		debugLog("zpool attach (raidz expand): %v", args)
		out, err := exec.Command("sudo", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("attach %s: %s", dev, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// GrowPool adds devices to an existing pool as a stripe vdev (zpool add).
func GrowPool(name string, devices []string) error {
	args := append([]string{"zpool", "add", "-f", name}, devices...)
	debugLog("zpool add: %v", args)
	out, err := exec.Command("sudo", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// GrowPoolWithVdev adds devices to an existing pool as a specific vdev type.
// vdev must be "mirror", "raidz1", or "raidz2".
func GrowPoolWithVdev(name, vdev string, devices []string) error {
	args := append([]string{"zpool", "add", "-f", name, vdev}, devices...)
	debugLog("zpool add vdev %s: %v", vdev, args)
	out, err := exec.Command("sudo", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// DestroyPool permanently destroys a pool.
func DestroyPool(name string) error {
	out, err := exec.Command("sudo", "zpool", "destroy", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ImportPool imports a named pool.
func ImportPool(name string) error {
	out, err := exec.Command("sudo", "zpool", "import", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// UpgradePool upgrades the pool to support all available ZFS feature flags.
// This is irreversible — older ZFS versions may not be able to import the pool
// after an upgrade.
func UpgradePool(name string) error {
	out, err := exec.Command("sudo", "zpool", "upgrade", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ImportPoolForce imports a named pool with -f (force), bypassing the
// "previously in use" safety check.
func ImportPoolForce(name string) error {
	out, err := exec.Command("sudo", "zpool", "import", "-f", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ── Datasets ──────────────────────────────────────────────────────────────────

// Dataset represents a ZFS filesystem dataset.
type Dataset struct {
	Name        string `json:"name"`
	ShortName   string `json:"short_name"`
	Used        uint64 `json:"used"`
	Avail       uint64 `json:"avail"`
	Refer       uint64 `json:"refer"`
	Quota       uint64 `json:"quota"`    // 0 = none
	RefQuota    uint64 `json:"refquota"` // 0 = none
	Compression string `json:"compression"`
	CompRatio   string `json:"compress_ratio"`
	RecordSize  uint64 `json:"record_size"`
	Mountpoint  string `json:"mountpoint"`
	UsedStr     string `json:"used_str"`
	AvailStr    string `json:"avail_str"`
	QuotaStr    string `json:"quota_str"`
	Depth       int    `json:"depth"` // 0 = pool root
}

// ListDatasets returns all datasets under poolName as a flat list (pool root first).
func ListDatasets(poolName string) ([]Dataset, error) {
	out, err := exec.Command("sudo", "zfs", "list", "-Hp", "-r",
		"-t", "filesystem",
		"-o", "name,used,avail,refer,quota,refquota,compression,compressratio,recordsize,mountpoint",
		poolName).Output()
	if err != nil {
		return nil, fmt.Errorf("zfs list failed: %w", err)
	}
	var datasets []Dataset
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		ds, err := parseDatasetLine(line, poolName)
		if err != nil {
			debugLog("dataset parse error: %v", err)
			continue
		}
		datasets = append(datasets, ds)
	}
	return datasets, nil
}

func parseDatasetLine(line, poolName string) (Dataset, error) {
	f := strings.Split(line, "\t")
	if len(f) < 10 {
		return Dataset{}, fmt.Errorf("unexpected zfs output: %q", line)
	}
	name := f[0]
	used, _ := strconv.ParseUint(f[1], 10, 64)
	avail, _ := strconv.ParseUint(f[2], 10, 64)
	refer, _ := strconv.ParseUint(f[3], 10, 64)
	quota, _ := parseZFSNum(f[4])
	refquota, _ := parseZFSNum(f[5])
	compression := f[6]
	compRatio := f[7]
	recordSize, _ := parseZFSNum(f[8])
	mountpoint := f[9]

	depth := strings.Count(name, "/") - strings.Count(poolName, "/")
	parts := strings.Split(name, "/")
	shortName := parts[len(parts)-1]

	return Dataset{
		Name:        name,
		ShortName:   shortName,
		Used:        used,
		Avail:       avail,
		Refer:       refer,
		Quota:       quota,
		RefQuota:    refquota,
		Compression: compression,
		CompRatio:   compRatio,
		RecordSize:  recordSize,
		Mountpoint:  mountpoint,
		UsedStr:     formatBytes(used),
		AvailStr:    formatBytes(avail),
		QuotaStr:    zeroOrBytes(quota),
		Depth:       depth,
	}, nil
}

// CreateDataset creates a new ZFS filesystem.
func CreateDataset(name string, quota uint64, quotaType, compression string) error {
	args := []string{"zfs", "create"}
	if quota > 0 {
		qt := "quota"
		if quotaType == "refquota" {
			qt = "refquota"
		}
		args = append(args, "-o", fmt.Sprintf("%s=%d", qt, quota))
	}
	if compression != "" && compression != "inherit" {
		args = append(args, "-o", "compression="+compression)
	}
	args = append(args, name)
	debugLog("zfs create: %v", args)
	out, err := exec.Command("sudo", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// SetDatasetProps sets one or more ZFS properties on a dataset.
func SetDatasetProps(name string, props map[string]string) error {
	for k, v := range props {
		out, err := exec.Command("sudo", "zfs", "set",
			fmt.Sprintf("%s=%s", k, v), name).CombinedOutput()
		if err != nil {
			return fmt.Errorf("zfs set %s=%s: %s", k, v, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// DestroyDataset removes a dataset. Fails if it has children or snapshots.
func DestroyDataset(name string) error {
	out, err := exec.Command("sudo", "zfs", "destroy", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// DestroyDatasetRecursive removes a dataset and all its children recursively.
func DestroyDatasetRecursive(name string) error {
	out, err := exec.Command("sudo", "zfs", "destroy", "-r", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ── Snapshots ─────────────────────────────────────────────────────────────────

// Snapshot represents a ZFS snapshot.
type Snapshot struct {
	Name     string    `json:"name"`
	Dataset  string    `json:"dataset"`
	SnapName string    `json:"snap_name"`
	Used     uint64    `json:"used"`
	Refer    uint64    `json:"refer"`
	Creation time.Time `json:"creation"`
	UsedStr  string    `json:"used_str"`
	ReferStr string    `json:"refer_str"`
}

// ListSnapshots returns all snapshots under poolName.
func ListSnapshots(poolName string) ([]Snapshot, error) {
	out, err := exec.Command("sudo", "zfs", "list", "-Hp", "-r", "-t", "snapshot",
		"-o", "name,used,refer,creation",
		"-s", "creation",
		poolName).Output()
	if err != nil {
		return []Snapshot{}, nil // no snapshots is fine
	}
	var snaps []Snapshot
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		s, err := parseSnapshotLine(line)
		if err != nil {
			debugLog("snapshot parse error: %v", err)
			continue
		}
		snaps = append(snaps, s)
	}
	return snaps, nil
}

func parseSnapshotLine(line string) (Snapshot, error) {
	f := strings.Split(line, "\t")
	if len(f) < 4 {
		return Snapshot{}, fmt.Errorf("unexpected snapshot output: %q", line)
	}
	name := f[0]
	used, _ := strconv.ParseUint(f[1], 10, 64)
	refer, _ := strconv.ParseUint(f[2], 10, 64)
	unix, _ := strconv.ParseInt(f[3], 10, 64)

	at := strings.LastIndex(name, "@")
	dataset := name[:at]
	snapName := name[at+1:]

	return Snapshot{
		Name:     name,
		Dataset:  dataset,
		SnapName: snapName,
		Used:     used,
		Refer:    refer,
		Creation: time.Unix(unix, 0),
		UsedStr:  formatBytes(used),
		ReferStr: formatBytes(refer),
	}, nil
}

// CreateSnapshot creates a snapshot named <dataset>@<label>-<timestamp>.
func CreateSnapshot(dataset, label string) (string, error) {
	ts := time.Now().Format("20060102-150405")
	fullName := fmt.Sprintf("%s@%s-%s", dataset, label, ts)
	out, err := exec.Command("sudo", "zfs", "snapshot", fullName).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return fullName, nil
}

// RollbackSnapshot rolls a dataset back to a snapshot (-r destroys newer snapshots).
func RollbackSnapshot(snapName string) error {
	out, err := exec.Command("sudo", "zfs", "rollback", "-r", snapName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// CloneSnapshot clones a snapshot into a new dataset.
func CloneSnapshot(snapName, target string) error {
	out, err := exec.Command("sudo", "zfs", "clone", snapName, target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// DestroySnapshot deletes a snapshot.
func DestroySnapshot(snapName string) error {
	out, err := exec.Command("sudo", "zfs", "destroy", snapName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func parseZFSNum(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "none" || s == "-" || s == "0" {
		return 0, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

func zeroOrBytes(n uint64) string {
	if n == 0 {
		return "none"
	}
	return formatBytes(n)
}
