package system

import (
	"fmt"
	"os"
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
	Members         []string `json:"members"`          // raw device paths as tracked by zpool (may be by-partuuid)
	MemberDevices   []string `json:"member_devices"`   // resolved canonical /dev/sdX paths
	MemberRoles     []string `json:"member_roles"`     // per-member vdev role: "stripe"|"mirror"|"raidz1"|"raidz2"
	MemberStatuses  []string `json:"member_statuses"`  // per-member device state: "ONLINE"|"FAULTED"|etc
	MemberPresent   []bool   `json:"member_present"`   // per-member: true if the device path exists in /dev
	CacheDevs     []string `json:"cache_devs"`      // raw L2ARC cache paths (may be by-partuuid)
	CacheDevices  []string `json:"cache_devices"`   // resolved canonical /dev/sdX paths
	VdevType    string   `json:"vdev_type"`  // "stripe" | "mirror" | "raidz1" | "raidz2"
	Operation   string   `json:"operation"`  // "" | "scrubbing" | "resilvering" | "expanding"
	SizeStr     string   `json:"size_str"`
	AllocStr    string   `json:"alloc_str"`
	FreeStr     string   `json:"free_str"`
	Compression string   `json:"compression"` // root dataset compression
	Dedup       string   `json:"dedup"`        // root dataset dedup
	Sync        string   `json:"sync"`         // root dataset sync
	Atime       string   `json:"atime"`        // root dataset atime
	Encrypted            bool   `json:"encrypted"`             // encryption property != "off"
	KeyLocked            bool   `json:"key_locked"`            // keystatus == "unavailable"
	EncryptionAlgorithm  string `json:"encryption_algorithm"`  // e.g. "aes-256-gcm", "" when off
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
	p.Members, p.MemberDevices, p.MemberRoles = poolMembers(p.Name)
	p.MemberStatuses = poolMemberStatuses(p.Name)
	p.MemberPresent  = poolMemberPresent(p.Members)
	p.CacheDevs, p.CacheDevices = poolCacheDevs(p.Name)
	p.VdevType   = poolVdevType(p.Name)
	p.Operation  = poolOperation(p.Name)
	p.Compression, p.Dedup, p.Sync, p.Atime = poolRootProps(p.Name)
	p.Encrypted, p.KeyLocked, p.EncryptionAlgorithm = poolEncryptionStatus(p.Name)
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

// GetAllPools returns all currently imported ZFS pools.
func GetAllPools() ([]*Pool, error) {
	out, err := exec.Command("sudo", "zpool", "list", "-Hp",
		"-o", "name,size,alloc,free,health").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return []*Pool{}, nil
	}
	var pools []*Pool
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		p, err := parsePool(line)
		if err != nil {
			continue
		}
		p.UsableUsed, p.UsableAvail = poolRootUsage(p.Name)
		p.UsableSize = p.UsableUsed + p.UsableAvail
		p.Members, p.MemberDevices, p.MemberRoles = poolMembers(p.Name)
		p.MemberStatuses = poolMemberStatuses(p.Name)
		p.MemberPresent  = poolMemberPresent(p.Members)
		p.CacheDevs, p.CacheDevices = poolCacheDevs(p.Name)
		p.VdevType  = poolVdevType(p.Name)
		p.Operation = poolOperation(p.Name)
		p.Compression, p.Dedup, p.Sync, p.Atime = poolRootProps(p.Name)
		p.Encrypted, p.KeyLocked, p.EncryptionAlgorithm = poolEncryptionStatus(p.Name)
		pools = append(pools, p)
	}
	return pools, nil
}

// GetPoolByName returns the pool with the given name, or nil if not found.
func GetPoolByName(name string) (*Pool, error) {
	out, err := exec.Command("sudo", "zpool", "list", "-Hp",
		"-o", "name,size,alloc,free,health", name).Output()
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
	p.UsableUsed, p.UsableAvail = poolRootUsage(p.Name)
	p.UsableSize = p.UsableUsed + p.UsableAvail
	p.Members, p.MemberDevices, p.MemberRoles = poolMembers(p.Name)
	p.MemberStatuses = poolMemberStatuses(p.Name)
	p.MemberPresent  = poolMemberPresent(p.Members)
	p.CacheDevs, p.CacheDevices = poolCacheDevs(p.Name)
	p.VdevType  = poolVdevType(p.Name)
	p.Operation = poolOperation(p.Name)
	p.Compression, p.Dedup, p.Sync, p.Atime = poolRootProps(p.Name)
	p.Encrypted, p.KeyLocked, p.EncryptionAlgorithm = poolEncryptionStatus(p.Name)
	return p, nil
}

// GetPoolStatusByName returns the raw output of `zpool status` for a specific pool.
// When name is empty it returns status for all pools.
func GetPoolStatusByName(name string) (string, error) {
	args := []string{"sudo", "zpool", "status"}
	if name != "" {
		args = append(args, name)
	}
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", fmt.Errorf("zpool status: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
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

// zpoolStatusDevices runs `zpool status [flags] poolName` and extracts device
// names from the config section in output order.  section controls which
// section to collect ("data" for data vdevs, "cache" for cache devices).
// Returns the ordered list of device name strings exactly as zpool printed them.
func zpoolStatusDevices(poolName, section string, withFullPaths bool) []string {
	args := []string{"sudo", "zpool", "status"}
	if withFullPaths {
		args = append(args, "-P")
	}
	args = append(args, poolName)
	out, err := exec.Command(args[0], args[1:]...).Output()
	if err != nil {
		return nil
	}

	validStates := map[string]bool{
		"ONLINE": true, "DEGRADED": true, "FAULTED": true,
		"OFFLINE": true, "REMOVED": true, "UNAVAIL": true,
	}
	vdevPrefixes := []string{"mirror-", "raidz2-", "raidz1-", "raidz-", "spare-", "log-", "cache-"}
	skipSections := map[string]bool{"cache": true, "log": true, "spare": true}

	inConfig := false
	inTarget := section == "data" // data section is active by default
	poolIndent := -1

	countIndent := func(line string) int {
		return len(line) - len(strings.TrimLeft(line, " \t"))
	}

	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "config:") {
			inConfig = true
			continue
		}
		if !inConfig {
			continue
		}
		if strings.HasPrefix(trimmed, "errors:") {
			break
		}
		if trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		indent := countIndent(line)

		// Section header (single token or token with state but not a valid-state token).
		if len(fields) == 1 {
			sectionName := strings.ToLower(trimmed)
			if section == "data" {
				inTarget = !skipSections[sectionName]
			} else {
				inTarget = sectionName == section
			}
			continue
		}
		if len(fields) < 2 {
			continue
		}
		name, state := fields[0], fields[1]
		if !validStates[state] {
			sectionName := strings.ToLower(name)
			if section == "data" {
				inTarget = !skipSections[sectionName]
			} else {
				inTarget = sectionName == section
			}
			continue
		}
		if !inTarget {
			continue
		}

		// Pool name line.
		if name == poolName {
			poolIndent = indent
			continue
		}
		if poolIndent < 0 {
			continue
		}

		// Skip vdev group headers.
		isVdev := false
		for _, pfx := range vdevPrefixes {
			if strings.HasPrefix(name, pfx) {
				isVdev = true
				break
			}
		}
		if isVdev || name == "NAME" {
			continue
		}

		// Leaf device.
		if section == "data" {
			// Data: collect top-level stripe disks and vdev members.
			if indent >= poolIndent+2 {
				names = append(names, name)
			}
		} else {
			// Cache/other: collect all leaf devices.
			names = append(names, name)
		}
	}
	return names
}

// poolMembers parses zpool status output to return physical device paths of
// DATA vdevs only (excludes cache, log, and spare sections).
// Returns (rawPaths, resolvedPaths, roles):
//   - rawPaths: exactly as zpool reports with -P (may be /dev/disk/by-partuuid/…)
//   - resolvedPaths: paths as zpool reports without -P (ZFS resolves its own stored paths)
//   - roles: per-disk vdev role — "stripe" | "mirror" | "raidz1" | "raidz2"
func poolMembers(poolName string) (raw, resolved, roles []string) {
	// Run with -P for raw stored paths.
	rawNames := zpoolStatusDevices(poolName, "data", true)
	// Run without -P: ZFS resolves its own partuuid/by-id paths to real device names.
	resolvedNames := zpoolStatusDevices(poolName, "data", false)

	if len(rawNames) == 0 {
		return nil, nil, nil
	}

	// Ensure resolved list matches raw list length; fall back to resolveDevPath if shorter.
	for i, r := range rawNames {
		var res string
		if i < len(resolvedNames) {
			res = resolvedNames[i]
		}
		// If ZFS returned an unresolved path (by-partuuid, by-id, or bare UUID string),
		// fall back to our own resolution using the raw -P path.
		if res == "" || strings.Contains(res, "/by-partuuid/") || strings.Contains(res, "/by-id/") || isPartuuidString(res) {
			res = resolveDevPath(r)
		}
		// Ensure path has /dev/ prefix.
		if res != "" && !strings.HasPrefix(res, "/dev/") {
			res = "/dev/" + res
		}
		raw = append(raw, r)
		resolved = append(resolved, res)
		roles = append(roles, "stripe") // role re-computed below
	}

	// Re-compute roles from the -P output (structure is the same).
	roles = poolMemberRoles(poolName, len(raw))
	return raw, resolved, roles
}

// poolMemberRoles returns the vdev role for each data member in order.
func poolMemberRoles(poolName string, count int) []string {
	out, err := exec.Command("sudo", "zpool", "status", "-P", poolName).Output()
	if err != nil || count == 0 {
		roles := make([]string, count)
		for i := range roles {
			roles[i] = "stripe"
		}
		return roles
	}
	validStates := map[string]bool{
		"ONLINE": true, "DEGRADED": true, "FAULTED": true,
		"OFFLINE": true, "REMOVED": true, "UNAVAIL": true,
	}
	vdevPrefixes := []string{"mirror-", "raidz2-", "raidz1-", "raidz-", "spare-", "log-", "cache-"}
	skipSections := map[string]bool{"cache": true, "log": true, "spare": true}
	inConfig, inData, seenPool := false, true, false
	poolIndent := -1
	vdevIndent := -1 // indent of vdev group headers (or direct-child stripe disks)
	currentRole := "stripe"
	countIndent := func(line string) int {
		return len(line) - len(strings.TrimLeft(line, " \t"))
	}
	var roles []string
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "config:") {
			inConfig = true
			continue
		}
		if !inConfig {
			continue
		}
		if strings.HasPrefix(trimmed, "errors:") {
			break
		}
		if trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		indent := countIndent(line)
		if len(fields) == 1 {
			inData = !skipSections[strings.ToLower(trimmed)]
			continue
		}
		if len(fields) < 2 {
			continue
		}
		name, state := fields[0], fields[1]
		if !validStates[state] {
			inData = !skipSections[strings.ToLower(name)]
			continue
		}
		if !inData {
			continue
		}
		// Capture pool name line and its indent.
		if name == poolName {
			seenPool = true
			poolIndent = indent
			continue
		}
		if !seenPool || poolIndent < 0 {
			continue
		}
		// Determine the vdev-level indent from the first direct child we encounter.
		if vdevIndent < 0 && indent > poolIndent {
			vdevIndent = indent
		}
		// Check if this is a vdev group header (mirror-N, raidz1-N, etc.).
		isVdev := false
		for _, pfx := range vdevPrefixes {
			if strings.HasPrefix(name, pfx) {
				isVdev = true
				switch {
				case strings.HasPrefix(name, "mirror-"):
					currentRole = "mirror"
				case strings.HasPrefix(name, "raidz2-"):
					currentRole = "raidz2"
				case strings.HasPrefix(name, "raidz1-"), strings.HasPrefix(name, "raidz-"):
					currentRole = "raidz1"
				}
				break
			}
		}
		if isVdev || name == "NAME" {
			continue
		}
		// Direct child of pool (at vdev indent level, not inside a named vdev) → stripe.
		if indent == vdevIndent {
			currentRole = "stripe"
		}
		roles = append(roles, currentRole)
	}
	// Pad or trim to match count.
	for len(roles) < count {
		roles = append(roles, "stripe")
	}
	return roles[:count]
}

// poolCacheDevs parses zpool status output to return L2ARC cache device paths.
// Returns (rawPaths, resolvedPaths): rawPaths are exactly as zpool reports with -P;
// resolvedPaths use the ZFS-resolved names (without -P).
func poolCacheDevs(poolName string) (raw, resolved []string) {
	rawNames := zpoolStatusDevices(poolName, "cache", true)
	resolvedNames := zpoolStatusDevices(poolName, "cache", false)
	for i, r := range rawNames {
		var res string
		if i < len(resolvedNames) {
			res = resolvedNames[i]
		}
		if res == "" || strings.Contains(res, "/by-partuuid/") || strings.Contains(res, "/by-id/") {
			res = resolveDevPath(r)
		}
		if res != "" && !strings.HasPrefix(res, "/dev/") {
			res = "/dev/" + res
		}
		raw = append(raw, r)
		resolved = append(resolved, res)
	}
	return raw, resolved
}

// poolMemberStatuses returns the per-device state for every leaf device in the
// pool's data vdevs (same order as poolMembers).
func poolMemberStatuses(poolName string) []string {
	out, err := exec.Command("sudo", "zpool", "status", poolName).Output()
	if err != nil {
		return nil
	}
	validStates := map[string]bool{
		"ONLINE": true, "DEGRADED": true, "FAULTED": true,
		"OFFLINE": true, "REMOVED": true, "UNAVAIL": true,
	}
	vdevPrefixes := []string{"mirror-", "raidz2-", "raidz1-", "raidz-", "spare-", "log-", "cache-"}
	skipSections := map[string]bool{"cache": true, "log": true, "spare": true}

	inConfig, inData := false, true
	poolIndent := -1
	countIndent := func(line string) int {
		return len(line) - len(strings.TrimLeft(line, " \t"))
	}
	var statuses []string
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "config:") { inConfig = true; continue }
		if !inConfig { continue }
		if strings.HasPrefix(trimmed, "errors:") { break }
		if trimmed == "" { continue }
		fields := strings.Fields(trimmed)
		indent := countIndent(line)
		if len(fields) < 2 || !validStates[fields[1]] { continue }
		name := fields[0]
		if name == "NAME" { continue }
		if poolIndent < 0 { poolIndent = indent; continue } // pool line itself
		if indent <= poolIndent { continue }
		if skipSections[strings.ToLower(name)] { inData = false; continue }
		if !inData { continue }
		isVdev := false
		for _, pfx := range vdevPrefixes {
			if strings.HasPrefix(name, pfx) { isVdev = true; break }
		}
		if !isVdev {
			statuses = append(statuses, fields[1])
		}
	}
	return statuses
}

// poolMemberPresent checks whether each raw member path physically exists under /dev.
// This is used to detect disks that are tracked as UNAVAIL/REMOVED by ZFS but have
// reappeared on the system (e.g. after a cable reseat or HBA reset).
func poolMemberPresent(members []string) []bool {
	present := make([]bool, len(members))
	for i, m := range members {
		path := m
		if path != "" && !strings.HasPrefix(path, "/") {
			path = "/dev/" + path
		}
		if path != "" {
			_, err := os.Stat(path)
			present[i] = (err == nil)
		}
	}
	return present
}

// OnlinePoolDisks runs `zpool online <pool> <dev>...` to re-mark one or more
// member disks as online after they have physically reappeared.
func OnlinePoolDisks(poolName string, devices []string) error {
	if len(devices) == 0 {
		return nil
	}
	args := append([]string{"sudo", "zpool", "online", poolName}, devices...)
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// SetDiskOffline takes a pool member disk offline using `zpool offline`.
func SetDiskOffline(poolName, device string) error {
	out, err := exec.Command("sudo", "zpool", "offline", poolName, device).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// SetDiskOnline brings an offline pool member disk back online using `zpool online`.
func SetDiskOnline(poolName, device string) error {
	out, err := exec.Command("sudo", "zpool", "online", poolName, device).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ClearPool runs `zpool clear` to clear error counts and re-enable faulted devices.
func ClearPool(poolName string) error {
	out, err := exec.Command("sudo", "zpool", "clear", poolName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// AddPoolCache adds a device as an L2ARC cache to the pool.
// The device is first wiped and repartitioned (GPT, type BF01) so the pool
// tracks it by stable PARTUUID.
func AddPoolCache(poolName, device string) error {
	puPath, err := PrepareZFSPartition(device)
	if err != nil {
		return fmt.Errorf("prepare %s: %w", device, err)
	}
	out, err := exec.Command("sudo", "zpool", "add", poolName, "cache", puPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// RemovePoolCache removes an L2ARC cache device from the pool.
func RemovePoolCache(poolName, device string) error {
	out, err := exec.Command("sudo", "zpool", "remove", poolName, device).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// resolveDevPath resolves symlinks (e.g. /dev/disk/by-id/... or
// /dev/disk/by-uuid/...) to their canonical /dev/sdX path.
// Returns the original path unchanged if resolution fails or the result
// does not look like a block device.
// isPartuuidString returns true if s is a bare PARTUUID (8-4-4-4-12 hex with dashes).
func isPartuuidString(s string) bool {
	if len(s) != 36 || strings.Count(s, "-") != 4 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-') {
			return false
		}
	}
	return true
}

// blkidPartuuidMap runs `sudo blkid -o export` and returns a map of
// lowercase PARTUUID → device path. This reads from disk directly and works
// even on systems without udev or /dev/disk/by-partuuid/ symlinks.
func blkidPartuuidMap() map[string]string {
	out, err := exec.Command("sudo", "blkid", "-o", "export").Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	m := make(map[string]string)
	var devName string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			devName = ""
			continue
		}
		if strings.HasPrefix(line, "DEVNAME=") {
			devName = strings.TrimPrefix(line, "DEVNAME=")
		} else if strings.HasPrefix(line, "PARTUUID=") && devName != "" {
			uuid := strings.ToLower(strings.TrimPrefix(line, "PARTUUID="))
			m[uuid] = devName
		}
	}
	return m
}

func resolveDevPath(p string) string {
	// 1. Direct symlink resolution (works when udev created /dev/disk/by-partuuid/).
	if real, err := filepath.EvalSymlinks(p); err == nil && strings.HasPrefix(real, "/dev/") {
		return real
	}

	// Extract UUID from a /by-partuuid/ path or a bare UUID string.
	var uuid string
	if strings.Contains(p, "/by-partuuid/") {
		uuid = strings.ToLower(filepath.Base(p))
	} else if isPartuuidString(p) {
		uuid = strings.ToLower(p)
	}
	if uuid == "" {
		return p
	}

	// 2. lsblk (fast, uses sysfs — works on most systems).
	if out, err := exec.Command("lsblk", "-ln", "-o", "NAME,PARTUUID").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && strings.ToLower(fields[1]) == uuid {
				return "/dev/" + fields[0]
			}
		}
	}

	// 3. blkid (reads from disk directly, works without udev/sysfs).
	if m := blkidPartuuidMap(); m != nil {
		if dev, ok := m[uuid]; ok {
			return dev
		}
	}

	return p
}

// PrepareZFSPartition wipes a disk and creates a single GPT partition of type
// BF01 (FreeBSD ZFS) consuming the full disk.  It returns the
// /dev/disk/by-partuuid/<uuid> path of the new partition, which is stable
// even if the disk is later moved to a different port or controller.
func PrepareZFSPartition(device string) (string, error) {
	// Wipe any existing partition table.
	if out, err := exec.Command("sudo", "sgdisk", "--zap-all", device).CombinedOutput(); err != nil {
		return "", fmt.Errorf("sgdisk --zap-all %s: %s", device, strings.TrimSpace(string(out)))
	}
	// Create one partition: start=0 (first usable), end=0 (last usable), type BF01.
	if out, err := exec.Command("sudo", "sgdisk", "-n", "1:0:0", "-t", "1:BF01", device).CombinedOutput(); err != nil {
		return "", fmt.Errorf("sgdisk create partition on %s: %s", device, strings.TrimSpace(string(out)))
	}
	// Inform the kernel of the new partition table.
	exec.Command("sudo", "partprobe", device).Run() //nolint

	// Locate the new partition's by-partuuid symlink.
	devName := filepath.Base(device) // e.g. "sda" or "nvme0n1"
	const dir = "/dev/disk/by-partuuid"
	for i := 0; i < 20; i++ { // up to 10 s
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, entry := range entries {
				link, err := filepath.EvalSymlinks(filepath.Join(dir, entry.Name()))
				if err != nil {
					continue
				}
				// The link target is a partition (e.g. /dev/sda1); strip the suffix.
				if diskBaseName(filepath.Base(link)) == devName {
					return filepath.Join(dir, entry.Name()), nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("by-partuuid symlink not found for partition on %s", device)
}

// CreatePool creates a new ZFS pool.
// Each device is first wiped and repartitioned (GPT, type BF01) so the pool
// tracks the partition by its stable PARTUUID rather than by kernel device name.
// layout: "stripe" | "mirror" | "raidz1" | "raidz2"
// ashift: 9, 12, or 13
// compression: "off" | "lz4" | "zstd"
// dedup: "off" | "on" | "verify"
// keyFilePath: absolute path to 32-byte raw key file, or "" for no encryption
func CreatePool(name, layout string, ashift int, compression, dedup string, devices []string, keyFilePath string) error {
	// Prepare each disk and collect the stable partuuid paths.
	partuuidPaths := make([]string, 0, len(devices))
	for _, dev := range devices {
		puPath, err := PrepareZFSPartition(dev)
		if err != nil {
			return fmt.Errorf("prepare %s: %w", dev, err)
		}
		partuuidPaths = append(partuuidPaths, puPath)
	}

	args := []string{"zpool", "create",
		"-o", fmt.Sprintf("ashift=%d", ashift),
		"-O", "atime=off",
	}
	if keyFilePath != "" {
		args = append(args,
			"-O", "encryption=aes-256-gcm",
			"-O", "keyformat=raw",
			"-O", "keylocation=file://"+keyFilePath,
		)
	}
	if compression != "off" {
		args = append(args, "-O", "compression="+compression)
	}
	if dedup != "" && dedup != "off" {
		args = append(args, "-O", "dedup="+dedup)
	}
	args = append(args, name)
	if layout == "mirror" || layout == "raidz1" || layout == "raidz2" {
		args = append(args, layout)
	}
	args = append(args, partuuidPaths...)
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
			// ZFS 2.x outputs an extra statistics line before the "% done" line:
			//   line i+1: "35.5G scanned at 887M/s, 6.18G issued at 154M/s, 3.61T total"
			//   line i+2: "0B repaired, 0.17% done, 0 days 00:39:09 to go"
			// Older ZFS puts "% done" directly on line i+1. Search up to 4 lines ahead.
			for j := i + 1; j < len(lines) && j <= i+4; j++ {
				next := strings.TrimSpace(lines[j])
				if pctIdx := strings.Index(next, "% done"); pctIdx > 0 {
					pctStr := strings.TrimSpace(next[:pctIdx])
					parts := strings.Fields(pctStr)
					if len(parts) > 0 {
						fmt.Sscanf(parts[len(parts)-1], "%f", &info.ProgressPct)
					}
					if toGoIdx := strings.Index(next, " to go"); toGoIdx > 0 {
						commaIdx := strings.LastIndex(next[:toGoIdx], ", ")
						if commaIdx >= 0 {
							info.TimeLeft = strings.TrimSpace(next[commaIdx+2 : toGoIdx])
						}
					}
					break
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

// poolRootProps fetches editable properties from the pool's root dataset.
func poolRootProps(name string) (compression, dedup, sync_, atime string) {
	out, err := exec.Command("sudo", "zfs", "get", "-Hp",
		"compression,dedup,sync,atime", name).Output()
	compression, dedup, sync_, atime = "lz4", "off", "standard", "off"
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 3 {
			continue
		}
		switch f[1] {
		case "compression":
			compression = f[2]
		case "dedup":
			dedup = f[2]
		case "sync":
			sync_ = f[2]
		case "atime":
			atime = f[2]
		}
	}
	return
}

// poolEncryptionStatus returns (encrypted, keyLocked, algorithm) for a ZFS pool.
// algorithm is the raw ZFS property value (e.g. "aes-256-gcm") or "" when off.
func poolEncryptionStatus(name string) (encrypted, keyLocked bool, algorithm string) {
	out, err := exec.Command("sudo", "zfs", "get", "-Hp", "-o", "property,value",
		"encryption,keystatus", name).Output()
	if err != nil {
		return false, false, ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "encryption":
			if f[1] != "off" && f[1] != "-" {
				encrypted = true
				algorithm = f[1]
			}
		case "keystatus":
			keyLocked = f[1] == "unavailable"
		}
	}
	return
}

// GetEncryptionStatus returns the raw encryption property value for a dataset ("aes-256-gcm", "off", etc.).
func GetEncryptionStatus(name string) string {
	out, err := exec.Command("sudo", "zfs", "get", "-Hp", "-o", "value", "encryption", name).Output()
	if err != nil {
		return "off"
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return "off"
	}
	return v
}

// GetKeyStatus returns the keystatus property value ("available", "unavailable", or "-").
func GetKeyStatus(name string) string {
	out, err := exec.Command("sudo", "zfs", "get", "-Hp", "-o", "value", "keystatus", name).Output()
	if err != nil {
		return "-"
	}
	return strings.TrimSpace(string(out))
}

// GetKeyLocation returns the keylocation property value for a dataset.
func GetKeyLocation(name string) string {
	out, err := exec.Command("sudo", "zfs", "get", "-Hp", "-o", "value", "keylocation", name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// LoadPoolKey loads the encryption key for a pool so it can be accessed.
// keyFilePath must be the absolute path to the 32-byte raw key file.
func LoadPoolKey(poolName, keyFilePath string) error {
	out, err := exec.Command("sudo", "zfs", "load-key",
		"-L", "file://"+keyFilePath, poolName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("zfs load-key: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// MountDataset mounts a ZFS dataset. Silently ignores "already mounted" errors.
func MountDataset(name string) error {
	out, err := exec.Command("sudo", "zfs", "mount", name).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "already mounted") {
			return nil
		}
		return fmt.Errorf("zfs mount: %s", msg)
	}
	return nil
}

// MountUnlockedChildren mounts all encrypted-but-unlocked datasets that are
// children of parent (prefix match) and are not yet mounted.
func MountUnlockedChildren(parent string) {
	datasets, err := ListAllDatasets()
	if err != nil {
		return
	}
	for _, d := range datasets {
		if d.Name == parent {
			continue
		}
		if !strings.HasPrefix(d.Name, parent+"/") {
			continue
		}
		if d.Encrypted && !d.KeyLocked && !d.Mounted &&
			d.Mountpoint != "none" && d.Mountpoint != "legacy" && d.CanMount != "off" {
			MountDataset(d.Name)
		}
	}
}

// UnloadPoolKey unloads the encryption key for a pool (locks it).
func UnloadPoolKey(poolName string) error {
	out, err := exec.Command("sudo", "zfs", "unload-key", poolName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("zfs unload-key: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// SetPoolProperties sets one or more ZFS properties on the pool's root dataset.
func SetPoolProperties(poolName string, props map[string]string) error {
	for k, v := range props {
		out, err := exec.Command("sudo", "zfs", "set", k+"="+v, poolName).CombinedOutput()
		if err != nil {
			return fmt.Errorf("set %s=%s: %s", k, v, strings.TrimSpace(string(out)))
		}
	}
	return nil
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

// prepareDevices calls PrepareZFSPartition on each device and returns the
// resulting partuuid paths in the same order.
func prepareDevices(devices []string) ([]string, error) {
	paths := make([]string, 0, len(devices))
	for _, dev := range devices {
		p, err := PrepareZFSPartition(dev)
		if err != nil {
			return nil, fmt.Errorf("prepare %s: %w", dev, err)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// GrowPoolRaidz adds devices to the pool's raidz vdev using `zpool attach`
// (OpenZFS 2.2+ RAIDZ expansion). Falls back to zpool add for stripe pools.
func GrowPoolRaidz(name string, devices []string) error {
	puPaths, err := prepareDevices(devices)
	if err != nil {
		return err
	}
	vdev := getRaidzVdev(name)
	if vdev == "" {
		// Stripe pool — fall through to the regular add path (paths already prepared).
		return growPoolRaw(name, puPaths)
	}
	for _, p := range puPaths {
		args := []string{"zpool", "attach", "-f", name, vdev, p}
		debugLog("zpool attach (raidz expand): %v", args)
		out, err := exec.Command("sudo", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("attach %s: %s", p, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// growPoolRaw issues zpool add with already-prepared paths (no partition step).
func growPoolRaw(name string, puPaths []string) error {
	args := append([]string{"zpool", "add", "-f", name}, puPaths...)
	debugLog("zpool add: %v", args)
	out, err := exec.Command("sudo", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// GrowPool adds devices to an existing pool as a stripe vdev (zpool add).
func GrowPool(name string, devices []string) error {
	puPaths, err := prepareDevices(devices)
	if err != nil {
		return err
	}
	args := append([]string{"zpool", "add", "-f", name}, puPaths...)
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
	puPaths, err := prepareDevices(devices)
	if err != nil {
		return err
	}
	args := append([]string{"zpool", "add", "-f", name, vdev}, puPaths...)
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
	Name             string `json:"name"`
	ShortName        string `json:"short_name"`
	Used             uint64 `json:"used"`
	Avail            uint64 `json:"avail"`
	Refer            uint64 `json:"refer"`
	Quota            uint64 `json:"quota"`          // 0 = none
	RefQuota         uint64 `json:"refquota"`       // 0 = none
	Refreservation   uint64 `json:"refreservation"` // 0 = none
	Compression      string `json:"compression"`
	CompRatio        string `json:"compress_ratio"`
	RecordSize       uint64 `json:"record_size"`
	RecordSizeRaw    string `json:"record_size_raw"` // e.g. "128K" or "inherit"
	Mountpoint       string `json:"mountpoint"`
	Sync             string `json:"sync"`             // standard|always|disabled|inherit
	Dedup            string `json:"dedup"`            // on|off|verify|inherit
	CaseSensitivity  string `json:"case_sensitivity"` // sensitive|insensitive|mixed
	Comment          string `json:"comment"`          // user property zfsnas:comment
	UsedStr          string `json:"used_str"`
	AvailStr         string `json:"avail_str"`
	QuotaStr         string `json:"quota_str"`
	RefreservationStr string `json:"refreservation_str"`
	Depth            int    `json:"depth"`     // 0 = pool root
	Encrypted           bool   `json:"encrypted"`            // encryption != "off"
	KeyLocked           bool   `json:"key_locked"`           // keystatus == "unavailable"
	EncryptionAlgorithm string `json:"encryption_algorithm"` // e.g. "aes-256-gcm", "" when off
	Mounted             bool   `json:"mounted"`              // zfs mounted == "yes"
	CanMount            string `json:"canmount"`             // on|off|noauto
}

// DatasetCreateOptions holds all properties for creating a new dataset.
type DatasetCreateOptions struct {
	Quota           uint64
	QuotaType       string // "quota" or "refquota"
	Refreservation  uint64
	Compression     string
	Sync            string
	Dedup           string
	CaseSensitivity string
	RecordSize      string // raw ZFS value e.g. "128K", "inherit", ""
	Comment         string
	KeyFilePath     string // non-empty → create with AES-256-GCM encryption, key at this path
}

// ListDatasets returns all datasets under poolName as a flat list (pool root first).
// ListAllDatasets returns datasets from every currently imported pool.
func ListAllDatasets() ([]Dataset, error) {
	pools, err := GetAllPools()
	if err != nil {
		return nil, err
	}
	var all []Dataset
	for _, p := range pools {
		ds, err := ListDatasets(p.Name)
		if err != nil {
			continue
		}
		all = append(all, ds...)
	}
	return all, nil
}

func ListDatasets(poolName string) ([]Dataset, error) {
	out, err := exec.Command("sudo", "zfs", "list", "-Hp", "-r",
		"-t", "filesystem",
		"-o", "name,used,avail,refer,quota,refquota,compression,compressratio,recordsize,mountpoint,sync,dedup,casesensitivity,refreservation,zfsnas:comment,encryption,keystatus,mounted,canmount",
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
	if len(f) < 15 {
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
	sync := f[10]
	dedup := f[11]
	caseSensitivity := f[12]
	refreservation, _ := parseZFSNum(f[13])
	comment := f[14]
	if comment == "-" {
		comment = ""
	}
	// Fields 15 (encryption), 16 (keystatus), 17 (mounted) are present when the zfs
	// list command includes them; older output without them is tolerated.
	var dsEncrypted, dsKeyLocked bool
	var dsEncAlgo string
	dsMounted := true // assume mounted unless ZFS explicitly says "no"
	if len(f) >= 17 {
		if f[15] != "off" && f[15] != "-" {
			dsEncrypted = true
			dsEncAlgo = f[15]
		}
		dsKeyLocked = f[16] == "unavailable"
	}
	dsCanMount := "on"
	if len(f) >= 18 {
		dsMounted = f[17] == "yes"
	}
	if len(f) >= 19 {
		dsCanMount = f[18]
	}

	// Derive human-readable record size string.
	recordSizeRaw := formatBytesShort(recordSize)

	depth := strings.Count(name, "/") - strings.Count(poolName, "/")
	parts := strings.Split(name, "/")
	shortName := parts[len(parts)-1]

	return Dataset{
		Name:              name,
		ShortName:         shortName,
		Used:              used,
		Avail:             avail,
		Refer:             refer,
		Quota:             quota,
		RefQuota:          refquota,
		Refreservation:    refreservation,
		Compression:       compression,
		CompRatio:         compRatio,
		RecordSize:        recordSize,
		RecordSizeRaw:     recordSizeRaw,
		Mountpoint:        mountpoint,
		Sync:              sync,
		Dedup:             dedup,
		CaseSensitivity:   caseSensitivity,
		Comment:           comment,
		UsedStr:           formatBytes(used),
		AvailStr:          formatBytes(avail),
		QuotaStr:          zeroOrBytes(quota),
		RefreservationStr: zeroOrBytes(refreservation),
		Depth:             depth,
		Encrypted:           dsEncrypted,
		KeyLocked:           dsKeyLocked,
		EncryptionAlgorithm: dsEncAlgo,
		Mounted:             dsMounted,
		CanMount:            dsCanMount,
	}, nil
}

// CreateDataset creates a new ZFS filesystem with the given options.
func CreateDataset(name string, opts DatasetCreateOptions) error {
	args := []string{"zfs", "create"}
	if opts.KeyFilePath != "" {
		args = append(args,
			"-o", "encryption=aes-256-gcm",
			"-o", "keyformat=raw",
			"-o", "keylocation=file://"+opts.KeyFilePath,
		)
	}
	if opts.Quota > 0 {
		qt := "quota"
		if opts.QuotaType == "refquota" {
			qt = "refquota"
		}
		args = append(args, "-o", fmt.Sprintf("%s=%d", qt, opts.Quota))
	}
	if opts.Compression != "" && opts.Compression != "inherit" {
		args = append(args, "-o", "compression="+opts.Compression)
	}
	if opts.Sync != "" && opts.Sync != "inherit" {
		args = append(args, "-o", "sync="+opts.Sync)
	}
	if opts.Dedup != "" && opts.Dedup != "inherit" {
		args = append(args, "-o", "dedup="+opts.Dedup)
	}
	if opts.CaseSensitivity != "" && opts.CaseSensitivity != "inherit" {
		args = append(args, "-o", "casesensitivity="+opts.CaseSensitivity)
	}
	if opts.RecordSize != "" && opts.RecordSize != "inherit" {
		args = append(args, "-o", "recordsize="+opts.RecordSize)
	}
	if opts.Refreservation > 0 {
		args = append(args, "-o", fmt.Sprintf("refreservation=%d", opts.Refreservation))
	}
	args = append(args, name)
	debugLog("zfs create: %v", args)
	out, err := exec.Command("sudo", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	// Set user property comment after creation (not supported as -o at create time).
	if opts.Comment != "" {
		if serr := SetDatasetProps(name, map[string]string{"zfsnas:comment": opts.Comment}); serr != nil {
			debugLog("set comment failed: %v", serr)
		}
	}
	return nil
}

// SetDatasetProps sets one or more ZFS properties on a dataset.
// A value of "" clears the property via `zfs inherit` (only meaningful for user properties).
func SetDatasetProps(name string, props map[string]string) error {
	for k, v := range props {
		var out []byte
		var err error
		if v == "" {
			out, err = exec.Command("sudo", "zfs", "inherit", k, name).CombinedOutput()
			if err != nil {
				return fmt.Errorf("zfs inherit %s: %s", k, strings.TrimSpace(string(out)))
			}
		} else {
			out, err = exec.Command("sudo", "zfs", "set",
				fmt.Sprintf("%s=%s", k, v), name).CombinedOutput()
			if err != nil {
				return fmt.Errorf("zfs set %s=%s: %s", k, v, strings.TrimSpace(string(out)))
			}
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

// formatBytesShort converts a byte count to a ZFS-style compact string
// e.g. 512→"512", 1024→"1K", 131072→"128K", 1048576→"1M".
func formatBytesShort(b uint64) string {
	if b == 0 {
		return "inherit"
	}
	units := []struct {
		div   uint64
		label string
	}{
		{1024 * 1024 * 1024 * 1024, "T"},
		{1024 * 1024 * 1024, "G"},
		{1024 * 1024, "M"},
		{1024, "K"},
	}
	for _, u := range units {
		if b%u.div == 0 {
			return fmt.Sprintf("%d%s", b/u.div, u.label)
		}
	}
	return fmt.Sprintf("%d", b)
}
