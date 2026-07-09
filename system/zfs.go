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

// VdevDisk is a single leaf device within a vdev group.
type VdevDisk struct {
	Raw         string `json:"raw"`                     // path as ZFS stores it (e.g. /dev/disk/by-partuuid/…)
	Device      string `json:"device"`                  // resolved canonical /dev/sdXN
	Status      string `json:"status"`                  // ONLINE | FAULTED | OFFLINE | REMOVED | UNAVAIL
	Present     bool   `json:"present"`                 // true if the device node exists on the system
	SubVdevType string `json:"sub_vdev_type,omitempty"` // type of direct parent sub-vdev (e.g. "spare", "replacing") when nested inside a top-level vdev
	SubVdevName string `json:"sub_vdev_name,omitempty"` // name of direct parent sub-vdev (e.g. "spare-2")
}

// VdevGroup is one top-level vdev in the pool's data section.
type VdevGroup struct {
	Type   string     `json:"type"`   // "mirror" | "raidz1" | "raidz2" | "raidz3" | "stripe" | "replacing"
	Name   string     `json:"name"`   // "mirror-0", "raidz1-0", or "" for a stripe vdev
	Status string     `json:"status"` // ONLINE | DEGRADED | FAULTED | …
	Disks  []VdevDisk `json:"disks"`
}

// Pool represents a ZFS pool.
type Pool struct {
	Name                string   `json:"name"`
	Size                uint64   `json:"size"`         // raw physical size (zpool list)
	Alloc               uint64   `json:"alloc"`        // allocated bytes (zpool list)
	Free                uint64   `json:"free"`         // free raw bytes (zpool list)
	UsableSize          uint64   `json:"usable_size"`  // usable = root used + root avail (zfs list)
	UsableUsed          uint64   `json:"usable_used"`  // root dataset used (zfs list)
	UsableAvail         uint64   `json:"usable_avail"` // root dataset avail (zfs list)
	Health              string   `json:"health"`
	Members             []string `json:"members"`         // raw device paths as tracked by zpool (may be by-partuuid)
	MemberDevices       []string `json:"member_devices"`  // resolved canonical /dev/sdX paths
	MemberRoles         []string `json:"member_roles"`    // per-member vdev role: "stripe"|"mirror"|"raidz1"|"raidz2"|"raidz3"
	MemberStatuses      []string `json:"member_statuses"` // per-member device state: "ONLINE"|"FAULTED"|etc
	MemberPresent       []bool   `json:"member_present"`  // per-member: true if the device path exists in /dev
	CacheDevs           []string `json:"cache_devs"`      // raw L2ARC cache paths (may be by-partuuid)
	CacheDevices        []string `json:"cache_devices"`   // resolved canonical /dev/sdX paths
	SpareDevs           []string `json:"spare_devs"`      // raw hot-spare paths (may be by-partuuid)
	SpareDevices        []string `json:"spare_devices"`   // resolved canonical /dev/sdX paths
	SpareStatuses       []string `json:"spare_statuses"`  // per-spare state: "AVAIL"|"INUSE"|"FAULTED" etc
	SparePresent        []bool   `json:"spare_present"`   // per-spare: true if the device path exists in /dev
	VdevType            string   `json:"vdev_type"`       // "stripe" | "mirror" | "raidz1" | "raidz2" | "raidz3"
	Operation           string   `json:"operation"`       // "" | "scrubbing" | "resilvering" | "expanding"
	SizeStr             string   `json:"size_str"`
	AllocStr            string   `json:"alloc_str"`
	FreeStr             string   `json:"free_str"`
	Ashift              int      `json:"ashift"`               // pool block size exponent (9=512B, 12=4K, 13=8K)
	Compression         string   `json:"compression"`          // root dataset compression
	CompRatio           string   `json:"compress_ratio"`       // root dataset compressratio
	Dedup               string   `json:"dedup"`                // root dataset dedup
	Sync                string   `json:"sync"`                 // root dataset sync
	Atime               string   `json:"atime"`                // root dataset atime
	Encrypted           bool     `json:"encrypted"`            // encryption property != "off"
	KeyLocked           bool     `json:"key_locked"`           // keystatus == "unavailable"
	EncryptionAlgorithm string   `json:"encryption_algorithm"` // e.g. "aes-256-gcm", "" when off
	// Vdevs is the structured topology of the pool's data section,
	// mirroring the tree shown by `zpool status`.
	Vdevs []VdevGroup `json:"vdevs,omitempty"`
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
	p.MemberPresent = poolMemberPresent(p.Members)
	p.CacheDevs, p.CacheDevices = poolCacheDevs(p.Name)
	p.SpareDevs, p.SpareDevices, p.SpareStatuses = poolSpareDevs(p.Name)
	p.SparePresent = poolMemberPresent(p.SpareDevs)
	p.VdevType = poolVdevType(p.Name)
	p.Operation = poolOperation(p.Name)
	p.Compression, p.CompRatio, p.Dedup, p.Sync, p.Atime = poolRootProps(p.Name)
	p.Ashift = poolAshift(p.Name)
	p.Encrypted, p.KeyLocked, p.EncryptionAlgorithm = poolEncryptionStatus(p.Name)
	p.Vdevs = poolVdevGroups(p.Name)
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
	if err != nil {
		// A command FAILURE (e.g. fork/exec starved under extreme load, or a
		// momentarily unresponsive zfs) must NOT be reported as "no pools" —
		// that makes the UI render the create-pool screen as if the pool
		// vanished. Surface it so the client shows a "system busy" + retry
		// state instead. (Genuinely-no-pools is exit 0 with empty output.)
		return nil, fmt.Errorf("zpool list: %w", err)
	}
	if strings.TrimSpace(string(out)) == "" {
		return []*Pool{}, nil // no pools configured (fresh host)
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
		p.MemberPresent = poolMemberPresent(p.Members)
		p.CacheDevs, p.CacheDevices = poolCacheDevs(p.Name)
		p.SpareDevs, p.SpareDevices, p.SpareStatuses = poolSpareDevs(p.Name)
		p.SparePresent = poolMemberPresent(p.SpareDevs)
		p.VdevType = poolVdevType(p.Name)
		p.Operation = poolOperation(p.Name)
		p.Compression, p.CompRatio, p.Dedup, p.Sync, p.Atime = poolRootProps(p.Name)
		p.Ashift = poolAshift(p.Name)
		p.Encrypted, p.KeyLocked, p.EncryptionAlgorithm = poolEncryptionStatus(p.Name)
		p.Vdevs = poolVdevGroups(p.Name)
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
	p.MemberPresent = poolMemberPresent(p.Members)
	p.CacheDevs, p.CacheDevices = poolCacheDevs(p.Name)
	p.SpareDevs, p.SpareDevices, p.SpareStatuses = poolSpareDevs(p.Name)
	p.SparePresent = poolMemberPresent(p.SpareDevs)
	p.VdevType = poolVdevType(p.Name)
	p.Operation = poolOperation(p.Name)
	p.Compression, p.CompRatio, p.Dedup, p.Sync, p.Atime = poolRootProps(p.Name)
	p.Ashift = poolAshift(p.Name)
	p.Encrypted, p.KeyLocked, p.EncryptionAlgorithm = poolEncryptionStatus(p.Name)
	p.Vdevs = poolVdevGroups(p.Name)
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
		"AVAIL": true, "INUSE": true,
	}
	vdevPrefixes := []string{"mirror-", "raidz3-", "raidz2-", "raidz1-", "raidz-", "spare-", "log-", "cache-", "replacing-"}
	skipSections := map[string]bool{"cache": true, "log": true, "logs": true, "spare": true, "spares": true}

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

		// Always capture the pool name line so poolIndent is set
		// regardless of which section we are targeting.
		if name == poolName {
			poolIndent = indent
			continue
		}

		if !inTarget {
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
		// If ZFS returned an unresolved path (by-partuuid, by-id, bare UUID, or
		// the bare filename of a by-id entry such as "ata-MODEL_SERIAL" which
		// `zpool status` without -P returns for pools created with by-id paths),
		// fall back to our own resolution using the raw -P path.
		if res == "" || strings.Contains(res, "/by-partuuid/") || strings.Contains(res, "/by-id/") ||
			isPartuuidString(res) || looksLikeByIDBasename(res) {
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
	vdevPrefixes := []string{"mirror-", "raidz3-", "raidz2-", "raidz1-", "raidz-", "spare-", "log-", "cache-", "replacing-"}
	skipSections := map[string]bool{"cache": true, "log": true, "logs": true, "spare": true, "spares": true}
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
				case strings.HasPrefix(name, "raidz3-"):
					currentRole = "raidz3"
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
		if res == "" || isPartuuidString(res) ||
			strings.Contains(res, "/by-partuuid/") || strings.Contains(res, "/by-id/") ||
			looksLikeByIDBasename(res) {
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

// poolSpareDevs parses zpool status output to return hot-spare device paths
// and their per-device status (AVAIL, INUSE, FAULTED, etc.).
// poolVdevGroups parses `zpool status -P poolName` and returns the vdev topology
// of the DATA section as a slice of VdevGroup values.  Cache / spare / log sections
// are excluded; those are handled by poolCacheDevs / poolSpareDevs.
func poolVdevGroups(poolName string) []VdevGroup {
	outP, err := exec.Command("sudo", "zpool", "status", "-P", poolName).Output()
	if err != nil {
		return nil
	}
	outNP, _ := exec.Command("sudo", "zpool", "status", poolName).Output()

	validStates := map[string]bool{
		"ONLINE": true, "DEGRADED": true, "FAULTED": true,
		"OFFLINE": true, "REMOVED": true, "UNAVAIL": true,
		"AVAIL": true, "INUSE": true,
	}
	skipSectionNames := map[string]bool{
		"spares": true, "spare": true,
		"cache": true,
		"logs":  true, "log": true,
	}
	vdevPfxType := []struct {
		pfx string
		typ string
	}{
		{"mirror-", "mirror"},
		{"raidz3-", "raidz3"},
		{"raidz2-", "raidz2"},
		{"raidz1-", "raidz1"},
		{"raidz-", "raidz1"},
		{"replacing-", "replacing"},
		{"spare-", "spare"},
	}

	countIndent := func(line string) int {
		return len(line) - len(strings.TrimLeft(line, " \t"))
	}

	// Build a positional index: for each valid-state leaf line in -P output,
	// record the corresponding name from the non-P output so we can map
	// raw PARTUUID paths → ZFS-resolved names.
	type entry struct {
		indent int
		name   string
	}
	collectEntries := func(data []byte) []entry {
		var out []entry
		inCfg := false
		for _, line := range strings.Split(string(data), "\n") {
			tr := strings.TrimSpace(line)
			if strings.HasPrefix(tr, "config:") {
				inCfg = true
				continue
			}
			if !inCfg {
				continue
			}
			if strings.HasPrefix(tr, "errors:") {
				break
			}
			if tr == "" {
				continue
			}
			f := strings.Fields(tr)
			if len(f) < 2 || !validStates[f[1]] {
				continue
			}
			out = append(out, entry{countIndent(line), f[0]})
		}
		return out
	}
	entriesP := collectEntries(outP)
	entriesNP := collectEntries(outNP)

	// rawToResolved: map the -P path to the ZFS-resolved (non-P) name.
	rawToResolved := make(map[string]string, len(entriesP))
	for i, e := range entriesP {
		if i < len(entriesNP) {
			rawToResolved[e.name] = entriesNP[i].name
		}
	}

	resolveDevice := func(raw string) string {
		res := rawToResolved[raw]
		// If ZFS returned a bare PARTUUID or another unresolved form, resolve it ourselves.
		if res == "" || isPartuuidString(res) ||
			strings.Contains(res, "/by-partuuid/") || strings.Contains(res, "/by-id/") ||
			looksLikeByIDBasename(res) {
			res = resolveDevPath(raw)
		}
		if res != "" && !strings.HasPrefix(res, "/dev/") {
			res = "/dev/" + res
		}
		return res
	}

	// Parse the -P output structure.
	inConfig := false
	inData := true
	poolIndent := -1
	var groups []VdevGroup
	currentGroup := -1
	subVdevIndent := -1 // indent of the current sub-vdev header (e.g. spare-2)
	subVdevType := ""   // type of current sub-vdev (e.g. "spare", "replacing")
	subVdevName := ""   // name of current sub-vdev (e.g. "spare-2")

	for _, line := range strings.Split(string(outP), "\n") {
		tr := strings.TrimSpace(line)
		if strings.HasPrefix(tr, "config:") {
			inConfig = true
			continue
		}
		if !inConfig {
			continue
		}
		if strings.HasPrefix(tr, "errors:") {
			break
		}
		if tr == "" {
			continue
		}

		indent := countIndent(line)
		fields := strings.Fields(tr)

		// Single-token lines are section headers (spares, cache, logs).
		if len(fields) == 1 {
			inData = !skipSectionNames[strings.ToLower(tr)]
			continue
		}
		if len(fields) < 2 || !validStates[fields[1]] {
			continue
		}
		name, status := fields[0], fields[1]

		// Pool name — always capture indent, regardless of section.
		if name == poolName {
			poolIndent = indent
			continue
		}
		if poolIndent < 0 || !inData {
			continue
		}

		vdevIndent := poolIndent + 2

		// Classify this line.
		isVdevHdr := false
		vdevType := ""
		for _, pt := range vdevPfxType {
			if strings.HasPrefix(name, pt.pfx) {
				isVdevHdr = true
				vdevType = pt.typ
				break
			}
		}

		// If we've stepped back out of a sub-vdev, clear sub-vdev tracking.
		if subVdevIndent >= 0 && indent <= subVdevIndent {
			subVdevIndent = -1
			subVdevType = ""
			subVdevName = ""
		}

		switch {
		case indent == vdevIndent && isVdevHdr:
			// Named top-level vdev group header (mirror-0, raidz1-0, …)
			groups = append(groups, VdevGroup{Type: vdevType, Name: name, Status: status})
			currentGroup = len(groups) - 1

		case indent == vdevIndent && !isVdevHdr:
			// Stripe disk — direct child of pool, no named vdev wrapper.
			dev := resolveDevice(name)
			_, statErr := os.Stat(name)
			groups = append(groups, VdevGroup{
				Type:   "stripe",
				Name:   "",
				Status: status,
				Disks: []VdevDisk{{
					Raw:     name,
					Device:  dev,
					Status:  status,
					Present: statErr == nil,
				}},
			})
			currentGroup = -1

		case indent > vdevIndent && currentGroup >= 0 && isVdevHdr:
			// Sub-vdev header inside a top-level vdev (e.g. spare-2 inside raidz1-0).
			subVdevIndent = indent
			subVdevType = vdevType
			subVdevName = name

		case indent > vdevIndent && currentGroup >= 0 && !isVdevHdr:
			// Leaf disk inside a named vdev.
			dev := resolveDevice(name)
			_, statErr := os.Stat(name)
			d := VdevDisk{
				Raw:     name,
				Device:  dev,
				Status:  status,
				Present: statErr == nil,
			}
			// Record sub-vdev parentage when this disk is inside a spare-N / replacing-N.
			if subVdevIndent >= 0 && indent > subVdevIndent {
				d.SubVdevType = subVdevType
				d.SubVdevName = subVdevName
			}
			groups[currentGroup].Disks = append(groups[currentGroup].Disks, d)
		}
	}
	return groups
}

func poolSpareDevs(poolName string) (raw, resolved, statuses []string) {
	rawNames := zpoolStatusDevices(poolName, "spares", true)
	resolvedNames := zpoolStatusDevices(poolName, "spares", false)
	// Collect statuses directly from zpool status output.
	out, _ := exec.Command("sudo", "zpool", "status", poolName).Output()
	spareStatus := map[string]string{}
	inSpares := false
	inConfig := false
	validStates := map[string]bool{
		"ONLINE": true, "DEGRADED": true, "FAULTED": true,
		"OFFLINE": true, "REMOVED": true, "UNAVAIL": true,
		"AVAIL": true, "INUSE": true,
	}
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
		if len(fields) == 1 {
			inSpares = strings.ToLower(trimmed) == "spares"
			continue
		}
		if len(fields) < 2 {
			continue
		}
		name, state := fields[0], fields[1]
		if !validStates[state] {
			inSpares = strings.ToLower(name) == "spares"
			continue
		}
		if !inSpares {
			continue
		}
		spareStatus[name] = state
	}

	for i, r := range rawNames {
		var res string
		if i < len(resolvedNames) {
			res = resolvedNames[i]
		}
		if res == "" || isPartuuidString(res) ||
			strings.Contains(res, "/by-partuuid/") || strings.Contains(res, "/by-id/") ||
			looksLikeByIDBasename(res) {
			res = resolveDevPath(r)
		}
		if res != "" && !strings.HasPrefix(res, "/dev/") {
			res = "/dev/" + res
		}
		raw = append(raw, r)
		resolved = append(resolved, res)
		st := spareStatus[resolvedNames[i]]
		if st == "" {
			// Try matching by basename.
			base := filepath.Base(r)
			for k, v := range spareStatus {
				if filepath.Base(k) == base {
					st = v
					break
				}
			}
		}
		if st == "" {
			st = "AVAIL"
		}
		statuses = append(statuses, st)
	}
	return raw, resolved, statuses
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
	vdevPrefixes := []string{"mirror-", "raidz3-", "raidz2-", "raidz1-", "raidz-", "spare-", "log-", "cache-", "replacing-"}
	skipSections := map[string]bool{"cache": true, "log": true, "logs": true, "spare": true, "spares": true}

	inConfig, inData := false, true
	poolIndent := -1
	countIndent := func(line string) int {
		return len(line) - len(strings.TrimLeft(line, " \t"))
	}
	var statuses []string
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
		if len(fields) < 2 || !validStates[fields[1]] {
			continue
		}
		name := fields[0]
		if name == "NAME" {
			continue
		}
		if poolIndent < 0 {
			poolIndent = indent
			continue
		} // pool line itself
		if indent <= poolIndent {
			continue
		}
		if skipSections[strings.ToLower(name)] {
			inData = false
			continue
		}
		if !inData {
			continue
		}
		isVdev := false
		for _, pfx := range vdevPrefixes {
			if strings.HasPrefix(name, pfx) {
				isVdev = true
				break
			}
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

// diskBaseDev strips the trailing partition number from a device path.
// e.g. "/dev/sdb1" → "/dev/sdb", "/dev/nvme0n1p1" → "/dev/nvme0n1".
func diskBaseDev(dev string) string {
	// nvme / mmcblk style: …p<N>
	if re := regexp.MustCompile(`^(/dev/(?:nvme|mmcblk)\d+n\d+)p\d+$`); re.MatchString(dev) {
		return re.FindStringSubmatch(dev)[1]
	}
	// sd / vd / xvd / hd style: trailing digit(s)
	return regexp.MustCompile(`\d+$`).ReplaceAllString(dev, "")
}

// ReplacePoolDisk replaces a failed or missing pool member with a new device.
// oldDev is the raw member path as tracked by ZFS (from Pool.Members).
// newDev is the canonical /dev/sdX path of the replacement disk.
//
// If newDev (or a partition of it) is already registered as a spare for the
// pool, the existing partition / PARTUUID path is reused directly — no
// repartitioning. Otherwise the disk is wiped and repartitioned (GPT BF01).
// ZFS starts a resilver automatically after the replacement.
func ReplacePoolDisk(poolName, oldDev, newDev string) error {
	// Check if newDev is already a spare for this pool.
	spareRaws, spareDevices, _ := poolSpareDevs(poolName)
	puPath := ""
	for i, dev := range spareDevices {
		if diskBaseDev(dev) == newDev || dev == newDev {
			puPath = spareRaws[i] // reuse the spare's existing PARTUUID path
			break
		}
	}
	if puPath == "" {
		var err error
		puPath, err = PrepareZFSPartition(newDev)
		if err != nil {
			return fmt.Errorf("prepare %s: %w", newDev, err)
		}
	}
	out, err := exec.Command("sudo", "zpool", "replace", "-f", poolName, oldDev, puPath).CombinedOutput()
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

// AddPoolSpare adds a disk as a hot spare to the pool.
// The disk is wiped and partitioned (GPT, type BF01) first so ZFS tracks it
// by stable PARTUUID — consistent with how capacity and cache disks are added.
func AddPoolSpare(poolName, device string) error {
	puPath, err := PrepareZFSPartition(device)
	if err != nil {
		return fmt.Errorf("prepare %s: %w", device, err)
	}
	out, err := exec.Command("sudo", "zpool", "add", poolName, "spare", puPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// RemovePoolSpare removes a hot spare from the pool.
// Fails if the spare is currently in use (actively replacing a failed disk).
func RemovePoolSpare(poolName, device string) error {
	out, err := exec.Command("sudo", "zpool", "remove", poolName, device).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// DetachPoolDisk detaches a disk from a mirror or replacing vdev in the pool.
// Typically used to remove an offline or faulted mirror member.
func DetachPoolDisk(poolName, device string) error {
	out, err := exec.Command("sudo", "zpool", "detach", poolName, device).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// AttachPoolDisk attaches newDevice as a mirror partner to existingDevice in the pool.
// If existingDevice is a single-disk vdev this converts it to a 2-way mirror;
// if it is already a mirror this adds a 3rd leg.
// newDevice is partitioned (GPT, type BF01) first so ZFS tracks it by stable PARTUUID.
func AttachPoolDisk(poolName, existingDevice, newDevice string) error {
	puPath, err := PrepareZFSPartition(newDevice)
	if err != nil {
		return fmt.Errorf("prepare %s: %w", newDevice, err)
	}
	out, err := exec.Command("sudo", "zpool", "attach", "-f", poolName, existingDevice, puPath).CombinedOutput()
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

// looksLikeByIDBasename returns true when s looks like the bare filename
// component of a /dev/disk/by-id/ entry (e.g. "ata-SAMSUNG_870_S5SVNG0N123456",
// "wwn-0x5000cca2bc5e3e80").  These have recognisable prefixes and contain
// hyphens but no path separators.  `zpool status` (without -P) returns them
// when a pool was created using by-id paths.
func looksLikeByIDBasename(s string) bool {
	if strings.Contains(s, "/") {
		return false
	}
	return strings.HasPrefix(s, "ata-") ||
		strings.HasPrefix(s, "wwn-") ||
		strings.HasPrefix(s, "scsi-") ||
		strings.HasPrefix(s, "nvme-eui.") ||
		strings.HasPrefix(s, "nvme-") ||
		strings.HasPrefix(s, "dm-name-") ||
		strings.HasPrefix(s, "dm-uuid-") ||
		strings.HasPrefix(s, "usb-")
}

func resolveDevPath(p string) string {
	// 1. Direct symlink resolution (works when udev created /dev/disk/by-partuuid/).
	if real, err := filepath.EvalSymlinks(p); err == nil && strings.HasPrefix(real, "/dev/") {
		return real
	}

	// 1b. For /dev/disk/by-* paths that EvalSymlinks couldn't resolve (e.g. udev
	// not yet settled), ask lsblk which reads from sysfs and may still succeed.
	if strings.HasPrefix(p, "/dev/disk/by-") {
		if out, err := exec.Command("lsblk", "-ln", "-o", "NAME", p).Output(); err == nil {
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			if len(lines) > 0 {
				if name := strings.TrimSpace(lines[0]); name != "" && !strings.Contains(name, " ") {
					return "/dev/" + name
				}
			}
		}
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
	// Inform the kernel of the new partition table, then wait for udev to
	// fully process the new partition (creates device node + by-partuuid symlink).
	exec.Command("sudo", "partprobe", device).Run()                 //nolint
	exec.Command("sudo", "udevadm", "settle", "--timeout=15").Run() //nolint

	// Locate the new partition's by-partuuid symlink.
	devName := filepath.Base(device) // e.g. "sda" or "nvme0n1"
	const dir = "/dev/disk/by-partuuid"
	for i := 0; i < 20; i++ { // up to 10 s fallback poll
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
// layout: "stripe" | "mirror" | "raid10" | "raidz1" | "raidz2" | "raidz3"
//
//	raid10: stripe of 2-way mirrors — len(devices) must be even and ≥4. Each
//	consecutive pair becomes its own mirror vdev, so the resulting top-level
//	layout is `mirror d0 d1 mirror d2 d3 …`.
//
// ashift: 9, 12, or 13
// compression: "off" | "lz4" | "zstd"
// dedup: "off" | "on" | "verify"
// keyFilePath: absolute path to 32-byte raw key file, or "" for no encryption
// mountRoot: if true, ZFS default mountpoint (/<name>); if false, pool is mounted at /mnt/<name>
func CreatePool(name, layout string, ashift int, compression, dedup string, devices []string, keyFilePath string, mountRoot bool) error {
	if layout == "raid10" {
		if len(devices) < 4 || len(devices)%2 != 0 {
			return fmt.Errorf("raid10 requires an even number of disks (≥4); got %d", len(devices))
		}
	}
	// Prepare each disk, then resolve the partuuid symlink to the real partition
	// device path before passing to zpool create.  On some systems the symlink
	// exists but its target is not yet accessible when zpool create runs,
	// causing "cannot resolve path" errors.
	devPaths := make([]string, 0, len(devices))
	for _, dev := range devices {
		puPath, err := PrepareZFSPartition(dev)
		if err != nil {
			return fmt.Errorf("prepare %s: %w", dev, err)
		}
		devPaths = append(devPaths, puPath)
	}

	// `cachefile=/etc/zfs/zpool.cache` is critical: without it, OpenZFS
	// 2.x leaves the cache property at "none" for newly-created pools,
	// so `zfs-import-cache.service` never finds the pool at boot and
	// the user comes back to "no pools available". Same dance applied
	// in ImportPool / ImportPoolForce so an imported pool also persists.
	args := []string{"zpool", "create", "-f",
		"-o", "cachefile=/etc/zfs/zpool.cache",
		"-o", fmt.Sprintf("ashift=%d", ashift),
		"-O", "atime=off",
	}
	if !mountRoot {
		args = append(args, "-m", "/mnt/"+name)
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
	switch layout {
	case "mirror", "raidz1", "raidz2", "raidz3":
		args = append(args, layout)
		args = append(args, devPaths...)
	case "raid10":
		// Stripe of 2-way mirrors: emit `mirror d0 d1 mirror d2 d3 …` so each
		// pair becomes its own top-level vdev. zpool stripes across vdevs
		// automatically.
		for i := 0; i < len(devPaths); i += 2 {
			args = append(args, "mirror", devPaths[i], devPaths[i+1])
		}
	default: // stripe
		args = append(args, devPaths...)
	}
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
	Pool        string  `json:"pool,omitempty"` // pool this status applies to (v6.5.26+)
	State       string  `json:"state"`          // idle | running | finished | canceled
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
	info := parseScrubInfo(string(out))
	info.Pool = poolName
	return info, nil
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
func poolRootProps(name string) (compression, compRatio, dedup, sync_, atime string) {
	out, err := exec.Command("sudo", "zfs", "get", "-Hp",
		"compression,compressratio,dedup,sync,atime", name).Output()
	compression, compRatio, dedup, sync_, atime = "lz4", "1.00x", "off", "standard", "off"
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
		case "compressratio":
			compRatio = f[2]
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

// poolAshift returns the ashift value for a pool (block size exponent).
func poolAshift(name string) int {
	out, err := exec.Command("sudo", "zpool", "get", "-Hp", "ashift", name).Output()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) >= 3 && f[1] == "ashift" {
			v, err := strconv.Atoi(f[2])
			if err == nil {
				return v
			}
		}
	}
	return 0
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

// DatasetExists returns true when the named ZFS dataset (or zvol) exists.
func DatasetExists(name string) bool {
	err := exec.Command("sudo", "zfs", "list", "-H", name).Run()
	return err == nil
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

// tryUnmountAndUnloadKey attempts to unmount a dataset and unload its key.
// Returns a "dataset is busy" error if the dataset is in use.
func tryUnmountAndUnloadKey(name string) error {
	umountOut, umountErr := exec.Command("sudo", "zfs", "umount", name).CombinedOutput()
	if umountErr != nil {
		return fmt.Errorf("dataset is busy: %s", strings.TrimSpace(string(umountOut)))
	}
	out, err := exec.Command("sudo", "zfs", "unload-key", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("zfs unload-key: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// UnloadDatasetKey unmounts a dataset and unloads its encryption key (locks it).
//
// If force is false and the dataset is busy, a "dataset is busy" error is returned
// so the caller can offer a force option.
//
// If force is true, any SMB/NFS shares whose path sits on the dataset mountpoint
// are temporarily marked disabled (SMB: "available = no"; NFS: omitted from exports)
// so that the service releases file handles without disrupting other shares.
// configDir is required for force mode to locate share configs.
func UnloadDatasetKey(name string, force bool, configDir string) error {
	if err := tryUnmountAndUnloadKey(name); err == nil {
		return nil
	} else if !force {
		return err
	}

	mp := datasetMountpoint(name)
	if mp == "" || mp == "none" || mp == "legacy" || configDir == "" {
		return tryUnmountAndUnloadKey(name)
	}

	// Disable affected SMB shares and reload Samba.
	var disabledSMB []string
	if smbShares, err := ListSMBShares(configDir); err == nil {
		for _, s := range smbShares {
			if s.Path == mp || strings.HasPrefix(s.Path, mp+"/") {
				if !s.Disabled {
					if setErr := SetSMBShareDisabled(configDir, s.Name, true); setErr == nil {
						disabledSMB = append(disabledSMB, s.Name)
					}
				}
			}
		}
	}
	if len(disabledSMB) > 0 {
		_ = ReloadSamba()
	}

	// Disable affected NFS shares and re-export.
	var disabledNFS []string
	if nfsShares, err := ListNFSShares(configDir); err == nil {
		for _, s := range nfsShares {
			if s.Path == mp || strings.HasPrefix(s.Path, mp+"/") {
				if !s.Disabled {
					if setErr := SetNFSShareDisabled(configDir, s.ID, true); setErr == nil {
						disabledNFS = append(disabledNFS, s.ID)
					}
				}
			}
		}
	}

	// Retry the unmount + key unload for up to 10 s, giving Samba/NFS time
	// to release all file handles after the share was disabled.
	var lockErr error
	deadline := time.Now().Add(10 * time.Second)
	for {
		lockErr = tryUnmountAndUnloadKey(name)
		if lockErr == nil {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Last resort: if the dataset is still busy after 10 s, stop smbd
	// entirely so it releases all file handles, force-unmount and unload the
	// key, then bring smbd back up before restoring the share config.
	if lockErr != nil {
		_ = ControlSamba("stop")
		time.Sleep(500 * time.Millisecond)
		lockErr = tryUnmountAndUnloadKey(name)
		_ = ControlSamba("start")
	}

	// Re-enable all affected shares regardless of lock outcome.
	for _, smbName := range disabledSMB {
		_ = SetSMBShareDisabled(configDir, smbName, false)
	}
	if len(disabledSMB) > 0 {
		_ = ReloadSamba()
	}
	for _, nfsID := range disabledNFS {
		_ = SetNFSShareDisabled(configDir, nfsID, false)
	}

	return lockErr
}

// LoadDatasetKeyPassphrase loads a dataset's encryption key by piping the
// given passphrase/hex string to zfs load-key via stdin.
// The passphrase is never written to disk or logged.
func LoadDatasetKeyPassphrase(name, passphrase string) error {
	cmd := exec.Command("sudo", "zfs", "load-key", name)
	cmd.Stdin = strings.NewReader(passphrase + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("zfs load-key: %s", strings.TrimSpace(string(out)))
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
// "raidz1", "raidz2", "raidz3", "mirror", or "stripe" (default when no named vdev is found).
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
		if strings.HasPrefix(name, "raidz3") {
			return "raidz3"
		}
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

// ExportPool exports (disconnects) a pool so it can be moved to another system.
func ExportPool(name string) error {
	out, err := exec.Command("sudo", "zpool", "export", name).CombinedOutput()
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

// ImportPool imports a named pool. `-o cachefile=/etc/zfs/zpool.cache`
// records the pool in the system cache so zfs-import-cache.service brings
// it back up automatically after the next reboot.
func ImportPool(name string) error {
	out, err := exec.Command("sudo", "zpool", "import",
		"-o", "cachefile=/etc/zfs/zpool.cache", name).CombinedOutput()
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
// "previously in use" safety check. Same cachefile semantics as
// ImportPool — persists the pool across reboots.
func ImportPoolForce(name string) error {
	out, err := exec.Command("sudo", "zpool", "import", "-f",
		"-o", "cachefile=/etc/zfs/zpool.cache", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ── Datasets ──────────────────────────────────────────────────────────────────

// Dataset represents a ZFS filesystem dataset.
type Dataset struct {
	Name                string `json:"name"`
	ShortName           string `json:"short_name"`
	Used                uint64 `json:"used"`
	Avail               uint64 `json:"avail"`
	Refer               uint64 `json:"refer"`
	Quota               uint64 `json:"quota"`          // 0 = none
	RefQuota            uint64 `json:"refquota"`       // 0 = none
	Refreservation      uint64 `json:"refreservation"` // 0 = none
	Compression         string `json:"compression"`
	CompRatio           string `json:"compress_ratio"`
	RecordSize          uint64 `json:"record_size"`
	RecordSizeRaw       string `json:"record_size_raw"` // e.g. "128K" or "inherit"
	Mountpoint          string `json:"mountpoint"`
	Sync                string `json:"sync"`             // standard|always|disabled|inherit
	Dedup               string `json:"dedup"`            // on|off|verify|inherit
	CaseSensitivity     string `json:"case_sensitivity"` // sensitive|insensitive|mixed
	Comment             string `json:"comment"`          // user property zfsnas:comment
	UsedStr             string `json:"used_str"`
	AvailStr            string `json:"avail_str"`
	QuotaStr            string `json:"quota_str"`
	RefreservationStr   string `json:"refreservation_str"`
	Depth               int    `json:"depth"`                // 0 = pool root
	Encrypted           bool   `json:"encrypted"`            // encryption != "off"
	KeyLocked           bool   `json:"key_locked"`           // keystatus == "unavailable"
	EncryptionAlgorithm string `json:"encryption_algorithm"` // e.g. "aes-256-gcm", "" when off
	Mounted             bool   `json:"mounted"`              // zfs mounted == "yes"
	CanMount            string `json:"canmount"`             // on|off|noauto
	UsedBySnapshots     uint64 `json:"used_by_snapshots"`    // space held by snapshots (usedbysnapshots)
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
	KeyFilePath     string // non-empty → create with AES-256-GCM encryption, key at this path (stored on server)
	ClientKeyHex    string // non-empty → create with AES-256-GCM, keyformat=hex, keylocation=prompt; key piped via stdin and NOT stored on server
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
		"-o", "name,used,avail,refer,quota,refquota,compression,compressratio,recordsize,mountpoint,sync,dedup,casesensitivity,refreservation,zfsnas:comment,encryption,keystatus,mounted,canmount,usedbysnapshots",
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
	var usedBySnapshots uint64
	if len(f) >= 20 {
		usedBySnapshots, _ = strconv.ParseUint(f[19], 10, 64)
	}

	// Derive human-readable record size string.
	recordSizeRaw := formatBytesShort(recordSize)

	depth := strings.Count(name, "/") - strings.Count(poolName, "/")
	parts := strings.Split(name, "/")
	shortName := parts[len(parts)-1]

	return Dataset{
		Name:                name,
		ShortName:           shortName,
		Used:                used,
		Avail:               avail,
		Refer:               refer,
		Quota:               quota,
		RefQuota:            refquota,
		Refreservation:      refreservation,
		Compression:         compression,
		CompRatio:           compRatio,
		RecordSize:          recordSize,
		RecordSizeRaw:       recordSizeRaw,
		Mountpoint:          mountpoint,
		Sync:                sync,
		Dedup:               dedup,
		CaseSensitivity:     caseSensitivity,
		Comment:             comment,
		UsedStr:             formatBytes(used),
		AvailStr:            formatBytes(avail),
		QuotaStr:            zeroOrBytes(quota),
		RefreservationStr:   zeroOrBytes(refreservation),
		Depth:               depth,
		Encrypted:           dsEncrypted,
		KeyLocked:           dsKeyLocked,
		EncryptionAlgorithm: dsEncAlgo,
		Mounted:             dsMounted,
		CanMount:            dsCanMount,
		UsedBySnapshots:     usedBySnapshots,
	}, nil
}

// CreateDataset creates a new ZFS filesystem with the given options.
// zfsComponentRe validates a single dataset path component (between slashes).
// ZFS permits alphanumerics plus _ - : . — the component must start alnum/_.
var zfsComponentRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:\-]*$`)

// validateZFSName checks a full dataset/zvol name (pool/child/…) is well-formed.
func validateZFSName(name string) error {
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.Contains(name, "//") {
		return fmt.Errorf("invalid dataset name %q", name)
	}
	parts := strings.Split(name, "/")
	if len(parts) < 2 {
		return fmt.Errorf("name must include the pool and at least one component (e.g. pool/name)")
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || !zfsComponentRe.MatchString(p) {
			return fmt.Errorf("invalid name component %q", p)
		}
	}
	return nil
}

// RenameDataset renames a dataset or zvol in place via `zfs rename`. ZFS can
// only rename within the same pool; any children and snapshots travel with it.
// The rename fails (and the error is surfaced) if the dataset is busy/mounted
// in a way ZFS refuses to remount.
func RenameDataset(oldName, newName string) error {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if oldName == "" || newName == "" {
		return fmt.Errorf("name must not be empty")
	}
	if oldName == newName {
		return fmt.Errorf("the new name is identical to the current name")
	}
	if !strings.Contains(oldName, "/") {
		return fmt.Errorf("cannot rename a pool root dataset")
	}
	if err := validateZFSName(newName); err != nil {
		return err
	}
	if strings.SplitN(oldName, "/", 2)[0] != strings.SplitN(newName, "/", 2)[0] {
		return fmt.Errorf("cannot rename across pools — keep the same pool prefix")
	}
	if out, err := exec.Command("sudo", "zfs", "rename", oldName, newName).CombinedOutput(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

func CreateDataset(name string, opts DatasetCreateOptions) error {
	args := []string{"zfs", "create"}
	if opts.KeyFilePath != "" {
		args = append(args,
			"-o", "encryption=aes-256-gcm",
			"-o", "keyformat=raw",
			"-o", "keylocation=file://"+opts.KeyFilePath,
		)
	} else if opts.ClientKeyHex != "" {
		// Client-managed key: hex key supplied via stdin, never stored on server.
		args = append(args,
			"-o", "encryption=aes-256-gcm",
			"-o", "keyformat=hex",
			"-o", "keylocation=prompt",
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
	cmd := exec.Command("sudo", args...)
	if opts.ClientKeyHex != "" {
		cmd.Stdin = strings.NewReader(opts.ClientKeyHex + "\n")
	}
	out, err := cmd.CombinedOutput()
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
// A value of "" or "inherit" resets the property to its inherited value via `zfs inherit`.
func SetDatasetProps(name string, props map[string]string) error {
	for k, v := range props {
		var out []byte
		var err error
		if v == "" || v == "inherit" {
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

// DestroyDatasetForce removes a dataset using "zfs destroy -Rf": -R recurses
// through children, snapshots, and clones; -f force-unmounts any active mounts.
// This is the "last resort" path exposed in the UI when a regular delete fails.
func DestroyDatasetForce(name string) error {
	out, err := exec.Command("sudo", "zfs", "destroy", "-Rf", name).CombinedOutput()
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

// strftimeToGo converts a strftime format string to a Go time layout string.
// Supports the subset used in SMB shadow:format: %Y %m %d %H %M %S.
func strftimeToGo(f string) string {
	r := strings.NewReplacer(
		"%Y", "2006",
		"%m", "01",
		"%d", "02",
		"%H", "15",
		"%M", "04",
		"%S", "05",
	)
	return r.Replace(f)
}

// DatasetForPath resolves a filesystem path (typically a share mountpoint such
// as "/mnt/tank/testds") to the ZFS dataset name that backs it (e.g. "tank/testds").
// First tries "zfs list -H -o name <path>" which returns the dataset whose mount
// area contains the path; falls back to a mountpoint scan via ListAllDatasets so
// the resolution still works when zfs/sudo paths differ between distributions.
func DatasetForPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	if out, err := exec.Command("sudo", "zfs", "list", "-H", "-o", "name", path).Output(); err == nil {
		name := strings.TrimSpace(string(out))
		if name != "" {
			return name, nil
		}
	}
	// Fallback: best mountpoint match (longest prefix wins so nested datasets
	// resolve to the closest ancestor).
	datasets, err := ListAllDatasets()
	if err != nil {
		return "", err
	}
	bestName := ""
	bestLen := 0
	for _, d := range datasets {
		mp := strings.TrimSpace(d.Mountpoint)
		if mp == "" || mp == "none" || mp == "-" || mp == "legacy" {
			continue
		}
		if path == mp || strings.HasPrefix(path, mp+"/") {
			if len(mp) > bestLen {
				bestLen = len(mp)
				bestName = d.Name
			}
		}
	}
	if bestName == "" {
		return "", fmt.Errorf("no ZFS dataset found for path %q", path)
	}
	return bestName, nil
}

// CreateShadowCopySnapshot creates a snapshot whose name matches the given
// strftime-style shadow:format string (e.g. "auto-%Y%m%d-%H%M%S").
// Used by the VSS Snapshot action so the resulting snapshot is visible to
// Samba's vfs_shadow_copy2 module as a Windows Previous Version.
func CreateShadowCopySnapshot(dataset, shadowFormat string) (string, error) {
	if shadowFormat == "" {
		shadowFormat = "auto-%Y%m%d-%H%M%S"
	}
	snapName := time.Now().Format(strftimeToGo(shadowFormat))
	fullName := fmt.Sprintf("%s@%s", dataset, snapName)
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

// ZfsOrigin returns the `origin` property of a dataset — the snapshot it was
// cloned from — or "" when the dataset is not a clone (ZFS reports "-") or the
// query fails. Used to detect instances whose storage is a ZFS clone of a
// backup snapshot (an Instant Independent Restore).
func ZfsOrigin(dataset string) string {
	out, err := exec.Command("zfs", "get", "-H", "-o", "value", "origin", dataset).Output()
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if v == "-" {
		return ""
	}
	return v
}

// ZfsSnapshotClones returns the dataset names cloned from a snapshot (the
// `clones` property), or nil when none. A snapshot with clones cannot be
// destroyed, which is how an Instant Independent Restore keeps its backup
// pinned until promoted to a full copy.
func ZfsSnapshotClones(snapshot string) []string {
	out, err := exec.Command("zfs", "get", "-H", "-o", "value", "clones", snapshot).Output()
	if err != nil {
		return nil
	}
	v := strings.TrimSpace(string(out))
	if v == "-" || v == "" {
		return nil
	}
	return strings.Split(v, ",")
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

// ── ZVol ──────────────────────────────────────────────────────────────────────

// ZVol represents a ZFS volume (block device).
type ZVol struct {
	Name           string `json:"name"`
	Pool           string `json:"pool"`
	Size           uint64 `json:"size"` // volsize in bytes
	Used           uint64 `json:"used"`
	Refer          uint64 `json:"refer"`
	Refreservation uint64 `json:"refreservation"` // 0 = none/thin
	Compression    string `json:"compression"`
	CompRatio      string `json:"comp_ratio"`
	Sync           string `json:"sync"`
	Dedup          string `json:"dedup"`
	VolBlockSize   string `json:"volblocksize"`
	Encrypted      bool   `json:"encrypted"`
	Comment        string `json:"comment"`
	DevPath        string `json:"dev_path"` // /dev/zvol/<name>
	Creation       int64  `json:"creation"` // unix seconds (v6.7.7)
}

// ZVolCreateRequest holds all parameters for creating a new ZVol.
type ZVolCreateRequest struct {
	Parent       string `json:"parent"` // pool or pool/dataset path
	Name         string `json:"name"`   // leaf name
	Size         string `json:"size"`   // e.g. "10G", "500M"
	Comment      string `json:"comment"`
	Provisioning string `json:"provisioning"`  // "thick"|"thin"|"25"|"50"|"75"
	Sync         string `json:"sync"`          // "" = inherit
	Compression  string `json:"compression"`   // "" = inherit
	Dedup        string `json:"dedup"`         // "" = inherit
	BlockSize    string `json:"block_size"`    // "" = inherit; "4K", "8K", etc.
	Encryption   string `json:"encryption"`    // "" = inherit, "enabled"
	KeyFilePath  string `json:"key_file_path"` // required when Encryption="enabled"
}

// ZVolEditRequest holds the mutable properties for editing a ZVol.
type ZVolEditRequest struct {
	Name            string `json:"name"`
	Comment         string `json:"comment"`
	Provisioning    string `json:"provisioning"`       // "thick"|"thin"|"25"|"50"|"75"
	VolSizeBytes    uint64 `json:"vol_size_bytes"`     // current volsize, required for % provisioning
	NewVolSizeBytes uint64 `json:"new_vol_size_bytes"` // if >0 and >= VolSizeBytes, grow the volume
	Sync            string `json:"sync"`
	Compression     string `json:"compression"`
	Dedup           string `json:"dedup"`
}

// ListAllZVols returns all ZFS volumes across all imported pools.
func ListAllZVols() ([]ZVol, error) {
	out, err := exec.Command("sudo", "zfs", "list",
		"-t", "volume",
		"-H", "-p",
		"-o", "name,volsize,used,refer,compression,compressratio,sync,dedup,volblocksize,encryption,zfsnas:comment,refreservation,creation",
	).Output()
	if err != nil {
		// No volumes is not an error — zfs list exits non-zero when there are no results.
		return []ZVol{}, nil
	}
	var zvols []ZVol
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		zv, err := parseZVolLine(line)
		if err != nil {
			debugLog("zvol parse error: %v", err)
			continue
		}
		zvols = append(zvols, zv)
	}
	return zvols, nil
}

func parseZVolLine(line string) (ZVol, error) {
	f := strings.Split(line, "\t")
	if len(f) < 11 {
		return ZVol{}, fmt.Errorf("unexpected zvol output: %q", line)
	}
	name := f[0]
	size, _ := strconv.ParseUint(f[1], 10, 64)
	used, _ := strconv.ParseUint(f[2], 10, 64)
	refer, _ := strconv.ParseUint(f[3], 10, 64)
	compression := f[4]
	compRatio := f[5]
	sync := f[6]
	dedup := f[7]
	volBlockSize := f[8]
	encrypted := f[9] != "off" && f[9] != "-"
	comment := f[10]
	if comment == "-" {
		comment = ""
	}
	var refreservation uint64
	if len(f) >= 12 {
		refreservation, _ = strconv.ParseUint(f[11], 10, 64)
	}
	var creation int64
	if len(f) >= 13 {
		creation, _ = strconv.ParseInt(f[12], 10, 64) // -p prints unix seconds
	}
	pool := strings.SplitN(name, "/", 2)[0]
	return ZVol{
		Name:           name,
		Pool:           pool,
		Size:           size,
		Used:           used,
		Refer:          refer,
		Refreservation: refreservation,
		Compression:    compression,
		CompRatio:      compRatio,
		Sync:           sync,
		Dedup:          dedup,
		VolBlockSize:   volBlockSize,
		Encrypted:      encrypted,
		Comment:        comment,
		DevPath:        "/dev/zvol/" + name,
		Creation:       creation,
	}, nil
}

// parseVolSizeBytes parses a human size string like "10G", "500M", "2T", "100K"
// into bytes. Case-insensitive suffix; no suffix = bytes.
func parseVolSizeBytes(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size string")
	}
	suffixes := map[byte]uint64{
		'K': 1 << 10, 'k': 1 << 10,
		'M': 1 << 20, 'm': 1 << 20,
		'G': 1 << 30, 'g': 1 << 30,
		'T': 1 << 40, 't': 1 << 40,
		'P': 1 << 50, 'p': 1 << 50,
	}
	last := s[len(s)-1]
	if mult, ok := suffixes[last]; ok {
		n, err := strconv.ParseUint(s[:len(s)-1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid size %q: %w", s, err)
		}
		return n * mult, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

// CreateZVol creates a new ZFS volume with the given options.
func CreateZVol(req ZVolCreateRequest) error {
	fullName := req.Parent + "/" + req.Name
	args := []string{"zfs", "create", "-V", req.Size}
	if req.KeyFilePath != "" {
		args = append(args,
			"-o", "encryption=aes-256-gcm",
			"-o", "keyformat=raw",
			"-o", "keylocation=file://"+req.KeyFilePath,
		)
	}
	// Do NOT set refreservation during create — ZFS computes it before all
	// properties (block size, compression) are resolved, which can over-estimate
	// the required space and fail with ENOSPC even when the pool has room.
	// We apply refreservation in a separate "zfs set" after creation.
	if req.Compression != "" && req.Compression != "inherit" {
		args = append(args, "-o", "compression="+zfsNormalizeCompression(req.Compression))
	}
	if req.Sync != "" && req.Sync != "inherit" {
		args = append(args, "-o", "sync="+req.Sync)
	}
	if req.Dedup != "" && req.Dedup != "inherit" {
		args = append(args, "-o", "dedup="+req.Dedup)
	}
	if req.BlockSize != "" && req.BlockSize != "inherit" {
		args = append(args, "-o", "volblocksize="+req.BlockSize)
	}
	args = append(args, fullName)
	debugLog("zfs create zvol: %v", args)
	out, err := exec.Command("sudo", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}

	// Apply refreservation after creation so ZFS has the final block size and
	// compression settings when computing the reservation value.
	var refreservation string
	switch req.Provisioning {
	case "thick":
		refreservation = "auto"
	case "thin":
		refreservation = "none"
	case "25", "50", "75":
		if sizeBytes, err := parseVolSizeBytes(req.Size); err == nil && sizeBytes > 0 {
			pct, _ := strconv.ParseUint(req.Provisioning, 10, 64)
			refreservation = fmt.Sprintf("%d", sizeBytes*pct/100)
		}
	}
	if refreservation != "" {
		if out, serr := exec.Command("sudo", "zfs", "set", "refreservation="+refreservation, fullName).CombinedOutput(); serr != nil {
			// Best-effort: log but don't fail the whole creation.
			debugLog("zvol set refreservation=%s failed: %v: %s", refreservation, serr, strings.TrimSpace(string(out)))
		}
	}

	if req.Comment != "" {
		if serr := SetDatasetProps(fullName, map[string]string{"zfsnas:comment": req.Comment}); serr != nil {
			debugLog("zvol set comment failed: %v", serr)
		}
	}
	return nil
}

// zfsNormalizeCompression maps the UI's "none" sentinel to ZFS's actual
// no-compression value ("off"). ZFS has no "none" compression value, so passing
// it through makes `zfs create/set compression=none` fail with
// "'compression' must be one of 'on | off | lzjb | gzip | …'".
func zfsNormalizeCompression(c string) string {
	if c == "none" {
		return "off"
	}
	return c
}

// EditZVol updates mutable properties on an existing ZVol.
func EditZVol(req ZVolEditRequest) error {
	props := map[string]string{}
	if req.Compression != "" {
		props["compression"] = zfsNormalizeCompression(req.Compression)
	}
	if req.Sync != "" {
		props["sync"] = req.Sync
	}
	if req.Dedup != "" {
		props["dedup"] = req.Dedup
	}
	// Provisioning → refreservation
	switch req.Provisioning {
	case "thick":
		props["refreservation"] = "auto"
	case "thin":
		props["refreservation"] = "none"
	case "25", "50", "75":
		if req.VolSizeBytes > 0 {
			pct, _ := strconv.ParseUint(req.Provisioning, 10, 64)
			props["refreservation"] = fmt.Sprintf("%d", req.VolSizeBytes*pct/100)
		}
	}
	// Grow the volume if a larger size was requested. ZFS rejects shrinks.
	if req.NewVolSizeBytes > 0 && req.NewVolSizeBytes >= req.VolSizeBytes {
		props["volsize"] = fmt.Sprintf("%d", req.NewVolSizeBytes)
	}
	// Comment: always include it (empty string → inherit/clear via SetDatasetProps).
	props["zfsnas:comment"] = strings.TrimSpace(req.Comment)
	return SetDatasetProps(req.Name, props)
}

// DeleteZVol destroys a ZVol and all its snapshots.
func DeleteZVol(name string) error {
	out, err := exec.Command("sudo", "zfs", "destroy", "-r", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// DeleteZVolForce destroys a ZVol using "zfs destroy -Rf": -R also removes any
// clones; -f releases the device if it is currently held open. Used by the UI
// after a regular delete fails (e.g. an LXD instance still has the zvol attached).
func DeleteZVolForce(name string) error {
	out, err := exec.Command("sudo", "zfs", "destroy", "-Rf", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}
