package system

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ARCStats holds the current ARC (Adaptive Replacement Cache) statistics
// and tunable parameters read from the kernel.
type ARCStats struct {
	// Current sizes (bytes)
	ARCSize       int64 `json:"arc_size"`
	ARCMin        int64 `json:"arc_min"`
	ARCMax        int64 `json:"arc_max"`
	ARCTarget     int64 `json:"arc_target"`
	ARCMetaUsed   int64 `json:"arc_meta_used"`
	ARCMetaLimit  int64 `json:"arc_meta_limit"`
	ARCMetaMax    int64 `json:"arc_meta_max"`
	MFUSize       int64 `json:"mfu_size"`
	MRUSize       int64 `json:"mru_size"`

	// Hit/miss counters
	Hits             int64   `json:"hits"`
	Misses           int64   `json:"misses"`
	HitRatio         float64 `json:"hit_ratio"`
	DemandDataHits   int64   `json:"demand_data_hits"`
	DemandMetaHits   int64   `json:"demand_meta_hits"`
	PrefetchDataHits int64   `json:"prefetch_data_hits"`

	// Eviction counters
	EvictedMFU int64 `json:"evicted_mfu"`
	EvictedMRU int64 `json:"evicted_mru"`

	// L2ARC counters
	L2Hits   int64 `json:"l2_hits"`
	L2Misses int64 `json:"l2_misses"`
	L2Size   int64 `json:"l2_size"`

	// Tunable kernel parameters (from /sys/module/zfs/parameters/)
	ParamARCMax int64 `json:"param_arc_max"`
	ParamARCMin int64 `json:"param_arc_min"`

	// Total system RAM in bytes (from /proc/meminfo MemTotal)
	TotalRAMBytes int64 `json:"total_ram_bytes"`

	// Why the ARC can sit above its maximum (see ARCPressure).
	Pressure ARCPressure `json:"pressure"`
}

// ARCPressure explains an ARC that sits above zfs_arc_max, and what to set
// instead. zfs_arc_max is a SOFT limit: ZFS can only evict what nothing else
// holds, and every file Linux keeps in its inode cache pins that file's ZFS
// metadata (dnode, bonus buffer, dbufs) in the ARC. A workload that touches
// millions of files (build servers, Docker image layers, mail stores) keeps
// the ARC well above a small maximum, and ZFS burns CPU in arc_evict trying
// to get back under it.
type ARCPressure struct {
	DataBytes        int64   `json:"data_bytes"`        // cached file data
	MetadataBytes    int64   `json:"metadata_bytes"`    // all metadata (arc_meta_used)
	DnodeBytes       int64   `json:"dnode_bytes"`       // per-file dnodes
	BonusBytes       int64   `json:"bonus_bytes"`       // per-file bonus buffers (attributes)
	DbufBytes        int64   `json:"dbuf_bytes"`        // dbuf headers
	EvictableBytes   int64   `json:"evictable_bytes"`   // what ZFS could free right now
	CachedInodes     int64   `json:"cached_inodes"`     // inodes Linux keeps cached (all filesystems)
	CachedDentries   int64   `json:"cached_dentries"`   // directory entries cached
	UnusedDentries   int64   `json:"unused_dentries"`   // of which nothing uses them
	BytesPerFile     int64   `json:"bytes_per_file"`    // ARC metadata held per cached file
	EvictCPUSeconds  float64 `json:"evict_cpu_seconds"` // CPU used by arc_evict since boot
	UptimeSeconds    float64 `json:"uptime_seconds"`
	VFSCachePressure int     `json:"vfs_cache_pressure"`
	// Status: "ok" (within the maximum), "over" (above it, mostly pinned
	// metadata), "default" (no maximum set by ZNAS: kernel managed).
	Status string `json:"status"`
	// RecommendedMax is a maximum that fits what this workload pins, rounded
	// up to 512 MiB (0 when the current maximum is fine). RecommendedCapped
	// is true when the need is above half the RAM and the figure was capped.
	RecommendedMax    int64 `json:"recommended_max"`
	RecommendedCapped bool  `json:"recommended_capped"`
}

const arcStatsPath = "/proc/spl/kstat/zfs/arcstats"
const arcParamDir  = "/sys/module/zfs/parameters/"
const modprobePath = "/etc/modprobe.d/zfs.conf"

// GetARCStats reads /proc/spl/kstat/zfs/arcstats and kernel sysfs parameters,
// returning a populated ARCStats struct.
func GetARCStats() (*ARCStats, error) {
	kstat, err := readKstat(arcStatsPath)
	if err != nil {
		return nil, fmt.Errorf("read arcstats: %w", err)
	}

	s := &ARCStats{}

	s.ARCSize      = kstatInt(kstat, "size")
	s.ARCMin       = kstatInt(kstat, "c_min")
	s.ARCMax       = kstatInt(kstat, "c_max")
	s.ARCTarget    = kstatInt(kstat, "c")
	s.ARCMetaUsed  = kstatInt(kstat, "arc_meta_used")
	s.ARCMetaLimit = kstatInt(kstat, "arc_meta_limit")
	s.ARCMetaMax   = kstatInt(kstat, "arc_meta_max")
	s.MFUSize      = kstatInt(kstat, "mfu_size")
	s.MRUSize      = kstatInt(kstat, "mru_size")

	s.Hits             = kstatInt(kstat, "hits")
	s.Misses           = kstatInt(kstat, "misses")
	s.DemandDataHits   = kstatInt(kstat, "demand_data_hits")
	s.DemandMetaHits   = kstatInt(kstat, "demand_metadata_hits")
	s.PrefetchDataHits = kstatInt(kstat, "prefetch_data_hits")

	s.EvictedMFU = kstatInt(kstat, "mfu_ghost_hits")
	s.EvictedMRU = kstatInt(kstat, "mru_ghost_hits")

	s.L2Hits   = kstatInt(kstat, "l2_hits")
	s.L2Misses = kstatInt(kstat, "l2_misses")
	s.L2Size   = kstatInt(kstat, "l2_size")

	total := s.Hits + s.Misses
	if total > 0 {
		s.HitRatio = float64(s.Hits) / float64(total) * 100
	}

	// Read kernel tunable parameters.
	s.ParamARCMax = readSysfsInt64(arcParamDir + "zfs_arc_max")
	s.ParamARCMin = readSysfsInt64(arcParamDir + "zfs_arc_min")

	// If sysfs params are 0 (not overridden), fall back to the live ARC value.
	if s.ParamARCMax == 0 {
		s.ParamARCMax = s.ARCMax
	}
	if s.ParamARCMin == 0 {
		s.ParamARCMin = s.ARCMin
	}

	// Read total system RAM from /proc/meminfo for percentage calculations.
	if totalKB, _, err := readMemInfo(); err == nil && totalKB > 0 {
		s.TotalRAMBytes = int64(totalKB) * 1024
	}

	p := &s.Pressure
	p.DataBytes = kstatInt(kstat, "data_size")
	p.MetadataBytes = s.ARCMetaUsed
	p.DnodeBytes = kstatInt(kstat, "dnode_size")
	p.BonusBytes = kstatInt(kstat, "bonus_size")
	p.DbufBytes = kstatInt(kstat, "dbuf_size")
	p.EvictableBytes = kstatInt(kstat, "mru_evictable_data") + kstatInt(kstat, "mru_evictable_metadata") +
		kstatInt(kstat, "mfu_evictable_data") + kstatInt(kstat, "mfu_evictable_metadata")
	p.CachedInodes = firstProcInt("/proc/sys/fs/inode-nr", 0)
	p.CachedDentries = firstProcInt("/proc/sys/fs/dentry-state", 0)
	p.UnusedDentries = firstProcInt("/proc/sys/fs/dentry-state", 1)
	p.VFSCachePressure = int(firstProcInt("/proc/sys/vm/vfs_cache_pressure", 0))
	p.EvictCPUSeconds = kernelThreadCPUSeconds("arc_evict")
	if up := firstProcFloat("/proc/uptime"); up > 0 {
		p.UptimeSeconds = up
	}
	explainARCPressure(s, s.ParamARCMax > 0 && readSysfsInt64(arcParamDir+"zfs_arc_max") > 0)
	return s, nil
}

// explainARCPressure fills Status, BytesPerFile and the recommendation from
// the raw figures. Pure, so it is unit-tested with the numbers seen live.
func explainARCPressure(s *ARCStats, maxSet bool) {
	p := &s.Pressure
	const mib = int64(1) << 20
	pinnedMeta := p.MetadataBytes
	if p.CachedInodes > 1000 && pinnedMeta > 0 {
		p.BytesPerFile = pinnedMeta / p.CachedInodes
	}
	switch {
	case !maxSet:
		p.Status = "default"
	case s.ARCMax > 0 && s.ARCSize > s.ARCMax+s.ARCMax/10:
		p.Status = "over"
	default:
		p.Status = "ok"
	}
	if p.Status != "over" {
		return
	}
	// What the workload needs: the metadata it pins, plus room for file data
	// (what is cached now, at least 512 MiB), with 20% headroom.
	data := p.DataBytes
	if data < 512*mib {
		data = 512 * mib
	}
	need := (pinnedMeta + data) * 12 / 10
	rec := (need + 512*mib - 1) / (512 * mib) * (512 * mib)
	if half := s.TotalRAMBytes / 2; half > 0 && rec > half {
		rec = half / (512 * mib) * (512 * mib)
		p.RecommendedCapped = true
	}
	if rec > s.ARCMax {
		p.RecommendedMax = rec
	}
}

// firstProcInt reads the idx-th whitespace-separated integer of a /proc file.
func firstProcInt(path string, idx int) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if idx >= len(f) {
		return 0
	}
	n, _ := strconv.ParseInt(f[idx], 10, 64)
	return n
}

func firstProcFloat(path string) float64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

// kernelThreadCPUSeconds sums utime+stime of the kernel threads named comm
// (e.g. arc_evict) from /proc/<pid>/stat. Kernel threads are children of
// kthreadd (pid 2), so only those are opened.
func kernelThreadCPUSeconds(comm string) float64 {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	var ticks int64
	for _, e := range ents {
		pid := e.Name()
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}
		b, err := os.ReadFile("/proc/" + pid + "/stat")
		if err != nil {
			continue
		}
		st := string(b)
		open, close := strings.IndexByte(st, '('), strings.LastIndexByte(st, ')')
		if open < 0 || close < open || st[open+1:close] != comm {
			continue
		}
		f := strings.Fields(st[close+1:])
		// After the comm: state(0) ppid(1) … utime(11) stime(12).
		if len(f) > 12 && f[1] == "2" {
			u, _ := strconv.ParseInt(f[11], 10, 64)
			k, _ := strconv.ParseInt(f[12], 10, 64)
			ticks += u + k
		}
	}
	return float64(ticks) / 100 // USER_HZ is 100 on Linux
}

// SetARCParams applies new ARC size limits immediately via sysfs and persists
// them across reboots by writing /etc/modprobe.d/zfs.conf.
//
// arcMax and arcMin are in bytes; pass 0 to leave a parameter unchanged.
func SetARCParams(arcMax, arcMin int64) error {
	if arcMax != 0 {
		if err := writeSysfsInt64(arcParamDir+"zfs_arc_max", arcMax); err != nil {
			return fmt.Errorf("set zfs_arc_max: %w", err)
		}
	}
	if arcMin != 0 {
		if err := writeSysfsInt64(arcParamDir+"zfs_arc_min", arcMin); err != nil {
			return fmt.Errorf("set zfs_arc_min: %w", err)
		}
	}
	return persistARCModprobe(arcMax, arcMin)
}

// persistARCModprobe writes (or updates) the ZFSNAS-managed block in
// /etc/modprobe.d/zfs.conf so that ARC parameters survive a reboot.
func persistARCModprobe(arcMax, arcMin int64) error {
	const begin = "# BEGIN ZFSNAS ARC"
	const end   = "# END ZFSNAS ARC"

	// Read the current file (if it exists).
	existing, err := os.ReadFile(modprobePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", modprobePath, err)
	}

	// Strip the existing managed block if present.
	content := string(existing)
	if i := strings.Index(content, begin); i >= 0 {
		if j := strings.Index(content, end); j >= 0 {
			content = content[:i] + content[j+len(end):]
			content = strings.TrimRight(content, "\n") + "\n"
		}
	}

	// Build the new managed block.
	var block strings.Builder
	block.WriteString(begin + "\n")
	if arcMax != 0 {
		block.WriteString(fmt.Sprintf("options zfs zfs_arc_max=%d\n", arcMax))
	}
	if arcMin != 0 {
		block.WriteString(fmt.Sprintf("options zfs zfs_arc_min=%d\n", arcMin))
	}
	block.WriteString(end + "\n")

	content = strings.TrimRight(content, "\n") + "\n" + block.String()

	// Write via sudo tee since /etc/modprobe.d/ requires root.
	cmd := exec.Command("sudo", "tee", modprobePath)
	cmd.Stdin = bytes.NewBufferString(content)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("write %s: %w: %s", modprobePath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// readKstat parses a Linux kstat file (3-column: name type value) into a map.
func readKstat(path string) (map[string]int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := make(map[string]int64)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Skip header lines.
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "name") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		v, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			continue
		}
		m[parts[0]] = v
	}
	return m, scanner.Err()
}

func kstatInt(m map[string]int64, key string) int64 {
	return m[key]
}

func readSysfsInt64(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func writeSysfsInt64(path string, v int64) error {
	// sysfs requires root; pipe through sudo tee.
	cmd := exec.Command("sudo", "tee", path)
	cmd.Stdin = bytes.NewBufferString(strconv.FormatInt(v, 10) + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
