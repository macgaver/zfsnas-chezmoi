package system

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CPU category constants (used both for the snapshot and frontend coloring).
const (
	CpuCatSMB       = "smb"
	CpuCatNFS       = "nfs"
	CpuCatZFS       = "zfs"
	CpuCatMinIO     = "minio"
	CpuCatISCSI     = "iscsi"
	CpuCatVM        = "vm"
	CpuCatContainer = "container"
	CpuCatOther     = "other"
)

// ProcCPUInfo is a single process CPU entry.
type ProcCPUInfo struct {
	PID      int     `json:"pid"`
	Name     string  `json:"name"`
	Cmd      string  `json:"cmd"`  // full command line from /proc/[pid]/cmdline
	CpuPct   float64 `json:"cpu_pct"`
	Category string  `json:"category"`
}

// CpuProcsSnapshot is the full snapshot returned by the API.
type CpuProcsSnapshot struct {
	SmbPct       float64       `json:"smb_pct"`
	NfsPct       float64       `json:"nfs_pct"`
	ZfsPct       float64       `json:"zfs_pct"`
	MinioPct     float64       `json:"minio_pct"`
	ISCSIPct     float64       `json:"iscsi_pct"`
	VMPct        float64       `json:"vm_pct"`
	ContainerPct float64       `json:"container_pct"`
	OtherPct     float64       `json:"other_pct"`
	TopProcs     []ProcCPUInfo `json:"top_procs"`
	At           time.Time     `json:"at"`
}

var (
	cpuProcsMu     sync.RWMutex
	cpuProcsLatest *CpuProcsSnapshot
	cpuProcsPrev   map[int]uint64 // pid → prev (utime+stime) ticks
	cpuTotalPrev   uint64
)

// GetCpuProcsSnapshot returns the latest CPU process snapshot (nil until first sample).
func GetCpuProcsSnapshot() *CpuProcsSnapshot {
	cpuProcsMu.RLock()
	defer cpuProcsMu.RUnlock()
	return cpuProcsLatest
}

// StartCpuProcsPoller samples per-process CPU usage every 3 s.
func StartCpuProcsPoller() {
	cpuProcsPrev = make(map[int]uint64)
	go func() {
		tick := time.NewTicker(3 * time.Second)
		defer tick.Stop()
		for range tick.C {
			snap := sampleCpuProcs()
			if snap != nil {
				cpuProcsMu.Lock()
				cpuProcsLatest = snap
				cpuProcsMu.Unlock()
			}
		}
	}()
}

func sampleCpuProcs() *CpuProcsSnapshot {
	totalTicks, err := readTotalCPUTicks()
	if err != nil {
		return nil
	}

	procDir, err := os.Open("/proc")
	if err != nil {
		return nil
	}
	entries, err := procDir.ReadDir(-1)
	procDir.Close()
	if err != nil {
		return nil
	}

	type procSample struct {
		pid   int
		name  string
		ticks uint64
	}

	var samples []procSample
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		name, ticks, err := readProcStat(pid)
		if err != nil {
			continue
		}
		samples = append(samples, procSample{pid: pid, name: name, ticks: ticks})
	}

	// Compute total CPU delta
	var deltaTotalTicks uint64
	if cpuTotalPrev > 0 && totalTicks > cpuTotalPrev {
		deltaTotalTicks = totalTicks - cpuTotalPrev
	}
	cpuTotalPrev = totalTicks

	if deltaTotalTicks == 0 {
		return nil
	}

	type procResult struct {
		pid      int
		name     string
		cpuPct   float64
		category string
	}

	newPrev := make(map[int]uint64, len(samples))
	var results []procResult

	for _, s := range samples {
		newPrev[s.pid] = s.ticks
		prev, hasPrev := cpuProcsPrev[s.pid]
		if !hasPrev || s.ticks < prev {
			continue
		}
		delta := s.ticks - prev
		if delta == 0 {
			continue
		}
		pct := float64(delta) / float64(deltaTotalTicks) * 100.0
		if pct < 0.05 {
			continue
		}
		results = append(results, procResult{
			pid:      s.pid,
			name:     s.name,
			cpuPct:   pct,
			category: categorizeProc(s.pid, s.name),
		})
	}
	cpuProcsPrev = newPrev

	// Sort by CPU descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].cpuPct > results[j].cpuPct
	})

	// Aggregate by category
	catPct := map[string]float64{
		CpuCatSMB:       0,
		CpuCatNFS:       0,
		CpuCatZFS:       0,
		CpuCatMinIO:     0,
		CpuCatISCSI:     0,
		CpuCatVM:        0,
		CpuCatContainer: 0,
		CpuCatOther:     0,
	}
	for _, r := range results {
		catPct[r.category] += r.cpuPct
	}

	// Cap total at 100% (can slightly exceed on multi-core with short samples)
	total := catPct[CpuCatSMB] + catPct[CpuCatNFS] + catPct[CpuCatZFS] + catPct[CpuCatMinIO] + catPct[CpuCatISCSI] + catPct[CpuCatVM] + catPct[CpuCatContainer] + catPct[CpuCatOther]
	if total > 100 {
		scale := 100.0 / total
		for k := range catPct {
			catPct[k] *= scale
		}
		for i := range results {
			results[i].cpuPct *= scale
		}
	}

	// Top 10 processes
	top := results
	if len(top) > 10 {
		top = top[:10]
	}
	topProcs := make([]ProcCPUInfo, len(top))
	for i, r := range top {
		topProcs[i] = ProcCPUInfo{
			PID:      r.pid,
			Name:     r.name,
			Cmd:      readProcCmdline(r.pid),
			CpuPct:   r.cpuPct,
			Category: r.category,
		}
	}

	return &CpuProcsSnapshot{
		SmbPct:       catPct[CpuCatSMB],
		NfsPct:       catPct[CpuCatNFS],
		ZfsPct:       catPct[CpuCatZFS],
		MinioPct:     catPct[CpuCatMinIO],
		ISCSIPct:     catPct[CpuCatISCSI],
		VMPct:        catPct[CpuCatVM],
		ContainerPct: catPct[CpuCatContainer],
		OtherPct:     catPct[CpuCatOther],
		TopProcs:     topProcs,
		At:           time.Now(),
	}
}

// readTotalCPUTicks reads the aggregate CPU tick count from /proc/stat.
func readTotalCPUTicks() (uint64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return 0, fmt.Errorf("unexpected /proc/stat format")
		}
		var total uint64
		for _, f := range fields[1:] {
			v, _ := strconv.ParseUint(f, 10, 64)
			total += v
		}
		return total, nil
	}
	return 0, fmt.Errorf("no cpu line in /proc/stat")
}

// readProcStat reads name and (utime+stime) ticks for a process.
// The /proc/[pid]/stat format puts the process name between the first '(' and last ')'
// to handle parentheses in the name itself.
func readProcStat(pid int) (name string, ticks uint64, err error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", 0, err
	}
	s := string(data)
	start := strings.Index(s, "(")
	end := strings.LastIndex(s, ")")
	if start < 0 || end < 0 || end <= start {
		return "", 0, fmt.Errorf("stat parse error for pid %d", pid)
	}
	name = s[start+1 : end]
	rest := strings.TrimSpace(s[end+1:])
	fields := strings.Fields(rest)
	// After ')': state(0) ppid(1) pgrp(2) session(3) tty(4) tpgid(5) flags(6)
	//             minflt(7) cminflt(8) majflt(9) cmajflt(10) utime(11) stime(12)
	if len(fields) < 13 {
		return name, 0, nil
	}
	utime, _ := strconv.ParseUint(fields[11], 10, 64)
	stime, _ := strconv.ParseUint(fields[12], 10, 64)
	return name, utime + stime, nil
}

// readProcCmdline reads the full command line from /proc/[pid]/cmdline.
// Arguments are NUL-separated; we join them with spaces and cap at 200 chars.
// Falls back to the empty string if the file is unreadable (kernel threads have empty cmdline).
func readProcCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return ""
	}
	// Replace NUL bytes with spaces
	for i, b := range data {
		if b == 0 {
			data[i] = ' '
		}
	}
	s := strings.TrimSpace(string(data))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// categorizeProc maps a process (by pid + name) to a CPU/memory category.
// It first checks by process name for well-known services, then falls back
// to cgroup inspection for LXD VMs (qemu) and containers.
func categorizeProc(pid int, name string) string {
	lower := strings.ToLower(name)

	// ── VMs: QEMU processes spawned by LXD ───────────────────────────────────
	if strings.HasPrefix(lower, "qemu-system-") || lower == "qemu-kvm" || lower == "qemu" {
		return CpuCatVM
	}

	// ── Name-based service categories ────────────────────────────────────────
	if cat := categorizeProcName(lower); cat != CpuCatOther {
		return cat
	}

	// ── Cgroup check: LXD containers ─────────────────────────────────────────
	if isLXDContainerProc(pid) {
		return CpuCatContainer
	}

	return CpuCatOther
}

// isLXDContainerProc returns true if the process's cgroup path indicates it
// runs inside an LXD container (cgroup path contains "lxc.payload").
func isLXDContainerProc(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "lxc.payload")
}

// categorizeProcName maps a lower-cased process name to a service category,
// returning CpuCatOther for unknown processes.
func categorizeProcName(lower string) string {
	switch {

	// ── SMB / Samba ─────────────────────────────────────────────────────────
	case strings.HasPrefix(lower, "smbd") ||
		strings.HasPrefix(lower, "nmbd") ||
		strings.HasPrefix(lower, "winbind") ||
		strings.HasPrefix(lower, "wb[") ||
		lower == "samba" ||
		strings.HasPrefix(lower, "samba-") ||
		strings.HasPrefix(lower, "rpcd_"):
		return CpuCatSMB

	// ── NFS ──────────────────────────────────────────────────────────────────
	case strings.HasPrefix(lower, "nfsd") ||
		lower == "rpc.mountd" || lower == "rpc.statd" || lower == "rpc.idmapd" ||
		lower == "rpc.gssd" || lower == "rpc.svcgssd" ||
		lower == "rpciod" || lower == "rpcbind" ||
		lower == "lockd" || lower == "nfsdcld" || lower == "blkmapd" ||
		lower == "nfsv4.1-svc":
		return CpuCatNFS

	// ── ZFS / OpenZFS / SPL ──────────────────────────────────────────────────
	case strings.HasPrefix(lower, "z_") ||
		lower == "zed" || lower == "zpool" || lower == "zfs" ||
		strings.HasPrefix(lower, "spa_") ||
		strings.HasPrefix(lower, "arc_") ||
		lower == "txg_sync" || lower == "txg_quiesce" ||
		lower == "l2arc_feed" ||
		strings.HasPrefix(lower, "zvol") ||
		lower == "zio_taskq" || lower == "zil_clean" ||
		strings.HasPrefix(lower, "dbuf_") || strings.HasPrefix(lower, "dbu_") ||
		strings.HasPrefix(lower, "dp_") ||
		strings.HasPrefix(lower, "spl_") ||
		lower == "mmp" || lower == "fsidd" || lower == "raidz_expand":
		return CpuCatZFS

	// ── MinIO (S3 object storage) ────────────────────────────────────────────
	case lower == "minio" || lower == "rustfs":
		return CpuCatMinIO

	// ── iSCSI ────────────────────────────────────────────────────────────────
	case strings.HasPrefix(lower, "iscsi") ||
		lower == "iscsiuio" || lower == "tgtd" ||
		strings.HasPrefix(lower, "lio_") ||
		lower == "targetcli":
		return CpuCatISCSI

	default:
		return CpuCatOther
	}
}
