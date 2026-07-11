package system

// LXD/Incus backup orchestration helpers (v6.5.19+).
//
// The handlers in handlers/lxd_backups.go drive the lifecycle; this file
// concentrates on the bits that touch the host (resolving Incus pool paths,
// invoking syncoid, applying retention on the destination snapshots, and
// triggering `incus admin recover` so a freshly received dataset is
// registered as a backup instance).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"
)

// LXDBackupSnapshotPrefix is the snapshot-name prefix written by both the
// scheduled-snapshot and the backup-fire codepaths. Kept aligned so the
// scheduled snapshot itself becomes the unit of replication; the user only
// sees one "auto-…" snapshot per fire on both source and destination.
const LXDBackupSnapshotPrefix = "auto"

// LXDBackupWorkloadMarker is the parent dataset name we create under any
// ZFS pool that hosts ZNAS-managed backups for an interlink peer (v6.5.19+).
// The full destination path on a peer is:
//
//	<peer-zfs-pool>/ZNAS-Backups-Workload/<kind>/bkup--<vm-id>
//
// (with `<kind>` = "virtual-machines" or "containers"). This layout means
// the destination peer does NOT need Incus installed — backups are plain
// ZFS datasets under a clearly-marked parent so they're easy to spot,
// audit, and prune. The Backups page and per-VM dropdown scan this path on
// every linked peer regardless of whether Incus is present there.
//
// Local-source same-host backups still use the Incus storage-pool layout
// because local code paths can rely on Incus being installed.
const LXDBackupWorkloadMarker = "ZNAS-Backups-Workload"

// LXDWorkloadBackupParent composes the parent dataset path for workload-
// style backups on a given ZFS pool. Returns "<pool>/ZNAS-Backups-Workload".
func LXDWorkloadBackupParent(zfsPool string) string {
	return zfsPool + "/" + LXDBackupWorkloadMarker
}

// LXDWorkloadBackupDataset composes the on-disk path for a backup's root-fs
// dataset under the workload layout.
func LXDWorkloadBackupDataset(zfsPool, kind, vm string) string {
	return LXDWorkloadBackupParent(zfsPool) + "/" + kind + "/" + LXDBackupPrefix + vm
}

// LXDInstanceKind returns "virtual-machines" or "containers" depending on
// the instance type. Used to compose the on-disk dataset path. Errors when
// the instance does not exist.
func LXDInstanceKind(name string) (string, error) {
	out, err := exec.Command("incus", "list", name, "--format", "json").Output()
	if err != nil {
		return "", fmt.Errorf("incus list %s: %w", name, err)
	}
	var raw []struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(out, &raw); err != nil || len(raw) == 0 {
		return "", fmt.Errorf("instance %s not found", name)
	}
	switch raw[0].Type {
	case "virtual-machine":
		return "virtual-machines", nil
	case "container":
		return "containers", nil
	}
	return "", fmt.Errorf("unknown instance type %q", raw[0].Type)
}

// LXDInstanceRootPool returns the Incus storage-pool name that backs the
// instance's root disk. "" means we couldn't determine it.
func LXDInstanceRootPool(name string) string {
	out, err := exec.Command("incus", "query", "/1.0/instances/"+name).Output()
	if err != nil {
		return ""
	}
	var info struct {
		ExpandedDevices map[string]map[string]string `json:"expanded_devices"`
	}
	if json.Unmarshal(out, &info) != nil {
		return ""
	}
	for _, dev := range info.ExpandedDevices {
		if dev["type"] == "disk" && dev["path"] == "/" {
			return dev["pool"]
		}
	}
	return ""
}

// LXDAllInstanceRootPools returns instanceName → root-disk storage-pool name
// for every instance, resolved from a single batched query (recursion=2 so the
// expanded_devices are included). Used by the storage Map to link each VM /
// container to the pool its disk actually lives on, rather than guessing.
func LXDAllInstanceRootPools() map[string]string {
	result := map[string]string{}
	out, err := exec.Command("incus", "query", "/1.0/instances?recursion=2").Output()
	if err != nil {
		return result
	}
	var arr []struct {
		Name            string                       `json:"name"`
		ExpandedDevices map[string]map[string]string `json:"expanded_devices"`
	}
	if json.Unmarshal(out, &arr) != nil {
		return result
	}
	for _, in := range arr {
		for _, dev := range in.ExpandedDevices {
			if dev["type"] == "disk" && dev["path"] == "/" {
				result[in.Name] = dev["pool"]
				break
			}
		}
	}
	return result
}

// LXDInstanceDisk is one disk device attached to an instance (from its
// expanded_devices), used by the Map to resolve each virtual disk to its zvol.
type LXDInstanceDisk struct {
	Device string `json:"device"`
	Pool   string `json:"pool"`
	Source string `json:"source"`
	Path   string `json:"path"`
}

// LXDAllInstanceDisks returns instanceName → its disk devices, from a single
// batched query (recursion=2).
func LXDAllInstanceDisks() map[string][]LXDInstanceDisk {
	res := map[string][]LXDInstanceDisk{}
	out, err := exec.Command("incus", "query", "/1.0/instances?recursion=2").Output()
	if err != nil {
		return res
	}
	var arr []struct {
		Name            string                       `json:"name"`
		ExpandedDevices map[string]map[string]string `json:"expanded_devices"`
	}
	if json.Unmarshal(out, &arr) != nil {
		return res
	}
	for _, in := range arr {
		for dev, d := range in.ExpandedDevices {
			if d["type"] == "disk" {
				res[in.Name] = append(res[in.Name], LXDInstanceDisk{
					Device: dev, Pool: d["pool"], Source: d["source"], Path: d["path"],
				})
			}
		}
	}
	return res
}

// LXDDiskUsage is the used/total of one filesystem inside an instance.
type LXDDiskUsage struct {
	Name  string `json:"name"`
	Usage uint64 `json:"usage"`
	Total uint64 `json:"total"`
}

// LXDInstanceMetrics holds live resource usage for one instance, used by the
// storage Map's hover popup.
type LXDInstanceMetrics struct {
	Name      string         `json:"name"`
	Running   bool           `json:"running"`
	CPUPct    float64        `json:"cpu_pct"`    // core-equivalent % (100 = one core)
	MemUsage  uint64         `json:"mem_usage"`
	MemTotal  uint64         `json:"mem_total"`
	Processes int            `json:"processes"`
	Disks     []LXDDiskUsage `json:"disks"`
}

type lxdInstState struct {
	Status string `json:"status"`
	CPU    struct {
		Usage int64 `json:"usage"`
	} `json:"cpu"`
	Memory struct {
		Usage uint64 `json:"usage"`
		Total uint64 `json:"total"`
	} `json:"memory"`
	Processes int `json:"processes"`
	Disk      map[string]struct {
		Usage uint64 `json:"usage"`
		Total uint64 `json:"total"`
	} `json:"disk"`
}

func lxdReadInstanceState(name string) (*lxdInstState, error) {
	out, err := exec.Command("incus", "query", "/1.0/instances/"+name+"/state").Output()
	if err != nil {
		return nil, err
	}
	var s lxdInstState
	if err := json.Unmarshal(out, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// LXDInstanceLiveMetrics samples the instance state twice (a short interval
// apart) so CPU usage can be turned into a live percentage; memory and
// per-filesystem usage are read from the second sample.
func LXDInstanceLiveMetrics(name string) (*LXDInstanceMetrics, error) {
	s1, err := lxdReadInstanceState(name)
	if err != nil {
		return nil, err
	}
	t0 := time.Now()
	time.Sleep(450 * time.Millisecond)
	s2, err := lxdReadInstanceState(name)
	if err != nil {
		return nil, err
	}
	m := &LXDInstanceMetrics{
		Name:      name,
		Running:   s2.Status == "Running",
		MemUsage:  s2.Memory.Usage,
		MemTotal:  s2.Memory.Total,
		Processes: s2.Processes,
	}
	if dt := time.Since(t0).Seconds(); dt > 0 && s2.CPU.Usage >= s1.CPU.Usage {
		m.CPUPct = float64(s2.CPU.Usage-s1.CPU.Usage) / 1e9 / dt * 100
	}
	for dev, du := range s2.Disk {
		m.Disks = append(m.Disks, LXDDiskUsage{Name: dev, Usage: du.Usage, Total: du.Total})
	}
	sort.Slice(m.Disks, func(i, j int) bool { return m.Disks[i].Name < m.Disks[j].Name })
	return m, nil
}

// LXDInstanceDataset returns the ZFS dataset path backing the instance's
// root filesystem on this host, or "" when it cannot be resolved (pool
// missing, non-zfs backend, etc.).
//
//	<pool-source>/<kind>/<name>
//
// Example:    NVMEPool/lxd-base/virtual-machines/ubuntu1
//
// IMPORTANT: for VMs this dataset is mostly empty — the actual disk lives
// in a SIBLING zvol named "<name>.block". Use LXDInstanceBackupDatasets
// when you need the full set of datasets that must be replicated together.
func LXDInstanceDataset(name string) (string, error) {
	pool := LXDInstanceRootPool(name)
	if pool == "" {
		return "", fmt.Errorf("could not determine root pool for %s", name)
	}
	src := getLXDPoolSource(pool)
	if src == "" {
		return "", fmt.Errorf("storage pool %s has no zfs source", pool)
	}
	kind, err := LXDInstanceKind(name)
	if err != nil {
		return "", err
	}
	return src + "/" + kind + "/" + name, nil
}

// LXDInstanceDiskPart describes one source dataset that participates in a
// backup of an instance — and the corresponding destination-side basename
// (last path component) where it should land. The destination prefix is
// computed by the backup orchestrator (local vs remote / source layout)
// and prepended to DstBaseName.
type LXDInstanceDiskPart struct {
	// SrcDataset is the absolute source ZFS dataset path on this host.
	SrcDataset string
	// DstBaseName is the basename for the destination side (e.g.
	// "bkup--<vm-id>" or "bkup--<vm-id>.block"). The caller composes the
	// full destination path: `<dst-source>/<kind>/<DstBaseName>`.
	DstBaseName string
	// Recursive controls whether syncoid sends children recursively.
	Recursive bool
	// Kind is the disk category for logging only:
	//   "root-fs"  filesystem dataset for the instance (mostly empty for VMs)
	//   "root-blk" the ".block" zvol for VM root disks
	//   "custom"   an attached custom-volume disk device
	Kind string
}

// LXDInstanceBackupDatasets enumerates every ZFS dataset that must be
// replicated to fully back up an instance. For a typical VM this returns
// two entries (the root filesystem dataset and the root .block zvol); for
// a container it returns one (the root filesystem dataset, recursive).
//
// Custom-volume disks attached to the instance are included so that a
// backup of "ubuntu1" with an extra 100 GiB data disk captures the data
// disk too. They are emitted under their own DstBaseName ("bkup--<vol>")
// so the orchestrator stages them alongside the root entry.
func LXDInstanceBackupDatasets(name string) ([]LXDInstanceDiskPart, error) {
	pool := LXDInstanceRootPool(name)
	if pool == "" {
		return nil, fmt.Errorf("could not determine root pool for %s", name)
	}
	src := getLXDPoolSource(pool)
	if src == "" {
		return nil, fmt.Errorf("storage pool %s has no zfs source", pool)
	}
	kind, err := LXDInstanceKind(name)
	if err != nil {
		return nil, err
	}
	parts := []LXDInstanceDiskPart{}

	// 1. Root filesystem dataset (always present).
	parts = append(parts, LXDInstanceDiskPart{
		SrcDataset:  src + "/" + kind + "/" + name,
		DstBaseName: LXDBackupPrefix + name,
		Recursive:   true,
		Kind:        "root-fs",
	})
	// 2. For VMs, the actual block storage lives in a SIBLING zvol named
	//    "<name>.block". --recursive on the parent does NOT include
	//    siblings, so we must enumerate it explicitly. Verify the dataset
	//    exists before adding it (some Incus builds skip it for cdrom-
	//    only "VMs").
	if kind == "virtual-machines" {
		blockSrc := src + "/" + kind + "/" + name + ".block"
		if datasetExists(blockSrc) {
			parts = append(parts, LXDInstanceDiskPart{
				SrcDataset:  blockSrc,
				DstBaseName: LXDBackupPrefix + name + ".block",
				Recursive:   false,
				Kind:        "root-blk",
			})
		}
	}
	// 3. Attached custom volumes — additional disks the user added to the
	//    instance through the Edit modal. They are stored under
	//    "<pool>/custom/<vol>" and shared between instances by reference,
	//    so we replicate each one exactly once per backup fire.
	customs, _ := instanceCustomDiskSources(name)
	seen := map[string]bool{}
	for _, c := range customs {
		// Resolve the custom volume's host pool — disks can sit on a
		// pool different from the instance's root pool.
		cpoolSource := getLXDPoolSource(c.Pool)
		if cpoolSource == "" {
			continue
		}
		// Incus stores custom volumes as "<src>/custom/<project>_<volume>", so
		// resolve the real dataset — the old "<src>/custom/<volume>" guess
		// silently missed every volume in the (default) project, leaving
		// attached disks out of the backup entirely.
		fullSrc := resolveCustomVolDataset(cpoolSource, c.Volume)
		if fullSrc == "" || seen[fullSrc] {
			continue
		}
		seen[fullSrc] = true
		parts = append(parts, LXDInstanceDiskPart{
			SrcDataset:  fullSrc,
			DstBaseName: LXDBackupPrefix + name + "." + c.Volume,
			Recursive:   true,
			Kind:        "custom",
		})
	}
	return parts, nil
}

// instanceCustomDiskSource is one attached custom-volume disk device.
type instanceCustomDiskSource struct {
	Pool   string
	Volume string
}

func instanceCustomDiskSources(name string) ([]instanceCustomDiskSource, error) {
	out, err := exec.Command("incus", "query", "/1.0/instances/"+name).Output()
	if err != nil {
		return nil, err
	}
	var info struct {
		ExpandedDevices map[string]map[string]string `json:"expanded_devices"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, err
	}
	var res []instanceCustomDiskSource
	for _, dev := range info.ExpandedDevices {
		if dev["type"] != "disk" {
			continue
		}
		// Skip the root disk (path == "/"); it's covered by the root-fs
		// + root-blk entries already.
		if dev["path"] == "/" {
			continue
		}
		src := dev["source"]
		pool := dev["pool"]
		// Only custom volumes — a bare host path ("/mnt/...") is a
		// passthrough and is intentionally NOT replicated by backups.
		if pool == "" || src == "" || strings.HasPrefix(src, "/") {
			continue
		}
		res = append(res, instanceCustomDiskSource{Pool: pool, Volume: src})
	}
	return res, nil
}

func datasetExists(ds string) bool {
	return exec.Command("zfs", "list", "-H", "-o", "name", ds).Run() == nil
}

// resolveCustomVolDataset finds the actual ZFS dataset backing an Incus custom
// volume named `vol` on zfs source `src`. Incus names it
// "<src>/custom/<project>_<vol>" (project prefix), so try the exact path first
// then match a "<project>_<vol>" leaf under <src>/custom. Returns "" if none.
func resolveCustomVolDataset(src, vol string) string {
	if exact := src + "/custom/" + vol; datasetExists(exact) {
		return exact // some layouts have no project prefix
	}
	out, err := exec.Command("zfs", "list", "-Hp", "-t", "filesystem,volume", "-o", "name", "-r", src+"/custom").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		name := strings.TrimSpace(line)
		base := name[strings.LastIndex(name, "/")+1:]
		if base == vol || strings.HasSuffix(base, "_"+vol) {
			return name
		}
	}
	return ""
}

// datasetUsedBytes returns the ZFS `used` property of one dataset in bytes.
// `used` already accounts for that dataset's own snapshots, so this is the
// real on-disk footprint. Unreadable / missing dataset → 0.
func datasetUsedBytes(ds string) int64 {
	out, err := exec.Command("zfs", "get", "-Hp", "-o", "value", "used", ds).Output()
	if err != nil {
		return 0
	}
	var n int64
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &n)
	return n
}

// backupInstanceUsedBytes is the total on-disk size of a workload backup
// instance: the root dataset's `used` (including its snapshots) plus the
// `.block` sibling that VM backups keep beside the root-fs dataset. Summing
// per-snapshot `used` undercounts badly — the bulk of a received-only backup
// is referenced by the live filesystem, not attributed to any one snapshot —
// so this is what the Backups page shows as "Total Size".
func backupInstanceUsedBytes(dataset string) int64 {
	total := datasetUsedBytes(dataset)
	if block := dataset + ".block"; datasetExists(block) {
		total += datasetUsedBytes(block)
	}
	return total
}

// LXDBackupDestDataset composes the ZFS dataset path on the destination side
// for the backup of <vm>. `kind` is "virtual-machines" or "containers",
// `poolSource` is the ZFS source path of the destination Incus storage pool.
func LXDBackupDestDataset(poolSource, kind, vm string) string {
	return poolSource + "/" + kind + "/" + LXDBackupPrefix + vm
}

// LXDIncusAdminRecover triggers `incus admin recover` so a freshly received
// "bkup--<vm>" dataset on `poolName` is registered as a known Incus
// instance. Best-effort; the dataset is still readable via `zfs list` even
// when recovery fails.
//
// The wizard scans EVERY known pool's virtual-machines/ + containers/
// subdirs and refuses to proceed if any orphan dataset's backup.yaml is
// inconsistent with its current location. Our other bkup--<vm> datasets
// (which we deliberately leave self-inconsistent so we don't have to rewrite
// backup.yaml on every incremental fire) would block the scan. To work
// around this, hide every OTHER bkup--*/backup.yaml during the recover by
// renaming the file out of the way, then put it back.
//
// `restoreDataset` is the freshly-restored dataset that recover SHOULD see
// (e.g. "<pool>/<incus-dataset>/virtual-machines/clone-of-vm-1"). Its
// backup.yaml is kept in place.
func LXDIncusAdminRecover(poolName string) ([]byte, error) {
	return lxdIncusAdminRecoverInner("")
}

func lxdIncusAdminRecoverInner(keepDataset string) ([]byte, error) {
	// Temporarily zfs-rename every other bkup--<vm> dataset out of the
	// virtual-machines / containers subtrees so `incus admin recover`
	// only sees the freshly-restored clone target. `keepDataset` is the
	// path of the dataset that should remain in place.
	renamed := lxdMaskBackupDatasets(keepDataset)
	defer lxdUnmaskBackupDatasets(renamed)
	return lxdRunAdminRecover()
}

// lxdRunAdminRecover runs `incus admin recover` non-interactively: don't add
// another pool, do scan, do recover the found volumes, accept the default for
// anything else.
//
// A hard timeout guards against `incus admin recover` blocking forever on an
// UNANTICIPATED interactive prompt. We feed a fixed answer script
// ("no\nyes\nyes\n") for the three expected questions, but recover can ask more
// — e.g. when it scans a leftover dataset whose name encodes a project that no
// longer exists it prints "You are currently missing … Please create those
// missing entries and then hit ENTER:" and waits indefinitely. Without a
// timeout the restore job stays "running" forever with no error and the masked
// datasets are never restored (the deferred unmask can't run). The masking in
// LXDIncusAdminRecoverWithMask hides the known poison; this is the safety net
// for anything new. On timeout we SIGKILL the whole process group (sudo + the
// incus child) so nothing is left blocked on stdin.
func lxdRunAdminRecover() ([]byte, error) {
	cmd := exec.Command("sudo", "incus", "admin", "recover")
	cmd.Stdin = strings.NewReader("no\nyes\nyes\n\n")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return buf.Bytes(), err
	case <-time.After(5 * time.Minute):
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		<-done
		return buf.Bytes(), fmt.Errorf("incus admin recover timed out after 5m — it is likely blocked on an "+
			"unexpected interactive prompt (often a leftover/orphan dataset that references a deleted project); "+
			"aborted. Output: %s", strings.TrimSpace(buf.String()))
	}
}

// LXDIncusAdminRecoverWithMask is the restore-path recover. Beyond hiding other
// bkup--* datasets, it masks every UNREGISTERED instance dataset that isn't the
// restore target `targetName`. Without this, an orphan instance dataset left by
// a PRIOR failed restore (recover also tries to import every unknown volume it
// finds) can abort the whole recovery — e.g. an orphan whose custom-volume
// reference is missing fails with "Storage volume not found", taking the fresh
// clone down with it. After recover, every masked dataset is moved back.
func LXDIncusAdminRecoverWithMask(targetName string) ([]byte, error) {
	renamed := lxdMaskBackupDatasets("")
	renamed = append(renamed, lxdMaskNonTargetInstances(targetName)...)
	renamed = append(renamed, lxdMaskStagingLeftovers()...)
	defer lxdUnmaskBackupDatasets(renamed)
	return lxdRunAdminRecover()
}

// lxdMaskStagingLeftovers hides leftover "incoming-restore-*" staging datasets
// from a PRIOR aborted clone-restore so `incus admin recover` doesn't choke on
// them. A failed restore can leave a half-pulled custom volume named
//
//	<pool-src>/custom/incoming-restore-<project>_<volume>
//
// recover then parses "incoming-restore-<project>" as a project that doesn't
// exist and BLOCKS forever on an interactive "Please create those missing
// entries and then hit ENTER:" prompt (observed on Incus 6.0.5). The live
// restore renames its OWN staging datasets to their final names before recover
// runs, so any dataset still carrying the "incoming-restore-" prefix at this
// point is garbage from a different, aborted run and is always safe to hide.
// Masked datasets are moved back by the deferred lxdUnmaskBackupDatasets.
func lxdMaskStagingLeftovers() []lxdMaskRename {
	const stagingPrefix = "incoming-restore-"
	var moves []lxdMaskRename
	pools, _ := LXDListStoragePools()
	seen := map[string]bool{}
	for _, p := range pools {
		src := getLXDPoolSource(p)
		if src == "" || seen[src] {
			continue
		}
		seen[src] = true
		maskParent := src + "/.znas-bkup-mask"
		for _, sub := range []string{"custom", "virtual-machines", "containers"} {
			parent := src + "/" + sub
			out, lerr := exec.Command("zfs", "list", "-H", "-o", "name", "-r", "-d", "1", parent).Output()
			if lerr != nil {
				continue
			}
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				ds := strings.TrimSpace(line)
				if ds == "" || ds == parent {
					continue
				}
				name := ds[strings.LastIndex(ds, "/")+1:]
				if strings.HasSuffix(name, ".block") {
					continue // moved together with its parent
				}
				if !strings.HasPrefix(name, stagingPrefix) {
					continue
				}
				_ = exec.Command("sudo", "zfs", "create", "-p", maskParent).Run()
				bucket := maskParent + "/staging_" + sub + "_" + name
				_ = exec.Command("sudo", "zfs", "create", "-p", bucket).Run()
				dst := bucket + "/" + name
				if _, e := exec.Command("sudo", "zfs", "rename", ds, dst).CombinedOutput(); e != nil {
					continue
				}
				moves = append(moves, lxdMaskRename{From: ds, To: dst})
				if blockDS := ds + ".block"; datasetExists(blockDS) {
					bdst := bucket + "/" + name + ".block"
					if _, e := exec.Command("sudo", "zfs", "rename", blockDS, bdst).CombinedOutput(); e == nil {
						moves = append(moves, lxdMaskRename{From: blockDS, To: bdst})
					}
				}
			}
		}
	}
	return moves
}

// lxdRegisteredInstanceNames returns the set of names Incus currently has
// instances registered under (all projects). Used to decide which on-disk
// instance datasets are orphans. Returns an error (→ mask nothing) if the list
// can't be read, so we never risk moving a live instance's dataset.
func lxdRegisteredInstanceNames() (map[string]bool, error) {
	out, err := exec.Command("incus", "list", "--all-projects", "--format", "csv", "-c", "n").Output()
	if err != nil {
		if out, err = exec.Command("incus", "list", "--format", "csv", "-c", "n").Output(); err != nil {
			return nil, err
		}
	}
	names := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		// Defensive: add every comma-field of every line. Extra non-name tokens
		// are harmless (no dataset is named after them); the point is that every
		// real instance name lands in the set so we never mask a live instance.
		for _, f := range strings.Split(line, ",") {
			if n := strings.TrimSpace(strings.Trim(f, "\"")); n != "" {
				names[n] = true
			}
		}
	}
	return names, nil
}

// lxdMaskNonTargetInstances hides every UNREGISTERED instance dataset (and its
// .block sibling) under <pool>/virtual-machines|containers, except `targetName`,
// so a restore-path `incus admin recover` only imports the target. Registered
// instances are NEVER moved. Fail-safe: if the registered-instance list can't be
// read, nothing is masked.
func lxdMaskNonTargetInstances(targetName string) []lxdMaskRename {
	var moves []lxdMaskRename
	registered, err := lxdRegisteredInstanceNames()
	if err != nil || len(registered) == 0 {
		return moves
	}
	isRegistered := func(name string) bool {
		if registered[name] {
			return true
		}
		// "<project>_<name>" dataset form → also treat as registered if the
		// post-underscore part is a known instance (conservative: over-skipping
		// only leaves an orphan unmasked, never moves a live instance).
		if i := strings.IndexByte(name, '_'); i >= 0 && registered[name[i+1:]] {
			return true
		}
		return false
	}
	pools, _ := LXDListStoragePools()
	seen := map[string]bool{}
	for _, p := range pools {
		src := getLXDPoolSource(p)
		if src == "" || seen[src] {
			continue
		}
		seen[src] = true
		maskParent := src + "/.znas-bkup-mask"
		for _, kind := range []string{"virtual-machines", "containers"} {
			parent := src + "/" + kind
			out, lerr := exec.Command("zfs", "list", "-H", "-o", "name", "-r", "-d", "1", parent).Output()
			if lerr != nil {
				continue
			}
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				ds := strings.TrimSpace(line)
				if ds == "" || ds == parent {
					continue
				}
				name := ds[strings.LastIndex(ds, "/")+1:]
				if strings.HasSuffix(name, ".block") {
					continue // moved together with its parent
				}
				if name == targetName || strings.HasPrefix(name, LXDBackupPrefix) || isRegistered(name) {
					continue
				}
				// Orphan/unregistered instance dataset → mask aside.
				_ = exec.Command("sudo", "zfs", "create", "-p", maskParent).Run()
				bucket := maskParent + "/orphan_" + kind + "_" + name
				_ = exec.Command("sudo", "zfs", "create", "-p", bucket).Run()
				dst := bucket + "/" + name
				if _, e := exec.Command("sudo", "zfs", "rename", ds, dst).CombinedOutput(); e != nil {
					continue
				}
				moves = append(moves, lxdMaskRename{From: ds, To: dst})
				if blockDS := ds + ".block"; datasetExists(blockDS) {
					bdst := bucket + "/" + name + ".block"
					if _, e := exec.Command("sudo", "zfs", "rename", blockDS, bdst).CombinedOutput(); e == nil {
						moves = append(moves, lxdMaskRename{From: blockDS, To: bdst})
					}
				}
			}
		}
	}
	return moves
}

// lxdMaskRename records a pair of zfs dataset paths that have been moved
// out of an Incus-scanned subtree for the duration of `incus admin recover`.
type lxdMaskRename struct {
	From string
	To   string
}

// lxdMaskBackupDatasets renames every bkup--<vm> root-fs dataset (and its
// sibling .block zvol, if any) out of <pool-src>/virtual-machines/ into
// <pool-src>/.znas-bkup-mask/ so `incus admin recover` doesn't see them.
// Returns the list of moves so the caller can revert with
// lxdUnmaskBackupDatasets. The dataset whose path equals `exempt` is
// skipped (used to keep the fresh restore target visible).
func lxdMaskBackupDatasets(exempt string) []lxdMaskRename {
	var moves []lxdMaskRename
	inst, err := LXDListAllBackupInstances()
	if err != nil {
		return moves
	}
	for _, i := range inst {
		src := getLXDPoolSource(i.RootPool)
		if src == "" {
			continue
		}
		maskParent := src + "/.znas-bkup-mask"
		// Create the parent (idempotent).
		_ = exec.Command("sudo", "zfs", "create", "-p", maskParent).Run()
		for _, kind := range []string{"virtual-machines", "containers"} {
			ds := src + "/" + kind + "/" + i.Name
			if !datasetExists(ds) || ds == exempt {
				continue
			}
			// Also the .block sibling if this is a VM backup.
			blockDS := ds + ".block"
			hasBlock := kind == "virtual-machines" && datasetExists(blockDS)

			// Make a unique sub-bucket so renames from different pools
			// don't collide if mask is created on multiple pools.
			bucket := maskParent + "/" + kind + "_" + i.Name
			_ = exec.Command("sudo", "zfs", "create", "-p", bucket).Run()
			target := bucket + "/" + i.Name
			if out, err := exec.Command("sudo", "zfs", "rename", ds, target).CombinedOutput(); err == nil {
				moves = append(moves, lxdMaskRename{From: ds, To: target})
			} else {
				// Couldn't mask — log? we're best-effort here.
				_ = out
				continue
			}
			if hasBlock {
				blockTarget := bucket + "/" + i.Name + ".block"
				if _, err := exec.Command("sudo", "zfs", "rename", blockDS, blockTarget).CombinedOutput(); err == nil {
					moves = append(moves, lxdMaskRename{From: blockDS, To: blockTarget})
				}
			}
		}
	}
	return moves
}

// lxdUnmaskBackupDatasets reverses lxdMaskBackupDatasets — moves each
// masked dataset back to its original path. Best-effort; errors are
// silently ignored because the recovery is already complete.
func lxdUnmaskBackupDatasets(moves []lxdMaskRename) {
	// Reverse order so .block goes back before its parent if the move
	// order matters (it doesn't here, but defensive).
	for i := len(moves) - 1; i >= 0; i-- {
		m := moves[i]
		_ = exec.Command("sudo", "zfs", "rename", m.To, m.From).Run()
	}
	// Clean up empty mask parent datasets per pool.
	pools, _ := LXDListStoragePools()
	for _, p := range pools {
		src := getLXDPoolSource(p)
		if src == "" {
			continue
		}
		_ = exec.Command("sudo", "zfs", "destroy", "-r", src+"/.znas-bkup-mask").Run()
	}
}

// LXDRewriteBackupYAML edits the destination dataset's `backup.yaml` so the
// `pool` references AND the instance `name:` field match where the dataset
// now lives. Without this, `incus admin recover` refuses the dataset with
// "pool name mismatch in its backup file" or "different instance name in
// its backup file".
//
// `dataset` is the destination ZFS filesystem dataset path (e.g.
// "NVMEPool/lxd/virtual-machines/bkup--vm-1"). `srcPool` is the Incus
// storage-pool name the dataset was originally tagged with (e.g. "BigRaid5")
// and `dstPool` is the destination pool name (e.g. "default"). `dstZFSSource`
// is the ZFS source string of the destination Incus pool — used to fix the
// embedded `zfs.pool_name:` line. `srcInstance` / `dstInstance` rename the
// instance entries in backup.yaml (e.g. "vm-1" → "bkup--vm-1").
//
// The function mounts the dataset to a temporary path (no-op for an already-
// mounted dataset), edits backup.yaml in-place, then unmounts. Errors are
// returned but the caller may choose to log-and-continue — the dataset is
// still usable, just not Incus-registered.
func LXDRewriteBackupYAML(dataset, srcPool, dstPool, dstZFSSource, srcInstance, dstInstance string) error {
	if srcPool == dstPool && srcInstance == dstInstance {
		return nil
	}
	tmpDir := "/tmp/znas-bkup-mount-" + strings.ReplaceAll(strings.ReplaceAll(dataset, "/", "_"), "@", "_")
	// Best-effort cleanup of any previous attempt.
	_ = exec.Command("sudo", "umount", tmpDir).Run()
	_ = exec.Command("sudo", "rmdir", tmpDir).Run()
	if out, err := exec.Command("sudo", "mkdir", "-p", tmpDir).CombinedOutput(); err != nil {
		return fmt.Errorf("mkdir mount point: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("sudo", "mount", "-t", "zfs", dataset, tmpDir).CombinedOutput(); err != nil {
		_ = exec.Command("sudo", "rmdir", tmpDir).Run()
		return fmt.Errorf("mount %s: %s", dataset, strings.TrimSpace(string(out)))
	}
	defer func() {
		_ = exec.Command("sudo", "umount", tmpDir).Run()
		_ = exec.Command("sudo", "rmdir", tmpDir).Run()
	}()

	backupYAML := tmpDir + "/backup.yaml"
	// Read file with sudo so we don't get bitten by 0600 perms.
	rawOut, err := exec.Command("sudo", "cat", backupYAML).Output()
	if err != nil {
		// No backup.yaml — nothing to fix (e.g. a custom volume dataset).
		return nil
	}
	content := string(rawOut)
	// Replace every `pool: <srcPool>` (any indentation) with `pool: <dstPool>`.
	// Also rewrite `zfs.pool_name:` so the embedded storage-pool config
	// matches the destination's ZFS source. And rewrite the instance
	// `name: <srcInstance>` to `name: <dstInstance>`.
	replaced := rewriteBackupYAMLContent(content, srcPool, dstPool, dstZFSSource, srcInstance, dstInstance)
	if replaced == content {
		return nil
	}
	// Write back via tee (sudo) — pipe through stdin so we don't have to
	// escape the YAML on the shell.
	teeCmd := exec.Command("sudo", "tee", backupYAML)
	teeCmd.Stdin = strings.NewReader(replaced)
	if out, err := teeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("rewrite backup.yaml: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// LXDRewriteBackupYAMLForRestore is the restore-time counterpart to
// LXDRewriteBackupYAML: it doesn't require the caller to know what the
// backup.yaml currently says — every `pool: …` line is unconditionally
// rewritten to `dstPool`, every `name: <srcInstance>` to `name: <dstInstance>`,
// and `zfs.pool_name:` to `dstZFSSource`. Plus the lines that match the
// `name:` of the source pool become `name: <dstPool>` (the embedded pool
// block inside backup.yaml). `srcInstance` is the original VM name the
// user is restoring (matches the `name:` field as the backup was saved).
// bkupDiskDevice is a disk device parsed from backup.yaml's device maps.
type bkupDiskDevice struct{ Name, Source, Path, Type string }

// backupYAMLDiskDevices extracts disk devices from the top-level devices:/
// expanded_devices: maps of a backup.yaml (used to decide which to strip).
func backupYAMLDiskDevices(content string) []bkupDiskDevice {
	var devs []bkupDiskDevice
	seen := map[string]bool{}
	inDevices := false
	devIndent := -1
	var cur *bkupDiskDevice
	flush := func() {
		if cur != nil && cur.Type == "disk" && !seen[cur.Name] {
			seen[cur.Name] = true
			devs = append(devs, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		ind := len(line) - len(strings.TrimLeft(line, " "))
		if trimmed == "devices:" || trimmed == "expanded_devices:" {
			flush()
			inDevices = true
			devIndent = ind
			continue
		}
		if !inDevices {
			continue
		}
		if trimmed != "" && ind <= devIndent {
			flush()
			inDevices = false
			continue
		}
		if ind == devIndent+2 && strings.HasSuffix(trimmed, ":") {
			flush()
			cur = &bkupDiskDevice{Name: strings.TrimSuffix(trimmed, ":")}
			continue
		}
		if cur != nil {
			switch {
			case strings.HasPrefix(trimmed, "type:"):
				cur.Type = strings.TrimSpace(trimmed[len("type:"):])
			case strings.HasPrefix(trimmed, "source:"):
				cur.Source = strings.TrimSpace(trimmed[len("source:"):])
			case strings.HasPrefix(trimmed, "path:"):
				cur.Path = strings.TrimSpace(trimmed[len("path:"):])
			}
		}
	}
	flush()
	return devs
}

// LXDRewriteBackupYAMLForRestore rewrites backup.yaml in place for restore.
// volRemap maps each captured custom-volume's original name → the name it was
// restored under (equal for same-name recovery; different on clone-to-new-
// name). Any attached disk device whose volume is NOT a key in volRemap is
// removed so recover doesn't fail on a volume that wasn't captured; kept
// devices have their source remapped. Pass nil to disable both.
func LXDRewriteBackupYAMLForRestore(dataset, dstPool, dstZFSSource, srcInstance, dstInstance string, volRemap map[string]string) error {
	tmpDir := "/tmp/znas-bkup-mount-" + strings.ReplaceAll(strings.ReplaceAll(dataset, "/", "_"), "@", "_")
	_ = exec.Command("sudo", "umount", tmpDir).Run()
	_ = exec.Command("sudo", "rmdir", tmpDir).Run()
	if out, err := exec.Command("sudo", "mkdir", "-p", tmpDir).CombinedOutput(); err != nil {
		return fmt.Errorf("mkdir mount point: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("sudo", "mount", "-t", "zfs", dataset, tmpDir).CombinedOutput(); err != nil {
		_ = exec.Command("sudo", "rmdir", tmpDir).Run()
		return fmt.Errorf("mount %s: %s", dataset, strings.TrimSpace(string(out)))
	}
	defer func() {
		_ = exec.Command("sudo", "umount", tmpDir).Run()
		_ = exec.Command("sudo", "rmdir", tmpDir).Run()
	}()

	backupYAML := tmpDir + "/backup.yaml"
	rawOut, err := exec.Command("sudo", "cat", backupYAML).Output()
	if err != nil {
		return nil // no backup.yaml — nothing to fix
	}
	content := string(rawOut)
	stripDevs := restoreStripDevs(content, volRemap)
	replaced := rewriteBackupYAMLForRestore(content, dstPool, dstZFSSource, srcInstance, dstInstance, stripDevs, volRemap)
	if replaced == content {
		return nil
	}
	teeCmd := exec.Command("sudo", "tee", backupYAML)
	teeCmd.Stdin = strings.NewReader(replaced)
	if out, err := teeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("rewrite backup.yaml: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// unknownVolatileKeysToStrip is the set of `volatile.*` config keys that
// cross-version Incus may reject during `admin recover`. Strip them from
// backup.yaml before recover; Incus will regenerate them on next start.
// We strip a conservative set rather than ALL volatile.* keys because
// some (like volatile.uuid) carry instance identity that other config
// references — losing them caused "invalid UUID length: 0" in earlier
// testing.
var unknownVolatileKeysToStrip = map[string]bool{
	"volatile.vm.rtc_offset":     true,
	"volatile.vm.rtc_adjustment": true,
	"volatile.vm.definition":     true,
}

// rewriteBackupYAMLForRestore unconditionally rewrites every "pool: …" line
// (regardless of the current value) to dstPool, every "zfs.pool_name: …" to
// dstZFSSource, and "name: <srcInstance>" to "name: <dstInstance>". Plus:
//
//   - The top-level "snapshots:" list is replaced with an empty list —
//     the caller destroys the dataset's snapshots so the clone starts
//     fresh, and Incus refuses any dataset whose snapshot count doesn't
//     match backup.yaml's list.
//   - The "name:" key inside the top-level "pool:" block (where Incus
//     stores the storage-pool descriptor) is rewritten to dstPool so the
//     embedded pool descriptor matches the destination pool. Without
//     this, recover fails with "pool name mismatch in its backup file".
// restoreStripDevs decides which non-root disk devices to drop from a backup.yaml
// on restore so `incus admin recover` doesn't abort on something the restore
// can't satisfy. Two cases are stripped:
//   1. Host-path disk devices (source begins with "/") — a cdrom/ISO or a bind
//      mount. The path is specific to the SOURCE host and isn't part of the
//      backup, so it won't exist on the restore target; recover otherwise fails
//      with `Missing source path "…" for disk "…"`. The user re-attaches any
//      ISO/host mount after restoring.
//   2. Custom-volume disks whose backing volume wasn't captured in this backup
//      (absent from volRemap).
//
// The root disk (path "/") is always kept. Returns an empty map when volRemap is
// nil (the legacy "keep everything" behaviour for callers that don't restore
// custom volumes).
func restoreStripDevs(content string, volRemap map[string]string) map[string]bool {
	strip := map[string]bool{}
	if volRemap == nil {
		return strip
	}
	for _, dv := range backupYAMLDiskDevices(content) {
		if dv.Path == "/" {
			continue
		}
		if strings.HasPrefix(dv.Source, "/") {
			strip[dv.Name] = true // host-path cdrom/ISO or bind mount
			continue
		}
		if dv.Source == "" {
			continue
		}
		if _, ok := volRemap[dv.Source]; !ok {
			strip[dv.Name] = true // uncaptured custom volume
		}
	}
	return strip
}

func rewriteBackupYAMLForRestore(content, dstPool, dstZFSSource, srcInstance, dstInstance string, stripDevs map[string]bool, volRemap map[string]string) string {
	out := []string{}
	inSnapshots := false
	inPoolBlock := false
	inDevices := false // inside a top-level devices:/expanded_devices: mapping
	devIndent := -1
	skipDev := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		indent := line[:len(line)-len(trimmed)]

		// Top-level snapshots: …block → snapshots: []
		if line == "snapshots:" {
			inSnapshots = true
			inDevices = false
			out = append(out, "snapshots: []")
			continue
		}
		if inSnapshots {
			if line == "" {
				continue
			}
			if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '-' {
				inSnapshots = false
				// fall through
			} else {
				continue
			}
		}

		// Drop disk devices listed in stripDevs (their backing custom volume
		// isn't part of the restore) so `incus admin recover` doesn't fail
		// with "Storage volume not found". Operates on the top-level
		// devices:/expanded_devices: maps only (snapshots are emptied above).
		if (len(stripDevs) > 0 || len(volRemap) > 0) && !inSnapshots {
			if trimmed == "devices:" || trimmed == "expanded_devices:" {
				inDevices = true
				devIndent = len(indent)
				skipDev = false
				out = append(out, line)
				continue
			}
			if inDevices {
				ind := len(indent)
				if trimmed != "" && ind <= devIndent {
					inDevices = false
					skipDev = false
					// fall through to normal handling of this line
				} else {
					if ind == devIndent+2 && strings.HasSuffix(trimmed, ":") {
						skipDev = stripDevs[strings.TrimSuffix(trimmed, ":")]
					}
					if skipDev {
						continue
					}
					// Rewrite a kept disk device's storage pool to the
					// destination pool. The clone-restore lands every disk on
					// dstPool, so a device that referenced a source-host pool
					// (e.g. "BigRaid5") must point at dstPool or recover fails
					// with `Failed to get storage pool "…": Storage pool not
					// found`. The general pool: rewrite below never sees these
					// lines because the device block `continue`s first.
					if strings.HasPrefix(trimmed, "pool:") {
						out = append(out, indent+"pool: "+dstPool)
						continue
					}
					// Remap a kept custom-disk device's source to the volume
					// name it was restored under (differs only on clone-to-
					// new-name).
					if len(volRemap) > 0 && strings.HasPrefix(trimmed, "source:") {
						v := strings.TrimSpace(trimmed[len("source:"):])
						if nv, ok := volRemap[v]; ok && nv != v {
							out = append(out, indent+"source: "+nv)
							continue
						}
					}
					out = append(out, line)
					continue
				}
			}
		}

		// Track the "pool:" top-level block so we can rewrite its
		// "name: …" child to dstPool. The block starts at column 0
		// (line == "pool:") and ends at the next column-0 line.
		if line == "pool:" {
			inPoolBlock = true
			out = append(out, line)
			continue
		}
		if inPoolBlock {
			if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
				inPoolBlock = false
				// fall through
			}
		}

		if strings.HasPrefix(trimmed, "pool: ") {
			out = append(out, indent+"pool: "+dstPool)
			continue
		}
		if strings.HasPrefix(trimmed, "zfs.pool_name:") && dstZFSSource != "" {
			out = append(out, indent+"zfs.pool_name: "+dstZFSSource)
			continue
		}
		// Inside the pool: block, the "name:" key (top-level inside
		// pool, so indent is 2 spaces) is the storage-pool's name and
		// must match dstPool.
		if inPoolBlock && len(indent) == 2 && strings.HasPrefix(trimmed, "name: ") {
			out = append(out, indent+"name: "+dstPool)
			continue
		}
		if trimmed == "name: "+srcInstance && srcInstance != "" {
			out = append(out, indent+"name: "+dstInstance)
			continue
		}
		// Strip a small set of cross-version-unsafe volatile.* config
		// keys so `incus admin recover` doesn't reject the dataset on a
		// destination that runs a different Incus version than the
		// source. Incus regenerates these on next start.
		if eq := strings.Index(trimmed, ":"); eq > 0 {
			key := strings.TrimSpace(trimmed[:eq])
			if unknownVolatileKeysToStrip[key] {
				continue
			}
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// rewriteBackupYAMLContent is the pure-string transformation extracted for
// testability. Three rewrites:
//
//	pool: <srcPool>           → pool: <dstPool>
//	zfs.pool_name: <anything> → zfs.pool_name: <dstZFSSource>
//	name: <srcInstance>       → name: <dstInstance>   (only when it matches exactly)
//
// The `name: <srcPool>` line that sits inside the embedded pool block is
// also rewritten to dstPool so the embedded storage-pool config is
// self-consistent. Snapshot entries (whose `name:` is the snapshot label
// like "auto-2026-05-19-0053") are NOT touched because their value won't
// match srcInstance.
func rewriteBackupYAMLContent(content, srcPool, dstPool, dstZFSSource, srcInstance, dstInstance string) string {
	out := []string{}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "pool: "+srcPool) {
			indent := line[:len(line)-len(trimmed)]
			out = append(out, indent+"pool: "+dstPool)
			continue
		}
		if strings.HasPrefix(trimmed, "zfs.pool_name:") && dstZFSSource != "" {
			indent := line[:len(line)-len(trimmed)]
			out = append(out, indent+"zfs.pool_name: "+dstZFSSource)
			continue
		}
		if trimmed == "name: "+srcInstance && srcInstance != "" {
			indent := line[:len(line)-len(trimmed)]
			out = append(out, indent+"name: "+dstInstance)
			continue
		}
		if trimmed == "name: "+srcPool {
			indent := line[:len(line)-len(trimmed)]
			out = append(out, indent+"name: "+dstPool)
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// LXDSnapshotEntry is the lightweight {name, created_at} pair used by the
// dropdown + Backups page. We don't go through `incus query` for retention
// pruning because we want to operate on the receive-side dataset BEFORE
// `incus admin recover` has been run; ZFS is the source of truth.
type LXDSnapshotEntry struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Used      int64     `json:"used"`    // space held exclusively by this snapshot
	Written   int64     `json:"written"` // space written since the previous snapshot
}

// LXDListDatasetSnapshots returns every snapshot of `dataset` whose name
// starts with `prefix-`. Results are sorted newest-first.
func LXDListDatasetSnapshots(dataset, prefix string) ([]LXDSnapshotEntry, error) {
	out, err := exec.Command("zfs", "list", "-Hpt", "snapshot", "-o", "name,creation,used,written", "-r", dataset).Output()
	if err != nil {
		// Non-existent dataset is not an error — empty list is the right answer.
		return nil, nil
	}
	var entries []LXDSnapshotEntry
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		full := f[0]
		at := strings.IndexByte(full, '@')
		if at < 0 {
			continue
		}
		snap := full[at+1:]
		// Only include this dataset's snapshots (not children); filter by prefix.
		if !strings.HasPrefix(full, dataset+"@") {
			continue
		}
		if prefix != "" && !strings.HasPrefix(snap, prefix+"-") && snap != prefix {
			continue
		}
		var sec int64
		fmt.Sscanf(f[1], "%d", &sec)
		var used, written int64
		fmt.Sscanf(f[2], "%d", &used)
		fmt.Sscanf(f[3], "%d", &written)
		entries = append(entries, LXDSnapshotEntry{
			Name:      snap,
			CreatedAt: time.Unix(sec, 0),
			Used:      used,
			Written:   written,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].CreatedAt.After(entries[j].CreatedAt) })
	return entries, nil
}

// LXDPruneRetentionByCount keeps the newest `keep` snapshots of `dataset`
// (prefix-filtered when prefix is non-empty; "" = every snapshot, which is
// what backup retention uses — the Backups UI lists every destination
// snapshot as a restore point, so retention must count them all) and
// destroys the rest. Returns the names destroyed. A snapshot that refuses
// to die (typically because an Instant Independent Restore clone still
// depends on it) is skipped, not fatal — it is retried on the next fire.
func LXDPruneRetentionByCount(dataset, prefix string, keep int) ([]string, error) {
	if keep <= 0 {
		return nil, nil
	}
	snaps, err := LXDListDatasetSnapshots(dataset, prefix)
	if err != nil {
		return nil, err
	}
	if len(snaps) <= keep {
		return nil, nil
	}
	var pruned []string
	for _, s := range snaps[keep:] {
		full := dataset + "@" + s.Name
		if err := exec.Command("sudo", "zfs", "destroy", "-r", full).Run(); err == nil {
			pruned = append(pruned, s.Name)
		}
	}
	return pruned, nil
}

// LXDPruneRetentionByAge destroys every snapshot older than `cutoff` —
// except the newest snapshot on the dataset, which always survives: it is
// the incremental anchor for the next syncoid run, and destroying it would
// force a full re-send whenever the schedule fires less often than the
// retention window. Returns the names destroyed; failures (dependent
// clones) are skipped like in the count variant.
func LXDPruneRetentionByAge(dataset, prefix string, cutoff time.Time) ([]string, error) {
	snaps, err := LXDListDatasetSnapshots(dataset, prefix)
	if err != nil {
		return nil, err
	}
	var pruned []string
	for i, s := range snaps { // newest-first; index 0 is the anchor
		if i == 0 {
			continue
		}
		if s.CreatedAt.Before(cutoff) {
			full := dataset + "@" + s.Name
			if err := exec.Command("sudo", "zfs", "destroy", "-r", full).Run(); err == nil {
				pruned = append(pruned, s.Name)
			}
		}
	}
	return pruned, nil
}

// WorkloadBackupPartDatasets returns every destination dataset that belongs
// to one workload backup of `vm` on `pool`: the root-fs dataset (VM or
// container branch), the VM's ".block" zvol sibling, and any custom-volume
// parts (named "bkup--<vm>.<volume>" under the custom/ branch). Only
// datasets that actually exist are returned. Used by the interlink
// prune-retention handler so a peer can apply retention to all parts of a
// backup it received.
func WorkloadBackupPartDatasets(pool, vm string) []string {
	parent := LXDWorkloadBackupParent(pool)
	bkup := LXDBackupPrefix + vm
	var out []string
	for _, ds := range []string{
		parent + "/virtual-machines/" + bkup,
		parent + "/virtual-machines/" + bkup + ".block",
		parent + "/containers/" + bkup,
	} {
		if datasetExists(ds) {
			out = append(out, ds)
		}
	}
	lsOut, err := exec.Command("zfs", "list", "-Hp", "-t", "filesystem,volume", "-o", "name", "-r", "-d", "1", parent+"/custom").Output()
	if err == nil {
		for _, ln := range strings.Split(string(lsOut), "\n") {
			name := strings.TrimSpace(ln)
			if name == "" || name == parent+"/custom" {
				continue
			}
			base := name[strings.LastIndexByte(name, '/')+1:]
			if strings.HasPrefix(base, bkup+".") {
				out = append(out, name)
			}
		}
	}
	return out
}

// LXDSnapshotName composes the standard auto-YYYY-MM-DD-HHMMSS snapshot
// name using the given prefix. Second precision matters because Backup Now
// and the scheduler can both fire inside the same minute (manual click after
// the schedule just fired), and Incus rejects duplicate snapshot names.
func LXDSnapshotName(prefix string, now time.Time) string {
	if prefix == "" {
		prefix = LXDBackupSnapshotPrefix
	}
	return prefix + "-" + now.Format("2006-01-02-150405")
}

// LXDBackupSnapshotPrefixFor builds the destination-specific source-side
// snapshot prefix used by the backup feature (v6.5.19+). The full name is
//
//	bkp-to-<label>-YYYY-MM-DD-HHMMSS
//
// where <label> is "local-<datastore>" for local backups or the peer's
// hostname for remote backups. The label is sanitized so it survives
// ZFS naming rules and stays unambiguous when grep'd: only [a-zA-Z0-9-]
// is kept, everything else becomes '-'. Empty labels fall back to
// "unknown".
//
// Naming the source snapshot after its destination makes the chain
// human-readable in the Snapshots dropdown — the user can tell which
// snapshot belongs to which backup target instead of seeing a sea of
// "snapshot-auto-..." entries.
func LXDBackupSnapshotPrefixFor(destLabel string) string {
	clean := sanitizeBackupLabel(destLabel)
	if clean == "" {
		clean = "unknown"
	}
	return "bkp-to-" + clean
}

// sanitizeBackupLabel maps any input string to a ZFS-snapshot-safe label.
// Allowed runes: a-z A-Z 0-9 dash. Everything else is collapsed to '-'.
// Adjacent dashes are reduced to one and edge dashes are trimmed so the
// resulting label stays compact.
func sanitizeBackupLabel(in string) string {
	if in == "" {
		return ""
	}
	out := make([]rune, 0, len(in))
	prevDash := false
	for _, r := range in {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-'
		if ok {
			out = append(out, r)
			prevDash = (r == '-')
			continue
		}
		if !prevDash {
			out = append(out, '-')
			prevDash = true
		}
	}
	s := string(out)
	for strings.HasPrefix(s, "-") {
		s = s[1:]
	}
	for strings.HasSuffix(s, "-") {
		s = s[:len(s)-1]
	}
	return s
}

// PruneSourceBackupAnchors keeps only the most recent source-side snapshot
// matching the supplied prefix (the bkp-to-<label> family). Older ones
// are deleted via `incus snapshot delete` — they're no longer needed as
// incremental anchors. Returns the names deleted (for logging) and any
// non-fatal errors.
//
// Idempotent: safe to call when 0, 1, or N matching snapshots exist.
func PruneSourceBackupAnchors(instance, prefix string) ([]string, error) {
	snaps, err := ListLXDSnapshots(instance)
	if err != nil {
		return nil, err
	}
	type entry struct {
		name string
		at   time.Time
	}
	var matched []entry
	for _, s := range snaps {
		if strings.HasPrefix(s.Name, prefix+"-") || s.Name == prefix {
			matched = append(matched, entry{name: s.Name, at: s.CreatedAt})
		}
	}
	if len(matched) <= 1 {
		return nil, nil
	}
	// Sort newest-first, drop everything after index 0.
	sort.Slice(matched, func(i, j int) bool { return matched[i].at.After(matched[j].at) })
	pruned := []string{}
	for _, e := range matched[1:] {
		if err := DeleteLXDSnapshot(instance, e.name); err == nil {
			pruned = append(pruned, e.name)
		}
	}
	return pruned, nil
}

// LXDListBackupSnapshots returns the ZFS snapshots of a backup instance's
// root filesystem dataset, given the backup instance name (e.g.
// "bkup--vm-1") and the Incus pool it sits on. Used by the per-VM Backups
// dropdown and the Backups page since the backup is not registered with
// Incus and therefore not visible via `incus snapshot list`.
func LXDListBackupSnapshots(backupInstance, poolName string) []LXDSnapshotEntry {
	src := getLXDPoolSource(poolName)
	if src == "" {
		return nil
	}
	// Try both kinds — we don't know whether this is a VM or container
	// backup at the call site; the dataset will only exist under one.
	for _, kind := range []string{"virtual-machines", "containers"} {
		ds := src + "/" + kind + "/" + backupInstance
		if !datasetExists(ds) {
			continue
		}
		entries, _ := LXDListDatasetSnapshots(ds, "")
		return entries
	}
	return nil
}

// LXDWorkloadBackupInstance is one bkup--<vm> dataset discovered under the
// workload layout (no Incus needed to enumerate).
type LXDWorkloadBackupInstance struct {
	Name      string // "bkup--<vm-id>"
	Type      string // "virtual-machine" | "container"
	ZFSPool   string // pool name on the host (e.g. "nvmepool")
	Dataset   string // full ZFS path: <pool>/ZNAS-Backups-Workload/<kind>/bkup--<vm-id>
	UsedBytes int64  // total on-disk size (root dataset + .block sibling, incl. snapshots)
}

// ListWorkloadBackupInstances scans every imported ZFS pool for backup
// instances living under "<pool>/ZNAS-Backups-Workload/{virtual-machines|
// containers}/bkup--<vm>". This is the peer-side enumeration the cross-
// server backups aggregator and the per-VM dropdown call over HMAC; it
// works on hosts that don't have Incus installed.
func ListWorkloadBackupInstances() ([]LXDWorkloadBackupInstance, error) {
	out, err := exec.Command("zpool", "list", "-H", "-o", "name").Output()
	if err != nil {
		return nil, fmt.Errorf("zpool list: %w", err)
	}
	var results []LXDWorkloadBackupInstance
	for _, pool := range strings.Split(string(out), "\n") {
		pool = strings.TrimSpace(pool)
		if pool == "" {
			continue
		}
		parent := LXDWorkloadBackupParent(pool)
		// Skip pools that don't have the workload marker yet.
		if !datasetExists(parent) {
			continue
		}
		dsOut, err := exec.Command("zfs", "list", "-Hpt", "filesystem", "-o", "name", "-r", parent).Output()
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(dsOut), "\n") {
			name := strings.TrimSpace(ln)
			if name == "" {
				continue
			}
			for _, kind := range []string{"virtual-machines", "containers"} {
				prefix := parent + "/" + kind + "/" + LXDBackupPrefix
				if !strings.HasPrefix(name, prefix) {
					continue
				}
				rest := name[len(prefix):]
				// Skip nested children and .block-style siblings (siblings
				// live BESIDE the fs dataset, not as children, so they get
				// matched independently — filter them out here so the
				// listing represents instance-level entries only).
				if strings.Contains(rest, "/") || strings.HasSuffix(rest, ".block") {
					continue
				}
				t := "container"
				if kind == "virtual-machines" {
					t = "virtual-machine"
				}
				results = append(results, LXDWorkloadBackupInstance{
					Name:      LXDBackupPrefix + rest,
					Type:      t,
					ZFSPool:   pool,
					Dataset:   name,
					UsedBytes: backupInstanceUsedBytes(name),
				})
			}
		}
	}
	return results, nil
}

// ListWorkloadBackupSnapshots returns the snapshots of one workload backup
// (peer-side enumeration). prefix="" includes every snapshot.
//
// For a VM backup the root-fs dataset only holds tiny config; the disk image
// lives in the `.block` zvol sibling. We merge the same-named snapshot from
// both datasets so each entry's Used/Written reflects the whole backup's
// per-snapshot footprint, not just the config portion.
func ListWorkloadBackupSnapshots(dataset string) []LXDSnapshotEntry {
	entries, _ := LXDListDatasetSnapshots(dataset, "")
	block := dataset + ".block"
	if datasetExists(block) {
		idxByName := map[string]int{}
		for i, e := range entries {
			idxByName[e.Name] = i
		}
		blockSnaps, _ := LXDListDatasetSnapshots(block, "")
		for _, bs := range blockSnaps {
			if i, ok := idxByName[bs.Name]; ok {
				entries[i].Used += bs.Used
				entries[i].Written += bs.Written
			} else {
				entries = append(entries, bs)
			}
		}
	}
	return entries
}

// DeleteWorkloadBackup destroys a workload-style backup. With snapshotName
// empty it removes the bkup--<vm> dataset (root-fs + .block sibling + any
// custom volume siblings). Otherwise it destroys just the named snapshot
// on each part that has it.
func DeleteWorkloadBackup(zfsPool, vmID, snapshotName string) error {
	bkup := LXDBackupPrefix + vmID
	parent := LXDWorkloadBackupParent(zfsPool)
	// Discover which kind directory hosts the backup.
	var kind string
	for _, k := range []string{"virtual-machines", "containers"} {
		if datasetExists(parent + "/" + k + "/" + bkup) {
			kind = k
			break
		}
	}
	if kind == "" {
		return fmt.Errorf("workload backup %s not found on pool %s", bkup, zfsPool)
	}
	// Refuse to delete a backup that an Instant Independent Restore is still
	// running off (a ZFS clone hangs off one of its snapshots). ZFS would block
	// the destroy anyway; this gives the user a clear, actionable message.
	if snapshotName == "" {
		if deps := BackupDependents(zfsPool, vmID); len(deps) > 0 {
			verb := "is"
			if len(deps) > 1 {
				verb = "are"
			}
			return fmt.Errorf("cannot delete — %s %s running off this backup as an Instant Independent Restore. "+
				"Promote it to a Full Copy first (the yellow \"Backup Dependent\" button on the instance page)", strings.Join(deps, ", "), verb)
		}
	}
	root := parent + "/" + kind + "/" + bkup
	parts := []string{root}
	if kind == "virtual-machines" {
		block := root + ".block"
		if datasetExists(block) {
			parts = append(parts, block)
		}
	}
	// Attached custom-volume backup datasets (<parent>/custom/bkup--<vm>.<vol>)
	// must be deleted too, otherwise they orphan on the pool forever.
	if out, err := exec.Command("zfs", "list", "-Hp", "-t", "filesystem,volume", "-o", "name", "-r", parent+"/custom").Output(); err == nil {
		prefix := parent + "/custom/" + bkup + "."
		for _, line := range strings.Split(string(out), "\n") {
			n := strings.TrimSpace(line)
			if strings.HasPrefix(n, prefix) && !strings.Contains(n[len(prefix):], "/") {
				parts = append(parts, n)
			}
		}
	}
	if snapshotName != "" {
		var anyErr error
		for _, p := range parts {
			tgt := p + "@" + snapshotName
			if out, err := exec.Command("sudo", "zfs", "destroy", tgt).CombinedOutput(); err != nil {
				if strings.Contains(string(out), "does not exist") {
					continue
				}
				if anyErr == nil {
					anyErr = fmt.Errorf("destroy %s: %s", tgt, strings.TrimSpace(string(out)))
				}
			}
		}
		return anyErr
	}
	var anyErr error
	for _, p := range parts {
		if out, err := exec.Command("sudo", "zfs", "destroy", "-r", p).CombinedOutput(); err != nil {
			if anyErr == nil {
				anyErr = fmt.Errorf("destroy %s: %s", p, strings.TrimSpace(string(out)))
			}
		}
	}
	return anyErr
}

// BackupDependents returns the instance names currently running off a ZFS clone
// of the workload backup `bkup--<vmID>` on `zfsPool` (Instant Independent
// Restores). Empty when the backup is free to delete. Derived from the `clones`
// property of every snapshot on the backup's datasets (root-fs, .block, customs).
func BackupDependents(zfsPool, vmID string) []string {
	bkup := LXDBackupPrefix + vmID
	parent := LXDWorkloadBackupParent(zfsPool)
	var datasets []string
	for _, k := range []string{"virtual-machines", "containers"} {
		root := parent + "/" + k + "/" + bkup
		if datasetExists(root) {
			datasets = append(datasets, root)
			if datasetExists(root + ".block") {
				datasets = append(datasets, root+".block")
			}
		}
	}
	if out, err := exec.Command("zfs", "list", "-Hp", "-t", "filesystem,volume", "-o", "name", "-r", parent+"/custom").Output(); err == nil {
		prefix := parent + "/custom/" + bkup + "."
		for _, line := range strings.Split(string(out), "\n") {
			n := strings.TrimSpace(line)
			if strings.HasPrefix(n, prefix) && !strings.Contains(n[len(prefix):], "/") {
				datasets = append(datasets, n)
			}
		}
	}
	seen := map[string]bool{}
	var insts []string
	for _, ds := range datasets {
		so, err := exec.Command("zfs", "list", "-Hp", "-t", "snapshot", "-o", "name", "-d", "1", ds).Output()
		if err != nil {
			continue
		}
		for _, sl := range strings.Split(string(so), "\n") {
			snap := strings.TrimSpace(sl)
			if !strings.HasPrefix(snap, ds+"@") {
				continue
			}
			for _, clone := range ZfsSnapshotClones(snap) {
				if inst := instanceNameFromCloneDataset(clone); inst != "" && !seen[inst] {
					seen[inst] = true
					insts = append(insts, inst)
				}
			}
		}
	}
	return insts
}

// instanceNameFromCloneDataset extracts the instance name from a clone dataset
// path under an Incus pool, e.g. "<src>/virtual-machines/myvm" → "myvm". Custom-
// volume clones return "" (the matching root-fs clone already names the instance).
func instanceNameFromCloneDataset(ds string) string {
	for _, seg := range []string{"/virtual-machines/", "/containers/"} {
		if i := strings.Index(ds, seg); i >= 0 {
			name := ds[i+len(seg):]
			if j := strings.IndexByte(name, '/'); j >= 0 {
				name = name[:j]
			}
			return strings.TrimSuffix(name, ".block")
		}
	}
	return ""
}

// ValidBackupCompressions is the closed list of compression values the UI
// + backend accept. Other values are rejected at save-policy time.
var ValidBackupCompressions = map[string]bool{
	"zstd-19": true, "zstd-9": true, "zstd-3": true,
	"lz4": true, "off": true,
}

// EnsureWorkloadParent makes sure the workload parent dataset (and the
// kind subdirectory) exist on a ZFS pool, AND sets the requested
// compression algorithm on the parent so newly-created child backup
// datasets inherit it. Idempotent. `compression=""` defaults to zstd-19.
func EnsureWorkloadParent(zfsPool, kind, compression string) error {
	if compression == "" {
		compression = "zstd-19"
	}
	if !ValidBackupCompressions[compression] {
		return fmt.Errorf("invalid compression %q", compression)
	}
	parent := LXDWorkloadBackupParent(zfsPool)
	// Create parent if it doesn't exist; otherwise just set compression.
	if !datasetExists(parent) {
		if out, err := exec.Command("sudo", "zfs", "create",
			"-o", "compression="+compression,
			"-o", "mountpoint=none",
			parent).CombinedOutput(); err != nil {
			return fmt.Errorf("create %s: %s", parent, strings.TrimSpace(string(out)))
		}
	} else {
		// Refresh compression so changes apply to future writes.
		if out, err := exec.Command("sudo", "zfs", "set",
			"compression="+compression, parent).CombinedOutput(); err != nil {
			return fmt.Errorf("set compression on %s: %s", parent, strings.TrimSpace(string(out)))
		}
	}
	// Kind subdir — same compression inherited; `zfs create -p` would
	// also create the parent if missing, but we already handled that.
	kindDS := parent + "/" + kind
	if !datasetExists(kindDS) {
		if out, err := exec.Command("sudo", "zfs", "create",
			"-o", "mountpoint=none",
			kindDS).CombinedOutput(); err != nil {
			return fmt.Errorf("create %s: %s", kindDS, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// ListLocalZFSPools returns every imported ZFS pool name on this host.
// Cheap wrapper used by the new HMAC peer endpoint that exposes pools to
// remote ZNAS peers picking a backup destination.
func ListLocalZFSPools() ([]string, error) {
	out, err := exec.Command("zpool", "list", "-H", "-o", "name").Output()
	if err != nil {
		return nil, fmt.Errorf("zpool list: %w", err)
	}
	var pools []string
	for _, ln := range strings.Split(string(out), "\n") {
		p := strings.TrimSpace(ln)
		if p != "" {
			pools = append(pools, p)
		}
	}
	return pools, nil
}

// workloadBackupParts returns the dataset-part list for a workload-layout
// backup on the local host. Mirrors LXDInstanceBackupDatasets's "root-fs
// + root-blk + custom" composition but rooted at the workload parent.
func workloadBackupParts(zfsPool, kind, backupInstance string) []LXDInstanceDiskPart {
	parent := LXDWorkloadBackupParent(zfsPool)
	parts := []LXDInstanceDiskPart{{
		SrcDataset:  parent + "/" + kind + "/" + backupInstance,
		DstBaseName: backupInstance,
		Recursive:   true,
		Kind:        "root-fs",
	}}
	if kind == "virtual-machines" {
		blockSrc := parent + "/" + kind + "/" + backupInstance + ".block"
		if datasetExists(blockSrc) {
			parts = append(parts, LXDInstanceDiskPart{
				SrcDataset:  blockSrc,
				DstBaseName: backupInstance + ".block",
				Recursive:   false,
				Kind:        "root-blk",
			})
		}
	}
	// Custom-volume datasets — same convention as in
	// LXDInstanceBackupDatasets (parent/custom/<backupInstance>.<vol>).
	out, err := exec.Command("zfs", "list", "-Hpt", "filesystem,volume", "-o", "name", "-r", parent+"/custom").Output()
	if err == nil {
		prefix := parent + "/custom/" + backupInstance + "."
		for _, line := range strings.Split(string(out), "\n") {
			name := strings.TrimSpace(line)
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			rest := name[len(prefix):]
			if strings.Contains(rest, "/") {
				continue
			}
			parts = append(parts, LXDInstanceDiskPart{
				SrcDataset:  name,
				DstBaseName: name[len(parent+"/custom/"):],
				Recursive:   true,
				Kind:        "custom",
			})
		}
	}
	return parts
}

// DatasetExistsForBackups is a public wrapper around the local
// datasetExists helper, kept so handlers can probe destination paths
// without importing private package-internals.
func DatasetExistsForBackups(ds string) bool { return datasetExists(ds) }

// SnapshotNameSetForBackups is the public wrapper around snapshotNameSet.
func SnapshotNameSetForBackups(dataset string) map[string]bool {
	return snapshotNameSet(dataset)
}

// HasCommonSnapshot returns true when src and dst share at least one
// snapshot (compared by short name, since syncoid carries names verbatim).
// Both arguments are dataset paths; either may be empty/nonexistent — the
// function returns false in those cases.
func HasCommonSnapshot(src, dst string) bool {
	srcSet := snapshotNameSet(src)
	if len(srcSet) == 0 {
		return false
	}
	dstSet := snapshotNameSet(dst)
	for n := range srcSet {
		if dstSet[n] {
			return true
		}
	}
	return false
}

// snapshotNameSet returns the short snapshot names of `dataset` as a set.
// `dataset` must NOT include an "@" — pass only the dataset path. Returns
// empty set when the dataset doesn't exist.
func snapshotNameSet(dataset string) map[string]bool {
	out, err := exec.Command("zfs", "list", "-Hpt", "snapshot", "-o", "name", "-r", dataset).Output()
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, dataset+"@") {
			continue
		}
		set[line[len(dataset)+1:]] = true
	}
	return set
}

// PrepLocalBackupChain ensures the local destination dataset for a backup
// is either (a) absent, so syncoid does a clean full send, or (b) shares
// at least one snapshot with the source so syncoid's incremental can
// continue. When the destination exists but the chain is broken (user
// deleted source snapshots while the destination kept its own), the
// destination dataset is destroyed and the function returns true to
// signal the caller that a full re-send is happening this fire.
//
// `logFn` receives a human-readable line describing whatever action was
// taken — handy because the user's expectation "I deleted a snapshot,
// why is the next backup huge?" becomes self-evident in the job log.
func PrepLocalBackupChain(srcDataset, dstDataset string, logFn func(string)) (heal bool) {
	if !datasetExists(dstDataset) {
		return false
	}
	if HasCommonSnapshot(srcDataset, dstDataset) {
		return false
	}
	if logFn != nil {
		logFn("Backup chain broken (no shared snapshot between source and destination) — wiping " + dstDataset + " and redoing a full send.")
	}
	_ = exec.Command("sudo", "zfs", "destroy", "-r", dstDataset).Run()
	return true
}

// DeleteLocalBackup destroys a backup on this host. When `snapshotName` is
// empty, the entire bkup--<vmID> dataset (root-fs + .block sibling + any
// custom volume datasets) is destroyed. Otherwise just the named snapshot
// on each part is destroyed.
func DeleteLocalBackup(vmID, datastore, snapshotName string) error {
	bkup := LXDBackupPrefix + vmID
	parts, _, err := LXDBackupInstanceDatasets(bkup, datastore)
	if err != nil {
		return fmt.Errorf("locate backup: %w", err)
	}
	if len(parts) == 0 {
		return fmt.Errorf("no datasets found for backup %s on %s", bkup, datastore)
	}
	if snapshotName != "" {
		// Targeted snapshot delete on every part. ZFS snapshots are
		// per-dataset; root-fs and root-blk share the same snapshot name
		// (taken atomically by Incus). Best-effort across parts.
		var anyErr error
		for _, p := range parts {
			target := p.SrcDataset + "@" + snapshotName
			if out, err := exec.Command("sudo", "zfs", "destroy", target).CombinedOutput(); err != nil {
				// Skip parts that don't have this snapshot (custom volumes).
				if strings.Contains(string(out), "does not exist") {
					continue
				}
				if anyErr == nil {
					anyErr = fmt.Errorf("destroy %s: %s", target, strings.TrimSpace(string(out)))
				}
			}
		}
		return anyErr
	}
	// Whole-backup delete — destroy each dataset recursively (-r includes
	// all snapshots on the dataset).
	var anyErr error
	for _, p := range parts {
		if out, err := exec.Command("sudo", "zfs", "destroy", "-r", p.SrcDataset).CombinedOutput(); err != nil {
			if anyErr == nil {
				anyErr = fmt.Errorf("destroy %s: %s", p.SrcDataset, strings.TrimSpace(string(out)))
			}
		}
	}
	return anyErr
}

// LXDBackupInstanceDatasets enumerates the ZFS datasets that compose a
// backup-instance on the local host, WITHOUT going through Incus.
//
// v6.5.19+: tries TWO layouts before giving up:
//
//	1. Workload layout (canonical):  <srcDatastore>/ZNAS-Backups-Workload/<kind>/<bkup>
//	   `srcDatastore` here is a ZFS pool name (e.g. "BIGRAID5").
//	2. Legacy Incus layout:          <pool-source>/<kind>/<bkup>
//	   `srcDatastore` is an Incus storage-pool name whose source
//	   attribute resolves to "<zfs-pool>/<incus-dataset>".
//
// Returns one entry per dataset that should be replicated together to
// fully restore the backup. `kind` ("virtual-machines"|"containers") and
// the root-fs / root-blk presence are derived from disk state.
func LXDBackupInstanceDatasets(backupInstance, srcDatastore string) ([]LXDInstanceDiskPart, string, error) {
	// Workload layout — preferred. srcDatastore is a ZFS pool name.
	workloadParent := LXDWorkloadBackupParent(srcDatastore)
	if datasetExists(workloadParent) {
		var kind string
		for _, k := range []string{"virtual-machines", "containers"} {
			if datasetExists(workloadParent + "/" + k + "/" + backupInstance) {
				kind = k
				break
			}
		}
		if kind != "" {
			return workloadBackupParts(srcDatastore, kind, backupInstance), kind, nil
		}
	}
	// Legacy Incus-pool layout fallback. srcDatastore is an Incus pool.
	src := getLXDPoolSource(srcDatastore)
	if src == "" {
		return nil, "", fmt.Errorf("backup %q not found on %q (workload nor Incus layout)", backupInstance, srcDatastore)
	}
	var kind string
	for _, k := range []string{"virtual-machines", "containers"} {
		if datasetExists(src + "/" + k + "/" + backupInstance) {
			kind = k
			break
		}
	}
	if kind == "" {
		return nil, "", fmt.Errorf("backup %q not found under any datastore-kind on %q", backupInstance, srcDatastore)
	}
	parts := []LXDInstanceDiskPart{{
		SrcDataset:  src + "/" + kind + "/" + backupInstance,
		DstBaseName: backupInstance,
		Recursive:   true,
		Kind:        "root-fs",
	}}
	// VM root block zvol is a sibling — include it if present.
	if kind == "virtual-machines" {
		blockSrc := src + "/" + kind + "/" + backupInstance + ".block"
		if datasetExists(blockSrc) {
			parts = append(parts, LXDInstanceDiskPart{
				SrcDataset:  blockSrc,
				DstBaseName: backupInstance + ".block",
				Recursive:   false,
				Kind:        "root-blk",
			})
		}
	}
	// Custom-volume datasets attached at backup time would live under
	// "<src>/custom/<volname>" with a naming convention like
	// "<backupInstance>.<volname>". Enumerate matching ones.
	out, err := exec.Command("zfs", "list", "-Hpt", "filesystem,volume", "-o", "name", "-r", src+"/custom").Output()
	if err == nil {
		prefix := src + "/custom/" + backupInstance + "."
		for _, line := range strings.Split(string(out), "\n") {
			name := strings.TrimSpace(line)
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			// Skip nested children (we'll let --recursive cover them).
			rest := name[len(prefix):]
			if strings.Contains(rest, "/") {
				continue
			}
			parts = append(parts, LXDInstanceDiskPart{
				SrcDataset:  name,
				DstBaseName: name[len(src+"/custom/"):],
				Recursive:   true,
				Kind:        "custom",
			})
		}
	}
	return parts, kind, nil
}

// LXDListAllBackupInstances returns every "bkup--*" backup discovered on
// this host. v6.5.19 — Sourced from ZFS dataset scanning rather than
// `incus list`, because the destination datasets often have backup.yaml /
// snapshot-count inconsistencies after incremental syncoid runs that prevent
// `incus admin recover` from registering them. The on-disk dataset IS the
// authoritative artifact for disaster recovery, so we render from there.
//
// Returns an LXDInstance-shaped record so the existing handler code can use
// the result unchanged. Type is derived from the parent path segment
// (virtual-machines / containers). RootPool is the Incus storage-pool name
// the dataset sits under, resolved by reverse-mapping the ZFS source.
func LXDListAllBackupInstances() ([]LXDInstance, error) {
	// Map ZFS-source → Incus pool name.
	poolByZFSSource := map[string]string{}
	pools, _ := LXDListStoragePools()
	for _, name := range pools {
		src := getLXDPoolSource(name)
		if src != "" {
			poolByZFSSource[src] = name
		}
	}
	// Scan all filesystem datasets and pick ones whose path matches
	// "<zfs-source>/<virtual-machines|containers>/bkup--<vm-id>" (the
	// ".block" zvol siblings are deliberately excluded — they're
	// disk parts, not standalone backups).
	out, err := exec.Command("zfs", "list", "-Hpt", "filesystem", "-o", "name").Output()
	if err != nil {
		return nil, err
	}
	results := []LXDInstance{}
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		for src, poolName := range poolByZFSSource {
			for _, kind := range []string{"virtual-machines", "containers"} {
				prefix := src + "/" + kind + "/" + LXDBackupPrefix
				if !strings.HasPrefix(name, prefix) {
					continue
				}
				inst := name[len(prefix):]
				// Skip nested children (only top-level bkup--<name>).
				if strings.Contains(inst, "/") {
					continue
				}
				// Skip the ".block" sibling — it pairs with a fs dataset.
				if strings.HasSuffix(inst, ".block") {
					continue
				}
				instType := "container"
				if kind == "virtual-machines" {
					instType = "virtual-machine"
				}
				results = append(results, LXDInstance{
					Name:     LXDBackupPrefix + inst,
					Type:     instType,
					Status:   "Stopped",
					RootPool: poolName,
				})
			}
		}
	}
	return results, nil
}

// LXDStoragePoolSource returns the ZFS source dataset for an Incus pool.
// Public wrapper of getLXDPoolSource (kept private historically) so the
// backup handlers don't have to live in package system.
func LXDStoragePoolSource(poolName string) string {
	return getLXDPoolSource(poolName)
}
