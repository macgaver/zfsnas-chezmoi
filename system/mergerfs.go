package system

// MergerFS union-filesystem support (v6.7.13, optional feature).
//
// Install: fetch the mergerfs .deb matching this host's OS from the upstream
// GitHub releases (trapexit/mergerfs); fall back to the static tarball when no
// per-codename deb exists (e.g. a brand-new Debian release). Create: build the
// mergerfs options string, write a systemd .mount unit that only assembles the
// union after every ZFS pool/dataset is mounted (bounded ≤30s wait), enable it
// so the union survives reboot. Status: live df + per-branch usage. Coordinated
// ZFS snapshots for all-ZFS unions live in mergerfs_snapshots.go.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"zfsnas/internal/config"
)

// MergerFSInstalled reports whether the mergerfs binary is present.
func MergerFSInstalled() bool { return binaryPresent("mergerfs") }

// mergerfsKnownRoots returns each union's mountpoint as a File Browser root
// (label "MergerFS: <name>"), so the tab's File Browser button can browse the
// union. Consumed by ResolveKnownRoots (filebrowser.go).
func mergerfsKnownRoots() map[string]string {
	out := map[string]string{}
	c, err := config.LoadAppConfig()
	if err != nil || c == nil {
		return out
	}
	for _, p := range c.MergerFS.Pools {
		if p.Mountpoint != "" {
			out[p.Mountpoint] = "MergerFS: " + p.Name
		}
	}
	return out
}

// ── OS / release-asset selection (pure, unit-tested) ─────────────────────────

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

// dpkgArch returns the Debian architecture string (amd64, arm64, …).
func dpkgArch() string {
	out, err := exec.Command("dpkg", "--print-architecture").Output()
	if err != nil {
		return "amd64"
	}
	return strings.TrimSpace(string(out))
}

// mergerfsOSTarget reads /etc/os-release → (id, codename). id is "debian" or
// "ubuntu"; codename is e.g. "bookworm"/"trixie"/"jammy"/"noble".
func mergerfsOSTarget() (id, codename string) {
	m := readOSRelease()
	id = strings.ToLower(m["ID"])
	codename = strings.ToLower(m["VERSION_CODENAME"])
	// Debian testing/sid sometimes omit VERSION_CODENAME.
	if codename == "" {
		if strings.Contains(strings.ToLower(m["PRETTY_NAME"]), "trixie") {
			codename = "trixie"
		}
	}
	return id, codename
}

// pickMergerFSAsset chooses the best download for (id, codename, arch) from a
// release's asset list. Prefers the exact per-distro deb
// (mergerfs_<ver>.<id>-<codename>_<arch>.deb); falls back to the arch-matched
// static tarball (mergerfs-static-linux_<arch>.tar.gz). Returns (url, isDeb,
// assetName). url is "" when nothing matches.
func pickMergerFSAsset(assets []ghAsset, id, codename, arch string) (string, bool, string) {
	debSuffix := fmt.Sprintf(".%s-%s_%s.deb", id, codename, arch)
	for _, a := range assets {
		if strings.HasSuffix(a.Name, debSuffix) {
			return a.URL, true, a.Name
		}
	}
	// Static fallback (works on any glibc Linux of that arch).
	staticName := fmt.Sprintf("mergerfs-static-linux_%s.tar.gz", arch)
	for _, a := range assets {
		if a.Name == staticName {
			return a.URL, false, a.Name
		}
	}
	return "", false, ""
}

// ── Path validation & ZFS resolution (pure, unit-tested) ─────────────────────

// mergerfsPathAllowed reports whether p is an acceptable mergerfs mountpoint or
// branch: it must be under /mnt or under one of the given ZFS pool/dataset
// mountpoints. Rejects relative paths and bare "/mnt"/pool roots' parents.
func mergerfsPathAllowed(p string, zfsMounts []string) bool {
	if !filepath.IsAbs(p) {
		return false
	}
	p = filepath.Clean(p)
	if p == "/mnt" || strings.HasPrefix(p, "/mnt/") {
		return true
	}
	for _, m := range zfsMounts {
		m = filepath.Clean(m)
		if m == "/" || m == "" {
			continue
		}
		if p == m || strings.HasPrefix(p, m+"/") {
			return true
		}
	}
	return false
}

// resolveBranchDataset returns the name of the deepest ZFS dataset whose
// mountpoint is a prefix of path (or "" if none). datasets maps dataset name →
// mountpoint.
func resolveBranchDataset(path string, datasets map[string]string) string {
	path = filepath.Clean(path)
	best, bestLen := "", -1
	for name, mp := range datasets {
		mp = filepath.Clean(mp)
		if mp == "" || mp == "/" || mp == "none" || mp == "legacy" {
			continue
		}
		if (path == mp || strings.HasPrefix(path, mp+"/")) && len(mp) > bestLen {
			best, bestLen = name, len(mp)
		}
	}
	return best
}

// zfsDatasetMounts returns dataset-name → mountpoint for every mounted ZFS
// dataset (used for branch resolution and path validation).
func zfsDatasetMounts() map[string]string {
	out := map[string]string{}
	b, err := exec.Command("zfs", "list", "-Hp", "-o", "name,mountpoint", "-t", "filesystem").Output()
	if err != nil {
		return out
	}
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 {
			out[f[0]] = f[1]
		}
	}
	return out
}

// zfsMountpointList returns all ZFS dataset mountpoints (for path validation).
func zfsMountpointList() []string {
	var out []string
	for _, mp := range zfsDatasetMounts() {
		if mp != "" && mp != "none" && mp != "legacy" && mp != "/" {
			out = append(out, mp)
		}
	}
	return out
}

// ── options string + systemd unit (pure, unit-tested) ────────────────────────

// mergerfsOptsString builds the comma-separated mergerfs option string for a
// pool (without the trailing nofail / systemd opts, which the unit adds).
func mergerfsOptsString(p config.MergerFSPool) string {
	opts := []string{
		"category.create=" + orDefault(p.CreatePolicy, "mfs"),
		"minfreespace=" + orDefault(p.MinFreeSpace, "50G"),
		"moveonenospc=" + mfsBool(p.MoveOnENOSPC),
		"cache.files=" + orDefault(p.CacheFiles, "off"),
		"dropcacheonclose=" + mfsBool(p.DropCacheOnClose),
		"inodecalc=" + orDefault(p.InodeCalc, "path-hash"),
		"fsname=" + orDefault(p.FsName, p.Name),
	}
	if p.AllowOther {
		opts = append(opts, "allow_other")
	}
	return strings.Join(opts, ",")
}

func branchPaths(p config.MergerFSPool) []string {
	out := make([]string, 0, len(p.Branches))
	for _, b := range p.Branches {
		out = append(out, b.Path)
	}
	return out
}

// mergerfsUnitName returns the systemd .mount unit filename for a mountpoint,
// e.g. "/mnt/media" → "mnt-media.mount".
func mergerfsUnitName(mountpoint string) string {
	out, err := exec.Command("systemd-escape", "-p", "--suffix=mount", mountpoint).Output()
	if err != nil {
		// Fallback escaping mirroring systemd's path scheme for the common case.
		s := strings.TrimPrefix(filepath.Clean(mountpoint), "/")
		s = strings.ReplaceAll(s, "-", "\\x2d")
		s = strings.ReplaceAll(s, "/", "-")
		return s + ".mount"
	}
	return strings.TrimSpace(string(out))
}

// mergerfsUnitContent renders the systemd .mount unit. It orders the union
// after ZFS is fully up and adds a bounded (≤30s) pre-start wait for every
// branch to be a live mountpoint, so pools/datasets are ready before the union
// assembles — then proceeds under nofail so a missing branch never hangs boot.
func mergerfsUnitContent(p config.MergerFSPool) string {
	opts := mergerfsOptsString(p) + ",nofail,x-systemd.mount-timeout=35"
	what := strings.Join(branchPaths(p), ":")
	// Build the bounded readiness gate: wait until each branch is mounted.
	var conds []string
	for _, bp := range branchPaths(p) {
		conds = append(conds, "mountpoint -q "+shellQuote(bp))
	}
	wait := "/usr/bin/timeout 30 /bin/sh -c " + shellQuote("until "+strings.Join(conds, " && ")+"; do sleep 1; done")
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by ZNAS — MergerFS union %q. Do not edit by hand.\n", p.Name)
	b.WriteString("[Unit]\n")
	fmt.Fprintf(&b, "Description=ZNAS MergerFS %s\n", p.Name)
	b.WriteString("After=zfs-import.target zfs-mount.service zfs.target local-fs.target\n")
	b.WriteString("Wants=zfs-mount.service\n\n")
	b.WriteString("[Mount]\n")
	fmt.Fprintf(&b, "What=%s\n", what)
	fmt.Fprintf(&b, "Where=%s\n", p.Mountpoint)
	b.WriteString("Type=fuse.mergerfs\n")
	fmt.Fprintf(&b, "Options=%s\n", opts)
	fmt.Fprintf(&b, "ExecStartPre=%s\n\n", wait)
	b.WriteString("[Install]\nWantedBy=multi-user.target\n")
	return b.String()
}

// ── install / uninstall ──────────────────────────────────────────────────────

const mergerfsReleasesAPI = "https://api.github.com/repos/trapexit/mergerfs/releases/latest"

// InstallMergerFS downloads and installs mergerfs for this host. log receives
// human-readable progress lines.
func InstallMergerFS(log func(string)) error {
	if log == nil {
		log = func(string) {}
	}
	id, codename := mergerfsOSTarget()
	arch := dpkgArch()
	log(fmt.Sprintf("Detected OS: %s %s (%s)", id, codename, arch))

	log("Querying latest mergerfs release from GitHub…")
	req, _ := http.NewRequest("GET", mergerfsReleasesAPI, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("fetch releases: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("GitHub releases returned HTTP %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return fmt.Errorf("decode releases: %w", err)
	}
	url, isDeb, asset := pickMergerFSAsset(rel.Assets, id, codename, arch)
	if url == "" {
		return fmt.Errorf("no mergerfs asset found for %s-%s (%s) in release %s", id, codename, arch, rel.TagName)
	}
	log(fmt.Sprintf("Selected %s (%s)", asset, map[bool]string{true: "distro package", false: "static build"}[isDeb]))

	if err := os.MkdirAll("/tmp/znas-mergerfs", 0755); err != nil {
		return fmt.Errorf("tmp dir: %w", err)
	}
	dl := filepath.Join("/tmp/znas-mergerfs", asset)
	log("Downloading " + asset + "…")
	if err := downloadFile(url, dl); err != nil {
		return fmt.Errorf("download: %w", err)
	}

	if isDeb {
		log("Installing package (apt-get, pulls fuse3)…")
		if out, err := exec.Command("sudo", "apt-get", "install", "-y", dl).CombinedOutput(); err != nil {
			return fmt.Errorf("apt-get install: %w: %s", err, strings.TrimSpace(string(out)))
		}
	} else {
		log("Ensuring fuse3 is present…")
		exec.Command("sudo", "apt-get", "install", "-y", "fuse3").Run() //nolint:errcheck
		log("Extracting static mergerfs → /usr/local/bin…")
		if out, err := exec.Command("sudo", "tar", "-xzf", dl, "-C", "/usr/local", "--strip-components=1").CombinedOutput(); err != nil {
			return fmt.Errorf("extract static: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}

	if err := ensureFuseAllowOther(); err != nil {
		log("warning: could not set user_allow_other in /etc/fuse.conf: " + err.Error())
	}
	if !MergerFSInstalled() {
		return fmt.Errorf("mergerfs binary still not found after install")
	}
	log("mergerfs installed successfully.")
	return nil
}

// UninstallMergerFS unmounts + removes every managed union, then removes the
// package. Source data is never touched.
func UninstallMergerFS(pools []config.MergerFSPool) error {
	for _, p := range pools {
		_ = DestroyMergerFS(p) // best-effort
	}
	exec.Command("sudo", "apt-get", "remove", "-y", "mergerfs").Run()      //nolint:errcheck
	exec.Command("sudo", "rm", "-f", "/usr/local/bin/mergerfs").Run()      //nolint:errcheck
	exec.Command("sudo", "rm", "-f", "/usr/local/bin/mergerfs-fusermount").Run() //nolint:errcheck
	return nil
}

// downloadFile fetches url → dest in-process (no wget/curl dependency; follows
// GitHub's redirect to the release CDN). 5-minute cap for large static builds.
func downloadFile(url, dest string) error {
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, url)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return nil
}

// ensureFuseAllowOther makes sure /etc/fuse.conf has user_allow_other so
// allow_other-mounted unions are reachable by Samba/NFS/containers.
func ensureFuseAllowOther() error {
	b, _ := os.ReadFile("/etc/fuse.conf")
	if strings.Contains(string(b), "user_allow_other") &&
		!strings.Contains(string(b), "#user_allow_other") {
		return nil
	}
	content := strings.TrimRight(string(b), "\n") + "\nuser_allow_other\n"
	cmd := exec.Command("sudo", "tee", "/etc/fuse.conf")
	cmd.Stdin = strings.NewReader(content)
	return cmd.Run()
}

// ── create / destroy / status ────────────────────────────────────────────────

// MergerFSValidateSpec validates a pool spec against live ZFS state and returns
// the spec with branches resolved to ZFS datasets + AllZFS computed.
func MergerFSValidateSpec(p config.MergerFSPool) (config.MergerFSPool, error) {
	if strings.TrimSpace(p.Name) == "" {
		return p, fmt.Errorf("name is required")
	}
	mounts := zfsMountpointList()
	if !mergerfsPathAllowed(p.Mountpoint, mounts) {
		return p, fmt.Errorf("mount point must be under /mnt or a ZFS pool path")
	}
	if len(p.Branches) < 1 {
		return p, fmt.Errorf("at least one source branch is required")
	}
	dsMounts := zfsDatasetMounts()
	allZFS := true
	for i := range p.Branches {
		bp := filepath.Clean(p.Branches[i].Path)
		if !mergerfsPathAllowed(bp, mounts) {
			return p, fmt.Errorf("branch %q must be under /mnt or a ZFS pool path", bp)
		}
		if bp == filepath.Clean(p.Mountpoint) || strings.HasPrefix(filepath.Clean(p.Mountpoint), bp+"/") {
			return p, fmt.Errorf("branch %q overlaps the mount point", bp)
		}
		p.Branches[i].Path = bp
		ds := resolveBranchDataset(bp, dsMounts)
		p.Branches[i].ZFSDataset = ds
		if ds == "" {
			allZFS = false
		}
	}
	p.AllZFS = allZFS
	return p, nil
}

// CreateMergerFS validates, writes the systemd unit, mkdir's the mountpoint,
// enables + starts the union. Returns the normalized pool.
func CreateMergerFS(p config.MergerFSPool) (config.MergerFSPool, error) {
	p, err := MergerFSValidateSpec(p)
	if err != nil {
		return p, err
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	if out, err := exec.Command("sudo", "mkdir", "-p", p.Mountpoint).CombinedOutput(); err != nil {
		return p, fmt.Errorf("mkdir mountpoint: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if err := writeMergerFSUnit(p); err != nil {
		return p, err
	}
	applyMergerFSCompression(p) // best-effort; only when AllZFS + value set
	unit := mergerfsUnitName(p.Mountpoint)
	exec.Command("sudo", "systemctl", "daemon-reload").Run() //nolint:errcheck
	if out, err := exec.Command("sudo", "systemctl", "enable", "--now", unit).CombinedOutput(); err != nil {
		return p, fmt.Errorf("enable %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
	}
	return p, nil
}

func writeMergerFSUnit(p config.MergerFSPool) error {
	unit := mergerfsUnitName(p.Mountpoint)
	cmd := exec.Command("sudo", "tee", "/etc/systemd/system/"+unit)
	cmd.Stdin = strings.NewReader(mergerfsUnitContent(p))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("write unit: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// UpdateMergerFS applies the runtime-settable options (and branch list) from
// `in` onto the existing pool `cur`: mount-time-only fields (mountpoint, fsname,
// allow_other, inodecalc, name) are preserved from cur. Runtime-settable opts
// are pushed to the LIVE mount via its `.mergerfs` control file (best-effort),
// and the systemd unit is rewritten so the change persists across reboot.
func UpdateMergerFS(cur, in config.MergerFSPool) (config.MergerFSPool, error) {
	// Start from cur; overlay only the editable fields.
	next := cur
	next.CreatePolicy = orDefault(in.CreatePolicy, cur.CreatePolicy)
	next.MinFreeSpace = orDefault(in.MinFreeSpace, cur.MinFreeSpace)
	next.MoveOnENOSPC = in.MoveOnENOSPC
	next.CacheFiles = orDefault(in.CacheFiles, cur.CacheFiles)
	next.DropCacheOnClose = in.DropCacheOnClose
	if len(in.Branches) > 0 {
		next.Branches = in.Branches
	}
	// Re-validate (resolves ZFS datasets + recomputes AllZFS; re-checks paths).
	next, err := MergerFSValidateSpec(next)
	if err != nil {
		return cur, err
	}
	// Push runtime-settable options to the live mount (ignored when unmounted).
	ctl := filepath.Join(next.Mountpoint, ".mergerfs")
	if mountpointMounted(next.Mountpoint) {
		setRuntime(ctl, "category.create", next.CreatePolicy)
		setRuntime(ctl, "minfreespace", next.MinFreeSpace)
		setRuntime(ctl, "moveonenospc", mfsBool(next.MoveOnENOSPC))
		setRuntime(ctl, "cache.files", next.CacheFiles)
		setRuntime(ctl, "dropcacheonclose", mfsBool(next.DropCacheOnClose))
		setRuntime(ctl, "branches", strings.Join(branchPaths(next), ":"))
	}
	// Compression change (all-ZFS unions only) applies to every member dataset.
	if in.ZFSCompression != "" {
		next.ZFSCompression = in.ZFSCompression
	}
	applyMergerFSCompression(next)
	// Persist to the unit so reboot keeps the change.
	if err := writeMergerFSUnit(next); err != nil {
		return cur, err
	}
	exec.Command("sudo", "systemctl", "daemon-reload").Run() //nolint:errcheck
	return next, nil
}

// mergerfsCompressionRe allowlists ZFS compression values we'll set (guards
// against shell injection via the config).
var mergerfsCompressionRe = regexp.MustCompile(`^(off|on|lz4|zle|lzjb|gzip|gzip-[1-9]|zstd|zstd-fast|zstd-fast-[0-9]{1,4}|zstd-[0-9]{1,2})$`)

// applyMergerFSCompression sets `compression` on every member ZFS dataset of an
// all-ZFS union so the whole pool shares one algorithm. No-op unless the union
// is all-ZFS and a valid, non-empty value is configured. ZFS compression isn't
// retroactive (only new writes), so this is a safe, cheap property set.
func applyMergerFSCompression(p config.MergerFSPool) {
	if !p.AllZFS || p.ZFSCompression == "" || !mergerfsCompressionRe.MatchString(p.ZFSCompression) {
		return
	}
	seen := map[string]bool{}
	for _, b := range p.Branches {
		if b.ZFSDataset == "" || seen[b.ZFSDataset] {
			continue
		}
		seen[b.ZFSDataset] = true
		exec.Command("sudo", "zfs", "set", "compression="+p.ZFSCompression, b.ZFSDataset).Run() //nolint:errcheck
	}
}

// setRuntime sets a mergerfs runtime option via the control file's xattr.
func setRuntime(ctlFile, key, val string) {
	exec.Command("sudo", "setfattr", "-n", "user.mergerfs."+key, "-v", val, ctlFile).Run() //nolint:errcheck
}

// DestroyMergerFS disables/stops the unit, unmounts, removes the unit file.
// Source data untouched.
func DestroyMergerFS(p config.MergerFSPool) error {
	unit := mergerfsUnitName(p.Mountpoint)
	exec.Command("sudo", "systemctl", "disable", "--now", unit).Run() //nolint:errcheck
	exec.Command("sudo", "umount", p.Mountpoint).Run()                //nolint:errcheck
	exec.Command("sudo", "rm", "-f", "/etc/systemd/system/"+unit).Run() //nolint:errcheck
	exec.Command("sudo", "systemctl", "daemon-reload").Run()          //nolint:errcheck
	return nil
}

// MergerFSBranchUsage is per-branch capacity.
type MergerFSBranchUsage struct {
	Path       string `json:"path"`
	ZFSDataset string `json:"zfs_dataset,omitempty"`
	TotalBytes int64  `json:"total_bytes"`
	UsedBytes  int64  `json:"used_bytes"`
	FreeBytes  int64  `json:"free_bytes"`
	Mounted    bool   `json:"mounted"`
}

// MergerFSStatus is the live view of a union.
type MergerFSStatus struct {
	Name       string                `json:"name"`
	Mountpoint string                `json:"mountpoint"`
	Mounted    bool                  `json:"mounted"`
	AllZFS     bool                  `json:"all_zfs"`
	TotalBytes int64                 `json:"total_bytes"`
	UsedBytes  int64                 `json:"used_bytes"`
	FreeBytes  int64                 `json:"free_bytes"`
	Branches   []MergerFSBranchUsage `json:"branches"`
}

// MergerFSGetStatus returns live status for a pool.
func MergerFSGetStatus(p config.MergerFSPool) MergerFSStatus {
	st := MergerFSStatus{Name: p.Name, Mountpoint: p.Mountpoint, AllZFS: p.AllZFS}
	st.Mounted = mountpointMounted(p.Mountpoint)
	if st.Mounted {
		st.TotalBytes, st.UsedBytes, st.FreeBytes = dfBytes(p.Mountpoint)
	}
	for _, b := range p.Branches {
		u := MergerFSBranchUsage{Path: b.Path, ZFSDataset: b.ZFSDataset, Mounted: mountpointMounted(b.Path)}
		if _, err := os.Stat(b.Path); err == nil {
			u.TotalBytes, u.UsedBytes, u.FreeBytes = dfBytes(b.Path)
		}
		st.Branches = append(st.Branches, u)
	}
	sort.Slice(st.Branches, func(i, j int) bool { return st.Branches[i].Path < st.Branches[j].Path })
	return st
}

func mountpointMounted(p string) bool {
	return exec.Command("mountpoint", "-q", p).Run() == nil
}

// dfBytes returns total/used/free bytes for the filesystem at path.
func dfBytes(path string) (total, used, free int64) {
	out, err := exec.Command("df", "-B1", "--output=size,used,avail", path).Output()
	if err != nil {
		return 0, 0, 0
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return 0, 0, 0
	}
	fmt.Sscanf(strings.TrimSpace(lines[len(lines)-1]), "%d %d %d", &total, &used, &free)
	return total, used, free
}

// ── small helpers ────────────────────────────────────────────────────────────

func orDefault(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}
func mfsBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// shellQuote single-quotes a string for safe embedding in an sh -c command.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
