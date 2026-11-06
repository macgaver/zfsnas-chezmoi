package system

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// zfsResolvedMountpoint returns the actual kernel mount point for a ZFS
// dataset, walking up the hierarchy until it finds a mounted ancestor.
// LXD storage datasets (e.g. "tank/lxd-base") are never mounted themselves;
// in that case we use the root pool's mount point.
//
// Special-case: if the walk reaches the pool root (no slash) and that pool
// has mountpoint=legacy with no kernel mount, set its mountpoint to /<pool>
// and mount it. This happens when Incus was given a separate zpool as its
// storage backend (e.g. `tank-incus`) — the zpool root is unmounted by
// default but its child datasets are all `legacy` too, so there's no
// mounted ancestor to walk to. The only safe place for the .isos directory
// is the pool root itself.
func zfsResolvedMountpoint(dataset string) (string, error) {
	// Walk from the given dataset up to the root pool looking for a mounted path.
	current := dataset
	for current != "" {
		mp, err := zfsOneMountpoint(current)
		if err == nil && filepath.IsAbs(mp) {
			return mp, nil
		}
		// Go up one level (strip last component).
		idx := strings.LastIndex(current, "/")
		if idx < 0 {
			break
		}
		current = current[:idx]
	}
	// Walk fell off the top — try to mount the pool root.
	root := dataset
	if i := strings.IndexByte(root, '/'); i >= 0 {
		root = root[:i]
	}
	if mp, err := mountPoolRootIfLegacy(root); err == nil {
		return mp, nil
	}
	return "", fmt.Errorf("cannot find a mounted ancestor for ZFS dataset %q", dataset)
}

// mountPoolRootIfLegacy gives an unmounted, legacy-mountpoint zpool root a
// real mountpoint at /<pool> and mounts it. Used as a fallback when the
// pool was created by Incus with no usable mountpoint anywhere in the
// hierarchy. Idempotent: if the mountpoint is already set and the dataset
// is mounted, returns the existing path.
func mountPoolRootIfLegacy(pool string) (string, error) {
	// Probe current mountpoint property.
	out, err := exec.Command("zfs", "get", "-H", "-o", "value", "mountpoint", pool).Output()
	if err != nil {
		return "", err
	}
	mp := strings.TrimSpace(string(out))
	if filepath.IsAbs(mp) {
		// Already has an absolute mountpoint — make sure it's mounted.
		if mountedOut, _ := exec.Command("zfs", "mount").Output(); strings.Contains(string(mountedOut), pool+" "+mp) {
			return mp, nil
		}
		if out, err := exec.Command("sudo", "/usr/sbin/zfs", "mount", pool).CombinedOutput(); err != nil {
			return "", fmt.Errorf("zfs mount %s: %s", pool, strings.TrimSpace(string(out)))
		}
		return mp, nil
	}
	// mountpoint is "legacy" / "none" / "-" — set to /<pool> and mount.
	target := "/" + pool
	if out, err := exec.Command("sudo", "/usr/sbin/zfs", "set", "mountpoint="+target, pool).CombinedOutput(); err != nil {
		return "", fmt.Errorf("zfs set mountpoint=%s %s: %s", target, pool, strings.TrimSpace(string(out)))
	}
	return target, nil
}

// zfsOneMountpoint returns the mount point for a single dataset without
// walking ancestors. Returns an error when the dataset is unmounted or
// has mountpoint=none/legacy-and-unmounted.
func zfsOneMountpoint(dataset string) (string, error) {
	out, err := exec.Command("zfs", "get", "-H", "-o", "value", "mountpoint", dataset).Output()
	if err != nil {
		return "", err
	}
	mp := strings.TrimSpace(string(out))
	switch mp {
	case "", "none", "-":
		return "", fmt.Errorf("dataset %q has no mountpoint", dataset)
	case "legacy":
		// Mounted via fstab — ask the kernel.
		if fm, err2 := exec.Command("findmnt", "-n", "-o", "TARGET", "--source", dataset).Output(); err2 == nil {
			if t := strings.TrimSpace(string(fm)); t != "" {
				return t, nil
			}
		}
		// Fallback: scan `zfs mount` output.
		if zml, err3 := exec.Command("zfs", "mount").Output(); err3 == nil {
			for _, line := range strings.Split(string(zml), "\n") {
				parts := strings.Fields(line)
				if len(parts) >= 2 && parts[0] == dataset {
					return parts[1], nil
				}
			}
		}
		return "", fmt.Errorf("dataset %q has legacy mountpoint but is not mounted", dataset)
	}
	return mp, nil
}

// isoNameRe validates safe ISO filenames: letters, digits, dots, underscores, hyphens.
// Must end in .iso (case-insensitive).
var isoNameRe = regexp.MustCompile(`^[A-Za-z0-9._\-]+\.iso$`)

// LXDISOInfo describes one ISO file. Pool is only populated by
// LXDListISOsAllPools (callers asking about a single pool already know
// the pool name); when present it tells the UI which storage pool the
// ISO lives in so the swap request can be routed back to the right one.
type LXDISOInfo struct {
	Name      string    `json:"name"`
	SizeBytes int64     `json:"size_bytes"`
	Modified  time.Time `json:"modified"`
	Pool      string    `json:"pool,omitempty"`
}

// LXDISODir returns the absolute path of the ISO directory for the given Incus
// storage pool.
//
// For ZFS-backed pools the directory is at the ZFS pool mountpoint; for
// dir/btrfs pools it is adjacent to the pool source path. Incus on Debian
// is deb-only (no snap), so QEMU sees the host filesystem directly and the
// ZFS pool's /<mount>/.isos path is reachable without any fd-passing trick.
func LXDISODir(lxdPool string) (string, error) {
	out, err := exec.Command("incus", "query", "/1.0/storage-pools/"+lxdPool).Output()
	if err != nil {
		return "", fmt.Errorf("query LXD pool %q: %w", lxdPool, err)
	}
	var sp struct {
		Driver string            `json:"driver"`
		Config map[string]string `json:"config"`
	}
	if err := json.Unmarshal(out, &sp); err != nil {
		return "", fmt.Errorf("parse pool %q: %w", lxdPool, err)
	}

	var base string
	switch sp.Driver {
	case "zfs":
		zfsPool := sp.Config["zfs.pool_name"]
		if zfsPool == "" {
			zfsPool = sp.Config["source"]
		}
		if zfsPool == "" {
			return "", fmt.Errorf("cannot determine ZFS pool for %q", lxdPool)
		}
		mp, err := zfsResolvedMountpoint(zfsPool)
		if err != nil {
			return "", err
		}
		base = mp
	case "dir", "btrfs", "lvm", "lvm-cluster":
		src := sp.Config["source"]
		if src == "" {
			return "", fmt.Errorf("pool %q has no source path configured", lxdPool)
		}
		if !filepath.IsAbs(src) {
			return "", fmt.Errorf("pool %q source path %q is not absolute", lxdPool, src)
		}
		base = src
	default:
		return "", fmt.Errorf("pool %q has unsupported driver %q for ISO storage", lxdPool, sp.Driver)
	}

	return filepath.Join(base, ".isos"), nil
}

// LXDListISOs returns all .iso files in the pool's .isos directory.
// Returns an empty slice (not an error) when the directory does not exist yet.
func LXDListISOs(lxdPool string) ([]LXDISOInfo, error) {
	dir, err := LXDISODir(lxdPool)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return []LXDISOInfo{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read iso dir: %w", err)
	}
	var out []LXDISOInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(strings.ToLower(n), ".iso") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, LXDISOInfo{
			Name:      n,
			SizeBytes: info.Size(),
			Modified:  info.ModTime().UTC(),
		})
	}
	if out == nil {
		out = []LXDISOInfo{}
	}
	return out, nil
}

// LXDListISOsAllPools enumerates every imported ZFS pool and returns the
// union of ISOs from each pool's /<mountpoint>/.isos directory, tagged
// with the originating ZFS pool name. We deliberately walk ZFS pools
// rather than Incus storage pools — an operator might drop an installer
// ISO under /<pool>/.isos on a ZFS pool that isn't (yet) registered as
// an Incus backend, and the VGA picker should still surface it. Pools
// without an .isos directory, or whose mountpoint we can't resolve, are
// silently skipped: the goal is to show every disc that's actually
// attachable, not to fail because one pool is misconfigured.
func LXDListISOsAllPools() ([]LXDISOInfo, error) {
	out, err := exec.Command("sudo", "zpool", "list", "-H", "-o", "name").Output()
	if err != nil {
		return nil, fmt.Errorf("zpool list: %w", err)
	}
	var isos []LXDISOInfo
	for _, name := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		mp, err := zfsResolvedMountpoint(name)
		if err != nil {
			continue
		}
		dir := filepath.Join(mp, ".isos")
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n := e.Name()
			if !strings.HasSuffix(strings.ToLower(n), ".iso") {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			isos = append(isos, LXDISOInfo{
				Name:      n,
				SizeBytes: info.Size(),
				Modified:  info.ModTime().UTC(),
				Pool:      name,
			})
		}
	}
	if isos == nil {
		isos = []LXDISOInfo{}
	}
	return isos, nil
}

// LXDResolveISOPath returns the absolute path of an ISO file given a pool
// name and filename. The pool may be either an Incus storage pool or a
// raw ZFS pool — we try the Incus resolver first (preserves the existing
// per-Incus-pool layout) and fall back to <zfs-mountpoint>/.isos for ZFS
// pools that haven't been registered with Incus. This mirrors the union
// that LXDListISOsAllPools surfaces to the picker.
func LXDResolveISOPath(pool, filename string) (string, error) {
	if !isoNameRe.MatchString(filename) {
		return "", fmt.Errorf("invalid ISO filename")
	}
	if dir, err := LXDISODir(pool); err == nil {
		p := filepath.Join(dir, filename)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	mp, err := zfsResolvedMountpoint(pool)
	if err != nil {
		return "", fmt.Errorf("resolve pool %q: %w", pool, err)
	}
	p := filepath.Join(mp, ".isos", filename)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("iso %q not found on pool %q", filename, pool)
	}
	return p, nil
}

// LXDDeleteISO deletes one ISO file from the pool's .isos directory.
// Uploads run via `sudo tee` (root-owned files) so deletes must use sudo too.
func LXDDeleteISO(lxdPool, filename string) error {
	if !isoNameRe.MatchString(filename) {
		return fmt.Errorf("invalid ISO filename")
	}
	dir, err := LXDISODir(lxdPool)
	if err != nil {
		return err
	}
	target := filepath.Join(dir, filename)
	if err := os.Remove(target); err == nil {
		return nil
	} else if !os.IsPermission(err) && !os.IsNotExist(err) {
		// Fall through to sudo only on permission errors / missing file.
		// Other errors (read-only fs, etc.) surface immediately.
		return err
	}
	if out, err := exec.Command("sudo", "/usr/bin/rm", "-f", target).CombinedOutput(); err != nil {
		return fmt.Errorf("rm: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// LXDSaveISO streams r into <isoDir>/<filename>, creating the directory as needed.
// Returns the absolute path of the saved file.
func LXDSaveISO(lxdPool, filename string, r io.Reader) (string, error) {
	if !isoNameRe.MatchString(filename) {
		return "", fmt.Errorf("invalid ISO filename")
	}
	dir, err := LXDISODir(lxdPool)
	if err != nil {
		return "", err
	}
	// The ISO directory sits inside a ZFS pool root owned by root; use sudo mkdir.
	if out, err2 := exec.Command("sudo", "mkdir", "-p", dir).CombinedOutput(); err2 != nil {
		return "", fmt.Errorf("create iso dir: %s", strings.TrimSpace(string(out)))
	}
	// Ensure the zfsnas process user can write files into the directory.
	if out, err2 := exec.Command("sudo", "chmod", "0775", dir).CombinedOutput(); err2 != nil {
		return "", fmt.Errorf("chmod iso dir: %s", strings.TrimSpace(string(out)))
	}
	dest := filepath.Join(dir, filename)
	// The directory is root-owned; use sudo tee to write the file as root.
	cmd := exec.Command("sudo", "tee", dest)
	cmd.Stdin = r
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		_ = exec.Command("sudo", "rm", "-f", dest).Run()
		return "", fmt.Errorf("write iso: %w", err)
	}
	return dest, nil
}

// ── ISO fetch from URL ─────────────────────────────────────────────────────

// LXDISOFetchJob tracks one server-side ISO download. Stored in
// `lxdISOFetchJobs` keyed by job ID; the HTTP layer polls it for the
// activity-bar progress display.
type LXDISOFetchJob struct {
	URL        string `json:"url"`
	Pool       string `json:"pool"`
	Name       string `json:"name"`
	BytesDone  int64  `json:"bytes_done"`
	TotalBytes int64  `json:"total_bytes"`
	Status     string `json:"status"` // "running" | "done" | "error"
	Error      string `json:"error,omitempty"`
	StartedAt  int64  `json:"started_at"`
	mu         sync.Mutex
	cancel     context.CancelFunc
}

var (
	lxdISOFetchJobs   sync.Map // jobID → *LXDISOFetchJob
	lxdISOFetchTicker int64    // monotonic counter for IDs
)

// NewLXDISOFetchJobID returns a short numeric job ID. Plenty for the
// session lifetime; not persistent across restarts.
func NewLXDISOFetchJobID() string {
	id := atomic.AddInt64(&lxdISOFetchTicker, 1)
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), id)
}

// LXDISOFetchJobGet returns a job snapshot by ID, or nil if absent.
func LXDISOFetchJobGet(id string) *LXDISOFetchJob {
	if v, ok := lxdISOFetchJobs.Load(id); ok {
		j := v.(*LXDISOFetchJob)
		j.mu.Lock()
		defer j.mu.Unlock()
		// Return a field snapshot so callers can't race the writer. Copy
		// fields explicitly: `*j` would also copy the held mutex and cancel.
		return &LXDISOFetchJob{
			URL:        j.URL,
			Pool:       j.Pool,
			Name:       j.Name,
			BytesDone:  j.BytesDone,
			TotalBytes: j.TotalBytes,
			Status:     j.Status,
			Error:      j.Error,
			StartedAt:  j.StartedAt,
		}
	}
	return nil
}

// LXDISOFetchStart begins a background download into pool's ISO dir.
// Returns the job ID immediately; progress is observable via
// LXDISOFetchJobGet.
//
// Validation order: (a) url is http(s); (b) filename matches isoNameRe;
// (c) on completion, sniff bytes 0x8001..0x8005 for "CD001" — the ISO
// 9660 Primary Volume Descriptor signature. Hybrid bootable ISOs still
// keep the descriptor at that offset, so the check passes for every
// well-formed image. Files that fail are deleted before the job flips
// to "error" — no half-baked .iso on disk.
//
// onComplete (optional) is invoked from the goroutine when the job
// terminates — used by the handler layer to write an audit log entry
// stamped with the user/role of the request that started the fetch.
// success is true iff the ISO landed at its final path; finalName is
// the resolved filename (which may differ from suggestedName when it
// was empty and we derived from the URL); errMsg is "" on success.
func LXDISOFetchStart(pool, rawURL, suggestedName string, onComplete func(success bool, errMsg, finalName string)) (string, error) {
	if pool == "" {
		return "", fmt.Errorf("pool is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("only http(s) URLs are accepted")
	}
	// Resolve filename: prefer the user-supplied name; otherwise derive
	// from the URL path. Either way it must end .iso and pass the
	// upload-side regex (no path traversal, no shell metas).
	name := strings.TrimSpace(suggestedName)
	if name == "" {
		name = filepath.Base(u.Path)
		if i := strings.IndexByte(name, '?'); i >= 0 {
			name = name[:i]
		}
	}
	if name == "" || name == "." || name == "/" {
		return "", fmt.Errorf("could not derive a filename from the URL — supply one explicitly")
	}
	if !strings.HasSuffix(strings.ToLower(name), ".iso") {
		name = name + ".iso"
	}
	if !isoNameRe.MatchString(name) {
		return "", fmt.Errorf("invalid ISO filename %q (allowed: letters, digits, dots, underscores, hyphens; must end .iso)", name)
	}

	dir, err := LXDISODir(pool)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithCancel(context.Background())
	job := &LXDISOFetchJob{
		URL:       rawURL,
		Pool:      pool,
		Name:      name,
		Status:    "running",
		StartedAt: time.Now().Unix(),
		cancel:    cancel,
	}
	id := NewLXDISOFetchJobID()
	lxdISOFetchJobs.Store(id, job)

	go func() {
		defer cancel()
		err := lxdRunISOFetch(ctx, job, dir)
		job.mu.Lock()
		if err != nil {
			job.Status = "error"
			job.Error = err.Error()
		} else {
			job.Status = "done"
		}
		finalName := job.Name
		job.mu.Unlock()
		if onComplete != nil {
			if err != nil {
				onComplete(false, err.Error(), finalName)
			} else {
				onComplete(true, "", finalName)
			}
		}
		// Best-effort GC: drop completed/errored jobs after 10 min so the
		// map doesn't accrete forever during a long ZNAS session.
		go func() {
			time.Sleep(10 * time.Minute)
			lxdISOFetchJobs.Delete(id)
		}()
	}()
	return id, nil
}

// lxdRunISOFetch is the actual download body. Streams to a temp file
// inside the same pool's ISO directory (to keep the rename atomic), then
// validates the ISO 9660 magic and moves it to the target name.
func lxdRunISOFetch(ctx context.Context, job *LXDISOFetchJob, dir string) error {
	// Make sure the ISO directory exists before we touch it. LXDSaveISO
	// already does this on upload; mirror it here.
	if out, err := exec.Command("sudo", "mkdir", "-p", dir).CombinedOutput(); err != nil {
		return fmt.Errorf("mkdir %s: %s", dir, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("sudo", "chmod", "0775", dir).CombinedOutput(); err != nil {
		return fmt.Errorf("chmod %s: %s", dir, strings.TrimSpace(string(out)))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, job.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ZNAS/iso-fetch")
	client := &http.Client{Timeout: 0} // no timeout; ISOs can take hours on slow links
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("download: HTTP %d %s", resp.StatusCode, resp.Status)
	}
	if resp.ContentLength > 0 {
		job.mu.Lock()
		job.TotalBytes = resp.ContentLength
		job.mu.Unlock()
	}

	// Stream to a temp file in the same dir (so the final move is a
	// rename inside one filesystem). The .part suffix tells anybody
	// looking that this isn't a finished file.
	tmpName := job.Name + ".part"
	tmpPath := filepath.Join(dir, tmpName)
	// `sudo tee` keeps ownership consistent with uploads (root-owned).
	cmd := exec.CommandContext(ctx, "sudo", "tee", tmpPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	// Pipe response → progress counter → tee. Errors from copy abort
	// the tee process so we don't leave a half-written file.
	pc := &progressCountingWriter{job: job}
	mw := io.MultiWriter(stdin, pc)
	_, copyErr := io.Copy(mw, resp.Body)
	stdin.Close()
	if waitErr := cmd.Wait(); waitErr != nil && copyErr == nil {
		copyErr = fmt.Errorf("tee: %w", waitErr)
	}
	if copyErr != nil {
		_ = exec.Command("sudo", "rm", "-f", tmpPath).Run()
		return copyErr
	}

	// ISO 9660 magic check: bytes 0x8001..0x8005 == "CD001".
	if err := lxdAssertISO9660(tmpPath); err != nil {
		_ = exec.Command("sudo", "rm", "-f", tmpPath).Run()
		return fmt.Errorf("downloaded file is not an ISO 9660 image: %w", err)
	}

	// Move into place. mv stays atomic on the same filesystem.
	finalPath := filepath.Join(dir, job.Name)
	if out, err := exec.Command("sudo", "mv", "-f", tmpPath, finalPath).CombinedOutput(); err != nil {
		_ = exec.Command("sudo", "rm", "-f", tmpPath).Run()
		return fmt.Errorf("mv: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// lxdAssertISO9660 reads the volume descriptor sector and verifies the
// "CD001" identifier. Used as a cheap "is this actually an ISO?" gate
// after a URL fetch — a HTML 404 page or an .img with the wrong name
// fails quickly here.
func lxdAssertISO9660(path string) error {
	// Use sudo cat to bypass the root-owned tmp file's mode. We only need
	// 5 bytes; pipe through head so we don't slurp the whole file.
	out, err := exec.Command("sudo", "/usr/bin/dd",
		"if="+path, "bs=1", "skip=32769", "count=5", "status=none").Output()
	if err != nil {
		return fmt.Errorf("read magic: %w", err)
	}
	if string(out) != "CD001" {
		return fmt.Errorf("expected ISO 9660 signature CD001 at offset 0x8001, got %q", string(out))
	}
	return nil
}

// progressCountingWriter atomically increments BytesDone on the job as
// the response stream flows through. Used inside the io.MultiWriter that
// also feeds `sudo tee`.
type progressCountingWriter struct {
	job *LXDISOFetchJob
}

func (w *progressCountingWriter) Write(p []byte) (int, error) {
	n := len(p)
	w.job.mu.Lock()
	w.job.BytesDone += int64(n)
	w.job.mu.Unlock()
	return n, nil
}
