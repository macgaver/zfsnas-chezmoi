// USB appliance image upgrades: detect a newer image on GitHub
// (macgaver/znas-usb-appliance), download it to the persist store, verify its
// signature, and hand it to zfsnas-upgrade-image, which rewrites the image
// region of the stick and leaves the settings partition alone.
package handlers

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"zfsnas/internal/audit"
	"zfsnas/internal/updater"
	"zfsnas/system"
)

const (
	applianceUpgradeScript = "/usr/local/sbin/zfsnas-upgrade-image"
	// The write runs in its own transient unit, NOT as a child of the portal:
	// restarting the portal (Instant Update, a crash) kills everything in its
	// cgroup, and a dd killed halfway leaves a stick that does not boot.
	applianceUpgradeUnit = "zfsnas-image-upgrade"
	// /run is tmpfs: the write's log and exit code are only meaningful until
	// the reboot that starts the new image.
	applianceUpgradeRunDir = "/run/zfsnas-image-upgrade"
	applianceCheckMaxAge   = 6 * time.Hour
	// Download flush interval (see downloadApplianceFile).
	applianceDownloadSyncEvery = 32 << 20
)

// Package-level so tests could point them elsewhere.
var (
	applianceReleaseSource  = updater.CheckApplianceReleases
	applianceDownloadClient = &http.Client{} // no total timeout: 1.5 GB on a slow link
)

type applianceCheckResult struct {
	CheckedAt time.Time
	Latest    *updater.ApplianceImageRelease
	Err       string
}

var (
	applianceCheckMu    sync.Mutex
	applianceCheckCache applianceCheckResult

	applianceJobMu sync.Mutex
	applianceJob   applianceUpgradeJob
)

// applianceUpgradeJob tracks the download and verify phases in memory. The
// write phase is read back from applianceUpgradeRunDir instead, so it is
// still reported correctly after a portal restart.
type applianceUpgradeJob struct {
	Phase    string // "", "downloading", "verifying", "failed"
	Version  string
	Mode     string // "stage": write, then wait for the admin; "reboot": reboot once written
	Bytes    int64  // downloading: bytes fetched; verifying: bytes hashed
	Total    int64
	StagedOn string // where the image is downloaded: "pool tank" / "the USB stick"
	Err      string
	cancel   context.CancelFunc
}

// applianceStickStageDir is the fallback download location: the settings
// partition on the stick itself.
func applianceStickStageDir() string {
	return filepath.Join(system.AppliancePersistStore(), "upgrade")
}

// applianceTmpDirName is created at the root of a ZFS pool to hold the
// download when a pool is available.
const applianceTmpDirName = ".znas-appliance-tmp"

// applianceStaging is where an upgrade downloads the image.
type applianceStaging struct {
	Dir  string
	Desc string // "pool tank" or "the USB stick", for the UI and audit log
}

// zfsPoolRoot is a pool's root dataset as a download candidate.
type zfsPoolRoot struct {
	Name       string
	Mountpoint string
	Mounted    bool
	ReadOnly   bool
	Healthy    bool
	Avail      int64
}

// chooseApplianceStaging prefers a ZFS pool over the stick: pool disks are
// far faster than a USB stick, and downloading there spares the stick ~1.5 GB
// of writes per upgrade (it still takes the image write itself). The stick
// is used only when no pool can take the file.
func chooseApplianceStaging(size int64) applianceStaging {
	if p := pickApplianceStagingPool(listZFSPoolRoots(), size); p != nil {
		return applianceStaging{Dir: filepath.Join(p.Mountpoint, applianceTmpDirName), Desc: "pool " + p.Name}
	}
	return applianceStaging{Dir: applianceStickStageDir(), Desc: "the USB stick"}
}

// pickApplianceStagingPool returns the healthy, mounted, writable pool with
// the most free space that fits the image with a margin, or nil.
func pickApplianceStagingPool(pools []zfsPoolRoot, size int64) *zfsPoolRoot {
	var best *zfsPoolRoot
	for i := range pools {
		p := &pools[i]
		if !p.Healthy || !p.Mounted || p.ReadOnly || !strings.HasPrefix(p.Mountpoint, "/") {
			continue
		}
		if p.Avail < size+2<<30 {
			continue
		}
		if best == nil || p.Avail > best.Avail {
			best = p
		}
	}
	return best
}

// listZFSPoolRoots reads every pool's root dataset. Errors (no ZFS, no pools)
// just mean no candidates.
func listZFSPoolRoots() []zfsPoolRoot {
	health := map[string]bool{}
	if out, err := exec.Command("zpool", "list", "-H", "-o", "name,health").Output(); err == nil {
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if f := strings.Fields(l); len(f) == 2 {
				health[f[0]] = f[1] == "ONLINE"
			}
		}
	}
	out, err := exec.Command("zfs", "list", "-H", "-p", "-d", "0",
		"-o", "name,mountpoint,mounted,readonly,available").Output()
	if err != nil {
		return nil
	}
	return parseZFSPoolRoots(string(out), health)
}

func parseZFSPoolRoots(out string, health map[string]bool) []zfsPoolRoot {
	var pools []zfsPoolRoot
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(l, "\t")
		if len(f) != 5 {
			continue
		}
		avail, _ := strconv.ParseInt(f[4], 10, 64)
		pools = append(pools, zfsPoolRoot{
			Name: f[0], Mountpoint: f[1], Mounted: f[2] == "yes", ReadOnly: f[3] == "on",
			Healthy: health[f[0]], Avail: avail,
		})
	}
	return pools
}

// clearApplianceStaged removes staged files that are not for keepPrefix, in
// every place an upgrade may have staged one (the stick and each pool).
func clearApplianceStaged(keepDir, keepPrefix string) {
	dirs := []string{applianceStickStageDir()}
	for _, p := range listZFSPoolRoots() {
		if p.Mounted && strings.HasPrefix(p.Mountpoint, "/") {
			dirs = append(dirs, filepath.Join(p.Mountpoint, applianceTmpDirName))
		}
	}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if d == keepDir && keepPrefix != "" && strings.HasPrefix(e.Name(), keepPrefix) {
				continue
			}
			os.Remove(filepath.Join(d, e.Name()))
		}
		if d != applianceStickStageDir() && d != keepDir {
			os.Remove(d) // only succeeds once empty
		}
	}
}

// refreshApplianceCheck asks GitHub for the newest published image.
func refreshApplianceCheck() applianceCheckResult {
	res := applianceCheckResult{CheckedAt: time.Now()}
	rels, err := applianceReleaseSource()
	if err != nil {
		res.Err = err.Error()
	} else {
		res.Latest = newestApplianceRelease(rels)
	}
	applianceCheckMu.Lock()
	applianceCheckCache = res
	applianceCheckMu.Unlock()
	return res
}

func newestApplianceRelease(rels []updater.ApplianceImageRelease) *updater.ApplianceImageRelease {
	var best *updater.ApplianceImageRelease
	for i := range rels {
		if best == nil || semverGreater(rels[i].Version, best.Version) {
			best = &rels[i]
		}
	}
	return best
}

func cachedApplianceCheck() applianceCheckResult {
	applianceCheckMu.Lock()
	res := applianceCheckCache
	applianceCheckMu.Unlock()
	if res.CheckedAt.IsZero() || time.Since(res.CheckedAt) > applianceCheckMaxAge {
		return refreshApplianceCheck()
	}
	return res
}

// ---- write phase (transient systemd unit) ---------------------------------

type applianceWriteState struct {
	Phase   string // "", "writing", "done", "failed"
	Version string
	Mode    string // "stage" or "reboot"
	Bytes   int64
	Total   int64
	Tracked bool // Bytes comes from the stick's own write counter
	Log     []string
	Err     string
}

// The run dir's meta file, one value per line (written before the unit starts).
type applianceWriteMeta struct {
	Version  string
	Total    int64
	Mode     string
	Disk     string // stick disk name, e.g. "sdc"
	Baseline int64  // its sectors-written counter when the write started
}

func (m applianceWriteMeta) String() string {
	return fmt.Sprintf("%s\n%d\n%s\n%s\n%d\n", m.Version, m.Total, m.Mode, m.Disk, m.Baseline)
}

func readApplianceWriteMeta() applianceWriteMeta {
	var m applianceWriteMeta
	f := strings.Split(readTrim(filepath.Join(applianceUpgradeRunDir, "meta")), "\n")
	get := func(i int) string {
		if i < len(f) {
			return strings.TrimSpace(f[i])
		}
		return ""
	}
	m.Version = get(0)
	m.Total, _ = strconv.ParseInt(get(1), 10, 64)
	m.Mode = get(2)
	m.Disk = get(3)
	m.Baseline, _ = strconv.ParseInt(get(4), 10, 64)
	return m
}

// applianceStickDisk returns the disk holding the appliance image ("sdc"),
// found the same way zfsnas-upgrade-image finds it: by the ISO volume label.
func applianceStickDisk() string {
	part, err := filepath.EvalSymlinks("/dev/disk/by-label/ZFSNAS-USB")
	if err != nil {
		return ""
	}
	return blockDiskOf(filepath.Base(part), "/sys/class/block")
}

// blockDiskOf maps a block device name to its whole disk: "sdc1" -> "sdc",
// "sdc" -> "sdc". An ISO carries its label on the whole disk AND on its
// first partition, so either can come in. The partition's real sysfs dir
// sits inside its disk's, so resolve the link FIRST and then take the parent
// — joining ".." onto the link is cleaned away lexically before any link is
// followed and yields /sys/class/block ("block").
func blockDiskOf(name, sysClassBlock string) string {
	real, err := filepath.EvalSymlinks(filepath.Join(sysClassBlock, name))
	if err != nil {
		return ""
	}
	if _, err := os.Stat(filepath.Join(real, "partition")); err != nil {
		return name
	}
	return filepath.Base(filepath.Dir(real))
}

// diskSectorsWritten reads the kernel's sectors-written counter for a disk
// (/sys/block/<disk>/stat, field 7; always 512-byte units).
func diskSectorsWritten(disk string) int64 {
	f := strings.Fields(readTrim(filepath.Join("/sys/block", disk, "stat")))
	if len(f) < 7 {
		return -1
	}
	n, err := strconv.ParseInt(f[6], 10, 64)
	if err != nil {
		return -1
	}
	return n
}

var ddBytesRe = regexp.MustCompile(`^(\d+) bytes`)

// readApplianceWriteState reconstructs the write phase from the run dir:
// rc present = finished (0 ok), log present + unit active = writing.
func readApplianceWriteState() applianceWriteState {
	var st applianceWriteState
	logB, err := os.ReadFile(filepath.Join(applianceUpgradeRunDir, "log"))
	if err != nil {
		return st
	}
	meta := readApplianceWriteMeta()
	st.Version, st.Total, st.Mode = meta.Version, meta.Total, meta.Mode
	st.Log, st.Bytes = splitDDLog(string(logB))
	// dd's own count is what it handed to the page cache, which on a slow
	// stick runs minutes ahead of the device and then sits at 100% during the
	// final fsync. The disk's sectors-written counter is what actually
	// reached the stick.
	if meta.Disk != "" && meta.Baseline >= 0 {
		if now := diskSectorsWritten(meta.Disk); now >= meta.Baseline {
			st.Bytes = min((now-meta.Baseline)*512, st.Total)
			st.Tracked = true
		}
	}

	rcStr := readTrim(filepath.Join(applianceUpgradeRunDir, "rc"))
	switch {
	case rcStr == "0":
		st.Phase = "done"
		st.Bytes = st.Total
	case rcStr != "":
		st.Phase = "failed"
		st.Err = lastNonEmpty(st.Log)
	case exec.Command("systemctl", "is-active", "--quiet", applianceUpgradeUnit).Run() == nil:
		st.Phase = "writing"
	default:
		// Log without rc and no live unit: the unit was killed.
		st.Phase = "failed"
		st.Err = "the image write stopped unexpectedly — the stick may not boot; run the upgrade again before rebooting"
	}
	return st
}

// splitDDLog turns the script's output into display lines. dd redraws its
// progress with \r, so those updates collapse into the latest one, whose byte
// count is returned for the progress bar.
func splitDDLog(s string) (lines []string, bytes int64) {
	for _, l := range strings.Split(s, "\n") {
		parts := strings.Split(l, "\r")
		l = strings.TrimSpace(parts[len(parts)-1])
		for _, p := range parts {
			if m := ddBytesRe.FindStringSubmatch(strings.TrimSpace(p)); m != nil {
				bytes, _ = strconv.ParseInt(m[1], 10, 64)
			}
		}
		if l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > 60 {
		lines = lines[len(lines)-60:]
	}
	return lines, bytes
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func lastNonEmpty(lines []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(lines[i]); s != "" {
			return strings.TrimPrefix(s, "error: ")
		}
	}
	return "the upgrade script failed"
}

// ApplianceImageWriteActive reports whether the stick is being rewritten right
// now. Reboot and shutdown refuse while it is: a half-written image does not
// boot.
func ApplianceImageWriteActive() bool {
	return system.ApplianceMode() && readApplianceWriteState().Phase == "writing"
}

// ---- HTTP -----------------------------------------------------------------

// HandleApplianceUpgradeStatus: GET /api/appliance/upgrade
func HandleApplianceUpgradeStatus(w http.ResponseWriter, r *http.Request) {
	if !system.ApplianceMode() {
		jsonOK(w, map[string]any{"appliance": false})
		return
	}
	jsonOK(w, applianceUpgradeStatus(cachedApplianceCheck()))
}

// HandleApplianceUpgradeCheck: POST /api/appliance/upgrade/check — forces a
// fresh GitHub lookup.
func HandleApplianceUpgradeCheck(w http.ResponseWriter, r *http.Request) {
	if !system.ApplianceMode() {
		jsonErr(w, http.StatusBadRequest, "not running on the USB appliance")
		return
	}
	jsonOK(w, applianceUpgradeStatus(refreshApplianceCheck()))
}

func applianceUpgradeStatus(chk applianceCheckResult) map[string]any {
	img := system.ApplianceImageInfo()
	kernel := readTrim("/proc/sys/kernel/osrelease")

	out := map[string]any{
		"appliance":       true,
		"image_version":   img.Version,
		"display_version": img.Display,
		"kernel":          kernel,
		"toram":           system.ApplianceBootedToRAM(),
		"checked_at":      chk.CheckedAt,
		"check_error":     chk.Err,
		"newer":           false,
	}
	if chk.Latest != nil {
		out["latest"] = chk.Latest
		out["newer"] = img.Version != "" && semverGreater(chk.Latest.Version, img.Version)
	}

	// Job: an active download/verify wins; otherwise report the write phase.
	applianceJobMu.Lock()
	job := applianceJob
	applianceJobMu.Unlock()
	jobOut := map[string]any{"phase": ""}
	if job.Phase == "downloading" || job.Phase == "verifying" {
		jobOut = map[string]any{"phase": job.Phase, "version": job.Version, "mode": job.Mode,
			"bytes": job.Bytes, "total": job.Total, "staged_on": job.StagedOn}
	} else if ws := readApplianceWriteState(); ws.Phase != "" {
		jobOut = map[string]any{"phase": ws.Phase, "version": ws.Version, "mode": ws.Mode,
			"bytes": ws.Bytes, "total": ws.Total, "log": ws.Log, "error": ws.Err,
			// No reliable count (stick not found): the UI animates instead.
			"indeterminate": ws.Phase == "writing" && !ws.Tracked && ws.Bytes == 0}
	} else if job.Phase == "failed" {
		jobOut = map[string]any{"phase": "failed", "version": job.Version, "error": job.Err}
	}
	out["job"] = jobOut
	return out
}

// HandleApplianceUpgradeApply: POST /api/appliance/upgrade/apply — starts
// download → verify → write for the newest published image.
func HandleApplianceUpgradeApply(w http.ResponseWriter, r *http.Request) {
	if !system.ApplianceMode() {
		jsonErr(w, http.StatusBadRequest, "not running on the USB appliance")
		return
	}
	if !system.ApplianceBootedToRAM() {
		jsonErr(w, http.StatusConflict,
			`The appliance was started with "run from stick", so the image on the stick is in use. Reboot and let the default "load OS to RAM" entry start, then upgrade.`)
		return
	}
	if bad := system.UnavailableIncusStoragePools(); len(bad) > 0 {
		jsonErr(w, http.StatusConflict,
			"Incus storage pool(s) "+strings.Join(bad, ", ")+" are unavailable. A new image can bring a newer Incus, "+
				"which upgrades its database on first start and refuses to start at all while a storage pool is missing — "+
				"every VM and container would stay down. Reconnect or import the pool, or delete the datastore, then upgrade.")
		return
	}
	var req struct {
		Mode string `json:"mode"` // "stage" (default) or "reboot"
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Mode != "reboot" {
		req.Mode = "stage"
	}
	chk := refreshApplianceCheck()
	img := system.ApplianceImageInfo()
	switch {
	case chk.Err != "":
		jsonErr(w, http.StatusBadGateway, "could not reach GitHub: "+chk.Err)
		return
	case chk.Latest == nil || !semverGreater(chk.Latest.Version, img.Version):
		jsonErr(w, http.StatusConflict, "no newer appliance image is published")
		return
	case chk.Latest.SigURL == "" || chk.Latest.SHA256URL == "":
		jsonErr(w, http.StatusConflict,
			"image "+chk.Latest.Version+" has no signature or checksum published — refusing to install it")
		return
	}
	if ws := readApplianceWriteState(); ws.Phase == "writing" {
		jsonErr(w, http.StatusConflict, "an image write is already in progress")
		return
	}

	applianceJobMu.Lock()
	if applianceJob.Phase == "downloading" || applianceJob.Phase == "verifying" {
		applianceJobMu.Unlock()
		jsonErr(w, http.StatusConflict, "an appliance upgrade is already in progress")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	rel := *chk.Latest
	applianceJob = applianceUpgradeJob{Phase: "downloading", Version: rel.Version,
		Mode: req.Mode, Total: rel.ISOSize, cancel: cancel}
	applianceJobMu.Unlock()

	sess := MustSession(r)
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: "appliance-upgrade",
		Target: rel.Version, Result: audit.ResultOK,
		Details: "started upgrade from " + img.Version + " to " + rel.Version + " (" + req.Mode + ")"})

	// Background context: the job must outlive this request, a browser
	// reload and a relay switch.
	go runApplianceUpgrade(ctx, rel, req.Mode, sess.Username, sess.Role)
	jsonOK(w, map[string]string{"status": "started"})
}

// HandleApplianceUpgradeCancel: POST /api/appliance/upgrade/cancel — only
// the download/verify phases can be cancelled; the write cannot.
func HandleApplianceUpgradeCancel(w http.ResponseWriter, r *http.Request) {
	applianceJobMu.Lock()
	defer applianceJobMu.Unlock()
	if applianceJob.Phase != "downloading" && applianceJob.Phase != "verifying" {
		jsonErr(w, http.StatusConflict, "nothing to cancel (the image write itself cannot be interrupted)")
		return
	}
	if applianceJob.cancel != nil {
		applianceJob.cancel()
	}
	jsonOK(w, map[string]string{"status": "cancelling"})
}

func setApplianceJob(f func(j *applianceUpgradeJob)) {
	applianceJobMu.Lock()
	f(&applianceJob)
	applianceJobMu.Unlock()
}

func failApplianceJob(err error, user, role, version string) {
	log.Printf("[appliance-upgrade] %v", err)
	setApplianceJob(func(j *applianceUpgradeJob) { j.Phase = "failed"; j.Err = err.Error(); j.cancel = nil })
	audit.Log(audit.Entry{User: user, Role: role, Action: "appliance-upgrade",
		Target: version, Result: audit.ResultError, Details: err.Error()})
}

func runApplianceUpgrade(ctx context.Context, rel updater.ApplianceImageRelease, mode, user, role string) {
	staging := chooseApplianceStaging(rel.ISOSize)
	if err := os.MkdirAll(staging.Dir, 0700); err != nil && staging.Dir != applianceStickStageDir() {
		log.Printf("[appliance-upgrade] %s not usable (%v) — downloading to the stick instead", staging.Dir, err)
		staging = applianceStaging{Dir: applianceStickStageDir(), Desc: "the USB stick"}
		err = os.MkdirAll(staging.Dir, 0700)
		if err != nil {
			failApplianceJob(fmt.Errorf("settings partition not writable: %w", err), user, role, rel.Version)
			return
		}
	} else if err != nil {
		failApplianceJob(fmt.Errorf("settings partition not writable: %w", err), user, role, rel.Version)
		return
	}
	stage := staging.Dir
	setApplianceJob(func(j *applianceUpgradeJob) { j.StagedOn = staging.Desc })
	isoPath := filepath.Join(stage, rel.ISOName)

	// Anything staged for another version, anywhere, is dead weight.
	clearApplianceStaged(stage, rel.ISOName)

	// A previous attempt that failed at the write step left a complete,
	// verified download behind — reuse it instead of fetching 1.5 GB again.
	if fi, err := os.Stat(isoPath); err != nil || fi.Size() != rel.ISOSize {
		if err := checkApplianceStageSpace(stage, rel.ISOSize); err != nil {
			failApplianceJob(err, user, role, rel.Version)
			return
		}
		if err := downloadApplianceFile(ctx, rel.ISOURL, isoPath, func(n int64) {
			setApplianceJob(func(j *applianceUpgradeJob) { j.Bytes = n })
		}); err != nil {
			os.Remove(isoPath + ".part")
			if errors.Is(err, context.Canceled) {
				err = errors.New("upgrade cancelled")
			}
			failApplianceJob(err, user, role, rel.Version)
			return
		}
	}
	if err := downloadApplianceFile(ctx, rel.SHA256URL, isoPath+".sha256", nil); err != nil {
		failApplianceJob(fmt.Errorf("download checksum: %w", err), user, role, rel.Version)
		return
	}

	setApplianceJob(func(j *applianceUpgradeJob) { j.Phase = "verifying"; j.Bytes = 0 })
	// One pass over the image checks both the signature and the published
	// checksum; the script is then told to skip its own (identical) re-read,
	// which costs minutes on a slow stick.
	digest, err := updater.VerifyFileSignature(isoPath, rel.SigURL, func(n int64) {
		setApplianceJob(func(j *applianceUpgradeJob) { j.Bytes = n })
	})
	if err == nil {
		err = matchPublishedChecksum(isoPath+".sha256", digest)
	}
	if err != nil {
		os.Remove(isoPath)
		os.Remove(isoPath + ".sha256")
		failApplianceJob(fmt.Errorf("image %s failed verification — not installed: %w", rel.Version, err),
			user, role, rel.Version)
		return
	}
	if ctx.Err() != nil {
		failApplianceJob(errors.New("upgrade cancelled"), user, role, rel.Version)
		return
	}

	if err := startApplianceImageWrite(isoPath, rel, mode); err != nil {
		failApplianceJob(err, user, role, rel.Version)
		return
	}
	// Hand over to the write phase, which reports from the run dir.
	setApplianceJob(func(j *applianceUpgradeJob) { *j = applianceUpgradeJob{} })

	for {
		time.Sleep(3 * time.Second)
		ws := readApplianceWriteState()
		if ws.Phase == "writing" {
			continue
		}
		if ws.Phase == "done" {
			clearApplianceStaged("", "")
			details := "image " + rel.Version + " written to the stick — reboot to start it"
			if mode == "reboot" {
				details = "image " + rel.Version + " written to the stick — rebooting into it"
			}
			audit.Log(audit.Entry{User: user, Role: role, Action: "appliance-upgrade",
				Target: rel.Version, Result: audit.ResultOK, Details: details})
		} else {
			audit.Log(audit.Entry{User: user, Role: role, Action: "appliance-upgrade",
				Target: rel.Version, Result: audit.ResultError, Details: "image write failed: " + ws.Err})
		}
		return
	}
}

// matchPublishedChecksum compares a `sha256sum` line with the digest the
// signature check already computed.
func matchPublishedChecksum(sumPath string, digest []byte) error {
	f := strings.Fields(readTrim(sumPath))
	if len(f) == 0 {
		return errors.New("published checksum file is empty")
	}
	if !strings.EqualFold(f[0], hex.EncodeToString(digest)) {
		return errors.New("checksum mismatch with the published .sha256")
	}
	return nil
}

// checkApplianceStageSpace makes sure the download fits in the persist store
// with room to spare for the settings that live there too.
func checkApplianceStageSpace(dir string, size int64) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return fmt.Errorf("statfs %s: %w", dir, err)
	}
	free := int64(st.Bavail) * int64(st.Bsize)
	need := size + 128<<20
	if free < need {
		return fmt.Errorf("not enough room on the stick's settings partition: the image needs %d MiB, %d MiB free",
			need>>20, free>>20)
	}
	return nil
}

func downloadApplianceFile(ctx context.Context, url, dest string, progress func(int64)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := applianceDownloadClient.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", filepath.Base(dest), resp.StatusCode)
	}
	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	// Flush to the device every applianceDownloadSyncEvery bytes. Without it
	// the kernel buffers the whole image in RAM (plenty on a toram appliance):
	// the bar hits 100% at network speed and then sits there for minutes while
	// the final Sync drains ~1.5 GB into a slow USB stick. Syncing as we go
	// makes the progress match what is really on the stick.
	var n, unsynced int64
	buf := make([]byte, 1<<20)
	for {
		m, rerr := resp.Body.Read(buf)
		if m > 0 {
			if _, werr := f.Write(buf[:m]); werr != nil {
				f.Close()
				return werr
			}
			n += int64(m)
			unsynced += int64(m)
			if unsynced >= applianceDownloadSyncEvery {
				if err := f.Sync(); err != nil {
					f.Close()
					return err
				}
				unsynced = 0
			}
			if progress != nil {
				progress(n)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return fmt.Errorf("download: %w", rerr)
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}

// startApplianceImageWrite launches zfsnas-upgrade-image in its own transient
// unit. The script re-checks everything that matters (toram, checksum, the
// image not reaching the settings partition) before it writes.
func startApplianceImageWrite(isoPath string, rel updater.ApplianceImageRelease, mode string) error {
	if _, err := os.Stat(applianceUpgradeScript); err != nil {
		return fmt.Errorf("%s is missing from this image", applianceUpgradeScript)
	}
	if err := os.MkdirAll(applianceUpgradeRunDir, 0755); err != nil {
		return err
	}
	logPath := filepath.Join(applianceUpgradeRunDir, "log")
	rcPath := filepath.Join(applianceUpgradeRunDir, "rc")
	os.Remove(logPath)
	os.Remove(rcPath)
	meta := applianceWriteMeta{Version: rel.Version, Total: rel.ISOSize, Mode: mode, Baseline: -1}
	if disk := applianceStickDisk(); disk != "" {
		meta.Disk, meta.Baseline = disk, diskSectorsWritten(disk)
	}
	if err := os.WriteFile(filepath.Join(applianceUpgradeRunDir, "meta"), []byte(meta.String()), 0644); err != nil {
		return err
	}
	// Create the log before the unit starts so the status reader never sees
	// "unit active, no log" as an idle state.
	if err := os.WriteFile(logPath, nil, 0644); err != nil {
		return err
	}
	// A finished unit from an earlier attempt would make the name collide.
	_ = exec.Command("systemctl", "reset-failed", applianceUpgradeUnit).Run()
	// --no-verify: the signature + checksum were just checked in one pass.
	// The reboot, when asked for, belongs to the unit and not to the portal:
	// it then happens even if the portal is restarted or the browser closed.
	out, err := exec.Command("systemd-run", "--unit="+applianceUpgradeUnit, "--collect", "--quiet",
		"/bin/sh", "-c",
		`"$0" "$1" --no-verify >"$2" 2>&1; rc=$?; echo $rc >"$3"; if [ "$rc" = 0 ] && [ "$4" = reboot ]; then echo "==> rebooting into the new image" >>"$2"; sleep 3; systemctl reboot; fi`,
		applianceUpgradeScript, isoPath, logPath, rcPath, mode).CombinedOutput()
	if err != nil {
		os.Remove(logPath)
		return fmt.Errorf("could not start the image write: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
