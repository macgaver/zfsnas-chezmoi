package system

// fbtransfer.go — File Browser copy/move as a cancellable background job.
//
// Design spec: PLANS/plan-filebrowser-transfer-progress.md
//
// Copy and move used to block the HTTP request for the whole operation
// (CopyPaths / MovePaths, still used for the same-filesystem move fast path).
// A 69 GB folder copy therefore ran for an hour with no progress, no ETA and
// no way to stop it. This file runs the transfer in a goroutine under
// context.Background() instead — the client can disconnect, reload, or go make
// coffee without affecting it — and exposes progress and cancellation.
//
// The architecture mirrors rsync_run.go, deliberately: retained sync.Map
// registry so a reloading browser can still resolve a job, --info=progress2
// parsing for the percentage, and a three-stage process-group kill for cancel.
//
// Engine: rsync when available (real percentage, speed and ETA, and its native
// interruption behaviour is exactly the cancel semantic we want — completed
// files stay, the in-flight temp file is unlinked). Otherwise the legacy
// cp -a / mv, which gives no percentage but still cancels.

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// FbTransferJob is the queryable state of one File Browser copy/move.
type FbTransferJob struct {
	ID         string    `json:"id"`
	Op         string    `json:"op"`        // "copy" | "move"
	SrcLabel   string    `json:"src_label"` // display only
	DstLabel   string    `json:"dst_label"`
	Items      int       `json:"items"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Status     string    `json:"status"` // "running" | "done" | "error" | "canceled"
	Error      string    `json:"error,omitempty"`
	Engine     string    `json:"engine"`   // "rsync" | "cp" — drives determinate vs spinner in the UI
	Progress   float64   `json:"progress"` // 0-100; always 0 while Engine == "cp"
	BytesDone  int64     `json:"bytes_done"`
	Speed      string    `json:"speed,omitempty"`
	ETA        string    `json:"eta,omitempty"`

	mu     sync.Mutex
	lines  []string
	cancel context.CancelFunc
	proc   *exec.Cmd
}

var fbTransfers sync.Map // job id → *FbTransferJob

var (
	fbTransferSeqMu sync.Mutex
	fbTransferSeq   int64
)

// fbTransferRetention is how long a finished job stays queryable, so a browser
// that reloads mid-transfer can still resolve what happened to it.
const fbTransferRetention = time.Hour

func newFbTransferID() string {
	fbTransferSeqMu.Lock()
	fbTransferSeq++
	n := fbTransferSeq
	fbTransferSeqMu.Unlock()
	return fmt.Sprintf("fbt-%d-%d", time.Now().Unix(), n)
}

// FbTransferByID returns a job or nil.
func FbTransferByID(id string) *FbTransferJob {
	if v, ok := fbTransfers.Load(id); ok {
		return v.(*FbTransferJob)
	}
	return nil
}

// FbTransfers returns every known job, running first and newest first within
// each group. Backs the discovery endpoint that lets any browser — and any
// interlink peer — see a transfer it did not start itself.
func FbTransfers() []*FbTransferJob {
	out := []*FbTransferJob{}
	fbTransfers.Range(func(_, v interface{}) bool {
		out = append(out, v.(*FbTransferJob))
		return true
	})
	sort.SliceStable(out, func(i, j int) bool {
		ri := out[i].Status == "running"
		rj := out[j].Status == "running"
		if ri != rj {
			return ri
		}
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out
}

func init() {
	RegisterJobProvider("filebrowser-transfer", func() []JobSummary {
		out := []JobSummary{}
		for _, j := range FbTransfers() {
			s := j.Snapshot()
			base := "/api/files/transfers/" + j.ID
			label := "Copying "
			if j.Op == "move" {
				label = "Moving "
			}
			out = append(out, JobSummary{
				Key:         "fbt-" + j.ID,
				ID:          j.ID,
				Kind:        "transfer",
				Op:          j.Op,
				Label:       label + itoa(j.Items) + " item(s) → " + j.DstLabel,
				Status:      j.Status,
				Progress:    j.Progress,
				StartedAt:   j.StartedAt,
				ProgressURL: base + "/progress",
				CancelURL:   base + "/cancel",
				BytesDone:   j.BytesDone,
				BytesTotal:  asInt64(s["bytes_total"]),
				Speed:       j.Speed,
				ETA:         j.ETA,
			})
		}
		return out
	})
}

func itoa(n int) string { return strconv.Itoa(n) }

func asInt64(v interface{}) int64 {
	if n, ok := v.(int64); ok {
		return n
	}
	return 0
}

// pruneFbTransfers drops finished jobs past the retention window. Called when a
// new transfer starts, which avoids adding a janitor goroutine for a map that
// only ever grows one entry per user-initiated copy.
func pruneFbTransfers() {
	cutoff := time.Now().Add(-fbTransferRetention)
	fbTransfers.Range(func(k, v interface{}) bool {
		j := v.(*FbTransferJob)
		j.mu.Lock()
		stale := !j.FinishedAt.IsZero() && j.FinishedAt.Before(cutoff)
		j.mu.Unlock()
		if stale {
			fbTransfers.Delete(k)
		}
		return true
	})
}

// Snapshot returns the poller wire shape (matches _bgPollJob's contract).
func (j *FbTransferJob) Snapshot() map[string]interface{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	lines := make([]string, len(j.lines))
	copy(lines, j.lines)
	// With --no-inc-recursive the progress2 percentage is accurate, so the total
	// extrapolates from done/pct for the "X of Y" readout.
	var totalEst int64
	if j.Progress > 0 && j.BytesDone > 0 {
		totalEst = int64(float64(j.BytesDone) * 100 / j.Progress)
	}
	return map[string]interface{}{
		"id":          j.ID,
		"op":          j.Op,
		"src_label":   j.SrcLabel,
		"dst_label":   j.DstLabel,
		"items":       j.Items,
		"started_at":  j.StartedAt,
		"finished_at": j.FinishedAt,
		"status":      j.Status,
		"error":       j.Error,
		"engine":      j.Engine,
		"progress":    j.Progress,
		"bytes_done":  j.BytesDone,
		"bytes_total": totalEst,
		"speed":       j.Speed,
		"eta":         j.ETA,
		"lines":       lines,
	}
}

func (j *FbTransferJob) appendLine(l string) {
	j.mu.Lock()
	j.lines = append(j.lines, l)
	if len(j.lines) > 400 { // bounded tail
		j.lines = j.lines[len(j.lines)-400:]
	}
	j.mu.Unlock()
}

// Cancel stops the transfer. Completed files stay at the destination; rsync
// unlinks the hidden temp file it was mid-write on, so nothing truncated is
// left behind.
func (j *FbTransferJob) Cancel() {
	j.mu.Lock()
	proc := j.proc
	if j.Status == "running" {
		j.Status = "canceled"
	}
	j.mu.Unlock()
	if proc == nil || proc.Process == nil {
		return
	}
	// Same three-stage kill as RsyncJob.stop: the transfer tree runs as root, so
	// an unprivileged group TERM usually gets EPERM on every member except sudo
	// itself. The reliable path is the group TERM as root, escalating to KILL if
	// the group has not fully died — FinishedAt is only set once Wait() returns,
	// which needs every pipe-holding descendant gone, so it is the exact signal.
	pgid := proc.Process.Pid
	syscall.Kill(-pgid, syscall.SIGTERM)                                        //nolint:errcheck
	exec.Command("sudo", "kill", "-TERM", "--", fmt.Sprintf("-%d", pgid)).Run() //nolint:errcheck
	go func() {
		time.Sleep(3 * time.Second)
		j.mu.Lock()
		done := !j.FinishedAt.IsZero()
		j.mu.Unlock()
		if !done {
			exec.Command("sudo", "kill", "-KILL", "--", fmt.Sprintf("-%d", pgid)).Run() //nolint:errcheck
		}
	}()
}

// buildTransferArgs returns the argv passed to sudo for one transfer.
//
// engine is "rsync" or "cp"; op is "copy" or "move".
//
// The rsync form relies on --no-inc-recursive: it builds the whole file list up
// front, which is what makes the progress2 percentage truthful rather than a
// number that restarts on every directory (rsync_run.go depends on the same
// property). --ignore-existing stands in for cp's -n, and --remove-source-files
// implements move by unlinking each source only once it is safely written.
func buildTransferArgs(engine, op string, srcs []string, dst string, overwrite bool) []string {
	if engine == "rsync" {
		args := []string{"rsync", "-aHAX", "--info=progress2", "--no-inc-recursive"}
		if !overwrite {
			args = append(args, "--ignore-existing")
		}
		if op == "move" {
			args = append(args, "--remove-source-files")
		}
		args = append(args, "--")
		args = append(args, srcs...)
		// Trailing slash: copy *into* the destination directory, matching what
		// cp and mv do with a directory destination.
		return append(args, strings.TrimSuffix(dst, "/")+"/")
	}

	flag := "-n"
	if overwrite {
		flag = "-f"
	}
	var args []string
	if op == "move" {
		args = []string{"mv", flag, "--"}
	} else {
		args = []string{"cp", "-a", flag, "--"}
	}
	args = append(args, srcs...)
	return append(args, dst)
}

// deviceOf returns the filesystem device id of path.
//
// os.Stat first because it costs nothing, with a `sudo stat` fallback for the
// traverse-denied roots the File Browser routinely serves — the same reason
// validateMoveCopy and the raw/list/chown paths shell through sudo.
func deviceOf(path string) (uint64, error) {
	if fi, err := os.Stat(path); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			return uint64(st.Dev), nil
		}
	}
	out, err := exec.Command("sudo", "stat", "-c", "%d", path).Output()
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	dev, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return dev, nil
}

// sameDevice reports whether two paths live on the same filesystem.
func sameDevice(a, b string) (bool, error) {
	da, err := deviceOf(a)
	if err != nil {
		return false, err
	}
	db, err := deviceOf(b)
	if err != nil {
		return false, err
	}
	return da == db, nil
}

// moveIsRename reports whether a move can be served by the instant rename
// (MovePaths) instead of a transfer job: true only when every source shares the
// destination's filesystem.
//
// Anything we cannot determine answers false. The transfer path works in every
// case, so falling back to it is merely slower; falling back the other way
// would fail outright on a cross-device move.
func moveIsRename(srcs []string, dst string) bool {
	dstDev, err := deviceOf(dst)
	if err != nil {
		return false
	}
	for _, s := range srcs {
		srcDev, err := deviceOf(s)
		if err != nil || srcDev != dstDev {
			return false
		}
	}
	return len(srcs) > 0
}

// lockRoots locks one or both root mutexes in a stable order (so concurrent
// operations on the same pair cannot deadlock) and returns the unlock func.
func lockRoots(a, b string) func() {
	if a > b {
		a, b = b, a
	}
	mu1 := fbRootMutex(a)
	mu1.Lock()
	if a == b {
		return mu1.Unlock
	}
	mu2 := fbRootMutex(b)
	mu2.Lock()
	return func() { mu2.Unlock(); mu1.Unlock() }
}

// StartFbTransfer validates a copy/move and runs it as a background job.
//
// Returns (nil, nil) when the operation was a same-filesystem move and has
// already completed as an instant rename — there is nothing to report progress
// on. Any validation failure returns an error before a job exists, so the
// caller can surface it synchronously and the existing overwrite-confirm flow
// keeps working.
func StartFbTransfer(op, srcAbsRoot string, srcSubpaths []string, dstAbsRoot, dstSubpath string, overwrite bool, onFinish func(*FbTransferJob)) (*FbTransferJob, error) {
	// Pre-flight under the root mutexes, exactly as the synchronous paths do.
	// The lock is released before the transfer starts: holding it for the hour a
	// large copy takes would block every mkdir, rename, upload and delete on
	// that root, which is precisely the freeze that backgrounding exists to
	// avoid. rsync is safe against concurrent operations.
	unlock := lockRoots(srcAbsRoot, dstAbsRoot)
	srcs, dst, err := validateMoveCopy(srcAbsRoot, srcSubpaths, dstAbsRoot, dstSubpath)
	isRename := op == "move" && err == nil && moveIsRename(srcs, dst)
	unlock()
	if err != nil {
		return nil, err
	}

	// A move within one filesystem is a rename: instant, no bytes copied, so
	// there is nothing worth showing a progress popup for.
	if isRename {
		if err := MovePaths(srcAbsRoot, srcSubpaths, dstAbsRoot, dstSubpath, overwrite); err != nil {
			return nil, err
		}
		return nil, nil
	}

	pruneFbTransfers()

	engine := "cp"
	if binaryPresent("rsync") {
		engine = "rsync"
	}
	ctx, cancel := context.WithCancel(context.Background())
	job := &FbTransferJob{
		ID:        newFbTransferID(),
		Op:        op,
		SrcLabel:  filepath.Base(srcs[0]),
		DstLabel:  dst,
		Items:     len(srcs),
		StartedAt: time.Now(),
		Status:    "running",
		Engine:    engine,
		cancel:    cancel,
	}
	if len(srcs) > 1 {
		job.SrcLabel = fmt.Sprintf("%s + %d more", filepath.Base(srcs[0]), len(srcs)-1)
	}
	fbTransfers.Store(job.ID, job)
	job.appendLine(fmt.Sprintf("%s %d item(s) → %s", op, len(srcs), dst))

	go func() {
		defer cancel()
		runErr := job.run(ctx, engine, op, srcs, dst, overwrite)

		// rsync could not even start: exited non-zero within 2s having moved no
		// bytes. That single condition covers every "unusable rsync" case —
		// sudoers not yet re-applied after the alias change, an rsync too old
		// for --info=progress2, a broken binary — without trying to enumerate
		// them. A failure *after* bytes moved is a real transfer error and is
		// never silently retried, which would risk redoing a partial move.
		if runErr != nil && engine == "rsync" && job.earlyFailure() {
			job.appendLine("rsync unavailable (" + runErr.Error() + ") — falling back to cp, progress will not be reported")
			job.mu.Lock()
			job.Engine = "cp"
			job.mu.Unlock()
			runErr = job.run(ctx, "cp", op, srcs, dst, overwrite)
		}

		// A move via rsync --remove-source-files unlinks the files but leaves
		// the emptied directory skeleton behind.
		if runErr == nil && op == "move" && job.engineNow() == "rsync" && !job.canceled() {
			job.pruneEmptySourceDirs(srcs)
		}

		job.mu.Lock()
		job.FinishedAt = time.Now()
		switch {
		case job.Status == "canceled":
			if job.Op == "move" {
				job.Error = "canceled — items already moved are at the destination, the rest were left in place"
			} else {
				job.Error = "canceled — files already copied were kept"
			}
		case runErr != nil:
			job.Status = "error"
			job.Error = firstLine(lastLines(job.lines, 3), runErr)
		default:
			job.Status = "done"
			job.Progress = 100
		}
		job.mu.Unlock()
		if onFinish != nil {
			onFinish(job)
		}
	}()
	return job, nil
}

func (j *FbTransferJob) canceled() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Status == "canceled"
}

func (j *FbTransferJob) engineNow() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Engine
}

// earlyFailure reports whether the run died quickly without moving anything —
// the signature of a command that could not start rather than a transfer that
// went wrong. A cancelled job is never an early failure, however fast it died.
func (j *FbTransferJob) earlyFailure() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Status != "canceled" && j.BytesDone == 0 &&
		time.Since(j.StartedAt) < 2*time.Second
}

// run executes one transfer command to completion, streaming its output into
// the job's progress fields and log tail.
func (j *FbTransferJob) run(ctx context.Context, engine, op string, srcs []string, dst string, overwrite bool) error {
	argv := buildTransferArgs(engine, op, srcs, dst, overwrite)
	cmd := exec.CommandContext(ctx, "sudo", argv...)
	// Setpgid so cancel can signal the whole tree: sudo leads the group and the
	// rsync/cp children join it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout // interleave; errors land in the log tail

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %v", engine, err)
	}
	j.mu.Lock()
	j.proc = cmd
	j.mu.Unlock()

	// progress2 rewrites one line with \r; treat both separators as EOL.
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	sc.Split(scanCROrLF)
	lastPct := -1
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " ")
		if line == "" {
			continue
		}
		if m := rsyncProgRe.FindStringSubmatch(line); m != nil {
			p, _ := strconv.Atoi(m[2])
			done, _ := strconv.ParseInt(strings.ReplaceAll(m[1], ",", ""), 10, 64)
			j.mu.Lock()
			if p >= 0 && p <= 100 {
				j.Progress = float64(p)
			}
			j.BytesDone = done
			j.Speed = m[3]
			j.ETA = m[4]
			j.mu.Unlock()
			// Progress rewrites arrive hundreds of times a second; only
			// whole-percent changes are worth keeping in the visible tail.
			if p == lastPct {
				continue
			}
			lastPct = p
		}
		j.appendLine(line)
	}
	return cmd.Wait()
}

// pruneEmptySourceDirs removes the directory skeleton rsync --remove-source-files
// leaves behind, so a completed move does not leave empty folders at the source.
// Best-effort: a non-empty directory (a file the user added mid-transfer, or one
// rsync skipped) is deliberately left alone by -empty.
func (j *FbTransferJob) pruneEmptySourceDirs(srcs []string) {
	for _, s := range srcs {
		if fi, err := os.Stat(s); err != nil || !fi.IsDir() {
			continue
		}
		out, err := exec.Command("sudo", "find", s, "-depth", "-type", "d", "-empty", "-delete").CombinedOutput()
		if err != nil {
			j.appendLine("note: could not remove emptied source folders: " + strings.TrimSpace(string(out)))
		}
	}
}
