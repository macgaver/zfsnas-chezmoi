package system

// rsync_run.go — v6.7.7 rsync job runner for external storages.
//
// Mirrors the LXD backup-jobs architecture: jobs run in a goroutine under
// context.Background() (never killed by the client), live in a retained
// sync.Map (finished jobs stay queryable so a reloading browser can resolve
// them), and cancel kills the whole process group so no orphan rsync/ssh
// children survive.
//
// Progress: rsync runs with --info=progress2, whose in-place updates
// (CR-separated) carry an overall percentage. We split on both \r and \n and
// keep the latest percentage + a bounded log tail.

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"zfsnas/internal/config"
)

// RsyncJob is the queryable state of one rsync run.
type RsyncJob struct {
	ID          string    `json:"id"`
	StorageID   string    `json:"storage_id"`
	StorageName string    `json:"storage_name"`
	Direction   string    `json:"direction"` // "pull" | "push"
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at,omitempty"`
	Status      string    `json:"status"` // "running" | "done" | "error" | "canceled" | "paused"
	PausedBy    string    `json:"paused_by,omitempty"` // "user" | "window" (Status=="paused")
	Error       string    `json:"error,omitempty"`
	Progress    float64   `json:"progress"`  // 0-100 (overall, from --info=progress2)
	Bytes       int64     `json:"bytes"`     // total transferred file size (from --stats)
	BytesDone   int64     `json:"bytes_done"` // live transferred-so-far (progress2)
	Speed       string    `json:"speed,omitempty"` // live rate, e.g. "10.23MB/s"
	ETA         string    `json:"eta,omitempty"`   // rsync's remaining-time estimate "0:01:23"

	mu     sync.Mutex
	lines  []string
	cancel context.CancelFunc
	proc   *exec.Cmd
}

var rsyncJobs sync.Map // job id → *RsyncJob

// rsyncJobSeq differentiates ids created in the same second.
var rsyncJobSeq int64
var rsyncSeqMu sync.Mutex

func newRsyncJobID() string {
	rsyncSeqMu.Lock()
	rsyncJobSeq++
	n := rsyncJobSeq
	rsyncSeqMu.Unlock()
	return fmt.Sprintf("rsj-%d-%d", time.Now().Unix(), n)
}

// RsyncJobByID returns a job or nil.
func RsyncJobByID(id string) *RsyncJob {
	if v, ok := rsyncJobs.Load(id); ok {
		return v.(*RsyncJob)
	}
	return nil
}

// RsyncJobs returns all jobs, running first, newest first within each group.
func RsyncJobs() []*RsyncJob {
	out := []*RsyncJob{}
	rsyncJobs.Range(func(_, v interface{}) bool {
		out = append(out, v.(*RsyncJob))
		return true
	})
	return out
}

// RsyncActiveForStorage reports whether a storage has a running job — used by
// the mount janitor to keep in-use mounts alive.
func RsyncActiveForStorage(storageID string) bool {
	active := false
	rsyncJobs.Range(func(_, v interface{}) bool {
		j := v.(*RsyncJob)
		if j.StorageID == storageID && j.Status == "running" {
			active = true
			return false
		}
		return true
	})
	return active
}

// Snapshot returns the poller wire shape (matches _bgPollJob's contract).
func (j *RsyncJob) Snapshot() map[string]interface{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	lines := make([]string, len(j.lines))
	copy(lines, j.lines)
	// Overall size estimate: with --no-inc-recursive the progress2 % is
	// accurate, so done/pct extrapolates the total for the "X of Y" readout.
	var totalEst int64
	if j.Progress > 0 && j.BytesDone > 0 {
		totalEst = int64(float64(j.BytesDone) * 100 / j.Progress)
	}
	return map[string]interface{}{
		"id":           j.ID,
		"storage_id":   j.StorageID,
		"storage_name": j.StorageName,
		"direction":    j.Direction,
		"started_at":   j.StartedAt,
		"finished_at":  j.FinishedAt,
		"status":       j.Status,
		"paused_by":    j.PausedBy,
		"error":        j.Error,
		"progress":     j.Progress,
		"bytes":        j.Bytes,
		"bytes_done":   j.BytesDone,
		"bytes_total":  totalEst,
		"speed":        j.Speed,
		"eta":          j.ETA,
		"lines":        lines,
	}
}

func (j *RsyncJob) appendLine(l string) {
	j.mu.Lock()
	j.lines = append(j.lines, l)
	if len(j.lines) > 400 { // bounded tail
		j.lines = j.lines[len(j.lines)-400:]
	}
	j.mu.Unlock()
}

// Cancel kills the whole process group.
func (j *RsyncJob) Cancel() {
	j.stop("canceled", "")
}

// Pause stops the run but marks it resumable (rsync --partial continues from
// where it left off on the next start). by = "user" | "window".
func (j *RsyncJob) Pause(by string) {
	j.stop("paused", by)
}

func (j *RsyncJob) stop(status, pausedBy string) {
	j.mu.Lock()
	proc := j.proc
	if j.Status == "running" {
		j.Status = status
		j.PausedBy = pausedBy
	}
	j.mu.Unlock()
	if proc == nil || proc.Process == nil {
		return
	}
	pgid := proc.Process.Pid // Setpgid: sudo leads the group; rsync's procs join it
	// Best-effort unprivileged group TERM. This alone is NOT reliable: the
	// rsync tree runs as root, so the zfsnas service usually gets EPERM on
	// every member except sudo itself (whose real uid may still be ours) —
	// exactly the failure that orphaned a paused rsync tree holding our
	// stdout pipe open, which in turn blocked the scanner goroutine and left
	// the job without a FinishedAt forever.
	syscall.Kill(-pgid, syscall.SIGTERM) //nolint:errcheck
	// The reliable path: group TERM as root (ZFSNAS_RSYNC sudoers entry).
	exec.Command("sudo", "kill", "-TERM", "--", fmt.Sprintf("-%d", pgid)).Run() //nolint:errcheck
	// Escalate to SIGKILL if the group hasn't fully died shortly after —
	// rsync can wedge forever trying to flush progress output to a dead
	// pty/pipe. FinishedAt is only set after Wait() returns, which requires
	// every pipe-holding descendant to be gone, so it is the exact "group
	// really dead" signal.
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

// progress2 line: "  1,234,567  45%   10.23MB/s    0:01:23 (xfr#3, to-chk=5/12)"
// Captures bytes-done, %, rate, and rsync's own remaining-time estimate.
var rsyncProgRe = regexp.MustCompile(`^\s*([\d,]+)\s+(\d{1,3})%\s+(\S+/s)\s+([\d:]+)`)
var rsyncPctRe = regexp.MustCompile(`(\d{1,3})%`)

// --stats summary: "Total transferred file size: 1,234,567 bytes"
var rsyncBytesRe = regexp.MustCompile(`Total transferred file size: ([\d,]+) bytes`)

// RsyncPaths resolves the src/dst directories for a storage's rsync config.
// Trailing slashes on the source sync its *contents* into dst.
func RsyncPaths(es *config.ExternalStorage) (src, dst string, err error) {
	rc := es.Rsync
	if rc == nil {
		return "", "", fmt.Errorf("rsync not configured")
	}
	if rc.LocalPath == "" || !strings.HasPrefix(rc.LocalPath, "/") {
		return "", "", fmt.Errorf("local path must be absolute")
	}
	remote := ExtMountpoint(es.ID)
	sub := strings.Trim(rc.RemotePath, "/")
	if sub != "" {
		if strings.Contains("/"+sub+"/", "/../") {
			return "", "", fmt.Errorf("invalid remote path")
		}
		remote = remote + "/" + sub
	}
	local := strings.TrimRight(rc.LocalPath, "/")
	if local == "" {
		local = "/"
	}
	switch rc.Direction {
	case "pull":
		return remote + "/", local + "/", nil
	case "push":
		return local + "/", remote + "/", nil
	}
	return "", "", fmt.Errorf("invalid direction %q", rc.Direction)
}

// StartRsyncJob mounts the storage (on-demand mounts included), then launches
// the rsync run in the background and returns the job immediately.
// onFinish is invoked (in the job goroutine) with the final job state so the
// caller can persist LastSync* fields, audit-log, and fire alerts.
func StartRsyncJob(configDir string, es *config.ExternalStorage, onFinish func(*RsyncJob)) (*RsyncJob, error) {
	if RsyncActiveForStorage(es.ID) {
		return nil, fmt.Errorf("a sync for this storage is already running")
	}
	src, dst, err := RsyncPaths(es)
	if err != nil {
		return nil, err
	}
	if err := ExtMount(configDir, es); err != nil {
		return nil, err
	}

	rc := es.Rsync
	// No --human-readable: the --stats summary must print exact byte counts
	// ("Total transferred file size: 20,971,532 bytes") for rsyncBytesRe.
	// --no-inc-recursive: scan the whole file list upfront so the progress2
	// overall % (and therefore our total-size/ETA estimates) are accurate —
	// with incremental recursion the denominator grows while transferring
	// and the bar jumps around or sticks.
	args := []string{"rsync", "-a", "--partial", "--no-inc-recursive", "--info=progress2", "--stats"}
	if rc.Delete {
		args = append(args, "--delete")
	}
	if rc.BWLimitKB > 0 {
		args = append(args, fmt.Sprintf("--bwlimit=%d", rc.BWLimitKB))
	}
	if extra := strings.TrimSpace(rc.ExtraFlags); extra != "" {
		args = append(args, strings.Fields(extra)...)
	}
	args = append(args, src, dst)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "sudo", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	cmd.Stderr = cmd.Stdout // interleave; rsync errors land in the log tail

	job := &RsyncJob{
		ID:          newRsyncJobID(),
		StorageID:   es.ID,
		StorageName: es.Name,
		Direction:   rc.Direction,
		StartedAt:   time.Now(),
		Status:      "running",
		cancel:      cancel,
		proc:        cmd,
	}
	job.appendLine(fmt.Sprintf("rsync %s: %s → %s", rc.Direction, src, dst))

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start rsync: %v", err)
	}
	rsyncJobs.Store(job.ID, job)
	ExtTouch(es.ID)

	go func() {
		defer cancel()
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
			if m := rsyncBytesRe.FindStringSubmatch(line); m != nil {
				if n, err := strconv.ParseInt(strings.ReplaceAll(m[1], ",", ""), 10, 64); err == nil {
					job.mu.Lock()
					job.Bytes = n
					job.mu.Unlock()
				}
			}
			if m := rsyncProgRe.FindStringSubmatch(line); m != nil {
				// Full progress2 update: bytes-done, %, rate, remaining time.
				p, _ := strconv.Atoi(m[2])
				done, _ := strconv.ParseInt(strings.ReplaceAll(m[1], ",", ""), 10, 64)
				job.mu.Lock()
				if p >= 0 && p <= 100 {
					job.Progress = float64(p)
				}
				job.BytesDone = done
				job.Speed = m[3]
				job.ETA = m[4]
				job.mu.Unlock()
				// Progress rewrites arrive hundreds of times; only keep
				// whole-percent changes in the visible tail.
				if p == lastPct {
					continue
				}
				lastPct = p
			} else if m := rsyncPctRe.FindStringSubmatch(line); m != nil {
				// Fallback for %-bearing lines that don't match the full shape.
				if p, err := strconv.Atoi(m[1]); err == nil && p >= 0 && p <= 100 {
					job.mu.Lock()
					job.Progress = float64(p)
					job.mu.Unlock()
					if p == lastPct {
						continue
					}
					lastPct = p
				}
			}
			job.appendLine(line)
		}
		err := cmd.Wait()
		job.mu.Lock()
		job.FinishedAt = time.Now()
		switch {
		case job.Status == "paused":
			// Deliberate interruption (user stop or window close) — not an
			// error; the next run continues via --partial.
			job.Error = ""
		case job.Status == "canceled":
			job.Error = "canceled by user"
		case err != nil:
			job.Status = "error"
			job.Error = firstLine(lastLines(job.lines, 3), err)
		default:
			job.Status = "done"
			job.Progress = 100
		}
		job.mu.Unlock()
		ExtTouch(es.ID)
		if onFinish != nil {
			onFinish(job)
		}
	}()
	return job, nil
}

// lastLines joins the last n log lines (for compact error summaries).
func lastLines(lines []string, n int) string {
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// scanCROrLF is a bufio.SplitFunc treating both \r and \n as line endings so
// rsync's in-place progress rewrites stream as individual lines.
func scanCROrLF(data []byte, atEOF bool) (advance int, token []byte, err error) {
	for i, b := range data {
		if b == '\n' || b == '\r' {
			return i + 1, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}
