package system

// Coordinated ZFS snapshots for an all-ZFS MergerFS union (v6.7.13). Because a
// union's branches usually span multiple zpools, a "global snapshot" is a set
// of per-dataset snapshots that all share one timestamped name, taken in
// parallel so they land as close to the same instant as possible (atomic within
// a pool; near-simultaneous across pools). Restore rolls every member dataset
// back to that shared name, coordinated the same way.

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/config"
)

// MergerFSSnapPrefix is the shared prefix for a union's snapshot names.
func MergerFSSnapPrefix(pool string) string { return "mfs-" + pool }

// MergerFSSnapName composes the shared, timestamped snapshot name.
func MergerFSSnapName(pool string, now time.Time) string {
	return MergerFSSnapPrefix(pool) + "-" + now.Format("2006-01-02-150405")
}

// mergerfsMemberDatasets returns the union's distinct member ZFS datasets.
func mergerfsMemberDatasets(p config.MergerFSPool) []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range p.Branches {
		if b.ZFSDataset != "" && !seen[b.ZFSDataset] {
			seen[b.ZFSDataset] = true
			out = append(out, b.ZFSDataset)
		}
	}
	return out
}

// MergerFSSnapshotSet is one logical global snapshot (same name across members).
type MergerFSSnapshotSet struct {
	Name         string    `json:"name"`          // the <name> after '@'
	CreatedAt    time.Time `json:"created_at"`
	Members      int       `json:"members"`       // member datasets that have this snapshot
	TotalMembers int       `json:"total_members"` // member datasets in the union
	UsedBytes    int64     `json:"used_bytes"`    // summed across members
}

// MergerFSListSnapshots returns the union's global snapshots, newest-first.
func MergerFSListSnapshots(p config.MergerFSPool) []MergerFSSnapshotSet {
	members := mergerfsMemberDatasets(p)
	prefix := MergerFSSnapPrefix(p.Name) + "-"
	agg := map[string]*MergerFSSnapshotSet{}
	for _, ds := range members {
		out, err := exec.Command("zfs", "list", "-Hpt", "snapshot", "-o", "name,creation,used", "-r", "-d", "1", ds).Output()
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(out), "\n") {
			f := strings.Fields(ln)
			if len(f) < 3 {
				continue
			}
			full := f[0]
			at := strings.IndexByte(full, '@')
			if at < 0 || full[:at] != ds { // only THIS dataset's own snapshots
				continue
			}
			snap := full[at+1:]
			if !strings.HasPrefix(snap, prefix) {
				continue
			}
			s := agg[snap]
			if s == nil {
				s = &MergerFSSnapshotSet{Name: snap, TotalMembers: len(members)}
				agg[snap] = s
			}
			s.Members++
			var sec, used int64
			fmt.Sscanf(f[1], "%d", &sec)
			fmt.Sscanf(f[2], "%d", &used)
			s.UsedBytes += used
			// Use the earliest member creation as the set's timestamp.
			t := time.Unix(sec, 0)
			if s.CreatedAt.IsZero() || t.Before(s.CreatedAt) {
				s.CreatedAt = t
			}
		}
	}
	sets := make([]MergerFSSnapshotSet, 0, len(agg))
	for _, s := range agg {
		sets = append(sets, *s)
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].CreatedAt.After(sets[j].CreatedAt) })
	return sets
}

// parallelZFS runs one zfs command per member dataset concurrently, returning a
// map of dataset→error message for the failures (empty on full success).
func parallelZFS(members []string, argsFor func(ds string) []string) map[string]string {
	var mu sync.Mutex
	errs := map[string]string{}
	var wg sync.WaitGroup
	for _, ds := range members {
		wg.Add(1)
		go func(ds string) {
			defer wg.Done()
			if out, err := exec.Command("sudo", append([]string{"zfs"}, argsFor(ds)...)...).CombinedOutput(); err != nil {
				mu.Lock()
				errs[ds] = strings.TrimSpace(string(out))
				if errs[ds] == "" {
					errs[ds] = err.Error()
				}
				mu.Unlock()
			}
		}(ds)
	}
	wg.Wait()
	return errs
}

// MergerFSTakeSnapshot snapshots every member dataset with one shared
// timestamped name, in parallel. Returns the name and per-dataset errors.
func MergerFSTakeSnapshot(p config.MergerFSPool) (string, map[string]string) {
	name := MergerFSSnapName(p.Name, time.Now())
	members := mergerfsMemberDatasets(p)
	errs := parallelZFS(members, func(ds string) []string { return []string{"snapshot", ds + "@" + name} })
	return name, errs
}

// MergerFSDeleteSnapshot destroys the named global snapshot on every member.
func MergerFSDeleteSnapshot(p config.MergerFSPool, snapName string) map[string]string {
	members := mergerfsMemberDatasets(p)
	// -r removes the snapshot on children too; missing ones are tolerated by
	// filtering below (zfs destroy of a nonexistent snap errors, so we probe).
	var mu sync.Mutex
	errs := map[string]string{}
	var wg sync.WaitGroup
	for _, ds := range members {
		wg.Add(1)
		go func(ds string) {
			defer wg.Done()
			target := ds + "@" + snapName
			// Skip datasets that don't have this snapshot (partial sets).
			if exec.Command("zfs", "list", "-t", "snapshot", target).Run() != nil {
				return
			}
			if out, err := exec.Command("sudo", "zfs", "destroy", target).CombinedOutput(); err != nil {
				mu.Lock()
				errs[ds] = strings.TrimSpace(string(out))
				mu.Unlock()
			}
		}(ds)
	}
	wg.Wait()
	return errs
}

// MergerFSRestoreSnapshot rolls every member dataset back to the shared-name
// snapshot, in parallel (coordinated on the timestamp). -r discards newer
// snapshots so the rollback can proceed; DATA newer than the snapshot is lost.
func MergerFSRestoreSnapshot(p config.MergerFSPool, snapName string) map[string]string {
	members := mergerfsMemberDatasets(p)
	var mu sync.Mutex
	errs := map[string]string{}
	var wg sync.WaitGroup
	for _, ds := range members {
		wg.Add(1)
		go func(ds string) {
			defer wg.Done()
			target := ds + "@" + snapName
			if exec.Command("zfs", "list", "-t", "snapshot", target).Run() != nil {
				return // member lacks this snapshot — skip, report via missing count
			}
			if out, err := exec.Command("sudo", "zfs", "rollback", "-r", target).CombinedOutput(); err != nil {
				mu.Lock()
				errs[ds] = strings.TrimSpace(string(out))
				mu.Unlock()
			}
		}(ds)
	}
	wg.Wait()
	return errs
}

// MergerFSPruneSnapshots keeps the newest `keep` global snapshot sets and
// destroys the rest across all members.
func MergerFSPruneSnapshots(p config.MergerFSPool, keep int) {
	if keep <= 0 {
		return
	}
	sets := MergerFSListSnapshots(p) // newest-first
	if len(sets) <= keep {
		return
	}
	for _, s := range sets[keep:] {
		MergerFSDeleteSnapshot(p, s.Name)
	}
}
