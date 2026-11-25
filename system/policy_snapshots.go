package system

import (
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Snapshot policies can include the child datasets of their dataset. Every
// snapshot a policy takes carries the user property zfsnas:policy=<id>, so
// retention only ever prunes that policy's own snapshots, dataset by
// dataset, and a restore can find the copies taken at the same moment.

// PolicyProp is the ZFS user property naming the policy that took a snapshot.
const PolicyProp = "zfsnas:policy"

// TreeDataset is one dataset or zvol under a policy's dataset.
type TreeDataset struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // filesystem | volume
	Mountpoint string `json:"mountpoint,omitempty"`
	Skip       string `json:"skip,omitempty"` // why it is left out; "" = included
}

// listTree returns dataset and every filesystem/volume below it, parents
// before children, as zfs lists them.
func listTree(dataset string) ([]TreeDataset, error) {
	out, err := exec.Command("sudo", "zfs", "list", "-H", "-r", "-t", "filesystem,volume",
		"-o", "name,type,mountpoint", dataset).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	var tree []TreeDataset
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 3 {
			continue
		}
		tree = append(tree, TreeDataset{Name: f[0], Type: f[1], Mountpoint: f[2]})
	}
	return tree, nil
}

// classifyTree marks the children a recursive policy must leave alone, with
// the reason, and the rest of their subtree with them:
//   - not mounted (mountpoint legacy or none): Incus/LXD storage and ZNAS
//     backup targets live there. Incus keeps its own snapshot list, and an
//     extra snapshot on a replication target makes the next incremental
//     receive fail;
//   - a replication destination listed in skipDest.
//
// The policy's own dataset (tree[0]) is never skipped.
func classifyTree(tree []TreeDataset, skipDest map[string]bool) []TreeDataset {
	var skippedRoots []string
	under := func(name string) string {
		for _, r := range skippedRoots {
			if strings.HasPrefix(name, r+"/") {
				return r
			}
		}
		return ""
	}
	for i := range tree {
		if i == 0 {
			continue
		}
		d := &tree[i]
		if r := under(d.Name); r != "" {
			d.Skip = "inside " + r
			continue
		}
		switch {
		case skipDest[d.Name]:
			d.Skip = "replication destination"
		case d.Type == "filesystem" && (d.Mountpoint == "legacy" || d.Mountpoint == "none"):
			d.Skip = "not mounted (" + d.Mountpoint + "): Incus storage or backup target"
		default:
			continue
		}
		skippedRoots = append(skippedRoots, d.Name)
	}
	return tree
}

// PolicyTree returns the datasets a recursive policy on dataset would
// snapshot (Skip == "") and the ones it leaves out.
func PolicyTree(dataset string, skipDest map[string]bool) ([]TreeDataset, error) {
	tree, err := listTree(dataset)
	if err != nil {
		return nil, err
	}
	return classifyTree(tree, skipDest), nil
}

// CreatePolicySnapshot takes "<label>-<UTC time>" on dataset, and when
// recursive on its included children too, in one atomic zfs snapshot call so
// every copy holds the same instant. Each snapshot is tagged with policyID.
// It returns the parent's full snapshot name and how many children were
// included.
func CreatePolicySnapshot(dataset, label, policyID string, recursive bool, skipDest map[string]bool) (string, int, error) {
	// UTC: Samba's Shadow Copy reads the name's timestamp as UTC (issue #175).
	snap := label + "-" + time.Now().UTC().Format("20060102-150405")
	targets := []string{dataset}
	if recursive {
		tree, err := PolicyTree(dataset, skipDest)
		if err != nil {
			return "", 0, err
		}
		targets = targets[:0]
		for _, d := range tree {
			if d.Skip == "" {
				targets = append(targets, d.Name)
			}
		}
	}
	args := []string{"zfs", "snapshot"}
	if policyID != "" {
		args = append(args, "-o", PolicyProp+"="+policyID)
	}
	for _, t := range targets {
		args = append(args, t+"@"+snap)
	}
	out, err := exec.Command("sudo", args...).CombinedOutput()
	if err != nil {
		return "", 0, fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return dataset + "@" + snap, len(targets) - 1, nil
}

// policySnap is one snapshot with the policy tag that took it.
type policySnap struct {
	Name     string // pool/ds@snap
	Dataset  string
	SnapName string
	Creation int64
	Policy   string // "" when untagged
}

func listPolicySnaps(dataset string, recursive bool) ([]policySnap, error) {
	args := []string{"zfs", "list", "-Hp", "-t", "snapshot", "-o", "name,creation," + PolicyProp, "-s", "creation"}
	if recursive {
		args = append(args, "-r")
	} else {
		args = append(args, "-d", "1")
	}
	args = append(args, dataset)
	out, err := exec.Command("sudo", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return parsePolicySnaps(string(out)), nil
}

func parsePolicySnaps(out string) []policySnap {
	var snaps []policySnap
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 3 {
			continue
		}
		at := strings.Index(f[0], "@")
		if at < 0 {
			continue
		}
		c, _ := strconv.ParseInt(f[1], 10, 64)
		pol := f[2]
		if pol == "-" {
			pol = ""
		}
		snaps = append(snaps, policySnap{Name: f[0], Dataset: f[0][:at], SnapName: f[0][at+1:], Creation: c, Policy: pol})
	}
	return snaps
}

// policyPrunePlan picks the snapshots a policy's retention removes:
//   - on the policy's dataset: its "<label>-…" snapshots that are tagged with
//     this policy or untagged (taken before tagging existed), keeping the
//     newest keep;
//   - on every other dataset below it: only the snapshots tagged with this
//     policy, keeping the newest keep on each;
//   - anywhere: the snapshots listed in adopt (left behind by a deleted
//     policy, see orphanCandidates), counted with the policy's own.
//
// A snapshot tagged by another live policy is never touched, even with the same label.
func policyPrunePlan(snaps []policySnap, dataset, label, policyID string, keep int, adopt map[string]bool) []string {
	if keep < 1 {
		return nil
	}
	byDS := map[string][]policySnap{}
	for _, s := range snaps {
		ours := adopt[s.Name]
		if !ours && s.Dataset == dataset {
			ours = snapLabelled(s, label) && (s.Policy == "" || s.Policy == policyID)
		} else if !ours {
			ours = policyID != "" && s.Policy == policyID
		}
		if ours {
			byDS[s.Dataset] = append(byDS[s.Dataset], s)
		}
	}
	var drop []string
	names := make([]string, 0, len(byDS))
	for ds := range byDS {
		names = append(names, ds)
	}
	sort.Strings(names)
	for _, ds := range names {
		list := byDS[ds]
		if len(list) <= keep {
			continue
		}
		sort.SliceStable(list, func(i, j int) bool { return list[i].Creation < list[j].Creation })
		for _, s := range list[:len(list)-keep] {
			drop = append(drop, s.Name)
		}
	}
	return drop
}

func snapLabelled(s policySnap, label string) bool {
	return s.SnapName == label || strings.HasPrefix(s.SnapName, label+"-")
}

// orphanCandidates lists the snapshots a policy may take over: tagged with a
// policy that no longer exists (deleted, or deleted and re-created with a new
// id — issue #189), carrying this policy's label, on a dataset the policy
// snapshots (its own, or an included child when recursive). Without a live
// list nothing is adopted. The caller still checks that the tag was set on
// this host (see localTagged): a received snapshot keeps the sender's tag.
func orphanCandidates(snaps []policySnap, dataset, label, policyID string, live, included map[string]bool) []string {
	if live == nil {
		return nil
	}
	var out []string
	for _, s := range snaps {
		if s.Policy == "" || s.Policy == policyID || live[s.Policy] || !snapLabelled(s, label) {
			continue
		}
		if s.Dataset == dataset || included[s.Dataset] {
			out = append(out, s.Name)
		}
	}
	return out
}

// localTagged returns the snapshots under dataset whose policy tag was set
// here (source "local"), not received from another host by zfs send -R/-w:
// those belong to the sender's policies, and pruning them on a replication
// target breaks the next incremental receive.
func localTagged(dataset string) (map[string]bool, error) {
	out, err := exec.Command("sudo", "zfs", "get", "-H", "-r", "-t", "snapshot",
		"-o", "name,source", PolicyProp, dataset).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return parseLocalTagged(string(out)), nil
}

func parseLocalTagged(out string) map[string]bool {
	m := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) >= 2 && f[1] == "local" {
			m[f[0]] = true
		}
	}
	return m
}

// PruneOptions tells retention which leftovers of deleted policies it may take over.
type PruneOptions struct {
	Recursive bool
	Live      map[string]bool // ids of the policies that exist; nil = adopt nothing
	SkipDest  map[string]bool // replication destinations (see PolicyTree)
}

// PrunePolicySnapshots applies a policy's retention to its dataset and to
// every dataset below it (see policyPrunePlan). Errors on single snapshots
// (a hold, a clone) are collected and the rest still go.
func PrunePolicySnapshots(dataset, label, policyID string, keep int, opt PruneOptions) (int, []error) {
	snaps, err := listPolicySnaps(dataset, true)
	if err != nil {
		return 0, []error{err}
	}
	included := map[string]bool{}
	if opt.Recursive {
		if tree, err := PolicyTree(dataset, opt.SkipDest); err == nil {
			for _, d := range tree {
				if d.Skip == "" {
					included[d.Name] = true
				}
			}
		}
	}
	var adopt map[string]bool
	if cand := orphanCandidates(snaps, dataset, label, policyID, opt.Live, included); len(cand) > 0 {
		if local, err := localTagged(dataset); err == nil {
			adopt = map[string]bool{}
			for _, n := range cand {
				if local[n] {
					adopt[n] = true
				}
			}
		}
	}
	var errs []error
	n := 0
	for _, name := range policyPrunePlan(snaps, dataset, label, policyID, keep, adopt) {
		if err := DestroySnapshot(name); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		n++
	}
	return n, errs
}

// PolicySnapshots lists the snapshots under dataset that policyID took here
// (tag set locally, so copies received on a replication target are left out).
func PolicySnapshots(dataset, policyID string) ([]string, error) {
	if policyID == "" {
		return nil, nil
	}
	snaps, err := listPolicySnaps(dataset, true)
	if err != nil {
		return nil, err
	}
	var mine []string
	for _, s := range snaps {
		if s.Policy == policyID {
			mine = append(mine, s.Name)
		}
	}
	if len(mine) == 0 {
		return nil, nil
	}
	local, err := localTagged(dataset)
	if err != nil {
		return nil, err
	}
	out := mine[:0]
	for _, n := range mine {
		if local[n] {
			out = append(out, n)
		}
	}
	return out, nil
}

// DestroyPolicySnapshots removes every snapshot policyID took under dataset
// (used when the policy is deleted together with its snapshots).
func DestroyPolicySnapshots(dataset, policyID string) (int, []error) {
	names, err := PolicySnapshots(dataset, policyID)
	if err != nil {
		return 0, []error{err}
	}
	var errs []error
	n := 0
	for _, name := range names {
		if err := DestroySnapshot(name); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		n++
	}
	return n, errs
}

// ── Restore ──────────────────────────────────────────────────────────────────

// RestoreTarget is one dataset a restore rolls back, with what it costs.
type RestoreTarget struct {
	Dataset string   `json:"dataset"`
	Newer   []string `json:"newer"`            // snapshots taken after it, destroyed by the rollback
	Clones  []string `json:"clones,omitempty"` // clones of those newer snapshots: they block the rollback
}

// RestorePlan describes rolling dataset back to snapName, alone or with the
// children that hold a snapshot of the same name.
type RestorePlan struct {
	Snapshot string          `json:"snapshot"` // pool/ds@snap
	Targets  []RestoreTarget `json:"targets"`  // [0] is the dataset itself
	// Children of the dataset that have no snapshot of that name (created
	// later, or left out of the policy). A recursive restore leaves them as they are.
	Untouched []string `json:"untouched"`
	Blocked   bool     `json:"blocked"` // a newer snapshot has a clone: nothing may be rolled back
}

// PlanRestore lists what restoring full (pool/ds@snap) touches. With
// children it adds every dataset below that has a snapshot of the same name.
func PlanRestore(full string, children bool) (*RestorePlan, error) {
	at := strings.Index(full, "@")
	if at <= 0 {
		return nil, fmt.Errorf("valid snapshot name required")
	}
	dataset, snap := full[:at], full[at+1:]
	args := []string{"zfs", "list", "-Hp", "-t", "snapshot", "-o", "name,creation,clones", "-s", "creation"}
	if children {
		args = append(args, "-r")
	} else {
		args = append(args, "-d", "1")
	}
	out, err := exec.Command("sudo", append(args, dataset)...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	var all []string
	if children {
		tree, err := listTree(dataset)
		if err != nil {
			return nil, err
		}
		for _, d := range tree {
			all = append(all, d.Name)
		}
	} else {
		all = []string{dataset}
	}
	plan := buildRestorePlan(string(out), dataset, snap, all)
	if len(plan.Targets) == 0 || plan.Targets[0].Dataset != dataset {
		return nil, fmt.Errorf("snapshot %s does not exist", full)
	}
	return plan, nil
}

// buildRestorePlan works from `zfs list -Hp -o name,creation,clones -s creation`
// output and the datasets in the tree (parent first).
func buildRestorePlan(listOut, dataset, snap string, tree []string) *RestorePlan {
	type row struct {
		name, ds, sn string
		creation     int64
		clones       []string
	}
	perDS := map[string][]row{}
	for _, line := range strings.Split(strings.TrimSpace(listOut), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 3 {
			continue
		}
		at := strings.Index(f[0], "@")
		if at < 0 {
			continue
		}
		c, _ := strconv.ParseInt(f[1], 10, 64)
		var clones []string
		if v := strings.TrimSpace(f[2]); v != "" && v != "-" {
			clones = strings.Split(v, ",")
		}
		r := row{name: f[0], ds: f[0][:at], sn: f[0][at+1:], creation: c, clones: clones}
		perDS[r.ds] = append(perDS[r.ds], r)
	}
	plan := &RestorePlan{Snapshot: dataset + "@" + snap, Targets: []RestoreTarget{}, Untouched: []string{}}
	for _, ds := range tree {
		rows := perDS[ds]
		idx := -1
		for i, r := range rows {
			if r.sn == snap {
				idx = i
				break
			}
		}
		if idx < 0 {
			if ds != dataset {
				plan.Untouched = append(plan.Untouched, ds)
			}
			continue
		}
		t := RestoreTarget{Dataset: ds, Newer: []string{}}
		for _, r := range rows[idx+1:] {
			t.Newer = append(t.Newer, r.sn)
			if len(r.clones) > 0 {
				t.Clones = append(t.Clones, r.clones...)
				plan.Blocked = true
			}
		}
		plan.Targets = append(plan.Targets, t)
	}
	return plan
}

// RestoreSnapshotSet rolls every target of the plan back to its snapshot of
// that name. It re-plans first and refuses when a newer snapshot has a clone,
// so nothing is rolled back unless every dataset can be. The dataset itself
// goes first; on a later failure the ones already done are reported.
func RestoreSnapshotSet(full string, children bool) ([]string, error) {
	plan, err := PlanRestore(full, children)
	if err != nil {
		return nil, err
	}
	if plan.Blocked {
		var c []string
		for _, t := range plan.Targets {
			c = append(c, t.Clones...)
		}
		return nil, fmt.Errorf("nothing was restored: newer snapshots have clones (%s); delete or promote them first", strings.Join(c, ", "))
	}
	snap := full[strings.Index(full, "@")+1:]
	var done []string
	for _, t := range plan.Targets {
		if err := RollbackSnapshot(t.Dataset + "@" + snap); err != nil {
			if len(done) == 0 {
				return nil, err
			}
			return done, fmt.Errorf("%s: %v (already restored: %s)", t.Dataset, err, strings.Join(done, ", "))
		}
		done = append(done, t.Dataset)
	}
	return done, nil
}
