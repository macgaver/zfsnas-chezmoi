package system

import (
	"reflect"
	"sort"
	"testing"
)

func TestClassifyTreeSkipsUnmountedAndReplicaSubtrees(t *testing.T) {
	tree := []TreeDataset{
		{Name: "tank", Type: "filesystem", Mountpoint: "/mnt/tank"},
		{Name: "tank/docs", Type: "filesystem", Mountpoint: "/mnt/tank/docs"},
		{Name: "tank/docs/2026", Type: "filesystem", Mountpoint: "/mnt/tank/docs/2026"},
		{Name: "tank/incus", Type: "filesystem", Mountpoint: "legacy"},
		{Name: "tank/incus/containers/c1", Type: "filesystem", Mountpoint: "legacy"},
		{Name: "tank/incus/virtual-machines/v1.block", Type: "volume", Mountpoint: "-"},
		{Name: "tank/ZNAS-Backups-Workload", Type: "filesystem", Mountpoint: "none"},
		{Name: "tank/ZNAS-Backups-Workload/x", Type: "filesystem", Mountpoint: "/mnt/odd"},
		{Name: "tank/replica", Type: "filesystem", Mountpoint: "/mnt/tank/replica"},
		{Name: "tank/replica/sub", Type: "filesystem", Mountpoint: "/mnt/tank/replica/sub"},
		{Name: "tank/vmdisk", Type: "volume", Mountpoint: "-"},
		{Name: "tank/incusish", Type: "filesystem", Mountpoint: "/mnt/tank/incusish"}, // prefix lookalike, kept
	}
	got := classifyTree(tree, map[string]bool{"tank/replica": true})
	var in []string
	skip := map[string]string{}
	for _, d := range got {
		if d.Skip == "" {
			in = append(in, d.Name)
		} else {
			skip[d.Name] = d.Skip
		}
	}
	want := []string{"tank", "tank/docs", "tank/docs/2026", "tank/vmdisk", "tank/incusish"}
	if !reflect.DeepEqual(in, want) {
		t.Fatalf("included %v, want %v", in, want)
	}
	for _, n := range []string{"tank/incus", "tank/incus/containers/c1", "tank/incus/virtual-machines/v1.block",
		"tank/ZNAS-Backups-Workload", "tank/ZNAS-Backups-Workload/x", "tank/replica", "tank/replica/sub"} {
		if skip[n] == "" {
			t.Errorf("%s should be skipped", n)
		}
	}
}

func TestClassifyTreeNeverSkipsThePolicyDataset(t *testing.T) {
	got := classifyTree([]TreeDataset{{Name: "tank/legacyroot", Type: "filesystem", Mountpoint: "legacy"}}, nil)
	if got[0].Skip != "" {
		t.Fatalf("policy dataset skipped: %q", got[0].Skip)
	}
}

func TestPolicyPrunePlan(t *testing.T) {
	out := "" +
		// parent: 2 untagged (pre-tagging) + 3 tagged, keep 3 → oldest 2 go
		"tank/a@auto-1\t1\t-\n" +
		"tank/a@auto-2\t2\t-\n" +
		"tank/a@auto-3\t3\tP1\n" +
		"tank/a@auto-4\t4\tP1\n" +
		"tank/a@auto-5\t5\tP1\n" +
		// another policy with the same label on the same dataset: never ours
		"tank/a@auto-9\t9\tP2\n" +
		// manual snapshot: never ours
		"tank/a@before-upgrade\t6\t-\n" +
		// child: 4 tagged → oldest 1 goes; untagged child snapshot with our label stays
		"tank/a/b@auto-2\t2\tP1\n" +
		"tank/a/b@auto-3\t3\tP1\n" +
		"tank/a/b@auto-4\t4\tP1\n" +
		"tank/a/b@auto-5\t5\tP1\n" +
		"tank/a/b@auto-0\t0\t-\n" +
		// child with its own policy P3 and the same label: not ours
		"tank/a/c@auto-1\t1\tP3\n" +
		"tank/a/c@auto-2\t2\tP3\n" +
		"tank/a/c@auto-3\t3\tP3\n" +
		"tank/a/c@auto-4\t4\tP3\n" +
		// child that only has 2 of ours: nothing to drop
		"tank/a/d@auto-4\t4\tP1\n" +
		"tank/a/d@auto-5\t5\tP1\n"
	got := policyPrunePlan(parsePolicySnaps(out), "tank/a", "auto", "P1", 3, nil)
	sort.Strings(got)
	want := []string{"tank/a/b@auto-2", "tank/a@auto-1", "tank/a@auto-2"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prune %v, want %v", got, want)
	}
}

func TestPolicyPrunePlanLabelPrefixIsExact(t *testing.T) {
	// label "auto" must not claim "autumn-…" snapshots
	out := "tank/a@autumn-1\t1\t-\ntank/a@auto-1\t2\t-\ntank/a@auto-2\t3\t-\n"
	got := policyPrunePlan(parsePolicySnaps(out), "tank/a", "auto", "P1", 1, nil)
	if !reflect.DeepEqual(got, []string{"tank/a@auto-1"}) {
		t.Fatalf("got %v", got)
	}
}

func TestBuildRestorePlan(t *testing.T) {
	out := "" +
		"tank/a@s1\t1\t-\n" +
		"tank/a@s2\t2\t-\n" +
		"tank/a@s3\t3\t-\n" +
		"tank/a/b@s1\t1\t-\n" +
		"tank/a/b@s2\t2\t-\n" +
		"tank/a/b@s3\t3\ttank/clone1\n" + // newer snapshot with a clone → blocked
		"tank/a/new@s3\t3\t-\n" // child created after s2
	tree := []string{"tank/a", "tank/a/b", "tank/a/new", "tank/a/empty"}
	p := buildRestorePlan(out, "tank/a", "s2", tree)
	if len(p.Targets) != 2 || p.Targets[0].Dataset != "tank/a" || p.Targets[1].Dataset != "tank/a/b" {
		t.Fatalf("targets %+v", p.Targets)
	}
	if !reflect.DeepEqual(p.Targets[0].Newer, []string{"s3"}) {
		t.Fatalf("newer %v", p.Targets[0].Newer)
	}
	if !p.Blocked || !reflect.DeepEqual(p.Targets[1].Clones, []string{"tank/clone1"}) {
		t.Fatalf("clone should block: %+v", p)
	}
	if !reflect.DeepEqual(p.Untouched, []string{"tank/a/new", "tank/a/empty"}) {
		t.Fatalf("untouched %v", p.Untouched)
	}
	// latest snapshot: nothing newer, not blocked
	p = buildRestorePlan(out, "tank/a", "s3", []string{"tank/a"})
	if p.Blocked || len(p.Targets) != 1 || len(p.Targets[0].Newer) != 0 {
		t.Fatalf("latest: %+v", p)
	}
}

// Issue #189: policies deleted and re-created leave snapshots tagged with the
// old id. The new policy with the same label takes them over on its dataset
// and included children; live policies, other labels, children outside the
// policy and a missing live list are left alone.
func TestOrphanCandidates(t *testing.T) {
	out := "" +
		"tank/a@auto-1\t1\tOLD\n" + // deleted policy, our label → adopt
		"tank/a@auto-2\t2\tP2\n" + // live policy → never
		"tank/a@daily-1\t3\tOLD\n" + // other label → never
		"tank/a@auto-3\t4\tP1\n" + // ours already
		"tank/a/b@auto-1\t1\tOLD\n" + // included child → adopt
		"tank/a/replica@auto-1\t1\tREMOTE\n" // not included → never
	snaps := parsePolicySnaps(out)
	live := map[string]bool{"P1": true, "P2": true}
	got := orphanCandidates(snaps, "tank/a", "auto", "P1", live, map[string]bool{"tank/a": true, "tank/a/b": true})
	if !reflect.DeepEqual(got, []string{"tank/a@auto-1", "tank/a/b@auto-1"}) {
		t.Fatalf("got %v", got)
	}
	if got := orphanCandidates(snaps, "tank/a", "auto", "P1", nil, nil); got != nil {
		t.Fatalf("no live list must adopt nothing, got %v", got)
	}
	// Non-recursive: children are not included.
	if got := orphanCandidates(snaps, "tank/a", "auto", "P1", live, nil); !reflect.DeepEqual(got, []string{"tank/a@auto-1"}) {
		t.Fatalf("non-recursive got %v", got)
	}
}

func TestPolicyPrunePlanAdoptsOrphans(t *testing.T) {
	out := "" +
		"tank/a@auto-1\t1\tOLD\n" +
		"tank/a@auto-2\t2\tOLD\n" +
		"tank/a@auto-3\t3\tP1\n" +
		"tank/a@auto-4\t4\tP1\n" +
		"tank/a/b@auto-1\t1\tOLD\n" +
		"tank/a/b@auto-4\t4\tP1\n"
	adopt := map[string]bool{"tank/a@auto-1": true, "tank/a@auto-2": true, "tank/a/b@auto-1": true}
	got := policyPrunePlan(parsePolicySnaps(out), "tank/a", "auto", "P1", 1, adopt)
	sort.Strings(got)
	want := []string{"tank/a/b@auto-1", "tank/a@auto-1", "tank/a@auto-2", "tank/a@auto-3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prune %v, want %v", got, want)
	}
	// Without adoption the old-id snapshots stay (the #189 symptom).
	got = policyPrunePlan(parsePolicySnaps(out), "tank/a", "auto", "P1", 1, nil)
	if !reflect.DeepEqual(got, []string{"tank/a@auto-3"}) {
		t.Fatalf("no-adopt prune %v", got)
	}
}

func TestParseLocalTagged(t *testing.T) {
	out := "tank/a@auto-1\tlocal\ntank/a/rep@auto-1\treceived\ntank/a@manual\t-\n"
	got := parseLocalTagged(out)
	if !got["tank/a@auto-1"] || got["tank/a/rep@auto-1"] || got["tank/a@manual"] {
		t.Fatalf("got %v", got)
	}
}
