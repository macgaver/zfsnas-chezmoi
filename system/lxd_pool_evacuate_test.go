package system

import (
	"reflect"
	"strings"
	"testing"
)

func disk(pool, path, source string) map[string]string {
	d := map[string]string{"type": "disk", "pool": pool}
	if path != "" {
		d["path"] = path
	}
	if source != "" {
		d["source"] = source
	}
	return d
}

func TestBuildEvacPlanOrderAndStops(t *testing.T) {
	insts := []evacInst{
		// root on the pool, running, owns data1 which web also uses (running)
		{Name: "db", Type: "virtual-machine", Status: "Running", Devices: map[string]map[string]string{
			"root": disk("old", "/", ""), "data": disk("old", "/data", "data1")}},
		// root elsewhere, uses data1 and an ISO on the pool
		{Name: "web", Type: "container", Status: "Running", Devices: map[string]map[string]string{
			"root": disk("fast", "/", ""), "data": disk("old", "/srv", "data1")}},
		{Name: "vm2", Type: "virtual-machine", Status: "Stopped", Devices: map[string]map[string]string{
			"root": disk("fast", "/", ""), "cd": disk("old", "", "debian.iso")}},
		// root on the pool, stopped
		{Name: "a-old", Type: "container", Status: "Stopped", Devices: map[string]map[string]string{
			"root": disk("old", "/", "")}},
		// unrelated
		{Name: "other", Type: "container", Status: "Running", Devices: map[string]map[string]string{
			"root": disk("fast", "/", "")}},
	}
	vols := []evacVol{
		{Name: "data1", Type: "custom", ContentType: "filesystem"},
		{Name: "debian.iso", Type: "custom", ContentType: "iso"},
		{Name: "loose", Type: "custom", ContentType: "block"},
		{Name: "loose/snap0", Type: "custom", ContentType: "block"},
		{Name: "abc123", Type: "image"},
		{Name: "db", Type: "virtual-machine"},
		{Name: "a-old", Type: "container"},
	}
	profiles := []evacProfile{
		{Name: "default", Devices: map[string]map[string]string{"root": disk("old", "/", "")}},
		{Name: "gpu", Devices: map[string]map[string]string{"root": disk("fast", "/", "")}},
	}
	steps, blocked := buildEvacPlan("old", insts, vols, profiles)
	if blocked != "" {
		t.Fatalf("unexpected block: %s", blocked)
	}
	type row struct {
		Kind, Name string
		Vols, Stop []string
	}
	var got []row
	for _, s := range steps {
		if s.Status != "pending" {
			t.Errorf("%s %s status %q", s.Kind, s.Name, s.Status)
		}
		got = append(got, row{s.Kind, s.Name, s.Vols, s.Stop})
	}
	want := []row{
		{"profile", "default", nil, nil},
		{"instance", "a-old", nil, nil},
		{"instance", "db", []string{"data1"}, []string{"db", "web"}},
		{"volume", "debian.iso", nil, nil},
		{"volume", "loose", nil, nil},
		{"image", "abc123", nil, nil},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plan:\n got  %+v\n want %+v", got, want)
	}
}

func TestBuildEvacPlanOtherProjectBlocks(t *testing.T) {
	insts := []evacInst{{Name: "x", Project: "lab", Status: "Stopped",
		Devices: map[string]map[string]string{"root": disk("old", "/", "")}}}
	_, blocked := buildEvacPlan("old", insts, nil, nil)
	if blocked == "" {
		t.Fatal("instance in another project must block the plan")
	}
}

func TestBuildEvacPlanEmptyPool(t *testing.T) {
	steps, blocked := buildEvacPlan("old", nil, nil, []evacProfile{
		{Name: "default", Devices: map[string]map[string]string{"root": disk("fast", "/", "")}}})
	if len(steps) != 0 || blocked != "" {
		t.Fatalf("empty pool: steps=%v blocked=%q", steps, blocked)
	}
}

func TestValidPoolName(t *testing.T) {
	for _, ok := range []string{"warning2tb-ds", "nvme_datastore", "p.1"} {
		if !validPoolName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "-x", ".x", "a/b", "a b", "a;rm"} {
		if validPoolName(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestEvacNameClashes(t *testing.T) {
	steps := []EvacStep{
		{Kind: "instance", Name: "db", Vols: []string{"data1"}},
		{Kind: "volume", Name: "debian.iso"},
		{Kind: "image", Name: "abc"},
	}
	tv := []evacVol{{Name: "data1", Type: "custom"}, {Name: "db", Type: "virtual-machine"}, {Name: "abc", Type: "image"}}
	got := evacNameClashes(steps, "fast", tv)
	if got == "" || !strings.Contains(got, "data1") || strings.Contains(got, "abc") {
		t.Fatalf("clash = %q", got)
	}
	if evacNameClashes(steps, "fast", nil) != "" {
		t.Fatal("no clash expected on an empty target")
	}
}
