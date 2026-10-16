package system

import "testing"

// The figures seen on .216 (2026-10-07): 768 MiB maximum, 3.9 GB ARC, 3.77 GB
// of pinned metadata, ~930k cached inodes, 32 GB of RAM.
func TestExplainARCPressureOverLimit(t *testing.T) {
	s := &ARCStats{ARCSize: 3915894544, ARCMax: 805306368, TotalRAMBytes: 33328742400, ARCMetaUsed: 3771693840}
	s.Pressure = ARCPressure{DataBytes: 144191488, MetadataBytes: 3771693840, CachedInodes: 928530}
	explainARCPressure(s, true)
	p := s.Pressure
	if p.Status != "over" {
		t.Fatalf("status %q", p.Status)
	}
	if p.BytesPerFile < 3500 || p.BytesPerFile > 4500 {
		t.Errorf("bytes per file %d, want ~4 KB", p.BytesPerFile)
	}
	const gib = int64(1) << 30
	// (3.77 GB + 512 MiB data) * 1.2 ≈ 5.1 GB → rounded up to 512 MiB.
	if p.RecommendedMax < 5*gib || p.RecommendedMax > 6*gib || p.RecommendedMax%(512<<20) != 0 || p.RecommendedCapped {
		t.Errorf("recommended %d (capped %v)", p.RecommendedMax, p.RecommendedCapped)
	}
}

func TestExplainARCPressureOKAndCapped(t *testing.T) {
	s := &ARCStats{ARCSize: 700 << 20, ARCMax: 768 << 20, TotalRAMBytes: 32 << 30, ARCMetaUsed: 200 << 20}
	explainARCPressure(s, true)
	if s.Pressure.Status != "ok" || s.Pressure.RecommendedMax != 0 {
		t.Errorf("within limit: %+v", s.Pressure)
	}
	s = &ARCStats{ARCSize: 3 << 30, ARCMax: 512 << 20, TotalRAMBytes: 4 << 30, ARCMetaUsed: 3 << 30}
	s.Pressure.MetadataBytes = 3 << 30
	explainARCPressure(s, true)
	if !s.Pressure.RecommendedCapped || s.Pressure.RecommendedMax != 2<<30 {
		t.Errorf("small box must cap at half the RAM: %+v", s.Pressure)
	}
	s = &ARCStats{ARCSize: 9 << 30, ARCMax: 16 << 30}
	explainARCPressure(s, false)
	if s.Pressure.Status != "default" {
		t.Errorf("no maximum set: %q", s.Pressure.Status)
	}
}

func TestKernelThreadCPUSecondsRuns(t *testing.T) {
	// No arc_evict on a dev box without ZFS: must just return 0, not fail.
	if v := kernelThreadCPUSeconds("no-such-thread-xyz"); v != 0 {
		t.Errorf("got %v", v)
	}
}
