package system

import (
	"strings"
	"testing"
)

// Swap device classification drives the card's warning. The distinction that
// matters operationally: swap on a ZFS zvol makes a page-in traverse the ZFS
// stack, and under pool load that fault can stall a VM for minutes. Observed on
// znas5 (2026-08-21): five qemu tasks blocked >122 s in shmem_swapin_folio with
// swap on NVMEPool/swap (/dev/zd160).
func TestClassifySwapDevice(t *testing.T) {
	cases := []struct{ dev, want string }{
		{"/dev/zram0", "zram"},
		{"/dev/zram1", "zram"},
		{"/dev/zd160", "zvol"},
		{"/dev/zd0", "zvol"},
		{"/dev/sda2", "partition"},
		{"/dev/nvme0n1p3", "partition"},
		{"/dev/mapper/vg-swap", "partition"},
		{"/swapfile", "file"},
		{"/var/swap/swapfile", "file"},
	}
	for _, c := range cases {
		if got := classifySwapDevice(c.dev); got != c.want {
			t.Errorf("classifySwapDevice(%q) = %q, want %q", c.dev, got, c.want)
		}
	}
}

// Real /proc/swaps content from znas5 — sizes are in KiB.
func TestParseProcSwaps(t *testing.T) {
	in := `Filename				Type		Size		Used		Priority
/dev/zd160                              partition	16777212	12850608	-1
/dev/zram0                              partition	4194300		1024		100
`
	got := parseProcSwaps(in)
	if len(got) != 2 {
		t.Fatalf("want 2 devices, got %d: %+v", len(got), got)
	}
	if got[0].Name != "/dev/zd160" || got[0].Kind != "zvol" {
		t.Errorf("first device wrong: %+v", got[0])
	}
	if got[0].SizeMB != 16383 || got[0].UsedMB != 12549 {
		t.Errorf("first device sizes wrong: size=%d used=%d", got[0].SizeMB, got[0].UsedMB)
	}
	if got[1].Kind != "zram" {
		t.Errorf("zram not classified: %+v", got[1])
	}
	if parseProcSwaps("Filename\tType\tSize\tUsed\tPriority\n") != nil {
		t.Error("a header-only file must yield no devices")
	}
}

// The value is written to a privileged path, so it is validated server-side —
// the UI slider is a convenience, not the boundary.
func TestValidateSwappiness(t *testing.T) {
	for _, v := range []int{0, 1, 10, 60, 100} {
		if err := validateSwappiness(v); err != nil {
			t.Errorf("valid value %d rejected: %v", v, err)
		}
	}
	for _, v := range []int{-1, 101, 1000, -100} {
		if err := validateSwappiness(v); err == nil {
			t.Errorf("out-of-range value %d accepted", v)
		}
	}
}

// The persisted file must survive reboot and be unambiguous about its owner, so
// a human who finds it knows what wrote it and why.
func TestSwappinessSysctlFile(t *testing.T) {
	out := swappinessSysctlFile(10)
	if !strings.Contains(out, "vm.swappiness = 10") {
		t.Errorf("setting missing from generated file:\n%s", out)
	}
	if !strings.Contains(out, "ZNAS") {
		t.Errorf("generated file does not identify its writer:\n%s", out)
	}
	// Rewriting must replace, never append a second directive — the last one
	// would silently win and the file would misreport itself.
	if n := strings.Count(swappinessSysctlFile(35), "vm.swappiness"); n != 1 {
		t.Errorf("want exactly 1 vm.swappiness directive, got %d", n)
	}
}

// The recommendation is the whole point of the marker on the slider, so it is
// defined once in Go and rendered from the API rather than hardcoded in the UI.
func TestRecommendedSwappiness(t *testing.T) {
	if RecommendedSwappiness != 10 {
		t.Errorf("recommended value changed to %d — the UI marker and the docs "+
			"both read this constant, so update the card copy too", RecommendedSwappiness)
	}
}

// The hardened sudoers template must actually grant what SetSwappiness runs,
// or the card fails on every hardened host with a bare "permission denied".
func TestSwappinessRulesAreInTemplate(t *testing.T) {
	tpl := RequiredSudoersContent()
	for _, want := range []string{
		"/usr/bin/tee " + swappinessProcPath,
		"/usr/bin/tee " + swappinessSysctlPath,
	} {
		if !strings.Contains(tpl, want) {
			t.Errorf("sudoers template is missing %q — SetSwappiness would be denied", want)
		}
	}
	// Every granted line should carry a Review explanation.
	for _, cmd := range []string{
		"/usr/bin/tee " + swappinessProcPath,
		"/usr/bin/tee " + swappinessSysctlPath,
	} {
		if lookupSudoersExplanation(cmd) == "" {
			t.Errorf("no Sudoers Review explanation for %q", cmd)
		}
	}
}
