package system

import "testing"

// A disk of the same size as the pool disk must be accepted: on 512 B
// sectors sgdisk's partition is the disk minus 2048+33 sectors.
func TestMirrorPartOverheadSameSizeDisk(t *testing.T) {
	const disk = 8589934592        // 8 GiB, as seen on the test VM
	const member = disk - 2081*512 // its ZFS partition (8588869120)
	if member+mirrorPartOverhead(512) > disk {
		t.Fatalf("an identical 8 GiB disk would be refused: needs %d, has %d", member+mirrorPartOverhead(512), disk)
	}
	if member+mirrorPartOverhead(512) != disk {
		t.Fatalf("overhead should match sgdisk exactly, got %d", mirrorPartOverhead(512))
	}
	if mirrorPartOverhead(0) != mirrorPartOverhead(512) {
		t.Fatal("unknown sector size should default to 512")
	}
}
