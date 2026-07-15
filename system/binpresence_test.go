package system

import (
	"os"
	"path/filepath"
	"testing"
)

// The sticky positive cache must be forgettable: an optional-feature uninstall
// (UPS/NUT, MinIO, iSCSI, MergerFS, hdparm) removes the binary and calls
// ForgetBinaryPresence so the Is*Installed helpers flip to false without a
// service restart. Regression test for the "UPS still shows installed after
// uninstall" bug.
func TestForgetBinaryPresenceFlipsAfterRemoval(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-upsd")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if !binaryPresent(bin) {
		t.Fatalf("expected %s to be detected as present", bin)
	}

	// Remove the binary; the sticky cache must keep reporting present…
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	if !binaryPresent(bin) {
		t.Fatalf("sticky cache should still report %s present after removal", bin)
	}

	// …until an uninstall flow explicitly forgets it.
	ForgetBinaryPresence(bin)
	if binaryPresent(bin) {
		t.Fatalf("expected %s to be reported absent after ForgetBinaryPresence", bin)
	}
}
