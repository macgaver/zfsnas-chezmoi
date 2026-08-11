package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMoveIsRenameSameFilesystem(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	for _, d := range []string{src, dst} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if !moveIsRename([]string{src}, dst) {
		t.Errorf("same-filesystem move must take the instant-rename path")
	}
}

func TestMoveIsRenameAcrossFilesystems(t *testing.T) {
	// /dev/shm is tmpfs on Linux and therefore a different device from the
	// disk-backed temp dir. Skip rather than fail if that is not true here.
	shm := "/dev/shm"
	if _, err := os.Stat(shm); err != nil {
		t.Skip("no /dev/shm on this host")
	}
	dir := t.TempDir()
	same, err := sameDevice(dir, shm)
	if err != nil {
		t.Fatal(err)
	}
	if same {
		t.Skip("temp dir and /dev/shm share a device here")
	}
	if moveIsRename([]string{dir}, shm) {
		t.Errorf("cross-filesystem move must not take the instant-rename path")
	}
}

// An unreadable or missing path must fall back to the transfer path, which
// works in every case, rather than to the rename path, which would fail.
func TestMoveIsRenameUnknownPathFallsBackToTransfer(t *testing.T) {
	dir := t.TempDir()
	if moveIsRename([]string{filepath.Join(dir, "does-not-exist")}, dir) {
		t.Errorf("unstattable source must not take the instant-rename path")
	}
}

// Every source has to be on the destination's filesystem — one straggler on
// another device makes the whole operation a transfer.
func TestMoveIsRenameMixedSourcesFallsBackToTransfer(t *testing.T) {
	shm := "/dev/shm"
	if _, err := os.Stat(shm); err != nil {
		t.Skip("no /dev/shm on this host")
	}
	dir := t.TempDir()
	same, err := sameDevice(dir, shm)
	if err != nil {
		t.Fatal(err)
	}
	if same {
		t.Skip("temp dir and /dev/shm share a device here")
	}
	local := filepath.Join(dir, "local")
	if err := os.Mkdir(local, 0o755); err != nil {
		t.Fatal(err)
	}
	if moveIsRename([]string{local, shm}, dir) {
		t.Errorf("mixed-device sources must not take the instant-rename path")
	}
}

func TestSameDeviceMissingPathErrors(t *testing.T) {
	if _, err := sameDevice(t.TempDir(), "/definitely/not/here"); err == nil {
		t.Errorf("want an error for a missing path")
	}
}
