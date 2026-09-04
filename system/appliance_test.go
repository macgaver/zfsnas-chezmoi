// system/appliance_test.go
package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplianceModeUncached(t *testing.T) {
	dir := t.TempDir()
	orig := applianceMarkerPath
	defer func() { applianceMarkerPath = orig }()

	applianceMarkerPath = filepath.Join(dir, "zfsnas-appliance")
	if applianceModeUncached() {
		t.Fatal("no marker file: expected false")
	}
	if err := os.WriteFile(applianceMarkerPath, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if !applianceModeUncached() {
		t.Fatal("marker file present: expected true")
	}
}

func TestApplianceRelease(t *testing.T) {
	dir := t.TempDir()
	orig := applianceReleasePath
	defer func() { applianceReleasePath = orig }()

	applianceReleasePath = filepath.Join(dir, "zfsnas-release")
	if v, d := ApplianceRelease(); v != "" || d != "" {
		t.Fatalf("missing file: want empty, got %q %q", v, d)
	}
	os.WriteFile(applianceReleasePath,
		[]byte("version=6.8.28\nbuild_date=2026-08-28\n"), 0644)
	v, d := ApplianceRelease()
	if v != "6.8.28" || d != "2026-08-28" {
		t.Fatalf("got %q %q", v, d)
	}
}

func TestPersistStatus(t *testing.T) {
	dir := t.TempDir()
	orig := persistStatusPath
	defer func() { persistStatusPath = orig }()

	persistStatusPath = filepath.Join(dir, "persist-status")
	if s := PersistStatus(); s != "" {
		t.Fatalf("missing file: want empty, got %q", s)
	}
	os.WriteFile(persistStatusPath, []byte("degraded\n"), 0644)
	if s := PersistStatus(); s != "degraded" {
		t.Fatalf("got %q", s)
	}
}

func TestSyncAuthFiles(t *testing.T) {
	src := t.TempDir()
	store := t.TempDir()

	files := map[string]string{
		"passwd":  "root:x:0:0:root:/root:/bin/bash\n",
		"shadow":  "root:!:19000:0:99999:7:::\n",
		"group":   "root:x:0:\n",
		"gshadow": "root:!::\n",
		// subuid intentionally absent below — must be skipped, not an error
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0640); err != nil {
			t.Fatal(err)
		}
	}
	// subgid present with a distinctive mode, to verify mode preservation
	if err := os.WriteFile(filepath.Join(src, "subgid"), []byte("root:100000:65536\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := syncAuthFiles(src, store); err != nil {
		t.Fatalf("syncAuthFiles: %v", err)
	}

	destDir := filepath.Join(store, "system", "etc-auth")
	for name, content := range files {
		got, err := os.ReadFile(filepath.Join(destDir, name))
		if err != nil {
			t.Fatalf("%s not copied: %v", name, err)
		}
		if string(got) != content {
			t.Fatalf("%s content mismatch: got %q want %q", name, got, content)
		}
	}
	if fi, err := os.Stat(filepath.Join(destDir, "passwd")); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0640 {
		t.Fatalf("passwd mode = %v, want 0640", fi.Mode().Perm())
	}
	if fi, err := os.Stat(filepath.Join(destDir, "subgid")); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0600 {
		t.Fatalf("subgid mode = %v, want 0600", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(destDir, "subuid")); !os.IsNotExist(err) {
		t.Fatalf("subuid: missing source should be skipped (no dest file), got err=%v", err)
	}
}

func TestSyncAuthFilesOverwritesExistingModeAndContent(t *testing.T) {
	src := t.TempDir()
	store := t.TempDir()
	destDir := filepath.Join(store, "system", "etc-auth")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		t.Fatal(err)
	}
	// pre-existing dest with stale content + mode, as if from a prior sync
	if err := os.WriteFile(filepath.Join(destDir, "passwd"), []byte("stale\n"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "passwd"), []byte("fresh:x:0:0::/root:/bin/bash\n"), 0640); err != nil {
		t.Fatal(err)
	}

	if err := syncAuthFiles(src, store); err != nil {
		t.Fatalf("syncAuthFiles: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destDir, "passwd"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "fresh:x:0:0::/root:/bin/bash\n" {
		t.Fatalf("stale content not overwritten: %q", got)
	}
	fi, err := os.Stat(filepath.Join(destDir, "passwd"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0640 {
		t.Fatalf("mode not re-applied to pre-existing dest: got %v want 0640", fi.Mode().Perm())
	}
}

func TestSyncAuthToPersistStoreOffAppliance(t *testing.T) {
	// ApplianceMode() is sync.Once-cached process-wide; on this test
	// runner there is no /etc/zfsnas-appliance marker, so it resolves
	// false the first time it's evaluated anywhere in the package's test
	// binary and stays false for the rest of the run.
	if ApplianceMode() {
		t.Skip("appliance marker present in this environment; off-appliance path not reachable")
	}
	orig := persistStoreDir
	defer func() { persistStoreDir = orig }()
	persistStoreDir = filepath.Join(t.TempDir(), "should-not-be-created")

	if err := SyncAuthToPersistStore(); err != nil {
		t.Fatalf("off-appliance: want nil, got %v", err)
	}
	if _, err := os.Stat(persistStoreDir); !os.IsNotExist(err) {
		t.Fatal("off-appliance sync must not touch the filesystem")
	}
}
