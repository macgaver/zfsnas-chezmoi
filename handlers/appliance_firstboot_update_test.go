package handlers

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"zfsnas/internal/updater"
)

// The whole point of the first-boot update: a release that does not verify
// must leave the binary that shipped in the image in place.
func TestFirstBootUpdateKeepsBakedBinaryOnBadSignature(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "bin", "zfsnas")
	os.MkdirAll(filepath.Dir(dest), 0755)
	os.WriteFile(dest, []byte("baked"), 0755)

	var downloaded string
	deps := firstBootDeps{
		download: func(url, destDir string) (string, error) {
			downloaded = filepath.Join(destDir, "tmp-download")
			return downloaded, os.WriteFile(downloaded, []byte("tampered"), 0755)
		},
		verify:  func(string, string) error { return errors.New("signature invalid") },
		replace: func(string, string) error { t.Fatal("must not install an unverified binary"); return nil },
	}

	err := installFirstBootRelease(updater.ReleaseInfo{
		Tag: "v9.9.9", DownloadURL: "https://example/zfsnas", SigURL: "https://example/zfsnas.sig",
	}, dest, deps)
	if err == nil {
		t.Fatal("a bad signature must be an error")
	}
	if b, _ := os.ReadFile(dest); string(b) != "baked" {
		t.Fatalf("baked binary was replaced: %q", b)
	}
	if _, err := os.Stat(downloaded); !os.IsNotExist(err) {
		t.Fatal("the rejected download must be deleted, not left in the persist store")
	}
}

func TestFirstBootUpdateRefusesUnsignedRelease(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "bin", "zfsnas")
	deps := firstBootDeps{
		download: func(string, string) (string, error) { t.Fatal("must not download an unsigned release"); return "", nil },
		verify:   func(string, string) error { return nil },
		replace:  func(string, string) error { return nil },
	}
	if err := installFirstBootRelease(updater.ReleaseInfo{
		Tag: "v9.9.9", DownloadURL: "https://example/zfsnas",
	}, dest, deps); err == nil {
		t.Fatal("a release with no .sig asset must be refused")
	}
}

func TestFirstBootUpdateInstallsVerifiedRelease(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "bin", "zfsnas")
	deps := firstBootDeps{
		download: func(url, destDir string) (string, error) {
			p := filepath.Join(destDir, "tmp-download")
			return p, os.WriteFile(p, []byte("newer"), 0755)
		},
		verify:  func(string, string) error { return nil },
		replace: func(tmp, d string) error { return os.Rename(tmp, d) },
	}
	if err := installFirstBootRelease(updater.ReleaseInfo{
		Tag: "v9.9.9", DownloadURL: "https://example/zfsnas", SigURL: "https://example/zfsnas.sig",
	}, dest, deps); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "newer" {
		t.Fatalf("verified release was not installed: %q", b)
	}
}
