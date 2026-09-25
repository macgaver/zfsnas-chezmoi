package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUbuntuPointVersion(t *testing.T) {
	cases := []struct{ version, id, point, display string }{
		{"26.04.1 LTS (Resolute Raccoon)", "26.04", "26.04.1", "26.04.1 LTS"},
		{"26.04 LTS (Resolute Raccoon)", "26.04", "26.04.0", "26.04 LTS"},
		{"", "26.04", "26.04.0", "26.04"},
		{"", "", "", ""},
	}
	for _, c := range cases {
		p, d := ubuntuPointVersion(c.version, c.id)
		if p != c.point || d != c.display {
			t.Errorf("%q/%q: got %q,%q want %q,%q", c.version, c.id, p, d, c.point, c.display)
		}
	}
}

func TestApplianceImageInfo(t *testing.T) {
	dir := t.TempDir()
	osr := filepath.Join(dir, "os-release")
	rel := filepath.Join(dir, "zfsnas-release")
	os.WriteFile(osr, []byte("NAME=\"Ubuntu\"\nVERSION_ID=\"26.04\"\nVERSION=\"26.04.1 LTS (Resolute Raccoon)\"\n"), 0644)

	// Image built before appliance_version existed: build 0 of its Ubuntu release.
	os.WriteFile(rel, []byte("version=6.9.3\nbuild_date=2026-09-01\n"), 0644)
	if got := applianceImageInfo(rel, osr); got.Version != "26.04.1-0" || got.Display != "26.04.1 LTS" {
		t.Errorf("legacy image: %+v", got)
	}

	os.WriteFile(rel, []byte("version=6.9.3\nappliance_version=26.04.1-2\n"), 0644)
	if got := applianceImageInfo(rel, osr); got.Version != "26.04.1-2" {
		t.Errorf("stamped image: %+v", got)
	}
}
