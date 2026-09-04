package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetTimezoneApplianceMode(t *testing.T) {
	dir := t.TempDir()
	origZ, origL, origT := zoneinfoDir, localtimePath, timezonePath
	defer func() { zoneinfoDir, localtimePath, timezonePath = origZ, origL, origT }()

	zoneinfoDir = filepath.Join(dir, "zoneinfo")
	localtimePath = filepath.Join(dir, "localtime")
	timezonePath = filepath.Join(dir, "timezone")

	os.MkdirAll(filepath.Join(zoneinfoDir, "Europe"), 0755)
	os.WriteFile(filepath.Join(zoneinfoDir, "Europe", "Paris"), []byte("TZDATA"), 0644)
	os.WriteFile(localtimePath, []byte("OLD"), 0644) // simulates the bound file

	if err := setTimezoneApplianceMode("Europe/Paris"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(localtimePath); string(b) != "TZDATA" {
		t.Fatalf("localtime not written through: %q", b)
	}
	if b, _ := os.ReadFile(timezonePath); string(b) != "Europe/Paris\n" {
		t.Fatalf("timezone file: %q", b)
	}
	// traversal + junk must be rejected
	for _, bad := range []string{"../etc/passwd", "Europe/../../x", "a b", ""} {
		if err := setTimezoneApplianceMode(bad); err == nil {
			t.Fatalf("accepted bad tz %q", bad)
		}
	}
}
