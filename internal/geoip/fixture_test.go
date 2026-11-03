package geoip

import (
	"os"
	"testing"
)

// TestWriteFixture regenerates system/testdata/tiny-country.mmdb when
// GEOIP_WRITE_FIXTURE is set (used by the geo DB download tests).
func TestWriteFixture(t *testing.T) {
	out := os.Getenv("GEOIP_WRITE_FIXTURE")
	if out == "" {
		t.Skip("set GEOIP_WRITE_FIXTURE=<path>")
	}
	p := writeTestDB(t, 6, 24, "DBIP-Country-Lite", map[string]map[string]any{
		"89.160.20.0/24": {"country": map[string]any{"iso_code": "SE", "names": map[string]any{"en": "Sweden"}}},
	})
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(out, b, 0644); err != nil {
		t.Fatal(err)
	}
}
