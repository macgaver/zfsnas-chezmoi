package handlers

import "testing"

// A homepage API key's PoolTarget selects which single pool's capacity the
// TrueNAS-compatible widget reports. Encoding is "<kind>:<name>" so a zpool and
// a MergerFS pool with the same name can't collide. Empty = default (first
// zpool), preserving pre-existing keys' behavior.

func TestParsePoolTarget(t *testing.T) {
	cases := []struct {
		in         string
		kind, name string
	}{
		{"", "", ""},                              // default
		{"zfs:tank", "zfs", "tank"},               // zpool
		{"mergerfs:media", "mergerfs", "media"},   // union
		{"zfs:", "", ""},                          // empty name → default
		{"mergerfs:", "", ""},                     // empty name → default
		{"tank", "", ""},                          // no kind prefix → default
		{"bogus:x", "", ""},                       // unknown kind → default
		{"zfs:pool:with:colons", "zfs", "pool:with:colons"}, // name may contain colons
	}
	for _, c := range cases {
		k, n := parsePoolTarget(c.in)
		if k != c.kind || n != c.name {
			t.Errorf("parsePoolTarget(%q) = (%q,%q), want (%q,%q)", c.in, k, n, c.kind, c.name)
		}
	}
}

func TestValidatePoolTarget(t *testing.T) {
	zpools := []string{"tank", "backup"}
	mergerfs := []string{"media"}

	valid := []string{"", "zfs:tank", "zfs:backup", "mergerfs:media"}
	for _, v := range valid {
		if err := validatePoolTarget(v, zpools, mergerfs); err != nil {
			t.Errorf("validatePoolTarget(%q) = %v, want nil", v, err)
		}
	}

	invalid := []string{
		"zfs:nope",       // no such zpool
		"mergerfs:nope",  // no such union
		"mergerfs:tank",  // right name, wrong kind
		"zfs:media",      // right name, wrong kind
		"tank",           // missing kind prefix
		"bogus:tank",     // unknown kind
		"zfs:",           // missing name
	}
	for _, v := range invalid {
		if err := validatePoolTarget(v, zpools, mergerfs); err == nil {
			t.Errorf("validatePoolTarget(%q) = nil, want error", v)
		}
	}
}
