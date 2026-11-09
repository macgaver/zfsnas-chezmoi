package system

import "testing"

func TestNormalizeDiskAlertPct(t *testing.T) {
	ok := map[string]string{"": "", "default": "", "off": "off", "0": "off", "85": "85", " 90% ": "90", "1": "1", "99": "99"}
	for in, want := range ok {
		if got, err := NormalizeDiskAlertPct(in); err != nil || got != want {
			t.Errorf("%q → %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"100", "-5", "abc", "9.5"} {
		if _, err := NormalizeDiskAlertPct(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDiskAlertThreshold(t *testing.T) {
	conf := map[string]string{DiskAlertKey("root"): "75", DiskAlertKey("data"): "off", DiskAlertKey("junk"): "x"}
	cases := map[string]int{"root": 75, "data": 0, "other": 90, "junk": 90}
	for dev, want := range cases {
		if got := diskAlertThreshold(conf, dev, 90); got != want {
			t.Errorf("%s: %d want %d", dev, got, want)
		}
	}
}
