package alerts

import "testing"

func TestMinVMDiskFullThreshold(t *testing.T) {
	cfg := &AlertConfig{}
	if on, _ := MinVMDiskFullThreshold(cfg); on {
		t.Fatal("enabled with no targets")
	}
	cfg.Ntfy.Enabled = true
	cfg.Ntfy.Events.VMDiskFull = true // threshold 0 → 90
	cfg.Email.Enabled = true
	cfg.Email.Events.VMDiskFull = true
	cfg.Email.Events.VMDiskFullThresholdPct = 80
	cfg.Gotify.Events.VMDiskFull = true // target disabled: ignored
	cfg.Gotify.Events.VMDiskFullThresholdPct = 50
	if on, pct := MinVMDiskFullThreshold(cfg); !on || pct != 80 {
		t.Fatalf("got %v %d", on, pct)
	}
}
