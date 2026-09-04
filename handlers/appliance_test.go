package handlers

import "testing"

// Off-appliance (the test host), the updater destination must be the
// running exe path, untouched.
func TestUpdaterDestPathOffAppliance(t *testing.T) {
	if got := updaterDestPath("/opt/zfsnas/zfsnas"); got != "/opt/zfsnas/zfsnas" {
		t.Fatalf("got %q", got)
	}
}
