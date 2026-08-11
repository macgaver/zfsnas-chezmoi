package handlers

import (
	"testing"

	"zfsnas/system"
)

// Getting this wrong in either direction is costly: too permissive and a
// backup clone's containers become services; too strict and a healthy
// instance is never authoritative, so its removed services are never pruned.
func TestScannableInstance(t *testing.T) {
	cases := []struct {
		name string
		inst system.LXDInstance
		want bool
	}{
		{"running container", system.LXDInstance{Name: "ipsvc", Status: "Running"}, true},
		{"running vm", system.LXDInstance{Name: "buildserver3", Status: "Running"}, true},
		{"stopped", system.LXDInstance{Name: "vm-off", Status: "Stopped"}, false},
		{"frozen", system.LXDInstance{Name: "vm-frozen", Status: "Frozen"}, false},
		{"backup clone", system.LXDInstance{Name: "bkup--ipsvc", Status: "Running"}, false},
	}
	for _, tc := range cases {
		if got := scannableInstance(tc.inst); got != tc.want {
			t.Errorf("%s: scannableInstance = %v, want %v", tc.name, got, tc.want)
		}
	}
}
