package system

import "testing"

// The first NAT network keeps the bare name `host-nat` — the default profile
// and existing setups reference it — and additional ones are numbered from 2.
func TestHostNatNetworkName(t *testing.T) {
	for i, want := range []string{"host-nat", "host-nat2", "host-nat3", "host-nat4"} {
		if got := HostNatNetworkName(i); got != want {
			t.Errorf("HostNatNetworkName(%d) = %q, want %q", i, got, want)
		}
	}
	if got := HostNatNetworkName(-1); got != "host-nat" {
		t.Errorf("negative index should fall back to host-nat, got %q", got)
	}
}

func TestIsHostNatNetwork(t *testing.T) {
	for _, name := range []string{"host-nat", "host-nat2", "host-nat10"} {
		if !IsHostNatNetwork(name) {
			t.Errorf("%q should be recognised as one of ours", name)
		}
	}
	// Must not swallow unrelated names — they'd be wrongly treated as internal
	// and their addresses skipped when picking the server's public IP.
	for _, name := range []string{"host-natx", "host-nat-lab", "vmbr0", "hostnat", "host-na"} {
		if IsHostNatNetwork(name) {
			t.Errorf("%q should NOT be treated as a host-nat network", name)
		}
	}
}
