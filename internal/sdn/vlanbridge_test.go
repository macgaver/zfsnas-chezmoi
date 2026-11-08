package sdn

import (
	"strings"
	"testing"
)

// A VLAN's VM-network bridge must be unique per VLAN and fit IFNAMSIZ-1,
// also on long port names (enp5s0f0) where "br-"+device is 16+ characters.
func TestBridgeDeviceNameUniqueAndShort(t *testing.T) {
	// Names that already fit keep their historic form (live bridges on
	// existing installs must not be renamed).
	if got := BridgeDeviceName("vmbr0-v700"); got != "br-vmbr0-v700" {
		t.Fatalf("short name changed: %q", got)
	}
	seen := map[string]string{}
	for _, parent := range []string{"enp5s0f0", "enp5s0f1", "enx00e04c680001", "eno1"} {
		for _, tag := range []int{7, 700, 701, 1000, 1001, 4094} {
			dev := VLANDeviceName(parent, tag)
			br := BridgeDeviceName(dev)
			if len(br) > 15 {
				t.Errorf("%s: bridge %q longer than 15", dev, br)
			}
			if br == dev {
				t.Errorf("%s: bridge has the device's own name", dev)
			}
			if prev, ok := seen[br]; ok && prev != dev {
				t.Errorf("bridge %q shared by %s and %s", br, prev, dev)
			}
			seen[br] = dev
		}
	}
}

// Two VLANs whose bridges would still share a name must be refused at
// validation, never silently merged into one bridge.
func TestValidateRejectsSharedVLANBridge(t *testing.T) {
	c := &Config{Settings: Settings{Mode: "router"}, Interfaces: []Interface{
		{ID: "a", Name: "A", Kind: "vlan", Parent: "eno1", VLANTag: 10, AllowVMs: true, IPv4Mode: "none"},
		{ID: "b", Name: "B", Kind: "bridge", Device: "br-eno1-v10", IPv4Mode: "none"},
	}}
	c.Normalize()
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "br-eno1-v10 is already used") {
		t.Fatalf("expected the shared bridge name to be refused, got %v", err)
	}
}
