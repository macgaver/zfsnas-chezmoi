package system

import (
	"os"
	"path/filepath"
	"testing"
)

// A bridge that netplan or ifupdown already defines must be reported, so
// CreateLXDNetwork refuses to hand the same interface to Incus as well.
func TestHostManagedBridgeSource(t *testing.T) {
	dir := t.TempDir()
	origNP, origIF := netplanDirForTest, interfacesFileForTest
	defer func() { netplanDirForTest, interfacesFileForTest = origNP, origIF }()

	netplanDirForTest = filepath.Join(dir, "netplan")
	interfacesFileForTest = filepath.Join(dir, "interfaces")
	os.MkdirAll(netplanDirForTest, 0755)

	os.WriteFile(filepath.Join(netplanDirForTest, "01-zfsnas.yaml"), []byte(
		"network:\n  version: 2\n  bridges:\n    vmbr0:\n      dhcp4: true\n"), 0600)
	os.WriteFile(interfacesFileForTest, []byte(
		"auto vmbr7\niface vmbr7 inet dhcp\n  bridge_ports eth9\n"), 0644)

	if got := hostManagedBridgeSource("vmbr0"); got == "" {
		t.Error("netplan-defined vmbr0 should be reported as host-managed")
	}
	if got := hostManagedBridgeSource("vmbr7"); got == "" {
		t.Error("ifupdown-defined vmbr7 should be reported as host-managed")
	}
	// Names the host does NOT manage must stay creatable — otherwise the
	// guard would block legitimate Incus networks.
	for _, name := range []string{"host-nat", "vmbr1", "", "vmbr"} {
		if got := hostManagedBridgeSource(name); got != "" {
			t.Errorf("%q should be free, but was reported as managed by %s", name, got)
		}
	}
}
