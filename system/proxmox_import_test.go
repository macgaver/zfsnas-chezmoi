package system

import (
	"strings"
	"testing"
)

// Regression: importing into a datastore other than the one the default
// profile points at used to fail with "Cannot update root disk device pool
// name to X", because the VM was created with a plain `init --empty` (which
// inherits the profile's root disk) and the pool was only set afterwards.
// Incus does not allow a root disk to change pools, so the pool has to be
// part of the creation command.
func TestProxmoxInitArgsPinsRootPoolAtCreation(t *testing.T) {
	args := proxmoxInitArgs("DAPv12", "raid6tb-ds", "32GiB")
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--storage raid6tb-ds") {
		t.Fatalf("the datastore must be set at init: %q", joined)
	}
	if strings.Contains(joined, "pool=") {
		t.Fatalf("`-d root,pool=` only overrides a device the profile already has — use --storage: %q", joined)
	}
	if !strings.Contains(joined, "root,size=32GiB") {
		t.Fatalf("root size missing: %q", joined)
	}
	if !strings.Contains(joined, "root,boot.priority=1") {
		t.Fatalf("root must stay the boot device: %q", joined)
	}
}

func TestProxmoxInitArgsWithoutPoolOrSize(t *testing.T) {
	args := proxmoxInitArgs("vm1", "", "")
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--storage") {
		t.Fatalf("no pool requested, none should be passed: %q", joined)
	}
	if strings.Contains(joined, "root,size=") {
		t.Fatalf("unknown disk size must not become an empty size flag: %q", joined)
	}
}
