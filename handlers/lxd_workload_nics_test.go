package handlers

import "testing"

// A VM without the Incus agent (Windows) is measured from the host: Incus
// names its NICs after the Incus devices (net0) and its disks dev-incus_<name>.
// Both must reach the Monitor charts and the table columns.
func TestInstanceNICsAgentlessVM(t *testing.T) {
	cases := []struct {
		devs []string
		want []string
	}{
		{[]string{"lo", "eth0", "docker0", "veth1a2b"}, []string{"eth0"}}, // agent: guest names only
		{[]string{"net0"}, []string{"net0"}},                              // agentless: Incus device name
		{[]string{"lan", "tap123"}, []string{"lan"}},                      // any name, plumbing still dropped
		{[]string{"enp5s0", "net0"}, []string{"enp5s0"}},                  // a guest name wins
		{[]string{"lo", "docker0"}, nil},                                  // nothing real
	}
	for _, c := range cases {
		got := instanceNICs(c.devs)
		if len(got) != len(c.want) {
			t.Errorf("instanceNICs(%v) = %v, want %v", c.devs, got, c.want)
			continue
		}
		for _, w := range c.want {
			if !got[w] {
				t.Errorf("instanceNICs(%v) = %v, want %v", c.devs, got, c.want)
			}
		}
	}
}

func TestPhysicalDiskReAgentlessVM(t *testing.T) {
	for _, d := range []string{"sda", "vdb", "nvme0n1", "dev-incus_root", "dev-incus_disk1"} {
		if !physicalDiskRe.MatchString(d) {
			t.Errorf("%q should count as a disk", d)
		}
	}
	for _, d := range []string{"sda1", "dm-0", "loop3", "/machine/system.flash0", "nvme0n1p2"} {
		if physicalDiskRe.MatchString(d) {
			t.Errorf("%q should not count as a disk", d)
		}
	}
}
