package system

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeIface writes a sysfs-shaped fixture for one interface. A nil attr value
// means "the file does not exist"; the kernel omits `speed` on virtual devices
// and fails the read outright on a link that is down.
func fakeIface(t *testing.T, root, name string, attrs map[string]string, bridge bool) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if bridge {
		if err := os.MkdirAll(filepath.Join(dir, "bridge"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range attrs {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func withFakeSysfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	old := sysClassNet
	sysClassNet = root
	t.Cleanup(func() { sysClassNet = old })
	return root
}

func TestFormatNICSpeed(t *testing.T) {
	cases := []struct {
		mbps int
		want string
	}{
		{0, ""},
		{-1, ""},
		{10, "10 Mb/s"},
		{100, "100 Mb/s"},
		{999, "999 Mb/s"},
		{1000, "1 Gb/s"},
		{2500, "2.5 Gb/s"},
		{5000, "5 Gb/s"},
		{10000, "10 Gb/s"},
		{25000, "25 Gb/s"},
		{40000, "40 Gb/s"},
		{100000, "100 Gb/s"},
	}
	for _, c := range cases {
		if got := FormatNICSpeed(c.mbps); got != c.want {
			t.Errorf("FormatNICSpeed(%d) = %q, want %q", c.mbps, got, c.want)
		}
	}
}

func TestNICSpeedMbps(t *testing.T) {
	root := withFakeSysfs(t)
	fakeIface(t, root, "enp1s0", map[string]string{"operstate": "up", "speed": "1000"}, false)
	fakeIface(t, root, "enp2s0", map[string]string{"operstate": "up", "speed": "10000"}, false)
	// Unplugged: the kernel keeps the file but the read fails; the fixture
	// models the other shape drivers use — the -1 sentinel.
	fakeIface(t, root, "enp3s0", map[string]string{"operstate": "down", "speed": "-1"}, false)
	// operstate "unknown" is common on some drivers — carrier decides.
	fakeIface(t, root, "enp4s0", map[string]string{"operstate": "unknown", "carrier": "1", "speed": "2500"}, false)
	fakeIface(t, root, "enp5s0", map[string]string{"operstate": "unknown", "carrier": "0", "speed": "1000"}, false)
	// Some drivers hand back -1 as an unsigned 32-bit value.
	fakeIface(t, root, "enp6s0", map[string]string{"operstate": "up", "speed": "4294967295"}, false)
	// A bridge aggregates ports and has no link of its own.
	fakeIface(t, root, "vmbr0", map[string]string{"operstate": "up", "speed": "1000"}, true)
	// Virtual instance ports report a bogus 10G.
	fakeIface(t, root, "veth1a2b", map[string]string{"operstate": "up", "speed": "10000"}, false)
	fakeIface(t, root, "tap0", map[string]string{"operstate": "up", "speed": "10000"}, false)

	cases := []struct {
		iface string
		want  int
	}{
		{"enp1s0", 1000},
		{"enp2s0", 10000},
		{"enp3s0", 0},
		{"enp4s0", 2500},
		{"enp5s0", 0},
		{"enp6s0", 0},
		{"vmbr0", 0},
		{"veth1a2b", 0},
		{"tap0", 0},
		{"", 0},
		{"nosuchnic", 0},
		{"../../etc/passwd", 0},
	}
	for _, c := range cases {
		if got := NICSpeedMbps(c.iface); got != c.want {
			t.Errorf("NICSpeedMbps(%q) = %d, want %d", c.iface, got, c.want)
		}
	}
}

func TestNICSpeedLabelUsesHumanUnits(t *testing.T) {
	root := withFakeSysfs(t)
	fakeIface(t, root, "enp1s0", map[string]string{"operstate": "up", "speed": "1000"}, false)
	if got := NICSpeedLabel("enp1s0"); got != "1 Gb/s" {
		t.Errorf("NICSpeedLabel = %q, want %q", got, "1 Gb/s")
	}
	if got := NICSpeedLabel("enp9s0"); got != "" {
		t.Errorf("NICSpeedLabel(missing) = %q, want empty", got)
	}
}

func TestNICSpeedsLabelCollapsesAndSorts(t *testing.T) {
	root := withFakeSysfs(t)
	fakeIface(t, root, "enp1s0", map[string]string{"operstate": "up", "speed": "1000"}, false)
	fakeIface(t, root, "enp2s0", map[string]string{"operstate": "up", "speed": "1000"}, false)
	fakeIface(t, root, "enp3s0", map[string]string{"operstate": "up", "speed": "10000"}, false)
	fakeIface(t, root, "enp4s0", map[string]string{"operstate": "down"}, false)

	// Two identical rates collapse to one label rather than repeating.
	if label, max := NICSpeedsLabel([]string{"enp1s0", "enp2s0"}); label != "1 Gb/s" || max != 1000 {
		t.Errorf("identical ports = (%q, %d), want (%q, %d)", label, max, "1 Gb/s", 1000)
	}
	// Mixed rates list both, and the fastest drives the sort key.
	if label, max := NICSpeedsLabel([]string{"enp1s0", "enp3s0"}); label != "1 Gb/s, 10 Gb/s" || max != 10000 {
		t.Errorf("mixed ports = (%q, %d), want (%q, %d)", label, max, "1 Gb/s, 10 Gb/s", 10000)
	}
	// A port with no carrier contributes nothing at all.
	if label, max := NICSpeedsLabel([]string{"enp4s0"}); label != "" || max != 0 {
		t.Errorf("down port = (%q, %d), want (%q, 0)", label, max, "")
	}
	if label, max := NICSpeedsLabel(nil); label != "" || max != 0 {
		t.Errorf("no ports = (%q, %d), want (%q, 0)", label, max, "")
	}
}

// The Speed column must describe exactly the interface the "Physical NIC"
// column names — enslaved ports when there are any, otherwise the NAT uplink,
// and nothing at all for an isolated bridge.
func TestPhysicalNICsMirrorsPhysicalNICColumn(t *testing.T) {
	cases := []struct {
		name string
		net  LXDNetwork
		want []string
	}{
		{"enslaved port", LXDNetwork{Ports: []string{"enp1s0"}}, []string{"enp1s0"}},
		{"instance ports ignored", LXDNetwork{Ports: []string{"veth1a", "tap3", "enp1s0"}}, []string{"enp1s0"}},
		{"vlan child ignored", LXDNetwork{Ports: []string{"vlan100"}}, nil},
		{"veth peer suffix", LXDNetwork{Ports: []string{"veth9x@if4"}}, nil},
		{"nat falls back to uplink", LXDNetwork{NAT: true, Uplink: "enp2s0"}, []string{"enp2s0"}},
		{"enslaved port beats uplink", LXDNetwork{Ports: []string{"enp1s0"}, NAT: true, Uplink: "enp2s0"}, []string{"enp1s0"}},
		{"isolated bridge", LXDNetwork{}, nil},
		{"physical network is itself a nic", LXDNetwork{Type: "physical", Name: "enp5s0"}, []string{"enp5s0"}},
		{"vlan network is itself a nic", LXDNetwork{Type: "vlan", Name: "enp5s0.100"}, []string{"enp5s0.100"}},
		{"loopback is not", LXDNetwork{Type: "loopback", Name: "lo"}, nil},
		{"non-nat with uplink set", LXDNetwork{Uplink: "enp2s0"}, nil},
	}
	for _, c := range cases {
		got := c.net.physicalNICs()
		if len(got) != len(c.want) {
			t.Errorf("%s: physicalNICs() = %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: physicalNICs() = %v, want %v", c.name, got, c.want)
				break
			}
		}
	}
}

// The table reads speed_label/speed_mbps straight off the JSON, so the wire
// contract matters as much as the formatting: a renamed or omitted field shows
// up as a silently empty column rather than a build failure.
func TestLXDNetworkSpeedJSONContract(t *testing.T) {
	root := withFakeSysfs(t)
	fakeIface(t, root, "enp1s0", map[string]string{"operstate": "up", "speed": "10000"}, false)

	n := LXDNetwork{Name: "vmbr0", Type: "bridge", Ports: []string{"enp1s0", "tap9"}}
	n.SpeedLabel, n.SpeedMbps = NICSpeedsLabel(n.physicalNICs())
	if n.SpeedLabel != "10 Gb/s" || n.SpeedMbps != 10000 {
		t.Fatalf("got (%q, %d), want (%q, %d)", n.SpeedLabel, n.SpeedMbps, "10 Gb/s", 10000)
	}
	b, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"speed_label":"10 Gb/s"`, `"speed_mbps":10000`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("marshalled network missing %s\ngot: %s", want, b)
		}
	}
}
