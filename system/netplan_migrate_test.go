package system

import (
	"reflect"
	"strings"
	"testing"
)

// The NIC is emitted as `auto` (networking.service brings it up); the boot-hang
// race is solved by hardenIfupdownBoot masking ifup@.service, not by switching
// the keyword. `auto` is also required so later bridge/VLAN pre-up stanzas run.
// Regression anchor for the znas3 slow-boot investigation (2026-06-06).
func TestRenderInterfacesFileUsesAuto(t *testing.T) {
	out := renderInterfacesFile([]liveDeviceSnapshot{
		{Name: "enp4s0f0", IPv4: "192.168.2.3/24", Gateway: "192.168.2.1", DNS: []string{"192.168.2.4"}},
	})
	if !strings.Contains(out, "auto enp4s0f0") {
		t.Errorf("expected `auto enp4s0f0`, got:\n%s", out)
	}
	if strings.Contains(out, "allow-hotplug") {
		t.Errorf("should not use allow-hotplug (ifup@ is masked instead):\n%s", out)
	}
	if !strings.Contains(out, "auto lo") {
		t.Errorf("lo must stay `auto`:\n%s", out)
	}
}

func TestParseNetplanYAML(t *testing.T) {
	cases := []struct {
		name       string
		yaml       string
		wantDevs   []string
		wantRender string
		wantUnsupp []string
	}{
		{
			// Exactly what Ubuntu's subiquity installer writes (4-space indent).
			// Regression: the old `+2` indent check returned ethernets=[] here,
			// producing "no ethernet devices found in netplan YAML".
			name: "subiquity 4-space static",
			yaml: `# This is the network config written by 'subiquity'
network:
    ethernets:
        enp4s0f0:
            addresses:
            - 192.168.2.3/24
            mtu: 1500
            nameservers:
                addresses:
                - 192.168.2.4
                search:
                - chezmoi.ca
            routes:
              - to: default
                via: 192.168.2.1
    version: 2
`,
			wantDevs: []string{"enp4s0f0"},
		},
		{
			name: "classic 2-space dhcp",
			yaml: `network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
    eth1:
      dhcp4: true
`,
			wantDevs:   []string{"eth0", "eth1"},
			wantRender: "networkd",
		},
		{
			name: "unsupported bridge surfaced",
			yaml: `network:
    ethernets:
        enp1s0:
            dhcp4: true
    bridges:
        br0:
            interfaces: [enp1s0]
`,
			wantDevs:   []string{"enp1s0"},
			wantUnsupp: []string{"bridges"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := &netplanScanResult{}
			parseNetplanYAMLInto([]byte(tc.yaml), res, map[string]bool{})
			if !reflect.DeepEqual(res.Devices, tc.wantDevs) {
				t.Errorf("Devices = %v, want %v", res.Devices, tc.wantDevs)
			}
			if tc.wantRender != "" && res.Renderer != tc.wantRender {
				t.Errorf("Renderer = %q, want %q", res.Renderer, tc.wantRender)
			}
			if tc.wantUnsupp != nil && !reflect.DeepEqual(res.Unsupported, tc.wantUnsupp) {
				t.Errorf("Unsupported = %v, want %v", res.Unsupported, tc.wantUnsupp)
			}
		})
	}
}
