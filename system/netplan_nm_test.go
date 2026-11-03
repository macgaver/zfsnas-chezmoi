package system

import (
	"strings"
	"testing"
)

// On a netplan host rendered by NetworkManager (Ubuntu with
// 01-network-manager-all.yaml) the static drop-in must not force the
// networkd renderer: networkd is not running there, so the address would
// never be applied (observed on a physical Ubuntu 26.04 server, 2026-10-29).
func TestNetplanStaticYAML_RendererFollowsHost(t *testing.T) {
	nd := netplanStaticYAML("enp3s0f0", "192.168.2.113/24", "192.168.2.254", []string{"192.168.2.33"}, true)
	if !strings.Contains(nd, "  renderer: networkd\n") {
		t.Fatalf("networkd host: renderer missing:\n%s", nd)
	}
	nm := netplanStaticYAML("enp3s0f0", "192.168.2.113/24", "192.168.2.254", []string{"192.168.2.33"}, false)
	if strings.Contains(nm, "renderer") {
		t.Fatalf("NetworkManager host: must inherit the renderer:\n%s", nm)
	}
	for _, want := range []string{"    enp3s0f0:\n", "      dhcp4: false\n", "        - 192.168.2.113/24\n", "          via: 192.168.2.254\n", "          - 192.168.2.33\n"} {
		if !strings.Contains(nm, want) {
			t.Fatalf("missing %q in:\n%s", want, nm)
		}
	}
}

// The migration hands the NICs to ifupdown and tells NetworkManager to keep
// its hands off them and off the VM bridges created later.
func TestNMUnmanagedConf(t *testing.T) {
	got := nmUnmanagedConf([]string{"enp3s0f0", "eno1"})
	for _, want := range []string{"[keyfile]\n", "unmanaged-devices=interface-name:enp3s0f0;interface-name:eno1;interface-name:vmbr*\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

// The installer file and the ZNAS static drop-in both name the NIC: it is
// one device.
func TestParseNetplanYAML_SameDeviceInTwoFiles(t *testing.T) {
	res := &netplanScanResult{}
	seen := map[string]bool{}
	parseNetplanYAMLInto([]byte("network:\n  ethernets:\n    enp5s0:\n      dhcp4: true\n  version: 2\n"), res, seen)
	parseNetplanYAMLInto([]byte("network:\n  version: 2\n  ethernets:\n    enp5s0:\n      dhcp4: false\n"), res, seen)
	if strings.Join(res.Devices, ",") != "enp5s0" {
		t.Fatalf("devices %v", res.Devices)
	}
}

// Without ifupdown, writing /etc/network/interfaces only leaves a stanza that
// NetworkManager's ifupdown plugin then treats as "unmanaged" — the NIC loses
// its address at the next NetworkManager restart. Refuse before writing.
func TestWriteIfupdownStatic_RefusesWithoutIfupdown(t *testing.T) {
	old := ifupdownInstalled
	ifupdownInstalled = func() bool { return false }
	defer func() { ifupdownInstalled = old }()
	err := writeIfupdownStaticAndApply("enp3s0f0", "192.168.2.113/24", "192.168.2.254", nil)
	if err == nil || !strings.Contains(err.Error(), "ifupdown") {
		t.Fatalf("expected a refusal naming ifupdown, got %v", err)
	}
}
