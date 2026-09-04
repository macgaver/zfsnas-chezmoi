package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleInterfaces = `# generated
auto lo
iface lo inet loopback

auto enp5s0
iface enp5s0 inet manual

auto vmbr0
iface vmbr0 inet dhcp
    bridge_ports enp5s0
    bridge_stp off
    bridge_fd 0

auto vmbr1
iface vmbr1 inet static
    address 10.0.0.5/24
    gateway 10.0.0.1
    bridge_ports enp6s0
    bridge_stp off
    bridge_fd 0
`

func withInterfaces(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "interfaces")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	orig := hostInterfacesPath
	hostInterfacesPath = path
	t.Cleanup(func() { hostInterfacesPath = orig })
	return path
}

func TestGetHostBridgeConfig(t *testing.T) {
	withInterfaces(t, sampleInterfaces)

	dhcp, err := GetHostBridgeConfig("vmbr0")
	if err != nil {
		t.Fatal(err)
	}
	if !dhcp.Exists || dhcp.Mode != "dhcp" {
		t.Errorf("vmbr0: exists=%v mode=%q, want true/dhcp", dhcp.Exists, dhcp.Mode)
	}
	if len(dhcp.Ports) != 1 || dhcp.Ports[0] != "enp5s0" {
		t.Errorf("vmbr0 ports = %v, want [enp5s0]", dhcp.Ports)
	}

	st, _ := GetHostBridgeConfig("vmbr1")
	if st.Mode != "static" || st.Address != "10.0.0.5/24" || st.Gateway != "10.0.0.1" {
		t.Errorf("vmbr1 = %+v, want static 10.0.0.5/24 gw 10.0.0.1", st)
	}

	missing, _ := GetHostBridgeConfig("vmbr9")
	if missing.Exists {
		t.Error("vmbr9 should not be reported as existing")
	}
}

// Switching addressing must never drop the bridge's own lines — losing
// bridge_ports would silently detach the bridge from its NIC.
func TestSetHostBridgeConfigKeepsBridgePorts(t *testing.T) {
	path := withInterfaces(t, sampleInterfaces)

	err := SetHostBridgeConfig(HostBridgeConfig{
		Name: "vmbr0", Mode: "static", Address: "192.168.1.50/24",
		Gateway: "192.168.1.1", DNS: []string{"1.1.1.1", "9.9.9.9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(path)
	body := string(out)

	for _, want := range []string{
		"iface vmbr0 inet static",
		"address 192.168.1.50/24",
		"gateway 192.168.1.1",
		"dns-nameservers 1.1.1.1 9.9.9.9",
		"bridge_ports enp5s0", // the critical one
		"bridge_stp off",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in rewritten file:\n%s", want, body)
		}
	}
	// The other interfaces must be untouched.
	if !strings.Contains(body, "iface vmbr1 inet static") || !strings.Contains(body, "address 10.0.0.5/24") {
		t.Errorf("vmbr1 stanza was disturbed:\n%s", body)
	}
	if !strings.Contains(body, "iface lo inet loopback") {
		t.Errorf("loopback lost:\n%s", body)
	}

	// Back to DHCP: the static keys must be gone, ports still there.
	if err := SetHostBridgeConfig(HostBridgeConfig{Name: "vmbr0", Mode: "dhcp"}); err != nil {
		t.Fatal(err)
	}
	out, _ = os.ReadFile(path)
	body = string(out)
	if strings.Contains(body, "192.168.1.50") {
		t.Errorf("static address survived the switch to DHCP:\n%s", body)
	}
	if !strings.Contains(body, "bridge_ports enp5s0") {
		t.Errorf("bridge_ports lost switching to DHCP:\n%s", body)
	}
}

func TestSetHostBridgeConfigValidation(t *testing.T) {
	withInterfaces(t, sampleInterfaces)
	for _, tc := range []struct {
		name string
		cfg  HostBridgeConfig
	}{
		{"no name", HostBridgeConfig{Mode: "dhcp"}},
		{"bad mode", HostBridgeConfig{Name: "vmbr0", Mode: "bogus"}},
		{"static without address", HostBridgeConfig{Name: "vmbr0", Mode: "static"}},
		{"address without prefix", HostBridgeConfig{Name: "vmbr0", Mode: "static", Address: "192.168.1.50"}},
		{"unknown bridge", HostBridgeConfig{Name: "nope0", Mode: "dhcp"}},
	} {
		if err := SetHostBridgeConfig(tc.cfg); err == nil {
			t.Errorf("%s: expected an error, got nil", tc.name)
		}
	}
}

func TestGatewayIfaces(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/interfaces"
	os.WriteFile(p, []byte(`auto lo
iface lo inet loopback

iface vmbr0 inet dhcp
    bridge_ports enp5s0

iface vmbr1 inet static
    address 192.168.2.114/24
    gateway 192.168.2.1
    bridge_ports enp6s0

iface vmbr2 inet static
    address 10.0.0.5/24
    gateway 10.0.0.1
`), 0644)
	old := hostInterfacesPath
	hostInterfacesPath = p
	defer func() { hostInterfacesPath = old }()

	got := GatewayIfaces()
	if len(got) != 2 || got[0] != "vmbr1" || got[1] != "vmbr2" {
		t.Fatalf("want [vmbr1 vmbr2], got %v", got)
	}
}

func TestSetHostBridgeEndsWithSingleNewline(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/interfaces"
	os.WriteFile(p, []byte("auto vmbr0\niface vmbr0 inet dhcp\n    bridge_ports enp5s0"), 0644)
	old := hostInterfacesPath
	hostInterfacesPath = p
	defer func() { hostInterfacesPath = old }()

	if err := SetHostBridgeConfig(HostBridgeConfig{Name: "vmbr0", Mode: "static",
		Address: "10.0.0.2/24", Gateway: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.HasSuffix(string(b), "bridge_ports enp5s0\n") {
		t.Fatalf("file must end with exactly one newline after the last line, got %q", string(b))
	}
	if strings.HasSuffix(string(b), "\n\n") {
		t.Fatalf("trailing blank line: %q", string(b))
	}
}

func TestPendingMarkerLifecycle(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/interfaces"
	os.WriteFile(p, []byte("auto vmbr9\niface vmbr9 inet dhcp\n    bridge_ports enp9s0\n"), 0644)
	old := hostInterfacesPath
	hostInterfacesPath = p
	defer func() { hostInterfacesPath = old }()
	oldDir := netPendingDir
	netPendingDir = dir
	defer func() { netPendingDir = oldDir }()
	marker := netPendingMarker("vmbr9")

	cfg, _ := GetHostBridgeConfig("vmbr9")
	if cfg.Pending {
		t.Fatal("a bridge nobody edited must not be pending")
	}
	if err := SetHostBridgeConfig(HostBridgeConfig{Name: "vmbr9", Mode: "dhcp"}); err != nil {
		t.Fatal(err)
	}
	cfg, _ = GetHostBridgeConfig("vmbr9")
	if !cfg.Pending {
		t.Fatal("saving must mark the interface pending")
	}
	// Applying is what clears it; nothing else may.
	os.Remove(marker)
	cfg, _ = GetHostBridgeConfig("vmbr9")
	if cfg.Pending {
		t.Fatal("clearing the marker must clear pending")
	}
	if err := ApplyHostBridge("vmbr9"); err == nil {
		t.Fatal("applying with nothing pending must be refused")
	}
}
