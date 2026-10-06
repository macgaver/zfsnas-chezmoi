package system

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// fakeSysNet builds a /sys/class/net-like tree:
//
//	enp3s0   real NIC (device link)
//	enp4s0   real NIC
//	bond0    bond of enp3s0 + enp4s0 (lower_ links)
//	vmbr0    bridge with ports enp3s0 + veth1
//	vmbr0.20 VLAN on the bridge
//	bond0.30 VLAN on the bond
//	dummy0   no device, nothing below
func fakeSysNet(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	dev := filepath.Join(root, "devices", "0000:03:00.0")
	os.MkdirAll(dev, 0755)
	mk := func(iface string) string {
		d := filepath.Join(root, iface)
		os.MkdirAll(d, 0755)
		return d
	}
	for _, n := range []string{"enp3s0", "enp4s0"} {
		os.Symlink(dev, filepath.Join(mk(n), "device"))
	}
	b := mk("bond0")
	os.Symlink("../enp3s0", filepath.Join(b, "lower_enp3s0"))
	os.Symlink("../enp4s0", filepath.Join(b, "lower_enp4s0"))
	br := mk("vmbr0")
	os.MkdirAll(filepath.Join(br, "bridge"), 0755)
	os.MkdirAll(filepath.Join(br, "brif", "enp3s0"), 0755)
	os.MkdirAll(filepath.Join(br, "brif", "veth1"), 0755)
	os.Symlink("../vmbr0", filepath.Join(mk("vmbr0.20"), "lower_vmbr0"))
	os.Symlink("../bond0", filepath.Join(mk("bond0.30"), "lower_bond0"))
	mk("dummy0")
	old := sysClassNet
	sysClassNet = root
	t.Cleanup(func() { sysClassNet = old })
}

func TestPhysicalPortsUnder(t *testing.T) {
	fakeSysNet(t)
	cases := map[string][]string{
		"enp3s0":   {"enp3s0"},
		"bond0":    {"enp3s0", "enp4s0"},
		"vmbr0.20": {"enp3s0"}, // through the bridge, veth ignored
		"bond0.30": {"enp3s0", "enp4s0"},
		"dummy0":   nil,
	}
	for in, want := range cases {
		if got := PhysicalPortsUnder(in); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", in, got, want)
		}
	}
}

func TestParseVLANLink(t *testing.T) {
	js := []byte(`[{"ifname":"enp3s0.20","link":"enp3s0","linkinfo":{"info_kind":"vlan","info_data":{"protocol":"802.1Q","id":20}}}]`)
	p, id, ok := parseVLANLink(js)
	if !ok || p != "enp3s0" || id != 20 {
		t.Errorf("got %q %d %v", p, id, ok)
	}
	if _, _, ok := parseVLANLink([]byte(`[{"ifname":"enp3s0","linkinfo":{"info_kind":"bond"}}]`)); ok {
		t.Error("a bond parsed as a VLAN")
	}
	if _, _, ok := parseVLANLink([]byte(`garbage`)); ok {
		t.Error("garbage parsed")
	}
}

func TestJoinVendorModel(t *testing.T) {
	cases := [][3]string{
		{"Realtek Semiconductor Co., Ltd.", "RTL8111/8168/8211/8411 PCI Express Gigabit Ethernet Controller", "Realtek Semiconductor RTL8111/8168/8211/8411 PCI Express Gigabit Ethernet Controller"},
		{"Intel Corporation", "Ethernet Controller I225-V", "Intel Ethernet Controller I225-V"},
		{"Intel Corporation", "Intel Ethernet I210", "Intel Ethernet I210"},
		{"Red Hat, Inc.", "Virtio 1.0 network device", "Red Hat Virtio 1.0 network device"},
		{"", "AX88179", "AX88179"},
		{"Mellanox Technologies", "", "Mellanox Technologies"},
	}
	for _, c := range cases {
		if got := joinVendorModel(c[0], c[1]); got != c[2] {
			t.Errorf("%q + %q = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}
