package system

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSDNMissingPackagesListsOnlyAbsentOnes(t *testing.T) {
	saved := sdnPackageChecks
	defer func() { sdnPackageChecks = saved }()
	yes, no := func() bool { return true }, func() bool { return false }
	sdnPackageChecks = []struct {
		pkg     string
		present func() bool
	}{{"nftables", yes}, {"conntrack", no}, {"dnsmasq-base", yes}, {"wireguard-tools", no}, {"suricata", no}, {"ppp", yes}}
	if got, want := SDNMissingPackages(), []string{"conntrack", "wireguard-tools", "suricata"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("missing = %v, want %v", got, want)
	}
	sdnPackageChecks = sdnPackageChecks[:1]
	if got := SDNMissingPackages(); got == nil || len(got) != 0 {
		t.Fatalf("all present: want empty non-nil list (JSON []), got %#v", got)
	}
}

// Every package the Firewall installs at enable must be one the prereqs
// install endpoint accepts on its own too (the per-feature banners).
func TestSDNPackageChecksCoverFeatures(t *testing.T) {
	want := map[string]bool{"nftables": true, "conntrack": true, "dnsmasq-base": true, "wireguard-tools": true, "suricata": true, "ppp": true, "iputils-arping": true, "ddclient": true}
	for _, c := range sdnPackageChecks {
		if !want[c.pkg] {
			t.Errorf("unexpected package %q", c.pkg)
		}
		delete(want, c.pkg)
	}
	for p := range want {
		t.Errorf("package %q not checked", p)
	}
}

// The USB appliance cannot install packages for good (its root is rebuilt at
// every boot): every Firewall package must be baked into the image.
func TestSDNPackagesBakedIntoAppliance(t *testing.T) {
	b, err := os.ReadFile("../usbimage/chroot-setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	words := map[string]bool{}
	for _, w := range strings.Fields(string(b)) {
		words[w] = true
	}
	for _, c := range sdnPackageChecks {
		if !words[c.pkg] {
			t.Errorf("%s is missing from usbimage/chroot-setup.sh", c.pkg)
		}
	}
}
