package system

import "testing"

// Issue #187: Ubuntu 26.04 with an /etc/network/interfaces file but no
// ifupdown package passed the check, so the bridge step wrote a bridge nothing
// applies and failed on "networking.service not found".
func TestNetworkPrereq(t *testing.T) {
	cases := []struct {
		name                                                     string
		ifupFile, ifupInstalled, hasNetplan, netplanLive, netwkd bool
		ok, canFix                                               bool
	}{
		{"debian ifupdown", true, true, false, false, false, true, false},
		{"migrated: dormant yamls", true, true, true, false, false, true, false},
		{"ifupdown + live netplan (networkd)", true, true, true, true, true, false, false},
		{"ifupdown + live netplan (NetworkManager)", true, true, true, true, false, false, false},
		{"ubuntu netplan only", false, false, true, true, true, false, true},
		{"#187: interfaces file, no ifupdown, netplan via NM", true, false, true, true, false, false, true},
		{"#187: interfaces file, no ifupdown, netplan via networkd", true, false, true, true, true, false, true},
		{"interfaces file, no ifupdown, raw networkd", true, false, false, false, true, false, true},
		{"interfaces file, no ifupdown, nothing to migrate", true, false, false, false, false, false, false},
		{"raw networkd", false, false, false, false, true, false, true},
		{"nothing", false, false, false, false, false, false, false},
	}
	for _, c := range cases {
		ok, note, fix := networkPrereq(c.ifupFile, c.ifupInstalled, c.hasNetplan, c.netplanLive, c.netwkd)
		if ok != c.ok || fix != c.canFix || (!ok && note == "") {
			t.Errorf("%s: ok=%v canFix=%v note=%q, want ok=%v canFix=%v", c.name, ok, fix, note, c.ok, c.canFix)
		}
	}
}
