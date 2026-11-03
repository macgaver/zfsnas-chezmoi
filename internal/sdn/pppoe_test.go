package sdn

import (
	"strings"
	"testing"
)

func pppoeIface() Interface {
	c := &Config{Interfaces: []Interface{{ID: "wanpppoe1", Name: "Fibre", Kind: "pppoe", Parent: "enp6s0.35", Role: "wan",
		PPPoEUser: "b1@isp.example", PPPoEPassword: "s3cr et"}}}
	c.Normalize()
	return c.Interfaces[0]
}

func TestRenderOwned_PPPoE(t *testing.T) {
	in := pppoeIface()
	got := RenderOwned(in)
	want := "# znas-sdn-start id=wanpppoe1 device=ppp-wanpppoe1\n" +
		"auto ppp-wanpppoe1\n" +
		"iface ppp-wanpppoe1 inet ppp\n" +
		"    pre-up ip link set enp6s0.35 up\n" +
		"    provider znas-wanpppoe1\n" +
		"# znas-sdn-end"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestPPPoEPeers(t *testing.T) {
	p := PPPoEPeers(pppoeIface())
	for _, want := range []string{"plugin pppoe.so\n", "nic-enp6s0.35\n", `user "b1@isp.example"` + "\n", "ifname ppp-wanpppoe1\n",
		"persist\n", "maxfail 0\n", "noipdefault\n", "nodefaultroute\n", "noipv6\n", "mtu 1492\n", "mru 1492\n", "lcp-echo-interval 10\n"} {
		if !strings.Contains(p, want) {
			t.Fatalf("peers lacks %q:\n%s", want, p)
		}
	}
	if strings.Contains(p, "s3cr") || strings.Contains(p, "usepeerdns") || strings.Contains(p, "defaultroute\n") && !strings.Contains(p, "nodefaultroute") {
		t.Fatalf("peers leaks password or takes DNS/default route:\n%s", p)
	}
	in := pppoeIface()
	in.MTU = 1500
	if !strings.Contains(PPPoEPeers(in), "mtu 1500\n") {
		t.Fatal("MTU override ignored")
	}
}

func TestSpliceSecrets(t *testing.T) {
	file := "# Secrets for authentication using CHAP\n# client\tserver\tsecret\tIP addresses\n\"other\" * \"keep\" *\n" +
		"\"old\" * \"gone\" * # znas-sdn id=wanold\n"
	got := SpliceSecrets(file, []Interface{pppoeIface(), {ID: "lan", Kind: "physical"}})
	if !strings.Contains(got, "\"other\" * \"keep\" *\n") || strings.Contains(got, "wanold") {
		t.Fatalf("foreign line lost or stale line kept:\n%s", got)
	}
	if !strings.Contains(got, "\"b1@isp.example\" * \"s3cr et\" * # znas-sdn id=wanpppoe1\n") {
		t.Fatalf("own line missing:\n%s", got)
	}
	if SpliceSecrets(got, []Interface{pppoeIface()}) != got {
		t.Fatal("not idempotent")
	}
	if back := SpliceSecrets(got, nil); strings.Contains(back, "znas-sdn") || !strings.Contains(back, "keep") {
		t.Fatalf("removal:\n%s", back)
	}
}

func TestValidate_PPPoECredentialChars(t *testing.T) {
	for _, bad := range []string{`a"b`, `a\b`, "a\nb", "a\x01b"} {
		c := &Config{Version: 1, Settings: Settings{Mode: "router"}, Interfaces: []Interface{
			{ID: "lan", Name: "LAN", Kind: "physical", Device: "enp5s0", Role: "lan", IPv4Mode: "dhcp"},
			{ID: "wanpppoe1", Name: "Fibre", Kind: "pppoe", Parent: "enp6s0", Role: "wan", PPPoEUser: "u", PPPoEPassword: bad}}}
		c.Normalize()
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "pppoe_password") {
			t.Fatalf("password %q accepted: %v", bad, err)
		}
		c.Interfaces[1].PPPoEPassword, c.Interfaces[1].PPPoEUser = "ok", bad
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "pppoe_user") {
			t.Fatalf("user %q accepted: %v", bad, err)
		}
	}
}

// A second PPPoE link on the same port is its own session, device and peer.
func TestPPPoE_TwoOnOnePort(t *testing.T) {
	c := ownerSample()
	for _, id := range []string{"ifppp001", "ifppp002"} {
		c.Interfaces = append(c.Interfaces, Interface{ID: id, Name: id, Kind: "pppoe", Parent: "enp2s0", Role: "wan", IPv4Mode: "pppoe", PPPoEUser: "u@" + id, PPPoEPassword: "p"})
	}
	c.Normalize()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if a, b := c.InterfaceByID("ifppp001").Device, c.InterfaceByID("ifppp002").Device; a == b || a == "" {
		t.Fatalf("%q %q", a, b)
	}
}
