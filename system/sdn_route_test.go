package system

import (
	"strings"
	"testing"

	"zfsnas/internal/sdn"
)

func gwConfig() *sdn.Config {
	c := labBase()
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "if0wan01", Name: "WAN1", Kind: "physical", Device: "enp6s0", Role: "wan", IPv4Mode: "static", IPv4: "10.250.0.2/24"})
	c.Gateways = []sdn.Gateway{{ID: "gwisp001", Name: "ISP1", Interface: "if0wan01", Address: "10.250.0.1", Priority: 1, Monitor: true}}
	c.Normalize()
	return c
}

func TestSDNSyncRules(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	rec.out = map[string]string{"ip -j rule show": `[{"priority":0,"table":"local"},{"priority":999,"table":"main","suppress_prefixlength":0},{"priority":1003,"fwmark":"0x103","table":"103"},{"priority":3004,"fwmark":"0x304","table":"304"},{"priority":32766,"table":"main"}]`}
	if err := SDNSyncRules(gwConfig()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip rule del priority 999", "ip rule del priority 1003", "ip rule del priority 3004",
		"ip rule add priority 999 lookup main suppress_prefixlength 0",
		"ip rule add priority 1000 fwmark 0x100 lookup 100",
		"ip rule add priority 2000 fwmark 0x200 lookup 200",
		"ip rule add priority 3000 fwmark 0x300 lookup 300",
	} {
		if rec.index(want) < 0 {
			t.Fatalf("missing %q in %v", want, rec.cmds)
		}
	}
}

func TestSDNApplyRoutes(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	via := sdn.Hop{Via: "10.250.0.1", Dev: "enp6s0"}
	SDNApplyRoutes(sdn.RoutePlan{Default: &via, Tables: map[int]*sdn.Hop{100: &via, 200: nil}})
	for _, want := range []string{
		"ip route replace default via 10.250.0.1 dev enp6s0 metric 0",
		"ip route replace default via 10.250.0.1 dev enp6s0 table 100",
		"ip route replace unreachable default table 200",
	} {
		if rec.index(want) < 0 {
			t.Fatalf("missing %q in %v", want, rec.cmds)
		}
	}
	rec.cmds = nil
	SDNApplyRoutes(sdn.RoutePlan{Default: &sdn.Hop{Dev: "ppp-x"}, Tables: map[int]*sdn.Hop{}})
	if rec.index("ip route replace default dev ppp-x metric 0") < 0 {
		t.Fatalf("p2p default: %v", rec.cmds)
	}
}

func TestSDNResolveHops(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	c := gwConfig()
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "if0wan02", Name: "WAN2", Kind: "physical", Device: "enp8s0", Role: "wan", IPv4Mode: "dhcp"})
	c.Gateways = append(c.Gateways, sdn.Gateway{ID: "gwisp002", Name: "ISP2", Interface: "if0wan02", Priority: 2, Monitor: true})
	c.Normalize()
	rec.out = map[string]string{"ip -4 -j route show default dev enp8s0": `[{"dst":"default","gateway":"10.251.0.1","dev":"enp8s0","metric":202}]`}
	h := SDNResolveHops(c)
	if h["gwisp001"].Via != "10.250.0.1" || h["gwisp002"].Via != "10.251.0.1" || h["gwisp002"].Dev != "enp8s0" {
		t.Fatalf("%+v", h)
	}
}

// ifup starts daemons (pppd, dhclient) that must outlive the portal and the
// revert service: they run in a scope of their own, not in our cgroup.
func TestSDNDetachedArgv(t *testing.T) {
	name, args := sdnDetachedArgv("ifup", []string{"ppp-x"})
	if name != "systemd-run" || strings.Join(args, " ") != "--scope --quiet --collect -- ifup ppp-x" {
		t.Fatalf("%s %v", name, args)
	}
	if name, _ := sdnDetachedArgv("nft", []string{"-f", "-"}); name != "nft" {
		t.Fatal("only ifup is detached")
	}
}
