package system

import (
	"os"
	"strings"
	"testing"

	"zfsnas/internal/sdn"
)

// Without a reverse-DNS record, the name still comes from what the Firewall
// knows: a host name it serves, or a DHCP device in its network's domain.
func TestSDNLocalFQDN(t *testing.T) {
	_, _ = sdnTestEnv(t)
	c := withServices(labBase()) // VLAN700, DHCP on, domain lab.lan
	c.DNS.Hosts = []sdn.DNSHost{{Name: "nas", IP: "10.128.7.5"}, {Name: "printer.other.lan", IP: "10.128.7.6"}}
	_ = os.MkdirAll(sdnLeaseDir, 0755)
	_ = os.WriteFile(sdn.DHCPLeaseFile(sdnLeaseDir, "if000700"), []byte("1999999999 aa:bb:cc:dd:ee:01 10.128.7.101 phone *\n"), 0644)
	for ip, want := range map[string][2]string{
		"10.128.7.101": {"phone", "phone.lab.lan"},
		"10.128.7.5":   {"nas", "nas.lab.lan"},
		"10.128.7.6":   {"printer.other.lan", "printer.other.lan"},
		"10.128.7.77":  {"", ""},
	} {
		name, fqdn := sdnLocalNames(c)(ip)
		if name != want[0] || fqdn != want[1] {
			t.Errorf("%s: %q %q, want %v", ip, name, fqdn, want)
		}
	}
}

// One conntrack read per second however many popups are open, and the rates
// come from it.
func TestSDNTopTalkers(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	sdnTalkersReset()
	line := "ipv4 2 tcp 6 431954 ESTABLISHED src=10.128.7.101 dst=52.1.1.1 sport=1 dport=443 packets=1 bytes=100 src=52.1.1.1 dst=69.1.1.1 sport=443 dport=1 packets=1 bytes=200 [ASSURED] mark=0 use=1 id=1\n"
	rec.out = map[string]string{"conntrack -L -o extended,id": line}
	c := withServices(labBase())
	r := SDNTopTalkers(c, "down", 10)
	if r.Ready || len(r.Talkers) != 0 {
		t.Fatalf("baseline: %+v", r)
	}
	SDNTopTalkers(c, "up", 10)
	n := 0
	for _, x := range rec.cmds {
		if strings.HasPrefix(x, "conntrack -L") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d conntrack reads within a second: %v", n, rec.cmds)
	}
}
