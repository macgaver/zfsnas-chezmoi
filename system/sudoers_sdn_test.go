package system

import (
	"strings"
	"testing"
)

// sudoersRuleMatches is sudo's matching for the shapes the template uses: an
// exact command line, or a fixed prefix followed by a trailing "*" that
// matches any (possibly empty) rest.
func sudoersRuleMatches(rule, cmd string) bool {
	if p, ok := strings.CutSuffix(rule, " *"); ok {
		return cmd == p || strings.HasPrefix(cmd, p+" ")
	}
	return rule == cmd
}

// Every command the Firewall runs through sudo (sdnRun as a non-root portal)
// must be granted once the feature is on, with classic sudo and with the
// sudo-rs widening — or a hardened host breaks in the middle of an apply.
func TestSudoersGrantEveryFirewallCommand(t *testing.T) {
	old := sdnEnabledForSudoers
	sdnEnabledForSudoers = func() bool { return true }
	defer func() { sdnEnabledForSudoers = old }()
	calls := []string{
		"/usr/sbin/nft -f -", "/usr/sbin/nft -j list table ip znas_sdn", "/usr/sbin/nft delete table ip znas_sdn", "/usr/sbin/nft -j list set ip znas_sdn blk",
		"/usr/sbin/ifdown --force enp7s0-v700", "/usr/bin/systemd-run --scope --quiet --collect -- ifup ppp-ifppp0003",
		"/usr/bin/systemd-run --unit znas-sdn-revert --collect --uid zfsnas /opt/zfsnas/zfsnas -config /opt/zfsnas/config -sdn-revert previous -sdn-revert-delay 30",
		"/usr/sbin/sysctl -e -p /etc/sysctl.d/90-znas-sdn.conf", "/usr/sbin/sysctl -w net.ipv4.ip_forward=0", "/usr/sbin/modprobe nf_conntrack",
		"/usr/sbin/ip rule add priority 1000 fwmark 0x100 lookup 100", "/usr/sbin/ip route flush table 100", "/usr/sbin/ip -4 -j route show table main",
		"/usr/sbin/conntrack -L -o extended,id", "/usr/sbin/conntrack -D --mark 0x300", "/usr/sbin/conntrack -E -e DESTROY -o extended,id",
		"/usr/bin/arping -D -c 2 -w 3 -I vmbr0 192.168.2.1", "/usr/bin/arping -U -c 2 -I vmbr0 192.168.2.1",
		"/usr/bin/systemctl daemon-reload",
		"/usr/bin/systemctl restart znas-sdn-gw.service", "/usr/bin/systemctl restart znas-sdn-dns.service", "/usr/bin/systemctl restart znas-sdn-ids.service",
		"/usr/bin/systemctl reload znas-sdn-ids.service", "/usr/bin/systemctl stop znas-sdn-gw.service", "/usr/bin/systemctl stop znas-sdn-dns.service",
		"/usr/bin/systemctl stop znas-sdn-ids.service", "/usr/bin/systemctl stop znas-sdn-dns.service znas-sdn-ids.service", "/usr/bin/systemctl stop znas-sdn-revert.service",
		"/usr/bin/systemctl reset-failed znas-sdn-revert.service", "/usr/bin/systemctl is-active znas-sdn-dns.service", "/usr/bin/systemctl is-active znas-sdn-ids.service",
		"/usr/bin/systemctl disable --now znas-sdn-gw.service", "/usr/bin/systemctl disable --now znas-sdn-dns.service", "/usr/bin/systemctl disable --now znas-sdn-ids.service",
		"/usr/bin/systemctl disable znas-sdn.service", "/usr/bin/systemctl is-enabled nftables.service", "/usr/bin/systemctl disable nftables.service",
		"/usr/bin/systemctl enable nftables.service", "/usr/bin/systemctl disable --now suricata.service", "/usr/bin/systemctl disable --now suricata-update.timer",
		"/usr/bin/wg syncconf wg-x /etc/wireguard/znas-x.conf", "/usr/bin/wg show wg-x dump",
		"/usr/bin/suricata-update -D /p/suricata/data update-sources", "/usr/bin/install -m 600 /dev/null /etc/ppp/chap-secrets",
		"/usr/bin/mkdir -p /etc/znas-sdn", "/usr/bin/mkdir -p -m 700 /etc/wireguard", "/usr/bin/rm -f /etc/znas-sdn/dnsmasq.conf",
		"/usr/bin/cat /etc/ppp/chap-secrets", "/usr/bin/cat /etc/ppp/pap-secrets", "/usr/bin/cat /etc/wireguard/znas-x.conf",
		"/usr/bin/cat /var/lib/misc/znas-sdn.leases", "/usr/bin/tee /etc/znas-sdn/dnsmasq.conf",
		"/usr/bin/systemctl enable znas-sdn.service znas-sdn-gw.service znas-sdn-dns.service znas-sdn-dhcp.service znas-sdn-ids.service znas-sdn-ddns.service",
		"/usr/bin/systemctl reload znas-sdn-dns.service", "/usr/bin/mkdir -p /var/lib/znas-sdn", "/usr/bin/tee /var/lib/znas-sdn/blocklist.hosts",
		"/usr/bin/rm -f /var/lib/znas-sdn/blocklist.hosts",
		"/usr/bin/systemctl restart znas-sdn-dhcp.service", "/usr/bin/systemctl reload znas-sdn-dhcp.service", "/usr/bin/systemctl stop znas-sdn-dhcp.service",
		"/usr/bin/systemctl is-active znas-sdn-dhcp.service", "/usr/bin/systemctl disable --now znas-sdn-dhcp.service",
		"/usr/bin/mkdir -p /etc/znas-sdn/dhcp.d", "/usr/bin/tee /etc/znas-sdn/dhcp.d/if000700.conf", "/usr/bin/rm -f /etc/znas-sdn/dhcp.d/if000700.conf",
		"/usr/bin/systemctl restart znas-sdn-ddns.service", "/usr/bin/systemctl stop znas-sdn-ddns.service", "/usr/bin/systemctl is-active znas-sdn-ddns.service",
		"/usr/bin/systemctl disable --now znas-sdn-ddns.service", "/usr/bin/systemctl disable --now ddclient.service",
		"/usr/bin/cat /etc/znas-sdn/ddclient.conf", "/usr/bin/cat /var/cache/znas-sdn/ddclient.cache",
		"/usr/bin/install -m 600 /dev/null /etc/znas-sdn/ddclient.conf", "/usr/bin/tee /etc/znas-sdn/ddclient.conf",
	}
	for _, flavor := range []struct {
		name  string
		widen bool
	}{{"sudo", false}, {"sudo-rs", true}} {
		s := strings.Replace(requiredSudoersTemplate, "{{ZFSNAS_FILES}}", buildFilesAlias(), 1)
		s = strings.Replace(s, "{{LXD_CAT_LINE}}", lxdConsoleCatLine(), 1)
		if flavor.widen {
			s = widenWildcardsForSudoRS(s)
		}
		s = gateSudoersAliases(s)
		if !strings.Contains(s, "ZFSNAS_SDN") {
			t.Fatalf("%s: ZFSNAS_SDN missing although the Firewall is on", flavor.name)
		}
		rules := extractSudoCommands(s)
		for _, c := range calls {
			ok := false
			for _, r := range rules {
				if sudoersRuleMatches(r, c) {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("%s: %q is not granted", flavor.name, c)
			}
		}
	}
}

func TestSudoersSDNAliasOnlyWhenEnabled(t *testing.T) {
	old := sdnEnabledForSudoers
	defer func() { sdnEnabledForSudoers = old }()
	sdnEnabledForSudoers = func() bool { return false }
	if strings.Contains(RequiredSudoersContent(), "ZFSNAS_SDN") {
		t.Fatal("Firewall rules present on a host without the Firewall")
	}
	sdnEnabledForSudoers = func() bool { return true }
	if !strings.Contains(RequiredSudoersContent(), "ZFSNAS_SDN") {
		t.Fatal("Firewall rules missing")
	}
}
