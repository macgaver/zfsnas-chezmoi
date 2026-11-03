package sdn

// PPPoE files (spec §6.1): /etc/ppp/peers/znas-<id> and our tagged lines in
// /etc/ppp/{chap,pap}-secrets. Regenerated at every apply and at boot (the
// appliance's /etc is in RAM); foreign lines are kept byte-identical.

import (
	"fmt"
	"strings"
)

// PPPoEPeerName is the pppd "provider" (peers file name) of an interface.
func PPPoEPeerName(id string) string { return "znas-" + id }

// PPPoEPeers renders the peers file. pppd sets no default route and takes no
// DNS: routing belongs to the gateway monitor, DNS to the Firewall.
func PPPoEPeers(i Interface) string {
	mtu := i.MTU
	if mtu <= 0 {
		mtu = 1492
	}
	var b strings.Builder
	b.WriteString("# Managed by ZNAS Firewall — rewritten on every apply and at boot.\n")
	b.WriteString("plugin pppoe.so\n")
	fmt.Fprintf(&b, "nic-%s\n", i.Parent)
	fmt.Fprintf(&b, "user \"%s\"\n", i.PPPoEUser)
	fmt.Fprintf(&b, "ifname %s\n", i.Device)
	b.WriteString("noauth\nhide-password\npersist\nmaxfail 0\nholdoff 5\n")
	b.WriteString("noipdefault\nnodefaultroute\nnoipv6\n")
	fmt.Fprintf(&b, "mtu %d\nmru %d\n", mtu, mtu)
	b.WriteString("lcp-echo-interval 10\nlcp-echo-failure 3\n")
	return b.String()
}

const secretTag = "# znas-sdn id="

// SpliceSecrets replaces our lines in a pppd secrets file with one per
// PPPoE interface in ifaces.
func SpliceSecrets(file string, ifaces []Interface) string {
	var out []string
	for _, l := range strings.SplitAfter(file, "\n") {
		if l != "" && !strings.Contains(l, secretTag) {
			out = append(out, l)
		}
	}
	if n := len(out); n > 0 && !strings.HasSuffix(out[n-1], "\n") {
		out[n-1] += "\n"
	}
	for _, i := range ifaces {
		if i.Kind == "pppoe" {
			out = append(out, fmt.Sprintf("\"%s\" * \"%s\" * %s%s\n", i.PPPoEUser, i.PPPoEPassword, secretTag, i.ID))
		}
	}
	return strings.Join(out, "")
}
