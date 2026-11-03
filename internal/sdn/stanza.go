package sdn

import (
	"fmt"
	"strings"
)

// Every interface SDN creates (VLANs, and the bridge of an "Allow VMs" VLAN)
// lives in /etc/network/interfaces between these markers, so SDN can rewrite
// its own stanzas without touching anything it did not write.
const (
	BlockStart = "# znas-sdn-start"
	BlockEnd   = "# znas-sdn-end"
)

// RenderOwned returns the marked block for an SDN-owned interface (no
// surrounding blank lines). The VLAN stanza mirrors the shape the VLAN
// feature already uses (pre-up ip link add / post-down ip link del); no
// dns-* lines (Ubuntu 26.04 resolvectl stall during ifup).
func RenderOwned(i Interface) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s id=%s device=%s\n", BlockStart, i.ID, i.Device)
	if i.Kind == "pppoe" {
		// pppd (started by ifupdown's "provider") creates the device; the
		// session runs on the parent, which must be up.
		fmt.Fprintf(&b, "auto %s\niface %s inet ppp\n", i.Device, i.Device)
		fmt.Fprintf(&b, "    pre-up ip link set %s up\n", i.Parent)
		fmt.Fprintf(&b, "    provider %s\n", PPPoEPeerName(i.ID))
		b.WriteString(BlockEnd)
		return b.String()
	}
	if i.Kind == "wireguard" {
		renderWireGuard(&b, i)
		b.WriteString(BlockEnd)
		return b.String()
	}
	vlanMode := ipv4Method(i)
	if i.AllowVMs {
		vlanMode = "manual"
	}
	fmt.Fprintf(&b, "auto %s\niface %s inet %s\n", i.Device, i.Device, vlanMode)
	// The parent may have no stanza of its own (a bare trunk port): bring it
	// up first or the VLAN never gets a carrier.
	fmt.Fprintf(&b, "    pre-up ip link set %s up\n", i.Parent)
	fmt.Fprintf(&b, "    pre-up ip link add link %s name %s type vlan id %d\n", i.Parent, i.Device, i.VLANTag)
	fmt.Fprintf(&b, "    post-down ip link del %s\n", i.Device)
	if !i.AllowVMs {
		writeAddressing(&b, i)
	} else if i.MTU > 0 {
		fmt.Fprintf(&b, "    mtu %d\n", i.MTU)
	}
	fmt.Fprintf(&b, "    post-up sysctl -w net.ipv6.conf.%s.disable_ipv6=1\n", i.Device)
	if i.AllowVMs {
		br := BridgeDeviceName(i.Device)
		fmt.Fprintf(&b, "auto %s\niface %s inet %s\n", br, br, ipv4Method(i))
		fmt.Fprintf(&b, "    bridge_ports %s\n    bridge_stp off\n    bridge_fd 0\n", i.Device)
		writeAddressing(&b, i)
		fmt.Fprintf(&b, "    post-up sysctl -w net.ipv6.conf.%s.disable_ipv6=1\n", br)
	}
	b.WriteString(BlockEnd)
	return b.String()
}

func ipv4Method(i Interface) string {
	switch i.IPv4Mode {
	case "static":
		return "static"
	case "dhcp":
		return "dhcp"
	}
	return "manual"
}

func writeAddressing(b *strings.Builder, i Interface) {
	if i.IPv4Mode == "static" {
		fmt.Fprintf(b, "    address %s\n", i.IPv4)
		if i.Gateway != "" {
			fmt.Fprintf(b, "    gateway %s\n", i.Gateway)
		}
	}
	if i.MTU > 0 {
		fmt.Fprintf(b, "    mtu %d\n", i.MTU)
	}
}

// SpliceOwned removes every SDN block from the interfaces file and inserts
// the blocks for the given owned interfaces right after their parent's
// stanza (so VLANs come up before any bridge stanza further down), or at the
// end when the parent has no stanza. Foreign stanzas are left byte-identical
// and splicing is reversible: SpliceOwned(SpliceOwned(f, x), nil) == f.
func SpliceOwned(file string, owned []Interface) string {
	lines := removeBlocks(strings.Split(file, "\n"))

	byParent := map[string][]string{}
	var parents []string
	for _, in := range owned {
		if !in.Owned || in.Disabled {
			continue
		}
		if _, ok := byParent[in.Parent]; !ok {
			parents = append(parents, in.Parent)
		}
		byParent[in.Parent] = append(byParent[in.Parent], RenderOwned(in))
	}
	for _, p := range parents {
		var ins []string
		for _, blk := range byParent[p] {
			ins = append(ins, "")
			ins = append(ins, strings.Split(blk, "\n")...)
		}
		at := parentStanzaEnd(lines, p)
		if at < 0 {
			// append before the trailing "" produced by the final newline
			at = len(lines)
			if at > 0 && lines[at-1] == "" {
				at--
			}
		}
		lines = append(lines[:at], append(ins, lines[at:]...)...)
	}
	return strings.Join(lines, "\n")
}

// removeBlocks drops each marked block and the blank line SpliceOwned put in
// front of it.
func removeBlocks(lines []string) []string {
	var out []string
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(lines[i], BlockStart) {
			out = append(out, lines[i])
			continue
		}
		if n := len(out); n > 0 && out[n-1] == "" {
			out = out[:n-1]
		}
		for i < len(lines) && lines[i] != BlockEnd {
			i++
		}
	}
	return out
}

// parentStanzaEnd returns the index just past the parent's iface stanza, or
// -1 when the file has no stanza for it.
func parentStanzaEnd(lines []string, parent string) int {
	marker := "iface " + parent + " "
	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), marker) {
			continue
		}
		end := i + 1
		for end < len(lines) {
			t := strings.TrimSpace(lines[end])
			if t == "" || strings.HasPrefix(t, "auto ") || strings.HasPrefix(t, "allow-hotplug ") ||
				strings.HasPrefix(t, "iface ") || strings.HasPrefix(t, "mapping ") || strings.HasPrefix(t, BlockStart) {
				break
			}
			end++
		}
		return end
	}
	return -1
}

// OwnedDevices lists the devices of the SDN blocks present in the file.
func OwnedDevices(file string) []string {
	var out []string
	for _, line := range strings.Split(file, "\n") {
		if !strings.HasPrefix(line, BlockStart) {
			continue
		}
		for _, f := range strings.Fields(line) {
			if d, ok := strings.CutPrefix(f, "device="); ok {
				out = append(out, d)
			}
		}
	}
	return out
}

// OwnedIfaces lists every interface defined inside the SDN blocks — VLANs
// and the bridges of "Allow VMs" VLANs — in file order.
func OwnedIfaces(file string) []string {
	var out []string
	in := false
	for _, line := range strings.Split(file, "\n") {
		switch {
		case strings.HasPrefix(line, BlockStart):
			in = true
		case line == BlockEnd:
			in = false
		case in:
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "iface" {
				out = append(out, f[1])
			}
		}
	}
	return out
}
