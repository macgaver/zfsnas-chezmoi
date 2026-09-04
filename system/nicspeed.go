package system

import (
	"os"
	"strconv"
	"strings"
)

// sysClassNet is the sysfs root for network devices. A var so tests can point
// it at a fixture tree instead of the live host.
var sysClassNet = "/sys/class/net"

// bridgePortVirtualPrefixes are the interface kinds that are never the
// physical uplink of a bridge: the instance-side veth/tap pairs, and the
// macvlan/vlan children stacked on top of a real port.
//
// Deliberately kept identical to the filter the networks table uses to pick
// what to print in its "Physical NIC" column, so the speed shown always
// describes the interface named beside it. This is narrower than
// isVirtualIfaceName, which answers a different question (which address is an
// instance reachable on) and also rules out bridges and loopback.
var bridgePortVirtualPrefixes = []string{"veth", "tap", "macvlan", "vlan"}

// isVirtualBridgePort reports whether name is a virtual port rather than the
// physical NIC carrying a bridge.
func isVirtualBridgePort(name string) bool {
	if i := strings.IndexByte(name, '@'); i >= 0 {
		name = name[:i] // strip the "@parent" suffix on veth/vlan peers
	}
	for _, p := range bridgePortVirtualPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// readSysNetAttr reads one sysfs attribute of an interface, trimmed. Missing
// files and unreadable attributes come back as "": reading `speed` on a link
// that is down fails with EINVAL rather than returning a value, so every
// caller has to tolerate an error here.
func readSysNetAttr(iface, attr string) string {
	if iface == "" || strings.ContainsAny(iface, "/\x00") {
		return "" // never let an interface name escape the sysfs directory
	}
	b, err := os.ReadFile(sysClassNet + "/" + iface + "/" + attr)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// isBridgeIface reports whether the interface is a Linux bridge. Bridges get a
// "bridge/" attribute directory; they aggregate their ports and have no link
// of their own, so asking one for a negotiated speed is meaningless.
func isBridgeIface(iface string) bool {
	if iface == "" || strings.ContainsAny(iface, "/\x00") {
		return false
	}
	st, err := os.Stat(sysClassNet + "/" + iface + "/bridge")
	return err == nil && st.IsDir()
}

// NICLinkUp reports whether the interface currently has carrier. A NIC with no
// link has negotiated nothing.
func NICLinkUp(iface string) bool {
	// operstate is the authoritative summary; carrier is the fallback for the
	// drivers that leave operstate "unknown".
	switch readSysNetAttr(iface, "operstate") {
	case "up":
		return true
	case "down", "lowerlayerdown":
		return false
	}
	return readSysNetAttr(iface, "carrier") == "1"
}

// NICSpeedMbps returns the speed the interface has negotiated, in Mbit/s.
//
// It returns 0 whenever there is nothing meaningful to report: a virtual port,
// a bridge, a driver that exposes no speed, or — the common case — a port with
// no cable in it. The kernel reports that last case as either an EINVAL read
// error or the sentinel -1, which some drivers hand back as the u32
// 4294967295; both are treated as unknown.
func NICSpeedMbps(iface string) int {
	if iface == "" || isVirtualBridgePort(iface) || isBridgeIface(iface) {
		return 0
	}
	if !NICLinkUp(iface) {
		return 0
	}
	mbps, err := strconv.Atoi(readSysNetAttr(iface, "speed"))
	if err != nil || mbps <= 0 || mbps >= 4294967295 {
		return 0
	}
	return mbps
}

// FormatNICSpeed renders a Mbit/s rate as a human-readable speed with its
// unit: 100 -> "100 Mb/s", 1000 -> "1 Gb/s", 2500 -> "2.5 Gb/s". A
// non-positive rate renders as "", so the caller supplies its own placeholder.
func FormatNICSpeed(mbps int) string {
	if mbps <= 0 {
		return ""
	}
	if mbps < 1000 {
		return strconv.Itoa(mbps) + " Mb/s"
	}
	gb := float64(mbps) / 1000.0
	// Whole rates read better without a trailing ".0" ("10 Gb/s", not
	// "10.0 Gb/s"); the odd ones like 2.5G keep a single decimal.
	s := strconv.FormatFloat(gb, 'f', -1, 64)
	if dot := strings.IndexByte(s, '.'); dot >= 0 && len(s)-dot > 2 {
		s = strconv.FormatFloat(gb, 'f', 1, 64)
	}
	return s + " Gb/s"
}

// NICSpeedLabel is the human-readable negotiated speed of a single interface,
// or "" when it has none.
func NICSpeedLabel(iface string) string { return FormatNICSpeed(NICSpeedMbps(iface)) }

// NICSpeedsLabel renders the negotiated speed of several NICs as a single cell
// and returns the fastest rate found, which the table sorts the column on.
//
// A bridge normally carries exactly one physical port, but a bond or a
// multi-homed bridge can list several; identical rates collapse to one label
// so a pair of gigabit ports reads "1 Gb/s" rather than "1 Gb/s, 1 Gb/s".
func NICSpeedsLabel(ifaces []string) (label string, maxMbps int) {
	var parts []string
	seen := map[string]bool{}
	for _, n := range ifaces {
		mbps := NICSpeedMbps(n)
		if mbps > maxMbps {
			maxMbps = mbps
		}
		s := FormatNICSpeed(mbps)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		parts = append(parts, s)
	}
	return strings.Join(parts, ", "), maxMbps
}
