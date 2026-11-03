package system

// One-shot migration from netplan / systemd-networkd to ifupdown +
// /etc/network/interfaces. Triggered by the "Switch to systemd Networking"
// button on the VMs & Containers enable prereqs page (6.5.6+).
//
// Why we migrate AWAY from netplan rather than teaching the rest of the
// portal to speak netplan: the existing Step-3 of the enable flow already
// rewrites /etc/network/interfaces to convert physical NICs into bridge
// stanzas. Reimplementing the same surgery in netplan YAML doubles the
// surface and forces a renderer decision on every edit. Once VMs &
// Containers is on, all bridge edits go through ifupdown, so it's
// simplest to settle the host onto ifupdown at enable time.
//
// Scope (locked deliberately small for 6.5.6):
//   - Plain ethernet devices only.
//   - networkd or NetworkManager renderer. With NetworkManager, the migrated
//     NICs (and the VM bridges) are declared unmanaged in a conf.d file;
//     NetworkManager itself keeps running for anything else (Wi-Fi…).
//   - No bonds, bridges, vlans, wifis in the netplan YAML — refuse with
//     a clear error so the user knows their setup needs manual
//     conversion.
//   - IPv4 only. IPv6 keeps SLAAC / kernel autoconf.
//
// On any failure mid-flight we roll back: re-enable netplan YAMLs,
// restart systemd-networkd, restore the original /etc/network/interfaces
// (or remove ours if there was none), and return an error.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// netplanScanResult is what a quick textual scan of /etc/netplan/*.yaml
// gives us: just enough to either refuse the migration with a clear note
// or hand off to the live-state-driven generator.
type netplanScanResult struct {
	Files       []string // absolute paths of *.yaml files
	Renderer    string   // "networkd" | "NetworkManager" | "" (default)
	Unsupported []string // names of constructs we won't migrate
	Devices     []string // physical-looking ethernet names found in the YAML
}

var (
	// Lines like "  enp5s0:" or "    enp5s0:" inside an "ethernets:" block.
	// We don't fully parse YAML (per CLAUDE.md, no new module deps) — we
	// just scan for top-level device-name keys under specific sections.
	netplanRendererRe  = regexp.MustCompile(`^\s*renderer:\s*([A-Za-z0-9_-]+)\s*$`)
	netplanSectionRe   = regexp.MustCompile(`^(\s*)(ethernets|bonds|bridges|vlans|wifis|tunnels|modems):\s*$`)
	netplanDeviceKeyRe = regexp.MustCompile(`^(\s+)([A-Za-z0-9_.-]+):\s*$`)
)

// scanNetplanYAMLs reads every /etc/netplan/*.yaml and returns a coarse
// digest. It does NOT validate IP/routing/DNS — that comes from the live
// `ip -j` snapshot. Detected unsupported sections are returned in
// Unsupported so the caller can refuse with a clear message.
func scanNetplanYAMLs() (*netplanScanResult, error) {
	files, _ := filepath.Glob("/etc/netplan/*.yaml")
	if len(files) == 0 {
		return nil, fmt.Errorf("no /etc/netplan/*.yaml files found")
	}
	res := &netplanScanResult{Files: files}
	seenSection := map[string]bool{}
	for _, path := range files {
		// Netplan YAML is owned by root with 0600 since some releases.
		// `sudo cat` is in the existing wildcard-cat path (or bash:
		// the file browser feature already covers this); for migration
		// we prefer in-process read because it's simpler and we only
		// run from a user with sudo (verified upstream).
		data, err := readPossiblyRoot(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		parseNetplanYAMLInto(data, res, seenSection)
	}
	return res, nil
}

// parseNetplanYAMLInto does the coarse line-scan of one netplan YAML document,
// accumulating renderer / ethernet device names / unsupported sections into
// res. seenSection dedups unsupported-section names across multiple files.
// Pure (no I/O) so it's unit-testable. We deliberately don't pull in a YAML
// library (CLAUDE.md: stdlib + gorilla only).
func parseNetplanYAMLInto(data []byte, res *netplanScanResult, seenSection map[string]bool) {
	var (
		currentSection       string
		currentSectionIndent int
		deviceIndent         = -1 // indent of device-name keys in the current ethernets block (detected lazily)
	)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := netplanRendererRe.FindStringSubmatch(line); m != nil {
			res.Renderer = m[1]
			continue
		}
		if m := netplanSectionRe.FindStringSubmatch(line); m != nil {
			currentSectionIndent = len(m[1])
			currentSection = m[2]
			deviceIndent = -1 // entering a new section — re-detect the device indent
			if currentSection != "ethernets" {
				if !seenSection[currentSection] {
					res.Unsupported = append(res.Unsupported, currentSection)
					seenSection[currentSection] = true
				}
			}
			continue
		}
		// Inside an ethernets: block, device-name keys sit at the FIRST
		// indent level deeper than the section keyword. Detect that level
		// dynamically rather than assuming 2-space indentation — Ubuntu's
		// subiquity installer writes 4-space indents (ethernets: at 4,
		// device at 8), which the old `+2` check silently dropped, yielding
		// ethernets=[] and "no ethernet devices found". The first key
		// deeper than the section defines the device level; anything deeper
		// is a nested property (addresses:/routes:/match:/nameservers:…).
		if currentSection == "ethernets" {
			if m := netplanDeviceKeyRe.FindStringSubmatch(line); m != nil {
				ind := len(m[1])
				if ind > currentSectionIndent {
					if deviceIndent == -1 {
						deviceIndent = ind
					}
					if ind == deviceIndent && !containsStr(res.Devices, m[2]) {
						// A device named in several files (installer + drop-in) is one device.
						res.Devices = append(res.Devices, m[2])
					}
				}
			}
		}
	}
}

// readPossiblyRoot reads a file directly when the caller can, else via
// sudo cat. /etc/netplan files on Ubuntu 26.04 are 0600 root:root, so we
// fall back to sudo on permission errors.
func readPossiblyRoot(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		return data, nil
	} else if !os.IsPermission(err) {
		return nil, err
	}
	out, err := exec.Command("sudo", "/usr/bin/cat", path).Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ipAddrLite is what we read from `ip -j addr` for the migration. We only
// touch a handful of fields, hence not reusing the bigger ipAddrIface struct
// from lxd_enable.go (different needs and we want this file self-contained).
type ipAddrLite struct {
	IfName   string `json:"ifname"`
	LinkType string `json:"link_type"`
	MTU      int    `json:"mtu"`
	Master   string `json:"master,omitempty"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Dynamic   bool   `json:"dynamic,omitempty"`
		Scope     string `json:"scope"`
	} `json:"addr_info"`
}

type ipRouteLite struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway,omitempty"`
	Dev     string `json:"dev"`
}

type liveDeviceSnapshot struct {
	Name    string
	IsDHCP  bool
	IPv4    string // "1.2.3.4/24"
	Gateway string // "" if not the default-route device
	MTU     int
	DNS     []string // global if device-specific not available
	// ClientID is the DHCP Option 61 byte string systemd-networkd was
	// presenting to the DHCP server, captured from /run/systemd/netif/leases.
	// Hex-encoded, lowercase, no separators (e.g. "0110666af8c2f0"). Empty
	// when the device wasn't on DHCP or the lease file couldn't be read.
	// Replayed into /etc/dhcpcd.conf so the host gets the SAME lease back
	// after the switch — without it, dhcpcd's default RFC-4361 DUID+IAID
	// Client-ID looks like a brand-new client to the DHCP server and the
	// server hands out a different IP.
	ClientID string
}

// snapshotLiveNet captures the host's current IPv4 view, keyed by interface.
// This is the source of truth for what we write into the new
// /etc/network/interfaces.
func snapshotLiveNet(devices []string) ([]liveDeviceSnapshot, error) {
	addrOut, err := exec.Command("ip", "-j", "addr").Output()
	if err != nil {
		return nil, fmt.Errorf("ip -j addr: %w", err)
	}
	var ifaces []ipAddrLite
	if err := json.Unmarshal(addrOut, &ifaces); err != nil {
		return nil, fmt.Errorf("parse ip addr: %w", err)
	}
	routeOut, err := exec.Command("ip", "-j", "route").Output()
	if err != nil {
		return nil, fmt.Errorf("ip -j route: %w", err)
	}
	var routes []ipRouteLite
	_ = json.Unmarshal(routeOut, &routes)
	gwByDev := map[string]string{}
	for _, r := range routes {
		if r.Dst == "default" && r.Gateway != "" {
			if _, exists := gwByDev[r.Dev]; !exists {
				gwByDev[r.Dev] = r.Gateway
			}
		}
	}
	dnsByDev, globalDNS := snapshotDNS()

	wanted := map[string]bool{}
	for _, d := range devices {
		wanted[d] = true
	}

	var out []liveDeviceSnapshot
	for _, iface := range ifaces {
		if !wanted[iface.IfName] {
			continue
		}
		if iface.LinkType != "ether" {
			continue
		}
		snap := liveDeviceSnapshot{Name: iface.IfName, MTU: iface.MTU}
		for _, a := range iface.AddrInfo {
			if a.Family != "inet" || a.Scope != "global" {
				continue
			}
			snap.IPv4 = fmt.Sprintf("%s/%d", a.Local, a.PrefixLen)
			snap.IsDHCP = a.Dynamic
			break
		}
		snap.Gateway = gwByDev[iface.IfName]
		if d := dnsByDev[iface.IfName]; len(d) > 0 {
			snap.DNS = d
		} else {
			snap.DNS = globalDNS
		}
		if snap.IsDHCP {
			snap.ClientID = readNetworkdClientID(iface.IfName)
		}
		out = append(out, snap)
	}
	return out, nil
}

// readNetworkdClientID parses /run/systemd/netif/leases/<ifindex> and returns
// the CLIENTID= line's value. Empty string on any read/parse failure — the
// migration then falls back to dhcpcd's default identifier (which means the
// DHCP server will likely hand out a different IP, but the migration still
// completes). Lease files are 644, owned by systemd-network — readable
// without sudo.
func readNetworkdClientID(ifname string) string {
	idxBytes, err := os.ReadFile("/sys/class/net/" + ifname + "/ifindex")
	if err != nil {
		return ""
	}
	ifindex := strings.TrimSpace(string(idxBytes))
	if ifindex == "" {
		return ""
	}
	data, err := os.ReadFile("/run/systemd/netif/leases/" + ifindex)
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "CLIENTID=") {
			return strings.TrimPrefix(line, "CLIENTID=")
		}
	}
	return ""
}

// formatDhcpcdClientID converts a lowercase concatenated hex string like
// "0110666af8c2f0" into the colon-separated form dhcpcd's clientid directive
// expects: "01:10:66:6a:f8:c2:f0". Returns "" if the input isn't an even
// number of hex chars.
func formatDhcpcdClientID(hex string) string {
	if len(hex) == 0 || len(hex)%2 != 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(hex); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex[i : i+2])
	}
	return b.String()
}

// dhcpcdConfigBlockMarkers wrap the migration-managed section of
// /etc/dhcpcd.conf so we can find and replace it on subsequent runs.
const (
	dhcpcdMarkerStart = "# >>> ZNAS netplan→ifupdown migration — clientid pinning >>>"
	dhcpcdMarkerEnd   = "# <<< ZNAS netplan→ifupdown migration — clientid pinning <<<"
)

// pinDhcpcdClientIDs writes the ZNAS-managed block of /etc/dhcpcd.conf. The
// block always contains `noipv4ll`, and additionally a per-interface `clientid`
// directive for every DHCP device whose Client-ID we captured from
// systemd-networkd. The block is bounded by start/end marker comments so
// re-running the migration replaces it cleanly.
//
// `noipv4ll` disables dhcpcd's IPv4 link-local (169.254/16) fallback. When the
// bridge first comes up at boot the slaved port spends a moment negotiating
// link, so dhcpcd's first DHCP attempts can fail and it would otherwise
// self-assign a 169.254 address that then lingers next to the real lease. The
// bridge stanza already uses `bridge_stp off`/`bridge_fd 0` to forward
// immediately; this is the belt-and-suspenders that guarantees no APIPA address
// ever appears.
func pinDhcpcdClientIDs(snap []liveDeviceSnapshot, log func(string)) error {
	const path = "/etc/dhcpcd.conf"
	var block strings.Builder
	block.WriteString(dhcpcdMarkerStart + "\n")
	block.WriteString("noipv4ll\n")
	log("    noipv4ll (disable dhcpcd 169.254 link-local fallback)")
	// Disable dhcpcd's built-in resolv.conf hook. On a systemd-resolved host
	// that hook calls `resolvconf`/`resolvectl`, which BLOCKS ~90 s at boot
	// because resolved hasn't claimed its D-Bus name yet ("Failed to set DNS
	// configuration: Transport endpoint is not connected") — dhcpcd then can't
	// background, so networking.service hangs for minutes. We instead write a
	// plain /etc/resolv.conf from the dhcpcd exit-hook (no resolvectl). See
	// dhcpcdResolvedHookBody and feedback_netplan_migration_waitonline_apipa.
	block.WriteString("nohook resolv.conf\n")
	log("    nohook resolv.conf (write a plain /etc/resolv.conf, not via resolved — avoids the 90s boot hang)")
	for _, d := range snap {
		if !d.IsDHCP || d.ClientID == "" {
			continue
		}
		cid := formatDhcpcdClientID(d.ClientID)
		if cid == "" {
			continue
		}
		fmt.Fprintf(&block, "interface %s\n    clientid %s\n", d.Name, cid)
		log(fmt.Sprintf("    %s ← clientid %s (matches systemd-networkd's lease ID)", d.Name, cid))
	}
	block.WriteString(dhcpcdMarkerEnd + "\n")

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	stripped := stripBlockBetweenMarkers(string(existing), dhcpcdMarkerStart, dhcpcdMarkerEnd)
	stripped = strings.TrimRight(stripped, "\n")
	if stripped != "" {
		stripped += "\n\n"
	}
	out := stripped + block.String()

	if err := writeRoot(path, []byte(out), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// stripBlockBetweenMarkers removes everything from the start marker to the
// end marker (inclusive). Returns the input unchanged if the markers aren't
// found in pair order.
func stripBlockBetweenMarkers(s, start, end string) string {
	a := strings.Index(s, start)
	if a < 0 {
		return s
	}
	b := strings.Index(s[a:], end)
	if b < 0 {
		return s
	}
	tail := s[a+b+len(end):]
	tail = strings.TrimLeft(tail, "\n")
	return strings.TrimRight(s[:a], "\n") + "\n" + tail
}

// snapshotDNS returns per-interface DNS servers and a global fallback,
// trying three sources in order so the migration captures DNS on every
// realistic host shape:
//
//  1. `resolvectl dns` — the primary path on hosts that have
//     systemd-resolved (Ubuntu defaults, most netplan installs).
//  2. `/etc/resolv.conf` `nameserver` lines — works on any host that
//     currently resolves DNS, including minimal Debian/Ubuntu installs
//     that ship without systemd-resolved at all (where `resolvectl`
//     itself is "command not found"). Confirmed root cause of a real
//     production failure in v6.5.6 — without this
//     fallback the post-migration `/etc/network/interfaces` had no
//     `dns-nameservers` line and `/etc/resolv.conf` lost its servers.
//  3. `/etc/netplan/*.yaml` `nameservers.addresses` — last-resort
//     capture for hosts where DNS is set in netplan but never made it
//     into a live resolver (e.g. a freshly edited YAML that hasn't
//     been applied yet, or a non-default renderer).
//
// Per-link and global DNS are accumulated independently across the three
// sources: a host with `/etc/resolv.conf` populated but no resolvectl
// still gets its DNS into the global list, and a host with per-interface
// DNS in netplan YAML still gets that into the per-interface map even
// when the global list comes from /etc/resolv.conf.
func snapshotDNS() (map[string][]string, []string) {
	per := map[string][]string{}
	var global []string

	// 1. resolvectl (best source — knows about per-link config).
	if out, err := exec.Command("resolvectl", "dns", "--no-pager").Output(); err == nil {
		linkRe := regexp.MustCompile(`^Link\s+\d+\s+\(([^)]+)\):\s*(.*)$`)
		globalRe := regexp.MustCompile(`^Global:\s*(.*)$`)
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if m := linkRe.FindStringSubmatch(line); m != nil {
				per[m[1]] = strings.Fields(m[2])
				continue
			}
			if m := globalRe.FindStringSubmatch(line); m != nil {
				global = strings.Fields(m[1])
			}
		}
	}

	// 2. /etc/resolv.conf — only fills the global slot if resolvectl
	// didn't already populate it. The file may be a regular file (the
	// hand-edited or migrated form) or a symlink to systemd-resolved's
	// stub: os.Open follows the symlink either way.
	if len(global) == 0 {
		global = readResolvConfNameservers("/etc/resolv.conf")
	}

	// 3. /etc/netplan/*.yaml `nameservers.addresses`. Merged into the
	// per-interface map for any device that still has nothing, and
	// promoted to the global list if global is also empty.
	yamlPer := readNetplanNameservers()
	for ifname, dns := range yamlPer {
		if len(per[ifname]) == 0 {
			per[ifname] = dns
		}
	}
	if len(global) == 0 {
		seen := map[string]bool{}
		for _, dns := range yamlPer {
			for _, s := range dns {
				if seen[s] {
					continue
				}
				seen[s] = true
				global = append(global, s)
			}
		}
	}

	return per, global
}

// readResolvConfNameservers scans a resolv.conf-shaped file for
// `nameserver <ip>` lines. Empty result on any read or parse error —
// callers treat empty as "fall through to next source".
func readResolvConfNameservers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		// Some libresolv-conf forms include a comment after the IP;
		// take the first whitespace-separated token only.
		ip := fields[1]
		if seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	return out
}

// readNetplanNameservers parses every /etc/netplan/*.yaml looking for
// per-interface `nameservers: { addresses: [...] }` blocks under an
// `ethernets:` section. We stay with the same indent-aware textual
// scan used by scanNetplanYAMLs (per CLAUDE.md, no new module deps for
// a real YAML parser). Result keys are interface names.
//
// Two YAML shapes are accepted:
//
//	ethernets:
//	  enp5s0:
//	    nameservers:
//	      addresses: [10.0.0.1, 10.0.0.2]
//
//	ethernets:
//	  enp5s0:
//	    nameservers:
//	      addresses:
//	        - 10.0.0.1
//	        - 10.0.0.2
//
// Anything we can't parse cleanly is silently skipped.
func readNetplanNameservers() map[string][]string {
	out := map[string][]string{}
	files, _ := filepath.Glob("/etc/netplan/*.yaml")
	for _, path := range files {
		data, err := readPossiblyRoot(path)
		if err != nil {
			continue
		}
		parseNetplanNameserversInto(string(data), out)
	}
	return out
}

// parseNetplanNameserversInto walks a single YAML doc's lines and merges
// any per-interface DNS it finds into `dst`. Pulled out so a unit test
// can pin the parser without touching /etc/netplan.
func parseNetplanNameserversInto(yaml string, dst map[string][]string) {
	var (
		inEthernets       bool
		ethernetsIndent   int
		ifname            string
		ifnameIndent      int
		inNameservers     bool
		nameserversIndent int
		inAddressesList   bool
		addressesIndent   int
	)
	inlineListRe := regexp.MustCompile(`^\s*addresses:\s*\[([^\]]*)\]\s*$`)
	listItemRe := regexp.MustCompile(`^\s*-\s*([0-9A-Fa-f.:]+)\s*$`)

	for _, line := range strings.Split(yaml, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))

		// Section change: any non-deeper-than-context key resets the
		// nested state we were tracking.
		if inAddressesList && indent <= addressesIndent {
			inAddressesList = false
		}
		if inNameservers && indent <= nameserversIndent {
			inNameservers = false
		}
		if ifname != "" && indent <= ifnameIndent {
			ifname = ""
		}
		if inEthernets && indent <= ethernetsIndent && !strings.HasPrefix(trimmed, "ethernets:") {
			inEthernets = false
		}

		if m := netplanSectionRe.FindStringSubmatch(line); m != nil {
			if m[2] == "ethernets" {
				inEthernets = true
				ethernetsIndent = len(m[1])
			}
			continue
		}
		if !inEthernets {
			continue
		}

		// Device key inside ethernets:
		if m := netplanDeviceKeyRe.FindStringSubmatch(line); m != nil && len(m[1]) == ethernetsIndent+2 {
			ifname = m[2]
			ifnameIndent = len(m[1])
			inNameservers = false
			inAddressesList = false
			continue
		}
		if ifname == "" {
			continue
		}

		// `nameservers:` opens a sub-block.
		if strings.HasPrefix(trimmed, "nameservers:") && indent > ifnameIndent {
			inNameservers = true
			nameserversIndent = indent
			continue
		}
		if !inNameservers {
			continue
		}

		// Inline form: addresses: [a, b].
		if m := inlineListRe.FindStringSubmatch(line); m != nil {
			for _, s := range strings.Split(m[1], ",") {
				s = strings.TrimSpace(s)
				s = strings.Trim(s, "\"'")
				if s != "" {
					dst[ifname] = append(dst[ifname], s)
				}
			}
			continue
		}
		// Block form: addresses:\n  - x\n  - y
		if strings.HasPrefix(trimmed, "addresses:") {
			inAddressesList = true
			addressesIndent = indent
			continue
		}
		if inAddressesList {
			if m := listItemRe.FindStringSubmatch(line); m != nil {
				dst[ifname] = append(dst[ifname], m[1])
			}
		}
	}
}

// renderInterfacesFile composes the /etc/network/interfaces text from the
// live snapshot. Always emits the lo loopback. Per-NIC stanza picks
// inet dhcp vs inet static based on whether the live address is dynamic.
func renderInterfacesFile(devices []liveDeviceSnapshot) string {
	var b strings.Builder
	b.WriteString("# /etc/network/interfaces — written by ZNAS netplan→ifupdown migration.\n")
	b.WriteString("# Source of truth was the live `ip -j addr` / `ip -j route` /\n")
	b.WriteString("# `resolvectl dns` output at migration time.\n\n")
	b.WriteString("auto lo\niface lo inet loopback\n\n")
	for _, d := range devices {
		// `auto` (NOT allow-hotplug): networking.service brings the NIC up via
		// `ifup -a`. The udev path that would otherwise race it (ifup@<dev>)
		// is masked by hardenIfupdownBoot, so there's a single bring-up path
		// and no /run/network/ifstate lock contention. `auto` is also required
		// for the later bridge/VLAN stanzas (their pre-up `ip link add` must
		// run from networking.service), so we keep one consistent keyword.
		b.WriteString(fmt.Sprintf("auto %s\n", d.Name))
		if d.IsDHCP || d.IPv4 == "" {
			// DHCP path: deliberately omit `dns-nameservers`. The
			// installed dhcpcd exit-hook pushes the DHCP-supplied
			// DNS into systemd-resolved via `resolvectl`, so no
			// static value should be baked into the interfaces file
			// (it would override the live DHCP answer).
			b.WriteString(fmt.Sprintf("iface %s inet dhcp\n", d.Name))
		} else {
			b.WriteString(fmt.Sprintf("iface %s inet static\n", d.Name))
			b.WriteString(fmt.Sprintf("    address %s\n", d.IPv4))
			if d.Gateway != "" {
				b.WriteString(fmt.Sprintf("    gateway %s\n", d.Gateway))
			}
			// Static path: the user's chosen DNS is part of the
			// static config and lives in the interfaces file. Step 3
			// of the enable flow preserves it onto the bridge stanza.
			if len(d.DNS) > 0 {
				b.WriteString(fmt.Sprintf("    dns-nameservers %s\n", strings.Join(d.DNS, " ")))
			}
		}
		if d.MTU > 0 && d.MTU != 1500 {
			b.WriteString(fmt.Sprintf("    mtu %d\n", d.MTU))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// MigrateNetplanToIfupdown runs the full migration and streams progress.
// stream is called with single short lines (newline-free). On any error
// the function rolls back what it can and returns the error; the caller
// (HTTP handler) just relays the error to the user.
func MigrateNetplanToIfupdown(stream func(string)) error {
	log := func(s string) {
		if stream != nil {
			stream(s)
		}
	}

	log("Scanning /etc/netplan/*.yaml…")
	scan, err := scanNetplanYAMLs()
	if err != nil {
		// No netplan YAMLs. On a stock Debian host the network is managed by
		// raw systemd-networkd (/etc/systemd/network/*.network) — migrate from
		// the live state instead. Everything below (snapshot → render
		// /etc/network/interfaces → disable+mask networkd → ifup) is renderer-
		// agnostic; only the device list and the netplan-file rename differ.
		// (v6.6.26.)
		if systemdNetworkdActive() {
			log("  No netplan YAMLs — migrating from raw systemd-networkd.")
			scan = &netplanScanResult{Renderer: "networkd", Devices: liveManagedEtherDevices()}
		} else {
			return err
		}
	}
	log(fmt.Sprintf("  Found %d file(s); renderer=%q; ethernets=%v",
		len(scan.Files), scan.Renderer, scan.Devices))

	viaNM := strings.EqualFold(scan.Renderer, "NetworkManager")
	if viaNM && !networkManagerActive() {
		return fmt.Errorf("netplan renderer is NetworkManager but NetworkManager is not running — fix the network configuration first")
	}
	if len(scan.Unsupported) > 0 {
		return fmt.Errorf("netplan contains unsupported sections (%s); migrate manually before enabling VMs & Containers",
			strings.Join(scan.Unsupported, ", "))
	}
	if len(scan.Devices) == 0 {
		return fmt.Errorf("no ethernet devices found in netplan YAML")
	}

	log("Snapshotting live IP / route / DNS state…")
	snap, err := snapshotLiveNet(scan.Devices)
	if err != nil {
		return err
	}
	for _, d := range snap {
		mode := "dhcp"
		if !d.IsDHCP && d.IPv4 != "" {
			mode = "static " + d.IPv4
			if d.Gateway != "" {
				mode += " gw " + d.Gateway
			}
		}
		log(fmt.Sprintf("  %s — %s, mtu=%d, dns=%v", d.Name, mode, d.MTU, d.DNS))
	}

	// Step 1: install ifupdown if missing.
	if !pkgInstalled("ifupdown") {
		log("Installing ifupdown package…")
		if out, err := exec.Command("sudo", "/usr/bin/apt-get", "install", "-y", "ifupdown").CombinedOutput(); err != nil {
			return fmt.Errorf("apt-get install ifupdown: %s", strings.TrimSpace(string(out)))
		}
	} else {
		log("ifupdown already installed.")
	}

	// Step 1b: configure dhcpcd — disable its 169.254 link-local fallback
	// (noipv4ll) and pin each DHCP interface's Client-Identifier to whatever
	// systemd-networkd was using, so the DHCP server hands the same lease back.
	// Best-effort — a failure here doesn't abort the migration; the host still
	// gets an IP, just possibly a different one.
	log("Configuring dhcpcd (noipv4ll + Client-ID pinning to match systemd-networkd)…")
	if err := pinDhcpcdClientIDs(snap, log); err != nil {
		log("  ⚠ Could not write dhcpcd config: " + err.Error() + " (continuing — IP may change)")
	}

	// Step 2: backup + write /etc/network/interfaces.
	newContent := renderInterfacesFile(snap)
	log("New /etc/network/interfaces:\n" + indent(newContent, "    | "))

	const targetPath = "/etc/network/interfaces"
	var backupPath string
	if existing, err := os.ReadFile(targetPath); err == nil {
		backupPath = fmt.Sprintf("%s.pre-znas-%d", targetPath, time.Now().Unix())
		log("Backing up existing " + targetPath + " → " + backupPath)
		if err := writeRoot(backupPath, existing, 0o644); err != nil {
			return fmt.Errorf("backup %s: %w", targetPath, err)
		}
	}

	log("Writing " + targetPath + "…")
	if err := writeRoot(targetPath, []byte(newContent), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", targetPath, err)
	}

	// Step 3: stop + disable systemd-networkd AND its activation sockets.
	// On Ubuntu 26.04 there are three socket units that can re-trigger
	// the service even after we stop it (varlink / resolve-hook / the
	// main netlink socket). We disable all of them; otherwise the
	// service comes back ~instantly after stop and reapplies the
	// netplan-generated /run/systemd/network/*.network configs we're
	// trying to walk away from. We tolerate "not loaded" / "does not
	// exist" so older releases without one or another socket don't
	// abort the migration.
	if viaNM {
		// NetworkManager renders netplan here: stop it managing the NICs we
		// hand to ifupdown (and the VM bridges created later). It keeps
		// running for anything else. systemd-networkd is not involved.
		log("Telling NetworkManager to leave " + strings.Join(scan.Devices, ", ") + " to ifupdown → " + nmUnmanagedConfPath)
		if err := writeRoot(nmUnmanagedConfPath, []byte(nmUnmanagedConf(scan.Devices)), 0o644); err != nil {
			rollbackInterfaces(targetPath, backupPath)
			return fmt.Errorf("write %s: %w", nmUnmanagedConfPath, err)
		}
		if out, err := exec.Command("sudo", "/usr/bin/systemctl", "reload", "NetworkManager").CombinedOutput(); err != nil {
			log("  systemctl reload NetworkManager: " + strings.TrimSpace(string(out)) + " (continuing)")
		}
	}
	rollbackNet := rollbackNetworkd
	if viaNM {
		rollbackNet = func() { rollbackNetworkManager(scan.Files) }
	}
	if !viaNM {
		disableNetworkd(log)
	}

	// Remove the netplan-generated systemd-networkd runtime configs.
	// These live on tmpfs (/run) and would normally vanish on reboot,
	// but until then they're what makes a re-spawned systemd-networkd
	// instantly start managing our NICs again.
	log("Removing leftover /run/systemd/network/*.network files…")
	if matches, _ := filepath.Glob("/run/systemd/network/*.network"); len(matches) > 0 {
		args := append([]string{"/usr/bin/rm", "-f"}, matches...)
		if out, err := exec.Command("sudo", args...).CombinedOutput(); err != nil {
			log("  rm: " + strings.TrimSpace(string(out)) + " (continuing)")
		}
	}

	// Step 4: rename netplan YAMLs out of the way.
	for _, p := range scan.Files {
		dst := p + ".znas-disabled"
		log("Renaming " + p + " → " + dst)
		if out, err := exec.Command("sudo", "/usr/bin/mv", p, dst).CombinedOutput(); err != nil {
			// Hard failure — without this rename, a future netplan apply
			// would clobber our config.
			rollbackInterfaces(targetPath, backupPath)
			rollbackNet()
			return fmt.Errorf("mv %s: %s", p, strings.TrimSpace(string(out)))
		}
	}

	if viaNM {
		// Drop the NetworkManager profiles netplan generated for them.
		if out, err := exec.Command("sudo", "/usr/sbin/netplan", "generate").CombinedOutput(); err != nil {
			log("  netplan generate: " + strings.TrimSpace(string(out)) + " (continuing)")
		}
		exec.Command("sudo", "/usr/bin/nmcli", "connection", "reload").Run() //nolint:errcheck
	}

	// Step 5: drop a cloud-init disable file (if cloud-init is installed)
	// so the next reboot doesn't regenerate /etc/netplan/50-cloud-init.yaml.
	if _, err := os.Stat("/etc/cloud/cloud.cfg.d"); err == nil {
		const disableFile = "/etc/cloud/cloud.cfg.d/99-znas-disable-network-config.cfg"
		log("Disabling cloud-init network management → " + disableFile)
		body := "# Written by ZNAS during netplan→ifupdown migration.\nnetwork: {config: disabled}\n"
		if err := writeRoot(disableFile, []byte(body), 0o644); err != nil {
			log("  ⚠ Could not write " + disableFile + ": " + err.Error())
		}
	} else {
		log("cloud-init not present; skipping its network-disable drop-in.")
	}

	// Step 5b: keep DNS dynamic for DHCP interfaces.
	//
	// Approach: leave systemd-resolved running and let it own /etc/resolv.conf
	// (the standard Ubuntu 26.04 stub-symlink). Install a small dhcpcd
	// exit-hook that, on every BOUND/RENEW/REBIND, calls `resolvectl dns
	// <iface> <ip…>` so resolved learns the DHCP-supplied DNS for that
	// interface. Static interfaces aren't touched here — for those, the
	// user's `dns-nameservers` line is the authoritative config and the
	// hook (which also calls resolvectl on STATIC interfaces with
	// dns-nameservers via ifupdown's resolvectl integration) is unnecessary.
	//
	// We never rewrite /etc/resolv.conf as a regular file. If a previous
	// migration of ours did, restore the stub symlink so resolved owns it
	// again.
	log("Installing dhcpcd → systemd-resolved exit-hook…")
	if err := installDhcpcdResolvedHook(); err != nil {
		log("  ⚠ Could not install dhcpcd hook: " + err.Error() + " (DHCP-supplied DNS may not propagate)")
	} else {
		log("  ✓ /etc/dhcpcd.exit-hook in place — DHCP DNS will be pushed to systemd-resolved per interface")
	}

	// Pick the right /etc/resolv.conf shape based on the user's intent:
	//
	//   • All DHCP → restore the systemd-resolved stub symlink. The hook
	//     above feeds resolved with whatever DNS the DHCP server hands
	//     back, dynamically.
	//
	//   • Any static interface with dns-nameservers → write /etc/resolv.conf
	//     as a regular file containing those static DNS servers. The
	//     user opted for static, so their DNS is part of that fixed
	//     config — it lives both in /etc/network/interfaces and in
	//     /etc/resolv.conf, exactly as the user expects.
	// Always write a PLAIN /etc/resolv.conf — never the systemd-resolved stub
	// symlink. On ifupdown we keep DNS in a plain file so NOTHING in the boot
	// path depends on systemd-resolved being reachable on D-Bus (it isn't, this
	// early in boot — see hardenIfupdownBoot). Static DNS is authoritative; for
	// DHCP interfaces the dhcpcd exit-hook (dhcpcdResolvedHookBody) refreshes
	// this same plain file on every lease. Previously DHCP restored the resolved
	// stub symlink, whose resolvectl-based hooks hung networking.service ~90 s
	// at boot (confirmed on a fresh Ubuntu 26.04 DHCP VM).
	dns := collectAllDNS(snap)
	if len(dns) > 0 {
		log(fmt.Sprintf("Writing plain /etc/resolv.conf with DNS %v…", dns))
	} else {
		log("No DNS captured; writing a plain /etc/resolv.conf for the dhcpcd exit-hook to populate on first lease…")
	}
	if err := writeStaticResolvConf(dns); err != nil {
		log("  ⚠ Could not write /etc/resolv.conf: " + err.Error())
	}

	// Step 5c: remove the two ifupdown boot-hang traps (resolved-vs-dbus race
	// and the udev ifup@ duplicate-bring-up race) BEFORE networking.service
	// runs, so the migration's own `ifup -a` below — and every subsequent
	// boot — is fast. See hardenIfupdownBoot.
	hardenIfupdownBoot(log)

	// Step 6: enable + start ifupdown's networking.service. This is the
	// "may briefly drop the link" moment.
	log("Enabling networking.service (ifupdown)…")
	if out, err := exec.Command("sudo", "/usr/bin/systemctl", "enable", "networking").CombinedOutput(); err != nil {
		log("  systemctl enable networking: " + strings.TrimSpace(string(out)))
	}

	// Flush each managed interface's IPv4 addresses + routes before
	// `ifup -a` runs. Without this, the addresses configured by netplan
	// (and not always reaped when systemd-networkd stops, especially for
	// static configs) collide with `ip addr add` inside the ifup hooks
	// and `networking.service` exits non-zero — even though the live
	// state is correct. The flush is brief (sub-second), the new
	// addresses come back via `ifup -a` immediately after, and the
	// dhcpcd Client-ID pinning means DHCP returns the same lease.
	log("Flushing managed interfaces' IPv4 state to avoid `ip addr add: File exists`…")
	for _, d := range snap {
		exec.Command("sudo", "/usr/bin/ip", "addr", "flush", "dev", d.Name, "scope", "global").Run()  //nolint:errcheck
		exec.Command("sudo", "/usr/bin/ip", "route", "flush", "dev", d.Name, "scope", "global").Run() //nolint:errcheck
	}

	log("Starting networking.service — your shell or HTTPS session may briefly hiccup…")
	if out, err := exec.Command("sudo", "/usr/bin/systemctl", "start", "networking").CombinedOutput(); err != nil {
		// On many Ubuntu installs `systemctl start networking` returns
		// non-zero because some interface failed (loopback already up,
		// etc.) but the device we care about IS up. Verify before we
		// roll back.
		log("  systemctl start networking returned an error: " + strings.TrimSpace(string(out)))
	}

	// Step 7: verify the managed devices still hold an IPv4 address.
	// Give ifupdown's dhclient a moment to finish.
	time.Sleep(3 * time.Second)
	bad := devicesMissingIPv4(scan.Devices)
	if len(bad) > 0 {
		log("Verification failed — interface(s) lost their IPv4: " + strings.Join(bad, ", "))
		log("Rolling back…")
		rollbackInterfaces(targetPath, backupPath)
		// Restore the netplan YAMLs.
		for _, p := range scan.Files {
			exec.Command("sudo", "/usr/bin/mv", p+".znas-disabled", p).Run() //nolint:errcheck
		}
		rollbackNet()
		return fmt.Errorf("ifupdown could not bring up %s — original network config restored",
			strings.Join(bad, ", "))
	}

	log("✓ Migration complete. /etc/network/interfaces is now authoritative.")
	return nil
}

// disableNetworkd stops, disables and masks systemd-networkd, its activation
// sockets and wait-online (networkd renderer migration).
func disableNetworkd(log func(string)) {
	log("Disabling systemd-networkd (service + activation sockets + wait-online)…")
	networkdUnits := []string{
		"systemd-networkd-resolve-hook.socket",
		"systemd-networkd-varlink.socket",
		"systemd-networkd.socket",
		"systemd-networkd.service",
		// The wait-online unit is the real boot-time troublemaker: it is pulled
		// in by network-online.target (Wants=) and its Requires=systemd-networkd
		// RE-ACTIVATES networkd at boot even after we disable it, then blocks
		// boot for ~2 min waiting for a "routable" interface networkd no longer
		// manages. Disable it here and mask it below.
		"systemd-networkd-wait-online.service",
	}
	for _, u := range networkdUnits {
		for _, action := range []string{"disable", "stop"} {
			out, err := exec.Command("sudo", "/usr/bin/systemctl", action, u).CombinedOutput()
			if err == nil {
				continue
			}
			msg := strings.TrimSpace(string(out))
			if !strings.Contains(msg, "not loaded") &&
				!strings.Contains(msg, "does not exist") &&
				!strings.Contains(msg, "Failed to disable") {
				log(fmt.Sprintf("  systemctl %s %s: %s (continuing)", action, u, msg))
			}
		}
	}

	// Mask systemd-networkd and its wait-online unit. Disabling alone is not
	// enough on Ubuntu 26.04: network-online.target still pulls wait-online,
	// which Requires= networkd and so brings it back at boot (and hangs boot
	// ~2 min). Masking severs that chain for good — neither unit can be started
	// or pulled in. Rollback (rollbackNetworkd) unmasks them.
	log("Masking systemd-networkd + wait-online so boot can't wait on or revive them…")
	for _, u := range []string{"systemd-networkd-wait-online.service", "systemd-networkd.service"} {
		if out, err := exec.Command("sudo", "/usr/bin/systemctl", "mask", u).CombinedOutput(); err != nil {
			log(fmt.Sprintf("  systemctl mask %s: %s (continuing)", u, strings.TrimSpace(string(out))))
		}
	}
}

// undoIfupdownHardening reverts hardenIfupdownBoot.
func undoIfupdownHardening() {
	exec.Command("sudo", "/usr/bin/systemctl", "unmask", "ifup@.service").Run() //nolint:errcheck
	exec.Command("sudo", "/usr/bin/chmod", "+x", resolvedIfupHook).Run()        //nolint:errcheck
}

// nmUnmanagedConfPath keeps NetworkManager off the NICs handed to ifupdown.
const nmUnmanagedConfPath = "/etc/NetworkManager/conf.d/99-znas-ifupdown.conf"

// nmUnmanagedConf: the migrated NICs and the VM bridges (vmbr*) are
// ifupdown's; NetworkManager keeps whatever else it manages.
func nmUnmanagedConf(devs []string) string {
	var parts []string
	for _, d := range devs {
		parts = append(parts, "interface-name:"+d)
	}
	parts = append(parts, "interface-name:vmbr*")
	return "# Written by ZNAS during the netplan→ifupdown migration: these interfaces\n" +
		"# are configured in /etc/network/interfaces (ifupdown).\n" +
		"[keyfile]\nunmanaged-devices=" + strings.Join(parts, ";") + "\n"
}

// rollbackNetworkManager gives the NICs back to NetworkManager: our conf.d
// file removed, the netplan files restored and applied.
func rollbackNetworkManager(files []string) {
	undoIfupdownHardening()
	exec.Command("sudo", "/usr/bin/systemctl", "disable", "networking").Run() //nolint:errcheck
	exec.Command("sudo", "/usr/bin/rm", "-f", nmUnmanagedConfPath).Run()      //nolint:errcheck
	for _, p := range files {
		if _, err := os.Stat(p + ".znas-disabled"); err == nil {
			exec.Command("sudo", "/usr/bin/mv", p+".znas-disabled", p).Run() //nolint:errcheck
		}
	}
	exec.Command("sudo", "/usr/bin/systemctl", "reload", "NetworkManager").Run() //nolint:errcheck
	exec.Command("sudo", "/usr/sbin/netplan", "apply").Run()                     //nolint:errcheck
}

// liveManagedEtherDevices returns the names of ether interfaces that carry a
// global IPv4 address and are not enslaved to a bridge/bond (Master unset) —
// the management NICs to migrate onto ifupdown. Used when there is no netplan
// YAML to read the device list from (raw systemd-networkd hosts). Mirrors the
// device set netplan would have listed under `ethernets:`.
func liveManagedEtherDevices() []string {
	out, err := exec.Command("ip", "-j", "addr").Output()
	if err != nil {
		return nil
	}
	var ifaces []ipAddrLite
	if err := json.Unmarshal(out, &ifaces); err != nil {
		return nil
	}
	var names []string
	for _, ifc := range ifaces {
		if ifc.LinkType != "ether" || ifc.Master != "" {
			continue
		}
		for _, a := range ifc.AddrInfo {
			if a.Family == "inet" && a.Scope == "global" {
				names = append(names, ifc.IfName)
				break
			}
		}
	}
	return names
}

// devicesMissingIPv4 returns the subset of names that no longer have a
// global IPv4 address in `ip -j addr`.
func devicesMissingIPv4(names []string) []string {
	out, err := exec.Command("ip", "-j", "addr").Output()
	if err != nil {
		return names
	}
	var ifaces []ipAddrLite
	if err := json.Unmarshal(out, &ifaces); err != nil {
		return names
	}
	hasIP := map[string]bool{}
	for _, iface := range ifaces {
		for _, a := range iface.AddrInfo {
			if a.Family == "inet" && a.Scope == "global" {
				hasIP[iface.IfName] = true
				break
			}
		}
	}
	var missing []string
	for _, n := range names {
		if !hasIP[n] {
			missing = append(missing, n)
		}
	}
	return missing
}

// pkgInstalled returns true if dpkg-query reports the named .deb is installed.
func pkgInstalled(name string) bool {
	out, err := exec.Command("dpkg-query", "-W", "-f=${Status}", name).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "install ok installed")
}

// writeRoot writes data to path, using direct I/O when running as root and
// `sudo tee` otherwise. Matches writeInterfacesFile in lxd_enable.go: tee
// writes the file with default 0644 mode; we don't chmod afterwards to
// keep the sudoers surface narrow (only `tee <path>` needed).
func writeRoot(path string, data []byte, _ os.FileMode) error {
	if os.Getuid() == 0 {
		return os.WriteFile(path, data, 0o644)
	}
	cmd := exec.Command("sudo", "/usr/bin/tee", path)
	cmd.Stdin = strings.NewReader(string(data))
	cmd.Stdout = nil
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// dhcpcdResolvedHookPath is where the dhcpcd→systemd-resolved bridge
// script lives. dhcpcd runs this after every lease event with a populated
// $reason and $new_domain_name_servers / $new_domain_search.
const dhcpcdResolvedHookPath = "/etc/dhcpcd.exit-hook"

// dhcpcdResolvedHookBody is the entire exit-hook content. It writes a PLAIN
// /etc/resolv.conf from the DHCP-supplied DNS — deliberately NOT via resolvectl
// / systemd-resolved. resolved hasn't claimed its D-Bus name this early in boot
// (it starts before dbus), so any resolvectl call BLOCKS ~90 s before failing
// "Transport endpoint is not connected", which prevents dhcpcd from
// backgrounding and hangs networking.service for minutes (confirmed on a fresh
// Ubuntu 26.04 DHCP VM). A plain file write is instant and resolves DNS the
// same way the static path does. Paired with `nohook resolv.conf` in
// dhcpcd.conf so dhcpcd's own resolved hook doesn't run. Idempotent.
const dhcpcdResolvedHookBody = `#!/bin/sh
# Managed by ZNAS netplan→ifupdown migration.
# Write a plain /etc/resolv.conf from the DHCP-supplied DNS. NO resolvectl /
# systemd-resolved (it isn't on D-Bus this early in boot and would hang
# networking.service ~90s). Single-uplink hosts: last lease wins.
case "$reason" in
    BOUND|RENEW|REBIND|REBOOT|INFORM)
        if [ -n "$new_domain_name_servers" ]; then
            {
                for s in $new_domain_name_servers; do echo "nameserver $s"; done
                [ -n "$new_domain_search" ] && echo "search $new_domain_search"
                [ -n "$new_domain_name" ] && echo "domain $new_domain_name"
            } > /etc/resolv.conf 2>/dev/null || true
        fi
        ;;
esac
`

// installDhcpcdResolvedHook writes the dhcpcd exit-hook and makes it
// executable. Idempotent — re-running the migration overwrites the file
// with the same content (so a future hook update lands on next migration).
func installDhcpcdResolvedHook() error {
	if err := writeRoot(dhcpcdResolvedHookPath, []byte(dhcpcdResolvedHookBody), 0o755); err != nil {
		return err
	}
	if out, err := exec.Command("sudo", "/usr/bin/chmod", "0755", dhcpcdResolvedHookPath).CombinedOutput(); err != nil {
		return fmt.Errorf("chmod 0755 %s: %s", dhcpcdResolvedHookPath, strings.TrimSpace(string(out)))
	}
	return nil
}

// collectStaticDNS returns the deduped DNS servers across every STATIC
// device that has dns-nameservers configured. DHCP devices are skipped
// — their DNS comes dynamically via the dhcpcd → systemd-resolved hook.
// Returns nil when no static device has DNS, which signals the caller
// to fall back to the systemd-resolved stub symlink.
func collectStaticDNS(devices []liveDeviceSnapshot) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range devices {
		if d.IsDHCP {
			continue
		}
		for _, s := range d.DNS {
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// collectAllDNS returns the deduped DNS servers across EVERY device (static and
// DHCP) captured at migration time. We seed /etc/resolv.conf with these so DNS
// works immediately after the switch; for DHCP interfaces the dhcpcd exit-hook
// then keeps the same plain file refreshed on each lease.
func collectAllDNS(devices []liveDeviceSnapshot) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range devices {
		for _, s := range d.DNS {
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// writeStaticResolvConf replaces /etc/resolv.conf with a regular file
// containing the given nameservers — used when at least one interface is
// static (the user opted out of dynamic DNS for that NIC, so the resolver
// config should be static too). If /etc/resolv.conf is currently a
// symlink (Ubuntu/Debian default → systemd-resolved stub), it is removed
// first; otherwise `tee` would write through into the resolved-managed
// run-time file, which is the opposite of what we want.
func writeStaticResolvConf(dns []string) error {
	const path = "/etc/resolv.conf"
	var b strings.Builder
	b.WriteString("# Written by ZNAS netplan→ifupdown migration.\n")
	b.WriteString("# Static DNS preserved from your static-IP interface(s);\n")
	b.WriteString("# replaces the systemd-resolved stub symlink so the user's\n")
	b.WriteString("# explicit dns-nameservers config is what gets queried.\n")
	for _, s := range dns {
		b.WriteString("nameserver " + s + "\n")
	}
	exec.Command("sudo", "/usr/bin/rm", "-f", path).Run() //nolint:errcheck
	return writeRoot(path, []byte(b.String()), 0o644)
}

// ensureResolvConfStubSymlink restores /etc/resolv.conf to point at
// /run/systemd/resolve/stub-resolv.conf (the standard Ubuntu / Debian
// systemd-resolved layout). No-op when the symlink already targets the
// stub. If the file is a regular file (e.g. left behind by an older ZNAS
// migration), it's removed first.
func ensureResolvConfStubSymlink(log func(string)) error {
	const target = "/run/systemd/resolve/stub-resolv.conf"
	const path = "/etc/resolv.conf"

	if cur, err := os.Readlink(path); err == nil && cur == target {
		return nil
	}
	log("Restoring /etc/resolv.conf → " + target + " (systemd-resolved stub)…")
	exec.Command("sudo", "/usr/bin/rm", "-f", path).Run() //nolint:errcheck
	if out, err := exec.Command("sudo", "/usr/bin/ln", "-sf", target, path).CombinedOutput(); err != nil {
		return fmt.Errorf("ln -sf: %s", strings.TrimSpace(string(out)))
	}
	// systemd-resolved is left running through the migration; ensure it's
	// enabled so the stub keeps resolving on the next reboot.
	exec.Command("sudo", "/usr/bin/systemctl", "enable", "systemd-resolved").Run() //nolint:errcheck
	exec.Command("sudo", "/usr/bin/systemctl", "start", "systemd-resolved").Run()  //nolint:errcheck
	return nil
}

func indent(s, prefix string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString(prefix)
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// rollbackInterfaces restores the /etc/network/interfaces backup if there
// was one, or removes the file we wrote if there wasn't.
func rollbackInterfaces(targetPath, backupPath string) {
	if backupPath == "" {
		exec.Command("sudo", "/usr/bin/rm", "-f", targetPath).Run() //nolint:errcheck
		return
	}
	if data, err := os.ReadFile(backupPath); err == nil {
		_ = writeRoot(targetPath, data, 0o644)
	}
}

// rollbackNetworkd re-enables systemd-networkd and its activation
// sockets. Best-effort. Mirrors the units we disabled in the forward
// pass so a rollback leaves systemd-networkd in the same state we
// found it.
// resolvedIfupHook is systemd-resolved's ifupdown hook. ifup runs it for every
// non-lo interface whenever resolved is enabled, and it calls `resolvectl` over
// D-Bus — the boot-hang trap that hardenIfupdownBoot neutralizes.
const resolvedIfupHook = "/etc/network/if-up.d/resolved"

// hardenIfupdownBoot removes the two boot-hang traps that surface after the
// switch to ifupdown on Ubuntu 26.04. Confirmed live on a fresh install (znas3,
// June 2026) where boot stalled ~5 min on networking.service/start and the
// portal/sshd didn't come up until network-online.target finally gave up:
//
//  1. ifup runs /etc/network/if-up.d/resolved, which calls `resolvectl` over
//     D-Bus. At boot, networking.service has no ordering guarantee vs dbus and
//     systemd-resolved usually hasn't claimed its org.freedesktop.resolve1
//     name yet (it starts in sysinit, before dbus), so resolvectl either blocks
//     25 s on D-Bus activation or fails with `sd_bus_open_system: No such file`
//     when dbus.socket isn't up — and networking.service then hits its 5-min
//     TimeoutStartSec, fails, and drags network-online.target (portal + sshd)
//     with it. We already write a static /etc/resolv.conf, so the hook is
//     redundant here. NEUTRALIZE it (chmod -x — ifup's run-parts only executes
//     executable files), removing dbus/resolved from the boot-critical network
//     path entirely.
//
//     Do NOT try to fix this by ordering resolved After=dbus via a drop-in: it
//     BACKFIRES. resolved is part of sysinit.target, which dbus transitively
//     needs, so After=dbus forms an ordering cycle; systemd breaks it by
//     deleting a job — non-deterministically dbus.socket — which bricks D-Bus
//     and makes boot WORSE and flaky (a lucky cycle-break boots fine, an
//     unlucky one hangs 5 min). This was tried on znas3 and reverted.
//
//  2. udev's ifupdown-hotplug starts ifup@<dev>.service in parallel with
//     networking.service's `ifup -a`; both race for /run/network/ifstate.<dev>.
//     Mask ifup@.service so networking.service is the single bring-up path.
//
// Both actions are undone by rollbackNetworkd. Best-effort: failures are logged
// but do not abort the migration.
func hardenIfupdownBoot(log func(string)) {
	log("Neutralizing the systemd-resolved ifup hook (it calls resolvectl over D-Bus and hangs boot; static /etc/resolv.conf already provides DNS)…")
	if out, err := exec.Command("sudo", "/usr/bin/chmod", "-x", resolvedIfupHook).CombinedOutput(); err != nil {
		log("  ⚠ chmod -x " + resolvedIfupHook + ": " + strings.TrimSpace(string(out)))
	}

	log("Masking ifup@.service so networking.service is the sole interface bring-up (avoids the udev ifup lock race)…")
	if out, err := exec.Command("sudo", "/usr/bin/systemctl", "mask", "ifup@.service").CombinedOutput(); err != nil {
		log("  ⚠ mask ifup@.service: " + strings.TrimSpace(string(out)))
	}
}

func rollbackNetworkd() {
	undoIfupdownHardening()

	// Undo the masks first — a masked unit can't be enabled or started.
	for _, u := range []string{"systemd-networkd.service", "systemd-networkd-wait-online.service"} {
		exec.Command("sudo", "/usr/bin/systemctl", "unmask", u).Run() //nolint:errcheck
	}
	for _, u := range []string{
		"systemd-networkd-resolve-hook.socket",
		"systemd-networkd-varlink.socket",
		"systemd-networkd.socket",
		"systemd-networkd.service",
	} {
		exec.Command("sudo", "/usr/bin/systemctl", "enable", u).Run() //nolint:errcheck
		exec.Command("sudo", "/usr/bin/systemctl", "start", u).Run()  //nolint:errcheck
	}
	// Re-enable wait-online so the restored networkd setup behaves normally on
	// the next boot, but do NOT start it now — starting it would block on the
	// online-wait for up to its timeout during an already-failed migration.
	exec.Command("sudo", "/usr/bin/systemctl", "enable", "systemd-networkd-wait-online.service").Run() //nolint:errcheck
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
