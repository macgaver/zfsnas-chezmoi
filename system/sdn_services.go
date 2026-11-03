package system

// Phase 4 services (spec §11.2, §11.3). DNS is one dnsmasq of its own
// (znas-sdn-dns.service); DHCP is one dnsmasq per network, run by the
// supervisor in sdn_dhcpd.go (znas-sdn-dhcp.service). Both keep running
// when the portal restarts. WireGuard tunnels are ifupdown stanzas
// (sdn.RenderOwned) whose keys live in /etc/wireguard/znas-<id>.conf.

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"zfsnas/internal/sdn"
)

const sdnDNSUnitName = "znas-sdn-dns.service"

var (
	sdnDnsmasqConf = "/etc/znas-sdn/dnsmasq.conf" // the DNS server
	sdnWGDir       = sdn.WGConfDir
	// sdnLegacyLeasePath: the lease file of the single DHCP+DNS server of
	// earlier versions; the DHCP supervisor hands its leases to each network.
	sdnLegacyLeasePath = func() string {
		if ApplianceMode() {
			return "/run/znas-sdn-dns/leases"
		}
		return "/var/lib/misc/znas-sdn.leases"
	}()
)

var (
	// sdnQueryLog: every DNS query, with advanced metrics on (RAM; rotated
	// by the DHCP supervisor, read by the portal).
	sdnQueryLog = "/run/znas-sdn-dns/queries.log"
	// sdnBlocklistFile: the blocklists and blocked domains, as a hosts file.
	sdnBlocklistFile = "/var/lib/znas-sdn/blocklist.hosts"
)

func sdnDNSPaths() sdn.DNSPaths {
	return sdn.DNSPaths{HostsDir: sdnHostsDir, QueryLog: sdnQueryLog, Blocklist: sdnBlocklistFile}
}

func sdnDNSUnitPath() string { return filepath.Join(filepath.Dir(sdnUnitPath), sdnDNSUnitName) }

func sdnDnsmasqBinary() string {
	for _, p := range []string{"/usr/sbin/dnsmasq", "/usr/bin/dnsmasq"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/usr/sbin/dnsmasq"
}

// sdnDNSUnitText: inert until the Firewall writes a DNS config. The hosts.d
// folder holds each network's DHCP names (written by the DHCP supervisor).
func sdnDNSUnitText() string {
	bin := sdnDnsmasqBinary()
	return fmt.Sprintf(`[Unit]
Description=ZNAS Firewall — DNS (dnsmasq)
After=znas-sdn.service network.target
ConditionPathExists=%[1]s

[Service]
Type=simple
RuntimeDirectory=znas-sdn-dns znas-sdn-dns/hosts.d
RuntimeDirectoryPreserve=yes
ExecStartPre=%[2]s --test --conf-file=%[1]s
ExecStart=%[2]s --keep-in-foreground --conf-file=%[1]s --pid-file=/run/znas-sdn-dns/dnsmasq.pid
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`, sdnDnsmasqConf, bin)
}

// SDNDnsmasqInstalled / SDNWireGuardInstalled: the runtime tools.
func SDNDnsmasqInstalled() bool {
	return binaryPresent("/usr/sbin/dnsmasq") || binaryPresent("dnsmasq")
}
func SDNWireGuardInstalled() bool { return binaryPresent("/usr/bin/wg") || binaryPresent("wg") }

// sdnSvcChanged says which DHCP/DNS configs an apply changed.
type sdnSvcChanged struct {
	DNS  bool // the DNS server's config
	DHCP bool // any network's DHCP config
}

// sdnServiceFiles writes the DNS config and each network's DHCP config
// (each removed when it serves nothing), and the tunnels' key files. Key
// files of tunnels that are gone are removed: those of prev by name (a
// non-root portal cannot list the 0700 /etc/wireguard), any other stale
// znas-* file when the directory is readable. Returns which DHCP/DNS
// configs changed and the tunnels whose key file changed.
func sdnServiceFiles(prev, c *sdn.Config) (chg sdnSvcChanged, wgChanged []string, err error) {
	if chg.DNS, err = sdnSyncFile(sdnDnsmasqConf, sdn.RenderDNS(c, sdnDNSPaths())); err != nil {
		return chg, nil, err
	}
	want := sdn.RenderDHCP(c, sdnLeaseDir)
	for id, text := range want {
		changed, err := sdnSyncFile(filepath.Join(sdnDHCPDir, id+".conf"), text)
		if err != nil {
			return chg, nil, err
		}
		chg.DHCP = chg.DHCP || changed
	}
	stale := map[string]bool{}
	if prev != nil {
		for _, d := range prev.DHCP {
			stale[d.Interface] = true
		}
	}
	if ents, err := os.ReadDir(sdnDHCPDir); err == nil {
		for _, e := range ents {
			if id, ok := strings.CutSuffix(e.Name(), ".conf"); ok {
				stale[id] = true
			}
		}
	}
	for id := range stale {
		if _, ok := want[id]; ok {
			continue
		}
		p := filepath.Join(sdnDHCPDir, id+".conf")
		if _, err := os.Stat(p); err == nil {
			if err := sdnRemoveFile(p); err != nil {
				return chg, nil, err
			}
			chg.DHCP = true
		}
	}

	keep := map[string]bool{}
	for _, in := range c.Interfaces {
		if in.Kind != "wireguard" {
			continue
		}
		keep[filepath.Base(sdnWGPath(in.ID))] = true
		changed, err := sdnWGFile(c, in.ID)
		if err != nil {
			return chg, wgChanged, err
		}
		if changed {
			wgChanged = append(wgChanged, in.ID)
		}
	}
	if prev != nil {
		for _, in := range prev.Interfaces {
			if in.Kind == "wireguard" && !keep[filepath.Base(sdnWGPath(in.ID))] {
				sdnRemoveFile(sdnWGPath(in.ID)) //nolint:errcheck — may be gone already
			}
		}
	}
	if ents, err := os.ReadDir(sdnWGDir); err == nil {
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "znas-") && strings.HasSuffix(e.Name(), ".conf") && !keep[e.Name()] {
				sdnRemoveFile(filepath.Join(sdnWGDir, e.Name())) //nolint:errcheck
			}
		}
	}
	return chg, wgChanged, nil
}

// sdnWGFile writes a tunnel's key file when it differs.
func sdnWGFile(c *sdn.Config, id string) (bool, error) {
	p := sdnWGPath(id)
	text := sdn.WGConf(c, id)
	old, rerr := os.ReadFile(p)
	if rerr != nil && !os.IsNotExist(rerr) {
		old, _ = sdnRun.Run(nil, "cat", p) // 0600 root: sudo cat
	}
	if string(old) == text {
		return false, nil
	}
	if err := os.MkdirAll(sdnWGDir, 0700); err != nil {
		sdnRun.Run(nil, "mkdir", "-p", "-m", "700", sdnWGDir) //nolint:errcheck
	}
	return true, sdnWriteSecret(p, []byte(text))
}

// sdnSyncFile writes text to path when it differs, or removes the file
// when text is "". Returns whether the file changed.
func sdnSyncFile(path, text string) (bool, error) {
	cur, rerr := os.ReadFile(path)
	switch {
	case text == "" && rerr == nil:
		return true, sdnRemoveFile(path)
	case text == "" || (rerr == nil && string(cur) == text):
		return false, nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		sdnRun.Run(nil, "mkdir", "-p", dir) //nolint:errcheck
	}
	return true, sdnWriteFile(path, []byte(text))
}

func sdnWGPath(id string) string { return filepath.Join(sdnWGDir, filepath.Base(sdn.WGConfPath(id))) }

// sdnApplyServices runs after the ruleset is loaded: the DNS server
// restarted when its config changed (stopped when gone); the DHCP
// supervisor told to pick up changed networks (it restarts only those);
// tunnels that were not just brought up get their new peers with
// `wg syncconf` (no bounce, sessions kept).
func sdnApplyServices(c *sdn.Config, chg sdnSvcChanged, wgChanged []string, broughtUp map[string]bool, res *SDNApplyResult) {
	if _, err := os.Stat(sdnDnsmasqConf); err == nil {
		active, _ := sdnRun.Run(nil, "systemctl", "is-active", sdnDNSUnitName)
		if chg.DNS || strings.TrimSpace(string(active)) != "active" {
			if _, err := sdnRun.Run(nil, "systemctl", "restart", sdnDNSUnitName); err != nil {
				res.Warnings = append(res.Warnings, "DNS did not start: "+err.Error())
			}
		}
	} else if chg.DNS {
		sdnRun.Run(nil, "systemctl", "stop", sdnDNSUnitName) //nolint:errcheck
	}
	want := sdn.RenderDHCP(c, sdnLeaseDir)
	if len(want) > 0 || chg.DHCP {
		active, _ := sdnRun.Run(nil, "systemctl", "is-active", sdnDHCPUnitName)
		switch {
		case strings.TrimSpace(string(active)) != "active":
			if _, err := sdnRun.Run(nil, "systemctl", "restart", sdnDHCPUnitName); err != nil {
				res.Warnings = append(res.Warnings, "DHCP did not start: "+err.Error())
			}
		case chg.DHCP:
			sdnRun.Run(nil, "systemctl", "reload", sdnDHCPUnitName) //nolint:errcheck — it also looks every 2 s
		}
	}
	if chg.DHCP && len(want) > 0 {
		sdnWaitDHCP(c, want, res)
	}
	for _, id := range wgChanged {
		in := c.InterfaceByID(id)
		if in == nil || broughtUp[in.Device] {
			continue
		}
		if _, err := sdnRun.Run(nil, "wg", "syncconf", in.Device, sdnWGPath(id)); err != nil {
			res.Warnings = append(res.Warnings, in.Name+": "+err.Error())
		}
	}
}

// sdnDHCPWait: how long an apply waits for the networks' DHCP servers.
var sdnDHCPWait = 6 * time.Second

// sdnWaitDHCP reports the networks whose DHCP server did not start.
func sdnWaitDHCP(c *sdn.Config, want map[string]string, res *SDNApplyResult) {
	deadline := time.Now().Add(sdnDHCPWait)
	for {
		st, _ := SDNDHCPStatus()
		bad := map[string]string{}
		for id := range want {
			if n, ok := st[id]; !ok || !n.Running || n.Error != "" {
				bad[id] = n.Error
			}
		}
		if len(bad) == 0 {
			return
		}
		if !time.Now().Before(deadline) {
			for id, e := range bad {
				name := id
				if in := c.InterfaceByID(id); in != nil {
					name = in.Name
				}
				if e == "" {
					e = "not started yet"
				}
				res.Warnings = append(res.Warnings, "DHCP on "+name+": "+e)
			}
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// sdnHostAddrs: the IPv4 networks on every device of this server.
var sdnHostAddrs = func() map[string][]string {
	m := map[string][]string{}
	ifs, _ := net.Interfaces()
	for _, it := range ifs {
		addrs, _ := it.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() {
				m[it.Name] = append(m[it.Name], p.String())
			}
		}
	}
	return m
}

// sdnHostNetConflicts: a network the Firewall creates (VLAN, tunnel) must
// not overlap one already on a device it does not manage — an Incus bridge,
// Docker, a hand-made interface — or routing breaks for both. Only new or
// re-addressed networks are judged: going back to a running configuration
// (rollback, revert) is never refused.
func sdnHostNetConflicts(prev, next *sdn.Config) error {
	mine := map[string]bool{}
	for _, in := range next.Interfaces {
		mine[in.Device], mine[in.L3Device()] = true, true
	}
	host := sdnHostAddrs()
	for _, in := range next.Interfaces {
		if !in.Owned || in.IPv4Mode != "static" || in.Disabled {
			continue
		}
		if prev != nil {
			if old := prev.InterfaceByID(in.ID); old != nil && old.IPv4Mode == "static" && old.IPv4 == in.IPv4 {
				continue
			}
		}
		want, err := netip.ParsePrefix(in.IPv4)
		if err != nil {
			continue
		}
		for dev, addrs := range host {
			if mine[dev] {
				continue
			}
			for _, a := range addrs {
				if p, err := netip.ParsePrefix(a); err == nil && p.Masked().Overlaps(want.Masked()) {
					return fmt.Errorf("%s: network %s is already used by %s on this server (%s) — choose another one", in.Name, want.Masked(), dev, a)
				}
			}
		}
	}
	return nil
}

// ── live data ──

// SDNLease is one DHCP lease.
type SDNLease struct {
	Interface string    `json:"interface"` // interface id ("" = outside every network)
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	Expires   time.Time `json:"expires"` // zero = infinite (reservation)
}

// SDNDHCPLeases reads every network's lease file (and the single file of
// earlier versions, until the DHCP supervisor has carried it over).
func SDNDHCPLeases(c *sdn.Config) []SDNLease {
	var b []byte
	var paths []string
	for _, d := range c.DHCP {
		paths = append(paths, sdn.DHCPLeaseFile(sdnLeaseDir, d.Interface))
	}
	paths = append(paths, sdnLegacyLeasePath)
	for _, p := range paths {
		if x, err := os.ReadFile(p); err == nil {
			b = append(b, x...)
		}
	}
	out := []SDNLease{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		l := SDNLease{MAC: f[1], IP: f[2]}
		if f[3] != "*" {
			l.Hostname = f[3]
		}
		if n, err := strconv.ParseInt(f[0], 10, 64); err == nil && n > 0 {
			l.Expires = time.Unix(n, 0)
		}
		if ip, err := netip.ParseAddr(l.IP); err == nil {
			for _, in := range c.Interfaces {
				if pfx, err := netip.ParsePrefix(in.IPv4); err == nil && in.IPv4Mode == "static" && pfx.Masked().Contains(ip) {
					l.Interface = in.ID
				}
			}
		}
		out = append(out, l)
	}
	return out
}

// SDNWGPeerStatus is one peer as the kernel sees it.
type SDNWGPeerStatus struct {
	PublicKey     string    `json:"public_key"`
	Endpoint      string    `json:"endpoint"`
	LastHandshake time.Time `json:"last_handshake"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	Country       string    `json:"country,omitempty"`
}

// parseWGDump reads `wg show <dev> dump` (first line = the interface).
func parseWGDump(s string) []SDNWGPeerStatus {
	var out []SDNWGPeerStatus
	for i, line := range strings.Split(strings.TrimSpace(s), "\n") {
		f := strings.Split(line, "\t")
		if i == 0 || len(f) < 8 {
			continue
		}
		p := SDNWGPeerStatus{PublicKey: f[0]}
		if f[2] != "(none)" {
			p.Endpoint = f[2]
		}
		if n, _ := strconv.ParseInt(f[4], 10, 64); n > 0 {
			p.LastHandshake = time.Unix(n, 0)
		}
		p.RxBytes, _ = strconv.ParseInt(f[5], 10, 64)
		p.TxBytes, _ = strconv.ParseInt(f[6], 10, 64)
		out = append(out, p)
	}
	return out
}

// SDNWireGuardStatus: per tunnel id, its peers' live state ("up" false when
// the device does not exist).
type SDNWGTunnelStatus struct {
	Up    bool              `json:"up"`
	Peers []SDNWGPeerStatus `json:"peers"`
	Heal  *SDNHealTunnel    `json:"heal,omitempty"` // what the monitor is doing about it
}

func SDNWireGuardStatus(c *sdn.Config) map[string]SDNWGTunnelStatus {
	out := map[string]SDNWGTunnelStatus{}
	heal := SDNHealStatus()
	for _, in := range c.Interfaces {
		if in.Kind != "wireguard" {
			continue
		}
		var hs *SDNHealTunnel
		if t, ok := heal.Tunnels[in.ID]; ok {
			hs = &t
		}
		b, err := sdnRun.Run(nil, "wg", "show", in.Device, "dump")
		if err != nil {
			out[in.ID] = SDNWGTunnelStatus{Peers: []SDNWGPeerStatus{}, Heal: hs}
			continue
		}
		peers := parseWGDump(string(b))
		for i := range peers {
			if host, _, ok := strings.Cut(peers[i].Endpoint, ":"); ok {
				if ip, err := netip.ParseAddr(host); err == nil {
					peers[i].Country = SDNGeo().Lookup(ip).CountryCode
				}
			}
		}
		if peers == nil {
			peers = []SDNWGPeerStatus{}
		}
		// The device can exist with its link down (a failed ifup leaves it so).
		known, up := sdnLinkFlags(in.Device)
		out[in.ID] = SDNWGTunnelStatus{Up: !known || up, Peers: peers, Heal: hs}
	}
	return out
}

// SDNServicesStatus: tools present, the DNS server running, and each
// network's DHCP server.
func SDNServicesStatus() map[string]any {
	active, _ := sdnRun.Run(nil, "systemctl", "is-active", sdnDNSUnitName)
	dhcp, _ := SDNDHCPStatus()
	return map[string]any{
		"dnsmasq_installed":   SDNDnsmasqInstalled(),
		"wireguard_installed": SDNWireGuardInstalled(),
		"dns_running":         strings.TrimSpace(string(active)) == "active",
		"dns_configured":      fileExists(sdnDnsmasqConf),
		"dhcp":                dhcp,
	}
}
