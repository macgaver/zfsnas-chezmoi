package sdn

// Intrusion detection (spec §11.4): Suricata in IDS (alert-only) mode on the
// chosen interfaces, with free rule sets only. Alerts go to the portal over
// a datagram socket (nothing written to disk by Suricata).

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

type IDSSettings struct {
	Enabled    bool     `json:"enabled"`
	Interfaces []string `json:"interfaces"` // interface ids; none = every WAN
	// Sources: free rule sets added to ET Open (always on), by their
	// suricata-update names.
	Sources []string `json:"sources"`
	// Categories: ET Open rule groups (file names without .rules) enabled.
	Categories []string `json:"categories"`
	// AlertSeverity: a ZNAS alert for IDS alerts of severity ≤ N
	// (1 = high … 3 = low); 0 = never.
	AlertSeverity int           `json:"alert_severity"`
	Suppressed    []IDSSuppress `json:"suppressed"`
}

// IDSSuppress silences a signature, everywhere or for one address.
type IDSSuppress struct {
	SID  int    `json:"sid"`
	IP   string `json:"ip,omitempty"`
	Note string `json:"note,omitempty"`
}

// IDSSource is a free rule set offered in the UI.
type IDSSource struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
	Default bool   `json:"default"`
}

// IDSSources: the free, non-obsolete sets of the suricata-update index.
// ET Open is always on. (ThreatFox is not in the index.)
var IDSSources = []IDSSource{
	{"abuse.ch/sslbl-blacklist", "abuse.ch SSL certificate blacklist (malware and botnet TLS certificates)", true},
	{"abuse.ch/sslbl-c2", "abuse.ch botnet C2 IP list (SSL IP blacklist)", true},
	{"abuse.ch/feodotracker", "abuse.ch Feodo Tracker botnet C2 IPs", false},
	{"abuse.ch/urlhaus", "abuse.ch URLhaus malware download URLs", false},
	{"abuse.ch/sslbl-ja3", "abuse.ch malicious TLS client fingerprints (JA3)", false},
	{"etnetera/aggressive", "Etnetera aggressive IP blacklist", false},
	{"oisf/trafficid", "Suricata traffic identification (applications)", false},
	{"tgreen/hunting", "Threat hunting rules (noisy)", false},
	{"stamus/lateral", "Lateral movement inside the network", false},
	{"aleksibovellan/nmap", "Nmap scans", false},
	{"ptrules/open", "Positive Technologies open rules", false},
	{"pawpatrules", "PAW Patrules", false},
	{"ipfire/dbl", "IPFire domain blocklist", false},
	{"julioliraup/antiphishing", "Phishing domains", false},
	{"echap/stalkerware", "Stalkerware", false},
}

// IDSDefaultCategories: the owner's OPNsense selection.
var IDSDefaultCategories = []string{"emerging-exploit", "emerging-malware", "compromised", "drop", "botcc"}

var idsGroupRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// IDSGroupNameOK: a rule category name (lowercase file name, no path).
func IDSGroupNameOK(s string) bool { return idsGroupRe.MatchString(s) }

func (c *Config) normalizeIDS() {
	s := &c.IDS
	if s.Interfaces == nil {
		s.Interfaces = []string{}
	}
	if s.Sources == nil {
		for _, src := range IDSSources {
			if src.Default {
				s.Sources = append(s.Sources, src.Name)
			}
		}
	}
	if s.Categories == nil {
		s.Categories = append([]string{}, IDSDefaultCategories...)
	}
	if s.Suppressed == nil {
		s.Suppressed = []IDSSuppress{}
	}
}

// IDSDevices: the kernel devices Suricata listens on.
func (c *Config) IDSDevices() []string {
	ids := c.IDS.Interfaces
	if len(ids) == 0 {
		for _, in := range c.Interfaces {
			if in.Role == "wan" {
				ids = append(ids, in.ID)
			}
		}
	}
	var out []string
	for _, id := range ids {
		if in := c.InterfaceByID(id); in != nil && !in.Disabled {
			out = append(out, in.L3Device())
		}
	}
	sort.Strings(out)
	return out
}

// IDSRuns: on, with something to watch — all its interfaces may be disabled.
func (c *Config) IDSRuns() bool { return c.IDS.Enabled && len(c.IDSDevices()) > 0 }

func (c *Config) validateIDS(add func(path, format string, a ...any)) {
	s := c.IDS
	missing := false
	for _, id := range s.Interfaces {
		if c.InterfaceByID(id) == nil {
			add("ids.interfaces", "a watched interface no longer exists")
			missing = true
			break
		}
	}
	watched := len(s.Interfaces) > 0
	for _, in := range c.Interfaces {
		watched = watched || in.Role == "wan" // a disabled one counts: it comes back
	}
	if s.Enabled && !missing && !watched {
		add("ids.interfaces", "choose the interfaces to watch (there is no WAN to default to)")
	}
	known := map[string]bool{}
	for _, src := range IDSSources {
		known[src.Name] = true
	}
	for _, src := range s.Sources {
		if !known[src] {
			add("ids.sources", "%q is not one of the free rule sets", src)
			break
		}
	}
	for _, g := range s.Categories {
		if !idsGroupRe.MatchString(g) {
			add("ids.categories", "%q is not a rule category name", g)
			break
		}
	}
	if s.AlertSeverity < 0 || s.AlertSeverity > 3 {
		add("ids.alert_severity", "severity must be 0 (never) to 3")
	}
	for i, sp := range s.Suppressed {
		p := fmt.Sprintf("ids.suppressed[%d]", i)
		if sp.SID <= 0 {
			add(p+".sid", "invalid signature id")
		} else if sp.IP != "" && !ipv4OK(sp.IP) {
			add(p+".ip", "%q is not an IPv4 address", sp.IP)
		}
	}
}

// IDSPaths are the files the Suricata configuration points at.
type IDSPaths struct {
	RulesDir, LogDir, Socket, Threshold string
}

// RenderSuricataYAML is a complete, minimal Suricata configuration: our
// address groups, af-packet on the watched devices, alert-only EVE to the
// portal's socket, no stats or other log files.
func RenderSuricataYAML(c *Config, p IDSPaths) string {
	var home []string
	seen := map[string]bool{}
	for _, in := range c.Interfaces {
		if in.Role == "wan" || in.IPv4Mode != "static" {
			continue
		}
		if pfx, err := netip.ParsePrefix(in.IPv4); err == nil && !seen[pfx.Masked().String()] {
			seen[pfx.Masked().String()] = true
			home = append(home, pfx.Masked().String())
		}
	}
	for _, peer := range c.WGPeers {
		for _, a := range peer.AllowedIPs {
			if pfx, err := netip.ParsePrefix(a); err == nil && pfx.Bits() < 32 && !seen[pfx.Masked().String()] {
				seen[pfx.Masked().String()] = true
				home = append(home, pfx.Masked().String())
			}
		}
	}
	if len(home) == 0 {
		home = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	}
	var b strings.Builder
	b.WriteString("%YAML 1.1\n---\n# Managed by ZNAS Firewall — rewritten on every apply and at boot.\n")
	fmt.Fprintf(&b, "vars:\n  address-groups:\n    HOME_NET: \"[%s]\"\n    EXTERNAL_NET: \"!$HOME_NET\"\n", strings.Join(home, ","))
	for _, g := range []string{"HTTP_SERVERS", "SMTP_SERVERS", "SQL_SERVERS", "DNS_SERVERS", "TELNET_SERVERS", "DC_SERVERS",
		"DNP3_SERVER", "DNP3_CLIENT", "MODBUS_CLIENT", "MODBUS_SERVER", "ENIP_CLIENT", "ENIP_SERVER"} {
		fmt.Fprintf(&b, "    %s: \"$HOME_NET\"\n", g)
	}
	b.WriteString("    AIM_SERVERS: \"$EXTERNAL_NET\"\n")
	b.WriteString(`  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544
`)
	fmt.Fprintf(&b, "default-log-dir: %s\nstats:\n  enabled: no\n", p.LogDir)
	fmt.Fprintf(&b, `outputs:
  - eve-log:
      enabled: yes
      filetype: unix_dgram
      filename: %s
      types:
        - alert:
            tagged-packets: no
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
af-packet:
`, p.Socket)
	for i, dev := range c.IDSDevices() {
		fmt.Fprintf(&b, "  - interface: %s\n    cluster-id: %d\n    cluster-type: cluster_flow\n    defrag: yes\n    tpacket-v3: yes\n", dev, 99-i)
	}
	b.WriteString(`app-layer:
  protocols:
    http:
      enabled: yes
    tls:
      enabled: yes
    dns:
      tcp:
        enabled: yes
      udp:
        enabled: yes
`)
	fmt.Fprintf(&b, "default-rule-path: %s\nrule-files:\n  - suricata.rules\n", p.RulesDir)
	fmt.Fprintf(&b, "classification-file: %s/classification.config\nreference-config-file: /etc/suricata/reference.config\nthreshold-file: %s\n", p.RulesDir, p.Threshold)
	return b.String()
}

// RenderThreshold: one suppress line per silenced signature.
func RenderThreshold(c *Config) string {
	var b strings.Builder
	b.WriteString("# Managed by ZNAS Firewall\n")
	for _, s := range c.IDS.Suppressed {
		if s.IP != "" {
			fmt.Fprintf(&b, "suppress gen_id 1, sig_id %d, track by_either, ip %s\n", s.SID, s.IP)
		} else {
			fmt.Fprintf(&b, "suppress gen_id 1, sig_id %d\n", s.SID)
		}
	}
	return b.String()
}

// RenderDisableConf: suricata-update's disable.conf turning off every ET
// Open group not chosen (groups = what the ET tarball holds). Disabling is
// used rather than enabling, which would also switch on the rules ET ships
// disabled.
func RenderDisableConf(c *Config, groups []string) string {
	on := map[string]bool{}
	for _, g := range c.IDS.Categories {
		on[g] = true
	}
	var b strings.Builder
	b.WriteString("# Managed by ZNAS Firewall: ET Open groups not chosen\n")
	sorted := append([]string{}, groups...)
	sort.Strings(sorted)
	for _, g := range sorted {
		if !on[g] {
			fmt.Fprintf(&b, "group:%s\n", g)
		}
	}
	return b.String()
}

func summarizeIDS(prev, next *Config) []string {
	switch {
	case prev.IDS.Enabled != next.IDS.Enabled:
		return []string{map[bool]string{true: "intrusion detection on", false: "intrusion detection off"}[next.IDS.Enabled]}
	case !same(prev.IDS, next.IDS):
		return []string{"intrusion detection edited"}
	}
	return nil
}
