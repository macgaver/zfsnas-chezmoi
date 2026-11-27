package sdn

// Auto groups (6.11.27): address lists the Firewall maintains by itself and
// rules can use as a source or destination, like a host group.
//
//   - Firewall lists: the reputation lists downloaded daily with the
//     location database (Spamhaus DROP, FireHOL level 1, Tor exit nodes).
//   - IDS lists: the address lists inside the active IDS rules (ET Open
//     CINS, DShield, Compromised hosts, Feodo, Tor…), as far as the IDS
//     has them enabled.
//
// They compile to nft interval sets named a_<id>. A list that is not
// available compiles to an EMPTY set — it matches nothing — so a missing
// list never stops the firewall from applying. Private and reserved ranges
// are always removed (FireHOL level 1 lists 10.0.0.0/8, 192.168.0.0/16…),
// and an auto group cannot be inverted ("everything except"): with a list
// that changes daily, or can be empty, that could open everything.

import (
	"bufio"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// AutoGroupDef is one entry of the catalog.
type AutoGroupDef struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Source string `json:"source"` // "firewall" | "ids"
	About  string `json:"about"`
	// Use: "from" — addresses that attack (use as source on WAN rules);
	// "to" — servers inside never need to reach (use as destination).
	Use string `json:"use"`
	// RepList: id of the downloaded firewall list (Source firewall).
	RepList string `json:"-"`
	// MsgRe: matches the msg of the IDS rules carrying this list.
	MsgRe *regexp.Regexp `json:"-"`
}

// AutoGroupCatalog lists every auto group ZNAS knows, in display order.
var AutoGroupCatalog = []AutoGroupDef{
	{ID: "fw-spamhaus-drop", Name: "Spamhaus DROP", Source: "firewall", Use: "from", RepList: "spamhaus-drop",
		About: "Address blocks hijacked or leased by spammers and cyber-criminals. No legitimate traffic comes from them."},
	{ID: "fw-firehol-level1", Name: "FireHOL level 1", Source: "firewall", Use: "from", RepList: "firehol-level1",
		About: "Several lists merged: attacks, malware, botnet control servers and hijacked blocks seen in the last days."},
	{ID: "fw-tor-exit", Name: "Tor exit nodes", Source: "firewall", Use: "from", RepList: "tor-exit",
		About: "Exit points of the Tor network: the real sender is hidden behind them."},

	{ID: "ids-et-compromised", Name: "Compromised hosts", Source: "ids", Use: "from", MsgRe: regexp.MustCompile(`^ET COMPROMISED `),
		About: "Hosts known to be compromised or hostile (ET Open, category compromised)."},
	{ID: "ids-et-drop", Name: "Spamhaus DROP (IDS)", Source: "ids", Use: "from", MsgRe: regexp.MustCompile(`^ET DROP Spamhaus`),
		About: "Spamhaus DROP as shipped in the IDS rules (ET Open, category drop)."},
	{ID: "ids-et-dshield", Name: "DShield top attackers", Source: "ids", Use: "from", MsgRe: regexp.MustCompile(`^ET DROP Dshield`),
		About: "Networks the SANS Internet Storm Center sees attacking the most (ET Open, category dshield)."},
	{ID: "ids-et-cins", Name: "CINS Army bad actors", Source: "ids", Use: "from", MsgRe: regexp.MustCompile(`^ET CINS `),
		About: "Addresses with a poor reputation in the CINS Army threat feed (ET Open, category ciarmy)."},
	{ID: "ids-et-tor-exit", Name: "Tor exit nodes (IDS)", Source: "ids", Use: "from", MsgRe: regexp.MustCompile(`^ET TOR Known Tor Exit`),
		About: "Tor exit nodes as shipped in the IDS rules (ET Open, category tor)."},
	{ID: "ids-et-tor-relay", Name: "Tor relays", Source: "ids", Use: "from", MsgRe: regexp.MustCompile(`^ET TOR Known Tor Relay`),
		About: "Tor relays that are not exits (ET Open, category tor)."},
	{ID: "ids-et-feodo", Name: "Botnet control servers (Feodo)", Source: "ids", Use: "to", MsgRe: regexp.MustCompile(`^ET CNC Feodo`),
		About: "Command servers of banking-trojan botnets: nothing inside should talk to them (ET Open, category botcc)."},
	{ID: "ids-threatview-c2", Name: "Cobalt Strike servers", Source: "ids", Use: "to", MsgRe: regexp.MustCompile(`^ET Threatview\.io .*C2`),
		About: "High-confidence Cobalt Strike command servers from Threatview.io (ET Open)."},
	{ID: "ids-etn-aggressive", Name: "Etnetera aggressive IPs", Source: "ids", Use: "from", MsgRe: regexp.MustCompile(`^ETN AGGRESSIVE`),
		About: "Addresses seen attacking by Etnetera's honeypots (IDS source etnetera/aggressive)."},
	{ID: "ids-abuse-feodo", Name: "abuse.ch Feodo Tracker", Source: "ids", Use: "to", MsgRe: regexp.MustCompile(`^Feodo Tracker:`),
		About: "Botnet command servers from abuse.ch Feodo Tracker (IDS source abuse.ch/feodotracker)."},
	{ID: "ids-abuse-sslbl", Name: "abuse.ch botnet C2 (SSL)", Source: "ids", Use: "to", MsgRe: regexp.MustCompile(`^SSLBL`),
		About: "Botnet command servers seen on TLS by abuse.ch (IDS source abuse.ch/sslbl-c2)."},
}

// AutoGroupByID returns the catalog entry, or nil.
func AutoGroupByID(id string) *AutoGroupDef {
	for i := range AutoGroupCatalog {
		if AutoGroupCatalog[i].ID == id {
			return &AutoGroupCatalog[i]
		}
	}
	return nil
}

// AutoSetName is the nft set of an auto group.
func AutoSetName(id string) string {
	var b strings.Builder
	b.WriteString("a_")
	for _, r := range id {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// reservedNets never belong in an auto group: blocking them would cut the
// local networks off (FireHOL level 1 lists most of them as "bogons").
var reservedNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/3"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// CleanAutoCIDRs drops reserved ranges and duplicates, removes networks
// already covered by a larger one, and returns them sorted.
func CleanAutoCIDRs(in []netip.Prefix) []string {
	var keep []netip.Prefix
	for _, p := range in {
		if !p.IsValid() || !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		bad := false
		for _, r := range reservedNets {
			if r.Overlaps(p) {
				bad = true
				break
			}
		}
		if !bad {
			keep = append(keep, p)
		}
	}
	// Larger networks first at equal start, so a covered one follows its cover.
	sort.Slice(keep, func(i, j int) bool {
		if c := keep[i].Addr().Compare(keep[j].Addr()); c != 0 {
			return c < 0
		}
		return keep[i].Bits() < keep[j].Bits()
	})
	out := make([]string, 0, len(keep))
	var last netip.Prefix
	for _, p := range keep {
		if last.IsValid() && last.Contains(p.Addr()) && last.Bits() <= p.Bits() {
			continue // duplicate, or inside the previous network
		}
		last = p
		if p.Bits() == 32 {
			out = append(out, p.Addr().String())
		} else {
			out = append(out, p.String())
		}
	}
	return out
}

var (
	idsMsgRe  = regexp.MustCompile(`msg:"([^"]*)"`)
	idsListRe = regexp.MustCompile(`\[([0-9][0-9./,]*)\]`)
)

// ParseIDSAutoLists reads a Suricata rule file and returns, per catalog
// IDS group, the addresses of its ENABLED rules (lines starting with
// "alert"; suricata-update comments disabled ones out).
func ParseIDSAutoLists(r io.Reader) map[string][]netip.Prefix {
	out := map[string][]netip.Prefix{}
	var defs []*AutoGroupDef
	for i := range AutoGroupCatalog {
		if AutoGroupCatalog[i].MsgRe != nil {
			defs = append(defs, &AutoGroupCatalog[i])
		}
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 256<<10), 4<<20)
	for sc.Scan() {
		l := sc.Text()
		if !strings.HasPrefix(l, "alert ") {
			continue
		}
		m := idsMsgRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		var def *AutoGroupDef
		for _, d := range defs {
			if d.MsgRe.MatchString(m[1]) {
				def = d
				break
			}
		}
		if def == nil {
			continue
		}
		// Only the header (before the options) holds the address list.
		head := l
		if i := strings.IndexByte(l, '('); i > 0 {
			head = l[:i]
		}
		lm := idsListRe.FindStringSubmatch(head)
		if lm == nil {
			continue
		}
		for _, s := range strings.Split(lm[1], ",") {
			s = strings.TrimSpace(s)
			if p, err := netip.ParsePrefix(s); err == nil {
				out[def.ID] = append(out[def.ID], p)
			} else if a, err := netip.ParseAddr(s); err == nil {
				out[def.ID] = append(out[def.ID], netip.PrefixFrom(a, 32))
			}
		}
	}
	return out
}

// usedAutoGroups lists, in first-use order, the auto groups enabled rules,
// port forwards and outbound NAT rules use.
func (c *Config) usedAutoGroups() []string {
	var out []string
	seen := map[string]bool{}
	add := func(e Endpoint) {
		if e.Type == "auto" && !seen[e.Value] {
			seen[e.Value] = true
			out = append(out, e.Value)
		}
	}
	for _, r := range c.Rules {
		if r.Enabled {
			add(r.Source)
			add(r.Destination)
		}
	}
	for _, f := range c.PortForwards {
		if f.Enabled && !f.Paused() {
			add(f.Source)
		}
	}
	for _, r := range c.SNATRules {
		if r.Enabled {
			add(r.Source)
			add(r.Destination)
		}
	}
	return out
}

// UsedAutoGroups is usedAutoGroups for callers outside the package
// (boot cache, daily set refresh).
func (c *Config) UsedAutoGroups() []string { return c.usedAutoGroups() }

// writeAutoSets declares one interval set per used auto group. A list the
// environment cannot provide is declared empty: it matches nothing.
func writeAutoSets(b *strings.Builder, c *Config, env Env) {
	for _, id := range c.usedAutoGroups() {
		var elems []string
		if env.AutoGroupCIDRs != nil {
			if v, err := env.AutoGroupCIDRs(id); err == nil {
				elems = v
			}
		}
		b.WriteString(AutoSetDecl(id, elems))
	}
}

// AutoSetDecl renders the set declaration (inside the table block).
func AutoSetDecl(id string, elems []string) string {
	var b strings.Builder
	b.WriteString("\tset " + AutoSetName(id) + " {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n")
	if len(elems) > 0 {
		b.WriteString("\t\telements = { " + strings.Join(elems, ", ") + " }\n")
	}
	b.WriteString("\t}\n")
	return b.String()
}

// AutoSetRefreshScript replaces the content of a live auto set in one
// nft transaction (no gap: flush and add commit together).
func AutoSetRefreshScript(id string, elems []string) string {
	name := AutoSetName(id)
	s := "flush set ip " + TableName + " " + name + "\n"
	if len(elems) > 0 {
		s += "add element ip " + TableName + " " + name + " { " + strings.Join(elems, ", ") + " }\n"
	}
	return s
}
