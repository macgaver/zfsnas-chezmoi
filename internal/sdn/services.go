package sdn

// Phase 4 services (spec §11.2, §11.3): DHCP & DNS served by one dnsmasq
// instance of our own, and WireGuard tunnels. A tunnel is an Interface of
// kind "wireguard" so rules, NAT and statistics treat it like any network.

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// DHCPServer serves one interface's network.
type DHCPServer struct {
	Interface  string   `json:"interface"`
	Enabled    bool     `json:"enabled"`
	RangeStart string   `json:"range_start"`
	RangeEnd   string   `json:"range_end"`
	Exclude    []string `json:"exclude,omitempty"` // "a.b.c.d" or "first-last", inside the range
	// NoPing: offer addresses without first pinging them (dnsmasq's check
	// waits up to 3 s for an answer when offering a new address).
	NoPing       bool              `json:"no_ping,omitempty"`
	LeaseHours   int               `json:"lease_hours"`
	Gateway      string            `json:"gateway,omitempty"`     // "" = the interface address
	DNSServers   []string          `json:"dns_servers,omitempty"` // "" = this router (DNS must answer there)
	Domain       string            `json:"domain,omitempty"`      // "" = the DNS local domain
	NTPServers   []string          `json:"ntp_servers,omitempty"`
	Routes       []DHCPRoute       `json:"routes,omitempty"` // classless static routes (options 121 and 249)
	Reservations []DHCPReservation `json:"reservations"`
	// Names: a host name for a device, whatever address it leases next.
	Names []DHCPName `json:"names,omitempty"`
}

// DHCPName names a device by its MAC without fixing its address: the name
// follows the device's lease, and through it the DNS record.
type DHCPName struct {
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
}

// DHCPRoute: clients reach Network through Via, a router in their network.
type DHCPRoute struct {
	Network string `json:"network"`
	Via     string `json:"via"`
}

// DHCPReservation: a fixed address, optionally with its own gateway, DNS
// servers and lease time instead of the network's.
type DHCPReservation struct {
	MAC         string   `json:"mac"`
	IP          string   `json:"ip"`
	Hostname    string   `json:"hostname,omitempty"`
	Description string   `json:"description,omitempty"`
	Gateway     string   `json:"gateway,omitempty"`
	DNSServers  []string `json:"dns_servers,omitempty"`
	LeaseHours  int      `json:"lease_hours,omitempty"` // 0 = the network's
}

// DNSSettings: the local resolver. DHCP hostnames (leases and reservations)
// are always registered as name and name.<domain>.
type DNSSettings struct {
	Enabled    bool         `json:"enabled"`
	Interfaces []string     `json:"interfaces"` // interface ids where DNS answers
	Upstreams  []string     `json:"upstreams"`  // none = the system's resolvers
	Domain     string       `json:"domain,omitempty"`
	Hosts      []DNSHost    `json:"hosts"`
	Forwards   []DNSForward `json:"forwards"`
	// Metrics: log every query (in RAM) for the DNS reports (Monitor → DNS).
	Metrics    bool           `json:"metrics,omitempty"`
	Blocklists []DNSBlocklist `json:"blocklists,omitempty"`
	Allow      []string       `json:"allow,omitempty"` // never blocked, even when a list has them
	Deny       []string       `json:"deny,omitempty"`  // always blocked
}

// DNSBlocklist is a list of domains to block, fetched from a URL every day
// (hosts, plain-domain and Adblock "||domain^" lines are read).
type DNSBlocklist struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
}

// DNSPaths are the files the DNS server's config names.
type DNSPaths struct {
	HostsDir  string // each network's DHCP names
	QueryLog  string // the query log (advanced metrics)
	Blocklist string // blocklists + blocked domains, as a hosts file
}

// Blocking: whether the DNS server reads the blocklist file.
func (d DNSSettings) Blocking() bool {
	if len(d.Deny) > 0 {
		return true
	}
	for _, l := range d.Blocklists {
		if l.Enabled {
			return true
		}
	}
	return false
}

// normDomains lowercases, trims and de-duplicates a domain list.
func normDomains(in []string) []string {
	out, seen := []string{}, map[string]bool{}
	for _, d := range in {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

type DNSHost struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

// DNSForward sends one domain to another DNS server (conditional forwarding).
type DNSForward struct {
	Domain string `json:"domain"`
	Server string `json:"server"`
}

// WGPeer is one device or site of a tunnel.
type WGPeer struct {
	ID              string   `json:"id"`
	Tunnel          string   `json:"tunnel"` // interface id
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	PublicKey       string   `json:"public_key"`
	PresharedKey    string   `json:"preshared_key,omitempty"`
	PresharedKeySet bool     `json:"preshared_key_set,omitempty"` // API: a preshared key is stored
	AllowedIPs      []string `json:"allowed_ips"`                 // its tunnel address + its networks (routes)
	Endpoint        string   `json:"endpoint,omitempty"`          // host:port, for a site we dial
	Keepalive       int      `json:"keepalive,omitempty"`
}

// WGConfDir holds the tunnels' key files (0600).
const WGConfDir = "/etc/wireguard"

// WGDeviceName is the kernel name of a tunnel.
func WGDeviceName(id string) string {
	if len(id) > 12 {
		id = id[:12]
	}
	return "wg-" + id
}

// WGConfPath is the `wg setconf` file of a tunnel.
func WGConfPath(id string) string { return WGConfDir + "/znas-" + id + ".conf" }

// ── keys ──

// GenerateWGKey returns a new private key, clamped like `wg genkey`.
func GenerateWGKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[0] &= 248
	b[31] = b[31]&127 | 64
	return base64.StdEncoding.EncodeToString(b), nil
}

// GenerateWGPSK returns a new preshared key.
func GenerateWGPSK() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// WGPublicKey derives the public key of a private key (X25519).
func WGPublicKey(priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("not a WireGuard key")
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

func wgKeyOK(k string) bool {
	raw, err := base64.StdEncoding.DecodeString(k)
	return err == nil && len(raw) == 32
}

// EnsureWGKeys gives every tunnel a private key generated on this box (it
// never travels to a browser) and recomputes the public keys.
func EnsureWGKeys(c *Config) error {
	for i := range c.Interfaces {
		in := &c.Interfaces[i]
		if in.Kind != "wireguard" {
			continue
		}
		if in.WGPrivateKey == "" {
			k, err := GenerateWGKey()
			if err != nil {
				return err
			}
			in.WGPrivateKey = k
		}
		if pub, err := WGPublicKey(in.WGPrivateKey); err == nil {
			in.WGPublicKey = pub
		}
	}
	return nil
}

// ── normalize ──

func (c *Config) normalizeServices() {
	if c.DHCP == nil {
		c.DHCP = []DHCPServer{}
	}
	for i := range c.DHCP {
		if c.DHCP[i].Reservations == nil {
			c.DHCP[i].Reservations = []DHCPReservation{}
		}
		if c.DHCP[i].LeaseHours == 0 {
			c.DHCP[i].LeaseHours = 12
		}
		ex := []string{}
		for _, e := range c.DHCP[i].Exclude {
			if e = strings.ReplaceAll(strings.TrimSpace(e), " ", ""); e != "" {
				ex = append(ex, e)
			}
		}
		c.DHCP[i].Exclude = ex
		for k := range c.DHCP[i].Routes {
			r := &c.DHCP[i].Routes[k]
			r.Network, r.Via = strings.TrimSpace(r.Network), strings.TrimSpace(r.Via)
		}
		for k := range c.DHCP[i].Reservations {
			c.DHCP[i].Reservations[k].MAC = strings.ToLower(strings.TrimSpace(c.DHCP[i].Reservations[k].MAC))
		}
		for k := range c.DHCP[i].Names {
			c.DHCP[i].Names[k].MAC = strings.ToLower(strings.TrimSpace(c.DHCP[i].Names[k].MAC))
			c.DHCP[i].Names[k].Hostname = strings.TrimSpace(c.DHCP[i].Names[k].Hostname)
		}
	}
	if c.DNS.Interfaces == nil {
		c.DNS.Interfaces = []string{}
	}
	if c.DNS.Upstreams == nil {
		c.DNS.Upstreams = []string{}
	}
	if c.DNS.Hosts == nil {
		c.DNS.Hosts = []DNSHost{}
	}
	if c.DNS.Forwards == nil {
		c.DNS.Forwards = []DNSForward{}
	}
	c.DNS.Allow, c.DNS.Deny = normDomains(c.DNS.Allow), normDomains(c.DNS.Deny)
	for i := range c.DNS.Blocklists {
		l := &c.DNS.Blocklists[i]
		l.URL = strings.TrimSpace(l.URL)
		if l.ID == "" {
			l.ID = NewID()
		}
	}
	if c.WGPeers == nil {
		c.WGPeers = []WGPeer{}
	}
	for i := range c.WGPeers {
		p := &c.WGPeers[i]
		if p.AllowedIPs == nil {
			p.AllowedIPs = []string{}
		}
		for k, a := range p.AllowedIPs {
			a = strings.TrimSpace(a)
			if !strings.Contains(a, "/") {
				if ip, err := netip.ParseAddr(a); err == nil && ip.Is4() {
					a += "/32"
				}
			}
			p.AllowedIPs[k] = a
		}
	}
	for i := range c.Interfaces {
		in := &c.Interfaces[i]
		if in.Kind != "wireguard" {
			continue
		}
		in.Device, in.Owned, in.Parent = WGDeviceName(in.ID), true, ""
		in.Routes = c.wgRoutes(*in)
	}
}

// wgRoutes: the peers' networks outside the tunnel's own network — those
// need a route through the tunnel (site-to-site).
func (c *Config) wgRoutes(in Interface) []string {
	own, err := netip.ParsePrefix(in.IPv4)
	if err != nil {
		return nil
	}
	own = own.Masked()
	seen := map[string]bool{}
	var out []string
	for _, p := range c.WGPeers {
		if p.Tunnel != in.ID || !p.Enabled {
			continue
		}
		for _, a := range p.AllowedIPs {
			pfx, err := netip.ParsePrefix(a)
			if err != nil || !pfx.Addr().Is4() || pfx.Bits() == 0 {
				continue
			}
			pfx = pfx.Masked()
			if own.Contains(pfx.Addr()) && pfx.Bits() >= own.Bits() {
				continue
			}
			if !seen[pfx.String()] {
				seen[pfx.String()] = true
				out = append(out, pfx.String())
			}
		}
	}
	sort.Strings(out)
	return out
}

// ── validation ──

var (
	macRe      = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
	hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	domainRe   = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

func ipv4OK(s string) bool {
	ip, err := netip.ParseAddr(s)
	return err == nil && ip.Is4()
}

// hostPortOK: "host:port" with an IPv4 or DNS name host.
func hostPortOK(s string) bool {
	host, port, ok := strings.Cut(s, ":")
	if !ok || !hostOK(host) {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

func hostOK(h string) bool { return ipv4OK(h) || (len(h) <= 253 && domainRe.MatchString(h)) }

func ifaceNet(in *Interface) (netip.Prefix, bool) {
	if in == nil || in.IPv4Mode != "static" {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(in.IPv4)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// checkWireGuard is the kind-specific part of checkInterface.
func checkWireGuard(in Interface) string {
	switch {
	case in.IPv4Mode != "static":
		return "ipv4_mode|a tunnel needs its own address, e.g. 10.66.0.1/24"
	case in.WGListenPort < 1 || in.WGListenPort > 65535:
		return "wg_listen_port|the listen port must be between 1 and 65535"
	case !wgKeyOK(in.WGPrivateKey):
		return "wg_private_key|the tunnel key is missing or invalid"
	case in.WGEndpoint != "" && !hostOK(in.WGEndpoint) && !hostPortOK(in.WGEndpoint):
		return "wg_endpoint|enter the public name or IPv4 address clients connect to"
	}
	return ""
}

// validateServices checks DHCP, DNS and WireGuard peers. valid holds the
// interfaces that passed their own checks: entries pointing at a broken
// interface are skipped (that interface already reports its error).
func (c *Config) validateServices(add func(path, format string, a ...any), valid map[string]bool) {
	dnsOn := map[string]bool{}
	if c.DNS.Enabled {
		for _, id := range c.DNS.Interfaces {
			dnsOn[id] = true
		}
	}

	seen := map[string]bool{}
	for i, d := range c.DHCP {
		p := fmt.Sprintf("dhcp[%d]", i)
		in := c.InterfaceByID(d.Interface)
		if in != nil && !valid[in.ID] {
			continue
		}
		if msg := c.checkDHCP(d, in, seen, dnsOn); msg != "" {
			field, text, _ := strings.Cut(msg, "|")
			add(p+"."+field, "%s", text)
		}
		if in != nil {
			seen[in.ID] = true
		}
	}

	if c.DNS.Enabled && len(c.DNS.Interfaces) == 0 {
		add("dns.interfaces", "choose the networks DNS answers on")
	}
	for _, id := range c.DNS.Interfaces {
		in := c.InterfaceByID(id)
		if in == nil {
			add("dns.interfaces", "a DNS network no longer exists")
			break
		}
		if in.Role == "wan" {
			add("dns.interfaces", "DNS cannot answer on %s: it is a WAN (an open resolver gets abused)", in.Name)
			break
		}
		if c.DNS.Enabled && in.IncusKeep && in.IncusDNS {
			add("dns.interfaces", "Incus already serves DNS on %s — turn it off on that network in VMs & Containers first", in.Name)
			break
		}
	}
	for _, u := range c.DNS.Upstreams {
		if !ipv4OK(u) {
			add("dns.upstreams", "%q is not an IPv4 address", u)
			break
		}
	}
	if c.DNS.Domain != "" && !domainRe.MatchString(c.DNS.Domain) {
		add("dns.domain", "%q is not a valid domain", c.DNS.Domain)
	}
	for i, h := range c.DNS.Hosts {
		p := fmt.Sprintf("dns.hosts[%d]", i)
		if !domainRe.MatchString(h.Name) {
			add(p+".name", "%q is not a valid host name", h.Name)
		} else if !ipv4OK(h.IP) {
			add(p+".ip", "%q is not an IPv4 address", h.IP)
		}
	}
	for i, f := range c.DNS.Forwards {
		p := fmt.Sprintf("dns.forwards[%d]", i)
		if !domainRe.MatchString(f.Domain) {
			add(p+".domain", "%q is not a valid domain", f.Domain)
		} else if !ipv4OK(f.Server) {
			add(p+".server", "%q is not an IPv4 address", f.Server)
		}
	}
	urls := map[string]bool{}
	for i, l := range c.DNS.Blocklists {
		p := fmt.Sprintf("dns.blocklists[%d]", i)
		u, err := url.Parse(l.URL)
		switch {
		case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.ContainsAny(l.URL, " \t\n\"'"):
			add(p+".url", "enter the list's address, starting with https://")
		case urls[l.URL]:
			add(p+".url", "this list is already there")
		case len(l.Description) > 80:
			add(p+".description", "description: at most 80 characters")
		}
		urls[l.URL] = true
	}
	if len(c.DNS.Blocklists) > 50 {
		add("dns.blocklists", "at most 50 lists")
	}
	for _, d := range c.DNS.Allow {
		if !domainRe.MatchString(d) {
			add("dns.allow", "%q is not a valid domain", d)
			break
		}
	}
	for _, d := range c.DNS.Deny {
		if !domainRe.MatchString(d) {
			add("dns.deny", "%q is not a valid domain", d)
			break
		}
	}

	c.validatePeers(add, valid)
}

func (c *Config) checkDHCP(d DHCPServer, in *Interface, seen, dnsOn map[string]bool) string {
	switch {
	case in == nil:
		return "interface|its network no longer exists"
	case seen[in.ID]:
		return "interface|DHCP is already configured on " + in.Name
	case in.Kind == "wireguard":
		return "interface|DHCP does not work through a WireGuard tunnel — give each peer its address"
	case in.Role == "wan":
		return "interface|DHCP cannot serve " + in.Name + ": it is a WAN"
	case in.IncusKeep && in.IncusDHCP:
		return "interface|Incus already serves DHCP on " + in.Name + " — turn it off on that network in VMs & Containers first"
	case in.IPv4Mode != "static":
		return "interface|" + in.Name + " needs a static address to serve DHCP"
	}
	if !d.Enabled {
		return ""
	}
	pfx, _ := ifaceNet(in)
	net := pfx.Masked()
	start, err1 := netip.ParseAddr(d.RangeStart)
	end, err2 := netip.ParseAddr(d.RangeEnd)
	switch {
	case err1 != nil || !net.Contains(start):
		return "range_start|the range must start inside " + net.String()
	case err2 != nil || !net.Contains(end):
		return "range_end|the range must end inside " + net.String()
	case end.Less(start):
		return "range_start|the range starts after it ends"
	}
	for _, e := range d.Exclude {
		a, b, ok := parseAddrRange(e)
		switch {
		case !ok:
			return "exclude|" + strconv.Quote(e) + " is not an address or a range like 10.0.0.20-10.0.0.29"
		case a.Less(start) || end.Less(b):
			return "exclude|" + e + " is outside the range " + d.RangeStart + " – " + d.RangeEnd
		}
	}
	switch {
	case len(d.Pools()) == 0:
		return "exclude|the excluded addresses cover the whole range"
	case d.LeaseHours < 1 || d.LeaseHours > 8760:
		return "lease_hours|lease time must be between 1 hour and 1 year"
	case d.Gateway != "" && (!ipv4OK(d.Gateway) || !net.Contains(netip.MustParseAddr(d.Gateway))):
		return "gateway|the gateway handed out must be inside " + net.String()
	case d.Domain != "" && !domainRe.MatchString(d.Domain):
		return "domain|not a valid domain"
	}
	for _, s := range d.DNSServers {
		if !ipv4OK(s) {
			return "dns_servers|" + strconv.Quote(s) + " is not an IPv4 address"
		}
	}
	for _, s := range d.NTPServers {
		if !ipv4OK(s) {
			return "ntp_servers|" + strconv.Quote(s) + " is not an IPv4 address (DHCP hands out addresses, not names)"
		}
	}
	routes := map[string]bool{}
	for k, r := range d.Routes {
		p := fmt.Sprintf("routes[%d]", k)
		dst, err := netip.ParsePrefix(r.Network)
		switch {
		case err != nil || !dst.Addr().Is4():
			return p + ".network|enter a network like 10.20.0.0/16"
		case dst != dst.Masked():
			return p + ".network|use the network address: " + dst.Masked().String()
		case dst.Bits() == 0:
			return p + ".network|the default route is the gateway handed out"
		case routes[dst.String()]:
			return p + ".network|" + dst.String() + " is routed twice"
		case !ipv4OK(r.Via) || !net.Contains(netip.MustParseAddr(r.Via)):
			return p + ".via|the router must be inside " + net.String()
		}
		routes[dst.String()] = true
	}
	if len(d.DNSServers) == 0 && !dnsOn[in.ID] {
		return "dns_servers|enter the DNS servers to hand out, or turn on DNS for " + in.Name
	}
	macs, ips := map[string]bool{}, map[string]bool{}
	for k, r := range d.Reservations {
		p := fmt.Sprintf("reservations[%d]", k)
		ip, err := netip.ParseAddr(r.IP)
		switch {
		case !macRe.MatchString(r.MAC):
			return p + ".mac|enter a MAC address like aa:bb:cc:dd:ee:ff"
		case macs[r.MAC]:
			return p + ".mac|" + r.MAC + " is reserved twice"
		case err != nil || !net.Contains(ip):
			return p + ".ip|the reserved address must be inside " + net.String()
		case ips[r.IP]:
			return p + ".ip|" + r.IP + " is reserved twice"
		case r.Hostname != "" && !hostnameRe.MatchString(r.Hostname):
			return p + ".hostname|a host name uses letters, digits and - only"
		case r.Gateway != "" && (!ipv4OK(r.Gateway) || !net.Contains(netip.MustParseAddr(r.Gateway))):
			return p + ".gateway|the gateway must be inside " + net.String()
		case r.LeaseHours < 0 || r.LeaseHours > 8760:
			return p + ".lease_hours|lease time must be between 1 hour and 1 year"
		}
		for _, s := range r.DNSServers {
			if !ipv4OK(s) {
				return p + ".dns_servers|" + strconv.Quote(s) + " is not an IPv4 address"
			}
		}
		macs[r.MAC], ips[r.IP] = true, true
	}
	hosts := map[string]bool{}
	for _, r := range d.Reservations {
		if r.Hostname != "" {
			hosts[strings.ToLower(r.Hostname)] = true
		}
	}
	for k, n := range d.Names {
		p := fmt.Sprintf("names[%d]", k)
		h := strings.ToLower(n.Hostname)
		switch {
		case !macRe.MatchString(n.MAC):
			return p + ".mac|enter a MAC address like aa:bb:cc:dd:ee:ff"
		case macs[n.MAC]:
			return p + ".mac|" + n.MAC + " has a reservation or a name already: set its name in one place"
		case !hostnameRe.MatchString(n.Hostname):
			return p + ".hostname|a host name uses letters, digits and - only"
		case hosts[h]:
			return p + ".hostname|" + n.Hostname + " is used twice on this network"
		}
		macs[n.MAC], hosts[h] = true, true
	}
	return ""
}

func (c *Config) validatePeers(add func(path, format string, a ...any), valid map[string]bool) {
	type owned struct {
		pfx  netip.Prefix
		name string
	}
	var taken []owned
	for _, in := range c.Interfaces {
		if pfx, ok := ifaceNet(&in); ok && in.Kind != "wireguard" {
			taken = append(taken, owned{pfx.Masked(), in.Name})
		}
	}
	keys := map[string]bool{}
	for _, in := range c.Interfaces {
		if in.Kind == "wireguard" {
			keys[in.ID+"/"+in.WGPublicKey] = true
		}
	}
	for i, p := range c.WGPeers {
		path := fmt.Sprintf("wg_peers[%d]", i)
		tun := c.InterfaceByID(p.Tunnel)
		if tun != nil && !valid[tun.ID] {
			continue
		}
		label := p.Name
		if label == "" {
			label = fmt.Sprintf("peer %d", i+1)
		}
		fail := func(field, format string, a ...any) {
			add(path+"."+field, "%s: "+format, append([]any{label}, a...)...)
		}
		switch {
		case !idRe.MatchString(p.ID):
			fail("id", "invalid id")
			continue
		case tun == nil || tun.Kind != "wireguard":
			fail("tunnel", "its tunnel no longer exists")
			continue
		case len(p.Name) > 64 || !pppSafe(p.Name):
			fail("name", "names are at most 64 characters, without quotes or backslashes")
			continue
		case !wgKeyOK(p.PublicKey):
			fail("public_key", "not a WireGuard public key")
			continue
		case keys[p.Tunnel+"/"+p.PublicKey]:
			fail("public_key", "this key is already used on this tunnel")
			continue
		case p.PresharedKey != "" && !wgKeyOK(p.PresharedKey):
			fail("preshared_key", "not a WireGuard preshared key")
			continue
		case len(p.AllowedIPs) == 0:
			fail("allowed_ips", "give the peer its tunnel address, e.g. 10.66.0.2/32")
			continue
		case p.Endpoint != "" && !hostPortOK(p.Endpoint):
			fail("endpoint", "enter host:port, e.g. vpn.example.com:51820")
			continue
		case p.Keepalive < 0 || p.Keepalive > 65535:
			fail("keepalive", "keepalive is 0–65535 seconds")
			continue
		}
		keys[p.Tunnel+"/"+p.PublicKey] = true
		tunNet, _ := ifaceNet(tun)
		tunNet = tunNet.Masked()
		var mine []owned
		bad := ""
		for _, a := range p.AllowedIPs {
			pfx, err := netip.ParsePrefix(a)
			if err != nil || !pfx.Addr().Is4() {
				bad = fmt.Sprintf("%q is not an IPv4 network", a)
				break
			}
			pfx = pfx.Masked()
			if pfx.Bits() == 0 {
				bad = "0.0.0.0/0 would send all traffic into the tunnel — list the peer's networks"
				break
			}
			if pfx.Overlaps(tunNet) && pfx.Bits() < tunNet.Bits() {
				bad = fmt.Sprintf("%s contains the tunnel's own network", pfx)
				break
			}
			for _, t := range taken {
				if t.pfx.Overlaps(pfx) {
					bad = fmt.Sprintf("%s overlaps %s", pfx, t.name)
					break
				}
			}
			if bad != "" {
				break
			}
			mine = append(mine, owned{pfx, label})
		}
		if bad != "" {
			fail("allowed_ips", "%s", bad)
			continue
		}
		if p.Enabled {
			taken = append(taken, mine...)
		}
	}
	ports := map[int]string{}
	for i, in := range c.Interfaces {
		if in.Kind != "wireguard" || !valid[in.ID] {
			continue
		}
		if other, ok := ports[in.WGListenPort]; ok {
			add(fmt.Sprintf("interfaces[%d].wg_listen_port", i), "port %d is already used by %s", in.WGListenPort, other)
			continue
		}
		ports[in.WGListenPort] = in.Name
	}
}

// ── rendering ──

// DHCP and DNS run as separate dnsmasq processes: one DNS server for every
// network (znas-sdn-dns), and one DHCP server per network, started by
// znas-sdn-dhcp. Each network's DHCP names reach the DNS server through a
// hosts file per network in a folder the DNS server watches; the DHCP
// supervisor writes it from the network's lease file.

// DHCPLeaseFile is where a network's DHCP server keeps its leases.
func DHCPLeaseFile(leaseDir, ifaceID string) string {
	return leaseDir + "/znas-sdn-" + ifaceID + ".leases"
}

// DHCPDomain is the domain a network's DHCP hands out and registers its
// names in: its own, else the Local DNS domain.
func (c *Config) DHCPDomain(d DHCPServer) string {
	if d.Domain != "" {
		return d.Domain
	}
	return c.DNS.Domain
}

func (c *Config) dhcpScopes() []DHCPServer {
	var out []DHCPServer
	for _, d := range c.DHCP {
		if in := c.InterfaceByID(d.Interface); d.Enabled && in != nil && !in.Disabled {
			out = append(out, d)
		}
	}
	return out
}

// RenderDNS is the DNS server's configuration, or "" when DNS is off.
// bind-dynamic + explicit interfaces: it never touches Incus' own dnsmasq
// bridges or systemd-resolved's 127.0.0.53.
func RenderDNS(c *Config, paths DNSPaths) string {
	var listen []string
	for _, id := range c.DNS.Interfaces {
		if in := c.InterfaceByID(id); in != nil && !in.Disabled {
			listen = append(listen, in.L3Device())
		}
	}
	// With no interface line dnsmasq would answer on every interface.
	if !c.DNS.Enabled || len(listen) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("# Managed by ZNAS Firewall — rewritten on every apply and at boot.\n")
	b.WriteString("bind-dynamic\nexcept-interface=lo\n")
	for _, dev := range listen {
		fmt.Fprintf(&b, "interface=%s\nno-dhcp-interface=%s\n", dev, dev)
	}
	if c.DNS.Metrics {
		// every query, for the reports; in RAM (the portal reads it)
		fmt.Fprintf(&b, "log-queries=extra\nlog-async=50\nlog-facility=%s\n", paths.QueryLog)
	} else {
		b.WriteString("log-facility=-\n")
	}
	b.WriteString("domain-needed\nbogus-priv\nno-hosts\ncache-size=1000\n")
	if c.DNS.Blocking() {
		fmt.Fprintf(&b, "addn-hosts=%s\n", paths.Blocklist)
	}
	if len(c.DNS.Upstreams) > 0 {
		b.WriteString("no-resolv\n")
		for _, u := range c.DNS.Upstreams {
			fmt.Fprintf(&b, "server=%s\n", u)
		}
	}
	for _, f := range c.DNS.Forwards {
		fmt.Fprintf(&b, "server=/%s/%s\n", f.Domain, f.Server)
	}
	for _, h := range c.DNS.Hosts {
		if c.DNS.Domain != "" && !strings.Contains(h.Name, ".") {
			fmt.Fprintf(&b, "host-record=%s.%s,%s,%s\n", h.Name, c.DNS.Domain, h.Name, h.IP)
		} else {
			fmt.Fprintf(&b, "host-record=%s,%s\n", h.Name, h.IP)
		}
	}
	// the local domains: never forwarded upstream
	locals := map[string]bool{}
	addLocal := func(d string) {
		if d != "" && !locals[d] {
			locals[d] = true
			fmt.Fprintf(&b, "local=/%s/\n", d)
		}
	}
	addLocal(c.DNS.Domain)
	scopes := c.dhcpScopes()
	for _, d := range scopes {
		addLocal(c.DHCPDomain(d))
	}
	// reserved names answer even before the device asks for its address
	for _, d := range scopes {
		dom := c.DHCPDomain(d)
		for _, r := range d.Reservations {
			if r.Hostname == "" {
				continue
			}
			if dom != "" {
				fmt.Fprintf(&b, "host-record=%s.%s,%s,%s\n", r.Hostname, dom, r.Hostname, r.IP)
			} else {
				fmt.Fprintf(&b, "host-record=%s,%s\n", r.Hostname, r.IP)
			}
		}
	}
	fmt.Fprintf(&b, "hostsdir=%s\n", paths.HostsDir)
	return b.String()
}

// RenderDHCP returns each network's DHCP server configuration, by
// interface id (none for networks without DHCP). port=0: these processes
// answer no DNS. One interface each: dnsmasq binds its DHCP socket to it,
// so the servers (and Incus' own) live side by side.
func RenderDHCP(c *Config, leaseDir string) map[string]string {
	dnsOn := map[string]bool{}
	if c.DNS.Enabled {
		for _, id := range c.DNS.Interfaces {
			dnsOn[id] = true
		}
	}
	out := map[string]string{}
	for _, d := range c.dhcpScopes() {
		in := c.InterfaceByID(d.Interface)
		pfx, _ := ifaceNet(in)
		net := pfx.Masked()
		var b strings.Builder
		fmt.Fprintf(&b, "# Managed by ZNAS Firewall — DHCP on %s; rewritten on every apply and at boot.\n", strings.ReplaceAll(in.Name, "\n", " "))
		fmt.Fprintf(&b, "port=0\nbind-dynamic\nexcept-interface=lo\ninterface=%s\nlog-facility=-\n", in.L3Device())
		fmt.Fprintf(&b, "dhcp-authoritative\ndhcp-leasefile=%s\n", DHCPLeaseFile(leaseDir, in.ID))
		if d.NoPing {
			b.WriteString("no-ping\n")
		}
		if dom := c.DHCPDomain(d); dom != "" {
			fmt.Fprintf(&b, "domain=%s\n", dom)
		}
		for _, p := range d.Pools() {
			fmt.Fprintf(&b, "dhcp-range=set:%s,%s,%s,%s,%dh\n", in.ID, p[0], p[1], prefixMask(net.Bits()), d.LeaseHours)
		}
		gw, vip := d.Gateway, in.clientsVIP()
		if gw == "" && vip != "" {
			gw = vip // follows the virtual IP when it moves to another server
		}
		if gw == "" {
			gw = pfx.Addr().String()
		}
		fmt.Fprintf(&b, "dhcp-option=tag:%s,option:router,%s\n", in.ID, gw)
		dns := d.DNSServers
		if len(dns) == 0 && dnsOn[d.Interface] {
			dns = []string{pfx.Addr().String()}
			if vip != "" {
				dns = []string{vip}
			}
		}
		if len(dns) > 0 {
			fmt.Fprintf(&b, "dhcp-option=tag:%s,option:dns-server,%s\n", in.ID, strings.Join(dns, ","))
		}
		if len(d.NTPServers) > 0 {
			fmt.Fprintf(&b, "dhcp-option=tag:%s,option:ntp-server,%s\n", in.ID, strings.Join(d.NTPServers, ","))
		}
		writeClasslessRoutes(&b, in.ID, d.Routes, gw)
		// A name without an address: dnsmasq gives it to the device's lease,
		// whatever address that is.
		for _, n := range d.Names {
			fmt.Fprintf(&b, "dhcp-host=%s,%s\n", n.MAC, n.Hostname)
		}
		// A reserved address with its own options gets a tag of its own:
		// dnsmasq ranks the dhcp-range tag below it, so these win.
		for _, r := range d.Reservations {
			f := []string{r.MAC}
			tag := ""
			if r.Gateway != "" || len(r.DNSServers) > 0 {
				tag = "h-" + strings.ReplaceAll(r.MAC, ":", "")
				f = append(f, "set:"+tag)
			}
			f = append(f, r.IP)
			if r.Hostname != "" {
				f = append(f, r.Hostname)
			}
			if r.LeaseHours > 0 {
				f = append(f, fmt.Sprintf("%dh", r.LeaseHours))
			}
			fmt.Fprintf(&b, "dhcp-host=%s\n", strings.Join(f, ","))
			if r.Gateway != "" {
				fmt.Fprintf(&b, "dhcp-option=tag:%s,option:router,%s\n", tag, r.Gateway)
				writeClasslessRoutes(&b, tag, d.Routes, r.Gateway)
			}
			if len(r.DNSServers) > 0 {
				fmt.Fprintf(&b, "dhcp-option=tag:%s,option:dns-server,%s\n", tag, strings.Join(r.DNSServers, ","))
			}
		}
		out[in.ID] = b.String()
	}
	return out
}

// parseAddrRange reads "a.b.c.d" or "first-last" (first <= last).
func parseAddrRange(s string) (netip.Addr, netip.Addr, bool) {
	x, y, isRange := strings.Cut(s, "-")
	a, err := netip.ParseAddr(x)
	if err != nil || !a.Is4() {
		return a, a, false
	}
	if !isRange {
		return a, a, true
	}
	b, err := netip.ParseAddr(y)
	if err != nil || !b.Is4() || b.Less(a) {
		return a, a, false
	}
	return a, b, true
}

// Pools: the range minus the excluded addresses, as the first-last pieces
// handed out (nil when the range itself is not valid).
func (d DHCPServer) Pools() [][2]netip.Addr {
	start, err1 := netip.ParseAddr(d.RangeStart)
	end, err2 := netip.ParseAddr(d.RangeEnd)
	if err1 != nil || err2 != nil || !start.Is4() || !end.Is4() || end.Less(start) {
		return nil
	}
	type span struct{ a, b uint32 }
	u := func(a netip.Addr) uint32 {
		b := a.As4()
		return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	ip := func(n uint32) netip.Addr {
		return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	}
	var ex []span
	for _, e := range d.Exclude {
		if a, b, ok := parseAddrRange(e); ok {
			ex = append(ex, span{u(a), u(b)})
		}
	}
	sort.Slice(ex, func(i, j int) bool { return ex[i].a < ex[j].a })
	var out [][2]netip.Addr
	cur, last := uint64(u(start)), uint64(u(end))
	for _, e := range ex {
		if uint64(e.a) > cur {
			hi := min(uint64(e.a)-1, last)
			if cur <= hi {
				out = append(out, [2]netip.Addr{ip(uint32(cur)), ip(uint32(hi))})
			}
		}
		if uint64(e.b)+1 > cur {
			cur = uint64(e.b) + 1
		}
		if cur > last {
			return out
		}
	}
	return append(out, [2]netip.Addr{ip(uint32(cur)), ip(uint32(last))})
}

// writeClasslessRoutes: option 121 (and 249, Windows' older copy of it).
// A client that gets them ignores the router option (RFC 3442), so the
// default route through gw ends the list.
func writeClasslessRoutes(b *strings.Builder, tag string, routes []DHCPRoute, gw string) {
	if len(routes) == 0 {
		return
	}
	var f []string
	for _, r := range routes {
		f = append(f, r.Network, r.Via)
	}
	list := strings.Join(append(f, "0.0.0.0/0", gw), ",")
	fmt.Fprintf(b, "dhcp-option=tag:%s,option:classless-static-route,%s\n", tag, list)
	fmt.Fprintf(b, "dhcp-option=tag:%s,249,%s\n", tag, list)
}

func prefixMask(bits int) string {
	m := uint32(0xffffffff) << (32 - bits)
	if bits == 0 {
		m = 0
	}
	return fmt.Sprintf("%d.%d.%d.%d", m>>24, m>>16&255, m>>8&255, m&255)
}

// WGEndpointIsName: the host of a host:port endpoint must be looked up.
func WGEndpointIsName(ep string) bool {
	host, _, err := net.SplitHostPort(ep)
	if err != nil {
		return false
	}
	_, err = netip.ParseAddr(host)
	return err != nil
}

// WGConf is the `wg setconf` file of a tunnel (keys, port, enabled peers).
func WGConf(c *Config, tunnel string) string {
	in := c.InterfaceByID(tunnel)
	if in == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nListenPort = %d\n", in.WGPrivateKey, in.WGListenPort)
	for _, p := range c.WGPeers {
		if p.Tunnel != tunnel || !p.Enabled {
			continue
		}
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		// A name is left to the gateway monitor (system/sdn_selfheal.go):
		// `wg setconf` would wait for DNS, and at boot hold up networking.
		if p.Endpoint != "" && !WGEndpointIsName(p.Endpoint) {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
		}
	}
	return b.String()
}

// renderWireGuard is RenderOwned for a tunnel.
func renderWireGuard(b *strings.Builder, i Interface) {
	fmt.Fprintf(b, "auto %s\niface %s inet static\n", i.Device, i.Device)
	fmt.Fprintf(b, "    pre-up ip link add dev %s type wireguard\n", i.Device)
	fmt.Fprintf(b, "    pre-up wg setconf %s %s\n", i.Device, WGConfPath(i.ID))
	fmt.Fprintf(b, "    address %s\n", i.IPv4)
	mtu := i.MTU
	if mtu == 0 {
		mtu = 1420
	}
	fmt.Fprintf(b, "    mtu %d\n", mtu)
	for _, r := range i.Routes {
		fmt.Fprintf(b, "    post-up ip route replace %s dev %s\n", r, i.Device)
	}
	fmt.Fprintf(b, "    post-up sysctl -w net.ipv6.conf.%s.disable_ipv6=1\n", i.Device)
	fmt.Fprintf(b, "    post-down ip link del dev %s\n", i.Device)
}

// serviceAllowLines: router mode lets DHCP and DNS reach the router on the
// interfaces that serve them, before the user's rules.
func serviceAllowLines(c *Config) []string {
	var out []string
	for _, in := range c.Interfaces {
		if in.IncusKeep && in.IncusDHCP {
			out = append(out, fmt.Sprintf("iifname %q udp dport 67 accept comment \"svc:dhcp\"", in.L3Device()))
		}
		if in.IncusKeep && in.IncusDNS {
			out = append(out, fmt.Sprintf("iifname %q meta l4proto { tcp, udp } th dport 53 accept comment \"svc:dns\"", in.L3Device()))
		}
	}
	for _, d := range c.DHCP {
		if in := c.InterfaceByID(d.Interface); d.Enabled && in != nil {
			out = append(out, fmt.Sprintf("iifname %q udp dport 67 accept comment \"svc:dhcp\"", in.L3Device()))
		}
	}
	if c.DNS.Enabled {
		for _, id := range c.DNS.Interfaces {
			if in := c.InterfaceByID(id); in != nil {
				out = append(out, fmt.Sprintf("iifname %q meta l4proto { tcp, udp } th dport 53 accept comment \"svc:dns\"", in.L3Device()))
			}
		}
	}
	return out
}

// noDNSLines: dnsmasq answers DNS on every interface it listens on, so an
// interface with DHCP but without DNS gets DNS to the router's address
// dropped (both modes: in monitor mode nothing else filters).
func noDNSLines(c *Config) []string {
	dnsOn := map[string]bool{}
	if c.DNS.Enabled {
		for _, id := range c.DNS.Interfaces {
			dnsOn[id] = true
		}
	}
	var out []string
	for _, d := range c.DHCP {
		in := c.InterfaceByID(d.Interface)
		pfx, ok := ifaceNet(in)
		if !d.Enabled || !ok || dnsOn[d.Interface] {
			continue
		}
		out = append(out, fmt.Sprintf("iifname %q ip daddr %s meta l4proto { tcp, udp } th dport 53 drop comment \"svc:nodns\"", in.L3Device(), pfx.Addr()))
	}
	return out
}

// summarizeServices adds the DHCP, DNS and WireGuard peer changes.
func summarizeServices(prev, next *Config) []string {
	var parts []string
	name := func(id string) string {
		if in := next.InterfaceByID(id); in != nil {
			return in.Name
		}
		if in := prev.InterfaceByID(id); in != nil {
			return in.Name
		}
		return id
	}
	was := map[string]DHCPServer{}
	for _, d := range prev.DHCP {
		was[d.Interface] = d
	}
	for _, d := range next.DHCP {
		old, ok := was[d.Interface]
		delete(was, d.Interface)
		switch {
		case (!ok || !old.Enabled) && d.Enabled:
			parts = append(parts, "DHCP on "+name(d.Interface)+" on")
		case ok && old.Enabled && !d.Enabled:
			parts = append(parts, "DHCP on "+name(d.Interface)+" off")
		case ok && !same(old, d):
			parts = append(parts, "DHCP on "+name(d.Interface)+" edited")
		}
	}
	for id, d := range was {
		if d.Enabled {
			parts = append(parts, "DHCP on "+name(id)+" off")
		}
	}
	switch {
	case prev.DNS.Enabled != next.DNS.Enabled:
		parts = append(parts, map[bool]string{true: "DNS on", false: "DNS off"}[next.DNS.Enabled])
	case !same(prev.DNS, next.DNS):
		parts = append(parts, "DNS edited")
	}
	peers := func(c *Config) map[string]any {
		m := map[string]any{}
		for _, p := range c.WGPeers {
			m[p.ID] = p
		}
		return m
	}
	return append(parts, countChanges(peers(prev), peers(next), "WireGuard peer")...)
}
