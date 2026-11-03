package sdn

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// servicesSample: DHCP + DNS on VLAN700/VLAN800, a road-warrior tunnel with
// one phone and one site-to-site peer.
func servicesSample() *Config {
	c := ownerSample()
	c.DHCP = []DHCPServer{
		{Interface: "if000800", Enabled: true, RangeStart: "10.128.8.100", RangeEnd: "10.128.8.199", LeaseHours: 12,
			Reservations: []DHCPReservation{{MAC: "aa:bb:cc:dd:ee:01", IP: "10.128.8.8", Hostname: "plex"}}},
		{Interface: "if000700", Enabled: true, RangeStart: "10.128.7.50", RangeEnd: "10.128.7.60", DNSServers: []string{"10.128.8.4", "10.128.8.33"}},
	}
	c.DNS = DNSSettings{Enabled: true, Interfaces: []string{"if000800"}, Upstreams: []string{"1.1.1.1", "9.9.9.9"}, Domain: "chezmoi.lan",
		Hosts:    []DNSHost{{Name: "nas", IP: "10.128.8.5"}},
		Forwards: []DNSForward{{Domain: "corp.example", Server: "10.128.8.33"}}}
	priv, pub := testKeys(1)
	c.Interfaces = append(c.Interfaces, Interface{ID: "ifwg0001", Name: "Road warriors", Kind: "wireguard", Role: "lan",
		IPv4Mode: "static", IPv4: "10.66.0.1/24", WGListenPort: 51820, WGPrivateKey: priv, WGPublicKey: pub})
	_, p2 := testKeys(2)
	_, p3 := testKeys(3)
	c.WGPeers = []WGPeer{
		{ID: "peer0001", Tunnel: "ifwg0001", Name: "Phone", Enabled: true, PublicKey: p2, PresharedKey: b64(4), AllowedIPs: []string{"10.66.0.2/32"}},
		{ID: "peer0002", Tunnel: "ifwg0001", Name: "znas40 site", Enabled: true, PublicKey: p3, AllowedIPs: []string{"10.66.0.3/32", "10.40.0.0/24"},
			Endpoint: "vpn.example.com:51820", Keepalive: 25},
	}
	c.Normalize()
	return c
}

func b64(seed byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func testKeys(seed byte) (string, string) {
	priv := b64(seed)
	pub, err := WGPublicKey(priv)
	if err != nil {
		panic(err)
	}
	return priv, pub
}

func TestServices_SampleValid(t *testing.T) {
	c := servicesSample()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if d := c.InterfaceByID("ifwg0001").Device; d != "wg-ifwg0001" {
		t.Fatalf("wireguard device %q", d)
	}
	if !c.InterfaceByID("ifwg0001").Owned {
		t.Fatal("a tunnel is created by the feature: owned")
	}
}

func TestServices_ValidationCases(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *Config)
		path   string
	}{
		{"dhcp unknown iface", func(c *Config) { c.DHCP[0].Interface = "nope" }, "dhcp[0].interface"},
		{"dhcp twice on one iface", func(c *Config) { c.DHCP[1].Interface = "if000800" }, "dhcp[1].interface"},
		{"dhcp range outside net", func(c *Config) { c.DHCP[0].RangeEnd = "10.128.9.10" }, "dhcp[0].range_end"},
		{"dhcp range reversed", func(c *Config) { c.DHCP[0].RangeStart = "10.128.8.200" }, "dhcp[0].range_start"},
		{"dhcp on wan", func(c *Config) { c.Interfaces[3].Role = "wan" }, "dhcp[1].interface"},
		{"dhcp on dhcp-client iface", func(c *Config) {
			c.Interfaces[2].IPv4Mode, c.Interfaces[2].IPv4 = "dhcp", ""
			c.DHCP = append(c.DHCP, DHCPServer{Interface: "if000500", Enabled: true, RangeStart: "10.128.5.10", RangeEnd: "10.128.5.20", DNSServers: []string{"1.1.1.1"}})
		}, "dhcp[2].interface"},
		{"dhcp bad gateway", func(c *Config) { c.DHCP[0].Gateway = "1.2.3.4" }, "dhcp[0].gateway"},
		{"dhcp no dns when dns off", func(c *Config) { c.DHCP[1].DNSServers = nil }, "dhcp[1].dns_servers"},
		{"dhcp bad lease", func(c *Config) { c.DHCP[0].LeaseHours = 9000 }, "dhcp[0].lease_hours"},
		{"reservation bad mac", func(c *Config) { c.DHCP[0].Reservations[0].MAC = "zz" }, "dhcp[0].reservations[0].mac"},
		{"reservation outside net", func(c *Config) { c.DHCP[0].Reservations[0].IP = "10.128.7.8" }, "dhcp[0].reservations[0].ip"},
		{"reservation bad hostname", func(c *Config) { c.DHCP[0].Reservations[0].Hostname = "pl ex" }, "dhcp[0].reservations[0].hostname"},
		{"reservation dup mac", func(c *Config) {
			c.DHCP[0].Reservations = append(c.DHCP[0].Reservations, DHCPReservation{MAC: "AA:BB:CC:DD:EE:01", IP: "10.128.8.9"})
		}, "dhcp[0].reservations[1].mac"},
		{"route not a network", func(c *Config) { c.DHCP[0].Routes = []DHCPRoute{{Network: "10.20.0.5/16", Via: "10.128.8.254"}} }, "dhcp[0].routes[0].network"},
		{"route bad network", func(c *Config) { c.DHCP[0].Routes = []DHCPRoute{{Network: "x", Via: "10.128.8.254"}} }, "dhcp[0].routes[0].network"},
		{"route default", func(c *Config) { c.DHCP[0].Routes = []DHCPRoute{{Network: "0.0.0.0/0", Via: "10.128.8.254"}} }, "dhcp[0].routes[0].network"},
		{"route via outside net", func(c *Config) { c.DHCP[0].Routes = []DHCPRoute{{Network: "10.20.0.0/16", Via: "10.128.7.254"}} }, "dhcp[0].routes[0].via"},
		{"route twice", func(c *Config) {
			c.DHCP[0].Routes = []DHCPRoute{{Network: "10.20.0.0/16", Via: "10.128.8.254"}, {Network: "10.20.0.0/16", Via: "10.128.8.253"}}
		}, "dhcp[0].routes[1].network"},
		{"ntp bad server", func(c *Config) { c.DHCP[0].NTPServers = []string{"pool.ntp.org"} }, "dhcp[0].ntp_servers"},
		{"reservation bad gateway", func(c *Config) { c.DHCP[0].Reservations[0].Gateway = "10.128.7.1" }, "dhcp[0].reservations[0].gateway"},
		{"reservation bad dns", func(c *Config) { c.DHCP[0].Reservations[0].DNSServers = []string{"x"} }, "dhcp[0].reservations[0].dns_servers"},
		{"reservation bad lease", func(c *Config) { c.DHCP[0].Reservations[0].LeaseHours = 9000 }, "dhcp[0].reservations[0].lease_hours"},
		{"exclusion not an address", func(c *Config) { c.DHCP[0].Exclude = []string{"x"} }, "dhcp[0].exclude"},
		{"exclusion reversed", func(c *Config) { c.DHCP[0].Exclude = []string{"10.128.8.130-10.128.8.120"} }, "dhcp[0].exclude"},
		{"exclusion outside the range", func(c *Config) { c.DHCP[0].Exclude = []string{"10.128.8.50"} }, "dhcp[0].exclude"},
		{"exclusion of the whole range", func(c *Config) { c.DHCP[0].Exclude = []string{"10.128.8.100-10.128.8.199"} }, "dhcp[0].exclude"},
		{"dns unknown iface", func(c *Config) { c.DNS.Interfaces = []string{"if000800", "nope"} }, "dns.interfaces"},
		{"dns bad upstream", func(c *Config) { c.DNS.Upstreams = []string{"dns.google"} }, "dns.upstreams"},
		{"dns bad domain", func(c *Config) { c.DNS.Domain = "bad domain" }, "dns.domain"},
		{"dns host bad ip", func(c *Config) { c.DNS.Hosts[0].IP = "x" }, "dns.hosts[0].ip"},
		{"dns forward bad server", func(c *Config) { c.DNS.Forwards[0].Server = "x" }, "dns.forwards[0].server"},
		{"wg no address", func(c *Config) { c.Interfaces[5].IPv4Mode = "none"; c.Interfaces[5].IPv4 = "" }, "interfaces[5].ipv4_mode"},
		{"wg bad port", func(c *Config) { c.Interfaces[5].WGListenPort = 0 }, "interfaces[5].wg_listen_port"},
		{"wg bad private key", func(c *Config) { c.Interfaces[5].WGPrivateKey = "short" }, "interfaces[5].wg_private_key"},
		{"wg bad endpoint", func(c *Config) { c.Interfaces[5].WGEndpoint = "a b" }, "interfaces[5].wg_endpoint"},
		{"peer unknown tunnel", func(c *Config) { c.WGPeers[0].Tunnel = "nope" }, "wg_peers[0].tunnel"},
		{"peer bad key", func(c *Config) { c.WGPeers[0].PublicKey = "nope" }, "wg_peers[0].public_key"},
		{"peer dup key", func(c *Config) { c.WGPeers[1].PublicKey = c.WGPeers[0].PublicKey }, "wg_peers[1].public_key"},
		{"peer bad psk", func(c *Config) { c.WGPeers[0].PresharedKey = "x" }, "wg_peers[0].preshared_key"},
		{"peer no allowed ips", func(c *Config) { c.WGPeers[0].AllowedIPs = nil }, "wg_peers[0].allowed_ips"},
		{"peer default route", func(c *Config) { c.WGPeers[1].AllowedIPs = []string{"0.0.0.0/0"} }, "wg_peers[1].allowed_ips"},
		{"peer overlap peer", func(c *Config) { c.WGPeers[1].AllowedIPs = []string{"10.66.0.2/32"} }, "wg_peers[1].allowed_ips"},
		{"peer overlaps lan", func(c *Config) { c.WGPeers[1].AllowedIPs = []string{"10.128.8.0/24"} }, "wg_peers[1].allowed_ips"},
		{"peer bad endpoint", func(c *Config) { c.WGPeers[1].Endpoint = "host" }, "wg_peers[1].endpoint"},
		{"peer bad keepalive", func(c *Config) { c.WGPeers[1].Keepalive = 70000 }, "wg_peers[1].keepalive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := servicesSample()
			tc.mutate(c)
			c.Normalize()
			e := onlyErr(t, c)
			if e.Path != tc.path {
				t.Fatalf("path %q (%s), want %q", e.Path, e.Message, tc.path)
			}
		})
	}
}

func TestServices_TwoTunnelsSamePort(t *testing.T) {
	c := servicesSample()
	priv, pub := testKeys(9)
	c.Interfaces = append(c.Interfaces, Interface{ID: "ifwg0002", Name: "Sites", Kind: "wireguard", IPv4Mode: "static",
		IPv4: "10.67.0.1/24", WGListenPort: 51820, WGPrivateKey: priv, WGPublicKey: pub})
	c.Normalize()
	if e := onlyErr(t, c); e.Path != "interfaces[6].wg_listen_port" {
		t.Fatalf("%+v", e)
	}
}

func TestWGPublicKey_KnownVector(t *testing.T) {
	// RFC 7748 §6.1 Alice.
	priv := "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="
	pub, err := WGPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if pub != "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=" {
		t.Fatalf("public key %s", pub)
	}
}

func TestGenerateWGKey(t *testing.T) {
	a, err := GenerateWGKey()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateWGKey()
	raw, _ := base64.StdEncoding.DecodeString(a)
	if len(raw) != 32 || a == b {
		t.Fatalf("keys %q %q", a, b)
	}
	if raw[0]&7 != 0 || raw[31]&0x80 != 0 || raw[31]&0x40 == 0 {
		t.Fatal("private key not clamped like wg genkey")
	}
}

func TestEnsureWGKeys(t *testing.T) {
	c := servicesSample()
	in := c.InterfaceByID("ifwg0001")
	in.WGPrivateKey, in.WGPublicKey = "", ""
	if err := EnsureWGKeys(c); err != nil {
		t.Fatal(err)
	}
	if in.WGPrivateKey == "" || in.WGPublicKey == "" {
		t.Fatal("keys not generated")
	}
	want, _ := WGPublicKey(in.WGPrivateKey)
	if in.WGPublicKey != want {
		t.Fatal("public key does not match the private key")
	}
	// An existing key is kept; the public key is always recomputed.
	old := in.WGPrivateKey
	in.WGPublicKey = "forged"
	_ = EnsureWGKeys(c)
	if in.WGPrivateKey != old || in.WGPublicKey != want {
		t.Fatal("existing key replaced or public key not recomputed")
	}
}

func TestServices_RedactedAndKeep(t *testing.T) {
	c := servicesSample()
	r := c.Redacted()
	b, _ := json.Marshal(r)
	s := string(b)
	if strings.Contains(s, c.Interfaces[5].WGPrivateKey) || strings.Contains(s, c.WGPeers[0].PresharedKey) {
		t.Fatal("secret leaked in redacted config")
	}
	if !r.Interfaces[5].WGPrivateKeySet || !r.WGPeers[0].PresharedKeySet || r.WGPeers[1].PresharedKeySet {
		t.Fatal("secret flags wrong")
	}
	if r.Interfaces[5].WGPublicKey == "" {
		t.Fatal("public key must stay visible")
	}
	r.KeepSecretsFrom(c)
	if r.Interfaces[5].WGPrivateKey != c.Interfaces[5].WGPrivateKey || r.WGPeers[0].PresharedKey != c.WGPeers[0].PresharedKey {
		t.Fatal("secrets not restored")
	}
	if r.Interfaces[5].WGPrivateKeySet || r.WGPeers[0].PresharedKeySet {
		t.Fatal("flags must not be stored")
	}
}

var dnsPaths = DNSPaths{HostsDir: "/run/znas-sdn-dns/hosts.d", QueryLog: "/run/znas-sdn-dns/queries.log", Blocklist: "/var/lib/znas-sdn/blocklist.hosts"}

// Advanced metrics log every query (to a file in RAM the portal reads);
// blocklists and blocked domains are one hosts file the DNS server reads.
func TestRenderDNS_MetricsAndBlocklists(t *testing.T) {
	c := servicesSample()
	got := RenderDNS(c, dnsPaths)
	for _, unwanted := range []string{"log-queries", "addn-hosts"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("%s without metrics/lists:\n%s", unwanted, got)
		}
	}
	c.DNS.Metrics = true
	c.DNS.Blocklists = []DNSBlocklist{{ID: "bl000001", URL: "https://example.com/hosts", Enabled: false}}
	got = RenderDNS(c, dnsPaths)
	for _, want := range []string{"\nlog-queries=extra\n", "\nlog-async=50\n", "\nlog-facility=/run/znas-sdn-dns/queries.log\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "log-facility=-") || strings.Contains(got, "addn-hosts") {
		t.Errorf("one log place; a disabled list blocks nothing:\n%s", got)
	}
	c.DNS.Blocklists[0].Enabled = true
	if got := RenderDNS(c, dnsPaths); !strings.Contains(got, "\naddn-hosts=/var/lib/znas-sdn/blocklist.hosts\n") {
		t.Errorf("enabled list not read:\n%s", got)
	}
	c.DNS.Blocklists = nil
	c.DNS.Deny = []string{"ads.example.com"}
	if got := RenderDNS(c, dnsPaths); !strings.Contains(got, "\naddn-hosts=") {
		t.Errorf("blocked domains alone need the file too:\n%s", got)
	}
}

func TestDNS_BlocklistValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(d *DNSSettings)
		path   string
	}{
		{"list not a URL", func(d *DNSSettings) { d.Blocklists = []DNSBlocklist{{ID: "a", URL: "hosts.txt", Enabled: true}} }, "dns.blocklists[0].url"},
		{"list ftp", func(d *DNSSettings) { d.Blocklists = []DNSBlocklist{{ID: "a", URL: "ftp://x.org/l", Enabled: true}} }, "dns.blocklists[0].url"},
		{"list twice", func(d *DNSSettings) {
			d.Blocklists = []DNSBlocklist{{ID: "a", URL: "https://x.org/l", Enabled: true}, {ID: "b", URL: "https://x.org/l", Enabled: true}}
		}, "dns.blocklists[1].url"},
		{"bad allowed domain", func(d *DNSSettings) { d.Allow = []string{"not a domain"} }, "dns.allow"},
		{"bad blocked domain", func(d *DNSSettings) { d.Deny = []string{"bad_domain!"} }, "dns.deny"},
	}
	for _, tc := range cases {
		c := servicesSample()
		tc.mutate(&c.DNS)
		c.Normalize()
		e := onlyErr(t, c)
		if e.Path != tc.path {
			t.Errorf("%s: path %q (%s), want %q", tc.name, e.Path, e.Message, tc.path)
		}
	}
	c := servicesSample()
	c.DNS.Allow = []string{" Ads.Example.COM. ", "ads.example.com"}
	c.DNS.Blocklists = []DNSBlocklist{{URL: " https://x.org/l ", Enabled: true}}
	c.Normalize()
	if len(c.DNS.Allow) != 1 || c.DNS.Allow[0] != "ads.example.com" || c.DNS.Blocklists[0].URL != "https://x.org/l" || c.DNS.Blocklists[0].ID == "" {
		t.Fatalf("normalized %+v %+v", c.DNS.Allow, c.DNS.Blocklists)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

// allDHCP: every network's DHCP config, in the order of c.DHCP.
func allDHCP(c *Config) string {
	m := RenderDHCP(c, "/x")
	var b strings.Builder
	for _, d := range c.DHCP {
		b.WriteString(m[d.Interface])
	}
	return b.String()
}

// One DNS server for every network; one DHCP server per network, each
// with its own lease file, domain and options.
func TestRenderDNSAndDHCP(t *testing.T) {
	c := servicesSample()
	golden(t, "dns.conf", RenderDNS(c, dnsPaths))
	m := RenderDHCP(c, "/var/lib/misc")
	if len(m) != 2 {
		t.Fatalf("one config per network with DHCP on: %v", m)
	}
	golden(t, "dhcp-if000800.conf", m["if000800"])
	golden(t, "dhcp-if000700.conf", m["if000700"])
}

// Names of every network reach the one DNS server: DHCP names through the
// watched folder (written from the lease files), reserved names directly,
// each in its network's domain, all answered locally.
func TestRenderDNS_EveryNetworksNames(t *testing.T) {
	c := servicesSample()
	c.DHCP[1].Domain = "iot.chezmoi.lan"
	c.Normalize()
	got := RenderDNS(c, DNSPaths{HostsDir: "/h"})
	for _, want := range []string{
		"hostsdir=/h\n",
		"local=/chezmoi.lan/\n",
		"local=/iot.chezmoi.lan/\n",
		"host-record=plex.chezmoi.lan,plex,10.128.8.8\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "dhcp-range") || strings.Contains(got, "dhcp-leasefile") {
		t.Errorf("DHCP in the DNS server:\n%s", got)
	}
	m := RenderDHCP(c, "/l")
	if !strings.Contains(m["if000700"], "\ndomain=iot.chezmoi.lan\n") || !strings.Contains(m["if000800"], "\ndomain=chezmoi.lan\n") {
		t.Errorf("each network hands out its own domain:\n%s\n%s", m["if000800"], m["if000700"])
	}
	if !strings.Contains(m["if000800"], "\ndhcp-leasefile=/l/znas-sdn-if000800.leases\n") || !strings.Contains(m["if000800"], "\nport=0\n") {
		t.Errorf("own lease file, no DNS:\n%s", m["if000800"])
	}
}

func TestRenderDnsmasq_NothingEnabled(t *testing.T) {
	c := servicesSample()
	c.DNS.Enabled = false
	for i := range c.DHCP {
		c.DHCP[i].Enabled = false
	}
	if got := RenderDNS(c, DNSPaths{HostsDir: "/h"}); got != "" {
		t.Fatalf("expected no DNS config, got:\n%s", got)
	}
	if got := RenderDHCP(c, "/x"); len(got) != 0 {
		t.Fatalf("expected no DHCP config, got:\n%v", got)
	}
}

func TestRenderDnsmasq_DHCPOnlyDisablesDNS(t *testing.T) {
	c := servicesSample()
	c.DNS.Enabled = false
	if got := RenderDNS(c, DNSPaths{HostsDir: "/h"}); got != "" {
		t.Fatalf("DNS must be off:\n%s", got)
	}
	got := allDHCP(c)
	if strings.Contains(got, "option:dns-server,10.128.8.1") {
		t.Fatal("must not hand out a DNS server that does not answer")
	}
}

func TestDHCP_DNSServersDefaultWhenDNSOff(t *testing.T) {
	c := servicesSample()
	c.DNS.Enabled = false
	c.Normalize()
	if e := onlyErr(t, c); e.Path != "dhcp[0].dns_servers" {
		t.Fatalf("%+v", e)
	}
}

func TestRenderOwned_WireGuard(t *testing.T) {
	c := servicesSample()
	got := RenderOwned(*c.InterfaceByID("ifwg0001"))
	for _, want := range []string{
		"auto wg-ifwg0001\niface wg-ifwg0001 inet static\n",
		"pre-up ip link add dev wg-ifwg0001 type wireguard",
		"pre-up wg setconf wg-ifwg0001 /etc/wireguard/znas-ifwg0001.conf",
		"address 10.66.0.1/24",
		"mtu 1420",
		"post-up ip route replace 10.40.0.0/24 dev wg-ifwg0001",
		"post-down ip link del dev wg-ifwg0001",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "10.66.0.3/32 dev") {
		t.Fatal("peer addresses inside the tunnel network need no route")
	}
}

func TestWGConf(t *testing.T) {
	c := servicesSample()
	got := WGConf(c, "ifwg0001")
	for _, want := range []string{
		"[Interface]\nPrivateKey = " + c.Interfaces[5].WGPrivateKey + "\nListenPort = 51820\n",
		"[Peer]\nPublicKey = " + c.WGPeers[0].PublicKey + "\nPresharedKey = " + c.WGPeers[0].PresharedKey + "\nAllowedIPs = 10.66.0.2/32\n",
		"AllowedIPs = 10.66.0.3/32, 10.40.0.0/24\nPersistentKeepalive = 25\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	// A name would make `wg setconf` (and boot) wait for DNS; the gateway
	// monitor sets it instead. An address needs no lookup and stays.
	if strings.Contains(got, "vpn.example.com") {
		t.Fatalf("name endpoint in the key file:\n%s", got)
	}
	c.WGPeers[1].Endpoint = "203.0.113.9:51820"
	if got := WGConf(c, "ifwg0001"); !strings.Contains(got, "Endpoint = 203.0.113.9:51820\n") {
		t.Fatalf("address endpoint dropped:\n%s", got)
	}
	c.WGPeers[1].Endpoint = "vpn.example.com:51820"
	c.WGPeers[0].Enabled = false
	if strings.Contains(WGConf(c, "ifwg0001"), c.WGPeers[0].PublicKey) {
		t.Fatal("disabled peer must not be configured")
	}
}

func TestCompile_ServicesAllowedOnTheirInterfaces(t *testing.T) {
	got, err := Compile(servicesSample(), testEnv)
	if err != nil {
		t.Fatal(err)
	}
	in := chainBody(got, "input")
	for _, want := range []string{
		`iifname "br-enp2s0-v800" udp dport 67 accept comment "svc:dhcp"`,
		`iifname "enp2s0-v700" udp dport 67 accept comment "svc:dhcp"`,
		`iifname "br-enp2s0-v800" meta l4proto { tcp, udp } th dport 53 accept comment "svc:dns"`,
	} {
		if !strings.Contains(in, want) {
			t.Fatalf("missing %q in input:\n%s", want, in)
		}
	}
	if strings.Contains(in, `"enp2s0-v700" meta l4proto { tcp, udp } th dport 53 accept`) {
		t.Fatal("DNS is not served on VLAN700")
	}
	// dnsmasq listens on VLAN700 for DHCP and would answer DNS there too.
	nodns := `iifname "enp2s0-v700" ip daddr 10.128.7.1 meta l4proto { tcp, udp } th dport 53 drop comment "svc:nodns"`
	if !strings.Contains(in, nodns) {
		t.Fatalf("missing %q", nodns)
	}
	mon := servicesSample()
	mon.Settings.Mode = "monitor"
	mg, _ := Compile(mon, testEnv)
	if !strings.Contains(chainBody(mg, "input"), nodns) {
		t.Fatal("the DNS-off drop must hold in monitor mode too")
	}
	if strings.Index(in, "svc:dhcp") > strings.Index(in, "jump any_in") {
		t.Fatal("service allows must come before the user rules")
	}
	if !strings.Contains(got, `iifname "wg-ifwg0001" jump in_ifwg0001`) {
		t.Fatal("the tunnel must be a filtered interface")
	}
}

func TestSummarize_Services(t *testing.T) {
	prev := servicesSample()
	next := servicesSample()
	next.DHCP[1].Enabled = false
	next.DNS.Upstreams = []string{"8.8.8.8"}
	_, pub := testKeys(7)
	next.WGPeers = append(next.WGPeers, WGPeer{ID: "peer0003", Tunnel: "ifwg0001", Name: "Laptop", Enabled: true, PublicKey: pub, AllowedIPs: []string{"10.66.0.4/32"}})
	got := Summarize(prev, next)
	for _, want := range []string{"DHCP on VLAN700 off", "DNS edited", "+1 WireGuard peer"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q lacks %q", got, want)
		}
	}
}

// Routes and NTP servers go to every client of the network. A client that
// gets classless routes (option 121, and 249 for Windows) ignores the
// router option (RFC 3442): the default route is always in the list.
// A reserved address can get its own gateway, DNS servers and lease time.
func TestRenderDnsmasq_DHCPExtras(t *testing.T) {
	c := servicesSample()
	c.DHCP[0].Routes = []DHCPRoute{{Network: "10.20.0.0/16", Via: "10.128.8.254"}, {Network: "172.16.5.0/24", Via: "10.128.8.253"}}
	c.DHCP[0].NTPServers = []string{"10.128.8.1", "162.159.200.1"}
	c.DHCP[0].Reservations = append(c.DHCP[0].Reservations,
		DHCPReservation{MAC: "aa:bb:cc:dd:ee:02", IP: "10.128.8.9", Hostname: "cam", Gateway: "10.128.8.254", DNSServers: []string{"9.9.9.9", "1.1.1.1"}, LeaseHours: 24},
		DHCPReservation{MAC: "aa:bb:cc:dd:ee:03", IP: "10.128.8.10", LeaseHours: 168})
	c.Normalize()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	got := allDHCP(c)
	for _, want := range []string{
		"dhcp-option=tag:if000800,option:ntp-server,10.128.8.1,162.159.200.1\n",
		"dhcp-option=tag:if000800,option:classless-static-route,10.20.0.0/16,10.128.8.254,172.16.5.0/24,10.128.8.253,0.0.0.0/0,10.128.8.1\n",
		"dhcp-option=tag:if000800,249,10.20.0.0/16,10.128.8.254,172.16.5.0/24,10.128.8.253,0.0.0.0/0,10.128.8.1\n",
		"dhcp-host=aa:bb:cc:dd:ee:01,10.128.8.8,plex\n",
		"dhcp-host=aa:bb:cc:dd:ee:02,set:h-aabbccddee02,10.128.8.9,cam,24h\n",
		"dhcp-option=tag:h-aabbccddee02,option:router,10.128.8.254\n",
		"dhcp-option=tag:h-aabbccddee02,option:dns-server,9.9.9.9,1.1.1.1\n",
		"dhcp-option=tag:h-aabbccddee02,option:classless-static-route,10.20.0.0/16,10.128.8.254,172.16.5.0/24,10.128.8.253,0.0.0.0/0,10.128.8.254\n",
		"dhcp-option=tag:h-aabbccddee02,249,10.20.0.0/16,10.128.8.254,172.16.5.0/24,10.128.8.253,0.0.0.0/0,10.128.8.254\n",
		"dhcp-host=aa:bb:cc:dd:ee:03,10.128.8.10,168h\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "tag:h-aabbccddee03") {
		t.Errorf("a lease time alone needs no host tag:\n%s", got)
	}
	// without routes nothing classless is sent: the router option does the job
	if strings.Contains(allDHCP(servicesSample()), "classless") {
		t.Error("classless routes sent without routes")
	}
}

// Excluded addresses split the range into the pools dnsmasq hands out.
func TestDHCPPools(t *testing.T) {
	d := DHCPServer{RangeStart: "10.128.8.100", RangeEnd: "10.128.8.150",
		Exclude: []string{"10.128.8.120-10.128.8.129", "10.128.8.140", "10.128.8.125", "10.128.8.100"}}
	var got []string
	for _, p := range d.Pools() {
		got = append(got, p[0].String()+"-"+p[1].String())
	}
	want := "10.128.8.101-10.128.8.119 10.128.8.130-10.128.8.139 10.128.8.141-10.128.8.150"
	if strings.Join(got, " ") != want {
		t.Fatalf("pools %v, want %s", got, want)
	}
	d.Exclude = []string{"10.128.8.100-10.128.8.150"}
	if p := d.Pools(); len(p) != 0 {
		t.Fatalf("whole range excluded: %v", p)
	}
}

func TestRenderDHCP_ExclusionsAndAddressCheck(t *testing.T) {
	c := servicesSample()
	c.DHCP[0].Exclude = []string{"10.128.8.120-10.128.8.129"}
	c.Normalize()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	m := RenderDHCP(c, "/x")
	for _, want := range []string{
		"dhcp-range=set:if000800,10.128.8.100,10.128.8.119,255.255.255.0,12h\n",
		"dhcp-range=set:if000800,10.128.8.130,10.128.8.199,255.255.255.0,12h\n",
	} {
		if !strings.Contains(m["if000800"], want) {
			t.Errorf("missing %q in:\n%s", want, m["if000800"])
		}
	}
	if strings.Contains(m["if000800"]+m["if000700"], "no-ping") {
		t.Error("the address check is on unless turned off")
	}
	// per network: off on one, still on on the other
	c.DHCP[0].NoPing = true
	m = RenderDHCP(c, "/x")
	if !strings.Contains(m["if000800"], "\nno-ping\n") || strings.Contains(m["if000700"], "no-ping") {
		t.Errorf("address check per network:\n%s\n%s", m["if000800"], m["if000700"])
	}
}

func TestWGEndpointName(t *testing.T) {
	for ep, want := range map[string]bool{
		"vpn.example.com:51820": true, "203.0.113.9:51820": false, "[2001:db8::1]:51820": false, "": false, "nonsense": false,
	} {
		if got := WGEndpointIsName(ep); got != want {
			t.Errorf("%q: got %v", ep, got)
		}
	}
}

// A name follows the device: no address on its dhcp-host line, and one device
// or one name can't be listed twice.
func TestDHCPNames(t *testing.T) {
	in := Interface{ID: "a", Name: "LAN", Kind: "physical", Device: "eth1", Role: "lan", IPv4Mode: "static", IPv4: "10.0.0.1/24"}
	base := func() *Config {
		return &Config{Interfaces: []Interface{in}, DHCP: []DHCPServer{{Interface: "a", Enabled: true, RangeStart: "10.0.0.50", RangeEnd: "10.0.0.59", LeaseHours: 12,
			Reservations: []DHCPReservation{{MAC: "aa:00:00:00:00:01", IP: "10.0.0.9", Hostname: "printer"}},
			Names:        []DHCPName{{MAC: "AA:00:00:00:00:02 ", Hostname: "tablet"}}}}}
	}
	c := base()
	c.Normalize()
	if got := RenderDHCP(c, "/l")["a"]; !strings.Contains(got, "dhcp-host=aa:00:00:00:00:02,tablet\n") {
		t.Fatalf("rendered:\n%s", got)
	}
	if e := c.checkDHCP(c.DHCP[0], &c.Interfaces[0], map[string]bool{}, map[string]bool{"a": true}); e != "" {
		t.Fatalf("valid config refused: %s", e)
	}
	for name, change := range map[string]func(*DHCPServer){
		"reserved MAC":  func(d *DHCPServer) { d.Names[0].MAC = "aa:00:00:00:00:01" },
		"reserved name": func(d *DHCPServer) { d.Names[0].Hostname = "PRINTER" },
		"bad name":      func(d *DHCPServer) { d.Names[0].Hostname = "a.b" },
		"bad MAC":       func(d *DHCPServer) { d.Names[0].MAC = "nope" },
	} {
		c := base()
		c.Normalize()
		change(&c.DHCP[0])
		if e := c.checkDHCP(c.DHCP[0], &c.Interfaces[0], map[string]bool{}, map[string]bool{"a": true}); !strings.HasPrefix(e, "names[0].") {
			t.Errorf("%s: %q", name, e)
		}
	}
}
