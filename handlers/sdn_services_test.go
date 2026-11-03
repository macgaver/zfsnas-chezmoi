package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"zfsnas/internal/config"
	"zfsnas/internal/sdn"
)

func TestSDNPutDraft_GeneratesTunnelKeyOnTheBox(t *testing.T) {
	appCfg, _, st := sdnHandlerEnv(t)
	c := sdnBaseConfig()
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "ifwg0001", Name: "VPN", Kind: "wireguard", IPv4Mode: "static", IPv4: "10.66.0.1/24", WGListenPort: 51820})
	cur, _ := st.LoadDraft()
	w := httptest.NewRecorder()
	HandleSDNPutDraft(appCfg)(w, sdnReq("PUT", "/api/sdn/draft", map[string]any{"base_revision": cur.Revision, "config": c}, config.RoleAdmin))
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	d, _ := st.LoadDraft()
	in := d.Config.InterfaceByID("ifwg0001")
	if in.WGPrivateKey == "" || in.WGPublicKey == "" {
		t.Fatalf("no key generated: %+v", in)
	}
	if strings.Contains(w.Body.String(), in.WGPrivateKey) || !strings.Contains(w.Body.String(), in.WGPublicKey) {
		t.Fatal("private key leaked or public key hidden")
	}
	// Saving the redacted copy again keeps the same key.
	var view struct {
		Revision int         `json:"revision"`
		Config   *sdn.Config `json:"config"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &view)
	w = httptest.NewRecorder()
	HandleSDNPutDraft(appCfg)(w, sdnReq("PUT", "/api/sdn/draft", map[string]any{"base_revision": view.Revision, "config": view.Config}, config.RoleAdmin))
	d2, _ := st.LoadDraft()
	if d2.Config.InterfaceByID("ifwg0001").WGPrivateKey != in.WGPrivateKey {
		t.Fatal("key changed on a second save")
	}
}

func TestSDNApply_ServicesNeedTheirTools(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(c *sdn.Config)
	}{
		{"dhcp", func(c *sdn.Config) {
			c.DHCP = []sdn.DHCPServer{{Interface: "if000700", Enabled: true, RangeStart: "10.128.7.10", RangeEnd: "10.128.7.20", DNSServers: []string{"1.1.1.1"}}}
		}},
		{"wireguard", func(c *sdn.Config) {
			k, _ := sdn.GenerateWGKey()
			c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "ifwg0001", Name: "VPN", Kind: "wireguard", IPv4Mode: "static", IPv4: "10.66.0.1/24", WGListenPort: 51820, WGPrivateKey: k})
		}},
		{"ddns", func(c *sdn.Config) {
			c.Gateways = append(c.Gateways, sdn.Gateway{ID: "gwddns01", Name: "ISP", Interface: c.Interfaces[0].ID, Address: "192.168.2.1", Priority: 9})
			c.DDNS = []sdn.DDNSEntry{{ID: "dd000001", Enabled: true, Gateway: "gwddns01", Provider: "duckdns", Hostnames: []string{"home.duckdns.org"}, Password: "t"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			appCfg, _, st := sdnHandlerEnv(t)
			old1, old2, old3 := sdnDnsmasqOK, sdnWGOK, sdnDDClientOK
			sdnDnsmasqOK, sdnWGOK, sdnDDClientOK = func() bool { return false }, func() bool { return false }, func() bool { return false }
			defer func() { sdnDnsmasqOK, sdnWGOK, sdnDDClientOK = old1, old2, old3 }()
			d, _ := st.LoadDraft()
			tc.mutate(d.Config)
			d.Config.Normalize()
			if _, err := st.SaveDraft(d.Config, d.Revision, "admin"); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			HandleSDNApply(appCfg)(w, sdnReq("POST", "/api/sdn/apply", map[string]any{"auto_revert": false}, config.RoleAdmin))
			if w.Code != 400 || !strings.Contains(w.Body.String(), "install") {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
}

func TestSDNWireGuardKeys(t *testing.T) {
	w := httptest.NewRecorder()
	HandleSDNWireGuardKeys(w, sdnReq("POST", "/api/sdn/wireguard/keys", nil, config.RoleAdmin))
	var k struct {
		PrivateKey   string `json:"private_key"`
		PublicKey    string `json:"public_key"`
		PresharedKey string `json:"preshared_key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &k); err != nil || k.PrivateKey == "" || k.PresharedKey == "" {
		t.Fatalf("%s", w.Body)
	}
	if pub, _ := sdn.WGPublicKey(k.PrivateKey); pub != k.PublicKey {
		t.Fatal("pair does not match")
	}
}

// Re-enabling the Firewall keeps DHCP/DNS, WireGuard and IDS settings for
// the interfaces that are still there.
func TestSDNCarryOver_Services(t *testing.T) {
	last := sdnBaseConfig()
	k, _ := sdn.GenerateWGKey()
	last.Interfaces = append(last.Interfaces,
		sdn.Interface{ID: "if000700", Name: "VLAN700", Kind: "vlan", Parent: "enp7s0", VLANTag: 700, IPv4Mode: "static", IPv4: "10.128.7.1/24", Owned: true},
		sdn.Interface{ID: "ifwg0001", Name: "VPN", Kind: "wireguard", IPv4Mode: "static", IPv4: "10.66.0.1/24", WGListenPort: 51820, WGPrivateKey: k})
	last.DHCP = []sdn.DHCPServer{{Interface: "if000700", Enabled: true, RangeStart: "10.128.7.10", RangeEnd: "10.128.7.20"}}
	last.DNS = sdn.DNSSettings{Enabled: true, Interfaces: []string{"if000700", "ifwg0001"}}
	pub, _ := sdn.WGPublicKey(k)
	last.WGPeers = []sdn.WGPeer{{ID: "peer0001", Tunnel: "ifwg0001", Name: "Phone", Enabled: true, PublicKey: pub, AllowedIPs: []string{"10.66.0.2/32"}}}
	last.IDS = sdn.IDSSettings{Enabled: true, Interfaces: []string{"if000700", "if0mgmt0"}, AlertSeverity: 2}
	last.Normalize()

	// The wizard re-adopted only the management port: VLAN700 is gone.
	next := &sdn.Config{Version: 1, Settings: last.Settings, Interfaces: sdnBaseConfig().Interfaces}
	sdnCarryOver(last, next)
	next.Normalize()
	if next.InterfaceByID("ifwg0001") == nil || len(next.WGPeers) != 1 {
		t.Fatalf("tunnel/peers not carried: %+v %+v", next.Interfaces, next.WGPeers)
	}
	if len(next.DHCP) != 0 {
		t.Fatalf("DHCP of a removed interface carried: %+v", next.DHCP)
	}
	if !next.DNS.Enabled || strings.Join(next.DNS.Interfaces, ",") != "ifwg0001" {
		t.Fatalf("DNS %+v", next.DNS)
	}
	if !next.IDS.Enabled || strings.Join(next.IDS.Interfaces, ",") != "if0mgmt0" || next.IDS.AlertSeverity != 2 {
		t.Fatalf("IDS %+v", next.IDS)
	}
	if err := next.Validate(); err != nil {
		t.Fatal(err)
	}
}

// A carried DHCP range that no longer fits a re-addressed interface must not
// make enabling fail: it is dropped.
func TestSDNCarryOver_DropsWhatNoLongerFits(t *testing.T) {
	last := sdnBaseConfig()
	last.Interfaces = append(last.Interfaces, sdn.Interface{ID: "if000700", Name: "VLAN700", Kind: "vlan", Parent: "enp7s0", VLANTag: 700, IPv4Mode: "static", IPv4: "10.128.7.1/24", Owned: true})
	last.DHCP = []sdn.DHCPServer{{Interface: "if000700", Enabled: true, RangeStart: "10.128.7.10", RangeEnd: "10.128.7.20", DNSServers: []string{"1.1.1.1"}}}
	last.Normalize()
	next := &sdn.Config{Version: 1, Settings: last.Settings, Interfaces: append([]sdn.Interface{}, last.Interfaces...)}
	next.Interfaces[1].IPv4 = "10.99.7.1/24" // re-addressed in the wizard
	sdnCarryOver(last, next)
	next.Normalize()
	if err := next.Validate(); err != nil {
		t.Fatalf("carried config invalid: %v", err)
	}
	if len(next.DHCP) != 0 {
		t.Fatalf("stale DHCP kept: %+v", next.DHCP)
	}
}

// Re-enabling: ports adopted again keep their old ids (so rules, gateways,
// DHCP… carry over) and the interfaces the Firewall created on them (VLANs,
// PPPoE) come back.
func TestSDNReuseLastInterfaces(t *testing.T) {
	last := sdnBaseConfig()
	last.Interfaces = append(last.Interfaces,
		sdn.Interface{ID: "ifwan001", Name: "WAN", Kind: "physical", Device: "enp6s0", Role: "wan", IPv4Mode: "static", IPv4: "10.250.0.2/24", Gateway: "10.250.0.1"},
		sdn.Interface{ID: "if000700", Name: "VLAN700", Kind: "vlan", Parent: "enp7s0", VLANTag: 700, IPv4Mode: "static", IPv4: "10.128.7.1/24", Owned: true},
		sdn.Interface{ID: "ifppp001", Name: "Fibre", Kind: "pppoe", Parent: "enp6s0", Role: "wan", PPPoEUser: "u", PPPoEPassword: "p"})
	last.Normalize()
	body := []sdn.Interface{
		{ID: "new00001", Name: "enp5s0", Kind: "physical", Device: "enp5s0", Role: "lan", IPv4Mode: "dhcp"},
		// Disable gave the port its pre-Firewall (empty) addressing back.
		{ID: "new00002", Name: "WAN again", Kind: "physical", Device: "enp6s0", Role: "wan", IPv4Mode: "none"},
	}
	old := sdnDeviceExists
	sdnDeviceExists = func(d string) bool { return d == "enp7s0" || d == "enp6s0" || d == "enp5s0" }
	defer func() { sdnDeviceExists = old }()
	got := sdnReuseLastInterfaces(last, body, "", false)
	ids := []string{}
	for _, in := range got {
		ids = append(ids, in.ID)
	}
	// VLAN700's trunk port was never adopted itself: it only has to exist.
	if strings.Join(ids, ",") != "if0mgmt0,ifwan001,if000700,ifppp001" {
		t.Fatalf("ids %v", ids)
	}
	if got[1].Name != "WAN again" {
		t.Fatal("the wizard's choices win over the old ones")
	}
	if got[1].IPv4Mode != "static" || got[1].IPv4 != "10.250.0.2/24" || got[1].Gateway != "10.250.0.1" {
		t.Fatalf("Firewall addressing not restored: %+v", got[1])
	}
	if got[0].IPv4Mode != "dhcp" {
		t.Fatal("addressing chosen in the wizard must win")
	}
}
