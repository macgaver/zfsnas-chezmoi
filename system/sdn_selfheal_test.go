package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"zfsnas/internal/sdn"
)

const shPeer = "PEERKEY="

func shConfig() *sdn.Config {
	return &sdn.Config{
		Interfaces: []sdn.Interface{{ID: "ifwg0001", Name: "Sites", Kind: "wireguard", Device: "wg-ifwg0001", IPv4Mode: "static", IPv4: "10.66.0.2/24", WGPrivateKey: "PRIV", WGListenPort: 51820}},
		WGPeers:    []sdn.WGPeer{{ID: "p1", Tunnel: "ifwg0001", Name: "Central", Enabled: true, PublicKey: shPeer, AllowedIPs: []string{"10.66.0.1/32"}, Endpoint: "vpn.example.com:51820", Keepalive: 59}},
	}
}

// shEnv: the device exists and is up, the key file is current, DNS answers ips.
func shEnv(t *testing.T, c *sdn.Config, up bool, ips ...string) (*recorder, *sdnHealer) {
	t.Helper()
	rec, _ := sdnTestEnv(t)
	oldLookup := sdnLookupIP
	t.Cleanup(func() { sdnLookupIP = oldLookup })
	sdnLookupIP = func(context.Context, string) ([]string, error) { return ips, nil }
	_ = os.MkdirAll(sdnWGDir, 0700)
	_ = os.WriteFile(sdnWGPath("ifwg0001"), []byte(sdn.WGConf(c, "ifwg0001")), 0600)
	shLink(t, "wg-ifwg0001", up)
	return rec, newSDNHealer()
}

func shLink(t *testing.T, dev string, up bool) {
	t.Helper()
	d := filepath.Join(sdnSysClassNet, dev)
	_ = os.MkdirAll(d, 0755)
	v := "0x90"
	if up {
		v = "0x91"
	}
	_ = os.WriteFile(filepath.Join(d, "flags"), []byte(v+"\n"), 0644)
}

func shPeerState(rec *recorder, endpoint string, handshake int64) {
	rec.out = map[string]string{
		"wg show wg-ifwg0001 endpoints":         shPeer + "\t" + endpoint + "\n",
		"wg show wg-ifwg0001 latest-handshakes": shPeer + "\t" + strconv.FormatInt(handshake, 10) + "\n",
	}
}

var shNow = time.Unix(1_800_000_000, 0)

// The boot case: no address at startup, then DNS works. The keepalive is
// turned off and on, otherwise WireGuard stays silent after setting the address.
func TestHeal_SetsEndpointWhenDNSAnswers(t *testing.T) {
	c := shConfig()
	rec, h := shEnv(t, c, true, "203.0.113.5")
	shPeerState(rec, "(none)", 0)
	st := h.cycle(c, shNow)
	off := rec.index("wg set wg-ifwg0001 peer " + shPeer + " persistent-keepalive off")
	set := rec.index("wg set wg-ifwg0001 peer " + shPeer + " endpoint 203.0.113.5:51820 persistent-keepalive 59")
	if off < 0 || set < off {
		t.Fatalf("endpoint not set: %v", rec.cmds)
	}
	if n := st.Tunnels["ifwg0001"].Peers[shPeer]; n.Note != "connecting" || n.Address != "203.0.113.5:51820" {
		t.Fatalf("state %+v", n)
	}
}

func TestHeal_DNSFailureIsRetried(t *testing.T) {
	c := shConfig()
	rec, h := shEnv(t, c, true)
	shPeerState(rec, "(none)", 0)
	sdnLookupIP = func(context.Context, string) ([]string, error) { return nil, errors.New("no such host") }
	st := h.cycle(c, shNow)
	if n := st.Tunnels["ifwg0001"].Peers[shPeer]; n.Note != "waiting_dns" {
		t.Fatalf("state %+v", n)
	}
	if rec.index("wg set") >= 0 {
		t.Fatalf("set without an address: %v", rec.cmds)
	}
	sdnLookupIP = func(context.Context, string) ([]string, error) { return []string{"203.0.113.5"}, nil }
	h.cycle(c, shNow.Add(10*time.Second))
	if rec.count("endpoint 203.0.113.5:51820") == 0 {
		t.Fatalf("not retried: %v", rec.cmds)
	}
}

// The other site's address changed: the old one stops answering.
func TestHeal_FollowsAddressChange(t *testing.T) {
	c := shConfig()
	rec, h := shEnv(t, c, true, "203.0.113.5")
	shPeerState(rec, "198.51.100.1:51820", shNow.Unix()-400)
	st := h.cycle(c, shNow)
	if rec.count("endpoint 203.0.113.5:51820") == 0 {
		t.Fatalf("not followed: %v", rec.cmds)
	}
	if n := st.Tunnels["ifwg0001"].Peers[shPeer]; n.Previous != "198.51.100.1:51820" || n.Changed.IsZero() {
		t.Fatalf("state %+v", n)
	}
}

// A connected peer is left alone, even if DNS says something else: the peer
// may be reaching us from another address.
func TestHeal_HealthyPeerUntouched(t *testing.T) {
	c := shConfig()
	rec, h := shEnv(t, c, true, "203.0.113.5")
	shPeerState(rec, "198.51.100.1:51820", shNow.Unix()-30)
	sdnLookupIP = func(context.Context, string) ([]string, error) { t.Fatal("looked up"); return nil, nil }
	h.cycle(c, shNow)
	if rec.index("wg set") >= 0 {
		t.Fatalf("touched: %v", rec.cmds)
	}
}

// Address unchanged, other side down for a while: WireGuard gives up after
// 90 s, so it is nudged — at most once a minute.
func TestHeal_NudgesSamePeerOncePerMinute(t *testing.T) {
	c := shConfig()
	rec, h := shEnv(t, c, true, "203.0.113.5")
	shPeerState(rec, "203.0.113.5:51820", shNow.Unix()-400)
	h.cycle(c, shNow)
	first := rec.count("persistent-keepalive off")
	h.cycle(c, shNow.Add(10*time.Second))
	if first != 1 || rec.count("persistent-keepalive off") != 1 {
		t.Fatalf("nudges: %d %v", first, rec.cmds)
	}
	h.cycle(c, shNow.Add(70*time.Second))
	if rec.count("persistent-keepalive off") != 2 {
		t.Fatalf("no second nudge: %v", rec.cmds)
	}
}

// A device we only listen on has no endpoint: nothing to look up or nudge.
func TestHeal_ListeningPeerIgnored(t *testing.T) {
	c := shConfig()
	c.WGPeers[0].Endpoint = ""
	rec, h := shEnv(t, c, true)
	shPeerState(rec, "(none)", 0)
	h.cycle(c, shNow)
	if rec.index("wg set") >= 0 {
		t.Fatalf("touched: %v", rec.cmds)
	}
}

// The state a failed boot leaves: device there, link down. It is removed
// first, or ifup's "ip link add" fails for ever. Retries back off.
func TestHeal_BringsDownTunnelBack(t *testing.T) {
	c := shConfig()
	rec, h := shEnv(t, c, false, "203.0.113.5")
	shPeerState(rec, "(none)", 0)
	h.cycle(c, shNow)
	del, up := rec.index("ip link del dev wg-ifwg0001"), rec.index("ifup wg-ifwg0001")
	if del < 0 || up < del {
		t.Fatalf("not repaired in order: %v", rec.cmds)
	}
	h.cycle(c, shNow.Add(5*time.Second))
	if rec.count("ifup wg-ifwg0001") != 1 {
		t.Fatalf("no backoff: %v", rec.cmds)
	}
	h.cycle(c, shNow.Add(31*time.Second))
	if rec.count("ifup wg-ifwg0001") != 2 {
		t.Fatalf("no retry: %v", rec.cmds)
	}
}

func TestHeal_DisabledTunnelStaysDown(t *testing.T) {
	c := shConfig()
	c.Interfaces[0].Disabled = true
	rec, h := shEnv(t, c, false, "203.0.113.5")
	h.cycle(c, shNow)
	if rec.index("ifup") >= 0 {
		t.Fatalf("brought up: %v", rec.cmds)
	}
}

// Up but the kernel lost its peers: reloaded from the key file, no bounce.
func TestHeal_ReloadsMissingPeers(t *testing.T) {
	c := shConfig()
	rec, h := shEnv(t, c, true, "203.0.113.5")
	rec.out = map[string]string{"wg show wg-ifwg0001 endpoints": "", "wg show wg-ifwg0001 latest-handshakes": ""}
	h.cycle(c, shNow)
	if rec.index("wg syncconf wg-ifwg0001 "+sdnWGPath("ifwg0001")) < 0 || rec.index("ifup") >= 0 {
		t.Fatalf("not reloaded: %v", rec.cmds)
	}
}

// A key file from an older version still names the host: rewritten, so the
// next boot does not wait for DNS.
func TestHeal_RewritesOldKeyFile(t *testing.T) {
	c := shConfig()
	rec, h := shEnv(t, c, true, "203.0.113.5")
	shPeerState(rec, "203.0.113.5:51820", shNow.Unix()-5)
	_ = os.WriteFile(sdnWGPath("ifwg0001"), []byte("[Interface]\nEndpoint = vpn.example.com:51820\n"), 0600)
	h.cycle(c, shNow)
	if b, _ := os.ReadFile(sdnWGPath("ifwg0001")); string(b) != sdn.WGConf(c, "ifwg0001") {
		t.Fatalf("not rewritten: %s", b)
	}
}

func shDDNS(t *testing.T) (*recorder, *sdnHealer, *sdn.Config) {
	c := &sdn.Config{
		Interfaces: []sdn.Interface{{ID: "ifwan", Name: "WAN", Kind: "physical", Device: "ppp0", Role: "wan"}},
		Gateways:   []sdn.Gateway{{ID: "gw1", Name: "ISP", Interface: "ifwan"}},
		DDNS:       []sdn.DDNSEntry{{ID: "d1", Enabled: true, Gateway: "gw1", Provider: "custom", Server: "x", Hostnames: []string{"home.example.com"}, Password: "s"}},
	}
	rec, _ := sdnTestEnv(t)
	_ = os.MkdirAll(filepath.Dir(sdnDDClientConf), 0755)
	_ = os.WriteFile(sdnDDClientConf, []byte(sdn.RenderDDClient(c)), 0600)
	rec.out = map[string]string{"ip -4 -j addr show dev " + c.Interfaces[0].L3Device(): `[{"addr_info":[{"local":"203.0.113.7"}]}]`}
	return rec, newSDNHealer(), c
}

func shCache(status, ip string) {
	_ = os.WriteFile(sdnDDClientCache, []byte("ipv4="+ip+",status-ipv4="+status+",mtime=1 home.example.com\n"), 0600)
}

const shRestart = "systemctl restart " + sdnDDNSUnitName

// New address: told to ddclient at once, not at its next 5-minute check;
// repeated with growing pauses until the provider has it.
func TestHeal_DDNSFollowsNewAddress(t *testing.T) {
	rec, h, c := shDDNS(t)
	shCache("good", "198.51.100.1")
	h.ddns(c, shNow)
	if rec.count(shRestart) != 1 {
		t.Fatalf("no update: %v", rec.cmds)
	}
	h.ddns(c, shNow.Add(30*time.Second))
	if rec.count(shRestart) != 1 {
		t.Fatalf("no backoff: %v", rec.cmds)
	}
	h.ddns(c, shNow.Add(71*time.Second))
	if rec.count(shRestart) != 2 {
		t.Fatalf("no retry: %v", rec.cmds)
	}
	h.ddns(c, shNow.Add(122*time.Second))
	if rec.count(shRestart) != 2 {
		t.Fatalf("pause did not grow: %v", rec.cmds)
	}
	shCache("good", "203.0.113.7")
	h.ddns(c, shNow.Add(time.Hour))
	if rec.count(shRestart) != 2 {
		t.Fatalf("restarted when in sync: %v", rec.cmds)
	}
}

func TestHeal_DDNSRewritesOldConfig(t *testing.T) {
	rec, h, c := shDDNS(t)
	shCache("good", "203.0.113.7")
	_ = os.WriteFile(sdnDDClientConf, []byte("old"), 0600)
	h.ddns(c, shNow)
	if b, _ := os.ReadFile(sdnDDClientConf); string(b) != sdn.RenderDDClient(c) || rec.count(shRestart) != 1 {
		t.Fatalf("not rewritten: %s %v", b, rec.cmds)
	}
	if _, err := os.Stat(sdnDDClientCache); err != nil {
		t.Fatalf("cache dropped: the provider would be called for nothing")
	}
}

func TestHeal_DDNSRetriesSoftFailure(t *testing.T) {
	rec, h, c := shDDNS(t)
	shCache("noconnect", "203.0.113.7")
	h.ddns(c, shNow)
	if rec.count(shRestart) != 1 {
		t.Fatalf("no retry: %v", rec.cmds)
	}
}

// A refused login is not helped by asking more often: ddclient's own 5-minute
// check goes on, and the provider does not block the account for abuse.
func TestHeal_DDNSLeavesRefusalsAlone(t *testing.T) {
	rec, h, c := shDDNS(t)
	shCache("badauth", "198.51.100.1")
	h.ddns(c, shNow)
	if rec.count(shRestart) != 0 {
		t.Fatalf("hammered: %v", rec.cmds)
	}
}

// PPPoE not up yet: no address to send, nothing to do.
func TestHeal_DDNSWaitsForAddress(t *testing.T) {
	rec, h, c := shDDNS(t)
	rec.out = map[string]string{}
	shCache("good", "198.51.100.1")
	h.ddns(c, shNow)
	if rec.count(shRestart) != 0 {
		t.Fatalf("restarted: %v", rec.cmds)
	}
}

func (r *recorder) count(sub string) int {
	n := 0
	for _, c := range r.cmds {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}
