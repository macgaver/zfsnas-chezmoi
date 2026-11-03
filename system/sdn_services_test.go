package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zfsnas/internal/sdn"
)

func withServices(c *sdn.Config) *sdn.Config {
	c = withVLAN700(c)
	c.DHCP = []sdn.DHCPServer{{Interface: "if000700", Enabled: true, RangeStart: "10.128.7.100", RangeEnd: "10.128.7.150"}}
	c.DNS = sdn.DNSSettings{Enabled: true, Interfaces: []string{"if000700"}, Domain: "lab.lan"}
	key, _ := sdn.GenerateWGKey()
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "ifwg0001", Name: "VPN", Kind: "wireguard", Role: "lan",
		IPv4Mode: "static", IPv4: "10.66.0.1/24", WGListenPort: 51820, WGPrivateKey: key})
	peer, _ := sdn.GenerateWGKey()
	pub, _ := sdn.WGPublicKey(peer)
	c.WGPeers = []sdn.WGPeer{{ID: "peer0001", Tunnel: "ifwg0001", Name: "Phone", Enabled: true, PublicKey: pub, AllowedIPs: []string{"10.66.0.2/32"}}}
	c.Normalize()
	_ = sdn.EnsureWGKeys(c)
	if err := c.Validate(); err != nil {
		panic(err)
	}
	return c
}

func TestSDNApply_StartsServices(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	next := withServices(labBase())
	if _, err := SDNApply(labBase(), next, sdnEnv); err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(sdnDnsmasqConf)
	if err != nil || !strings.Contains(string(conf), "interface=enp7s0-v700") || !strings.Contains(string(conf), "hostsdir="+sdnHostsDir) {
		t.Fatalf("DNS config not written: %v\n%s", err, conf)
	}
	dhcp, err := os.ReadFile(filepath.Join(sdnDHCPDir, "if000700.conf"))
	if err != nil || !strings.Contains(string(dhcp), "dhcp-range=set:if000700,10.128.7.100,10.128.7.150") || !strings.Contains(string(dhcp), "port=0") {
		t.Fatalf("DHCP config of the network not written: %v\n%s", err, dhcp)
	}
	wg := filepath.Join(sdnWGDir, "znas-ifwg0001.conf")
	st, err := os.Stat(wg)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("tunnel key file: %v %v", err, st)
	}
	// The key file must exist before ifup runs the stanza's "wg setconf".
	w, up := rec.index("write "+wg), rec.index("ifup wg-ifwg0001")
	if w < 0 || up < 0 || w > up {
		t.Fatalf("key file must be written before ifup: %v", rec.cmds)
	}
	if rec.index("systemctl restart "+sdnDNSUnitName) < rec.index("nft -f -") {
		t.Fatalf("dnsmasq must (re)start after the ruleset: %v", rec.cmds)
	}
	if rec.index("systemctl restart "+sdnDHCPUnitName) < rec.index("nft -f -") {
		t.Fatalf("the DHCP supervisor must start after the ruleset: %v", rec.cmds)
	}
}

// Editing one network's DHCP restarts neither DNS nor the other networks:
// the supervisor is told to look, and restarts that network only.
func TestSDNApply_DHCPEditLeavesDNSRunning(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	prev := withServices(labBase())
	if _, err := SDNApply(labBase(), prev, sdnEnv); err != nil {
		t.Fatal(err)
	}
	next := withServices(labBase())
	next.DHCP[0].LeaseHours = 24
	next.DHCP[0].NoPing = true
	rec.cmds = nil
	rec.out = map[string]string{"systemctl is-active " + sdnDNSUnitName: "active\n", "systemctl is-active " + sdnDHCPUnitName: "active\n"}
	if _, err := SDNApply(prev, next, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("systemctl restart "+sdnDNSUnitName) >= 0 {
		t.Fatalf("DNS restarted for a DHCP edit: %v", rec.cmds)
	}
	if rec.index("systemctl reload "+sdnDHCPUnitName) < 0 || rec.index("systemctl restart "+sdnDHCPUnitName) >= 0 {
		t.Fatalf("supervisor not told (or restarted): %v", rec.cmds)
	}
	if b, _ := os.ReadFile(filepath.Join(sdnDHCPDir, "if000700.conf")); !strings.Contains(string(b), "\nno-ping\n") || !strings.Contains(string(b), ",24h\n") {
		t.Fatalf("network config not updated:\n%s", b)
	}
}

func TestSDNApply_PeerChangeSyncsWithoutBounce(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	prev := withServices(labBase())
	if _, err := SDNApply(labBase(), prev, sdnEnv); err != nil {
		t.Fatal(err)
	}
	next := withServices(labBase())
	next.Interfaces[2].WGPrivateKey = prev.Interfaces[2].WGPrivateKey
	next.WGPeers[0].PublicKey = prev.WGPeers[0].PublicKey
	k, _ := sdn.GenerateWGKey()
	pub, _ := sdn.WGPublicKey(k)
	next.WGPeers = append(next.WGPeers, sdn.WGPeer{ID: "peer0002", Tunnel: "ifwg0001", Name: "Laptop", Enabled: true, PublicKey: pub, AllowedIPs: []string{"10.66.0.3/32"}})
	next.Normalize()
	_ = sdn.EnsureWGKeys(next)
	rec.cmds = nil
	rec.out = map[string]string{"systemctl is-active " + sdnDNSUnitName: "active\n"}
	if _, err := SDNApply(prev, next, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("ifup wg-ifwg0001") >= 0 || rec.index("ifdown --force wg-ifwg0001") >= 0 {
		t.Fatalf("a peer change must not bounce the tunnel: %v", rec.cmds)
	}
	if rec.index("wg syncconf wg-ifwg0001 "+filepath.Join(sdnWGDir, "znas-ifwg0001.conf")) < 0 {
		t.Fatalf("peers not synced: %v", rec.cmds)
	}
	if rec.index("systemctl restart "+sdnDNSUnitName) >= 0 {
		t.Fatalf("dnsmasq config unchanged: no restart: %v", rec.cmds)
	}
}

func TestSDNApply_SiteRouteBouncesTunnel(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	prev := withServices(labBase())
	_, _ = SDNApply(labBase(), prev, sdnEnv)
	next := withServices(labBase())
	next.Interfaces[2].WGPrivateKey = prev.Interfaces[2].WGPrivateKey
	next.WGPeers[0].PublicKey = prev.WGPeers[0].PublicKey
	next.WGPeers[0].AllowedIPs = append(next.WGPeers[0].AllowedIPs, "10.40.0.0/24")
	next.Normalize()
	_ = sdn.EnsureWGKeys(next)
	rec.cmds = nil
	if _, err := SDNApply(prev, next, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("ifup wg-ifwg0001") < 0 {
		t.Fatalf("a new network behind a peer needs its route (stanza): %v", rec.cmds)
	}
	b, _ := os.ReadFile(hostInterfacesPath)
	if !strings.Contains(string(b), "post-up ip route replace 10.40.0.0/24 dev wg-ifwg0001") {
		t.Fatalf("route missing:\n%s", b)
	}
}

func TestSDNApply_ServicesRemovedStopsAndCleans(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	prev := withServices(labBase())
	_, _ = SDNApply(labBase(), prev, sdnEnv)
	rec.cmds = nil
	if _, err := SDNApply(prev, withVLAN700(labBase()), sdnEnv); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sdnDnsmasqConf); !os.IsNotExist(err) {
		t.Fatal("DNS config must be removed")
	}
	if _, err := os.Stat(filepath.Join(sdnDHCPDir, "if000700.conf")); !os.IsNotExist(err) {
		t.Fatal("the network's DHCP config must be removed")
	}
	if _, err := os.Stat(filepath.Join(sdnWGDir, "znas-ifwg0001.conf")); !os.IsNotExist(err) {
		t.Fatal("tunnel key file must be removed")
	}
	if rec.index("systemctl stop "+sdnDNSUnitName) < 0 || rec.index("ifdown --force wg-ifwg0001") < 0 {
		t.Fatalf("dnsmasq not stopped or tunnel not down: %v", rec.cmds)
	}
}

func TestSDNBoot_WritesServiceFiles(t *testing.T) {
	_, dir := sdnTestEnv(t)
	st := sdn.Store{Dir: filepath.Join(dir, "cfg")}
	c := withServices(labBase())
	_ = os.MkdirAll(filepath.Join(sdnSysClassNet, "enp7s0"), 0755)
	if err := st.SaveConfirmed(c); err != nil {
		t.Fatal(err)
	}
	_ = st.SaveState(sdn.State{Enabled: true})
	if err := SDNBoot(st, sdnEnv); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sdnDnsmasqConf); err != nil {
		t.Fatal("boot must write the DNS config (fresh /etc on the appliance)")
	}
	if _, err := os.Stat(filepath.Join(sdnDHCPDir, "if000700.conf")); err != nil {
		t.Fatal("boot must write each network's DHCP config")
	}
	if _, err := os.Stat(filepath.Join(sdnWGDir, "znas-ifwg0001.conf")); err != nil {
		t.Fatal("boot must write the tunnel key file before networking")
	}
}

func TestSDNDHCPLeases(t *testing.T) {
	_, dir := sdnTestEnv(t)
	_ = dir
	// the network's own lease file, and what is left of the single file of
	// earlier versions
	_ = os.MkdirAll(sdnLeaseDir, 0755)
	_ = os.WriteFile(sdn.DHCPLeaseFile(sdnLeaseDir, "if000700"), []byte("1767225600 aa:bb:cc:dd:ee:01 10.128.7.101 phone 01:aa:bb:cc:dd:ee:01\n0 aa:bb:cc:dd:ee:02 10.128.7.8 * *\n"), 0644)
	_ = os.WriteFile(sdnLegacyLeasePath, []byte("1767225600 aa:bb:cc:dd:ee:03 10.9.9.9 other *\n"), 0644)
	got := SDNDHCPLeases(withServices(labBase()))
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	if got[0].Interface != "if000700" || got[0].Hostname != "phone" || got[0].Expires.Unix() != 1767225600 {
		t.Fatalf("%+v", got[0])
	}
	if got[1].Hostname != "" || !got[1].Expires.IsZero() {
		t.Fatalf("infinite lease / no name: %+v", got[1])
	}
	if got[2].Interface != "" {
		t.Fatalf("lease outside every network: %+v", got[2])
	}
}

func TestParseWGDump(t *testing.T) {
	dump := "PRIV\tPUB\t51820\toff\n" +
		"PEER1\t(none)\t81.2.69.142:40000\t10.66.0.2/32\t1767225600\t1024\t2048\toff\n" +
		"PEER2\tPSK\t(none)\t10.66.0.3/32,10.40.0.0/24\t0\t0\t0\t25\n"
	peers := parseWGDump(dump)
	if len(peers) != 2 || peers[0].PublicKey != "PEER1" || peers[0].Endpoint != "81.2.69.142:40000" ||
		peers[0].RxBytes != 1024 || peers[0].TxBytes != 2048 || peers[0].LastHandshake.Unix() != 1767225600 {
		t.Fatalf("%+v", peers)
	}
	if peers[1].Endpoint != "" || !peers[1].LastHandshake.IsZero() {
		t.Fatalf("%+v", peers[1])
	}
}

func TestSDNApply_RefusesNetworkUsedOnTheHost(t *testing.T) {
	sdnTestEnv(t)
	old := sdnHostAddrs
	sdnHostAddrs = func() map[string][]string {
		return map[string][]string{"labnat": {"10.66.0.1/24"}, "enp5s0": {"192.168.2.130/24"}}
	}
	defer func() { sdnHostAddrs = old }()
	_, err := SDNApply(labBase(), withServices(labBase()), sdnEnv)
	if err == nil || !strings.Contains(err.Error(), "labnat") {
		t.Fatalf("expected a conflict with labnat, got %v", err)
	}
	// Already running: a rollback/revert to it is never refused.
	if _, err := SDNApply(withServices(labBase()), withServices(labBase()), sdnEnv); err != nil {
		t.Fatalf("unchanged network refused: %v", err)
	}
	// A device the Firewall manages may of course hold its own network.
	sdnHostAddrs = func() map[string][]string { return map[string][]string{"wg-ifwg0001": {"10.66.0.1/24"}} }
	if _, err := SDNApply(labBase(), withServices(labBase()), sdnEnv); err != nil {
		t.Fatal(err)
	}
}

// The appliance image bakes the DHCP/DNS unit: it must stay the unit the
// portal writes.
func TestSDNDNSUnit_MatchesApplianceImage(t *testing.T) {
	b, err := os.ReadFile("../usbimage/chroot-setup.sh")
	if err != nil {
		t.Skip(err)
	}
	s := string(b)
	start := strings.Index(s, "<<'SDNDNSUNIT'\n")
	end := strings.Index(s, "\nSDNDNSUNIT\n")
	if start < 0 || end < 0 {
		t.Fatal("znas-sdn-dns.service not baked in usbimage/chroot-setup.sh")
	}
	baked := s[start+len("<<'SDNDNSUNIT'\n") : end+1]
	want := strings.ReplaceAll(sdnDNSUnitText(), sdnDnsmasqBinary(), "/usr/sbin/dnsmasq")
	if baked != want {
		t.Fatalf("baked unit differs:\n--- baked ---\n%s\n--- portal ---\n%s", baked, want)
	}
}

// The appliance image bakes the DHCP supervisor's unit and enables it.
func TestSDNDHCPUnit_MatchesApplianceImage(t *testing.T) {
	b, err := os.ReadFile("../usbimage/chroot-setup.sh")
	if err != nil {
		t.Skip(err)
	}
	s := string(b)
	start, end := strings.Index(s, "<<'SDNDHCPUNIT'\n"), strings.Index(s, "\nSDNDHCPUNIT\n")
	if start < 0 || end < 0 {
		t.Fatal("znas-sdn-dhcp.service not baked in usbimage/chroot-setup.sh")
	}
	if baked, want := s[start+len("<<'SDNDHCPUNIT'\n"):end+1], sdnDHCPUnitText("/opt/zfsnas/zfsnas"); baked != want {
		t.Fatalf("baked unit differs:\n--- baked ---\n%s\n--- portal ---\n%s", baked, want)
	}
	if !strings.Contains(s, "znas-sdn-dns.service znas-sdn-dhcp.service") {
		t.Fatal("the appliance does not enable znas-sdn-dhcp.service")
	}
}

// /etc/wireguard is root-only (0700): a portal that cannot list it must
// still delete the key file of a removed tunnel.
func TestSDNServiceFiles_RemovesKeyOfRemovedTunnelWithoutListing(t *testing.T) {
	rec, _ := sdnTestEnv(t)
	prev := withServices(labBase())
	if _, err := SDNApply(labBase(), prev, sdnEnv); err != nil {
		t.Fatal(err)
	}
	oldDir := sdnWGDir
	_ = os.Chmod(sdnWGDir, 0300) // writable, not listable
	defer os.Chmod(oldDir, 0700)
	rec.cmds = nil
	if _, err := SDNApply(prev, withVLAN700(labBase()), sdnEnv); err != nil {
		t.Fatal(err)
	}
	if rec.index("rm "+filepath.Join(sdnWGDir, "znas-ifwg0001.conf")) < 0 {
		t.Fatalf("key file not removed: %v", rec.cmds)
	}
}
