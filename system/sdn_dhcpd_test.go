package system

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const dhcpConf800 = `# Managed by ZNAS Firewall — DHCP on VLAN800; rewritten on every apply and at boot.
port=0
interface=br-enp2s0-v800
dhcp-leasefile=LEASES
domain=chezmoi.lan
dhcp-range=set:if000800,10.128.8.100,10.128.8.119,255.255.255.0,12h
dhcp-range=set:if000800,10.128.8.130,10.128.8.199,255.255.255.0,12h
dhcp-host=aa:bb:cc:dd:ee:01,10.128.8.8,plex
dhcp-host=aa:bb:cc:dd:ee:02,set:h-aabbccddee02,10.128.8.9,cam,24h
`

// What the supervisor needs from a network's DHCP config: its lease file,
// its domain, its network, and the reserved addresses (named by the DNS
// server itself).
func TestParseSDNDHCPConf(t *testing.T) {
	m := parseSDNDHCPConf(strings.ReplaceAll(dhcpConf800, "LEASES", "/l/x.leases"))
	if m.leaseFile != "/l/x.leases" || m.domain != "chezmoi.lan" || m.network.String() != "10.128.8.0/24" {
		t.Fatalf("%+v", m)
	}
	if !m.reserved["10.128.8.8"] || !m.reserved["10.128.8.9"] || len(m.reserved) != 2 {
		t.Fatalf("reserved %v", m.reserved)
	}
}

// A network's names for the DNS server: one line per live lease with a
// name, the full name first (reverse lookups answer it). Expired leases,
// leases without a name and reserved addresses are left out.
func TestSDNDHCPHostsFile(t *testing.T) {
	now := time.Unix(1800000000, 0)
	leases := "1800000600 aa:bb:cc:00:00:01 10.128.8.120 phone 01:aa\n" +
		"1799999000 aa:bb:cc:00:00:02 10.128.8.101 gone *\n" +
		"0 aa:bb:cc:00:00:03 10.128.8.105 forever *\n" +
		"1800000600 aa:bb:cc:00:00:04 10.128.8.102 * *\n" +
		"1800000600 aa:bb:cc:dd:ee:01 10.128.8.8 plex *\n" +
		"1800000600 aa:bb:cc:00:00:05 10.128.8.20 laptop *\n"
	m := parseSDNDHCPConf(dhcpConf800)
	got := sdnDHCPHostsFile(leases, m, now)
	want := "10.128.8.20 laptop.chezmoi.lan laptop\n10.128.8.105 forever.chezmoi.lan forever\n10.128.8.120 phone.chezmoi.lan phone\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	m.domain = ""
	if got := sdnDHCPHostsFile("1800000600 aa:bb:cc:00:00:01 10.128.8.120 phone *\n", m, now); got != "10.128.8.120 phone\n" {
		t.Fatalf("without a domain: %q", got)
	}
}

// Leases of the single DHCP server of earlier versions are handed to the
// network they belong to, so devices keep their address after the upgrade.
func TestSDNDHCPLegacyLeases(t *testing.T) {
	legacy := "1800000600 aa:bb:cc:00:00:01 10.128.8.120 phone *\n1800000600 aa:bb:cc:00:00:02 10.128.7.55 tv *\n"
	m := parseSDNDHCPConf(dhcpConf800)
	if got := sdnLegacyLeasesFor(legacy, m); got != "1800000600 aa:bb:cc:00:00:01 10.128.8.120 phone *\n" {
		t.Fatalf("%q", got)
	}
}

type fakeDHCPProc struct {
	done    chan error
	stopped bool
}

func (p *fakeDHCPProc) Done() <-chan error { return p.done }
func (p *fakeDHCPProc) Stop()              { p.stopped = true; close(p.done) }
func (p *fakeDHCPProc) LastError() string {
	return "dnsmasq: failed to bind DHCP server socket: Address in use"
}

// The supervisor runs one dnsmasq per network config: started when the
// config appears, restarted only when it changes, stopped when it goes
// away; a process that dies is restarted after a pause. It keeps each
// network's names for the DNS server and says how each network is doing.
func TestSDNDHCPSupervisorSync(t *testing.T) {
	dir := t.TempDir()
	confDir, hostsDir, leaseDir := filepath.Join(dir, "dhcp.d"), filepath.Join(dir, "hosts.d"), filepath.Join(dir, "leases")
	for _, d := range []string{confDir, hostsDir, leaseDir} {
		_ = os.MkdirAll(d, 0755)
	}
	legacy := filepath.Join(leaseDir, "znas-sdn.leases")
	_ = os.WriteFile(legacy, []byte("1800000600 aa:bb:cc:00:00:01 10.128.8.120 phone *\n"), 0644)
	lease800 := filepath.Join(leaseDir, "znas-sdn-if000800.leases")
	conf := strings.ReplaceAll(dhcpConf800, "LEASES", lease800)
	_ = os.WriteFile(filepath.Join(confDir, "if000800.conf"), []byte(conf), 0644)
	_ = os.WriteFile(filepath.Join(confDir, "README"), []byte("not a network"), 0644)

	var started []string
	procs := map[string]*fakeDHCPProc{}
	s := &sdnDHCPSup{confDir: confDir, hostsDir: hostsDir, statusPath: filepath.Join(dir, "status.json"), legacyLeases: legacy,
		children: map[string]*sdnDHCPChild{},
		start: func(id, path string) (sdnDHCPProc, error) {
			started = append(started, id)
			p := &fakeDHCPProc{done: make(chan error)}
			procs[id] = p
			return p, nil
		}}
	now := time.Unix(1800000000, 0)
	s.sync(now)
	if len(started) != 1 || started[0] != "if000800" {
		t.Fatalf("started %v", started)
	}
	// the earlier version's lease moved to the network's own file first
	if b, _ := os.ReadFile(lease800); !strings.Contains(string(b), "10.128.8.120 phone") {
		t.Fatalf("legacy lease not carried over: %q", b)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("legacy lease file kept: it would be carried over again")
	}
	if b, _ := os.ReadFile(filepath.Join(hostsDir, "if000800")); string(b) != "10.128.8.120 phone.chezmoi.lan phone\n" {
		t.Fatalf("names for DNS: %q", b)
	}
	var st sdnDHCPStatusFile
	b, _ := os.ReadFile(s.statusPath)
	if json.Unmarshal(b, &st) != nil || !st.Networks["if000800"].Running {
		t.Fatalf("status %s", b)
	}

	// nothing changed: nothing restarted
	s.sync(now.Add(2 * time.Second))
	if len(started) != 1 {
		t.Fatalf("restarted for nothing: %v", started)
	}
	// a new lease shows up in DNS
	_ = os.WriteFile(lease800, []byte("1800000600 aa:bb:cc:00:00:01 10.128.8.120 phone *\n1800000600 aa:bb:cc:00:00:09 10.128.8.121 tv *\n"), 0644)
	s.sync(now.Add(4 * time.Second))
	if b, _ := os.ReadFile(filepath.Join(hostsDir, "if000800")); !strings.Contains(string(b), "10.128.8.121 tv.chezmoi.lan tv") {
		t.Fatalf("new lease not in DNS: %q", b)
	}
	// config changed: that network restarts
	_ = os.WriteFile(filepath.Join(confDir, "if000800.conf"), []byte(conf+"no-ping\n"), 0644)
	first := procs["if000800"]
	s.sync(now.Add(6 * time.Second))
	if !first.stopped || len(started) != 2 {
		t.Fatalf("changed config not restarted: stopped=%v started=%v", first.stopped, started)
	}
	// the process dies: restarted after a pause, and the error is reported
	second := procs["if000800"]
	close(second.done)
	s.sync(now.Add(8 * time.Second))
	b, _ = os.ReadFile(s.statusPath)
	_ = json.Unmarshal(b, &st)
	if st.Networks["if000800"].Running || !strings.Contains(st.Networks["if000800"].Error, "Address in use") {
		t.Fatalf("death not reported: %s", b)
	}
	if len(started) != 2 {
		t.Fatalf("restarted without a pause: %v", started)
	}
	s.sync(now.Add(20 * time.Second))
	if len(started) != 3 {
		t.Fatalf("not restarted after the pause: %v", started)
	}
	// config removed: stopped, names gone
	_ = os.Remove(filepath.Join(confDir, "if000800.conf"))
	third := procs["if000800"]
	s.sync(now.Add(22 * time.Second))
	if !third.stopped {
		t.Fatal("removed network still served")
	}
	if _, err := os.Stat(filepath.Join(hostsDir, "if000800")); !os.IsNotExist(err) {
		t.Fatal("names of a removed network kept in DNS")
	}
	b, _ = os.ReadFile(s.statusPath)
	if strings.Contains(string(b), "if000800") {
		t.Fatalf("removed network in the status: %s", b)
	}
}

// The DNS query log (advanced metrics) is the portal's to read, and is
// rotated before it grows big: renamed, a new file made for the DNS server
// (which runs unprivileged and cannot create it), and the server told to
// reopen it.
func TestSDNDHCPSupervisor_QueryLog(t *testing.T) {
	dir := t.TempDir()
	qlog, pid := filepath.Join(dir, "queries.log"), filepath.Join(dir, "dnsmasq.pid")
	_ = os.WriteFile(qlog, []byte("x\n"), 0600)
	_ = os.WriteFile(pid, []byte("4242\n"), 0644)
	var signalled []int
	s := &sdnDHCPSup{confDir: filepath.Join(dir, "none"), hostsDir: filepath.Join(dir, "h"), statusPath: filepath.Join(dir, "st.json"),
		children: map[string]*sdnDHCPChild{}, queryLog: qlog, dnsPid: pid, queryLogMax: 10,
		reopen: func(p int) { signalled = append(signalled, p) }}
	s.sync(time.Now())
	if st, _ := os.Stat(qlog); st.Mode().Perm() != 0644 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	if len(signalled) != 0 {
		t.Fatal("rotated a small log")
	}
	_ = os.WriteFile(qlog, []byte(strings.Repeat("a line\n", 3)), 0644)
	s.sync(time.Now())
	if b, _ := os.ReadFile(qlog + ".1"); !strings.Contains(string(b), "a line") {
		t.Fatalf("not rotated: %q", b)
	}
	if st, err := os.Stat(qlog); err != nil || st.Size() != 0 || st.Mode().Perm() != 0644 {
		t.Fatalf("new log: %v %v", st, err)
	}
	if len(signalled) != 1 || signalled[0] != 4242 {
		t.Fatalf("DNS server not told: %v", signalled)
	}
}

// "Delete lease": the network's server stops, the lease leaves its file,
// the server starts again; the other leases and the request file don't stay.
func TestSDNDHCPSupervisor_Release(t *testing.T) {
	dir := t.TempDir()
	confDir, hostsDir := filepath.Join(dir, "dhcp.d"), filepath.Join(dir, "hosts.d")
	_ = os.MkdirAll(confDir, 0755)
	_ = os.MkdirAll(hostsDir, 0755)
	lease := filepath.Join(dir, "if000800.leases")
	_ = os.WriteFile(filepath.Join(confDir, "if000800.conf"), []byte(strings.ReplaceAll(dhcpConf800, "LEASES", lease)), 0644)
	_ = os.WriteFile(lease, []byte("1800000600 aa:bb:cc:00:00:01 10.128.8.120 phone *\n1800000600 aa:bb:cc:00:00:09 10.128.8.121 tv *\n"), 0644)
	var started int
	procs := []*fakeDHCPProc{}
	s := &sdnDHCPSup{confDir: confDir, hostsDir: hostsDir, statusPath: filepath.Join(dir, "status.json"),
		children: map[string]*sdnDHCPChild{},
		start: func(id, path string) (sdnDHCPProc, error) {
			started++
			p := &fakeDHCPProc{done: make(chan error)}
			procs = append(procs, p)
			return p, nil
		}}
	now := time.Unix(1800000000, 0)
	s.sync(now)
	req := filepath.Join(confDir, "if000800-1.release")
	_ = os.WriteFile(req, []byte("if000800 AA:BB:CC:00:00:09 10.128.8.121\nbad line\n"), 0644)
	s.sync(now.Add(time.Second))
	if !procs[0].stopped || started != 2 {
		t.Fatalf("server not restarted: stopped=%v started=%d", procs[0].stopped, started)
	}
	if b, _ := os.ReadFile(lease); string(b) != "1800000600 aa:bb:cc:00:00:01 10.128.8.120 phone *\n" {
		t.Fatalf("lease file: %q", b)
	}
	if _, err := os.Stat(req); !os.IsNotExist(err) {
		t.Fatal("request file kept: the lease would be deleted again")
	}
	if b, _ := os.ReadFile(filepath.Join(hostsDir, "if000800")); strings.Contains(string(b), "tv") {
		t.Fatalf("deleted lease still in DNS: %q", b)
	}
	// a request for a network not served is dropped, nothing restarts
	_ = os.WriteFile(filepath.Join(confDir, "x.release"), []byte("if000999 aa:bb:cc:00:00:01 10.128.9.5\n"), 0644)
	s.sync(now.Add(2 * time.Second))
	if started != 2 {
		t.Fatalf("restarted for another network: %d", started)
	}
}
