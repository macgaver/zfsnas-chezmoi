package system

// DHCP supervisor (znas-sdn-dhcp.service, `zfsnas -sdn-dhcp`): one dnsmasq
// per network, from the configs the Firewall writes in /etc/znas-sdn/dhcp.d
// (one file per network, named after the interface id). A network's server
// restarts only when its own config changes, so editing one network never
// interrupts another, nor DNS. Each network's DHCP names reach the one DNS
// server (znas-sdn-dns) through a hosts file per network in the folder it
// watches, rebuilt here from the network's lease file. Runs without the
// portal, like the gateway monitor.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const sdnDHCPUnitName = "znas-sdn-dhcp.service"

var (
	sdnDHCPDir        = "/etc/znas-sdn/dhcp.d"
	sdnHostsDir       = "/run/znas-sdn-dns/hosts.d"
	sdnDHCPStatusPath = "/run/znas-sdn-dns/dhcp-status.json"
	// sdnLeaseDir: the appliance keeps leases in RAM (no wear on the stick;
	// the servers are authoritative, so clients simply renew after a reboot).
	sdnLeaseDir = func() string {
		if ApplianceMode() {
			return "/run/znas-sdn-dns"
		}
		return "/var/lib/misc"
	}()
)

func sdnDHCPUnitPath() string { return filepath.Join(filepath.Dir(sdnUnitPath), sdnDHCPUnitName) }

// sdnDHCPUnitText: idle until the Firewall writes a network's DHCP config.
func sdnDHCPUnitText(binary string) string {
	return fmt.Sprintf(`[Unit]
Description=ZNAS Firewall — DHCP (one dnsmasq per network)
After=znas-sdn.service network.target

[Service]
Type=simple
RuntimeDirectory=znas-sdn-dns znas-sdn-dns/hosts.d
RuntimeDirectoryPreserve=yes
ExecStart=%s -sdn-dhcp
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`, binary)
}

// ── a network's config, as the supervisor reads it ──

type sdnDHCPConfInfo struct {
	leaseFile string
	domain    string
	network   netip.Prefix
	reserved  map[string]bool
}

func parseSDNDHCPConf(s string) sdnDHCPConfInfo {
	m := sdnDHCPConfInfo{reserved: map[string]bool{}}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "dhcp-leasefile":
			m.leaseFile = v
		case "domain":
			m.domain, _, _ = strings.Cut(v, ",")
		case "dhcp-range":
			// set:<tag>,first,last,mask,lease
			f := strings.Split(v, ",")
			if len(f) >= 4 && !m.network.IsValid() {
				if a, err := netip.ParseAddr(f[1]); err == nil {
					if mask, err := netip.ParseAddr(f[3]); err == nil && mask.Is4() {
						b := mask.As4()
						bits := 0
						for _, x := range b {
							for ; x != 0; x <<= 1 {
								bits++
							}
						}
						m.network, _ = a.Prefix(bits)
					}
				}
			}
		case "dhcp-host":
			for _, f := range strings.Split(v, ",") {
				if ip, err := netip.ParseAddr(f); err == nil && ip.Is4() {
					m.reserved[f] = true
					break
				}
			}
		}
	}
	return m
}

// sdnDHCPHostsFile: the network's names for the DNS server, from its lease
// file ("expiry mac ip name clientid" lines). Full name first: a reverse
// lookup answers it.
func sdnDHCPHostsFile(leases string, m sdnDHCPConfInfo, now time.Time) string {
	type entry struct {
		ip   netip.Addr
		line string
	}
	var out []entry
	seen := map[string]bool{}
	for _, l := range strings.Split(leases, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || f[3] == "*" || m.reserved[f[2]] {
			continue
		}
		exp, err := strconv.ParseInt(f[0], 10, 64)
		ip, err2 := netip.ParseAddr(f[2])
		if err != nil || err2 != nil || (exp != 0 && exp <= now.Unix()) || !sdnHostnameRe.MatchString(f[3]) {
			continue
		}
		line := f[2] + " " + f[3]
		if m.domain != "" {
			line = f[2] + " " + f[3] + "." + m.domain + " " + f[3]
		}
		if !seen[line] {
			seen[line] = true
			out = append(out, entry{ip, line})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ip.Less(out[j].ip) })
	var b strings.Builder
	for _, e := range out {
		b.WriteString(e.line + "\n")
	}
	return b.String()
}

var sdnHostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// sdnLegacyLeasesFor: the leases of the single DHCP server of earlier
// versions that belong to this network.
func sdnLegacyLeasesFor(legacy string, m sdnDHCPConfInfo) string {
	var b strings.Builder
	for _, l := range strings.Split(legacy, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		if ip, err := netip.ParseAddr(f[2]); err == nil && m.network.IsValid() && m.network.Contains(ip) {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

// ── the supervisor ──

// sdnDHCPProc is one running dnsmasq.
type sdnDHCPProc interface {
	Done() <-chan error // closed (or sent to) when it exits
	Stop()              // asks it to exit, and waits
	LastError() string  // its last line of output
}

type sdnDHCPChild struct {
	hash    string
	proc    sdnDHCPProc
	since   time.Time
	err     string
	fails   int
	next    time.Time // earliest restart after a failure
	running bool
}

// SDNDHCPNetStatus is how one network's DHCP server is doing.
type SDNDHCPNetStatus struct {
	Running bool      `json:"running"`
	Since   time.Time `json:"since,omitempty"`
	Error   string    `json:"error,omitempty"`
}

type sdnDHCPStatusFile struct {
	Binary   string                      `json:"binary"` // size-mtime of the supervisor's binary
	Networks map[string]SDNDHCPNetStatus `json:"networks"`
}

type sdnDHCPSup struct {
	confDir, hostsDir, statusPath, legacyLeases string
	binary                                      string
	children                                    map[string]*sdnDHCPChild
	start                                       func(id, confPath string) (sdnDHCPProc, error)
	lastStatus                                  string
	// the DNS server's query log (advanced metrics): made readable for the
	// portal, rotated past queryLogMax bytes (reopen signals the server)
	queryLog, dnsPid string
	queryLogMax      int64
	reopen           func(pid int)
}

var sdnDHCPIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

func (s *sdnDHCPSup) confs() map[string]string {
	out := map[string]string{}
	ents, _ := os.ReadDir(s.confDir)
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".conf")
		if !ok || !sdnDHCPIDRe.MatchString(id) {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(s.confDir, e.Name())); err == nil {
			out[id] = string(b)
		}
	}
	return out
}

func writeIfChanged(path, text string) {
	if b, err := os.ReadFile(path); err == nil && string(b) == text {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0644); err != nil {
		log.Printf("[sdn-dhcp] %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("[sdn-dhcp] %v", err)
	}
}

// sync brings the running servers in line with the configs, rebuilds the
// names for DNS and writes the status. Called every 2 s and on SIGHUP.
func (s *sdnDHCPSup) sync(now time.Time) {
	confs := s.confs()
	for id, ch := range s.children {
		text, ok := confs[id]
		sum := sha256.Sum256([]byte(text))
		if ok && hex.EncodeToString(sum[:]) == ch.hash {
			continue
		}
		if ch.running {
			ch.proc.Stop()
		}
		if !ok {
			delete(s.children, id)
			os.Remove(filepath.Join(s.hostsDir, id)) //nolint:errcheck — may not exist
			log.Printf("[sdn-dhcp] %s: stopped (network no longer served)", id)
			continue
		}
		// changed: start again right away
		ch.running, ch.hash, ch.fails, ch.next, ch.err = false, "", 0, time.Time{}, ""
	}
	for id, text := range confs {
		info := parseSDNDHCPConf(text)
		ch := s.children[id]
		if ch == nil {
			ch = &sdnDHCPChild{}
			s.children[id] = ch
		}
		if ch.running {
			select {
			case <-ch.proc.Done():
				ch.running = false
				ch.err = "stopped: " + ch.proc.LastError()
				if now.Sub(ch.since) > time.Minute {
					ch.fails = 0
				}
				ch.fails++
				ch.next = now.Add(min(time.Duration(1<<min(ch.fails, 5))*2*time.Second, time.Minute))
				log.Printf("[sdn-dhcp] %s: %s", id, ch.err)
			default:
			}
		}
		if !ch.running && !now.Before(ch.next) {
			s.carryLegacy(info)
			sum := sha256.Sum256([]byte(text))
			ch.hash = hex.EncodeToString(sum[:]) // a failed start waits its pause too
			p, err := s.start(id, filepath.Join(s.confDir, id+".conf"))
			if err != nil {
				ch.err, ch.fails = err.Error(), ch.fails+1
				ch.next = now.Add(min(time.Duration(1<<min(ch.fails, 5))*2*time.Second, time.Minute))
				log.Printf("[sdn-dhcp] %s: %v", id, err)
			} else {
				ch.proc, ch.running, ch.since = p, true, now
				log.Printf("[sdn-dhcp] %s: started", id)
			}
		}
		// names for DNS
		leases, _ := os.ReadFile(info.leaseFile)
		writeIfChanged(filepath.Join(s.hostsDir, id), sdnDHCPHostsFile(string(leases), info, now))
	}
	// names of networks no longer served
	if ents, err := os.ReadDir(s.hostsDir); err == nil {
		for _, e := range ents {
			if _, ok := confs[e.Name()]; !ok && !strings.HasSuffix(e.Name(), ".tmp") {
				os.Remove(filepath.Join(s.hostsDir, e.Name())) //nolint:errcheck
			}
		}
	}
	if s.legacyLeases != "" {
		if _, err := os.Stat(s.legacyLeases); err == nil {
			// carried over to every network that existed: done with it
			os.Remove(s.legacyLeases) //nolint:errcheck
		}
	}
	s.queryLogUpkeep()
	st := sdnDHCPStatusFile{Binary: s.binary, Networks: map[string]SDNDHCPNetStatus{}}
	for id, ch := range s.children {
		n := SDNDHCPNetStatus{Running: ch.running, Error: ch.err}
		if ch.running {
			n.Since = ch.since
			if now.Sub(ch.since) < 5*time.Second {
				n.Error = "" // a fresh start clears the last failure once it holds
			}
		}
		st.Networks[id] = n
	}
	if b, err := json.Marshal(st); err == nil && string(b) != s.lastStatus {
		s.lastStatus = string(b)
		writeIfChanged(s.statusPath, string(b)+"\n")
	}
}

// queryLogUpkeep: the DNS server creates its log readable by itself only,
// and cannot create a new one after a rotation (it runs unprivileged).
func (s *sdnDHCPSup) queryLogUpkeep() {
	if s.queryLog == "" {
		return
	}
	st, err := os.Stat(s.queryLog)
	if err != nil {
		return
	}
	if st.Mode().Perm() != 0644 {
		os.Chmod(s.queryLog, 0644) //nolint:errcheck
	}
	if st.Size() <= s.queryLogMax {
		return
	}
	b, err := os.ReadFile(s.dnsPid)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return
	}
	if err := os.Rename(s.queryLog, s.queryLog+".1"); err != nil {
		return
	}
	if f, err := os.OpenFile(s.queryLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		f.Close()
		os.Chmod(s.queryLog, 0644) //nolint:errcheck — umask
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			os.Chown(s.queryLog, int(sys.Uid), int(sys.Gid)) //nolint:errcheck — the server's own user
		}
	}
	s.reopen(pid)
}

// carryLegacy hands a network the leases of the single DHCP server of
// earlier versions, before its own server first starts.
func (s *sdnDHCPSup) carryLegacy(info sdnDHCPConfInfo) {
	if s.legacyLeases == "" || info.leaseFile == "" {
		return
	}
	if _, err := os.Stat(info.leaseFile); err == nil {
		return
	}
	b, err := os.ReadFile(s.legacyLeases)
	if err != nil {
		return
	}
	if mine := sdnLegacyLeasesFor(string(b), info); mine != "" {
		_ = os.MkdirAll(filepath.Dir(info.leaseFile), 0755)
		writeIfChanged(info.leaseFile, mine)
	}
}

// ── real dnsmasq processes ──

type sdnDnsmasqProc struct {
	cmd  *exec.Cmd
	done chan error
	mu   sync.Mutex
	last string
}

func (p *sdnDnsmasqProc) Done() <-chan error { return p.done }
func (p *sdnDnsmasqProc) LastError() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last == "" {
		return "exited"
	}
	return p.last
}
func (p *sdnDnsmasqProc) Stop() {
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

// relay copies the process' output to ours (the journal) and keeps its
// last line for the status.
func (p *sdnDnsmasqProc) relay(id string, r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		log.Printf("[sdn-dhcp] %s: %s", id, line)
		p.mu.Lock()
		p.last = line
		p.mu.Unlock()
	}
}

func sdnStartDnsmasq(id, confPath string) (sdnDHCPProc, error) {
	cmd := exec.Command(sdnDnsmasqBinary(), "--keep-in-foreground", "--conf-file="+confPath,
		"--pid-file=/run/znas-sdn-dns/dhcp-"+id+".pid")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	p := &sdnDnsmasqProc{cmd: cmd, done: make(chan error, 1)}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	relayed := make(chan struct{})
	go func() { p.relay(id, out); close(relayed) }()
	go func() {
		<-relayed // the last line is in before anyone looks
		p.done <- cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

// sdnBinaryStamp identifies a binary file's content well enough to tell
// whether the supervisor runs the installed one.
func sdnBinaryStamp(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d-%d", st.Size(), st.ModTime().Unix())
}

// SDNDHCPSupervise is `zfsnas -sdn-dhcp` (never returns).
func SDNDHCPSupervise() {
	exe, _ := os.Executable()
	s := &sdnDHCPSup{confDir: sdnDHCPDir, hostsDir: sdnHostsDir, statusPath: sdnDHCPStatusPath,
		legacyLeases: sdnLegacyLeasePath, binary: sdnBinaryStamp(exe), children: map[string]*sdnDHCPChild{}, start: sdnStartDnsmasq,
		queryLog: sdnQueryLog, dnsPid: "/run/znas-sdn-dns/dnsmasq.pid", queryLogMax: 16 << 20,
		reopen: func(pid int) { syscall.Kill(pid, syscall.SIGUSR2) }} //nolint:errcheck
	_ = os.MkdirAll(s.hostsDir, 0755)
	hup := make(chan os.Signal, 1)
	term := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	signal.Notify(term, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(2 * time.Second)
	for {
		s.sync(time.Now())
		select {
		case <-tick.C:
		case <-hup:
		case <-term:
			for _, ch := range s.children {
				if ch.running {
					ch.proc.Stop()
				}
			}
			os.Exit(0)
		}
	}
}

// SDNDHCPStatus reads the supervisor's status ("" binary when it is not
// running or has not written one yet).
func SDNDHCPStatus() (map[string]SDNDHCPNetStatus, string) {
	var st sdnDHCPStatusFile
	b, err := os.ReadFile(sdnDHCPStatusPath)
	if err != nil || json.Unmarshal(b, &st) != nil {
		return map[string]SDNDHCPNetStatus{}, ""
	}
	if st.Networks == nil {
		st.Networks = map[string]SDNDHCPNetStatus{}
	}
	return st.Networks, st.Binary
}
