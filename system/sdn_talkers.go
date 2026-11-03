package system

// Top talkers (the Network Focus header's popups): which inside devices use
// the Internet right now. conntrack is read only while someone looks.

import (
	"sort"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/sdn"
	"zfsnas/internal/traffic"
)

// SDNTalkersReport is one popup's content.
type SDNTalkersReport struct {
	Available bool             `json:"available"` // the Firewall is on
	Ready     bool             `json:"ready"`     // rates exist (not the first look)
	DownBps   int64            `json:"down_bps"`
	UpBps     int64            `json:"up_bps"`
	Talkers   []traffic.Talker `json:"talkers"`
}

var sdnTalk = struct {
	sync.Mutex
	t    *traffic.Talkers
	last time.Time
}{t: traffic.NewTalkers()}

func sdnTalkersReset() {
	sdnTalk.Lock()
	defer sdnTalk.Unlock()
	sdnTalk.t, sdnTalk.last = traffic.NewTalkers(), time.Time{}
}

// sdnLocalNames answers from the configuration and the leases: a device's
// name and its name in the domain of its network.
func sdnLocalNames(c *sdn.Config) func(ip string) (string, string) {
	type n struct{ name, fqdn string }
	m := map[string]n{}
	full := func(name, dom string) string {
		if dom == "" || strings.Contains(name, ".") {
			return name
		}
		return name + "." + dom
	}
	for _, l := range SDNDHCPLeases(c) {
		if l.Hostname == "" {
			continue
		}
		dom := c.DNS.Domain
		for _, d := range c.DHCP {
			if d.Interface == l.Interface {
				dom = c.DHCPDomain(d)
			}
		}
		m[l.IP] = n{l.Hostname, full(l.Hostname, dom)}
	}
	for _, d := range c.DHCP {
		for _, r := range d.Reservations {
			if r.Hostname != "" {
				m[r.IP] = n{r.Hostname, full(r.Hostname, c.DHCPDomain(d))}
			}
		}
	}
	for _, h := range c.DNS.Hosts {
		m[h.IP] = n{h.Name, full(h.Name, c.DNS.Domain)}
	}
	return func(ip string) (string, string) { x := m[ip]; return x.name, x.fqdn }
}

// sdnTalkersSample reads conntrack, at most once a second. Hold sdnTalk.
func sdnTalkersSample(now time.Time) {
	if now.Sub(sdnTalk.last) < time.Second {
		return
	}
	out, err := sdnRun.Run(nil, "conntrack", "-L", "-o", "extended,id")
	if err != nil && len(out) == 0 {
		return
	}
	var flows []traffic.Flow
	for _, line := range strings.Split(string(out), "\n") {
		if f, ok := traffic.ParseConntrack(line); ok && !f.OrigSrc.IsLoopback() {
			flows = append(flows, f)
		}
	}
	sdnTalk.t.Sample(flows, sdnTC.env(), now)
	sdnTalk.last = now
}

// SDNTopTalkers lists the busiest inside devices in a direction ("down" or
// "up"), with their names.
func SDNTopTalkers(c *sdn.Config, dir string, n int) SDNTalkersReport {
	now := time.Now()
	sdnTalk.Lock()
	sdnTalkersSample(now)
	r := SDNTalkersReport{Available: true, Ready: sdnTalk.t.Ready(), Talkers: sdnTalk.t.Top(dir, n)}
	r.DownBps, r.UpBps = sdnTalk.t.Totals()
	sdnTalk.Unlock()

	ips := make([]string, 0, len(r.Talkers))
	for _, h := range r.Talkers {
		ips = append(ips, h.IP)
	}
	sort.Strings(ips)
	known := SDNHostNames(c, ips, now)
	local := sdnLocalNames(c)
	for i := range r.Talkers {
		h := &r.Talkers[i]
		k := known[h.IP]
		name, fqdn := local(h.IP)
		if h.Name == "" {
			h.Name = k.Name
		}
		if h.Name == "" {
			h.Name = name
		}
		h.FQDN = k.FQDN
		if h.FQDN == "" {
			h.FQDN = fqdn
		}
	}
	return r
}
