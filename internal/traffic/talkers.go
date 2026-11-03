package traffic

// Top talkers: which inside devices use the Internet right now, from the
// growth of their connections' counters between two conntrack snapshots.

import (
	"net/netip"
	"sort"
	"time"
)

const (
	talkerSpark  = 30               // sparkline points
	talkerMaxGap = 15 * time.Second // longer without a look: a new baseline
	talkerKeep   = 5 * time.Minute  // an idle device leaves the list
	talkerThis   = "this-server"    // this server's entry
)

// Talker is one inside device.
type Talker struct {
	IP          string  `json:"ip"`
	Name        string  `json:"name,omitempty"`
	FQDN        string  `json:"fqdn,omitempty"`
	DownBps     int64   `json:"down_bps"`
	UpBps       int64   `json:"up_bps"`
	PeakDownBps int64   `json:"peak_down_bps"`
	PeakUpBps   int64   `json:"peak_up_bps"`
	Conns       int     `json:"conns"`
	DownBytes   uint64  `json:"down_bytes"` // on its open connections
	UpBytes     uint64  `json:"up_bytes"`
	SparkDown   []int64 `json:"spark_down"`
	SparkUp     []int64 `json:"spark_up"`
	lastActive  time.Time
}

type talkerConn struct{ orig, reply uint64 }

// Talkers keeps the state between snapshots. Not safe for concurrent use.
type Talkers struct {
	prev  map[uint64]talkerConn
	at    time.Time
	ready bool
	hosts map[string]*Talker
}

// NewTalkers starts without a baseline.
func NewTalkers() *Talkers {
	return &Talkers{prev: map[uint64]talkerConn{}, hosts: map[string]*Talker{}}
}

// Ready: the last snapshot gave rates (it was not a baseline).
func (t *Talkers) Ready() bool { return t.ready }

func delta(cur, prev uint64) uint64 {
	if cur < prev { // the id was reused: all of it is new
		return cur
	}
	return cur - prev
}

func pushSpark(s []int64, v int64) []int64 {
	s = append(s, v)
	if len(s) > talkerSpark {
		s = s[len(s)-talkerSpark:]
	}
	return s
}

// Sample takes a snapshot of the connections.
func (t *Talkers) Sample(flows []Flow, env Env, now time.Time) {
	baseline := t.at.IsZero() || now.Sub(t.at) > talkerMaxGap
	dt := now.Sub(t.at).Seconds()
	type acc struct {
		name, ip           string
		down, up           uint64 // growth
		downBytes, upBytes uint64
		conns              int
	}
	seen := map[string]*acc{}
	next := make(map[uint64]talkerConn, len(flows))
	for _, f := range flows {
		next[f.ID] = talkerConn{f.BytesOrig, f.BytesReply}
		_, r, ok := Classify(f, env)
		if !ok || r.Inside == "" {
			continue
		}
		key := r.Inside
		if ip, err := netip.ParseAddr(r.Inside); err == nil && env.Local != nil && env.Local(ip) {
			key = talkerThis // one device, whichever address it used
		}
		a := seen[key]
		if a == nil {
			a = &acc{name: r.Name, ip: r.Inside}
			seen[key] = a
		}
		if key == talkerThis && r.Inside < a.ip {
			a.ip = r.Inside // a stable address for it
		}
		a.conns++
		// Rec: BytesIn travels toward the inside, whoever started.
		a.downBytes += r.BytesIn
		a.upBytes += r.BytesOut
		if baseline {
			continue
		}
		p := t.prev[f.ID] // a new connection: all its bytes are new
		dOrig, dReply := delta(f.BytesOrig, p.orig), delta(f.BytesReply, p.reply)
		if r.Dir == "in" {
			a.down, a.up = a.down+dOrig, a.up+dReply
		} else {
			a.up, a.down = a.up+dOrig, a.down+dReply
		}
	}
	t.prev, t.at, t.ready = next, now, !baseline
	if baseline {
		// charts and rates start over; the devices are known from now on
		for _, h := range t.hosts {
			h.DownBps, h.UpBps, h.SparkDown, h.SparkUp, h.PeakDownBps, h.PeakUpBps = 0, 0, nil, nil, 0, 0
		}
	}
	for key, a := range seen {
		h := t.hosts[key]
		if h == nil {
			h = &Talker{lastActive: now}
			t.hosts[key] = h
		}
		h.IP, h.Name = a.ip, a.name
	}
	for ip, h := range t.hosts {
		a := seen[ip]
		if a == nil {
			a = &acc{}
		}
		h.Conns, h.DownBytes, h.UpBytes = a.conns, a.downBytes, a.upBytes
		if baseline {
			continue
		}
		h.DownBps, h.UpBps = int64(float64(a.down)*8/dt), int64(float64(a.up)*8/dt)
		h.PeakDownBps, h.PeakUpBps = max(h.PeakDownBps, h.DownBps), max(h.PeakUpBps, h.UpBps)
		h.SparkDown, h.SparkUp = pushSpark(h.SparkDown, h.DownBps), pushSpark(h.SparkUp, h.UpBps)
		if h.DownBps > 0 || h.UpBps > 0 {
			h.lastActive = now
		}
		if now.Sub(h.lastActive) > talkerKeep && a.conns == 0 {
			delete(t.hosts, ip)
		}
	}
}

// Host returns one device (the server's own addresses share one entry).
func (t *Talkers) Host(ip string, local bool) (Talker, bool) {
	if local {
		ip = talkerThis
	}
	h, ok := t.hosts[ip]
	if !ok {
		return Talker{}, false
	}
	return *h, true
}

// Top lists the busiest devices in a direction ("down" or "up"); none until
// there are rates.
func (t *Talkers) Top(dir string, n int) []Talker {
	out := []Talker{}
	if !t.ready {
		return out
	}
	for _, h := range t.hosts {
		out = append(out, *h)
	}
	rate := func(a Talker) (int64, int64, uint64) {
		if dir == "up" {
			return a.UpBps, a.PeakUpBps, a.UpBytes
		}
		return a.DownBps, a.PeakDownBps, a.DownBytes
	}
	sort.Slice(out, func(i, j int) bool {
		ri, pi, bi := rate(out[i])
		rj, pj, bj := rate(out[j])
		switch {
		case ri != rj:
			return ri > rj
		case pi != pj:
			return pi > pj
		case bi != bj:
			return bi > bj
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Totals are all devices' rates: download, upload.
func (t *Talkers) Totals() (down, up int64) {
	for _, h := range t.hosts {
		down += h.DownBps
		up += h.UpBps
	}
	return down, up
}
