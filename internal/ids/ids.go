// Package ids keeps the intrusion-detection alerts Suricata sends to the
// portal (EVE "alert" records over a datagram socket), grouped by signature,
// source, destination and port. The groups live in memory and are written,
// gzipped, to the statistics directory every few minutes — never one write
// per alert (wear).
package ids

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Event is one EVE alert.
type Event struct {
	Time      time.Time
	InIface   string
	Src, Dst  string
	SrcPort   int
	DstPort   int
	Proto     string
	SID       int
	Signature string
	Category  string
	Severity  int
	// Behind NAT (filled by the portal, not Suricata): the inside host that
	// Src (our public address, outgoing) or Dst (incoming, port forward)
	// really was, found in the connection-tracking table.
	SrcInside, DstInside string
}

type eve struct {
	Timestamp string    `json:"timestamp"`
	EventType string    `json:"event_type"`
	InIface   string    `json:"in_iface"`
	SrcIP     string    `json:"src_ip"`
	SrcPort   int       `json:"src_port"`
	DestIP    string    `json:"dest_ip"`
	DestPort  int       `json:"dest_port"`
	Proto     string    `json:"proto"`
	Direction string    `json:"direction"` // to_server | to_client (Suricata 7+)
	Flow      *struct { // the flow as its initiator opened it (Suricata 7+)
		SrcIP    string `json:"src_ip"`
		DestIP   string `json:"dest_ip"`
		SrcPort  int    `json:"src_port"`
		DestPort int    `json:"dest_port"`
	} `json:"flow"`
	Alert *struct {
		SID       int    `json:"signature_id"`
		Signature string `json:"signature"`
		Category  string `json:"category"`
		Severity  int    `json:"severity"`
	} `json:"alert"`
}

// ParseEVE decodes one EVE record; ok is false for anything but an alert.
func ParseEVE(b []byte) (Event, bool) {
	var r eve
	if err := json.Unmarshal(b, &r); err != nil || r.EventType != "alert" || r.Alert == nil {
		return Event{}, false
	}
	t, err := time.Parse("2006-01-02T15:04:05.999999-0700", r.Timestamp)
	if err != nil {
		t = time.Now()
	}
	// File the alert by who started the connection (the packet that matched
	// may be a reply): Src = initiator, Dst/DstPort = its target.
	src, dst, sp, dp := r.SrcIP, r.DestIP, r.SrcPort, r.DestPort
	switch {
	case r.Flow != nil && r.Flow.SrcIP != "" && r.Flow.DestIP != "":
		src, dst, sp, dp = r.Flow.SrcIP, r.Flow.DestIP, r.Flow.SrcPort, r.Flow.DestPort
	case r.Direction == "to_client":
		src, dst, sp, dp = dst, src, dp, sp
	}
	return Event{Time: t, InIface: r.InIface, Src: src, Dst: dst, SrcPort: sp, DstPort: dp,
		Proto: r.Proto, SID: r.Alert.SID, Signature: r.Alert.Signature, Category: r.Alert.Category, Severity: r.Alert.Severity}, true
}

// Group is every alert of one signature between the same two addresses (a
// port scan is one group, with the ports it touched).
type Group struct {
	SID       int       `json:"sid"`
	Signature string    `json:"signature"`
	Category  string    `json:"category"`
	Severity  int       `json:"severity"`
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
	DstPort   int       `json:"dst_port"`   // the last one
	Ports     []int     `json:"ports"`      // the first 20 distinct ports
	PortCount int       `json:"port_count"` // distinct ports seen
	Proto     string    `json:"proto"`
	InIface   string    `json:"in_iface"`
	SrcInside string    `json:"src_inside,omitempty"` // the inside host behind Src (our public address, NAT)
	DstInside string    `json:"dst_inside,omitempty"` // the inside host behind Dst (port forward)
	Count     int64     `json:"count"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`

	seen map[int]bool // distinct ports (not saved; capped)
}

func (g Group) key() string {
	return g.baseKey() + "|" + g.SrcInside + "|" + g.DstInside
}

// baseKey: the group as Suricata sees it, whatever host is behind the NAT.
func (g Group) baseKey() string {
	return strconv.Itoa(g.SID) + "|" + g.Src + "|" + g.Dst + "|" + g.Proto
}

func (g *Group) addPort(p int) {
	g.DstPort = p
	if g.seen == nil {
		g.seen = map[int]bool{}
		for _, x := range g.Ports {
			g.seen[x] = true
		}
	}
	if g.seen[p] || len(g.seen) >= 4096 {
		return
	}
	g.seen[p] = true
	if len(g.Ports) < 20 {
		g.Ports = append(g.Ports, p)
	}
	if len(g.seen) > g.PortCount {
		g.PortCount = len(g.seen)
	}
}

// Store holds the groups of the last Retain.
type Store struct {
	mu     sync.Mutex
	path   string
	groups map[string]*Group
	inside map[string]string // baseKey → key of the group with the last inside host found
	max    int
	retain time.Duration
}

// NewStore loads path if it exists.
func NewStore(path string) *Store {
	s := &Store{path: path, groups: map[string]*Group{}, inside: map[string]string{}, max: 5000, retain: 30 * 24 * time.Hour}
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		if zr, err := gzip.NewReader(f); err == nil {
			var list []Group
			if json.NewDecoder(zr).Decode(&list) == nil {
				for i := range list {
					g := list[i]
					s.groups[g.key()] = &g
					if g.SrcInside != "" || g.DstInside != "" {
						if cur, ok := s.groups[s.inside[g.baseKey()]]; !ok || g.Last.After(cur.Last) {
							s.inside[g.baseKey()] = g.key()
						}
					}
				}
			}
		}
	}
	return s
}

// Path is where the store is saved ("" = memory only).
func (s *Store) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

func (s *Store) Add(e Event) {
	g := Group{SID: e.SID, Signature: e.Signature, Category: e.Category, Severity: e.Severity, Src: e.Src, Dst: e.Dst,
		Proto: e.Proto, InIface: e.InIface, SrcInside: e.SrcInside, DstInside: e.DstInside}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := g.key()
	if g.SrcInside != "" || g.DstInside != "" {
		s.inside[g.baseKey()] = k
	} else if ik, ok := s.inside[g.baseKey()]; ok && s.groups[ik] != nil {
		// not looked up this time (rate limit, flow gone): the host found last
		k = ik
	}
	if cur, ok := s.groups[k]; ok {
		cur.Count++
		cur.addPort(e.DstPort)
		if e.Time.After(cur.Last) {
			cur.Last = e.Time
		}
		cur.Signature, cur.Category, cur.Severity, cur.InIface = e.Signature, e.Category, e.Severity, e.InIface
		return
	}
	g.Count, g.First, g.Last = 1, e.Time, e.Time
	g.addPort(e.DstPort)
	s.groups[k] = &g
}

// List returns the groups seen since since, most recent first.
func (s *Store) List(since time.Time) []Group {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Group{}
	for _, g := range s.groups {
		if g.Last.After(since) {
			c := *g
			c.Ports, c.seen = append([]int{}, g.Ports...), nil
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out
}

// Save prunes (older than the retention, then the oldest beyond max) and
// writes the store.
func (s *Store) Save() error {
	s.mu.Lock()
	cut := time.Now().Add(-s.retain)
	list := make([]Group, 0, len(s.groups))
	for k, g := range s.groups {
		if g.Last.Before(cut) {
			delete(s.groups, k)
			if s.inside[g.baseKey()] == k {
				delete(s.inside, g.baseKey())
			}
			continue
		}
		list = append(list, *g)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Last.After(list[j].Last) })
	if len(list) > s.max {
		for _, g := range list[s.max:] {
			delete(s.groups, g.key())
			if s.inside[g.baseKey()] == g.key() {
				delete(s.inside, g.baseKey())
			}
		}
		list = list[:s.max]
	}
	path := s.path
	s.mu.Unlock()
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ids-*")
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(tmp)
	if err := json.NewEncoder(zw).Encode(list); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	zw.Close()
	tmp.Close()
	return os.Rename(tmp.Name(), path)
}

// MoveTo saves to a new location from now on (statistics moved to a pool).
func (s *Store) MoveTo(path string) {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
}
