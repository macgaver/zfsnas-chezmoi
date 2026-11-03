package traffic

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// BucketSize is the finest precision kept (owner: 5-minute precision).
const BucketSize = 5 * time.Minute

// Bucket is one 5-minute slice of statistics.
type Bucket struct {
	Start time.Time `json:"t"`
	Recs  []Rec     `json:"r"`
}

// Blocked is one sample of a blocked-attempt counter (cumulative packets).
type Blocked struct {
	Src, Proto, Iface, Rule string
	Port                    uint16
	Packets                 uint64
}

type baseline struct {
	bo, br, po, pr uint64
	seen           time.Time
}

// Aggregator accumulates flows in memory (5-minute buckets) until the store
// drains them — the memory-first half of the low-wear design.
type Aggregator struct {
	Env    Env
	Seeded bool // false until the first full poll: flows found then only set baselines
	Cap    int  // max records per bucket; beyond, fold into per-country rows

	mu      sync.Mutex
	buckets map[int64]map[string]*Rec
	base    map[uint64]baseline
	blkPrev map[string]uint64
}

func NewAggregator(env Env) *Aggregator {
	return &Aggregator{Env: env, Cap: 20000, buckets: map[int64]map[string]*Rec{}, base: map[uint64]baseline{}, blkPrev: map[string]uint64{}}
}

func sub(a, b uint64) uint64 {
	if a < b { // counters restarted (id reused)
		return a
	}
	return a - b
}

// AddFlow accounts a conntrack entry (poll) or event (DESTROY). Counters
// are cumulative per conntrack id: only the growth since the last sight is
// added, so a flow polled several times and then destroyed counts once.
func (a *Aggregator) AddFlow(f Flow) {
	if f.At.IsZero() {
		f.At = time.Now()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	b, had := a.base[f.ID]
	session := uint64(0)
	d := f
	switch {
	case had:
		d.BytesOrig, d.BytesReply = sub(f.BytesOrig, b.bo), sub(f.BytesReply, b.br)
		d.PktsOrig, d.PktsReply = sub(f.PktsOrig, b.po), sub(f.PktsReply, b.pr)
	case !a.Seeded && !f.Destroy:
		// Open before the collector started: its bytes so far may already
		// be on disk from the previous run.
		a.base[f.ID] = baseline{f.BytesOrig, f.BytesReply, f.PktsOrig, f.PktsReply, f.At}
		return
	default:
		session = 1
	}
	if f.Destroy {
		delete(a.base, f.ID)
	} else {
		a.base[f.ID] = baseline{f.BytesOrig, f.BytesReply, f.PktsOrig, f.PktsReply, f.At}
	}
	if d.BytesOrig+d.BytesReply == 0 && session == 0 {
		return
	}
	key, r, ok := Classify(d, a.Env)
	if !ok {
		return
	}
	r.Sessions = session
	a.add(f.At, key, r)
}

// SetSeeded marks the first full poll done (new flows count from now on).
func (a *Aggregator) SetSeeded() {
	a.mu.Lock()
	a.Seeded = true
	a.mu.Unlock()
}

// BlockedTracked is the number of blocked-attempt counters remembered.
func (a *Aggregator) BlockedTracked() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.blkPrev)
}

// AddBlocked accounts a full sample of the blocked-attempt counters. The
// baselines are rebuilt from the sample: elements that expired from the nft
// set are forgotten, so memory follows the set, not every scanner ever seen.
func (a *Aggregator) AddBlocked(list []Blocked, at time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := a.blkPrev
	a.blkPrev = make(map[string]uint64, len(list))
	for _, e := range list {
		k := strings.Join([]string{"blk", e.Src, e.Proto, strconv.Itoa(int(e.Port)), e.Iface, e.Rule}, "|")
		d := sub(e.Packets, prev[k])
		a.blkPrev[k] = e.Packets
		if d == 0 {
			continue
		}
		r := Rec{Dir: "blk", Remote: e.Src, Proto: e.Proto, Port: e.Port, Iface: e.Iface, Rule: e.Rule, Pkts: d, Sessions: d}
		if ip, err := netip.ParseAddr(e.Src); err == nil && a.Env.Geo != nil {
			r.geo(a.Env.Geo(ip))
		}
		a.add(at, k, r)
	}
}

func (a *Aggregator) add(at time.Time, key string, r Rec) {
	start := at.Truncate(BucketSize).Unix()
	bk := a.buckets[start]
	if bk == nil {
		bk = map[string]*Rec{}
		a.buckets[start] = bk
	}
	cur := bk[key]
	if cur == nil && a.Cap > 0 && len(bk) >= a.Cap {
		// Memory stays bounded under a flood of one-off addresses: fold
		// into the exact per-country row.
		key = r.Dir + "|*|" + r.CC
		cur = bk[key]
		r = Rec{Dir: r.Dir, CC: r.CC, Country: r.Country, Lat: r.Lat, Lon: r.Lon, BytesIn: r.BytesIn, BytesOut: r.BytesOut, Pkts: r.Pkts, Sessions: r.Sessions}
	}
	if cur == nil {
		r.First, r.Last = at, at
		cp := r
		bk[key] = &cp
		return
	}
	cur.BytesIn += r.BytesIn
	cur.BytesOut += r.BytesOut
	cur.Pkts += r.Pkts
	cur.Sessions += r.Sessions
	// Facts unknown at the first sighting (address assigned seconds ago,
	// geo database still downloading) come from later ones.
	if cur.Name == "" {
		cur.Name = r.Name
	}
	if cur.Iface == "" {
		cur.Iface = r.Iface
	}
	if cur.CC == "" && r.CC != "" {
		cur.CC, cur.Country, cur.City, cur.Lat, cur.Lon, cur.ASN, cur.ASOrg = r.CC, r.Country, r.City, r.Lat, r.Lon, r.ASN, r.ASOrg
	}
	if at.After(cur.Last) {
		cur.Last = at
	}
	if at.Before(cur.First) {
		cur.First = at
	}
}

func toBucket(start int64, m map[string]*Rec) Bucket {
	b := Bucket{Start: time.Unix(start, 0).UTC()}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.Recs = append(b.Recs, *m[k])
	}
	return b
}

// Drain removes and returns the buckets that ended before `before`, and
// forgets baselines of flows not seen for 10 minutes (lost DESTROY events).
func (a *Aggregator) Drain(before time.Time) []Bucket {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []Bucket
	for s, m := range a.buckets {
		if time.Unix(s, 0).Add(BucketSize).After(before) {
			continue
		}
		out = append(out, toBucket(s, m))
		delete(a.buckets, s)
	}
	for id, b := range a.base {
		if before.Sub(b.seen) > 10*time.Minute {
			delete(a.base, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

// Snapshot copies the buckets still in memory (queries include them).
func (a *Aggregator) Snapshot() []Bucket {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []Bucket
	for s, m := range a.buckets {
		out = append(out, toBucket(s, m))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}
