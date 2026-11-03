// Package capacityrrd implements a multi-resolution round-robin database for
// storage capacity metrics (per-pool and per-dataset). Unlike the single-resolution
// rrd package, each tier stores min/avg/max aggregates per bucket.
//
// Three tiers:
//   - Tier 0: 5-minute samples,  2016 slots = 1 week
//   - Tier 1: 30-minute samples, 1440 slots = 30 days
//   - Tier 2: daily samples,     1825 slots = 5 years
package capacityrrd

import (
	"log"

	"zfsnas/internal/rrd"

	"encoding/json"
	"os"
	"sync"
	"time"
)

const (
	Tier0Slots = 2016 // 7 * 24 * 12  (5-min resolution, 1 week)
	Tier1Slots = 1440 // 30 * 24 * 2  (30-min resolution, 30 days)
	Tier2Slots = 1825 // 365 * 5      (daily resolution, 5 years)

	tier0Secs = 5 * 60
	tier1Secs = 30 * 60
	tier2Secs = 24 * 60 * 60
)

// CapSample is one aggregated slot in a tier.
type CapSample struct {
	TS  int64   `json:"ts"`  // Unix epoch seconds (bucket start)
	Min float64 `json:"min"` // minimum value in bucket
	Avg float64 `json:"avg"` // mean value in bucket
	Max float64 `json:"max"` // maximum value in bucket
	N   int     `json:"n"`   // number of raw samples in bucket
}

// capSeries is a fixed-size circular buffer of CapSamples for one named series
// in one tier. We store it with a head index + count (same pattern as internal/rrd).
type capSeries struct {
	Buf   []CapSample `json:"buf"`
	Head  int         `json:"head"`
	Count int         `json:"count"`
	Slots int         `json:"slots"` // max capacity (constant per tier)
}

func newCapSeries(slots int) *capSeries {
	// Buf grows lazily up to Slots instead of pre-allocating the full tier.
	// Most series — every daily/5-year tier especially — sit far below their
	// capacity, so reserving all slots up front wasted hundreds of MB of
	// resident heap holding empty samples. The small initial capacity avoids
	// reallocation churn for the first handful of pushes.
	return &capSeries{
		Buf:   make([]CapSample, 0, 16),
		Slots: slots,
	}
}

func (s *capSeries) push(sample CapSample) {
	if s.Slots <= 0 {
		s.Slots = len(s.Buf) // defensive: should never happen post-load
	}
	if len(s.Buf) < s.Slots {
		// Growth phase: append until the ring reaches full size. Samples sit
		// chronologically in Buf[0..len). Head marks the next write slot, and
		// becomes 0 (oldest) the moment the ring fills.
		s.Buf = append(s.Buf, sample)
		s.Count = len(s.Buf)
		if len(s.Buf) >= s.Slots {
			s.Head = 0
		} else {
			s.Head = len(s.Buf)
		}
		return
	}
	// Full ring: overwrite the oldest slot.
	s.Buf[s.Head] = sample
	s.Head = (s.Head + 1) % s.Slots
	s.Count = s.Slots
}

func (s *capSeries) all() []CapSample {
	n := len(s.Buf)
	if n == 0 {
		return nil
	}
	if n < s.Slots {
		// Growth phase: already chronological.
		result := make([]CapSample, n)
		copy(result, s.Buf)
		return result
	}
	// Full ring: unwrap starting at Head (oldest).
	h := s.Head
	if h < 0 || h >= n {
		h = 0
	}
	result := make([]CapSample, n)
	k := n - h
	copy(result, s.Buf[h:])
	copy(result[k:], s.Buf[:h])
	return result
}

// legacyAll extracts the logical sample sequence from a series as it was just
// loaded from disk, honouring the OLD head/count/full-buffer semantics (where
// Buf was always Slots long and Count tracked how many slots were populated).
// Used only during load migration; works for both legacy full-length buffers
// and already-compact buffers written by the current code.
func (s *capSeries) legacyAll() []CapSample {
	cnt := s.Count
	if cnt > len(s.Buf) {
		cnt = len(s.Buf)
	}
	if cnt <= 0 {
		return nil
	}
	if cnt < s.Slots {
		out := make([]CapSample, cnt)
		copy(out, s.Buf[:cnt])
		return out
	}
	h := s.Head
	if h < 0 || h >= len(s.Buf) {
		h = 0
	}
	out := make([]CapSample, len(s.Buf))
	k := len(s.Buf) - h
	copy(out, s.Buf[h:])
	copy(out[k:], s.Buf[:h])
	return out
}

// compactForSlots rebuilds the series from its loaded form into the compact
// growth/ring representation: Buf holds only real samples (len ≤ Slots) instead
// of a full pre-allocated tier. Idempotent across reloads.
func (s *capSeries) compactForSlots(slots int) {
	s.Slots = slots
	logical := s.legacyAll()
	if len(logical) > slots {
		// Tier shrank (shouldn't happen with fixed constants) — keep newest.
		logical = logical[len(logical)-slots:]
	}
	s.Buf = logical
	s.Count = len(logical)
	if len(logical) >= slots {
		s.Head = 0
	} else {
		s.Head = len(logical)
	}
}

// scrub drops the samples holding an impossible value an earlier version
// stored (an aggregate's maximum shows it, and its average is poisoned too).
func (s *capSeries) scrub(key string) {
	all := s.all()
	kept := all[:0:0]
	for _, x := range all {
		if rrd.Plausible(key, x.Max) && rrd.Plausible(key, x.Min) && rrd.Plausible(key, x.Avg) {
			kept = append(kept, x)
		}
	}
	if len(kept) == len(all) {
		return
	}
	log.Printf("[rrd] %s: dropped %d impossible samples", key, len(all)-len(kept))
	s.Buf, s.Count = kept, len(kept)
	s.Head = len(kept)
	if len(kept) >= s.Slots {
		s.Head = 0
	}
}

// tierStore holds all series for one resolution tier.
type tierStore struct {
	Slots  int                   `json:"slots"`
	Series map[string]*capSeries `json:"series"`
}

func newTierStore(slots int) tierStore {
	return tierStore{Slots: slots, Series: make(map[string]*capSeries)}
}

func (t *tierStore) get(key string) *capSeries {
	s, ok := t.Series[key]
	if !ok {
		s = newCapSeries(t.Slots)
		t.Series[key] = s
	}
	return s
}

// dbData is the full on-disk JSON structure.
type dbData struct {
	Tier0 tierStore `json:"tier0"`
	Tier1 tierStore `json:"tier1"`
	Tier2 tierStore `json:"tier2"`
}

// pendingBucket accumulates raw values within the current aggregate window.
type pendingBucket struct {
	bucketStart int64 // Unix seconds, truncated to bucket boundary
	pending     map[string][]float64
}

// DB is a thread-safe multi-resolution capacity round-robin database.
type DB struct {
	mu   sync.Mutex
	path string
	data dbData

	// In-memory accumulators for Tier1 (30-min) and Tier2 (daily) aggregation.
	t1 pendingBucket
	t2 pendingBucket
}

// Open loads a DB from disk, or creates a new empty one if the file doesn't exist.
func Open(path string) (*DB, error) {
	db := &DB{
		path: path,
		data: dbData{
			Tier0: newTierStore(Tier0Slots),
			Tier1: newTierStore(Tier1Slots),
			Tier2: newTierStore(Tier2Slots),
		},
		t1: pendingBucket{pending: make(map[string][]float64)},
		t2: pendingBucket{pending: make(map[string][]float64)},
	}

	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return db, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &db.data); err != nil {
		// Corrupt file — start fresh.
		db.data = dbData{
			Tier0: newTierStore(Tier0Slots),
			Tier1: newTierStore(Tier1Slots),
			Tier2: newTierStore(Tier2Slots),
		}
	}
	// Ensure Slots fields are correct after load (they may differ if we added
	// tiers), and compact each series so empty pre-allocated slots from older
	// on-disk files (or older builds) aren't kept resident. New series grow
	// lazily from here on.
	db.data.Tier0.Slots = Tier0Slots
	db.data.Tier1.Slots = Tier1Slots
	db.data.Tier2.Slots = Tier2Slots
	for _, s := range db.data.Tier0.Series {
		s.compactForSlots(Tier0Slots)
	}
	for _, s := range db.data.Tier1.Series {
		s.compactForSlots(Tier1Slots)
	}
	for _, s := range db.data.Tier2.Series {
		s.compactForSlots(Tier2Slots)
	}
	for _, t := range []*tierStore{&db.data.Tier0, &db.data.Tier1, &db.data.Tier2} {
		for key, s := range t.Series {
			s.scrub(key)
		}
	}
	return db, nil
}

// Record adds one 5-minute raw sample. It also folds pending values into
// Tier1 and Tier2 when bucket boundaries are crossed.
func (db *DB) Record(key string, value float64, now time.Time) {
	if !rrd.Plausible(key, value) {
		log.Printf("[rrd] %s: refused impossible value %v", key, value)
		return
	}
	db.mu.Lock()
	defer db.mu.Unlock()

	// --- Tier 0: raw 5-min sample ---
	t0Bucket := now.Unix() / tier0Secs * tier0Secs
	db.data.Tier0.get(key).push(CapSample{TS: t0Bucket, Min: value, Avg: value, Max: value, N: 1})

	// --- Tier 1: 30-min aggregation ---
	t1Bucket := now.Unix() / tier1Secs * tier1Secs
	if db.t1.bucketStart == 0 {
		db.t1.bucketStart = t1Bucket
	}
	if t1Bucket != db.t1.bucketStart {
		// Bucket rolled — flush accumulated values into Tier1.
		db.flushTier1()
		db.t1.bucketStart = t1Bucket
	}
	db.t1.pending[key] = append(db.t1.pending[key], value)

	// --- Tier 2: daily aggregation ---
	t2Bucket := now.Unix() / tier2Secs * tier2Secs
	if db.t2.bucketStart == 0 {
		db.t2.bucketStart = t2Bucket
	}
	if t2Bucket != db.t2.bucketStart {
		db.flushTier2()
		db.t2.bucketStart = t2Bucket
	}
	db.t2.pending[key] = append(db.t2.pending[key], value)
}

// flushTier1 computes min/avg/max from pending and writes to Tier1. Must hold mu.
func (db *DB) flushTier1() {
	for key, vals := range db.t1.pending {
		if len(vals) == 0 {
			continue
		}
		s := aggregate(db.t1.bucketStart, vals)
		db.data.Tier1.get(key).push(s)
	}
	db.t1.pending = make(map[string][]float64)
}

// flushTier2 computes min/avg/max from pending and writes to Tier2. Must hold mu.
func (db *DB) flushTier2() {
	for key, vals := range db.t2.pending {
		if len(vals) == 0 {
			continue
		}
		s := aggregate(db.t2.bucketStart, vals)
		db.data.Tier2.get(key).push(s)
	}
	db.t2.pending = make(map[string][]float64)
}

// aggregate computes a CapSample from a slice of raw float64 values.
func aggregate(ts int64, vals []float64) CapSample {
	mn, mx, sum := vals[0], vals[0], 0.0
	for _, v := range vals {
		if v < mn {
			mn = v
		}
		if v > mx {
			mx = v
		}
		sum += v
	}
	return CapSample{TS: ts, Min: mn, Avg: sum / float64(len(vals)), Max: mx, N: len(vals)}
}

// Query returns all stored samples for the given tier and key, in chronological order.
// tier: 0 = 5-min, 1 = 30-min, 2 = daily.
// Returns nil if the series doesn't exist or is empty.
func (db *DB) Query(tier int, key string) []CapSample {
	db.mu.Lock()
	defer db.mu.Unlock()
	switch tier {
	case 0:
		s, ok := db.data.Tier0.Series[key]
		if !ok {
			return nil
		}
		return s.all()
	case 1:
		s, ok := db.data.Tier1.Series[key]
		if !ok {
			return nil
		}
		return s.all()
	case 2:
		s, ok := db.data.Tier2.Series[key]
		if !ok {
			return nil
		}
		return s.all()
	}
	return nil
}

// Keys returns all series names present in Tier0.
func (db *DB) Keys() []string {
	db.mu.Lock()
	defer db.mu.Unlock()
	keys := make([]string, 0, len(db.data.Tier0.Series))
	for k := range db.data.Tier0.Series {
		keys = append(keys, k)
	}
	return keys
}

// OldestTS returns the Unix timestamp of the oldest Tier0 sample across all series.
// Returns 0 if no data exists.
func (db *DB) OldestTS() int64 {
	db.mu.Lock()
	defer db.mu.Unlock()
	var oldest int64
	for _, s := range db.data.Tier0.Series {
		samples := s.all()
		if len(samples) == 0 {
			continue
		}
		ts := samples[0].TS
		if oldest == 0 || ts < oldest {
			oldest = ts
		}
	}
	return oldest
}

// DeleteKey removes all data for the given series across all tiers.
func (db *DB) DeleteKey(key string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	delete(db.data.Tier0.Series, key)
	delete(db.data.Tier1.Series, key)
	delete(db.data.Tier2.Series, key)
	delete(db.t1.pending, key)
	delete(db.t2.pending, key)
}

// Flush persists the DB to disk atomically.
func (db *DB) Flush() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	b, err := json.Marshal(&db.data)
	if err != nil {
		return err
	}
	return os.WriteFile(db.path, b, 0640)
}
