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
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"zfsnas/internal/rrd"
)

// On disk a DB is <path>.gz: gzip'd JSON, written whole to a temporary file
// then renamed over the old one (a crash never leaves half a file). The
// plain <path> of older builds is still read; whichever of the two is newer
// wins (a restored backup may hold the plain one), and the plain file goes
// at the next write.
//
// Writes happen only when something changed, at most every WriteEvery
// (samples keep their 5-minute resolution in memory); FlushNow writes at
// once (shutdown).
var WriteEvery = 30 * time.Minute

// registry: every open DB, for FlushAll at shutdown.
var registry = struct {
	sync.Mutex
	dbs map[*DB]bool
}{dbs: map[*DB]bool{}}

// FlushAll writes every open DB that has unsaved samples (shutdown).
func FlushAll() {
	registry.Lock()
	dbs := make([]*DB, 0, len(registry.dbs))
	for db := range registry.dbs {
		dbs = append(dbs, db)
	}
	registry.Unlock()
	for _, db := range dbs {
		if err := db.FlushNow(); err != nil {
			log.Printf("[rrd] %s: %v", db.path, err)
		}
	}
}

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

// pendingBucket accumulates samples within the current aggregate window.
type pendingBucket struct {
	bucketStart int64 // Unix seconds, truncated to bucket boundary
	pending     map[string][]CapSample
}

// DB is a thread-safe multi-resolution capacity round-robin database.
type DB struct {
	mu   sync.Mutex
	path string
	data dbData

	// In-memory accumulators for Tier1 (30-min) and Tier2 (daily) aggregation.
	t1 pendingBucket
	t2 pendingBucket

	dirty   bool      // samples not on disk yet
	written time.Time // last write (or open)
	closed  bool      // Close: never written again (its file was deleted)
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
		t1: pendingBucket{pending: make(map[string][]CapSample)},
		t2: pendingBucket{pending: make(map[string][]CapSample)},
	}

	db.written = time.Now()
	registry.Lock()
	registry.dbs[db] = true
	registry.Unlock()

	src, gz, err := newestFile(path)
	if err != nil {
		return nil, err
	}
	if src == "" {
		return db, nil
	}
	if !gz {
		db.dirty = true // moves to the compressed file at the next write
	}
	if err := decodeFile(src, gz, &db.data); err != nil {
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
	db.record(key, CapSample{Min: value, Avg: value, Max: value, N: 1}, now)
}

// RecordAgg adds one 5-minute slot that already summarises n readings (for
// a metric sampled more often than every 5 minutes, e.g. gateway latency):
// the slot keeps their true spread, and the 30-min and daily tiers roll up
// min of mins, n-weighted mean and max of maxes.
func (db *DB) RecordAgg(key string, mn, avg, mx float64, n int, now time.Time) {
	if n <= 0 {
		return
	}
	for _, v := range []float64{mn, avg, mx} {
		if !rrd.Plausible(key, v) {
			log.Printf("[rrd] %s: refused impossible value %v", key, v)
			return
		}
	}
	db.record(key, CapSample{Min: mn, Avg: avg, Max: mx, N: n}, now)
}

func (db *DB) record(key string, cs CapSample, now time.Time) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.dirty = true

	// --- Tier 0: raw 5-min sample ---
	cs.TS = now.Unix() / tier0Secs * tier0Secs
	db.data.Tier0.get(key).push(cs)

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
	db.t1.pending[key] = append(db.t1.pending[key], cs)

	// --- Tier 2: daily aggregation ---
	t2Bucket := now.Unix() / tier2Secs * tier2Secs
	if db.t2.bucketStart == 0 {
		db.t2.bucketStart = t2Bucket
	}
	if t2Bucket != db.t2.bucketStart {
		db.flushTier2()
		db.t2.bucketStart = t2Bucket
	}
	db.t2.pending[key] = append(db.t2.pending[key], cs)
}

// flushTier1 computes min/avg/max from pending and writes to Tier1. Must hold mu.
func (db *DB) flushTier1() {
	for key, vals := range db.t1.pending {
		if len(vals) == 0 {
			continue
		}
		db.data.Tier1.get(key).push(aggregate(db.t1.bucketStart, vals))
	}
	db.t1.pending = make(map[string][]CapSample)
}

// flushTier2 computes min/avg/max from pending and writes to Tier2. Must hold mu.
func (db *DB) flushTier2() {
	for key, vals := range db.t2.pending {
		if len(vals) == 0 {
			continue
		}
		db.data.Tier2.get(key).push(aggregate(db.t2.bucketStart, vals))
	}
	db.t2.pending = make(map[string][]CapSample)
}

// aggregate rolls samples up: min of mins, n-weighted mean, max of maxes.
// For plain Record samples (N=1, min=avg=max) that is the usual min/avg/max.
func aggregate(ts int64, vals []CapSample) CapSample {
	out := CapSample{TS: ts, Min: vals[0].Min, Max: vals[0].Max}
	sum := 0.0
	for _, v := range vals {
		n := v.N
		if n <= 0 {
			n = 1
		}
		if v.Min < out.Min {
			out.Min = v.Min
		}
		if v.Max > out.Max {
			out.Max = v.Max
		}
		sum += v.Avg * float64(n)
		out.N += n
	}
	out.Avg = sum / float64(out.N)
	return out
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

// AllKeys returns every series name of any tier.
func (db *DB) AllKeys() []string {
	db.mu.Lock()
	defer db.mu.Unlock()
	seen := map[string]bool{}
	for _, t := range []*tierStore{&db.data.Tier0, &db.data.Tier1, &db.data.Tier2} {
		for k := range t.Series {
			seen[k] = true
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
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
	if _, ok := db.data.Tier0.Series[key]; ok {
		db.dirty = true
	} else if _, ok := db.data.Tier1.Series[key]; ok {
		db.dirty = true
	} else if _, ok := db.data.Tier2.Series[key]; ok {
		db.dirty = true
	}
	delete(db.data.Tier0.Series, key)
	delete(db.data.Tier1.Series, key)
	delete(db.data.Tier2.Series, key)
	delete(db.t1.pending, key)
	delete(db.t2.pending, key)
}

// Flush writes the DB when it has unsaved samples and the last write is
// at least WriteEvery old. Collectors call it after every sample.
func (db *DB) Flush() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if !db.dirty || db.closed || time.Since(db.written) < WriteEvery {
		return nil
	}
	return db.writeLocked()
}

// FlushNow writes unsaved samples at once.
func (db *DB) FlushNow() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if !db.dirty || db.closed {
		return nil
	}
	return db.writeLocked()
}

// Close forgets the DB: it is never written again (its file is about to be
// deleted) and FlushAll skips it.
func (db *DB) Close() {
	db.mu.Lock()
	db.closed = true
	db.mu.Unlock()
	registry.Lock()
	delete(registry.dbs, db)
	registry.Unlock()
}

// Files returns the paths a DB stored at path may occupy (compressed, plain).
func Files(path string) []string { return []string{path + ".gz", path} }

func (db *DB) writeLocked() error {
	dst := db.path + ".gz"
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(f, 256<<10)
	zw, _ := gzip.NewWriterLevel(bw, gzip.BestSpeed)
	err = json.NewEncoder(zw).Encode(&db.data)
	if e := zw.Close(); err == nil {
		err = e
	}
	if e := bw.Flush(); err == nil {
		err = e
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if _, e := os.Stat(db.path); e == nil {
		os.Remove(db.path) // the plain file of an older build: replaced
	}
	db.dirty, db.written = false, time.Now()
	return nil
}

// newestFile picks the file to load: the newer of <path>.gz and <path>
// ("" when neither exists).
func newestFile(path string) (src string, gz bool, err error) {
	gzInfo, gerr := os.Stat(path + ".gz")
	plainInfo, perr := os.Stat(path)
	switch {
	case gerr == nil && (perr != nil || !plainInfo.ModTime().After(gzInfo.ModTime())):
		return path + ".gz", true, nil
	case perr == nil:
		return path, false, nil
	case os.IsNotExist(gerr) && os.IsNotExist(perr):
		return "", false, nil
	case !os.IsNotExist(perr):
		return "", false, perr
	default:
		return "", false, gerr
	}
}

// decodeFile streams a stored DB into v (no whole-file buffer).
func decodeFile(path string, gz bool, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = bufio.NewReaderSize(f, 256<<10)
	if gz {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return err
		}
		defer zr.Close()
		r = zr
	}
	return json.NewDecoder(r).Decode(v)
}
