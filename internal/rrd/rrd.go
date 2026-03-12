// Package rrd implements a lightweight circular-buffer RRD (round-robin database).
// No external dependencies — all in Go, persisted as a compact JSON file.
// Resolution: 288 slots = 24 hours at 5-minute sampling intervals.
package rrd

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// MaxSamples is the number of slots per series (288 = 24h at 5-min intervals).
const MaxSamples = 288

// Sample is a single timestamped data point.
type Sample struct {
	TS int64   `json:"ts"` // Unix epoch seconds
	V  float64 `json:"v"`
}

// series is the internal circular buffer for one metric key.
type series struct {
	Samples [MaxSamples]Sample `json:"samples"`
	Head    int                `json:"head"`  // index of next write slot
	Count   int                `json:"count"` // number of valid samples (≤ MaxSamples)
}

// dbData is the JSON-serialisable payload.
type dbData struct {
	Series map[string]*series `json:"series"`
}

// DB is a thread-safe round-robin database of named series.
type DB struct {
	mu   sync.Mutex
	path string
	data dbData
}

// Open loads a DB from disk, or creates a new empty one if the file doesn't exist.
func Open(path string) (*DB, error) {
	db := &DB{
		path: path,
		data: dbData{Series: make(map[string]*series)},
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return db, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &db.data); err != nil {
		// Corrupt file — start fresh rather than failing.
		db.data.Series = make(map[string]*series)
	}
	return db, nil
}

// Record adds one sample to the named series at the given time.
func (db *DB) Record(key string, v float64, now time.Time) {
	db.mu.Lock()
	defer db.mu.Unlock()
	s, ok := db.data.Series[key]
	if !ok {
		s = &series{}
		db.data.Series[key] = s
	}
	s.Samples[s.Head] = Sample{TS: now.Unix(), V: v}
	s.Head = (s.Head + 1) % MaxSamples
	if s.Count < MaxSamples {
		s.Count++
	}
}

// Query returns all recorded samples for the named series in chronological order.
// Returns an empty (non-nil) slice if the series doesn't exist.
func (db *DB) Query(key string) []Sample {
	db.mu.Lock()
	defer db.mu.Unlock()
	s, ok := db.data.Series[key]
	if !ok {
		return []Sample{}
	}
	count := s.Count
	result := make([]Sample, count)
	if count < MaxSamples {
		// Buffer not yet full: slots [0, count) are in write order.
		copy(result, s.Samples[:count])
	} else {
		// Buffer full: oldest sample is at Head, wraps around.
		n := MaxSamples - s.Head
		copy(result, s.Samples[s.Head:])
		copy(result[n:], s.Samples[:s.Head])
	}
	return result
}

// Keys returns the names of all series currently stored in the DB.
func (db *DB) Keys() []string {
	db.mu.Lock()
	defer db.mu.Unlock()
	keys := make([]string, 0, len(db.data.Series))
	for k := range db.data.Series {
		keys = append(keys, k)
	}
	return keys
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
