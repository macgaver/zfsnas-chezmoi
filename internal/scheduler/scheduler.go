package scheduler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Policy describes a recurring snapshot schedule for one dataset.
type Policy struct {
	ID          string    `json:"id"`
	Dataset     string    `json:"dataset"`
	Frequency   string    `json:"frequency"`    // hourly | daily | weekly | monthly
	Hour        int       `json:"hour"`         // 0-23 (daily / weekly / monthly)
	Minute      int       `json:"minute"`       // 0-59
	Weekday     int       `json:"weekday"`      // 0=Sun … 6=Sat (weekly)
	DayOfMonth  int       `json:"day_of_month"` // 1-31 (monthly)
	Retention   int       `json:"retention"`    // keep last N auto-snapshots
	Label       string    `json:"label"`        // prefix for snapshot names (e.g. "auto")
	Enabled     bool      `json:"enabled"`
	LastRun     time.Time `json:"last_run,omitempty"`
	LastStatus  string    `json:"last_status,omitempty"` // "ok" | "error" | ""
	LastError   string    `json:"last_error,omitempty"`
	LastDetails string    `json:"last_details,omitempty"` // human-readable summary of last run

	// Replication run state (populated when ReplicationEnabled).
	LastRepStatus string `json:"last_rep_status,omitempty"` // "ok" | "error" | ""
	LastRepError  string `json:"last_rep_error,omitempty"`  // short error description
	LastRepLog    string `json:"last_rep_log,omitempty"`    // stdout/stderr after the separator line
	LastRepSnap   string `json:"last_rep_snap,omitempty"`   // snap suffix of last successful replication

	// Optional remote replication — runs after each successful snapshot.
	ReplicationEnabled    bool   `json:"replication_enabled,omitempty"`
	ReplicationHost       string `json:"replication_host,omitempty"`
	ReplicationUser       string `json:"replication_user,omitempty"`
	ReplicationDataset    string `json:"replication_dataset,omitempty"`
	ReplicationRecursive  bool   `json:"replication_recursive,omitempty"`
	ReplicationCompressed bool   `json:"replication_compressed,omitempty"`

	// Optional local replication — zfs send | zfs receive within this host.
	LocalReplEnabled    bool   `json:"local_repl_enabled,omitempty"`
	LocalReplDataset    string `json:"local_repl_dataset,omitempty"` // destination dataset path
	LocalReplRecursive  bool   `json:"local_repl_recursive,omitempty"`
	LocalReplCompressed bool   `json:"local_repl_compressed,omitempty"`

	// Local replication run state.
	LastLocalReplStatus string `json:"last_local_repl_status,omitempty"` // "ok" | "error" | ""
	LastLocalReplError  string `json:"last_local_repl_error,omitempty"`
	LastLocalReplSnap   string `json:"last_local_repl_snap,omitempty"`
}

var (
	configDir string
	mu        sync.RWMutex
)

// Init sets the config directory used for schedule persistence.
func Init(dir string) {
	configDir = dir
}

func schedulesPath() string {
	return filepath.Join(configDir, "snapshot-schedules.json")
}

// LoadPolicies reads all policies from disk.
func LoadPolicies() ([]Policy, error) {
	mu.RLock()
	defer mu.RUnlock()
	data, err := os.ReadFile(schedulesPath())
	if os.IsNotExist(err) {
		return []Policy{}, nil
	}
	if err != nil {
		return nil, err
	}
	var policies []Policy
	if err := json.Unmarshal(data, &policies); err != nil {
		return nil, err
	}
	if policies == nil {
		return []Policy{}, nil
	}
	return policies, nil
}

// SavePolicies writes all policies to disk.
func SavePolicies(policies []Policy) error {
	mu.Lock()
	defer mu.Unlock()
	data, err := json.MarshalIndent(policies, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(schedulesPath(), data, 0640)
}

// IsDue returns true when policy p should fire at time now (checked per minute).
func IsDue(p Policy, now time.Time) bool {
	if p.Frequency == "manual" {
		return false
	}
	switch p.Frequency {
	case "hourly":
		return now.Minute() == p.Minute
	case "daily":
		return now.Hour() == p.Hour && now.Minute() == p.Minute
	case "weekly":
		return int(now.Weekday()) == p.Weekday && now.Hour() == p.Hour && now.Minute() == p.Minute
	case "monthly":
		dom := clampDOM(p.DayOfMonth)
		return now.Day() == dom && now.Hour() == p.Hour && now.Minute() == p.Minute
	}
	return false
}

// NextRun computes the next scheduled fire time for p after from.
func NextRun(p Policy, from time.Time) time.Time {
	if p.Frequency == "manual" {
		return time.Time{}
	}
	loc := from.Location()
	switch p.Frequency {
	case "hourly":
		t := from.Truncate(time.Hour).Add(time.Duration(p.Minute) * time.Minute)
		if !t.After(from) {
			t = t.Add(time.Hour)
		}
		return t
	case "daily":
		t := time.Date(from.Year(), from.Month(), from.Day(), p.Hour, p.Minute, 0, 0, loc)
		if !t.After(from) {
			t = t.AddDate(0, 0, 1)
		}
		return t
	case "weekly":
		t := time.Date(from.Year(), from.Month(), from.Day(), p.Hour, p.Minute, 0, 0, loc)
		for int(t.Weekday()) != p.Weekday || !t.After(from) {
			t = t.AddDate(0, 0, 1)
			t = time.Date(t.Year(), t.Month(), t.Day(), p.Hour, p.Minute, 0, 0, loc)
		}
		return t
	case "monthly":
		dom := clampDOM(p.DayOfMonth)
		t := time.Date(from.Year(), from.Month(), dom, p.Hour, p.Minute, 0, 0, loc)
		if !t.After(from) {
			t = t.AddDate(0, 1, 0)
			t = time.Date(t.Year(), t.Month(), dom, p.Hour, p.Minute, 0, 0, loc)
		}
		return t
	}
	return from
}

func clampDOM(d int) int {
	if d < 1 {
		return 1
	}
	if d > 28 {
		return 28 // safe for every month
	}
	return d
}
