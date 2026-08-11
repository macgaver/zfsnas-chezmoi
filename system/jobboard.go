package system

// jobboard.go — one registry for every long-running background job.
//
// Rule this exists to enforce: a background job is visible from EVERY web
// session and every interlink server, never only the tab that started it.
//
// A job is server-side state, but the activity bar's job map is per-browser
// (in-memory, mirrored to localStorage), so client state alone can never show a
// job to a second session. Each job type used to solve that on its own — or not
// at all: rsync had a list endpoint discovered once at boot, LXD backup/restore
// had their own discovery loop, and File Browser transfers had nothing. Adding
// a list + aggregate + peer-fetch trio per job type would mean duplicating the
// interlink HMAC fan-out once per type and paying for N peer round-trips per
// poll.
//
// Instead every registry contributes a provider here, and the whole fleet is
// served by ONE endpoint pair (/api/jobs, /api/jobs/aggregate) and ONE peer
// fan-out. Adding a new job type means writing a provider — nothing else — and
// it is visible everywhere for free.

import (
	"sort"
	"sync"
	"time"
)

// JobSummary is the uniform shape every job type is reduced to for discovery.
//
// The URLs travel with the job so the board needs no knowledge of any
// particular job type's routes, and Key is the exact activity-bar key that
// type's own poller uses — matching it is what stops a discovered job from
// being tracked twice alongside one the browser started itself.
type JobSummary struct {
	Key         string    `json:"key"`
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`  // "transfer"|"rsync"|"backup"|"restore"|"disk-move"|"pool-create"
	Label       string    `json:"label"` // human-readable, shown in the activity bar
	Status      string    `json:"status"`
	Progress    float64   `json:"progress"` // 0-100; 0 when the type reports none
	StartedAt   time.Time `json:"started_at"`
	ProgressURL string    `json:"progress_url"`
	CancelURL   string    `json:"cancel_url,omitempty"`
	System      string    `json:"system,omitempty"`
	BytesDone   int64     `json:"bytes_done,omitempty"`
	BytesTotal  int64     `json:"bytes_total,omitempty"`
	Speed       string    `json:"speed,omitempty"`
	ETA         string    `json:"eta,omitempty"`
	Op          string    `json:"op,omitempty"` // sub-type, e.g. copy/move for transfers
	// LocalOnly pins a job's poller to the host it runs on, so a session that
	// relays to a peer keeps tracking it instead of asking the peer about a job
	// it has never heard of.
	LocalOnly bool `json:"local_only,omitempty"`
}

var jobProviders sync.Map // name → func() []JobSummary

// RegisterJobProvider adds (or replaces) a source of jobs. Call it from an
// init() next to the registry it reads, so the job type and its discovery
// cannot drift apart.
func RegisterJobProvider(name string, fn func() []JobSummary) {
	if fn == nil {
		return
	}
	jobProviders.Store(name, fn)
}

// JobProviderNames lists the registered providers. Exists so a test can assert
// that every job registry still contributes one — losing a provider is silent
// at runtime, the jobs simply stop being visible to other sessions.
func JobProviderNames() []string {
	out := []string{}
	jobProviders.Range(func(k, _ interface{}) bool {
		if s, ok := k.(string); ok {
			out = append(out, s)
		}
		return true
	})
	sort.Strings(out)
	return out
}

// jobsFrom calls one provider, converting a panic into "no jobs". The board is
// polled by every session, so one broken registry must never be able to hide
// every other job type.
func jobsFrom(fn func() []JobSummary) (out []JobSummary) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	return fn()
}

// jobIsActive reports whether a job is still doing something. Queued counts:
// the user started it and is waiting, so it belongs at the top with the rest.
func jobIsActive(status string) bool {
	return status == "running" || status == "queued"
}

// AllJobs returns every job every provider knows about, active first and newest
// first within each group.
func AllJobs() []JobSummary {
	out := []JobSummary{}
	jobProviders.Range(func(_, v interface{}) bool {
		out = append(out, jobsFrom(v.(func() []JobSummary))...)
		return true
	})
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := jobIsActive(out[i].Status), jobIsActive(out[j].Status)
		if ai != aj {
			return ai
		}
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out
}
