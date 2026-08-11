package system

import (
	"testing"
	"time"
)

func resetJobProviders() {
	jobProviders.Range(func(k, _ interface{}) bool { jobProviders.Delete(k); return true })
}

func TestAllJobsMergesEveryProvider(t *testing.T) {
	resetJobProviders()
	RegisterJobProvider("a", func() []JobSummary {
		return []JobSummary{{Key: "a1", Kind: "rsync", Status: "running"}}
	})
	RegisterJobProvider("b", func() []JobSummary {
		return []JobSummary{{Key: "b1", Kind: "transfer", Status: "running"}}
	})

	got := AllJobs()
	if len(got) != 2 {
		t.Fatalf("want 2 jobs from 2 providers, got %d: %+v", len(got), got)
	}
}

// The board is what every session polls. One misbehaving provider must not be
// able to blank out every other job type — a panic in, say, the LXD registry
// would otherwise hide a running file transfer from every browser.
func TestAllJobsSurvivesAPanickingProvider(t *testing.T) {
	resetJobProviders()
	RegisterJobProvider("bad", func() []JobSummary { panic("boom") })
	RegisterJobProvider("good", func() []JobSummary {
		return []JobSummary{{Key: "g1", Kind: "transfer", Status: "running"}}
	})

	got := AllJobs()
	if len(got) != 1 || got[0].Key != "g1" {
		t.Fatalf("a panicking provider must not hide other jobs, got %+v", got)
	}
}

func TestAllJobsSortsActiveFirstThenNewest(t *testing.T) {
	resetJobProviders()
	now := time.Now()
	RegisterJobProvider("p", func() []JobSummary {
		return []JobSummary{
			{Key: "done-new", Status: "done", StartedAt: now},
			{Key: "run-old", Status: "running", StartedAt: now.Add(-time.Hour)},
			{Key: "queued-new", Status: "queued", StartedAt: now},
		}
	})

	got := AllJobs()
	if got[0].Key == "done-new" {
		t.Errorf("finished job must not sort ahead of active ones: %+v", got)
	}
	if got[len(got)-1].Key != "done-new" {
		t.Errorf("finished job must sort last, got %q", got[len(got)-1].Key)
	}
	// Both queued and running count as active; newest first among them.
	if got[0].Key != "queued-new" {
		t.Errorf("newest active job must sort first, got %q", got[0].Key)
	}
}

// Re-registering the same name replaces the provider rather than duplicating
// it, so a package whose init runs twice under test cannot double-report jobs.
func TestRegisterJobProviderReplacesByName(t *testing.T) {
	resetJobProviders()
	RegisterJobProvider("dup", func() []JobSummary {
		return []JobSummary{{Key: "first", Status: "running"}}
	})
	RegisterJobProvider("dup", func() []JobSummary {
		return []JobSummary{{Key: "second", Status: "running"}}
	})

	got := AllJobs()
	if len(got) != 1 || got[0].Key != "second" {
		t.Fatalf("want only the latest provider for a name, got %+v", got)
	}
}
