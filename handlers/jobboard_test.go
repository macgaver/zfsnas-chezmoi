package handlers

import (
	"strings"
	"testing"

	"zfsnas/system"
)

// Guards the rule that every background job is visible from every session.
//
// The client skips any summary without a key or a progress URL, and a job it
// skips is a job nobody but the originating tab can see — the exact defect this
// board exists to prevent. A provider that forgets either field fails here
// rather than silently going invisible in production.
func TestEveryJobProviderYieldsDiscoverableSummaries(t *testing.T) {
	// Seed one live job in each registry this package owns, so the providers
	// actually produce something. Without this the assertions below iterate an
	// empty list and pass without testing anything.
	lxdBackupJobs.Store("t-bkp", &lxdBackupJob{
		Status: "running", Instance: "vm1", DestKind: "local", DestPool: "tank",
	})
	lxdRestoreJobs.Store("t-rst", &lxdRestoreJob{
		Status: "running", VMID: "vm1", CloneName: "vm1-restored",
	})
	dmvJobs.Store("t-dmv", &dmvJob{
		Status: "running", Instance: "vm1", DiskName: "root", Target: "fast",
	})
	poolCreateJobs.Store("t-pool", &poolCreateJob{Status: "running"})
	t.Cleanup(func() {
		lxdBackupJobs.Delete("t-bkp")
		lxdRestoreJobs.Delete("t-rst")
		dmvJobs.Delete("t-dmv")
		poolCreateJobs.Delete("t-pool")
	})

	jobs := system.AllJobs()
	if len(jobs) < 4 {
		t.Fatalf("want at least the 4 seeded jobs, got %d — a provider is missing", len(jobs))
	}
	for _, j := range jobs {
		if j.Key == "" {
			t.Errorf("%s job has no Key — the client cannot de-duplicate it: %+v", j.Kind, j)
		}
		if j.ProgressURL == "" {
			t.Errorf("%s job has no ProgressURL — the client will skip it entirely: %+v", j.Kind, j)
		}
		if j.Label == "" {
			t.Errorf("%s job has no Label — it would render as an unnamed row: %+v", j.Kind, j)
		}
		if j.ProgressURL != "" && !strings.HasPrefix(j.ProgressURL, "/api/") {
			t.Errorf("%s job ProgressURL must be a portal-relative /api path, got %q", j.Kind, j.ProgressURL)
		}
	}
}

// The registries that back the activity bar must all be represented. Dropping a
// provider is easy to do by accident and impossible to notice at runtime — the
// jobs simply stop appearing for everyone but the tab that started them.
func TestExpectedJobProvidersAreRegistered(t *testing.T) {
	want := []string{
		"filebrowser-transfer", "extstorage-rsync",
		"lxd-backup", "lxd-restore", "lxd-disk-move", "pool-create",
	}
	have := map[string]bool{}
	for _, n := range system.JobProviderNames() {
		have[n] = true
	}
	for _, name := range want {
		if !have[name] {
			t.Errorf("job provider %q is not registered — its jobs are invisible to other sessions", name)
		}
	}
}
