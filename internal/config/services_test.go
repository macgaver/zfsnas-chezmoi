package config

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// ServiceID must be stable across rescans and process restarts — it is the key
// that carries user overrides forward, so any drift silently resets a user's
// port / icon / open-mode choices.
func TestServiceIDIsStableAndDistinct(t *testing.T) {
	a := ServiceID("vm1", "jellyfin", "jellyfin-web")
	if a == "" {
		t.Fatal("ServiceID returned empty string")
	}
	if b := ServiceID("vm1", "jellyfin", "jellyfin-web"); a != b {
		t.Fatalf("ServiceID not stable: %q vs %q", a, b)
	}
	// A standalone container must not collide with a compose project.
	if ServiceID("vm1", "", "jellyfin-web") == a {
		t.Error("standalone container collides with compose project ID")
	}
	// The same service on another instance is a different service.
	if ServiceID("vm2", "jellyfin", "jellyfin-web") == a {
		t.Error("same service on different instances shares an ID")
	}
	// For a compose project the container name must NOT affect the ID —
	// electing a different primary container on a later scan must not orphan
	// the user's overrides.
	if ServiceID("vm1", "jellyfin", "other-container") != a {
		t.Error("compose ID changed when the elected container changed")
	}
}

func TestMergeServicesPreservesOverrides(t *testing.T) {
	existing := []ServiceEntry{{
		ID: "abc", Source: "discovered", Instance: "vm1", Container: "web",
		PortOverride: 9999, OpenMode: "window", Hidden: true,
		IconOverride: "jellyfin", Name: "My Media",
	}}
	discovered := []ServiceEntry{{
		ID: "abc", Source: "discovered", Instance: "vm1", Container: "web",
		DetectedPort: 8096, LastState: "running", Image: "jellyfin:latest",
	}}
	out := MergeServices(existing, discovered, map[string]bool{"vm1": true}, map[string]bool{"vm1": true}, time.Now())
	if len(out) != 1 {
		t.Fatalf("want 1 entry, got %d", len(out))
	}
	g := out[0]
	if g.PortOverride != 9999 || g.OpenMode != "window" || !g.Hidden ||
		g.IconOverride != "jellyfin" || g.Name != "My Media" {
		t.Errorf("user overrides clobbered by rediscovery: %+v", g)
	}
	if g.DetectedPort != 8096 || g.LastState != "running" || g.Image != "jellyfin:latest" {
		t.Errorf("discovered fields not refreshed: %+v", g)
	}
}

// A service whose instance is now stopped is absent from `discovered`. It must
// be kept (greyed + startable in the UI), not deleted.
func TestMergeServicesRemembersStopped(t *testing.T) {
	// A realistic entry: anything discoverable has a project or published
	// ports, otherwise the retroactive sweep would (correctly) drop it.
	existing := []ServiceEntry{{
		ID: "gone", Source: "discovered", Instance: "vm2", LastState: "running",
		Project: "media", PublishedPorts: []int{8096}, DetectedPort: 8096,
	}}
	// vm2 is alive but powered off, so the pass could not scan it. This is the
	// case that must NOT prune.
	out := MergeServices(existing, nil, map[string]bool{}, map[string]bool{"vm2": true}, time.Now())
	if len(out) != 1 {
		t.Fatalf("stopped-instance service was dropped")
	}
	if out[0].LastState != "unknown" {
		t.Errorf("want LastState=unknown for an unseen service, got %q", out[0].LastState)
	}
}

// Custom services are user-authored and never touched by discovery.
func TestMergeServicesKeepsCustom(t *testing.T) {
	existing := []ServiceEntry{{
		ID: "x", Source: "custom", Name: "Router", URLOverride: "https://10.0.0.1",
		LastState: "running",
	}}
	out := MergeServices(existing, nil, map[string]bool{}, map[string]bool{}, time.Now())
	if len(out) != 1 {
		t.Fatalf("custom service dropped")
	}
	if out[0].Name != "Router" || out[0].URLOverride != "https://10.0.0.1" {
		t.Errorf("custom service altered: %+v", out[0])
	}
	if out[0].LastState == "unknown" {
		t.Error("custom service marked unknown by a discovery pass")
	}
}

// A newly discovered service is appended.
func TestMergeServicesAddsNew(t *testing.T) {
	out := MergeServices(nil, []ServiceEntry{{ID: "new", Source: "discovered", LastState: "running"}},
		map[string]bool{}, map[string]bool{}, time.Now())
	if len(out) != 1 || out[0].ID != "new" {
		t.Fatalf("new service not added: %+v", out)
	}
}

// Rediscovery must be idempotent — running it twice must not duplicate rows.
func TestMergeServicesIsIdempotent(t *testing.T) {
	d := []ServiceEntry{{ID: "a", Source: "discovered", LastState: "running"}}
	once := MergeServices(nil, d, map[string]bool{}, map[string]bool{}, time.Now())
	twice := MergeServices(once, d, map[string]bool{}, map[string]bool{}, time.Now())
	if len(twice) != 1 {
		t.Errorf("merge not idempotent: %d entries", len(twice))
	}
}

// The two default-on toggles use pointers so an ABSENT key means enabled.
// A plain bool would silently disable the feature for every existing config.
func TestServiceTogglesDefaultOn(t *testing.T) {
	c := &AppConfig{}
	if !c.ServiceDiscoveryOn() {
		t.Error("discovery must default ON when the key is absent")
	}
	if !c.ServiceProxyOn() {
		t.Error("proxy must default ON when the key is absent")
	}
}

// Turning discovery off must also disable the proxy (spec §2.6).
func TestServiceProxyOffWhenDiscoveryOff(t *testing.T) {
	off := false
	c := &AppConfig{ServiceDiscoveryEnabled: &off}
	if c.ServiceDiscoveryOn() {
		t.Fatal("discovery reported on with toggle off")
	}
	if c.ServiceProxyOn() {
		t.Error("proxy must be off whenever discovery is off")
	}
}

// The proxy can be disabled independently while discovery stays on.
func TestServiceProxyIndependentlyDisabled(t *testing.T) {
	off := false
	c := &AppConfig{ServiceProxyEnabled: &off}
	if !c.ServiceDiscoveryOn() {
		t.Error("discovery should still be on")
	}
	if c.ServiceProxyOn() {
		t.Error("proxy should be off")
	}
}

// Reachable must always serialise, including when false.
//
// With `omitempty` a false value vanishes from the JSON, so the frontend cannot
// tell "this service is unreachable" from "the server didn't say" — which
// silently suppressed the unreachable warning and left users staring at an
// unrelated certificate prompt instead.
func TestServiceEntryAlwaysReportsReachable(t *testing.T) {
	b, err := json.Marshal(ServiceEntry{ID: "x", Reachable: false})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(b, []byte(`"reachable":false`)) {
		t.Errorf("reachable=false must appear in the JSON, got: %s", b)
	}
	b2, _ := json.Marshal(ServiceEntry{ID: "x", Reachable: true})
	if !bytes.Contains(b2, []byte(`"reachable":true`)) {
		t.Errorf("reachable=true missing: %s", b2)
	}
}

// Pinning is independent of the open mode, but must not move anything out of
// the left menu on upgrade: entries saved before the flag existed have no value
// and fall back to "embedded means pinned".
func TestPinnedOnFallsBackToOpenMode(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name string
		e    ServiceEntry
		want bool
	}{
		{"unset + panel keeps the old implicit pin", ServiceEntry{OpenMode: "panel"}, true},
		{"unset + tab is not pinned", ServiceEntry{OpenMode: ""}, false},
		{"unset + window is not pinned", ServiceEntry{OpenMode: "window"}, false},
		{"explicit pin on a tab service", ServiceEntry{OpenMode: "", Pinned: &yes}, true},
		{"explicit unpin beats the panel default", ServiceEntry{OpenMode: "panel", Pinned: &no}, false},
	}
	for _, c := range cases {
		e := c.e
		if got := e.PinnedOn(); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// A discovery pass refreshes observed facts only — a user's pin must survive it.
func TestMergeServicesKeepsPin(t *testing.T) {
	yes := true
	existing := []ServiceEntry{{ID: "a", Source: "discovered", Pinned: &yes, OpenMode: ""}}
	merged := MergeServices(existing, []ServiceEntry{{ID: "a", Source: "discovered", LastState: "running", IP: "10.0.0.9"}},
		map[string]bool{}, map[string]bool{}, time.Now())
	if len(merged) != 1 {
		t.Fatalf("got %d entries", len(merged))
	}
	if merged[0].Pinned == nil || !*merged[0].Pinned {
		t.Errorf("pin lost across a discovery pass: %+v", merged[0])
	}
	if merged[0].IP != "10.0.0.9" || merged[0].LastState != "running" {
		t.Errorf("observed facts not refreshed: %+v", merged[0])
	}
}

// The core distinction this change exists to make: "we looked and it is not
// there" must not be treated the same as "we could not look".
func TestMergeServicesPrunesWhenScanAuthoritative(t *testing.T) {
	now := time.Now()
	existing := []ServiceEntry{{
		ID: "old", Source: "discovered", Instance: "vm1", LastState: "running",
		Project: "ci", PublishedPorts: []int{8080},
	}}
	scanned := map[string]bool{"vm1": true}
	alive := map[string]bool{"vm1": true}

	// First authoritative miss: retained, stamped, and shown as gone.
	out := MergeServices(existing, nil, scanned, alive, now)
	if len(out) != 1 {
		t.Fatalf("entry dropped on first miss — the grace period must protect it")
	}
	if out[0].GoneSince.IsZero() {
		t.Fatal("GoneSince not stamped on an authoritative miss")
	}
	if out[0].LastState != "gone" {
		t.Errorf("LastState = %q, want gone", out[0].LastState)
	}
	stamped := out[0].GoneSince

	// Still inside the window: retained, and the original stamp is kept so the
	// clock does not reset on every pass.
	out = MergeServices(out, nil, scanned, alive, now.Add(ServiceGoneGrace-time.Minute))
	if len(out) != 1 {
		t.Fatal("entry pruned before the grace period elapsed")
	}
	if !out[0].GoneSince.Equal(stamped) {
		t.Error("GoneSince re-stamped — the grace period would never elapse")
	}

	// Past the window: pruned.
	out = MergeServices(out, nil, scanned, alive, now.Add(ServiceGoneGrace+time.Minute))
	if len(out) != 0 {
		t.Errorf("entry survived the grace period: %+v", out)
	}
}

// An instance that no longer exists will never report again, so its services
// are just as provably gone as ones we scanned.
func TestMergeServicesPrunesVanishedInstance(t *testing.T) {
	now := time.Now()
	existing := []ServiceEntry{{
		ID: "orphan", Source: "discovered", Instance: "deleted-vm",
		LastState: "running", Project: "app",
		GoneSince: now.Add(-ServiceGoneGrace - time.Hour),
	}}
	out := MergeServices(existing, nil, map[string]bool{}, map[string]bool{"other": true}, now)
	if len(out) != 0 {
		t.Errorf("service of a deleted instance retained: %+v", out)
	}
}

// The property that made unconditional retention worth having: a powered-off
// VM is alive but unscanned, so its services never accrue gone-time.
func TestMergeServicesNeverPrunesUnscannedInstance(t *testing.T) {
	now := time.Now()
	existing := []ServiceEntry{{
		ID: "sleeping", Source: "discovered", Instance: "vm-off",
		LastState: "running", Project: "app",
	}}
	alive := map[string]bool{"vm-off": true}
	out := MergeServices(existing, nil, map[string]bool{}, alive, now)
	if len(out) != 1 {
		t.Fatal("service of a powered-off instance was dropped")
	}
	if out[0].LastState != "unknown" {
		t.Errorf("LastState = %q, want unknown", out[0].LastState)
	}
	if !out[0].GoneSince.IsZero() {
		t.Error("unscanned instance accrued gone-time — it would eventually be pruned")
	}
	// Even a year later, still there.
	out = MergeServices(out, nil, map[string]bool{}, alive, now.Add(365*24*time.Hour))
	if len(out) != 1 {
		t.Error("powered-off instance's service pruned by the passage of time")
	}
}

// A container that comes back must lose its death mark entirely.
func TestMergeServicesRediscoveryClearsGone(t *testing.T) {
	now := time.Now()
	existing := []ServiceEntry{{
		ID: "back", Source: "discovered", Instance: "vm1", LastState: "gone",
		Project: "app", GoneSince: now.Add(-time.Hour),
	}}
	discovered := []ServiceEntry{{
		ID: "back", Source: "discovered", Instance: "vm1", LastState: "running",
		Project: "app",
	}}
	out := MergeServices(existing, discovered, map[string]bool{"vm1": true}, map[string]bool{"vm1": true}, now)
	if len(out) != 1 {
		t.Fatalf("want 1 entry, got %d", len(out))
	}
	if !out[0].GoneSince.IsZero() {
		t.Error("GoneSince not cleared on rediscovery — entry would be pruned while present")
	}
	if out[0].LastState != "running" {
		t.Errorf("LastState = %q, want running", out[0].LastState)
	}
}

// Custom services are user-authored and must be immune to every prune path.
func TestMergeServicesNeverPrunesCustom(t *testing.T) {
	now := time.Now()
	existing := []ServiceEntry{{
		ID: "c1", Source: "custom", Name: "Router", URLOverride: "https://10.0.0.1",
		GoneSince: now.Add(-ServiceGoneGrace * 10),
	}}
	out := MergeServices(existing, nil, map[string]bool{}, map[string]bool{}, now)
	if len(out) != 1 {
		t.Fatal("custom service pruned")
	}
	if out[0].LastState == "gone" {
		t.Error("custom service marked gone")
	}
}

// Entries already on disk that the ingest filter would never admit are dropped
// immediately: they can never be rediscovered, so a grace period would only
// delay the cleanup. This is what clears the 49 CI-runner entries observed on
// the live host.
func TestMergeServicesRetroactivelyDropsIneligible(t *testing.T) {
	now := time.Now()
	existing := []ServiceEntry{
		{ID: "junk1", Source: "discovered", Instance: "buildserver3",
			Container: "runner-cuga6vblp-project-74296642-concurrent-0-ae08eb5f979a2b0a-build",
			LastState: "unknown"},
		{ID: "junk2", Source: "discovered", Instance: "buildserver3",
			Container: "runner-cuga6vblp-project-8175782-concurrent-1-0e12079672cbe540-predefined",
			LastState: "unknown"},
		// Keepers: a published port, a compose project, a custom entry.
		{ID: "keep1", Source: "discovered", Instance: "buildserver3",
			Container: "registry", PublishedPorts: []int{6000}, DetectedPort: 6000,
			LastState: "running"},
		{ID: "keep2", Source: "discovered", Instance: "ipsvc",
			Project: "myscripts", Container: "myscripts", LastState: "running"},
		{ID: "keep3", Source: "custom", Name: "Router", URLOverride: "https://10.0.0.1"},
	}
	// Nothing scanned, nothing alive — the sweep must not depend on authority.
	out := MergeServices(existing, nil, map[string]bool{}, map[string]bool{"buildserver3": true, "ipsvc": true}, now)

	got := map[string]bool{}
	for _, e := range out {
		got[e.ID] = true
	}
	if got["junk1"] || got["junk2"] {
		t.Errorf("ineligible entries retained: %+v", out)
	}
	for _, id := range []string{"keep1", "keep2", "keep3"} {
		if !got[id] {
			t.Errorf("eligible entry %s was dropped: %+v", id, out)
		}
	}
}

// A bare-looking entry the user has actually touched is not silently deleted —
// it falls through to the normal grace path instead.
func TestMergeServicesRetroactiveSweepSparesUserOverrides(t *testing.T) {
	now := time.Now()
	yes := true
	for _, tc := range []struct {
		name string
		e    ServiceEntry
	}{
		{"named", ServiceEntry{ID: "a", Source: "discovered", Instance: "vm1", Name: "My App"}},
		{"port override", ServiceEntry{ID: "a", Source: "discovered", Instance: "vm1", PortOverride: 8080}},
		{"icon", ServiceEntry{ID: "a", Source: "discovered", Instance: "vm1", IconOverride: "jellyfin"}},
		{"hidden", ServiceEntry{ID: "a", Source: "discovered", Instance: "vm1", Hidden: true}},
		{"pinned", ServiceEntry{ID: "a", Source: "discovered", Instance: "vm1", Pinned: &yes}},
	} {
		// vm1 is alive but unscanned, so the grace path retains it.
		out := MergeServices([]ServiceEntry{tc.e}, nil,
			map[string]bool{}, map[string]bool{"vm1": true}, now)
		if len(out) != 1 {
			t.Errorf("%s: entry with a user override was swept away", tc.name)
		}
	}
}

// Docker only lists port bindings while a container RUNS. Erasing the stored
// ports every time one stops would destroy the record of what the service
// publishes — and leave it looking like ephemeral junk to the retroactive
// sweep, deleting a service the user had merely stopped.
func TestMergeServicesKeepsPortsWhenPassReportsNone(t *testing.T) {
	now := time.Now()
	existing := []ServiceEntry{{
		ID: "reg", Source: "discovered", Instance: "buildserver3", Container: "registry",
		DetectedPort: 6000, PublishedPorts: []int{6000}, LastState: "running",
	}}
	// The container is still there, just stopped: no ports reported.
	discovered := []ServiceEntry{{
		ID: "reg", Source: "discovered", Instance: "buildserver3", Container: "registry",
		DetectedPort: 0, PublishedPorts: nil, LastState: "exited",
	}}
	out := MergeServices(existing, discovered,
		map[string]bool{"buildserver3": true}, map[string]bool{"buildserver3": true}, now)
	if len(out) != 1 {
		t.Fatalf("want 1 entry, got %d", len(out))
	}
	if out[0].DetectedPort != 6000 || len(out[0].PublishedPorts) != 1 || out[0].PublishedPorts[0] != 6000 {
		t.Errorf("ports erased by a stopped container: %+v", out[0])
	}
	if out[0].LastState != "exited" {
		t.Errorf("state not refreshed: %q", out[0].LastState)
	}

	// A container recreated on a DIFFERENT port still updates — only the empty
	// case is preserved, so this is not a one-way latch.
	moved := []ServiceEntry{{
		ID: "reg", Source: "discovered", Instance: "buildserver3", Container: "registry",
		DetectedPort: 7000, PublishedPorts: []int{7000}, LastState: "running",
	}}
	out = MergeServices(out, moved,
		map[string]bool{"buildserver3": true}, map[string]bool{"buildserver3": true}, now)
	if out[0].DetectedPort != 7000 || out[0].PublishedPorts[0] != 7000 {
		t.Errorf("real port change not applied: %+v", out[0])
	}
}

// The whole point of the known-services callback, verified at the merge layer:
// a stopped standalone service stays listed rather than being swept away.
func TestMergeServicesKeepsStoppedStandaloneService(t *testing.T) {
	now := time.Now()
	existing := []ServiceEntry{{
		ID: "reg", Source: "discovered", Instance: "buildserver3", Container: "registry",
		DetectedPort: 6000, PublishedPorts: []int{6000}, LastState: "running",
	}}
	// Rediscovered while stopped (thanks to the known callback), no ports.
	discovered := []ServiceEntry{{
		ID: "reg", Source: "discovered", Instance: "buildserver3", Container: "registry",
		LastState: "exited",
	}}
	out := MergeServices(existing, discovered,
		map[string]bool{"buildserver3": true}, map[string]bool{"buildserver3": true}, now)
	if len(out) != 1 {
		t.Fatalf("stopped standalone service dropped: %+v", out)
	}
	// And it survives its instance being powered off afterwards.
	out = MergeServices(out, nil, map[string]bool{}, map[string]bool{"buildserver3": true}, now)
	if len(out) != 1 {
		t.Fatalf("stopped standalone service dropped once its instance went down")
	}
	if out[0].LastState != "unknown" {
		t.Errorf("LastState = %q, want unknown", out[0].LastState)
	}
}
