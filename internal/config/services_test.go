package config

import (
	"bytes"
	"encoding/json"
	"testing"
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
	out := MergeServices(existing, discovered)
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
	existing := []ServiceEntry{{
		ID: "gone", Source: "discovered", Instance: "vm2", LastState: "running",
	}}
	out := MergeServices(existing, nil)
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
	out := MergeServices(existing, nil)
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
	out := MergeServices(nil, []ServiceEntry{{ID: "new", Source: "discovered", LastState: "running"}})
	if len(out) != 1 || out[0].ID != "new" {
		t.Fatalf("new service not added: %+v", out)
	}
}

// Rediscovery must be idempotent — running it twice must not duplicate rows.
func TestMergeServicesIsIdempotent(t *testing.T) {
	d := []ServiceEntry{{ID: "a", Source: "discovered", LastState: "running"}}
	once := MergeServices(nil, d)
	twice := MergeServices(once, d)
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
	merged := MergeServices(existing, []ServiceEntry{{ID: "a", Source: "discovered", LastState: "running", IP: "10.0.0.9"}})
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
