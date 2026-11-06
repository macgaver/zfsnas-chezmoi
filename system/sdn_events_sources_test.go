package system

import (
	"strings"
	"testing"
	"time"
)

func TestGWEventRecorded(t *testing.T) {
	dir := t.TempDir()
	m := &gwMonitor{configDir: dir}
	t0 := time.Now()
	m.addEvent(GWEvent{At: t0, Kind: "down", ID: "gw1", Name: "Bell"})
	m.addEvent(GWEvent{At: t0.Add(150 * time.Second), Kind: "up", ID: "gw1", Name: "Bell"})
	ev := SDNReadEvents(dir, "gateway", 0)
	if len(ev) != 2 || ev[0].Kind != "gw_up" || ev[0].DownFor != 150 || !strings.Contains(ev[0].Text, "2 min 30 s") {
		t.Fatalf("got %+v", ev)
	}
	if ev[1].Kind != "gw_down" || ev[1].Severity != "warn" || ev[1].Name != "Bell" {
		t.Fatalf("down: %+v", ev[1])
	}
	if len(m.events) != 2 {
		t.Fatal("the published events must still be kept for alerts")
	}
}

func TestDDNSChange(t *testing.T) {
	now := time.Now()
	a := SDNDDNSHost{IP: "174.92.237.165", Status: "good"}
	b := SDNDDNSHost{IP: "174.92.235.203", Status: "good"}
	if e := ddnsChange("chezmoi.ca", a, true, b, now); e == nil || e.Kind != "ddns_ok" || e.Text != "chezmoi.ca updated: 174.92.237.165 → 174.92.235.203" {
		t.Fatalf("ok: %+v", e)
	}
	bad := SDNDDNSHost{IP: "174.92.237.165", Status: "badauth"}
	e := ddnsChange("chezmoi.ca", a, true, bad, now)
	if e == nil || e.Kind != "ddns_failed" || e.Severity != "error" || !strings.Contains(e.Text, "badauth") {
		t.Fatalf("fail: %+v", e)
	}
	if e := ddnsChange("chezmoi.ca", bad, true, bad, now); e != nil {
		t.Fatalf("same failure again is not news: %+v", e)
	}
	if e := ddnsChange("chezmoi.ca", bad, true, a, now); e == nil || e.Kind != "ddns_ok" {
		t.Fatalf("recovery: %+v", e)
	}
	if e := ddnsChange("chezmoi.ca", a, true, a, now); e != nil {
		t.Fatalf("no change: %+v", e)
	}
}

func TestDDNSFirstSightNoEvent(t *testing.T) {
	if e := ddnsChange("chezmoi.ca", SDNDDNSHost{}, false, SDNDDNSHost{IP: "1.2.3.4", Status: "good"}, time.Now()); e != nil {
		t.Fatalf("first sighting must not be an event: %+v", e)
	}
}
