package system

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestEventsAppendAndRead(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 11, 5, 20, 10, 0, 0, time.Local)
	for i, k := range []string{"ppp_down", "ddns_ok", "safe_mode", "gw_up"} {
		if err := SDNRecordEvent(dir, SDNEvent{At: t0.Add(time.Duration(i) * time.Second), Kind: k, Text: k}); err != nil {
			t.Fatal(err)
		}
	}
	all := SDNReadEvents(dir, "all", 0)
	if len(all) != 4 || all[0].Kind != "gw_up" || all[3].Kind != "ppp_down" {
		t.Fatalf("want newest first, got %+v", all)
	}
	if got := SDNReadEvents(dir, "", 2); len(got) != 2 || got[0].Kind != "gw_up" {
		t.Fatalf("limit: %+v", got)
	}
	gw := SDNReadEvents(dir, "gateway", 0)
	if len(gw) != 2 || gw[0].Kind != "gw_up" || gw[1].Kind != "ppp_down" {
		t.Fatalf("gateway filter: %+v", gw)
	}
	if d := SDNReadEvents(dir, "ddns", 0); len(d) != 1 || d[0].Kind != "ddns_ok" {
		t.Fatalf("ddns filter: %+v", d)
	}
	if s := SDNReadEvents(dir, "system", 0); len(s) != 1 || s[0].Kind != "safe_mode" {
		t.Fatalf("system filter: %+v", s)
	}
	if fi, err := os.Stat(SDNEventsPath(dir)); err != nil || fi.Mode().Perm() != 0644 {
		t.Fatalf("events file must be 0644 for the portal: %v %v", fi.Mode(), err)
	}
}

func TestEventsCap(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Now()
	for i := 0; i < 1101; i++ {
		if err := SDNRecordEvent(dir, SDNEvent{At: t0.Add(time.Duration(i) * time.Second), Kind: "gw_up", Text: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	all := SDNReadEvents(dir, "all", 0)
	if len(all) != 1000 {
		t.Fatalf("want 1000 kept, got %d", len(all))
	}
	if all[0].Text != "1100" || all[999].Text != "101" {
		t.Fatalf("kept the wrong end: newest %q oldest %q", all[0].Text, all[999].Text)
	}
}

func TestEventsCorruptLine(t *testing.T) {
	dir := t.TempDir()
	_ = SDNRecordEvent(dir, SDNEvent{At: time.Now(), Kind: "gw_down", Text: "a"})
	f, _ := os.OpenFile(SDNEventsPath(dir), os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString(`{"at":"2026-11-05T20:1`) // crash mid-write, no newline
	f.Close()
	_ = SDNRecordEvent(dir, SDNEvent{At: time.Now(), Kind: "gw_up", Text: "b"})
	all := SDNReadEvents(dir, "all", 0)
	if len(all) != 2 || all[0].Text != "b" || all[1].Text != "a" {
		t.Fatalf("corrupt line must be skipped, got %+v", all)
	}
}
