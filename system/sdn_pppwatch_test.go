package system

import (
	"strings"
	"testing"
	"time"
)

// The 2026-11-05 outage on .3, as pppd logged it.
func pppOutageFixture() []pppLine {
	at := func(s string) time.Time {
		t, _ := time.ParseInLocation("2006-01-02 15:04:05", "2026-11-05 "+s, time.Local)
		return t
	}
	raw := [][2]string{
		{"07:13:52", "Using interface ppp-797f95dc"},
		{"07:13:52", "local  IP address 174.92.237.165"},
		{"20:10:30", "No response to 3 echo-requests"},
		{"20:10:30", "Serial link appears to be disconnected."},
		{"20:10:30", "Connect time 776.7 minutes."},
		{"20:10:36", "Connection terminated."},
		{"20:10:36", "Sent PADT"},
		{"20:10:36", "Modem hangup"},
		{"20:11:11", "Timeout waiting for PADO packets"},
		{"20:11:11", "Unable to complete PPPoE Discovery phase 1"},
		{"20:11:52", "Timeout waiting for PADO packets"},
		{"20:12:32", "Timeout waiting for PADO packets"},
		{"20:12:52", "Using interface ppp-797f95dc"},
		{"20:12:54", "PAP authentication succeeded"},
		{"20:12:55", "local  IP address 174.92.235.203"},
		{"20:12:55", "remote IP address 10.11.16.145"},
	}
	out := make([]pppLine, len(raw))
	for i, r := range raw {
		out[i] = pppLine{At: at(r[0]), PID: 2537, Msg: r[1]}
	}
	return out
}

func testPPPWatcher() *pppWatcher {
	w := newPPPWatcher()
	w.gwFor = func(ifaceID string) (string, string) {
		if ifaceID == "797f95dc" {
			return "gw1", "Bell Fibe"
		}
		return "", ""
	}
	w.ifaceForPID = func(int) string { return "" }
	w.onlyPPPoE = func() (string, string) { return "", "" }
	return w
}

func feedAll(w *pppWatcher, lines []pppLine) []SDNEvent {
	var out []SDNEvent
	for _, l := range lines {
		out = append(out, w.feed(l)...)
	}
	return out
}

func TestPPPOutageSequence(t *testing.T) {
	ev := feedAll(testPPPWatcher(), pppOutageFixture())
	var kinds []string
	for _, e := range ev {
		kinds = append(kinds, e.Kind)
		if e.GatewayID != "gw1" || e.Name != "Bell Fibe" {
			t.Fatalf("event not tied to the gateway: %+v", e)
		}
	}
	want := "ppp_up,ppp_down,ppp_retry_failed,ppp_retry_failed,ppp_retry_failed,ppp_up"
	if strings.Join(kinds, ",") != want {
		t.Fatalf("kinds = %v, want %s", kinds, want)
	}
	down := ev[1]
	if !strings.Contains(down.Text, "ISP stopped answering") || down.Severity != "warn" {
		t.Fatalf("down: %+v", down)
	}
	up := ev[5]
	if !strings.Contains(up.Text, "(3 reconnect attempts failed)") {
		t.Fatalf("up must count the failed attempts: %q", up.Text)
	}
	if up.DownFor != 139 || !strings.Contains(up.Text, "174.92.235.203") || !strings.Contains(up.Text, "was 174.92.237.165") ||
		!strings.Contains(up.Text, "2 min 19 s") {
		t.Fatalf("up: %+v", up)
	}
	if ev[0].DownFor != 0 || strings.Contains(ev[0].Text, "was ") {
		t.Fatalf("first connection has no previous IP or downtime: %+v", ev[0])
	}
}

func TestPPPGatewayFallback(t *testing.T) {
	w := testPPPWatcher()
	w.onlyPPPoE = func() (string, string) { return "gw9", "Only Link" }
	ev := w.feed(pppLine{At: time.Now(), PID: 99, Msg: "Timeout waiting for PADO packets"})
	if len(ev) != 1 || ev[0].GatewayID != "gw9" || ev[0].Name != "Only Link" {
		t.Fatalf("fallback to the only PPPoE gateway: %+v", ev)
	}
	w.onlyPPPoE = func() (string, string) { return "", "" }
	ev = w.feed(pppLine{At: time.Now(), PID: 98, Msg: "Timeout waiting for PADO packets"})
	if len(ev) != 1 || ev[0].Name != "PPPoE" {
		t.Fatalf("fallback name: %+v", ev)
	}
}

func TestPPPCatchUpSkipsStored(t *testing.T) {
	lines := pppOutageFixture()
	w := testPPPWatcher()
	w.after = lines[8].At // the first PADO timeout was stored before a restart
	ev := feedAll(w, lines)
	if len(ev) != 3 || ev[0].Kind != "ppp_retry_failed" || ev[2].Kind != "ppp_up" {
		t.Fatalf("catch-up must only emit what is newer: %+v", ev)
	}
	// replayed state still gives the downtime and the previous address
	if ev[2].DownFor != 139 || !strings.Contains(ev[2].Text, "was 174.92.237.165") {
		t.Fatalf("state lost on catch-up: %+v", ev[2])
	}
}

func TestPPPAuthFailedAndStop(t *testing.T) {
	w := testPPPWatcher()
	now := time.Now()
	w.feed(pppLine{At: now, PID: 5, Msg: "Using interface ppp-797f95dc"})
	ev := w.feed(pppLine{At: now, PID: 5, Msg: "PAP authentication failed"})
	if len(ev) != 1 || ev[0].Kind != "ppp_auth_failed" || ev[0].Severity != "error" {
		t.Fatalf("auth: %+v", ev)
	}
	w.feed(pppLine{At: now, PID: 5, Msg: "Terminating on signal 15"})
	ev = w.feed(pppLine{At: now, PID: 5, Msg: "Connection terminated."})
	if len(ev) != 1 || ev[0].Kind != "ppp_down" || ev[0].Severity != "info" || !strings.Contains(ev[0].Text, "stopped by the system") {
		t.Fatalf("stop: %+v", ev)
	}
}

func TestPPPParseJournalJSON(t *testing.T) {
	l, ok := parsePPPJournal([]byte(`{"__REALTIME_TIMESTAMP":"1762391436000000","_PID":"2537","MESSAGE":"Connection terminated."}`))
	if !ok || l.PID != 2537 || l.Msg != "Connection terminated." || l.At.Unix() != 1762391436 {
		t.Fatalf("parse: %+v %v", l, ok)
	}
	if _, ok := parsePPPJournal([]byte(`not json`)); ok {
		t.Fatal("garbage must not parse")
	}
}

func TestPPPLongOutageThrottled(t *testing.T) {
	w := testPPPWatcher()
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.Local)
	w.feed(pppLine{At: t0, PID: 7, Msg: "Using interface ppp-797f95dc"})
	w.feed(pppLine{At: t0, PID: 7, Msg: "local  IP address 1.1.1.1"})
	w.feed(pppLine{At: t0.Add(time.Minute), PID: 7, Msg: "Connection terminated."})
	var retries []SDNEvent
	at := t0.Add(time.Minute)
	for i := 0; i < 90; i++ { // 1 hour of failures every 40 s
		at = at.Add(40 * time.Second)
		retries = append(retries, w.feed(pppLine{At: at, PID: 7, Msg: "Timeout waiting for PADO packets"})...)
	}
	// 3 one by one, then one summary per 15 minutes
	if len(retries) < 5 || len(retries) > 7 {
		t.Fatalf("an hour of retries gave %d events", len(retries))
	}
	if !strings.Contains(retries[3].Text, "Still not connected") {
		t.Fatalf("summary: %q", retries[3].Text)
	}
	up := w.feed(pppLine{At: at.Add(time.Minute), PID: 7, Msg: "local  IP address 2.2.2.2"})
	if len(up) != 1 || !strings.Contains(up[0].Text, "(90 reconnect attempts failed)") {
		t.Fatalf("up: %+v", up)
	}
}

func TestPPPRetrySpacing(t *testing.T) {
	w := testPPPWatcher()
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.Local)
	w.feed(pppLine{At: t0, PID: 7, Msg: "Connection terminated."})
	n := 0
	for at := t0.Add(40 * time.Second); at.Before(t0.Add(72 * time.Hour)); at = at.Add(40 * time.Second) {
		n += len(w.feed(pppLine{At: at, PID: 7, Msg: "Timeout waiting for PADO packets"}))
	}
	// 3 + ~3 (first hour) + ~23 (rest of day 1) + ~8 (days 2-3)
	if n < 30 || n > 42 {
		t.Fatalf("3 days down gave %d retry events", n)
	}
}

func TestPPPPeerHangup(t *testing.T) {
	w := testPPPWatcher()
	now := time.Now()
	w.feed(pppLine{At: now, PID: 5, Msg: "Modem hangup"})
	ev := w.feed(pppLine{At: now, PID: 5, Msg: "Connection terminated."})
	if len(ev) != 1 || !strings.Contains(ev[0].Text, "the ISP closed the connection") {
		t.Fatalf("peer hangup: %+v", ev)
	}
	// on .3 "Modem hangup" came after the echo failure: that reason stays
	ev = feedAll(testPPPWatcher(), pppOutageFixture())
	if !strings.Contains(ev[1].Text, "ISP stopped answering") {
		t.Fatalf("echo reason overwritten: %q", ev[1].Text)
	}
}

func TestPPPStaleReasonCleared(t *testing.T) {
	w := testPPPWatcher()
	ev := feedAll(w, pppOutageFixture()) // ends connected; its "Modem hangup" came after the drop
	_ = ev
	now := time.Now()
	got := w.feed(pppLine{At: now, PID: 2537, Msg: "Connection terminated."})
	if len(got) != 1 || !strings.Contains(got[0].Text, "connection lost") {
		t.Fatalf("stale reason leaked: %+v", got)
	}
}

func TestPPPJournalCursor(t *testing.T) {
	if c := pppJournalCursor([]byte(`{"__CURSOR":"s=abc;i=1","MESSAGE":"x"}`)); c != "s=abc;i=1" {
		t.Fatalf("cursor %q", c)
	}
}
