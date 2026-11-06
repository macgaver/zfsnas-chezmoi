package system

// PPPoE history from pppd's own log lines (journal tag "pppd"): link down
// with the reason, redials the provider ignored, login refused, back up with
// the public address and the downtime. It works whether or not the gateway
// is monitored: on 2026-11-05 an outage on .3 left no trace but these lines.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"zfsnas/internal/sdn"
)

type pppLine struct {
	At  time.Time
	PID int
	Msg string
}

type pppGWState struct {
	lastIP string
	downAt time.Time
	reason string // set by the lines just before "Connection terminated."
	sev    string
	fails  int       // reconnect attempts that failed since the link went down
	lastEv time.Time // when a retry event was last returned
}

// A provider that stays down makes pppd retry every 40 s or so: the first
// few failures are told one by one, then a summary now and then, so a
// long outage does not push everything else out of the history.
const pppRetryEach = 3

// pppRetryEvery spaces the summaries as an outage drags on: every 15 min in
// the first hour, hourly the first day, then every 6 hours.
func pppRetryEvery(down time.Duration) time.Duration {
	switch {
	case down < time.Hour:
		return 15 * time.Minute
	case down < 24*time.Hour:
		return time.Hour
	}
	return 6 * time.Hour
}

type pppWatcher struct {
	pidIface    map[int]string // from "Using interface ppp-<id>"
	gw          map[string]*pppGWState
	after       time.Time // events at or before this are already stored
	gwFor       func(ifaceID string) (gwID, name string)
	ifaceForPID func(pid int) string
	onlyPPPoE   func() (gwID, name string)
}

func newPPPWatcher() *pppWatcher {
	return &pppWatcher{pidIface: map[int]string{}, gw: map[string]*pppGWState{}}
}

var (
	pppEchoRe  = regexp.MustCompile(`^No response to (\d+) echo-requests`)
	pppLocalRe = regexp.MustCompile(`^local\s+IP address (\S+)`)
	pppIfRe    = regexp.MustCompile(`^Using interface ppp-(\S+)`)
)

// who names the gateway a pppd process belongs to.
func (w *pppWatcher) who(pid int) (string, string) {
	id := w.pidIface[pid]
	if id == "" && w.ifaceForPID != nil {
		if id = w.ifaceForPID(pid); id != "" {
			w.pidIface[pid] = id
		}
	}
	if id != "" && w.gwFor != nil {
		if g, n := w.gwFor(id); g != "" {
			return g, n
		}
	}
	if w.onlyPPPoE != nil {
		if g, n := w.onlyPPPoE(); g != "" {
			return g, n
		}
	}
	return "", "PPPoE"
}

func (w *pppWatcher) state(gwID, name string) *pppGWState {
	k := gwID
	if k == "" {
		k = "name:" + name
	}
	s := w.gw[k]
	if s == nil {
		s = &pppGWState{}
		w.gw[k] = s
	}
	return s
}

// fmtDowntime: "45 s", "2 min 19 s", "1 h 4 min".
func fmtDowntime(d time.Duration) string {
	s := int64(d.Round(time.Second) / time.Second)
	switch {
	case s < 60:
		return fmt.Sprintf("%d s", s)
	case s < 3600:
		return fmt.Sprintf("%d min %d s", s/60, s%60)
	}
	return fmt.Sprintf("%d h %d min", s/3600, s%3600/60)
}

// feed takes one pppd line and returns the events it completes. State is
// always updated; events at or before w.after are not returned (catch-up).
func (w *pppWatcher) feed(l pppLine) []SDNEvent {
	msg := strings.TrimSpace(l.Msg)
	if m := pppIfRe.FindStringSubmatch(msg); m != nil {
		w.pidIface[l.PID] = m[1]
		return nil
	}
	gwID, name := w.who(l.PID)
	st := w.state(gwID, name)
	var ev *SDNEvent
	mk := func(kind, sev, text string) *SDNEvent {
		return &SDNEvent{At: l.At, Kind: kind, Severity: sev, GatewayID: gwID, Name: name, Text: text}
	}
	switch {
	case pppEchoRe.MatchString(msg):
		n := pppEchoRe.FindStringSubmatch(msg)[1]
		st.reason, st.sev = "ISP stopped answering (no reply to "+n+" echo requests)", "warn"
	case strings.HasPrefix(msg, "LCP terminated by peer"):
		st.reason, st.sev = "ISP ended the session", "warn"
	case strings.HasPrefix(msg, "Hangup (SIGHUP)"):
		st.reason, st.sev = "redial requested by the gateway monitor (ping tests failed)", "warn"
	case msg == "Modem hangup" && st.reason == "":
		// before "Connection terminated." only when the other end hung up
		st.reason, st.sev = "the ISP closed the connection", "warn"
	case strings.HasPrefix(msg, "Terminating on signal"):
		st.reason, st.sev = "stopped by the system (shutdown, restart or configuration change)", "info"
	case msg == "Connection terminated.":
		r, sev := st.reason, st.sev
		if r == "" {
			r, sev = "connection lost", "warn"
		}
		st.reason, st.sev = "", ""
		if st.downAt.IsZero() {
			st.downAt = l.At
		}
		ev = mk("ppp_down", sev, "PPPoE link down: "+r)
	case strings.HasPrefix(msg, "Timeout waiting for PADO"):
		if st.downAt.IsZero() {
			st.downAt = l.At
		}
		st.fails++
		st.reason, st.sev = "", "" // a hangup logged after the drop is not the next one's reason
		switch {
		case st.fails <= pppRetryEach:
			ev = mk("ppp_retry_failed", "warn", "Reconnect attempt failed: ISP did not answer (no PADO)")
		case l.At.Sub(st.lastEv) >= pppRetryEvery(l.At.Sub(st.downAt)):
			ev = mk("ppp_retry_failed", "warn", fmt.Sprintf("Still not connected: %d reconnect attempts failed so far, down for %s; the ISP does not answer (no PADO)",
				st.fails, fmtDowntime(l.At.Sub(st.downAt))))
		}
		if ev != nil {
			st.lastEv = l.At
		}
	case strings.Contains(msg, "authentication failed"):
		proto := strings.Fields(msg)[0]
		ev = mk("ppp_auth_failed", "error", "Login refused by the ISP ("+proto+" authentication failed): check the PPPoE username and password")
	case pppLocalRe.MatchString(msg):
		ip := pppLocalRe.FindStringSubmatch(msg)[1]
		text := "PPPoE link up: public IP " + ip
		if st.lastIP != "" && st.lastIP != ip {
			text += " (was " + st.lastIP + ")"
		}
		ev = mk("ppp_up", "info", text)
		if !st.downAt.IsZero() && l.At.After(st.downAt) {
			d := l.At.Sub(st.downAt)
			ev.DownFor = int64(d.Round(time.Second) / time.Second)
			ev.Text += ", down for " + fmtDowntime(d)
		}
		if st.fails > 0 {
			ev.Text += fmt.Sprintf(" (%d reconnect attempt%s failed)", st.fails, map[bool]string{true: "", false: "s"}[st.fails == 1])
		}
		st.lastIP, st.downAt, st.fails = ip, time.Time{}, 0
		st.reason, st.sev = "", ""
	}
	if ev == nil || !l.At.After(w.after) {
		return nil
	}
	return []SDNEvent{*ev}
}

// pppJournalCursor is the record's journal position (__CURSOR).
func pppJournalCursor(b []byte) string {
	var j struct {
		C string `json:"__CURSOR"`
	}
	_ = json.Unmarshal(b, &j)
	return j.C
}

// parsePPPJournal reads one `journalctl -o json` record.
func parsePPPJournal(b []byte) (pppLine, bool) {
	var j struct {
		TS  string `json:"__REALTIME_TIMESTAMP"`
		PID string `json:"_PID"`
		Msg any    `json:"MESSAGE"`
	}
	if json.Unmarshal(b, &j) != nil {
		return pppLine{}, false
	}
	us, err := strconv.ParseInt(j.TS, 10, 64)
	msg, ok := j.Msg.(string) // binary messages come as byte arrays: skip
	if err != nil || !ok {
		return pppLine{}, false
	}
	pid, _ := strconv.Atoi(j.PID)
	return pppLine{At: time.UnixMicro(us), PID: pid, Msg: msg}, true
}

// pppIfaceFromProc reads `pppd call znas-<id>` from the process command line.
func pppIfaceFromProc(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	args := strings.Split(string(b), "\x00")
	for i, a := range args {
		if a == "call" && i+1 < len(args) && strings.HasPrefix(args[i+1], sdn.PPPoEPeerName("")) {
			return strings.TrimPrefix(args[i+1], sdn.PPPoEPeerName(""))
		}
	}
	return ""
}

// sdnPPPWatchLoop follows pppd's journal for as long as the daemon lives.
// It replays the last 7 days first (all boots) so it knows the previous
// address and when a link went down, and stores only what is newer than the
// history.
func sdnPPPWatchLoop(st sdn.Store) {
	w := newPPPWatcher()
	gwFor := func(ifaceID string) (string, string) {
		c, err := st.LoadConfirmed()
		if err != nil {
			return "", ""
		}
		for _, g := range c.Gateways {
			if g.Interface == ifaceID {
				return g.ID, g.Name
			}
		}
		return "", ""
	}
	w.gwFor = gwFor
	w.ifaceForPID = pppIfaceFromProc
	w.onlyPPPoE = func() (string, string) {
		c, err := st.LoadConfirmed()
		if err != nil {
			return "", ""
		}
		var id, name string
		n := 0
		for _, g := range c.Gateways {
			if in := c.InterfaceByID(g.Interface); in != nil && in.Kind == "pppoe" {
				id, name, n = g.ID, g.Name, n+1
			}
		}
		if n == 1 {
			return id, name
		}
		return "", ""
	}
	// systemd 256+ `journalctl -f` only shows the current boot, so the
	// replay (earlier boots too: the link went down before the reboot) is a
	// plain read, and the follow resumes from its last journal cursor.
	cursor := ""
	feed := func(b []byte) {
		l, ok := parsePPPJournal(b)
		if !ok {
			return
		}
		if c := pppJournalCursor(b); c != "" {
			cursor = c
		}
		for _, e := range w.feed(l) {
			if err := SDNRecordEvent(st.Dir, e); err != nil {
				log.Printf("[sdn-events] %v", err)
			}
			w.after = e.At
		}
	}
	run := func(args ...string) error {
		cmd := exec.Command("journalctl", append([]string{"-t", "pppd", "-o", "json", "--no-pager"}, args...)...)
		out, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			feed(sc.Bytes())
		}
		return cmd.Wait()
	}
	w.after = sdnNewestEvent(st.Dir, "ppp_")
	if err := run("--since", time.Now().Add(-7*24*time.Hour).Format("2006-01-02 15:04:05")); err != nil {
		log.Printf("[sdn-events] pppd journal: %v", err)
	}
	for {
		args := []string{"-f", "-n", "0"}
		if cursor != "" {
			args = []string{"-f", "--after-cursor", cursor}
		}
		if err := run(args...); err != nil {
			log.Printf("[sdn-events] pppd journal: %v", err)
			time.Sleep(time.Minute)
		}
		time.Sleep(5 * time.Second)
	}
}
