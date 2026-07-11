package system

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// JournalEntry is one parsed line from `journalctl -o json`, reduced to the
// columns the Activity & Events journal viewer shows. The host name is
// deliberately omitted — every entry comes from the local box, so a hostname
// column would just repeat the same value on every row.
type JournalEntry struct {
	TS      string `json:"ts"`       // human-readable local time "2006-01-02 15:04:05"
	TSUnix  int64  `json:"ts_unix"`  // milliseconds since epoch (for sorting / live dedup)
	Prio    int    `json:"prio"`     // syslog severity 0-7 (0 = emerg, 7 = debug)
	PrioLbl string `json:"prio_lbl"` // "err", "warning", "info", …
	Unit    string `json:"unit"`     // syslog identifier / service name
	PID     string `json:"pid"`      // process id, if any
	Message string `json:"message"`  // the log line text
}

// journalKindArgs maps a viewer tab to its journalctl source selector.
//   - kernel : the kernel ring buffer (dmesg-style)
//   - zfsnas : this portal's own systemd unit
//   - samba  : the Samba daemons (smbd + nmbd; multiple -u flags are OR'd)
//   - incus  : the virtualization daemon's unit (only meaningful when Incus is on)
//   - all    : the full system journal
var journalKindArgs = map[string][]string{
	"kernel": {"-k"},
	"zfsnas": {"-u", "zfsnas"},
	"samba":  {"-u", "smbd", "-u", "nmbd"},
	"incus":  {"-u", "incus"},
	"all":    {},
}

var (
	journalAvailMu   sync.Mutex
	journalAvailVal  bool
	journalAvailWhen time.Time
)

// JournalAvailable reports whether the portal can read the journal via passwordless
// sudo. The journal tabs are hidden in the UI when this is false (e.g. the sudoers
// file predates the ZFSNAS_JOURNAL grant and hasn't been regenerated). The result
// is cached briefly so the per-tab availability probe doesn't spawn sudo on every
// open.
func JournalAvailable() bool {
	journalAvailMu.Lock()
	defer journalAvailMu.Unlock()
	if time.Since(journalAvailWhen) < 20*time.Second && !journalAvailWhen.IsZero() {
		return journalAvailVal
	}
	// `-n 0 --no-pager` returns immediately with no output; we only care that
	// sudo grants the command without prompting for a password (-n).
	cmd := exec.Command("sudo", "-n", "journalctl", "-n", "0", "--no-pager")
	err := cmd.Run()
	journalAvailVal = err == nil
	journalAvailWhen = time.Now()
	return journalAvailVal
}

// ReadJournal returns the last `lines` entries for the given kind, oldest-first
// (matching journalctl's default ordering with -n). kind must be one of the keys
// in journalKindArgs.
//
// maxPrio filters by syslog severity using journalctl's native -p: when in the
// range 0..7, only entries at that priority OR MORE SEVERE are returned (lower
// number = more severe, so -p 4/"warning" yields priorities 0..4). A value < 0
// or > 7 means "no filter" (all levels).
func ReadJournal(kind string, lines, maxPrio int) ([]JournalEntry, error) {
	sel, ok := journalKindArgs[kind]
	if !ok {
		return nil, fmt.Errorf("unknown journal kind %q", kind)
	}
	if lines < 1 {
		lines = 25
	}
	args := []string{"-n", "journalctl"}
	args = append(args, sel...)
	if maxPrio >= 0 && maxPrio <= 7 {
		args = append(args, "-p", strconv.Itoa(maxPrio))
	}
	args = append(args, "-o", "json", "-n", strconv.Itoa(lines), "--no-pager")

	var out, stderr bytes.Buffer
	cmd := exec.Command("sudo", args...)
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("journalctl: %s", msg)
	}

	entries := make([]JournalEntry, 0, lines)
	sc := bufio.NewScanner(&out)
	// Journal messages can be long; raise the line limit well above the default 64 KiB.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			continue // skip malformed lines rather than failing the whole read
		}
		entries = append(entries, parseJournalEntry(m))
	}
	return entries, nil
}

// parseJournalEntry turns one decoded journal record into a JournalEntry,
// tolerating journald's quirks: MESSAGE (and other fields) can be a JSON string
// or a JSON array of byte values when the original contained non-UTF8 data.
func parseJournalEntry(m map[string]json.RawMessage) JournalEntry {
	var e JournalEntry

	if usecStr := jfield(m, "__REALTIME_TIMESTAMP"); usecStr != "" {
		if usec, err := strconv.ParseInt(usecStr, 10, 64); err == nil {
			t := time.UnixMicro(usec).Local()
			e.TS = t.Format("2006-01-02 15:04:05")
			e.TSUnix = usec / 1000
		}
	}

	e.Prio = 6 // default to "info" when unset
	e.PrioLbl = prioLabel(6)
	if p := jfield(m, "PRIORITY"); p != "" {
		if pi, err := strconv.Atoi(p); err == nil {
			e.Prio = pi
			e.PrioLbl = prioLabel(pi)
		}
	}

	// Name column: syslog identifier first, then the command, then the unit
	// (with the ".service" suffix trimmed for readability).
	e.Unit = jfield(m, "SYSLOG_IDENTIFIER")
	if e.Unit == "" {
		e.Unit = jfield(m, "_COMM")
	}
	if e.Unit == "" {
		if u := jfield(m, "_SYSTEMD_UNIT"); u != "" {
			e.Unit = strings.TrimSuffix(u, ".service")
		}
	}
	if e.Unit == "" {
		e.Unit = "-"
	}

	e.PID = jfield(m, "_PID")
	if e.PID == "" {
		e.PID = jfield(m, "SYSLOG_PID")
	}

	e.Message = jfield(m, "MESSAGE")
	return e
}

// jfield extracts a journal field as a string. journald encodes most fields as
// JSON strings, but binary/non-UTF8 values come through as an array of integers
// (one per byte); both shapes are handled here.
func jfield(m map[string]json.RawMessage, key string) string {
	raw, ok := m[key]
	if !ok {
		return ""
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return ""
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err == nil {
			return s
		}
		return ""
	}
	if trimmed[0] == '[' {
		var nums []int
		if err := json.Unmarshal(trimmed, &nums); err == nil {
			b := make([]byte, 0, len(nums))
			for _, n := range nums {
				b = append(b, byte(n))
			}
			return string(b)
		}
		return ""
	}
	return string(trimmed)
}

func prioLabel(p int) string {
	switch p {
	case 0:
		return "emerg"
	case 1:
		return "alert"
	case 2:
		return "crit"
	case 3:
		return "err"
	case 4:
		return "warning"
	case 5:
		return "notice"
	case 6:
		return "info"
	case 7:
		return "debug"
	default:
		return "info"
	}
}
