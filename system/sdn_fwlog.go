package system

// Firewall log (6.11.27): the kernel log lines of rules with "Log matching
// connections" (nft `log prefix "znas r:<id> "`, rate-limited per rule —
// see internal/sdn/compile.go), read back from the journal for the
// Monitor → Firewall log page.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"zfsnas/internal/sdn"
)

// SDNLogEntry is one logged packet.
type SDNLogEntry struct {
	Time  time.Time `json:"time"`
	Rule  string    `json:"rule"`
	In    string    `json:"in,omitempty"`
	Out   string    `json:"out,omitempty"`
	Src   string    `json:"src"`
	Dst   string    `json:"dst"`
	Proto string    `json:"proto"`
	SPort int       `json:"sport,omitempty"`
	DPort int       `json:"dport,omitempty"`
	Len   int       `json:"len,omitempty"`
}

// parseFWLogLine reads the message of one kernel log line:
// "znas r:<id> IN=eth0 OUT= MAC=… SRC=a DST=b LEN=60 … PROTO=TCP SPT=1 DPT=2 …".
func parseFWLogLine(msg string) (SDNLogEntry, bool) {
	i := strings.Index(msg, sdn.LogPrefix)
	if i < 0 {
		return SDNLogEntry{}, false
	}
	rest := msg[i+len(sdn.LogPrefix):]
	f := strings.Fields(rest)
	if len(f) == 0 {
		return SDNLogEntry{}, false
	}
	e := SDNLogEntry{Rule: f[0]}
	for _, kv := range f[1:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "IN":
			e.In = v
		case "OUT":
			e.Out = v
		case "SRC":
			e.Src = v
		case "DST":
			e.Dst = v
		case "PROTO":
			e.Proto = v
		case "SPT":
			e.SPort, _ = strconv.Atoi(v)
		case "DPT":
			e.DPort, _ = strconv.Atoi(v)
		case "LEN":
			if e.Len == 0 { // first LEN is the IP length
				e.Len, _ = strconv.Atoi(v)
			}
		}
	}
	if e.Src == "" || e.Rule == "" {
		return SDNLogEntry{}, false
	}
	return e, true
}

// journal record (journalctl -o json): MESSAGE is a string, or an array of
// bytes when it is not valid UTF-8.
type fwJournalRec struct {
	Message  json.RawMessage `json:"MESSAGE"`
	Realtime string          `json:"__REALTIME_TIMESTAMP"`
}

func (r fwJournalRec) text() string {
	var s string
	if json.Unmarshal(r.Message, &s) == nil {
		return s
	}
	var b []byte
	if json.Unmarshal(r.Message, &b) == nil {
		return string(b)
	}
	var ints []int
	if json.Unmarshal(r.Message, &ints) == nil {
		out := make([]byte, len(ints))
		for i, v := range ints {
			out[i] = byte(v)
		}
		return string(out)
	}
	return ""
}

func parseFWJournal(out []byte) []SDNLogEntry {
	var res []SDNLogEntry
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var rec fwJournalRec
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		e, ok := parseFWLogLine(rec.text())
		if !ok {
			continue
		}
		if us, err := strconv.ParseInt(rec.Realtime, 10, 64); err == nil {
			e.Time = time.UnixMicro(us).UTC()
		}
		res = append(res, e)
	}
	sort.SliceStable(res, func(i, j int) bool { return res[i].Time.After(res[j].Time) })
	return res
}

// errNoJournalMatch: journalctl --grep found nothing (exit 1, no output).
var errNoJournalMatch = fmt.Errorf("no match")

// sdnJournalctl runs journalctl — through sudo when this process is not
// root (as the journal viewer does): a service user can read its own
// journal only, and then "succeeds" with nothing.
var sdnJournalctl = func(args ...string) ([]byte, error) {
	name := "journalctl"
	if os.Geteuid() != 0 {
		name, args = "sudo", append([]string{"-n", "journalctl"}, args...)
	}
	var stderr bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 && len(out) == 0 && strings.TrimSpace(stderr.String()) == "" {
			return nil, errNoJournalMatch
		}
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return out, fmt.Errorf("%s", msg)
		}
	}
	return out, err
}

// SDNFirewallLog returns the newest logged packets (of one rule when rule
// is set) from the last 24 hours, at most limit.
func SDNFirewallLog(rule string, limit int) ([]SDNLogEntry, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	if rule != "" && !validRuleID(rule) {
		return nil, fmt.Errorf("invalid rule id")
	}
	pat := sdn.LogPrefix + rule
	if rule != "" {
		pat += " "
	}
	args := []string{"-k", "-o", "json", "--no-pager", "--since", "-24h", "-n", strconv.Itoa(limit), "--grep", pat}
	out, err := sdnJournalctl(args...)
	if err == errNoJournalMatch {
		return []SDNLogEntry{}, nil
	}
	if err != nil && len(out) == 0 && strings.Contains(strings.ToLower(err.Error()), "pattern") {
		// journalctl built without pattern matching: filter here instead.
		args = []string{"-k", "-o", "json", "--no-pager", "--since", "-24h", "-n", strconv.Itoa(limit * 20)}
		out, err = sdnJournalctl(args...)
	}
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("reading the kernel log: %v", err)
	}
	res := parseFWJournal(out)
	if rule != "" {
		keep := res[:0]
		for _, e := range res {
			if e.Rule == rule {
				keep = append(keep, e)
			}
		}
		res = keep
	}
	if len(res) > limit {
		res = res[:limit]
	}
	return res, nil
}

func validRuleID(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
