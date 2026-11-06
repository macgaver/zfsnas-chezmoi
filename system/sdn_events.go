package system

// Firewall event history: the important things that happened to the
// gateways, dynamic DNS and the firewall itself, in plain words, so a user
// can see when the internet went down and why. Written by the gateway daemon
// (root) to config/sdn/events.jsonl, 0644 so the portal can read it; capped.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SDNEvent is one line of the history.
type SDNEvent struct {
	At        time.Time `json:"at"`
	Kind      string    `json:"kind"`
	Severity  string    `json:"severity"` // info | warn | error
	GatewayID string    `json:"gateway_id,omitempty"`
	Name      string    `json:"name,omitempty"`
	Text      string    `json:"text"`
	DownFor   int64     `json:"down_for,omitempty"` // seconds, on a recovery
}

const (
	sdnEventsKeep = 1000
	sdnEventsTrim = 1100 // rewrite only now and then
)

var sdnEventsMu sync.Mutex

// SDNEventCategory groups a kind for the filters: gateway, ddns or system.
func SDNEventCategory(kind string) string {
	switch {
	case strings.HasPrefix(kind, "ppp_"), strings.HasPrefix(kind, "gw_"):
		return "gateway"
	case strings.HasPrefix(kind, "ddns_"):
		return "ddns"
	}
	return "system"
}

// SDNEventsPath is the history file under the portal's config directory.
func SDNEventsPath(configDir string) string {
	return filepath.Join(configDir, "sdn", "events.jsonl")
}

// SDNRecordEvent appends e to the history, keeping the newest 1000.
func SDNRecordEvent(configDir string, e SDNEvent) error {
	if e.Severity == "" {
		e.Severity = "info"
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	sdnEventsMu.Lock()
	defer sdnEventsMu.Unlock()
	p := SDNEventsPath(configDir)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}
	// A line cut short by a crash would swallow the next record.
	prefix := []byte{}
	if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
		if f, err := os.Open(p); err == nil {
			last := make([]byte, 1)
			if _, err := f.ReadAt(last, fi.Size()-1); err == nil && last[0] != '\n' {
				prefix = []byte{'\n'}
			}
			f.Close()
		}
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	_ = f.Chmod(0644)
	_, err = f.Write(append(append(prefix, b...), '\n'))
	f.Close()
	if err != nil {
		return err
	}
	lines := sdnEventLines(p)
	if len(lines) > sdnEventsTrim {
		keep := bytes.Join(lines[len(lines)-sdnEventsKeep:], []byte{'\n'})
		tmp := p + ".tmp"
		if err := os.WriteFile(tmp, append(keep, '\n'), 0644); err != nil {
			return err
		}
		return os.Rename(tmp, p)
	}
	return nil
}

func sdnEventLines(p string) [][]byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if l := bytes.TrimSpace(sc.Bytes()); len(l) > 0 {
			out = append(out, append([]byte(nil), l...))
		}
	}
	return out
}

// SDNReadEvents returns the history newest first; category "" or "all" for
// everything, limit <= 0 for no limit.
func SDNReadEvents(configDir, category string, limit int) []SDNEvent {
	lines := sdnEventLines(SDNEventsPath(configDir))
	out := []SDNEvent{}
	for i := len(lines) - 1; i >= 0; i-- {
		var e SDNEvent
		if json.Unmarshal(lines[i], &e) != nil || e.Kind == "" {
			continue
		}
		if category != "" && category != "all" && SDNEventCategory(e.Kind) != category {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// sdnNewestEvent is the time of the newest stored event whose kind starts
// with prefix (zero if none): the pppd catch-up starts after it.
func sdnNewestEvent(configDir, prefix string) time.Time {
	for _, e := range SDNReadEvents(configDir, "all", 0) {
		if strings.HasPrefix(e.Kind, prefix) {
			return e.At
		}
	}
	return time.Time{}
}
