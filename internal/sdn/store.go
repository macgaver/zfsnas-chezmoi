package sdn

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Store keeps the feature's files under the portal config dir:
//
//	sdn/config.json                 confirmed (what the kernel runs)
//	sdn/draft.json                  the admin's pending edits, with a revision
//	sdn/state.json                  enabled flag + pre-SDN networking capture
//	sdn-history/<unixnano>-<id>.json  last 15 applied snapshots
//
// History sits in a top-level dir so the .znasbak export can skip it.
type Store struct{ Dir string }

// ErrStaleDraft is returned when a draft save is based on an older revision
// than the one on disk (another admin saved in between).
var ErrStaleDraft = errors.New("stale draft")

// HistoryKeep is how many applied snapshots are kept (owner decision).
const HistoryKeep = 15

type Draft struct {
	Revision int       `json:"revision"`
	EditedBy string    `json:"edited_by"`
	EditedAt time.Time `json:"edited_at"`
	Config   *Config   `json:"config"`
}

type Snapshot struct {
	ID           string    `json:"id"`
	User         string    `json:"user"`
	Summary      string    `json:"summary"`
	Outcome      string    `json:"outcome"` // pending | confirmed | auto-reverted | restored | imported
	At           time.Time `json:"at"`
	RestoredFrom string    `json:"restored_from,omitempty"`
	Config       *Config   `json:"config,omitempty"`
}

type State struct {
	Enabled                bool              `json:"enabled"`
	PreSDNInterfaces       string            `json:"pre_sdn_interfaces"`
	PreSDNSysctl           map[string]string `json:"pre_sdn_sysctl,omitempty"`
	NftablesServiceEnabled bool              `json:"nftables_service_enabled,omitempty"` // Disable re-enables it
	PreSDNDefaultRoute     string            `json:"pre_sdn_default_route,omitempty"`    // "via X dev Y": put back on disable
}

func (s Store) path(parts ...string) string {
	return filepath.Join(append([]string{s.Dir}, parts...)...)
}

// DefaultConfig is what a never-configured server starts from.
func DefaultConfig() *Config {
	c := &Config{Version: 1, Settings: Settings{Mode: "monitor", AntiLockout: true}}
	c.Normalize()
	return c
}

func (s Store) LoadConfirmed() (*Config, error) {
	c := DefaultConfig()
	if err := readJSON(s.path("sdn", "config.json"), c); err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, err
	}
	c.Normalize()
	return c, nil
}

func (s Store) SaveConfirmed(c *Config) error {
	return s.write(s.path("sdn", "config.json"), c)
}

// HasConfirmed reports whether a confirmed config exists on disk (the boot
// unit's ConditionPathExists uses the same file).
func (s Store) HasConfirmed() bool {
	_, err := os.Stat(s.path("sdn", "config.json"))
	return err == nil
}

func (s Store) LoadDraft() (*Draft, error) {
	d := &Draft{}
	if err := readJSON(s.path("sdn", "draft.json"), d); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		c, err := s.LoadConfirmed()
		if err != nil {
			return nil, err
		}
		return &Draft{Config: c}, nil
	}
	if d.Config == nil {
		d.Config = DefaultConfig()
	}
	d.Config.Normalize()
	return d, nil
}

func (s Store) SaveDraft(c *Config, baseRevision int, user string) (*Draft, error) {
	cur, err := s.LoadDraft()
	if err != nil {
		return nil, err
	}
	if cur.Revision != baseRevision {
		return cur, ErrStaleDraft
	}
	d := &Draft{Revision: cur.Revision + 1, EditedBy: user, EditedAt: time.Now().UTC(), Config: c}
	return d, s.write(s.path("sdn", "draft.json"), d)
}

// DiscardDraft drops the pending edits; the next LoadDraft returns a copy of
// the confirmed config. The revision counter keeps increasing so a client
// holding the old draft still gets ErrStaleDraft.
func (s Store) DiscardDraft() error {
	cur, err := s.LoadDraft()
	if err != nil {
		return err
	}
	c, err := s.LoadConfirmed()
	if err != nil {
		return err
	}
	return s.write(s.path("sdn", "draft.json"), &Draft{Revision: cur.Revision + 1, Config: c})
}

func (s Store) AddSnapshot(sn Snapshot) error {
	name := s.snapshotFile(sn)
	if err := s.write(name, sn); err != nil {
		return err
	}
	files, err := s.historyFiles()
	if err != nil {
		return err
	}
	for i := HistoryKeep; i < len(files); i++ {
		_ = os.Remove(files[i])
	}
	return nil
}

func (s Store) snapshotFile(sn Snapshot) string {
	return s.path("sdn-history", sn.At.UTC().Format("20060102T150405.000000000")+"-"+sn.ID+".json")
}

// historyFiles returns snapshot paths newest first (names sort by time).
func (s Store) historyFiles() ([]string, error) {
	entries, err := os.ReadDir(s.path("sdn-history"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			out = append(out, s.path("sdn-history", e.Name()))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, nil
}

func (s Store) ListSnapshots() ([]Snapshot, error) {
	files, err := s.historyFiles()
	if err != nil {
		return nil, err
	}
	out := make([]Snapshot, 0, len(files))
	for _, f := range files {
		var sn Snapshot
		if readJSON(f, &sn) == nil {
			sn.Config = nil
			out = append(out, sn)
		}
	}
	return out, nil
}

func (s Store) findSnapshot(id string) (string, error) {
	files, err := s.historyFiles()
	if err != nil {
		return "", err
	}
	for _, f := range files {
		if strings.HasSuffix(f, "-"+id+".json") {
			return f, nil
		}
	}
	return "", os.ErrNotExist
}

func (s Store) LoadSnapshot(id string) (*Snapshot, error) {
	f, err := s.findSnapshot(id)
	if err != nil {
		return nil, err
	}
	var sn Snapshot
	if err := readJSON(f, &sn); err != nil {
		return nil, err
	}
	return &sn, nil
}

func (s Store) SetOutcome(id, outcome string) error {
	f, err := s.findSnapshot(id)
	if err != nil {
		return err
	}
	var sn Snapshot
	if err := readJSON(f, &sn); err != nil {
		return err
	}
	sn.Outcome = outcome
	return s.write(f, sn)
}

func (s Store) LoadState() (State, error) {
	var st State
	err := readJSON(s.path("sdn", "state.json"), &st)
	if os.IsNotExist(err) {
		return State{}, nil
	}
	return st, err
}

func (s Store) SaveState(st State) error {
	return s.write(s.path("sdn", "state.json"), st)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// write stores v atomically (unique tmp + rename) with 0600: later phases
// keep secrets (PPPoE, WireGuard keys) in these files. When running as root
// (the boot unit, the appliance portal) every file and directory created is
// handed to the config dir's owner, so a non-root portal can still read what
// the boot unit rewrote.
func (s Store) write(path string, v any) error {
	if err := s.mkdirOwned(filepath.Dir(path)); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// On disk before it counts: the appliance's settings partition commits
	// only every 60 s, and a power cut must not lose an applied change.
	_, werr := f.Write(b)
	if werr == nil {
		werr = f.Sync()
	}
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		if werr != nil {
			return werr
		}
		return cerr
	}
	_ = os.Chmod(tmp, 0600)
	s.chownToOwner(tmp)
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func (s Store) mkdirOwned(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for d := dir; d != s.Dir && strings.HasPrefix(d, s.Dir); d = filepath.Dir(d) {
		s.chownToOwner(d)
	}
	return nil
}

func (s Store) chownToOwner(p string) {
	if os.Getuid() != 0 {
		return
	}
	fi, err := os.Stat(s.Dir)
	if err != nil {
		return
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		_ = os.Lchown(p, int(st.Uid), int(st.Gid))
	}
}

// Lock takes the feature-wide lock (an flock on sdn/lock) shared by the
// portal and the revert/boot one-shots, so a confirm can never race a revert
// in progress. Returns the unlock function.
func (s Store) Lock() (func(), error) {
	if err := s.mkdirOwned(s.path("sdn")); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.path("sdn", "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	s.chownToOwner(f.Name())
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// SaveApplying records the config being applied before the kernel is
// touched: if the portal dies mid-apply, the revert knows what to undo.
// MarkRestored records that the confirmed config came from a backup and has
// not been enabled yet: the Enable wizard offers to start from it or not.
func (s Store) MarkRestored() error {
	return s.write(s.path("sdn", "restored.json"), map[string]time.Time{"at": time.Now().UTC()})
}

// Restored reports the marker of MarkRestored.
func (s Store) Restored() bool {
	_, err := os.Stat(s.path("sdn", "restored.json"))
	return err == nil
}

// ClearRestored drops the marker.
func (s Store) ClearRestored() { _ = os.Remove(s.path("sdn", "restored.json")) }

func (s Store) SaveApplying(c *Config) error { return s.write(s.path("sdn", "applying.json"), c) }

func (s Store) LoadApplying() (*Config, error) {
	c := &Config{}
	if err := readJSON(s.path("sdn", "applying.json"), c); err != nil {
		return nil, err
	}
	c.Normalize()
	return c, nil
}

func (s Store) ClearApplying() { _ = os.Remove(s.path("sdn", "applying.json")) }

// SaveRevertPoint stores the config that was running before an apply; the
// pending revert restores exactly this, whatever the history holds.
func (s Store) SaveRevertPoint(c *Config) error {
	return s.write(s.path("sdn", "revert.json"), c)
}

func (s Store) LoadRevertPoint() (*Config, error) {
	c := &Config{}
	if err := readJSON(s.path("sdn", "revert.json"), c); err != nil {
		return nil, err
	}
	c.Normalize()
	return c, nil
}
