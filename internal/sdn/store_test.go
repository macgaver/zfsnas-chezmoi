package sdn

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestStore_LoadConfirmedDefault(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	c, err := s.LoadConfirmed()
	if err != nil {
		t.Fatal(err)
	}
	if c.Settings.Mode != "monitor" || !c.Settings.AntiLockout || c.Version != 1 {
		t.Fatalf("unexpected default: %+v", c.Settings)
	}
}

func TestStore_ConfirmedRoundTrip(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if err := s.SaveConfirmed(ownerSample()); err != nil {
		t.Fatal(err)
	}
	c, err := s.LoadConfirmed()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Interfaces) != 5 || c.Interfaces[4].Device != "enp2s0-v800" {
		t.Fatalf("round trip lost data: %+v", c.Interfaces)
	}
	fi, _ := os.Stat(filepath.Join(s.Dir, "sdn", "config.json"))
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("config.json mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestStore_DraftStaleRevision(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	d, err := s.SaveDraft(ownerSample(), 0, "alice")
	if err != nil || d.Revision != 1 {
		t.Fatalf("first save: rev %v err %v", d, err)
	}
	if _, err := s.SaveDraft(ownerSample(), 0, "bob"); !errors.Is(err, ErrStaleDraft) {
		t.Fatalf("stale save err = %v, want ErrStaleDraft", err)
	}
	got, _ := s.LoadDraft()
	if got.EditedBy != "alice" || got.Revision != 1 {
		t.Fatalf("draft = %+v", got)
	}
}

func TestStore_DraftDefaultsToConfirmed(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	_ = s.SaveConfirmed(ownerSample())
	d, err := s.LoadDraft()
	if err != nil || d.Revision != 0 || len(d.Config.Rules) != 2 {
		t.Fatalf("draft = %+v err %v", d, err)
	}
	_, _ = s.SaveDraft(&Config{Version: 1}, 0, "a")
	if err := s.DiscardDraft(); err != nil {
		t.Fatal(err)
	}
	d, _ = s.LoadDraft()
	if len(d.Config.Rules) != 2 {
		t.Fatalf("discard did not fall back to confirmed")
	}
}

func TestStore_HistoryKeeps15(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	base := time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 17; i++ {
		if err := s.AddSnapshot(Snapshot{ID: NewID(), User: "admin", Summary: "x", Outcome: "confirmed",
			At: base.Add(time.Duration(i) * time.Minute), Config: ownerSample()}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 15 {
		t.Fatalf("kept %d, want 15", len(list))
	}
	if !list[0].At.Equal(base.Add(16 * time.Minute)) {
		t.Fatalf("newest first violated: %v", list[0].At)
	}
	files, _ := os.ReadDir(filepath.Join(s.Dir, "sdn-history"))
	if len(files) != 15 {
		t.Fatalf("%d files on disk, want 15", len(files))
	}
}

func TestStore_ListOmitsConfig(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	id := NewID()
	_ = s.AddSnapshot(Snapshot{ID: id, At: time.Now(), Outcome: "pending", Config: ownerSample()})
	list, _ := s.ListSnapshots()
	if list[0].Config != nil {
		t.Fatal("list must omit config")
	}
	sn, err := s.LoadSnapshot(id)
	if err != nil || sn.Config == nil {
		t.Fatalf("load: %v %v", sn, err)
	}
	if err := s.SetOutcome(id, "confirmed"); err != nil {
		t.Fatal(err)
	}
	sn, _ = s.LoadSnapshot(id)
	if sn.Outcome != "confirmed" {
		t.Fatalf("outcome %q", sn.Outcome)
	}
}

func TestStore_State(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	st, err := s.LoadState()
	if err != nil || st.Enabled {
		t.Fatalf("default state %+v %v", st, err)
	}
	_ = s.SaveState(State{Enabled: true, PreSDNInterfaces: "auto lo\n"})
	st, _ = s.LoadState()
	if !st.Enabled || st.PreSDNInterfaces != "auto lo\n" {
		t.Fatalf("state %+v", st)
	}
}

func TestStore_RevertPoint(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, err := s.LoadRevertPoint(); err == nil {
		t.Fatal("expected an error when no revert point exists")
	}
	_ = s.SaveRevertPoint(ownerSample())
	c, err := s.LoadRevertPoint()
	if err != nil || len(c.Rules) != 2 {
		t.Fatalf("revert point %v %v", c, err)
	}
}

func TestStore_LockExcludes(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	unlock, err := s.Lock()
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{})
	go func() {
		u2, err := s.Lock() // separate open file description → really excluded
		if err == nil {
			u2()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("second Lock did not wait")
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("second Lock never acquired after unlock")
	}
}

func TestStore_Applying(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, err := s.LoadApplying(); err == nil {
		t.Fatal("expected no applying config")
	}
	_ = s.SaveApplying(ownerSample())
	c, err := s.LoadApplying()
	if err != nil || len(c.Rules) != 2 {
		t.Fatalf("%v %v", c, err)
	}
	s.ClearApplying()
	if _, err := s.LoadApplying(); err == nil {
		t.Fatal("not cleared")
	}
}

// Files written by root (the boot unit) must stay owned by the config dir's
// owner, or the non-root portal can no longer read them.
func TestStore_RootWritesKeepOwner(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	dir := t.TempDir()
	_ = os.Chown(dir, 4242, 4242)
	s := Store{Dir: dir}
	_ = s.SaveConfirmed(ownerSample())
	for _, p := range []string{filepath.Join(dir, "sdn"), filepath.Join(dir, "sdn", "config.json")} {
		fi, _ := os.Stat(p)
		if st := fi.Sys().(*syscall.Stat_t); st.Uid != 4242 {
			t.Fatalf("%s owned by %d", p, st.Uid)
		}
	}
}
