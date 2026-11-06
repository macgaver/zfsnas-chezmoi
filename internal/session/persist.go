// Encrypted on-disk persistence for the session store. Keeps users logged in
// across `systemctl restart zfsnas`. Threat model:
//
//   - Anyone who can read sessions.json.enc can mint a request as any
//     currently-logged-in user. Hence AES-256-GCM at rest with a per-install
//     32-byte key in config/session.key (mode 0600 — same pattern alerts.go
//     uses for SMTP passwords).
//   - Tampering or key rotation is detected by GCM auth failure: the file is
//     wiped and we keep going. All users have to log in once. Never panic
//     a corrupted sessions file out of an otherwise-healthy server.
//   - Per-request writes would be insane (the SPA polls every few seconds);
//     instead the in-memory map is the source of truth and a 60-s ticker
//     plus an explicit FlushNow() on graceful shutdown captures the
//     LastActivityAt heartbeat. The worst case after an unclean crash is
//     that an inactivity timer fires a few seconds early.

package session

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"zfsnas/internal/secret"
)

const (
	persistFile = "sessions.json.enc"
	persistKey  = "session.key"
	flushPeriod = 60 * time.Second
)

type persistConfig struct {
	path string
	key  []byte
	// Save path is invoked from a singleflight-ish goroutine — multiple
	// rapid Create/Delete/Touch calls coalesce into one disk write.
	dirtyMu sync.Mutex
	dirty   bool
}

// BindPersistence wires the store to an encrypted file under configDir
// and immediately rehydrates any previously-persisted sessions. Returns
// (loaded, error). loaded is the count of valid sessions restored.
//
// On any decrypt / unmarshal failure, the file is removed and zero is
// returned — all users have to log in once but the server still starts.
func (s *Store) BindPersistence(configDir string) (int, error) {
	keyPath := filepath.Join(configDir, persistKey)
	key, err := secret.LoadOrCreateKey(keyPath)
	if err != nil {
		return 0, err
	}
	cfg := &persistConfig{
		path: filepath.Join(configDir, persistFile),
		key:  key,
	}
	s.mu.Lock()
	s.persist = cfg
	s.mu.Unlock()

	loaded := s.loadFromDisk()
	go s.flushLoop()
	return loaded, nil
}

// loadFromDisk decrypts and replays the persisted session map. Sessions
// past their hard cap or past their idle timeout are dropped silently.
// Failure modes (missing file, bad decrypt, bad JSON) are non-fatal: the
// store is left empty and a warning is logged.
func (s *Store) loadFromDisk() int {
	s.mu.RLock()
	cfg := s.persist
	s.mu.RUnlock()
	if cfg == nil {
		return 0
	}
	data, err := os.ReadFile(cfg.path)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		log.Printf("[sessions] read %s: %v — starting empty", cfg.path, err)
		return 0
	}
	plain, err := secret.Decrypt(cfg.key, string(data))
	if err != nil {
		log.Printf("[sessions] decrypt %s: %v — wiping (all users will re-login)", cfg.path, err)
		os.Remove(cfg.path)
		return 0
	}
	var rec []Session
	if err := json.Unmarshal([]byte(plain), &rec); err != nil {
		log.Printf("[sessions] unmarshal %s: %v — wiping", cfg.path, err)
		os.Remove(cfg.path)
		return 0
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	loaded := 0
	for i := range rec {
		sess := rec[i]
		if now.After(sess.ExpiresAt) {
			continue
		}
		if sess.IdleTimeout > 0 && now.Sub(sess.LastActivityAt) > sess.IdleTimeout {
			continue
		}
		s.sessions[sess.Token] = &sess
		loaded++
	}
	return loaded
}

// savePersistAsync marks the store dirty so the flush ticker / shutdown
// path picks up the change. Cheap — no I/O on the calling goroutine.
func (s *Store) savePersistAsync() {
	s.mu.RLock()
	cfg := s.persist
	s.mu.RUnlock()
	if cfg == nil {
		return
	}
	cfg.dirtyMu.Lock()
	cfg.dirty = true
	cfg.dirtyMu.Unlock()
}

// FlushNow forces an immediate synchronous save. Called from the
// shutdown handler in main.go so the very latest LastActivityAt
// timestamps land on disk before the process exits.
func (s *Store) FlushNow() {
	s.flushIfDirty(true)
}

func (s *Store) flushLoop() {
	t := time.NewTicker(flushPeriod)
	defer t.Stop()
	for range t.C {
		s.flushIfDirty(false)
	}
}

// flushIfDirty writes the current in-memory map to disk if anything has
// changed since the last save. forceActivity makes us also persist the
// rolling LastActivityAt timestamps even when no Create/Delete fired —
// used by FlushNow on shutdown so we don't lose the last minute of
// activity.
func (s *Store) flushIfDirty(forceActivity bool) {
	s.mu.RLock()
	cfg := s.persist
	s.mu.RUnlock()
	if cfg == nil {
		return
	}
	cfg.dirtyMu.Lock()
	dirty := cfg.dirty
	cfg.dirty = false
	cfg.dirtyMu.Unlock()
	if !dirty && !forceActivity {
		return
	}

	// Snapshot under read lock — keep the critical section short.
	s.mu.RLock()
	out := make([]Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, *sess)
	}
	s.mu.RUnlock()

	plain, err := json.Marshal(out)
	if err != nil {
		log.Printf("[sessions] marshal: %v", err)
		return
	}
	enc, err := secret.Encrypt(cfg.key, string(plain))
	if err != nil {
		log.Printf("[sessions] encrypt: %v", err)
		return
	}
	// Atomic write — write to .tmp then rename, so a crash mid-write
	// can't leave a torn file that wipes every active session.
	tmp := cfg.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(enc), 0600); err != nil {
		log.Printf("[sessions] write %s: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, cfg.path); err != nil {
		log.Printf("[sessions] rename %s: %v", cfg.path, err)
		os.Remove(tmp)
	}
}
