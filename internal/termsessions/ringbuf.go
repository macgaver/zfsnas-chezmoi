package termsessions

import "sync"

// ringBuf is a fixed-capacity byte ring buffer used to hold the most recent
// terminal output of a detached PTY session. On WebSocket reattach the
// caller dumps the buffer back to the new client so the user resumes with
// the same screen state they would have seen had they stayed attached.
//
// The buffer is intentionally raw bytes (escape sequences included). xterm.js
// is happy to consume the replay as one chunk; storing post-parse cells
// would multiply the cost and lose mode/colour state.
type ringBuf struct {
	mu   sync.Mutex
	buf  []byte // ring storage, cap = ring capacity
	pos  int    // write position (next byte goes here)
	full bool   // true once write wrapped past end at least once
}

func newRingBuf(capacity int) *ringBuf {
	if capacity < 1024 {
		capacity = 1024
	}
	return &ringBuf{buf: make([]byte, capacity)}
}

// Write appends p to the ring, overwriting the oldest bytes as needed.
// Never returns an error; mirrors io.Writer for convenience.
func (r *ringBuf) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(p)
	cap := len(r.buf)
	if n >= cap {
		// Incoming chunk fills (or overflows) the entire ring — keep only the tail.
		copy(r.buf, p[n-cap:])
		r.pos = 0
		r.full = true
		return n, nil
	}
	tail := cap - r.pos
	if n <= tail {
		copy(r.buf[r.pos:], p)
		r.pos += n
		if r.pos == cap {
			r.pos = 0
			r.full = true
		}
	} else {
		copy(r.buf[r.pos:], p[:tail])
		copy(r.buf, p[tail:])
		r.pos = n - tail
		r.full = true
	}
	return n, nil
}

// Snapshot returns a copy of the buffer contents in chronological order
// (oldest byte first, newest last).
func (r *ringBuf) Snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		out := make([]byte, r.pos)
		copy(out, r.buf[:r.pos])
		return out
	}
	cap := len(r.buf)
	out := make([]byte, cap)
	copy(out, r.buf[r.pos:])
	copy(out[cap-r.pos:], r.buf[:r.pos])
	return out
}
