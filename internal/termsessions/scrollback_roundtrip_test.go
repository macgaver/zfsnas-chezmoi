package termsessions

import (
	"bytes"
	"testing"
)

// End-to-end of the replay path: PTY output (with an embedded DECRQM query)
// flows into the scrollback ring, then Attach snapshots + strips it. This is
// what the iPad-resume reconnect actually does, minus the WebSocket.
func TestScrollbackRoundTripStripsDECRQM(t *testing.T) {
	rb := newRingBuf(4096)
	// Simulate a prompt repaint that ends by querying cursor-blink mode.
	rb.Write([]byte("user@host:~$ "))
	rb.Write([]byte("\x1b[?12$p")) // often arrives as its own PTY write
	replay := stripScrollbackQueries(rb.Snapshot())
	if bytes.Contains(replay, []byte("\x1b[?12$p")) {
		t.Fatalf("DECRQM survived the ring round-trip: %q", replay)
	}
	if !bytes.Contains(replay, []byte("user@host:~$ ")) {
		t.Fatalf("prompt lost from replay: %q", replay)
	}
}

// The ring can wrap mid-query; Snapshot re-linearizes it, so the strip still
// sees a contiguous sequence.
func TestScrollbackRoundTripStripsAcrossWrap(t *testing.T) {
	rb := newRingBuf(1024) // min capacity
	// Fill most of the ring, then write a query that pushes past the end so the
	// snapshot must reassemble across the wrap point.
	rb.Write(bytes.Repeat([]byte("x"), 1020))
	rb.Write([]byte("\x1b[?2026$p")) // straddles the wrap
	replay := stripScrollbackQueries(rb.Snapshot())
	if bytes.Contains(replay, []byte("$p")) {
		t.Fatalf("DECRQM query survived across wrap: %q", replay)
	}
}
