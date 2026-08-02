package termsessions

import (
	"bytes"
	"testing"
)

// Regression: an iPad user switching apps and returning saw "12;2$y" pasted at
// the shell prompt. A program had queried DEC private mode 12 (cursor blink)
// via DECRQM "\x1b[?12$p"; those bytes sit in the scrollback ring. On reattach
// the ring is replayed, SwiftTerm re-answers with DECRPM "\x1b[?12;2$y", and
// that answer lands at the idle prompt where readline eats "\x1b[?" and shows
// "12;2$y". stripScrollbackQueries must drop the DECRQM request from the replay.
func TestStripScrollbackDropsDECRQM(t *testing.T) {
	cases := [][]byte{
		[]byte("\x1b[?12$p"),       // the reported case (cursor blink)
		[]byte("\x1b[?2026$p"),     // synchronized output
		[]byte("\x1b[?2004$p"),     // bracketed paste
		[]byte("\x1b[?1049;2004$p"), // multi-parameter
		[]byte("\x1b[4$p"),         // ANSI (non-private) DECRQM
	}
	for _, q := range cases {
		in := append(append([]byte("hello "), q...), []byte(" world")...)
		got := stripScrollbackQueries(in)
		if bytes.Contains(got, q) {
			t.Errorf("DECRQM query %q survived replay: %q", q, got)
		}
		if !bytes.Contains(got, []byte("hello ")) || !bytes.Contains(got, []byte(" world")) {
			t.Errorf("surrounding output damaged for %q: %q", q, got)
		}
	}
}

// The pre-existing query classes must still be stripped.
func TestStripScrollbackKeepsStrippingKnownQueries(t *testing.T) {
	for _, q := range [][]byte{
		[]byte("\x1b[6n"), []byte("\x1b[5n"),
		[]byte("\x1b[c"), []byte("\x1b[>c"),
		[]byte("\x1b]11;?\x07"), // OSC background-colour query
	} {
		in := append(append([]byte("A"), q...), []byte("B")...)
		if got := stripScrollbackQueries(in); bytes.Contains(got, q) {
			t.Errorf("known query %q no longer stripped: %q", q, got)
		}
	}
}

// Ordinary output that merely resembles a query must be preserved. In
// particular real SGR/mode sequences and literal text must not be touched.
func TestStripScrollbackPreservesNormalOutput(t *testing.T) {
	keep := [][]byte{
		[]byte("\x1b[?25h"),   // show cursor (mode set, not a query)
		[]byte("\x1b[?1049h"), // alt-screen enter
		[]byte("\x1b[0m"),     // SGR reset
		[]byte("\x1b[2J"),     // clear screen
		[]byte("price is 12$ and 2$y left"), // literal text with $ and $y
	}
	for _, k := range keep {
		if got := stripScrollbackQueries(k); !bytes.Equal(got, k) {
			t.Errorf("normal output altered:\n in=%q\nout=%q", k, got)
		}
	}
}
