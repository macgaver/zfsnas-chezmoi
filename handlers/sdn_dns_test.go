package handlers

import (
	"testing"
	"time"
)

func TestSDNDNSSpan(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 24 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour,
		"30d": 30 * 24 * time.Hour, "1y": 365 * 24 * time.Hour, "bogus": 24 * time.Hour} {
		if got := sdnDNSSpan(in); got != want {
			t.Errorf("%q: %v, want %v", in, got, want)
		}
	}
}
