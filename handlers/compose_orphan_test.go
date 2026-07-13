package handlers

import (
	"errors"
	"testing"
)

// composeErrInstanceGone decides whether an auto-update failure means the stack
// left this host (pushed/moved/deleted) so its orphaned schedule should be
// auto-removed rather than retried + alerted every interval. The real error
// seen in the field was: Failed to fetch instance "stack-1" in project
// "default": Instance not found.
func TestComposeErrInstanceGone(t *testing.T) {
	gone := []string{
		`Failed to fetch instance "stack-1" in project "default": Instance not found`,
		"Instance not found",
		`instance "x" not found in project "default"`,
	}
	for _, m := range gone {
		if !composeErrInstanceGone(errors.New(m)) {
			t.Errorf("expected gone=true for %q", m)
		}
	}
	notGone := []string{
		"podman-compose pull: network timeout",
		"exit status 1: manifest unknown",
		"permission denied",
	}
	for _, m := range notGone {
		if composeErrInstanceGone(errors.New(m)) {
			t.Errorf("expected gone=false for %q", m)
		}
	}
	if composeErrInstanceGone(nil) {
		t.Error("nil error must be gone=false")
	}
}
