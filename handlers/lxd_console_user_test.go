package handlers

import (
	"reflect"
	"testing"
)

func TestLXDConsoleArgs(t *testing.T) {
	yes := func() bool { return true }
	no := func() bool { return false }
	cases := []struct {
		user    string
		rootPw  bool
		hasBash func() bool
		want    []string
	}{
		{"", false, yes, []string{"exec", "ct", "--", "bash"}},
		{"root", false, no, []string{"exec", "ct", "--", "sh"}},
		{"root", true, yes, []string{"exec", "ct", "--", "login"}},
		{"alice", false, yes, []string{"exec", "ct", "--", "su", "-l", "alice"}},
		{"alice", true, yes, []string{"exec", "ct", "--", "login", "alice"}},
	}
	for _, c := range cases {
		if got := lxdConsoleArgs("ct", c.user, c.rootPw, c.hasBash); !reflect.DeepEqual(got, c.want) {
			t.Errorf("user=%q rootPw=%v: got %v, want %v", c.user, c.rootPw, got, c.want)
		}
	}
}

func TestLXDConsoleUserRe(t *testing.T) {
	for _, ok := range []string{"root", "alice", "user1", "svc_backup", "a.b-c", "_x"} {
		if !lxdConsoleUserRe.MatchString(ok) {
			t.Errorf("%q should be accepted", ok)
		}
	}
	for _, bad := range []string{"", "-c", "--help", "a b", "a;b", "a/b", "$(id)", "abcdefghijabcdefghijabcdefghijabc"} {
		if lxdConsoleUserRe.MatchString(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
