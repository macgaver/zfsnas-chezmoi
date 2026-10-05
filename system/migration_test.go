package system

import (
	"os"
	"path/filepath"
	"testing"
)

func withAuthFixtures(t *testing.T, passwd, group string) {
	t.Helper()
	dir := t.TempDir()
	pp, gp := filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
	os.WriteFile(pp, []byte(passwd), 0644)
	os.WriteFile(gp, []byte(group), 0644)
	op, og := passwdPath, groupPath
	passwdPath, groupPath = pp, gp
	t.Cleanup(func() { passwdPath, groupPath = op, og })
}

func TestAccountConflict(t *testing.T) {
	withAuthFixtures(t,
		"root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001:ZNAS portal user:/home/alice:/usr/sbin/nologin\nowner:x:1000:1000:Owner:/home/owner:/bin/bash\n",
		"owner:x:1000:\nalice:x:1001:\nmedia:x:2000:\n")
	cases := []struct {
		a    LinuxAccount
		want bool // conflict expected
	}{
		{LinuxAccount{Name: "alice", UID: 1001, GID: 1001, Group: "alice"}, false}, // same account
		{LinuxAccount{Name: "alice", UID: 1005, GID: 1005, Group: "alice"}, true},  // same name, other uid
		{LinuxAccount{Name: "bob", UID: 1000, GID: 1002, Group: "bob"}, true},      // uid taken by owner
		{LinuxAccount{Name: "bob", UID: 1002, GID: 1002, Group: "bob"}, false},     // free
		{LinuxAccount{Name: "carol", UID: 1003, GID: 2001, Group: "media"}, true},  // group gid differs
	}
	for _, c := range cases {
		if got := AccountConflict(c.a) != ""; got != c.want {
			t.Errorf("%+v: conflict=%v (%q), want %v", c.a, got, AccountConflict(c.a), c.want)
		}
	}
	if err := RestoreLinuxAccount(LinuxAccount{Name: "x", UID: 0, GID: 0}); err == nil {
		t.Error("uid 0 accepted")
	}
}

func TestExportLinuxAccounts(t *testing.T) {
	withAuthFixtures(t,
		"alice:x:1001:1001:ZNAS portal user:/nonexistent:/usr/sbin/nologin\nowner:x:1000:1000:Owner:/home/owner:/bin/bash\n",
		"alice:x:1001:\nsambashare:x:990:alice,owner\n")
	accts, warns := ExportLinuxAccounts([]string{"alice", "owner", "ghost"})
	if len(accts) != 1 || accts[0].Name != "alice" {
		t.Fatalf("only the portal-managed account must be exported, got %+v", accts)
	}
	a := accts[0]
	if a.UID != 1001 || a.GID != 1001 || a.Group != "alice" || len(a.Groups) != 1 || a.Groups[0] != "sambashare" || a.HasLogin {
		t.Errorf("bad export: %+v", a)
	}
	if len(warns) != 0 {
		t.Errorf("no-login account must not need its shadow hash: %v", warns)
	}
}
