package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAccountManaged(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "passwd")
	os.WriteFile(fixture, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"+
			"owner:x:1000:1000:Server Owner,,,:/home/owner:/bin/bash\n"+
			"portaluser:x:1001:1001:ZNAS portal user:/home/portaluser:/bin/bash\n"+
			"oldsmb:x:1002:1002::/nonexistent:/usr/sbin/nologin\n"+
			"lowsmb:x:998:998::/nonexistent:/usr/sbin/nologin\n"), 0644)
	old := passwdPath
	passwdPath = fixture
	defer func() { passwdPath = old }()

	cases := map[string]bool{
		"root":       false, // the system's own root
		"daemon":     false, // system account (uid < 1000)
		"lowsmb":     false, // no-login but a system uid
		"owner":      false, // the server owner's real login: never touch it
		"portaluser": true,  // created by the portal (comment marker)
		"oldsmb":     true,  // no-login SMB account from an earlier version
		"newname":    true,  // does not exist yet: the portal will create it
	}
	for name, want := range cases {
		if got, reason := accountManaged(name); got != want {
			t.Errorf("accountManaged(%q) = %v (%s), want %v", name, got, reason, want)
		}
	}
	// The account the portal runs as is never managed, whatever its entry.
	if svc := portalServiceUser(); svc != "" {
		if got, _ := accountManaged(svc); got {
			t.Errorf("the portal's own service account %q must not be managed", svc)
		}
	}
	// Unmanaged accounts are left alone: these must be no-ops, not errors,
	// and must not run anything (the fixture users do not exist on this host).
	if err := RemoveSudoAccess("owner"); err != nil {
		t.Errorf("RemoveSudoAccess(owner) = %v, want a silent no-op", err)
	}
	if err := EnsureShellUser("owner", "secret"); err == nil {
		t.Error("EnsureShellUser must refuse to take over the owner's account")
	}
	if !ShellLoginEnabled("owner") || ShellLoginEnabled("oldsmb") {
		t.Error("ShellLoginEnabled must read the shell from the passwd file")
	}
}
