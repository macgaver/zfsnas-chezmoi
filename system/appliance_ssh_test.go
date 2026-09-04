// system/appliance_ssh_test.go
package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetRootSSHAccessKey(t *testing.T) {
	dir := t.TempDir()
	origDir, origRun := rootSSHDir, chpasswdRun
	defer func() { rootSSHDir, chpasswdRun = origDir, origRun }()
	rootSSHDir = filepath.Join(dir, ".ssh")
	var gotPw string
	chpasswdRun = func(pw string) error { gotPw = pw; return nil }

	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake user@host"
	if err := SetRootSSHAccess("", key); err != nil {
		t.Fatal(err)
	}
	ak := filepath.Join(rootSSHDir, "authorized_keys")
	b, err := os.ReadFile(ak)
	if err != nil || strings.Count(string(b), key) != 1 {
		t.Fatalf("append failed: %v %q", err, b)
	}
	// idempotent
	if err := SetRootSSHAccess("", key); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(ak)
	if strings.Count(string(b), key) != 1 {
		t.Fatalf("not idempotent: %q", b)
	}
	if fi, _ := os.Stat(ak); fi.Mode().Perm() != 0600 {
		t.Fatalf("authorized_keys mode %v", fi.Mode())
	}

	// password path
	if err := SetRootSSHAccess("s3cret!", ""); err != nil || gotPw != "s3cret!" {
		t.Fatalf("password: err=%v got=%q", err, gotPw)
	}

	// rejections
	for _, bad := range []struct{ pw, key string }{
		{"", ""},                  // nothing to do
		{"has\nnewline", ""},      // newline injects a 2nd chpasswd line
		{"has:colon", ""},         // colon breaks user:pass format
		{"", "garbage not a key"}, // bad key format
		{"", "ssh-ed25519"},       // truncated key
	} {
		if err := SetRootSSHAccess(bad.pw, bad.key); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}
