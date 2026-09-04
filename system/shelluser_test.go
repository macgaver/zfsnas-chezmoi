package system

import (
	"os"
	"path/filepath"
	"testing"
)

// The username becomes a real system account, so the validation is the
// security boundary here — anything that could look like a flag or a second
// chpasswd field must be refused before it reaches useradd/chpasswd.
func TestEnsureShellUserValidation(t *testing.T) {
	bad := []struct{ name, user, pass string }{
		{"empty user", "", "pw"},
		{"leading dash (looks like a flag)", "-rf", "pw"},
		{"uppercase", "Demo", "pw"},
		{"space", "de mo", "pw"},
		{"slash", "de/mo", "pw"},
		{"too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "pw"},
		{"no password", "demo", ""},
		{"newline in password", "demo", "pw\nroot:hax"},
		{"colon in password", "demo", "pw:x"},
	}
	for _, tc := range bad {
		if err := EnsureShellUser(tc.user, tc.pass); err == nil {
			t.Errorf("%s: expected rejection, got nil", tc.name)
		}
	}
	if err := DisableShellLogin("-rf"); err == nil {
		t.Error("DisableShellLogin should reject an invalid name")
	}
}

func withFakeGroupFile(t *testing.T, content string) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "group")
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	old := groupFilePath
	groupFilePath = f
	t.Cleanup(func() { groupFilePath = old })
}

const fixtureGroupFile = `root:x:0:
adm:x:4:syslog,alice
sudo:x:27:alice,bob
sambashare:x:132:alice,carol
nogroup:x:65534:
`

func TestGroupMembers(t *testing.T) {
	withFakeGroupFile(t, fixtureGroupFile)
	got := groupMembers(groupFilePath, "sudo")
	want := []string{"alice", "bob"}
	if len(got) != len(want) {
		t.Fatalf("groupMembers(sudo) = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("groupMembers(sudo) = %v, want %v", got, want)
		}
	}
	if m := groupMembers(groupFilePath, "nogroup"); len(m) != 0 {
		t.Errorf("empty member field should yield nothing, got %v", m)
	}
	if m := groupMembers(groupFilePath, "nosuchgroup"); m != nil {
		t.Errorf("missing group should yield nil, got %v", m)
	}
}

func TestInSudoGroup(t *testing.T) {
	withFakeGroupFile(t, fixtureGroupFile)
	cases := []struct {
		user string
		want bool
	}{
		{"alice", true},
		{"bob", true},
		// carol is in sambashare, NOT sudo — being in some other group must
		// never read as sudo access.
		{"carol", false},
		{"dave", false},
		{"", false},
		// Invalid names are rejected before the file is consulted, so a
		// crafted value can never match a substring of the member list.
		{"alice,bob", false},
		{"-rf", false},
		{"Alice", false},
	}
	for _, c := range cases {
		if got := InSudoGroup(c.user); got != c.want {
			t.Errorf("InSudoGroup(%q) = %v, want %v", c.user, got, c.want)
		}
	}
}

// The sudo helpers must refuse a name that could be read as a flag or a second
// field before it ever reaches `sudo gpasswd`.
func TestSudoAccessValidatesUsername(t *testing.T) {
	for _, bad := range []string{"", "-rf", "Demo", "a b", "root:x", "alice,bob"} {
		if err := EnsureSudoAccess(bad); err == nil {
			t.Errorf("EnsureSudoAccess(%q) accepted an invalid name", bad)
		}
		if err := RemoveSudoAccess(bad); err == nil {
			t.Errorf("RemoveSudoAccess(%q) accepted an invalid name", bad)
		}
	}
}
