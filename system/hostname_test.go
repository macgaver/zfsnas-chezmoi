package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateHostname(t *testing.T) {
	bad := map[string]string{
		"":                      "empty",
		"nas.local":             "FQDN — the domain part belongs to DNS",
		"-nas":                  "leading hyphen",
		"nas-":                  "trailing hyphen",
		"na s":                  "space",
		"nas_1":                 "underscore is not valid in a hostname",
		"localhost":             "reserved",
		strings.Repeat("a", 64): "too long",
	}
	for in, why := range bad {
		if err := ValidateHostname(in); err == nil {
			t.Errorf("ValidateHostname(%q) accepted it — %s", in, why)
		}
	}
	for _, in := range []string{"nas", "znas3", "NAS-01", "a", strings.Repeat("a", 63)} {
		if err := ValidateHostname(in); err != nil {
			t.Errorf("ValidateHostname(%q) rejected a valid name: %v", in, err)
		}
	}
}

func TestUpdateEtcHostsRenamesOnlyTheHostsOwnEntry(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hosts")
	os.WriteFile(p, []byte(`127.0.0.1	localhost
127.0.1.1	znas3
# 127.0.1.1 znas3 (commented out on purpose)
192.168.2.40	znas3-backup znas3
::1	ip6-localhost
`), 0644)
	old := etcHostsPath
	etcHostsPath = p
	defer func() { etcHostsPath = old }()

	if err := updateEtcHosts("znas3", "vault"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	s := string(got)
	if !strings.Contains(s, "127.0.1.1\tvault") {
		t.Fatalf("loopback entry not renamed:\n%s", s)
	}
	if !strings.Contains(s, "192.168.2.40\tznas3-backup znas3") {
		t.Fatalf("a LAN entry was rewritten — only the host's own loopback line may change:\n%s", s)
	}
	if !strings.Contains(s, "# 127.0.1.1 znas3") {
		t.Fatalf("a comment was rewritten:\n%s", s)
	}
	if !strings.Contains(s, "127.0.0.1\tlocalhost") {
		t.Fatalf("localhost line lost:\n%s", s)
	}
}

func TestUpdateEtcHostsAddsEntryWhenNoneClaimsTheOldName(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hosts")
	os.WriteFile(p, []byte("127.0.0.1\tlocalhost\n"), 0644)
	old := etcHostsPath
	etcHostsPath = p
	defer func() { etcHostsPath = old }()

	if err := updateEtcHosts("oldname", "vault"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if !strings.Contains(string(got), "127.0.1.1\tvault") {
		t.Fatalf("new name must still resolve:\n%s", got)
	}
}
