package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMergeLocalConfigKeepsHostKeys(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "config.json")
	os.WriteFile(local, []byte(`{"port":9443,"sudoers_hardening_enabled":true,"active_cert_name":"mine","smb_workgroup":"OLD"}`), 0600)
	incoming := []byte(`{"port":8443,"smb_workgroup":"HOME","active_cert_name":"theirs","interlink_relay_mode":true}`)

	out, err := mergeLocalConfig(local, incoming, false)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(out, &m)
	if m["port"] != float64(9443) || m["sudoers_hardening_enabled"] != true {
		t.Errorf("host keys not kept: %v", m)
	}
	if m["smb_workgroup"] != "HOME" {
		t.Errorf("imported setting lost: %v", m)
	}
	if m["active_cert_name"] != "mine" {
		t.Errorf("without certs the local active cert must stay: %v", m)
	}
	if _, ok := m["interlink_relay_mode"]; ok {
		t.Errorf("relay mode must not come from the backup: %v", m)
	}
	out, _ = mergeLocalConfig(local, incoming, true)
	json.Unmarshal(out, &m)
	if m["active_cert_name"] != "theirs" {
		t.Errorf("with certs the imported active cert is used: %v", m)
	}
}

func TestWriteConfigFiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string][]byte{
		"config/users.json":    []byte(`[]`),
		"config/keys/k1.key":   {1, 2},
		"config/totp.key":      {3},
		"system/accounts.json": []byte(`[]`), // not a config file: ignored here
	}
	if err := writeConfigFiles(dir, files, false); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"users.json", "keys/k1.key", "totp.key"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s not written", f)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "accounts.json")); err == nil {
		t.Error("system/ file written into config")
	}
	if err := writeConfigFiles(dir, map[string][]byte{"config/../escape": nil}, false); err == nil {
		t.Error("path escaping the config dir accepted")
	}
}

func TestCopyDirSkipsRollbackCopies(t *testing.T) {
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "a.json"), []byte("a"), 0600)
	os.MkdirAll(filepath.Join(src, preImportPrefix+"old"), 0700)
	os.WriteFile(filepath.Join(src, preImportPrefix+"old", "x"), []byte("x"), 0600)
	dst := filepath.Join(src, preImportPrefix+"new") // inside src, like the real snapshot
	if err := copyDir(src, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "a.json")); err != nil {
		t.Error("file not copied")
	}
	if _, err := os.Stat(filepath.Join(dst, preImportPrefix+"old")); err == nil {
		t.Error("older rollback copy copied into the new one")
	}
}

func TestRestoreSnapshotRemovesImportedSettings(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, preImportPrefix+"1")
	os.MkdirAll(snap, 0700)
	os.WriteFile(filepath.Join(snap, "config.json"), []byte("old"), 0600)
	os.WriteFile(filepath.Join(snap, "session.key"), []byte("old-key"), 0600)
	os.WriteFile(filepath.Join(dir, "session.key"), []byte("live-key"), 0600)
	// state after the import
	os.WriteFile(filepath.Join(dir, "config.json"), []byte("new"), 0600)
	os.WriteFile(filepath.Join(dir, "users.json"), []byte("[imported]"), 0600)
	os.WriteFile(filepath.Join(dir, "totp.key"), []byte("k"), 0600)
	os.MkdirAll(filepath.Join(dir, "keys"), 0700)
	os.WriteFile(filepath.Join(dir, "keys", "a.key"), []byte("k"), 0600)

	if err := restoreSnapshot(dir, snap); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "config.json")); string(b) != "old" {
		t.Errorf("config.json not restored: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "users.json")); err == nil {
		t.Error("users.json added by the import survived the rollback")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "session.key")); string(b) != "live-key" {
		t.Errorf("session key of the running portal replaced: %q", b)
	}
	for _, f := range []string{"totp.key", "keys/a.key"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s removed: key material must be kept", f)
		}
	}
}
