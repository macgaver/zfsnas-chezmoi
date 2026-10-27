package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"zfsnas/internal/config"
	"zfsnas/system"
)

func carryTestCfg(t *testing.T) *config.AppConfig {
	t.Helper()
	if err := config.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	return &config.AppConfig{
		InterLink: []config.LinkedServer{
			{ID: "srcpeer", URL: "https://10.0.0.1:8443", SharedSecret: "abcd1234"},
			{ID: "nas3", URL: "https://10.0.0.3:8443", SharedSecret: "ffff0000"},
		},
	}
}

func signedImport(t *testing.T, secret string, pl system.LXDImportSchedulesPayload) *http.Request {
	t.Helper()
	payload, _ := json.Marshal(pl)
	ts := time.Now().Unix()
	body, _ := json.Marshal(system.LXDImportSchedulesRequest{
		Timestamp: ts, Nonce: "n1", Payload: payload,
		HMAC: system.LXDImportSchedulesHMAC(secret, ts, "n1", payload),
	})
	return httptest.NewRequest("POST", "/api/lxd/interlink-import-schedules", bytes.NewReader(body))
}

func TestRemoveLXDInstanceSchedules(t *testing.T) {
	cfg := carryTestCfg(t)
	cfg.LXDSnapshotPolicies = []config.LXDSnapshotPolicy{{Instance: "cloudflared"}, {Instance: "keep"}}
	cfg.LXDBackupPolicies = []config.LXDBackupPolicy{{Instance: "cloudflared"}, {Instance: "keep"}}
	got := RemoveLXDInstanceSchedules(cfg, "cloudflared")
	if len(got) != 2 || len(cfg.LXDSnapshotPolicies) != 1 || len(cfg.LXDBackupPolicies) != 1 ||
		cfg.LXDSnapshotPolicies[0].Instance != "keep" || cfg.LXDBackupPolicies[0].Instance != "keep" {
		t.Fatalf("removed %v, left %+v / %+v", got, cfg.LXDSnapshotPolicies, cfg.LXDBackupPolicies)
	}
	if got := RemoveLXDInstanceSchedules(cfg, "nothing"); len(got) != 0 {
		t.Errorf("nothing to remove, got %v", got)
	}
}

func TestLXDInstanceGoneNeedsIncusConfirmation(t *testing.T) {
	defer func(f func(string) bool) { lxdMissingFn = f }(lxdMissingFn)
	notFound := errors.New(`Failed to fetch instance "cloudflared" in project "default": Instance not found`)
	lxdMissingFn = func(string) bool { return true }
	if !lxdInstanceGone("cloudflared", notFound) {
		t.Error("confirmed missing instance must count as gone")
	}
	// backup scheduler wording
	if !lxdInstanceGone("cloudflared", errors.New("source instance not found: not found")) {
		t.Error("backup scheduler error must count as gone when Incus confirms")
	}
	// Incus down / instance back: keep the schedules.
	lxdMissingFn = func(string) bool { return false }
	if lxdInstanceGone("cloudflared", notFound) {
		t.Error("without Incus confirmation it is not gone")
	}
	lxdMissingFn = func(string) bool { return true }
	if lxdInstanceGone("cloudflared", errors.New("snapshot failed: disk full")) {
		t.Error("other errors are not gone")
	}
	if lxdInstanceGone("cloudflared", nil) {
		t.Error("no error is not gone")
	}
}

func TestImportSchedules(t *testing.T) {
	defer func(f func(string) error, z func(string) bool) { lxdStatusFn, zpoolExistsFn = f, z }(lxdStatusFn, zpoolExistsFn)
	lxdStatusFn = func(string) error { return nil }
	zpoolExistsFn = func(p string) bool { return p == "tank" }

	cases := []struct {
		name        string
		backup      config.LXDBackupPolicy
		destURL     string
		destIsPeer  bool
		wantEnabled bool
		wantServer  string
	}{
		{"local pool exists", config.LXDBackupPolicy{DestKind: "local", DestPool: "tank", Enabled: true}, "", false, true, ""},
		{"local pool missing", config.LXDBackupPolicy{DestKind: "local", DestPool: "BIGRAID", Enabled: true}, "", false, false, ""},
		{"remote mapped by host", config.LXDBackupPolicy{DestKind: "remote", DestServerID: "theirid", DestPool: "p", Enabled: true}, "https://10.0.0.3:8443/", false, true, "nas3"},
		{"remote unknown", config.LXDBackupPolicy{DestKind: "remote", DestServerID: "theirid", DestPool: "p", Enabled: true}, "https://10.9.9.9:8443", false, false, ""},
		{"remote was this server", config.LXDBackupPolicy{DestKind: "remote", DestServerID: "me", DestPool: "p", Enabled: true}, "", true, false, ""},
	}
	for _, c := range cases {
		cfg := carryTestCfg(t)
		cfg.LXDSnapshotPolicies = []config.LXDSnapshotPolicy{{Instance: "web2", EveryN: 9}}
		b := c.backup
		b.Instance, b.LastStatus, b.LastError = "web", "error", "old"
		pl := system.LXDImportSchedulesPayload{
			SourceHost: "znas5", Instance: "web2",
			Snapshot:      &config.LXDSnapshotPolicy{Instance: "web", Enabled: true, EveryN: 1, Unit: "hour", NamePrefix: "auto", KeepLast: 5, LastStatus: "error"},
			Backup:        &b,
			BackupDestURL: c.destURL, BackupDestIsPeer: c.destIsPeer,
		}
		w := httptest.NewRecorder()
		HandleInterlinkImportSchedules(cfg)(w, signedImport(t, "abcd1234", pl))
		if w.Code != 200 {
			t.Fatalf("%s: status %d %s", c.name, w.Code, w.Body.String())
		}
		if len(cfg.LXDSnapshotPolicies) != 1 || cfg.LXDSnapshotPolicies[0].EveryN != 1 || cfg.LXDSnapshotPolicies[0].Instance != "web2" || cfg.LXDSnapshotPolicies[0].LastStatus != "" {
			t.Errorf("%s: snapshot policy not replaced/renamed: %+v", c.name, cfg.LXDSnapshotPolicies)
		}
		if len(cfg.LXDBackupPolicies) != 1 {
			t.Fatalf("%s: backup policies %+v", c.name, cfg.LXDBackupPolicies)
		}
		got := cfg.LXDBackupPolicies[0]
		if got.Instance != "web2" || got.Enabled != c.wantEnabled {
			t.Errorf("%s: got %+v", c.name, got)
		}
		if c.wantServer != "" && got.DestServerID != c.wantServer {
			t.Errorf("%s: dest server %q, want %q", c.name, got.DestServerID, c.wantServer)
		}
		if !c.wantEnabled && got.LastError == "" {
			t.Errorf("%s: a turned-off import must explain why", c.name)
		}
		if c.wantEnabled && got.LastError != "" {
			t.Errorf("%s: stale last error kept: %q", c.name, got.LastError)
		}
	}
}

func TestImportSchedulesRejects(t *testing.T) {
	defer func(f func(string) error) { lxdStatusFn = f }(lxdStatusFn)
	lxdStatusFn = func(string) error { return nil }
	cfg := carryTestCfg(t)
	pl := system.LXDImportSchedulesPayload{Instance: "web", Snapshot: &config.LXDSnapshotPolicy{Instance: "web"}}

	w := httptest.NewRecorder()
	HandleInterlinkImportSchedules(cfg)(w, signedImport(t, "not-a-linked-secret", pl))
	if w.Code != http.StatusUnauthorized || len(cfg.LXDSnapshotPolicies) != 0 {
		t.Errorf("unknown secret: status %d, policies %v", w.Code, cfg.LXDSnapshotPolicies)
	}

	// payload altered after signing
	req := signedImport(t, "abcd1234", pl)
	var env system.LXDImportSchedulesRequest
	json.NewDecoder(req.Body).Decode(&env) //nolint:errcheck
	env.Payload = json.RawMessage(`{"instance":"other","snapshot":{"instance":"x"}}`)
	body, _ := json.Marshal(env)
	w = httptest.NewRecorder()
	HandleInterlinkImportSchedules(cfg)(w, httptest.NewRequest("POST", "/", bytes.NewReader(body)))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("tampered payload: status %d", w.Code)
	}

	lxdStatusFn = func(string) error { return errors.New("Instance not found") }
	w = httptest.NewRecorder()
	HandleInterlinkImportSchedules(cfg)(w, signedImport(t, "abcd1234", pl))
	if w.Code != http.StatusNotFound || len(cfg.LXDSnapshotPolicies) != 0 {
		t.Errorf("missing instance: status %d", w.Code)
	}
}
