package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zfsnas/internal/session"
	"zfsnas/system"
)

func TestParseApplianceInstallLog(t *testing.T) {
	lines, steps := parseApplianceInstallLog("STEP 1 preflight\n==> target ok\nSTEP 5 write-image\n10 bytes\r20 bytes copied\n\nerror: boom\n")
	if strings.Join(steps, ",") != "preflight,write-image" {
		t.Fatalf("steps %v", steps)
	}
	if strings.Join(lines, "|") != "==> target ok|20 bytes copied|error: boom" {
		t.Fatalf("lines %q", lines)
	}
}

func TestCheckApplianceInstallRequest(t *testing.T) {
	ok := applianceInstallRequest{Disk: "nvme0n1", Confirm: "nvme0n1", Password: "x", Pool: "zpool-1"}
	if msg := checkApplianceInstallRequest(ok); msg != "" {
		t.Fatalf("valid request refused: %s", msg)
	}
	for name, r := range map[string]applianceInstallRequest{
		"typo":      {Disk: "nvme0n1", Confirm: "nvme0n2", Password: "x"},
		"no pw":     {Disk: "sdb", Confirm: "sdb"},
		"bad disk":  {Disk: "../sda", Confirm: "../sda", Password: "x"},
		"bad pool":  {Disk: "sdb", Confirm: "sdb", Password: "x", Pool: "1;rm"},
		"no disk":   {Confirm: "", Password: "x"},
		"injection": {Disk: "sdb --no-pool", Confirm: "sdb --no-pool", Password: "x"},
	} {
		if checkApplianceInstallRequest(r) == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	if a := strings.Join(applianceInstallArgs(applianceInstallRequest{Disk: "sdb", Confirm: "sdb"}), " "); a != "--install sdb --confirm sdb --no-pool" {
		t.Fatalf("args %q", a)
	}
	if a := strings.Join(applianceInstallArgs(ok), " "); a != "--install nvme0n1 --confirm nvme0n1 --pool zpool-1" {
		t.Fatalf("args %q", a)
	}
}

func TestReadApplianceInstallState(t *testing.T) {
	dir := t.TempDir()
	oldDir, oldRun := applianceInstallRunDir, applianceInstallUnitRun
	t.Cleanup(func() { applianceInstallRunDir, applianceInstallUnitRun = oldDir, oldRun })
	applianceInstallRunDir = dir
	running := true
	applianceInstallUnitRun = func() bool { return running }

	if st := readApplianceInstallState(); st.Phase != "idle" {
		t.Fatalf("no log: %+v", st)
	}
	os.WriteFile(filepath.Join(dir, "log"), []byte("STEP 1 preflight\nSTEP 4 wipe\n"), 0644)
	os.WriteFile(filepath.Join(dir, "rc"), []byte("running\n"), 0644)
	if st := readApplianceInstallState(); st.Phase != "running" || st.Step != "wipe" {
		t.Fatalf("running: %+v", st)
	}
	running = false // unit gone without an rc: killed
	if st := readApplianceInstallState(); st.Phase != "failed" || !strings.Contains(st.Err, "unchanged") {
		t.Fatalf("killed: %+v", st)
	}
	os.WriteFile(filepath.Join(dir, "log"), []byte("STEP 1 preflight\nerror: nvme0n1 can't be used: in pool tank\n"), 0644)
	os.WriteFile(filepath.Join(dir, "rc"), []byte("1\n"), 0644)
	if st := readApplianceInstallState(); st.Phase != "failed" || st.Err != "nvme0n1 can't be used: in pool tank" {
		t.Fatalf("failed: %+v", st)
	}
	os.WriteFile(filepath.Join(dir, "rc"), []byte("0\n"), 0644)
	os.WriteFile(filepath.Join(dir, "disk"), []byte("nvme0n1\n"), 0644)
	if st := readApplianceInstallState(); st.Phase != "done" || st.Disk != "nvme0n1" {
		t.Fatalf("done: %+v", st)
	}
}

// Erasing a disk through InterLink is refused before anything is read.
func TestApplianceInstallRefusedThroughInterLink(t *testing.T) {
	defer system.SetApplianceModeForTest(true)()
	body := bytes.NewBufferString(`{"disk":"sdb","confirm":"sdb","password":"x","pool":"zpool-1"}`)
	req := httptest.NewRequest("POST", "/api/appliance/install-disk", body)
	relay := &session.Session{Username: "admin", Role: "admin"}
	req = req.WithContext(context.WithValue(req.Context(), relaySessionKey, relay))
	req = req.WithContext(context.WithValue(req.Context(), sessionKey, relay))
	w := httptest.NewRecorder()
	HandleApplianceInstallStart(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "InterLink") {
		t.Fatalf("relayed erase: %d %s", w.Code, w.Body.String())
	}
}
