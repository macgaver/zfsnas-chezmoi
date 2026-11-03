package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"zfsnas/internal/config"
	"zfsnas/internal/sdn"
	"zfsnas/internal/session"
	"zfsnas/system"

	"github.com/gorilla/mux"
)

type sdnRec struct {
	cmds []string
	fail func(string) error
}

func (r *sdnRec) Run(stdin []byte, name string, args ...string) ([]byte, error) {
	c := strings.Join(append([]string{name}, args...), " ")
	r.cmds = append(r.cmds, c)
	if r.fail != nil {
		if err := r.fail(c); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func (r *sdnRec) count(prefix string) int {
	n := 0
	for _, c := range r.cmds {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func sdnBaseConfig() *sdn.Config {
	c := &sdn.Config{Version: 1, Settings: sdn.Settings{Mode: "router", MgmtInterface: "enp5s0", AntiLockout: true},
		Interfaces: []sdn.Interface{{ID: "if0mgmt0", Name: "LAN", Kind: "physical", Device: "enp5s0", Role: "lan", IPv4Mode: "dhcp"}}}
	c.Normalize()
	return c
}

// sdnHandlerEnv: enabled feature, confirmed base config, draft with one new
// VLAN — ready for an apply.
func sdnHandlerEnv(t *testing.T) (*config.AppConfig, *sdnRec, sdn.Store) {
	t.Helper()
	dir := t.TempDir()
	rec := &sdnRec{}
	t.Cleanup(system.SDNSetTestEnv(rec, dir))
	_ = os.WriteFile(filepath.Join(dir, "interfaces"), []byte("auto lo\niface lo inet loopback\n"), 0644)
	for _, d := range []string{"enp5s0", "enp7s0"} {
		_ = os.MkdirAll(filepath.Join(dir, "sys", d), 0755)
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
	st := sdn.Store{Dir: dir}
	_ = st.SaveState(sdn.State{Enabled: true})
	_ = st.SaveConfirmed(sdnBaseConfig())
	next := sdnBaseConfig()
	next.Interfaces = append(next.Interfaces, sdn.Interface{ID: "if000700", Name: "VLAN700", Kind: "vlan", Parent: "enp7s0",
		VLANTag: 700, IPv4Mode: "static", IPv4: "10.128.7.1/24", Owned: true})
	next.Normalize()
	if _, err := st.SaveDraft(next, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	return &config.AppConfig{ConfigDir: dir, Port: 8443}, rec, st
}

func sdnReq(method, path string, body any, role string) *http.Request {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	sess := &session.Session{Username: "admin", Role: role, UserID: "u-" + role}
	return r.WithContext(context.WithValue(r.Context(), sessionKey, sess))
}

func TestSDNApply_RefusesWhilePending(t *testing.T) {
	appCfg, rec, _ := sdnHandlerEnv(t)
	w := httptest.NewRecorder()
	HandleSDNApply(appCfg)(w, sdnReq("POST", "/api/sdn/apply", map[string]bool{"auto_revert": true}, config.RoleAdmin))
	if w.Code != 200 {
		t.Fatalf("first apply %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	HandleSDNApply(appCfg)(w, sdnReq("POST", "/api/sdn/apply", map[string]bool{"auto_revert": true}, config.RoleAdmin))
	if w.Code != http.StatusConflict {
		t.Fatalf("second apply %d, want 409", w.Code)
	}
	if n := rec.count("systemd-run"); n != 1 {
		t.Fatalf("%d revert timers armed", n)
	}
}

func TestSDNPending_SurvivesReload(t *testing.T) {
	appCfg, _, _ := sdnHandlerEnv(t)
	w := httptest.NewRecorder()
	HandleSDNApply(appCfg)(w, sdnReq("POST", "/api/sdn/apply", map[string]bool{"auto_revert": true}, config.RoleAdmin))
	var applied struct{ Snapshot string }
	_ = json.Unmarshal(w.Body.Bytes(), &applied)
	w = httptest.NewRecorder()
	HandleSDNPending(appCfg)(w, sdnReq("GET", "/api/sdn/pending", nil, config.RoleAdmin))
	var p struct {
		Snapshot    string  `json:"snapshot"`
		SecondsLeft float64 `json:"seconds_left"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("%v: %s", err, w.Body)
	}
	if p.Snapshot == "" || p.Snapshot != applied.Snapshot || p.SecondsLeft <= 0 || p.SecondsLeft > 30 {
		t.Fatalf("pending = %+v (applied %q)", p, applied.Snapshot)
	}
}

func TestSDNApply_ValidationRefused(t *testing.T) {
	appCfg, rec, st := sdnHandlerEnv(t)
	d, _ := st.LoadDraft()
	d.Config.Rules = []sdn.Rule{{ID: "r1", Enabled: true, Interface: "ifgone00", Action: "allow", Protocol: "any",
		Source: sdn.Endpoint{Type: "any"}, Destination: sdn.Endpoint{Type: "any"}}}
	_, _ = st.SaveDraft(d.Config, d.Revision, "admin")
	w := httptest.NewRecorder()
	HandleSDNApply(appCfg)(w, sdnReq("POST", "/api/sdn/apply", map[string]bool{"auto_revert": true}, config.RoleAdmin))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("code %d %s", w.Code, w.Body)
	}
	if rec.count("nft") != 0 {
		t.Fatalf("nft ran on an invalid config: %v", rec.cmds)
	}
}

func TestSDNApply_FailureRollsBack(t *testing.T) {
	appCfg, rec, st := sdnHandlerEnv(t)
	n := 0
	rec.fail = func(c string) error {
		if strings.HasPrefix(c, "nft -f") {
			n++
			if n == 1 {
				return errors.New("nft: Error: boom")
			}
		}
		return nil
	}
	w := httptest.NewRecorder()
	HandleSDNApply(appCfg)(w, sdnReq("POST", "/api/sdn/apply", map[string]bool{"auto_revert": true}, config.RoleAdmin))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "boom") {
		t.Fatalf("code %d %s", w.Code, w.Body)
	}
	if rec.count("nft -f") != 2 {
		t.Fatalf("rollback did not reload the previous ruleset: %v", rec.cmds)
	}
	cur, _ := st.LoadConfirmed()
	if len(cur.Interfaces) != 1 {
		t.Fatal("confirmed config changed after a failed apply")
	}
	// Armed before touching the kernel (I4), so it must be disarmed again.
	if rec.count("systemctl stop znas-sdn-revert.service") == 0 {
		t.Fatal("revert left armed after a failed apply")
	}
	if _, ok := system.SDNPendingRevert(st); ok {
		t.Fatal("pending marker left after a failed apply")
	}
}

func TestSDNConfirm_ClearsPending(t *testing.T) {
	appCfg, rec, st := sdnHandlerEnv(t)
	w := httptest.NewRecorder()
	HandleSDNApply(appCfg)(w, sdnReq("POST", "/api/sdn/apply", map[string]bool{"auto_revert": true}, config.RoleAdmin))
	w = httptest.NewRecorder()
	HandleSDNConfirm(appCfg)(w, sdnReq("POST", "/api/sdn/confirm", nil, config.RoleAdmin))
	if w.Code != 200 || rec.count("systemctl stop znas-sdn-revert.service") != 1 {
		t.Fatalf("confirm %d %v", w.Code, rec.cmds)
	}
	list, _ := st.ListSnapshots()
	if len(list) != 1 || list[0].Outcome != "confirmed" {
		t.Fatalf("history %+v", list)
	}
}

func TestSDNDraft_Stale409(t *testing.T) {
	appCfg, _, _ := sdnHandlerEnv(t)
	w := httptest.NewRecorder()
	HandleSDNPutDraft(appCfg)(w, sdnReq("PUT", "/api/sdn/draft", map[string]any{"base_revision": 0, "config": sdnBaseConfig()}, config.RoleAdmin))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "edited by admin") {
		t.Fatalf("code %d %s", w.Code, w.Body)
	}
}

func TestSDNPerm_ViewFirewall(t *testing.T) {
	appCfg, _, _ := sdnHandlerEnv(t)
	_ = config.SaveUsers([]config.User{
		{ID: "u-standard", Username: "std", Role: config.RoleStandard, StandardPerms: &config.StandardPermissions{}},
	})
	h := RequireFirewallView(HandleSDNGetConfig(appCfg))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, sdnReq("GET", "/api/sdn/config", nil, config.RoleStandard))
	if w.Code != http.StatusForbidden {
		t.Fatalf("standard without view_firewall: %d", w.Code)
	}
	_ = config.SaveUsers([]config.User{
		{ID: "u-standard", Username: "std", Role: config.RoleStandard, StandardPerms: &config.StandardPermissions{ViewFirewall: true}},
	})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, sdnReq("GET", "/api/sdn/config", nil, config.RoleStandard))
	if w.Code != 200 {
		t.Fatalf("standard with view_firewall: %d", w.Code)
	}
	w = httptest.NewRecorder()
	RequireAdmin(HandleSDNApply(appCfg)).ServeHTTP(w, sdnReq("POST", "/api/sdn/apply", nil, config.RoleStandard))
	if w.Code != http.StatusForbidden {
		t.Fatalf("standard apply: %d", w.Code)
	}
}

func TestSDNExportImportFlow(t *testing.T) {
	appCfg, _, st := sdnHandlerEnv(t)
	w := httptest.NewRecorder()
	HandleSDNExport(appCfg)(w, sdnReq("POST", "/api/sdn/export", map[string]string{"password": "correct horse battery"}, config.RoleAdmin))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), ".znasfw") {
		t.Fatalf("export %d %v", w.Code, w.Header())
	}
	file := w.Body.Bytes()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "fw.znasfw")
	_, _ = fw.Write(file)
	_ = mw.WriteField("password", "correct horse battery")
	_ = mw.Close()
	r := sdnReq("POST", "/api/sdn/import/inspect", nil, config.RoleAdmin)
	r.Body = io.NopCloser(&buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w = httptest.NewRecorder()
	HandleSDNImportInspect(appCfg)(w, r)
	var insp struct {
		ID             string   `json:"id"`
		DevicesMissing []string `json:"devices_missing"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &insp) != nil || insp.ID == "" {
		t.Fatalf("inspect %d %s", w.Code, w.Body)
	}
	// enp5s0 exists in the fake /sys, so nothing is missing
	if len(insp.DevicesMissing) != 0 {
		t.Fatalf("missing %v", insp.DevicesMissing)
	}
	w = httptest.NewRecorder()
	HandleSDNImportApply(appCfg)(w, sdnReq("POST", "/api/sdn/import/apply", map[string]any{"id": insp.ID, "mapping": map[string]string{"enp5s0": "enp7s0"}}, config.RoleAdmin))
	if w.Code != 200 {
		t.Fatalf("apply %d %s", w.Code, w.Body)
	}
	d, _ := st.LoadDraft()
	if d.Config.Interfaces[0].Device != "enp7s0" || d.Config.Settings.MgmtInterface != "enp7s0" {
		t.Fatalf("mapping not applied: %+v", d.Config.Interfaces)
	}
}

func TestSDNApply_NothingToApply(t *testing.T) {
	appCfg, rec, st := sdnHandlerEnv(t)
	_ = st.DiscardDraft() // draft == confirmed
	w := httptest.NewRecorder()
	HandleSDNApply(appCfg)(w, sdnReq("POST", "/api/sdn/apply", map[string]bool{"auto_revert": true}, config.RoleAdmin))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "nothing to apply") {
		t.Fatalf("code %d %s", w.Code, w.Body)
	}
	if rec.count("nft") != 0 || rec.count("systemd-run") != 0 {
		t.Fatalf("an empty apply touched the system: %v", rec.cmds)
	}
	if list, _ := st.ListSnapshots(); len(list) != 0 {
		t.Fatal("an empty apply was recorded in history")
	}
}

// ── final-review fixes ─────────────────────────────────────────────────

func sdnOKHooks(t *testing.T) {
	oldS, oldP := sdnSudoOK, sdnPackagesOK
	sdnSudoOK, sdnPackagesOK = func() bool { return true }, func() bool { return true }
	t.Cleanup(func() { sdnSudoOK, sdnPackagesOK = oldS, oldP })
}

// I1: a root-owned (unreadable) config must not crash the status page.
func TestSDNStatus_UnreadableConfigNoPanic(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads everything")
	}
	appCfg, _, st := sdnHandlerEnv(t)
	_ = os.Chmod(filepath.Join(st.Dir, "sdn", "config.json"), 0)
	w := httptest.NewRecorder()
	HandleSDNStatus(appCfg)(w, sdnReq("GET", "/api/sdn/status", nil, config.RoleAdmin))
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	w = httptest.NewRecorder()
	HandleSDNGetDraft(appCfg)(w, sdnReq("GET", "/api/sdn/draft", nil, config.RoleAdmin))
	if w.Code != 200 && w.Code != 500 {
		t.Fatalf("draft %d", w.Code)
	}
}

// I2
func TestSDNRevertNow_StopsService(t *testing.T) {
	appCfg, rec, _ := sdnHandlerEnv(t)
	w := httptest.NewRecorder()
	HandleSDNApply(appCfg)(w, sdnReq("POST", "/api/sdn/apply", map[string]bool{"auto_revert": true}, config.RoleAdmin))
	rec.cmds = nil
	w = httptest.NewRecorder()
	HandleSDNRevertNow(appCfg)(w, sdnReq("POST", "/api/sdn/revert-now", nil, config.RoleAdmin))
	if w.Code != 200 || rec.count("systemctl stop znas-sdn-revert.service") == 0 {
		t.Fatalf("%d %v", w.Code, rec.cmds)
	}
}

// I3: the change was already auto-reverted → "keep it" must say so.
func TestSDNConfirm_AfterAutoRevert409(t *testing.T) {
	appCfg, _, st := sdnHandlerEnv(t)
	w := httptest.NewRecorder()
	HandleSDNApply(appCfg)(w, sdnReq("POST", "/api/sdn/apply", map[string]bool{"auto_revert": true}, config.RoleAdmin))
	if err := system.SDNRevertPendingNow(st, sdnEnvFor(appCfg), "auto-reverted"); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	HandleSDNConfirm(appCfg)(w, sdnReq("POST", "/api/sdn/confirm", nil, config.RoleAdmin))
	if w.Code != http.StatusConflict {
		t.Fatalf("confirm after revert: %d", w.Code)
	}
	list, _ := st.ListSnapshots()
	if list[0].Outcome != "auto-reverted" {
		t.Fatalf("outcome overwritten: %q", list[0].Outcome)
	}
}

// I4: the revert must be armed before the kernel changes.
func TestSDNApply_ArmsBeforeApplying(t *testing.T) {
	appCfg, rec, st := sdnHandlerEnv(t)
	w := httptest.NewRecorder()
	HandleSDNApply(appCfg)(w, sdnReq("POST", "/api/sdn/apply", map[string]bool{"auto_revert": true}, config.RoleAdmin))
	arm, nft := -1, -1
	for i, c := range rec.cmds {
		if strings.HasPrefix(c, "systemd-run") && arm < 0 {
			arm = i
		}
		if strings.HasPrefix(c, "nft -f") && nft < 0 {
			nft = i
		}
	}
	if arm < 0 || nft < 0 || arm > nft {
		t.Fatalf("revert armed after the kernel changed: %v", rec.cmds)
	}
	if _, err := st.LoadApplying(); err == nil {
		t.Fatal("applying.json must be cleared after a successful apply")
	}
}

// I4: a failed apply disarms the revert it armed.
func TestSDNApply_FailureDisarms(t *testing.T) {
	appCfg, rec, st := sdnHandlerEnv(t)
	n := 0
	rec.fail = func(c string) error {
		if strings.HasPrefix(c, "nft -f") {
			n++
			if n == 1 {
				return errors.New("boom")
			}
		}
		return nil
	}
	w := httptest.NewRecorder()
	HandleSDNApply(appCfg)(w, sdnReq("POST", "/api/sdn/apply", map[string]bool{"auto_revert": true}, config.RoleAdmin))
	if w.Code != 500 || rec.count("systemctl stop znas-sdn-revert.service") == 0 {
		t.Fatalf("%d %v", w.Code, rec.cmds)
	}
	if _, ok := system.SDNPendingRevert(st); ok {
		t.Fatal("pending marker left after a failed apply")
	}
}

// I13: in safe mode, re-applying the unchanged confirmed config is allowed.
func TestSDNApply_SafeModeAllowsSameConfig(t *testing.T) {
	appCfg, _, st := sdnHandlerEnv(t)
	_ = st.DiscardDraft()
	_ = os.MkdirAll(filepath.Join(st.Dir, "run"), 0755)
	_ = os.WriteFile(filepath.Join(st.Dir, "run", "safemode"), []byte("network port(s) not found: enp9s0\n"), 0644)
	w := httptest.NewRecorder()
	HandleSDNApply(appCfg)(w, sdnReq("POST", "/api/sdn/apply", map[string]bool{"auto_revert": true}, config.RoleAdmin))
	if w.Code != 200 {
		t.Fatalf("re-apply in safe mode refused: %d %s", w.Code, w.Body)
	}
}

// I8 + I9: the wizard's interfaces win over a stale saved list, Router mode
// seeds the LAN starter rules, and a failed enable keeps the saved config.
func TestSDNEnable_WizardInterfacesAndStarterRules(t *testing.T) {
	appCfg, _, st := sdnHandlerEnv(t)
	sdnOKHooks(t)
	_ = st.SaveState(sdn.State{})
	body := map[string]any{"mgmt_interface": "enp5s0", "mode": "router", "interfaces": []sdn.Interface{
		{ID: "ifnew001", Name: "LAN", Kind: "physical", Device: "enp5s0", Role: "lan", IPv4Mode: "dhcp"},
		{ID: "ifnew002", Name: "WAN", Kind: "physical", Device: "enp7s0", Role: "wan", IPv4Mode: "dhcp"},
	}}
	w := httptest.NewRecorder()
	HandleSDNEnable(appCfg)(w, sdnReq("POST", "/api/sdn/enable", body, config.RoleAdmin))
	if w.Code != 200 {
		t.Fatalf("enable %d %s", w.Code, w.Body)
	}
	c, _ := st.LoadConfirmed()
	// The port adopted before keeps its old id (its rules carry over); the
	// wizard's name and role win.
	if len(c.Interfaces) != 2 || c.Interfaces[0].ID != "if0mgmt0" || c.Interfaces[1].ID != "ifnew002" || c.Interfaces[1].Role != "wan" {
		t.Fatalf("wizard interfaces ignored: %+v", c.Interfaces)
	}
	if len(c.Rules) != 1 || c.Rules[0].Interface != "if0mgmt0" {
		t.Fatalf("starter rule missing: %+v", c.Rules)
	}
}

func TestSDNEnable_FailureKeepsSavedConfig(t *testing.T) {
	appCfg, rec, st := sdnHandlerEnv(t)
	sdnOKHooks(t)
	_ = st.SaveState(sdn.State{})
	rec.fail = func(c string) error {
		if strings.HasPrefix(c, "nft -f") {
			return errors.New("boom")
		}
		return nil
	}
	body := map[string]any{"mgmt_interface": "enp5s0", "mode": "monitor", "interfaces": []sdn.Interface{
		{ID: "ifnew001", Name: "LAN", Kind: "physical", Device: "enp5s0", Role: "lan", IPv4Mode: "dhcp"}}}
	w := httptest.NewRecorder()
	HandleSDNEnable(appCfg)(w, sdnReq("POST", "/api/sdn/enable", body, config.RoleAdmin))
	if w.Code == 200 {
		t.Fatal("enable should have failed")
	}
	c, _ := st.LoadConfirmed()
	if len(c.Interfaces) != 1 || c.Interfaces[0].ID != "if0mgmt0" {
		t.Fatalf("saved config overwritten by a failed enable: %+v", c.Interfaces)
	}
}

// Infrastructure must not edit or delete a network the Firewall manages.
func TestInfraRefusesFirewallOwnedNetwork(t *testing.T) {
	appCfg, _, st := sdnHandlerEnv(t)
	_ = appCfg
	block := "auto lo\niface lo inet loopback\n\n# znas-sdn-start id=if000800 device=enp7s0-v800\nauto br-enp7s0-v800\niface br-enp7s0-v800 inet static\n    address 10.97.8.1/24\n# znas-sdn-end\n"
	_ = os.WriteFile(filepath.Join(st.Dir, "interfaces"), []byte(block), 0644)
	for _, h := range []struct {
		name string
		fn   http.HandlerFunc
		req  *http.Request
	}{
		{"delete", HandleDeleteLXDNetwork, sdnReq("DELETE", "/api/lxd/network-bridges/br-enp7s0-v800", nil, config.RoleAdmin)},
		{"edit", HandleEditLXDNetwork, sdnReq("PUT", "/api/lxd/network-bridges/br-enp7s0-v800", map[string]string{"description": "x"}, config.RoleAdmin)},
		{"host-bridge", HandleSetHostBridge, sdnReq("PUT", "/api/lxd/host-bridges/br-enp7s0-v800", map[string]string{"mode": "dhcp"}, config.RoleAdmin)},
	} {
		w := httptest.NewRecorder()
		h.fn(w, mux.SetURLVars(h.req, map[string]string{"name": "br-enp7s0-v800"}))
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "managed by the Firewall") {
			t.Fatalf("%s: %d %s", h.name, w.Code, w.Body)
		}
	}
}

func sdnForwardHooks(t *testing.T) *[]string {
	var calls []string
	oldA, oldD, oldR := sdnAdoptForwards, sdnDropForwards, sdnRestoreForwards
	sdnAdoptForwards = func(last *sdn.Config) []sdn.PortForward {
		calls = append(calls, "adopt")
		return []sdn.PortForward{{ID: sdn.InstanceForwardID("web", "eth0", "tcp", 443), Enabled: true, Protocol: "tcp", PubPorts: "443",
			TargetPorts: "443", Target: "10.0.0.20", TargetAuto: true, Instance: "web", NIC: "eth0", Source: sdn.Endpoint{Type: "any"}}}
	}
	sdnDropForwards = func() { calls = append(calls, "drop") }
	sdnRestoreForwards = func(c *sdn.Config) { calls = append(calls, "restore "+strconv.Itoa(len(c.PortForwards))) }
	t.Cleanup(func() { sdnAdoptForwards, sdnDropForwards, sdnRestoreForwards = oldA, oldD, oldR })
	return &calls
}

func TestSDNEnable_CarriesGatewaysNATAndAdoptsForwards(t *testing.T) {
	appCfg, _, st := sdnHandlerEnv(t)
	sdnOKHooks(t)
	calls := sdnForwardHooks(t)
	last := sdnBaseConfig()
	last.Interfaces = append(last.Interfaces, sdn.Interface{ID: "if0wan01", Name: "WAN", Kind: "physical", Device: "enp7s0", Role: "wan", IPv4Mode: "static", IPv4: "10.250.0.2/24"})
	last.Gateways = []sdn.Gateway{{ID: "gwisp001", Name: "ISP", Interface: "if0wan01", Address: "10.250.0.1", Priority: 1}}
	last.PortForwards = []sdn.PortForward{
		{ID: "pfmanual1", Enabled: true, Protocol: "tcp", PubPorts: "80", TargetPorts: "80", Target: "10.0.0.5", Interfaces: []string{"if0wan01", "ifgone"}},
		{ID: "stale", Instance: "old", NIC: "eth0", Protocol: "tcp", PubPorts: "22", TargetPorts: "22"}, // replaced by the adopted list
	}
	last.SNATRules = []sdn.SNATRule{{ID: "sn1", Enabled: true, Gateway: "gwisp001", Translate: "iface", Source: sdn.Endpoint{Type: "any"}, Destination: sdn.Endpoint{Type: "any"}, Protocol: "any"}}
	last.Normalize()
	_ = st.SaveConfirmed(last)
	_ = st.SaveState(sdn.State{})
	w := httptest.NewRecorder()
	HandleSDNEnable(appCfg)(w, sdnReq("POST", "/api/sdn/enable", map[string]any{"mgmt_interface": "enp5s0", "mode": "router"}, config.RoleAdmin))
	if w.Code != 200 {
		t.Fatalf("enable %d %s", w.Code, w.Body)
	}
	c, _ := st.LoadConfirmed()
	if len(c.Gateways) != 1 || len(c.SNATRules) != 1 || len(c.PortForwards) != 2 {
		t.Fatalf("gw %d snat %d fwd %+v", len(c.Gateways), len(c.SNATRules), c.PortForwards)
	}
	if f := c.PortForwards[0]; f.ID != "pfmanual1" || len(f.Interfaces) != 1 {
		t.Fatalf("manual forward: %+v", f)
	}
	if c.PortForwards[1].Instance != "web" || strings.Join(*calls, ",") != "adopt" {
		t.Fatalf("adopted %+v calls %v", c.PortForwards[1], *calls)
	}
	// Proxies go only once the enable is confirmed.
	w = httptest.NewRecorder()
	HandleSDNConfirm(appCfg)(w, sdnReq("POST", "/api/sdn/confirm", nil, config.RoleAdmin))
	if w.Code != 200 || strings.Join(*calls, ",") != "adopt,drop" {
		t.Fatalf("confirm %d calls %v", w.Code, *calls)
	}
	// Disable puts them back as proxy devices.
	w = httptest.NewRecorder()
	HandleSDNDisable(appCfg)(w, sdnReq("POST", "/api/sdn/disable", nil, config.RoleAdmin))
	if w.Code != 200 || (*calls)[2] != "restore 2" {
		t.Fatalf("disable %d calls %v", w.Code, *calls)
	}
}

func TestSDNSecretsNeverReturned(t *testing.T) {
	appCfg, _, st := sdnHandlerEnv(t)
	c := sdnBaseConfig()
	c.Interfaces = append(c.Interfaces, sdn.Interface{ID: "wanpppoe1", Name: "Fibre", Kind: "pppoe", Parent: "enp7s0", Role: "wan", PPPoEUser: "u", PPPoEPassword: "hunter2"})
	c.Normalize()
	_ = st.SaveConfirmed(c)
	_ = st.DiscardDraft()
	_ = st.AddSnapshot(sdn.Snapshot{ID: "s1", Summary: "x", Outcome: "confirmed", Config: c})
	for name, h := range map[string]http.HandlerFunc{"config": HandleSDNGetConfig(appCfg), "draft": HandleSDNGetDraft(appCfg), "history": HandleSDNHistory(appCfg)} {
		w := httptest.NewRecorder()
		h(w, sdnReq("GET", "/api/sdn/"+name, nil, config.RoleAdmin))
		if strings.Contains(w.Body.String(), "hunter2") || name != "history" && !strings.Contains(w.Body.String(), `"pppoe_password_set":true`) {
			t.Fatalf("%s leaks or hides the flag: %s", name, w.Body)
		}
	}
	// The browser sends the config back without the password: kept.
	c.Interfaces[1].PPPoEPassword, c.Interfaces[1].Name = "", "Fibre renamed"
	cur, _ := st.LoadDraft()
	w := httptest.NewRecorder()
	HandleSDNPutDraft(appCfg)(w, sdnReq("PUT", "/api/sdn/draft", map[string]any{"base_revision": cur.Revision, "config": c}, config.RoleAdmin))
	if w.Code != 200 || strings.Contains(w.Body.String(), "hunter2") {
		t.Fatalf("put %d %s", w.Code, w.Body)
	}
	d, _ := st.LoadDraft()
	if d.Config.Interfaces[1].PPPoEPassword != "hunter2" {
		t.Fatalf("password lost: %+v", d.Config.Interfaces[1])
	}
}
