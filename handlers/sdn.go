package handlers

// HTTP API of the SDN (routing & firewall) feature — spec PLANS/spec-sdn-firewall.md.
// Edits go to a draft; Apply moves the kernel to the draft and (by default)
// arms a 30 s revert timer that only the admin's "All good" disarms.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/sdn"
	"zfsnas/system"

	"github.com/gorilla/mux"
)

// sdnMu serialises every state-changing SDN operation (apply, confirm,
// revert, restore, enable, disable, import).
var sdnMu sync.Mutex

// SDNCountdownSeconds is the owner-fixed confirmation window.
const SDNCountdownSeconds = 30

func sdnStoreFor(appCfg *config.AppConfig) sdn.Store { return sdn.Store{Dir: appCfg.ConfigDir} }

func sdnEnvFor(appCfg *config.AppConfig) sdn.Env {
	return system.SDNEnvFor(appCfg.Port, appCfg.BindPort443, appCfg.ConfigDir)
}

// sdnRunAs is the user the revert timer runs as: the portal's own user, so
// the files it rewrites keep their owner. Empty when the portal is root.
func sdnRunAs() string {
	if os.Getuid() == 0 {
		return ""
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

func sdnBinary() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "/opt/zfsnas/zfsnas"
}

// RequireFirewallView gates the read-only Firewall endpoints like
// RequireNetView: admin and read-only pass, a standard user needs
// view_firewall.
func RequireFirewallView(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := standardPermsForSession(r); p != nil && !p.ViewFirewall {
			jsonErr(w, http.StatusForbidden, "permission denied")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type sdnPendingView struct {
	Snapshot    string  `json:"snapshot"`
	SecondsLeft float64 `json:"seconds_left"`
}

func sdnPendingNow(st sdn.Store) *sdnPendingView {
	p, ok := system.SDNPendingRevert(st)
	if !ok {
		return nil
	}
	left := math.Max(0, time.Until(p.Deadline).Seconds())
	return &sdnPendingView{Snapshot: p.Applied, SecondsLeft: math.Round(left*10) / 10}
}

// HandleSDNStatus — GET /api/sdn/status
func HandleSDNStatus(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := sdnStoreFor(appCfg)
		state, _ := st.LoadState()
		mode := ""
		if c, err := st.LoadConfirmed(); err == nil {
			mode = c.Settings.Mode
		}
		sudo := system.CheckSudoAccess().Type
		resp := map[string]any{
			"installed":        system.SDNPackagesInstalled(),
			"ppp_installed":    system.SDNPPPInstalled(),
			"missing_packages": system.SDNMissingPackages(),
			"virtual_ips":      system.SDNVIPStatus(),
			"enabled":          state.Enabled,
			"restored":         !state.Enabled && st.Restored(),
			"appliance":        system.ApplianceMode(),
			"sudo_ok":          sudo == "root" || sudo == "all",
			"mode":             mode,
			"safe_mode_reason": system.SDNSafeModeReason(),
			"pending":          sdnPendingNow(st),
			"last_change":      nil,
			"portal_ports":     append(append([]int{}, sdnEnvFor(appCfg).PortalPorts...), sdnEnvFor(appCfg).SSHPort),
		}
		if list, _ := st.ListSnapshots(); len(list) > 0 {
			resp["last_change"] = map[string]any{"at": list[0].At, "summary": list[0].Summary, "outcome": list[0].Outcome}
		}
		jsonOK(w, resp)
	}
}

// HandleSDNGetConfig — GET /api/sdn/config (confirmed)
func HandleSDNGetConfig(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := sdnStoreFor(appCfg).LoadConfirmed()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, c.Redacted())
	}
}

func sdnDraftView(st sdn.Store, d *sdn.Draft) map[string]any {
	summary := "no changes"
	if cur, err := st.LoadConfirmed(); err == nil {
		summary = sdn.Summarize(cur, d.Config)
	}
	n := 0
	if summary != "no changes" {
		n = len(strings.Split(summary, " · "))
	}
	return map[string]any{"revision": d.Revision, "edited_by": d.EditedBy, "edited_at": d.EditedAt,
		"config": d.Config.Redacted(), "pending_changes": n, "summary": summary}
}

// HandleSDNGetDraft — GET /api/sdn/draft
func HandleSDNGetDraft(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := sdnStoreFor(appCfg)
		d, err := st.LoadDraft()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, sdnDraftView(st, d))
	}
}

// HandleSDNPutDraft — PUT /api/sdn/draft {base_revision, config}
func HandleSDNPutDraft(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			BaseRevision int         `json:"base_revision"`
			Config       *sdn.Config `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Config == nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		body.Config.Normalize()
		st := sdnStoreFor(appCfg)
		// Secrets come back redacted: keep the stored ones.
		if cur, err := st.LoadDraft(); err == nil {
			body.Config.KeepSecretsFrom(cur.Config)
		}
		// Tunnel keys are made here, never in the browser.
		if err := sdn.EnsureWGKeys(body.Config); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		d, err := st.SaveDraft(body.Config, body.BaseRevision, MustSession(r).Username)
		if errors.Is(err, sdn.ErrStaleDraft) {
			jsonErr(w, http.StatusConflict, fmt.Sprintf("edited by %s at %s — reload to see their changes",
				d.EditedBy, d.EditedAt.Local().Format("15:04 2006-01-02")))
			return
		}
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, sdnDraftView(st, d))
	}
}

// HandleSDNDiscardDraft — DELETE /api/sdn/draft
func HandleSDNDiscardDraft(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := sdnStoreFor(appCfg).DiscardDraft(); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleSDNValidate — POST /api/sdn/validate (Config) → {errors}
func HandleSDNValidate(w http.ResponseWriter, r *http.Request) {
	var c sdn.Config
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	c.Normalize()
	errs := sdn.ValidationErrors{}
	if err := c.Validate(); err != nil {
		errs = err.(sdn.ValidationErrors)
	}
	jsonOK(w, map[string]any{"errors": errs})
}

// Hooks for tests (enable needs root/sudo-all and the runtime tools).
var (
	sdnSudoOK     = func() bool { t := system.CheckSudoAccess().Type; return t == "root" || t == "all" }
	sdnPackagesOK = system.SDNPackagesInstalled
	sdnPPPOK      = system.SDNPPPInstalled
	sdnDnsmasqOK  = system.SDNDnsmasqInstalled
	sdnWGOK       = system.SDNWireGuardInstalled
	sdnSuricataOK = system.SDNSuricataInstalled
	sdnDDClientOK = system.SDNDDClientInstalled
	// Instance port forwards: proxy devices ⇄ Firewall forwards.
	sdnAdoptForwards   = system.SDNAdoptProxyForwards
	sdnDropForwards    = system.SDNDropProxyForwards
	sdnRestoreForwards = system.SDNRestoreProxyForwards
)

// sdnLocked runs fn under both locks: sdnMu (this process) and the store's
// flock (shared with the revert service and the boot unit), so a confirm can
// never race a revert in progress.
func sdnLocked(st sdn.Store, fn func()) error {
	sdnMu.Lock()
	defer sdnMu.Unlock()
	unlock, err := st.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	fn()
	return nil
}

// sdnApplyConfig moves the kernel from cur to next and records it. When
// autoRevert is set, the revert (to target: system.PreviousTarget, or
// system.PreSDNTarget right after enabling) is armed BEFORE the kernel is
// touched, so a portal that dies mid-apply is still covered. Caller holds
// the locks. Returns the HTTP status and the JSON body.
func sdnApplyConfig(appCfg *config.AppConfig, cur *sdn.Config, user, role string, next *sdn.Config, autoRevert bool,
	target, summaryPrefix, restoredFrom string) (int, any) {
	st := sdnStoreFor(appCfg)
	if _, ok := system.SDNPendingRevert(st); ok {
		return http.StatusConflict, map[string]string{"error": "a change is waiting for confirmation — confirm or revert it first"}
	}
	next.Normalize()
	if err := next.Validate(); err != nil {
		return http.StatusUnprocessableEntity, map[string]any{"error": "the configuration has errors", "errors": err}
	}
	for _, in := range next.Interfaces {
		if in.Kind == "pppoe" && !sdnPPPOK() {
			return http.StatusBadRequest, map[string]string{"error": "PPPoE needs the ppp package — install it first (Optional Features → Firewall)"}
		}
		if in.Kind == "wireguard" && !sdnWGOK() {
			return http.StatusBadRequest, map[string]string{"error": "WireGuard needs the wireguard-tools package — install it first (Firewall → WireGuard)"}
		}
	}
	if next.IDS.Enabled && !sdnSuricataOK() {
		return http.StatusBadRequest, map[string]string{"error": "Intrusion detection needs the suricata package — install it first (Firewall → Intrusion detection)"}
	}
	if sdnUsesDDNS(next) && !sdnDDClientOK() {
		return http.StatusBadRequest, map[string]string{"error": "Dynamic DNS needs the ddclient package — install it first (Firewall → Dynamic DNS)"}
	}
	if sdnUsesDnsmasq(next) && !sdnDnsmasqOK() {
		return http.StatusBadRequest, map[string]string{"error": "DHCP and DNS need the dnsmasq-base package — install it first (Firewall → DHCP & DNS)"}
	}
	env := sdnEnvFor(appCfg)
	// In safe mode re-applying the unchanged configuration is the repair.
	if sdn.Summarize(cur, next) == "no changes" && system.SDNSafeModeReason() == "" {
		return http.StatusBadRequest, map[string]string{"error": "nothing to apply — this is already the running configuration"}
	}
	summary := summaryPrefix + sdn.Summarize(cur, next)
	if summary == summaryPrefix+"no changes" {
		summary = summaryPrefix + "re-applied after safe mode"
	}
	id := sdn.NewID()
	if err := st.SaveRevertPoint(cur); err != nil {
		return http.StatusInternalServerError, map[string]string{"error": err.Error()}
	}
	if err := st.SaveApplying(next); err != nil {
		return http.StatusInternalServerError, map[string]string{"error": err.Error()}
	}
	disarm := func() {
		system.SDNStopRevertService()
		_ = system.SDNCancelRevert(st)
	}
	if autoRevert {
		if err := system.SDNArmRevert(st, sdnBinary(), target, id, SDNCountdownSeconds, sdnRunAs()); err != nil {
			st.ClearApplying()
			return http.StatusInternalServerError, map[string]string{"error": "could not arm the auto-revert: " + err.Error()}
		}
	}
	started := time.Now()
	res, err := system.SDNApply(cur, next, env)
	if err != nil {
		if autoRevert {
			disarm()
		}
		// Put the kernel back on the running config; nothing is saved.
		system.SDNApply(next, cur, env) //nolint:errcheck — best effort, the original error is what matters
		st.ClearApplying()
		audit.Log(audit.Entry{User: user, Role: role, Action: audit.ActionSDNApply, Target: "firewall",
			Result: audit.ResultError, Details: err.Error()})
		return http.StatusInternalServerError, map[string]string{"error": err.Error()}
	}
	if err := st.SaveConfirmed(next); err != nil {
		if autoRevert {
			disarm()
		}
		system.SDNApply(next, cur, env) //nolint:errcheck
		st.ClearApplying()
		return http.StatusInternalServerError, map[string]string{"error": err.Error()}
	}
	st.ClearApplying()
	system.SDNRefreshCountryCache(appCfg.ConfigDir, next, env)
	if system.SDNIDSNeedsUpdate(next) {
		go system.SDNIDSUpdate(next) //nolint:errcheck — first rules, or new sources/categories
	}
	system.SDNBlocklistsKick(false) // new lists, or allowed/blocked domains
	outcome := "confirmed"
	if autoRevert {
		outcome = "pending"
	}
	_ = st.AddSnapshot(sdn.Snapshot{ID: id, User: user, Summary: summary, Outcome: outcome,
		At: time.Now().UTC(), Config: next, RestoredFrom: restoredFrom})
	_ = st.DiscardDraft()
	seconds := 0
	if autoRevert {
		seconds = SDNCountdownSeconds - int(time.Since(started).Seconds())
		if seconds < 1 {
			seconds = 1
		}
	}
	audit.Log(audit.Entry{User: user, Role: role, Action: audit.ActionSDNApply, Target: "firewall",
		Result: audit.ResultOK, Details: summary})
	return http.StatusOK, map[string]any{"snapshot": id, "seconds": seconds, "summary": summary, "warnings": res.Warnings}
}

// HandleSDNApply — POST /api/sdn/apply {auto_revert}
func HandleSDNApply(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AutoRevert bool `json:"auto_revert"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		sess := MustSession(r)
		st := sdnStoreFor(appCfg)
		code, resp := 0, any(nil)
		if err := sdnLocked(st, func() {
			if state, _ := st.LoadState(); !state.Enabled {
				code, resp = http.StatusBadRequest, map[string]string{"error": "the Firewall feature is not enabled"}
				return
			}
			d, err := st.LoadDraft()
			cur, cerr := st.LoadConfirmed()
			if err != nil || cerr != nil {
				code, resp = http.StatusInternalServerError, map[string]string{"error": "cannot read the firewall configuration: " + errors.Join(err, cerr).Error()}
				return
			}
			code, resp = sdnApplyConfig(appCfg, cur, sess.Username, sess.Role, d.Config, body.AutoRevert, system.PreviousTarget, "", "")
		}); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		sdnWrite(w, code, resp)
	}
}

func sdnWrite(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// HandleSDNConfirm — POST /api/sdn/confirm ("All good — keep it")
func HandleSDNConfirm(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		st := sdnStoreFor(appCfg)
		code, msg := http.StatusOK, ""
		if err := sdnLocked(st, func() {
			p, ok := system.SDNPendingRevert(st)
			if !ok {
				code, msg = http.StatusConflict, "too late — the change was already reverted"
				return
			}
			if sn, err := st.LoadSnapshot(p.Applied); err == nil && sn.Outcome != "pending" {
				code, msg = http.StatusConflict, "too late — the change was already reverted"
				return
			}
			if err := system.SDNCancelRevert(st); err != nil {
				code, msg = http.StatusInternalServerError, err.Error()
				return
			}
			_ = st.SetOutcome(p.Applied, "confirmed")
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionSDNConfirm, Target: "firewall", Result: audit.ResultOK})
		}); err != nil {
			code, msg = http.StatusInternalServerError, err.Error()
		}
		if code == http.StatusOK {
			// A confirmed enable: the Firewall now owns instance forwards.
			sdnDropForwards()
		}
		if code != http.StatusOK {
			jsonErr(w, code, msg)
			return
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleSDNRevertNow — POST /api/sdn/revert-now
func HandleSDNRevertNow(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		st := sdnStoreFor(appCfg)
		var rerr error
		if err := sdnLocked(st, func() {
			// The sleeping revert service must not fire later nor block the
			// next apply's arm.
			system.SDNStopRevertService()
			rerr = system.SDNRevertPendingNow(st, sdnEnvFor(appCfg), "reverted")
		}); err != nil {
			rerr = err
		}
		res := audit.ResultOK
		if rerr != nil {
			res = audit.ResultError
		}
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionSDNRestore, Target: "firewall",
			Result: res, Details: "revert now"})
		if rerr != nil {
			jsonErr(w, http.StatusInternalServerError, rerr.Error())
			return
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleSDNPending — GET /api/sdn/pending → {snapshot, seconds_left} | null
func HandleSDNPending(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, sdnPendingNow(sdnStoreFor(appCfg)))
	}
}

// HandleSDNHistory — GET /api/sdn/history
func HandleSDNHistory(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := sdnStoreFor(appCfg).ListSnapshots()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		for i := range list {
			if list[i].Config != nil {
				list[i].Config = list[i].Config.Redacted()
			}
		}
		jsonOK(w, list)
	}
}

// HandleSDNRestore — POST /api/sdn/history/{id}/restore {auto_revert}
func HandleSDNRestore(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AutoRevert bool `json:"auto_revert"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		sess := MustSession(r)
		id := mux.Vars(r)["id"]
		st := sdnStoreFor(appCfg)
		code, resp := 0, any(nil)
		if err := sdnLocked(st, func() {
			sn, err := st.LoadSnapshot(id)
			if err != nil {
				code, resp = http.StatusNotFound, map[string]string{"error": "change not found in history"}
				return
			}
			cur, err := st.LoadConfirmed()
			if err != nil {
				code, resp = http.StatusInternalServerError, map[string]string{"error": err.Error()}
				return
			}
			prefix := "Restored " + sn.At.Local().Format("15:04 2006-01-02") + ": "
			code, resp = sdnApplyConfig(appCfg, cur, sess.Username, sess.Role, sn.Config, body.AutoRevert, system.PreviousTarget, prefix, id)
		}); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		sdnWrite(w, code, resp)
	}
}

// HandleSDNEnable — POST /api/sdn/enable {mgmt_interface, mode, interfaces}
//
// The wizard's interface list wins; groups and the rules whose interfaces
// still exist are kept from the last configuration (re-enabling after a
// disable). Router mode seeds the "allow LAN → anywhere" starter rules. The
// saved configuration is only replaced when the apply succeeds.
func HandleSDNEnable(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			MgmtInterface string          `json:"mgmt_interface"`
			Mode          string          `json:"mode"`
			Interfaces    []sdn.Interface `json:"interfaces"`
			// A config restored from a backup: its ports' names here, or
			// start without it.
			Mapping map[string]string `json:"mapping"`
			Fresh   bool              `json:"fresh"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if !sdnSudoOK() {
			jsonErr(w, http.StatusBadRequest, "the Firewall feature needs the portal to run as root or with unrestricted sudo")
			return
		}
		if !sdnPackagesOK() {
			jsonErr(w, http.StatusBadRequest, "required packages are missing (nftables, ifupdown) — install them first")
			return
		}
		sess := MustSession(r)
		st := sdnStoreFor(appCfg)
		code, resp := 0, any(nil)
		if err := sdnLocked(st, func() {
			state, _ := st.LoadState()
			if state.Enabled {
				code, resp = http.StatusConflict, map[string]string{"error": "the Firewall feature is already enabled"}
				return
			}
			saved, err := st.LoadConfirmed()
			if err != nil {
				code, resp = http.StatusInternalServerError, map[string]string{"error": err.Error()}
				return
			}
			last := saved
			if body.Fresh {
				last = sdn.DefaultConfig()
			} else if len(body.Mapping) > 0 {
				last = sdn.RemapDevices(saved, body.Mapping)
			}
			next := &sdn.Config{Version: 1, Settings: last.Settings, Interfaces: last.Interfaces, Groups: last.Groups}
			restored := st.Restored() && !body.Fresh
			if len(body.Interfaces) > 0 {
				next.Interfaces = sdnReuseLastInterfaces(last, body.Interfaces, body.MgmtInterface, restored)
			}
			sdnCarryOver(last, next)
			var dropped []string
			if restored {
				dropped = sdnCarryDropped(last, next)
			}
			// Instance forwards come from the instances' proxy devices as
			// they are now (paused unless published the last time).
			next.PortForwards = append(next.PortForwards, sdnAdoptForwards(last)...)
			next.Settings.MgmtInterface = body.MgmtInterface
			next.Settings.AntiLockout = true
			if body.Mode != "" {
				next.Settings.Mode = body.Mode
			}
			// A restored config has the rules its owner chose.
			if next.Settings.Mode == "router" && !restored {
				sdn.AddStarterRules(next)
			}
			next.Normalize()
			if err := next.Validate(); err != nil {
				code, resp = http.StatusUnprocessableEntity, map[string]any{"error": "the configuration has errors", "errors": err}
				return
			}
			ifaces, sysctl, err := system.SDNCapture()
			if err != nil {
				code, resp = http.StatusInternalServerError, map[string]string{"error": "cannot read the current network configuration: " + err.Error()}
				return
			}
			nftOn := system.SDNNftablesServiceEnabled()
			pre := sdn.State{Enabled: true, PreSDNInterfaces: ifaces, PreSDNSysctl: sysctl, NftablesServiceEnabled: nftOn,
				PreSDNDefaultRoute: system.SDNDefaultRoute()}
			if err := system.SDNInstallUnit(sdnBinary(), appCfg.ConfigDir); err != nil {
				code, resp = http.StatusInternalServerError, map[string]string{"error": "boot unit: " + err.Error()}
				return
			}
			if err := st.SaveState(pre); err != nil {
				code, resp = http.StatusInternalServerError, map[string]string{"error": err.Error()}
				return
			}
			// Every interface is new to the kernel's point of view: apply
			// from an empty config; the revert target is the pre-SDN state.
			code, resp = sdnApplyConfig(appCfg, sdn.DefaultConfig(), sess.Username, sess.Role, next, true, system.PreSDNTarget, "Firewall enabled: ", "")
			if code != http.StatusOK {
				_ = system.SDNRestorePreSDN(st, pre, true)
				_ = st.SaveConfirmed(saved) // the failed attempt must not cost the saved configuration
			} else {
				st.ClearRestored()
				// config.json exists now: the monitor's start condition holds.
				if err := system.SDNStartGatewayMonitor(); err != nil {
					log.Printf("[sdn] starting the gateway monitor: %v", err)
				}
				if m, ok := resp.(map[string]any); ok && len(dropped) > 0 {
					m["dropped"] = dropped
				}
			}
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionSDNEnable, Target: "firewall",
				Result: map[bool]string{true: audit.ResultOK, false: audit.ResultError}[code == http.StatusOK]})
		}); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		sdnWrite(w, code, resp)
	}
}

// HandleSDNDisable — POST /api/sdn/disable {delete_traffic}
func HandleSDNDisable(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		st := sdnStoreFor(appCfg)
		code, msg := http.StatusOK, ""
		if err := sdnLocked(st, func() {
			if _, ok := system.SDNPendingRevert(st); ok {
				code, msg = http.StatusConflict, "a change is waiting for confirmation — confirm or revert it first"
				return
			}
			state, _ := st.LoadState()
			if !state.Enabled {
				code, msg = http.StatusConflict, "the Firewall feature is not enabled"
				return
			}
			cur, _ := st.LoadConfirmed()
			err := system.SDNRestorePreSDN(st, state, false)
			if err == nil {
				sdnRestoreForwards(cur)
			}
			res := audit.ResultOK
			if err != nil {
				res, code, msg = audit.ResultError, http.StatusInternalServerError, err.Error()
			}
			audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionSDNDisable, Target: "firewall", Result: res})
		}); err != nil {
			code, msg = http.StatusInternalServerError, err.Error()
		}
		if code != http.StatusOK {
			jsonErr(w, code, msg)
			return
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleSDNLiveInterfaces — GET /api/sdn/interfaces/live
func HandleSDNLiveInterfaces(w http.ResponseWriter, r *http.Request) {
	local := ""
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if host, _, err := net.SplitHostPort(a.String()); err == nil {
			local = host
		}
	}
	list, err := system.SDNLiveInterfaces(local)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, list)
}

// HandleSDNCounters — GET /api/sdn/counters → {rule id: counters}
func HandleSDNCounters(w http.ResponseWriter, r *http.Request) {
	m, err := system.SDNRuleCounters()
	if err != nil {
		jsonOK(w, map[string]system.RuleCounter{}) // table absent (monitor mode not applied yet): no hits
		return
	}
	jsonOK(w, m)
}

// sdnCarryOver copies the parts of the last configuration that still fit
// the interfaces being enabled: rules, gateways, manual port forwards
// (dropping interfaces that are gone) and outbound NAT rules.
func sdnCarryOver(last, next *sdn.Config) {
	// WireGuard tunnels need no port: they come back with their peers.
	for _, in := range last.Interfaces {
		if in.Kind == "wireguard" && next.InterfaceByID(in.ID) == nil {
			next.Interfaces = append(next.Interfaces, in)
		}
	}
	for _, p := range last.WGPeers {
		if next.InterfaceByID(p.Tunnel) != nil {
			next.WGPeers = append(next.WGPeers, p)
		}
	}
	for _, d := range last.DHCP {
		if next.InterfaceByID(d.Interface) != nil {
			next.DHCP = append(next.DHCP, d)
		}
	}
	keepIfaces := func(ids []string) []string {
		out := []string{}
		for _, id := range ids {
			if next.InterfaceByID(id) != nil {
				out = append(out, id)
			}
		}
		return out
	}
	next.DNS = last.DNS
	next.DNS.Interfaces = keepIfaces(last.DNS.Interfaces)
	if len(next.DNS.Interfaces) == 0 {
		next.DNS.Enabled = false
	}
	next.IDS = last.IDS
	next.IDS.Interfaces = keepIfaces(last.IDS.Interfaces)
	for _, g := range last.Gateways {
		if next.InterfaceByID(g.Interface) != nil {
			next.Gateways = append(next.Gateways, g)
		}
	}
	for _, rl := range last.Rules {
		if rl.Interface == "" || next.InterfaceByID(rl.Interface) != nil {
			if rl.Gateway != "" && next.GatewayByID(rl.Gateway) == nil {
				rl.Gateway, rl.OnlyGateway = "", false
			}
			next.Rules = append(next.Rules, rl)
		}
	}
	for _, f := range last.PortForwards {
		if f.Instance != "" {
			continue
		}
		var keep []string
		for _, id := range f.Interfaces {
			if next.InterfaceByID(id) != nil {
				keep = append(keep, id)
			}
		}
		if len(keep) == 0 {
			continue
		}
		f.Interfaces = keep
		next.PortForwards = append(next.PortForwards, f)
	}
	for _, r := range last.SNATRules {
		if r.Gateway == "" || next.GatewayByID(r.Gateway) != nil {
			next.SNATRules = append(next.SNATRules, r)
		}
	}
	for _, d := range last.DDNS {
		if next.GatewayByID(d.Gateway) != nil {
			next.DDNS = append(next.DDNS, d)
		}
	}
	sdnDropInvalidServices(next)
}

// sdnCarryDropped lists what of a restored config did not fit this server,
// for the admin to see.
func sdnCarryDropped(last, next *sdn.Config) []string {
	var out []string
	count := func(what string, had, has int) {
		if n := had - has; n > 0 {
			out = append(out, fmt.Sprintf("%d %s", n, what))
		}
	}
	count("interface(s)", len(last.Interfaces), len(next.Interfaces))
	count("firewall rule(s)", len(last.Rules), len(next.Rules))
	count("gateway(s)", len(last.Gateways), len(next.Gateways))
	manual := 0
	for _, f := range last.PortForwards {
		if f.Instance == "" {
			manual++
		}
	}
	kept := 0
	for _, f := range next.PortForwards {
		if f.Instance == "" {
			kept++
		}
	}
	count("port forward(s)", manual, kept)
	count("outbound NAT rule(s)", len(last.SNATRules), len(next.SNATRules))
	count("DHCP network(s)", len(last.DHCP), len(next.DHCP))
	count("VPN peer(s)", len(last.WGPeers), len(next.WGPeers))
	count("dynamic DNS name(s)", len(last.DDNS), len(next.DDNS))
	if last.DNS.Enabled && !next.DNS.Enabled {
		out = append(out, "local DNS")
	}
	if last.IDS.Enabled && !next.IDS.Enabled {
		out = append(out, "intrusion detection")
	}
	return out
}

// sdnDeviceExists: a network device is present on this server.
var sdnDeviceExists = func(dev string) bool {
	for _, d := range system.SDNDeviceNames() {
		if d == dev {
			return true
		}
	}
	return false
}

// sdnReuseLastInterfaces: the wizard's interfaces, where a port that was
// already adopted keeps its old id (so its rules, gateways, DHCP… carry
// over) and gets its Firewall addressing back when the wizard brings none
// (disabling gave the port its original addressing), plus the VLANs and
// PPPoE links the Firewall had created on ports still present. The wizard's
// names, roles and addressing win — except for a config restored from a
// backup, whose addressing and Incus mode come back too; the management port
// keeps the address the admin reaches it on.
func sdnReuseLastInterfaces(last *sdn.Config, body []sdn.Interface, mgmt string, restored bool) []sdn.Interface {
	if last == nil {
		return body
	}
	byDev := map[string]sdn.Interface{}
	for _, in := range last.Interfaces {
		if !in.Owned {
			byDev[in.Device] = in
		}
	}
	out := make([]sdn.Interface, 0, len(body))
	devs := map[string]bool{}
	taken := map[string]bool{}
	for _, in := range body {
		if old, ok := byDev[in.Device]; ok && !taken[old.ID] {
			in.ID = old.ID
			taken[old.ID] = true
			if (in.IPv4Mode == "none" && old.IPv4Mode != "none") || (restored && in.Device != mgmt) {
				in.IPv4Mode, in.IPv4, in.Gateway, in.MTU = old.IPv4Mode, old.IPv4, old.Gateway, old.MTU
			}
			if restored {
				in.IncusKeep, in.IncusDHCP, in.IncusDNS = old.IncusKeep, old.IncusDHCP, old.IncusDNS
			}
		}
		devs[in.Device], devs[in.L3Device()] = true, true
		out = append(out, in)
	}
	for _, in := range last.Interfaces {
		if (in.Kind == "vlan" || in.Kind == "pppoe") && in.Owned && (devs[in.Parent] || sdnDeviceExists(in.Parent)) && !taken[in.ID] {
			taken[in.ID] = true
			out = append(out, in)
		}
	}
	// A PPPoE link may sit on a VLAN that just came back.
	for _, in := range last.Interfaces {
		if in.Kind == "pppoe" && !taken[in.ID] {
			for _, o := range out {
				if o.Device == in.Parent {
					taken[in.ID] = true
					out = append(out, in)
					break
				}
			}
		}
	}
	return out
}

var sdnIndexedPath = regexp.MustCompile(`^(dhcp|wg_peers)\[(\d+)\]`)

// sdnDropInvalidServices removes carried service settings that no longer
// validate (an interface re-addressed in the wizard): a DHCP server or peer
// at a time, DNS and IDS turned off — enabling must never fail on them.
func sdnDropInvalidServices(c *sdn.Config) {
	for tries := 0; tries < 64; tries++ {
		c.Normalize()
		ve, ok := c.Validate().(sdn.ValidationErrors)
		if !ok || len(ve) == 0 {
			return
		}
		changed := false
		for _, e := range ve {
			if m := sdnIndexedPath.FindStringSubmatch(e.Path); m != nil {
				i, _ := strconv.Atoi(m[2])
				if m[1] == "dhcp" && i < len(c.DHCP) {
					c.DHCP = append(c.DHCP[:i], c.DHCP[i+1:]...)
				} else if m[1] == "wg_peers" && i < len(c.WGPeers) {
					c.WGPeers = append(c.WGPeers[:i], c.WGPeers[i+1:]...)
				}
				changed = true
				break
			}
			if strings.HasPrefix(e.Path, "dns.") && c.DNS.Enabled {
				c.DNS = sdn.DNSSettings{}
				changed = true
				break
			}
			if strings.HasPrefix(e.Path, "ids.") && c.IDS.Enabled {
				c.IDS.Enabled, c.IDS.Interfaces = false, []string{}
				changed = true
				break
			}
		}
		if !changed {
			return // other errors: the wizard reports them
		}
	}
}

// HandleSDNGateways — GET /api/sdn/gateways: the gateway monitor's state.
func HandleSDNGateways(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, system.SDNGatewayState())
}

// HandleSDNForwardInterfaces — GET /api/sdn/forward-interfaces →
// {enabled, interfaces:[{id,name,role,color,device}]}. WAN interfaces first.
func HandleSDNForwardInterfaces(appCfg *config.AppConfig) http.HandlerFunc {
	type brief struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Role   string `json:"role"`
		Color  string `json:"color,omitempty"`
		Device string `json:"device"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		st := sdnStoreFor(appCfg)
		resp := map[string]any{"enabled": false, "interfaces": []brief{}}
		if state, _ := st.LoadState(); state.Enabled {
			if c, err := st.LoadConfirmed(); err == nil {
				list := []brief{}
				for _, wan := range []bool{true, false} {
					for _, in := range c.Interfaces {
						if (in.Role == "wan") == wan {
							list = append(list, brief{in.ID, in.Name, in.Role, in.Color, in.L3Device()})
						}
					}
				}
				resp = map[string]any{"enabled": true, "interfaces": list}
			}
		}
		jsonOK(w, resp)
	}
}

// HandleSDNRoutes — GET /api/sdn/routes: the main routing table now.
func HandleSDNRoutes(w http.ResponseWriter, r *http.Request) {
	rs, err := system.SDNRoutesLive()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{"routes": rs})
}

// HandleSDNGatewayTest — POST /api/sdn/gateways/test: pings the address a
// gateway would test, for the gateway form.
func HandleSDNGatewayTest(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Interface string `json:"interface"`
			Address   string `json:"address"`
			Target    string `json:"target"`
			Pings     int    `json:"pings"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		st := sdnStoreFor(appCfg)
		var c *sdn.Config
		if d, err := st.LoadDraft(); err == nil && d.Config != nil {
			c = d.Config
		} else if c, err = st.LoadConfirmed(); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, system.SDNTestGateway(c, body.Interface, body.Address, body.Target, body.Pings))
	}
}
