package main

import (
	"log"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/sdn"
	"zfsnas/system"
)

// runSDNOneShot implements -sdn-boot and -sdn-revert. It always returns 0 for
// -sdn-boot (a configuration problem must not fail the boot; SDNBoot falls
// back to safe mode and records why).
func runSDNOneShot(configDir string, boot bool, revertTarget string, revertDelay int) int {
	abs, err := filepath.Abs(configDir)
	if err != nil {
		log.Printf("[sdn] config path: %v", err)
		return 1
	}
	if err := config.Init(abs); err != nil {
		log.Printf("[sdn] config init: %v", err)
		return 1
	}
	audit.Init(abs)
	alerts.Init(abs)
	// Same paths as the portal (the Suricata config names its alert socket).
	system.SDNSetConfigDir(abs)
	env := system.SDNEnvFor(8443, false, abs)
	if appCfg, err := config.LoadAppConfig(); err == nil {
		env = system.SDNEnvFor(appCfg.Port, appCfg.BindPort443, abs)
	}
	st := sdn.Store{Dir: abs}
	if c, err := st.LoadConfirmed(); err == nil && c.Settings.StatsDir != "" {
		system.SDNSetGeoDir(system.SDNGeoDir(c.Settings.StatsDir))
	}
	if boot {
		if err := system.SDNBoot(st, env); err != nil {
			log.Printf("[sdn] boot: %v", err)
		}
		if r := system.SDNSafeModeReason(); r != "" {
			log.Printf("[sdn] SAFE MODE: %s", r)
			_ = system.SDNRecordEvent(abs, system.SDNEvent{At: time.Now(), Kind: "safe_mode", Severity: "error",
				Text: "Firewall started in safe mode (management access only, no routing): " + r})
		}
		return 0
	}
	// The countdown: the admin's "All good" stops this service (and clears
	// the marker) while we sleep.
	time.Sleep(time.Duration(revertDelay) * time.Second)
	// From here on the revert must not be interrupted half-way: take the
	// lock shared with the portal (a confirm in progress wins, then we see
	// no marker) and ignore SIGTERM from a late "systemctl stop".
	unlock, err := st.Lock()
	if err != nil {
		log.Printf("[sdn] revert lock: %v", err)
		return 1
	}
	defer unlock()
	signal.Ignore(syscall.SIGTERM)
	p, ok := system.SDNPendingRevert(st)
	if !ok || p.Target != revertTarget {
		log.Printf("[sdn] revert %s: nothing pending (already confirmed)", revertTarget)
		return 0
	}
	err = system.SDNRevertPendingNow(st, env, "auto-reverted")
	res := audit.ResultOK
	details := "not confirmed within the countdown; restored " + revertTarget
	if err != nil {
		res, details = audit.ResultError, details+": "+err.Error()
		log.Printf("[sdn] revert: %v", err)
	}
	sev := "warn"
	if err != nil {
		sev = "error"
	}
	_ = system.SDNRecordEvent(abs, system.SDNEvent{At: time.Now(), Kind: "auto_revert", Severity: sev,
		Text: "Firewall change rolled back automatically: " + details})
	audit.Log(audit.Entry{User: "system", Role: "system", Action: audit.ActionSDNAutoRevert, Target: "firewall", Result: res, Details: details})
	// This process exits right after: wait for delivery (bounded).
	if _, _, aerr := alerts.SendSync(alerts.EventFirewall, "Firewall change auto-reverted", "Firewall Auto-Revert",
		"A firewall change was not confirmed within the countdown and was rolled back. "+details, 20*time.Second); aerr != nil {
		log.Printf("[sdn] revert alert: %v", aerr)
	}
	if err != nil {
		return 1
	}
	return 0
}

// runSDNGatewayMonitor implements -sdn-gwmon (never returns on success).
func runSDNGatewayMonitor(configDir string) int {
	abs, err := filepath.Abs(configDir)
	if err != nil {
		log.Printf("[sdn-gw] config path: %v", err)
		return 1
	}
	system.SDNGatewayMonitor(sdn.Store{Dir: abs})
	return 0
}
