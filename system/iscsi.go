package system

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"zfsnas/internal/config"
)

// ISCSIServiceStatus describes the current state of the iSCSI daemon.
type ISCSIServiceStatus struct {
	Active bool   `json:"active"`
	Status string `json:"status"`
}

// ISCSIPrereqsInstalled returns true when targetcli is available on the system.
func ISCSIPrereqsInstalled() bool {
	return binaryInstalled("targetcli")
}

// iscsiServiceName returns the systemd service name for the iSCSI daemon.
// targetcli-fb installs "rtslib-fb-targetctl"; fall back to "targetclid" then "tgt".
func iscsiServiceName() string {
	for _, svc := range []string{"rtslib-fb-targetctl", "targetclid", "tgt"} {
		out, err := exec.Command("systemctl", "list-unit-files", "--no-legend", svc+".service").Output()
		if err == nil && strings.Contains(string(out), svc) {
			return svc
		}
	}
	return "rtslib-fb-targetctl"
}

// GetISCSIServiceStatus returns whether the iSCSI daemon is active.
func GetISCSIServiceStatus() ISCSIServiceStatus {
	svc := iscsiServiceName()
	out, err := exec.Command("systemctl", "is-active", svc).Output()
	status := strings.TrimSpace(string(out))
	if err != nil && status == "" {
		status = "unknown"
	}
	return ISCSIServiceStatus{
		Active: status == "active",
		Status: status,
	}
}

// StartISCSIService starts the iSCSI daemon.
func StartISCSIService() error {
	out, err := exec.Command("sudo", "systemctl", "start", iscsiServiceName()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// StopISCSIService stops the iSCSI daemon.
func StopISCSIService() error {
	out, err := exec.Command("sudo", "systemctl", "stop", iscsiServiceName()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// UninstallISCSI stops the iSCSI service, disables it, and removes targetcli-fb.
func UninstallISCSI() error {
	svc := iscsiServiceName()
	exec.Command("sudo", "systemctl", "stop", svc).Run()
	exec.Command("sudo", "systemctl", "disable", svc).Run()
	if out, err := exec.Command("sudo", "apt-get", "remove", "-y", "targetcli-fb").CombinedOutput(); err != nil {
		return fmt.Errorf("apt-get remove: %w: %s", err, strings.TrimSpace(string(out)))
	}
	exec.Command("sudo", "apt-get", "autoremove", "-y").Run()
	// Drop targetcli from the sticky presence cache so ISCSIPrereqsInstalled()
	// reports false without a service restart.
	ForgetBinaryPresence("targetcli")
	return nil
}

// RestartISCSIService restarts the iSCSI daemon.
func RestartISCSIService() error {
	out, err := exec.Command("sudo", "systemctl", "restart", iscsiServiceName()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// GetSystemISCSITargets returns all iSCSI target IQNs that are currently active in
// the kernel by reading the configfs hierarchy at /sys/kernel/config/target/iscsi/.
// This is the authoritative live view — it always reflects what is actually loaded,
// unlike the targetcli save file which may lag or be stale.
func GetSystemISCSITargets() []string {
	entries, err := os.ReadDir("/sys/kernel/config/target/iscsi")
	if err != nil {
		return nil
	}
	var iqns []string
	for _, e := range entries {
		// Only include directories whose names look like valid iSCSI qualifiers.
		// Other entries like "discovery_auth" are control directories, not targets.
		name := e.Name()
		if e.IsDir() && (strings.HasPrefix(name, "iqn.") || strings.HasPrefix(name, "eui.") || strings.HasPrefix(name, "naa.")) {
			iqns = append(iqns, name)
		}
	}
	return iqns
}

// GetISCSISessions returns active initiator sessions grouped by target IQN.
//
// Two session sources are checked per target:
//
//  1. ACL-based sessions: tpgt_1/acls/<initiator_iqn>/info — each ACL directory
//     has an "info" file; the initiator is actively logged in when that file
//     contains "Session State: TARG_SESS_STATE_LOGGED_IN".
//
//  2. Dynamic (open-access) sessions: tpgt_1/dynamic_sessions/ — each
//     subdirectory is an active session from an initiator that logged in without
//     a pre-configured ACL (generate_node_acls=1).
//
// Note: the kernel does NOT create a tpgt_1/sessions/ directory on this kernel
// version; the above two paths are the authoritative sources.
func GetISCSISessions() map[string][]string {
	result := make(map[string][]string)
	targets, err := os.ReadDir("/sys/kernel/config/target/iscsi")
	if err != nil {
		return result
	}
	for _, t := range targets {
		if !t.IsDir() {
			continue
		}
		name := t.Name()
		if !strings.HasPrefix(name, "iqn.") && !strings.HasPrefix(name, "eui.") && !strings.HasPrefix(name, "naa.") {
			continue
		}
		base := "/sys/kernel/config/target/iscsi/" + name + "/tpgt_1"
		var active []string

		// 1. ACL-based sessions: read each ACL's info file.
		if acls, err := os.ReadDir(base + "/acls"); err == nil {
			for _, acl := range acls {
				if !acl.IsDir() {
					continue
				}
				info, err := os.ReadFile(base + "/acls/" + acl.Name() + "/info")
				if err != nil {
					continue
				}
				if strings.Contains(string(info), "TARG_SESS_STATE_LOGGED_IN") {
					active = append(active, acl.Name())
				}
			}
		}

		// 2. Dynamic sessions (open-access targets).
		if dynSessions, err := os.ReadDir(base + "/dynamic_sessions"); err == nil {
			for _, s := range dynSessions {
				if s.IsDir() {
					active = append(active, s.Name())
				}
			}
		}

		if active == nil {
			active = []string{}
		}
		result[name] = active
	}
	return result
}

// GenerateTargetIQN returns a target IQN for a share using the configured base name.
func GenerateTargetIQN(baseName, shareID string) string {
	if len(shareID) > 8 {
		shareID = shareID[:8]
	}
	return baseName + ":" + shareID
}

// ApplyISCSIConfig performs a full teardown and rebuild of the targetcli configuration
// by piping all commands to a single targetcli session. Running everything in one
// session is more reliable than separate subprocess invocations because the fabric
// modules stay loaded and state is consistent across commands.
func ApplyISCSIConfig(cfg *config.ISCSIConfig) error {
	if !ISCSIPrereqsInstalled() {
		return fmt.Errorf("targetcli is not installed")
	}

	// Build a map of host IQNs for quick lookup.
	hostIQN := make(map[string]string, len(cfg.Hosts))
	for _, h := range cfg.Hosts {
		hostIQN[h.ID] = h.IQN
	}

	// Disable every active TPG via configfs before teardown.
	// Writing 0 to the enable file drops all active sessions for that target,
	// allowing the subsequent delete commands to succeed cleanly.
	if entries, err := os.ReadDir("/sys/kernel/config/target/iscsi"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			enablePath := "/sys/kernel/config/target/iscsi/" + e.Name() + "/tpgt_1/enable"
			_ = os.WriteFile(enablePath, []byte("0"), 0644)
		}
	}

	var script strings.Builder

	// Explicit teardown: delete each existing iSCSI target individually.
	// This is more reliable than clearconfig confirm=True, which can silently fail
	// when sessions are in progress and leave stale ACLs and config behind.
	for _, iqn := range GetSystemISCSITargets() {
		fmt.Fprintf(&script, "cd /iscsi\ndelete %s\n", iqn)
	}

	// Delete all block backstores named "share-*" (our naming convention).
	// Targets must be deleted first so backstores are no longer referenced.
	if bsEntries, err := os.ReadDir("/sys/kernel/config/target/core/iblock_0"); err == nil {
		for _, e := range bsEntries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "share-") {
				fmt.Fprintf(&script, "cd /backstores/block\ndelete %s\n", e.Name())
			}
		}
	}

	// Build a credential lookup map for CHAP application.
	credMap := make(map[string]config.ISCSICredential, len(cfg.Credentials))
	for _, c := range cfg.Credentials {
		credMap[c.ID] = c
	}

	// Rebuild each share.
	for _, share := range cfg.Shares {
		blockName := "share-" + share.ID[:8]
		devPath := "/dev/zvol/" + share.ZVol

		// Create block backstore.
		fmt.Fprintf(&script, "cd /backstores/block\ncreate name=%s dev=%s\n", blockName, devPath)

		// Create iSCSI target.
		fmt.Fprintf(&script, "cd /iscsi\ncreate %s\n", share.IQN)

		tpgPath := fmt.Sprintf("/iscsi/%s/tpg1", share.IQN)

		// Attach LUN.
		fmt.Fprintf(&script, "cd %s/luns\ncreate /backstores/block/%s\n", tpgPath, blockName)

		if len(share.HostIDs) == 0 {
			// No ACL restrictions: allow any initiator and enable writes.
			fmt.Fprintf(&script, "cd %s\nset attribute generate_node_acls=1\nset attribute demo_mode_write_protect=0\nset attribute authentication=0\n", tpgPath)
		} else {
			// Enforce ACL mode: only listed initiators may log in.
			fmt.Fprintf(&script, "cd %s\nset attribute generate_node_acls=0\nset attribute demo_mode_write_protect=0\n", tpgPath)

			// Determine whether any host has CHAP assigned so we can enable TPG authentication.
			chapEnabled := false
			for _, hid := range share.HostIDs {
				if cid, ok := share.HostCreds[hid]; ok && cid != "" {
					if _, hasCred := credMap[cid]; hasCred {
						chapEnabled = true
						break
					}
				}
			}
			if chapEnabled {
				fmt.Fprintf(&script, "cd %s\nset attribute authentication=1\n", tpgPath)
			} else {
				fmt.Fprintf(&script, "cd %s\nset attribute authentication=0\n", tpgPath)
			}

			for _, hid := range share.HostIDs {
				iqn, ok := hostIQN[hid]
				if !ok || iqn == "" {
					continue
				}
				fmt.Fprintf(&script, "cd %s/acls\ncreate %s\n", tpgPath, iqn)
				// Apply per-initiator CHAP credentials if assigned.
				if cid, ok := share.HostCreds[hid]; ok && cid != "" {
					if cred, ok := credMap[cid]; ok {
						aclPath := fmt.Sprintf("%s/acls/%s", tpgPath, iqn)
						fmt.Fprintf(&script, "cd %s\nset auth userid=%s password=%s\n", aclPath, cred.InUsername, cred.InPassword)
						if cred.Method == "bidirectional" && cred.OutUsername != "" {
							fmt.Fprintf(&script, "cd %s\nset auth mutual_userid=%s mutual_password=%s\n", aclPath, cred.OutUsername, cred.OutPassword)
						}
					}
				}
			}
		}
	}

	// Persist to disk so the service restores config on reboot.
	script.WriteString("saveconfig\n")
	script.WriteString("exit\n")

	cmd := exec.Command("sudo", "targetcli")
	cmd.Stdin = strings.NewReader(script.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("targetcli apply failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}

	return nil
}
