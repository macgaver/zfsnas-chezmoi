package system

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"zfsnas/internal/sdn"
)

var (
	sdnUnitPath = "/etc/systemd/system/znas-sdn.service"
	sdnRunDir   = "/run/znas-sdn"
	// sdnBootWait bounds how long boot waits for configured NICs that are
	// not there yet (drivers loaded by udev, renames) before safe mode.
	sdnBootWait = 15 * time.Second
)

const sdnUnitName = "znas-sdn.service"

// sdnUnitText is the boot unit. It runs before networking so the firewall is
// in place before any interface comes up, and it is inert until the feature
// has written a confirmed config (ConditionPathExists) — which is what lets
// the appliance image ship it enabled.
func sdnUnitText(binary, configDir string) string {
	return fmt.Sprintf(`[Unit]
Description=ZNAS SDN — load the confirmed firewall/routing state
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
After=local-fs.target systemd-modules-load.service nftables.service
ConditionPathExists=%s

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%s -config %s -sdn-boot

[Install]
WantedBy=multi-user.target
`, filepath.Join(configDir, "sdn", "config.json"), binary, configDir)
}

const sdnGWUnitName = "znas-sdn-gw.service"

func sdnGWUnitPath() string { return filepath.Join(filepath.Dir(sdnUnitPath), sdnGWUnitName) }

// sdnGWUnitText is the gateway monitor daemon (system/sdn_gwmon.go): it owns
// the default route and the per-gateway tables, independent of the portal.
func sdnGWUnitText(binary, configDir string) string {
	return fmt.Sprintf(`[Unit]
Description=ZNAS SDN — gateway monitor and failover
After=znas-sdn.service network.target
ConditionPathExists=%s

[Service]
Type=simple
ExecStart=%s -config %s -sdn-gwmon
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`, filepath.Join(configDir, "sdn", "config.json"), binary, configDir)
}

// SDNInstallUnit writes and enables the boot unit and the gateway monitor,
// and (re)starts the monitor so it runs the current binary.
func SDNInstallUnit(binary, configDir string) error {
	if err := sdnWriteFile(sdnUnitPath, []byte(sdnUnitText(binary, configDir))); err != nil {
		return err
	}
	if err := sdnWriteFile(sdnGWUnitPath(), []byte(sdnGWUnitText(binary, configDir))); err != nil {
		return err
	}
	if err := sdnWriteFile(sdnDNSUnitPath(), []byte(sdnDNSUnitText())); err != nil {
		return err
	}
	if err := sdnWriteFile(sdnDHCPUnitPath(), []byte(sdnDHCPUnitText(binary))); err != nil {
		return err
	}
	if err := sdnWriteFile(sdnIDSUnitPath(), []byte(sdnIDSUnitText())); err != nil {
		return err
	}
	if err := sdnWriteFile(sdnDDNSUnitPath(), []byte(sdnDDNSUnitText())); err != nil {
		return err
	}
	if _, err := sdnRun.Run(nil, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	// Debian's nftables.service loads /etc/nftables.conf ("flush ruleset")
	// at boot, which would wipe our table and Incus'. The feature owns the
	// firewall from now on.
	sdnRun.Run(nil, "systemctl", "disable", "nftables.service") //nolint:errcheck — absent on some hosts
	if _, err := sdnRun.Run(nil, "systemctl", "enable", sdnUnitName, sdnGWUnitName, sdnDNSUnitName, sdnDHCPUnitName, sdnIDSUnitName, sdnDDNSUnitName); err != nil {
		return err
	}
	// The DHCP supervisor restarts every network's server: only when it
	// does not run the installed binary (or does not run).
	if _, stamp := SDNDHCPStatus(); stamp == "" || stamp != sdnBinaryStamp(binary) {
		if _, err := sdnRun.Run(nil, "systemctl", "restart", sdnDHCPUnitName); err != nil {
			return err
		}
	}
	_, err := sdnRun.Run(nil, "systemctl", "restart", sdnGWUnitName)
	return err
}

// SDNRemoveUnit disables and deletes the boot unit and stops the monitor.
func SDNRemoveUnit() error {
	sdnRun.Run(nil, "systemctl", "disable", "--now", sdnGWUnitName)   //nolint:errcheck
	sdnRun.Run(nil, "systemctl", "disable", "--now", sdnDNSUnitName)  //nolint:errcheck
	sdnRun.Run(nil, "systemctl", "disable", "--now", sdnDHCPUnitName) //nolint:errcheck
	sdnRun.Run(nil, "systemctl", "disable", "--now", sdnIDSUnitName)  //nolint:errcheck
	sdnRun.Run(nil, "systemctl", "disable", "--now", sdnDDNSUnitName) //nolint:errcheck
	sdnRun.Run(nil, "systemctl", "disable", sdnUnitName)              //nolint:errcheck
	if _, err := sdnRun.Run(nil, "rm", "-f", sdnUnitPath, sdnGWUnitPath(), sdnDNSUnitPath(), sdnDHCPUnitPath(), sdnIDSUnitPath(), sdnDDNSUnitPath()); err != nil {
		return err
	}
	_, err := sdnRun.Run(nil, "systemctl", "daemon-reload")
	return err
}

// SDNSafeModeReason returns why the last boot fell back to safe mode, or "".
func SDNSafeModeReason() string {
	b, _ := os.ReadFile(filepath.Join(sdnRunDir, "safemode"))
	return strings.TrimSpace(string(b))
}

// SDNBoot is `zfsnas -sdn-boot`: reproduce the confirmed state at boot,
// without the portal. A change that was never confirmed (reboot during the
// countdown) is reverted first. If the confirmed state cannot be loaded, the
// safe-mode ruleset keeps the management interface reachable and the reason
// is written for the portal banner. Never returns an error for a
// configuration problem — boot must go on.
func SDNBoot(st sdn.Store, env sdn.Env) error {
	state, err := st.LoadState()
	if err != nil || !state.Enabled {
		return nil
	}
	_ = os.Remove(filepath.Join(sdnRunDir, "safemode"))
	if _, ok := SDNPendingRevert(st); ok {
		// Rebooted during a countdown: the change was never confirmed.
		sdnNoLinkOps = true
		err := SDNRevertPendingNow(st, env, "auto-reverted")
		sdnNoLinkOps = false
		if err == nil || SDNSafeModeReason() != "" {
			return nil
		}
		// Never fall through to config.json: it holds the unconfirmed change.
		c, _ := st.LoadConfirmed()
		return sdnSafeMode(c, env, "could not restore the previous configuration after a reboot during the confirmation countdown: "+err.Error())
	}
	c, err := st.LoadConfirmed()
	if err != nil {
		return sdnSafeMode(nil, env, "cannot read the saved firewall configuration: "+err.Error())
	}
	for deadline := time.Now().Add(sdnBootWait); len(sdnMissingDevices(c)) > 0 && time.Now().Before(deadline); {
		time.Sleep(250 * time.Millisecond)
	}
	if missing := sdnMissingDevices(c); len(missing) > 0 {
		return sdnSafeMode(c, env, "network port(s) not found: "+strings.Join(missing, ", "))
	}
	sdnSyncIncusKept(c)
	script, err := sdn.Compile(c, env)
	if err != nil {
		return sdnSafeMode(c, env, "invalid saved configuration: "+err.Error())
	}
	sdnApplySysctl(c)
	if _, err := sdnRun.Run([]byte(script), "nft", "-f", "-"); err != nil {
		return sdnSafeMode(c, env, err.Error())
	}
	// Before networking starts: ifupdown's "provider" needs the peers file
	// (the appliance's /etc/ppp is fresh at every boot).
	if err := sdnWritePPP(c); err != nil {
		log.Printf("[sdn] PPPoE files: %v", err)
	}
	// Tunnel keys (ifup's "wg setconf"), the DNS config and each network's
	// DHCP config, which their own units start after us.
	if _, _, err := sdnServiceFiles(nil, c); err != nil {
		log.Printf("[sdn] DHCP/DNS/WireGuard files: %v", err)
	}
	if _, _, err := sdnIDSFiles(c); err != nil {
		log.Printf("[sdn] intrusion detection files: %v", err)
	}
	if _, err := sdnDDNSFiles(c); err != nil {
		log.Printf("[sdn] dynamic DNS file: %v", err)
	}
	return nil
}

func sdnSafeMode(c *sdn.Config, env sdn.Env, reason string) error {
	if _, err := sdnRun.Run([]byte(sdn.SafeModeRuleset(c, env)), "nft", "-f", "-"); err != nil {
		reason += " (safe mode ruleset also failed: " + err.Error() + ")"
	}
	// The revert service runs as the portal user: /run needs sudo then.
	if err := os.MkdirAll(sdnRunDir, 0755); err != nil {
		sdnRun.Run(nil, "mkdir", "-p", sdnRunDir) //nolint:errcheck
	}
	_ = sdnWriteFile(filepath.Join(sdnRunDir, "safemode"), []byte(reason+"\n"))
	return nil
}

var ifaceDefRe = regexp.MustCompile(`(?m)^\s*iface\s+(\S+)\s`)

// sdnMissingDevices lists configured devices that cannot exist at boot:
// physical ports absent from /sys/class/net, and VLAN parents that are
// neither present nor defined (bridges) in the interfaces file. Devices
// created later by ifupdown (VLANs, bridges) are not checked.
func sdnMissingDevices(c *sdn.Config) []string {
	defined := map[string]bool{}
	if b, err := os.ReadFile(hostInterfacesPath); err == nil {
		for _, m := range ifaceDefRe.FindAllStringSubmatch(string(b), -1) {
			defined[m[1]] = true
		}
	}
	exists := func(d string) bool {
		_, err := os.Stat(filepath.Join(sdnSysClassNet, d))
		return err == nil
	}
	var missing []string
	for _, in := range c.Interfaces {
		if in.Disabled {
			continue
		}
		switch in.Kind {
		case "physical":
			if !exists(in.Device) {
				missing = append(missing, in.Device)
			}
		case "vlan", "pppoe":
			if !exists(in.Parent) && !defined[in.Parent] {
				missing = append(missing, in.Parent)
			}
		}
	}
	return missing
}

// SDNCapture records the networking as it is before the feature is enabled.
func SDNCapture() (string, map[string]string, error) {
	b, err := os.ReadFile(hostInterfacesPath)
	if err != nil {
		return "", nil, err
	}
	fwd, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return string(b), map[string]string{"net.ipv4.ip_forward": strings.TrimSpace(string(fwd))}, nil
}

// SDNRestorePreSDN undoes the feature: SDN VLANs down, our table and
// sysctl drop-in removed, ip_forward and nftables.service as captured, boot
// unit removed, state disabled. The confirmed config is kept so re-enabling
// starts from it.
//
// verbatim (the revert right after enabling) writes back the captured
// interfaces file as it was. Otherwise (Disable, possibly months later) only
// SDN's own blocks are removed and SDN's readdressing of adopted interfaces
// is undone: stanzas added since by other features survive.
func SDNRestorePreSDN(st sdn.Store, state sdn.State, verbatim bool) error {
	c, _ := st.LoadConfirmed()
	// The gateway monitor must not put its routes back while we undo them.
	sdnRun.Run(nil, "systemctl", "stop", sdnGWUnitName) //nolint:errcheck — absent is fine
	SDNReconcileVIPs(nil)                               // virtual IPs leave with the Firewall
	if cur, err := os.ReadFile(hostInterfacesPath); err == nil {
		bridged := map[string]bool{}
		if c != nil {
			for _, in := range c.Interfaces {
				if in.Owned && in.AllowVMs {
					bridged[in.Device] = true
				}
			}
		}
		devs := sdn.OwnedDevices(string(cur))
		for i := len(devs) - 1; i >= 0; i-- {
			if bridged[devs[i]] {
				sdnRun.Run(nil, "ifdown", "--force", sdn.BridgeDeviceName(devs[i])) //nolint:errcheck
			}
			sdnRun.Run(nil, "ifdown", "--force", devs[i]) //nolint:errcheck
		}
		if err := sdnWritePPP(&sdn.Config{}); err != nil {
			log.Printf("[sdn] removing PPPoE files: %v", err)
		}
		sdnRun.Run(nil, "systemctl", "stop", sdnDNSUnitName, sdnIDSUnitName) //nolint:errcheck
		sdnRun.Run(nil, "systemctl", "stop", sdnDHCPUnitName)                //nolint:errcheck
		sdnRun.Run(nil, "systemctl", "stop", sdnDDNSUnitName)                //nolint:errcheck
		if _, err := sdnDDNSFiles(&sdn.Config{}); err != nil {
			log.Printf("[sdn] removing the dynamic DNS file: %v", err)
		}
		if _, _, err := sdnServiceFiles(c, &sdn.Config{}); err != nil {
			log.Printf("[sdn] removing DHCP/DNS/WireGuard files: %v", err)
		}
		if _, _, err := sdnIDSFiles(&sdn.Config{}); err != nil {
			log.Printf("[sdn] removing intrusion detection files: %v", err)
		}
		if verbatim && state.PreSDNInterfaces != "" {
			if err := sdnWriteInterfaces(hostInterfacesPath, []byte(state.PreSDNInterfaces)); err != nil {
				return err
			}
		} else {
			if out := sdn.SpliceOwned(string(cur), nil); out != string(cur) {
				if err := sdnWriteInterfaces(hostInterfacesPath, []byte(out)); err != nil {
					return err
				}
			}
			if c != nil && state.PreSDNInterfaces != "" {
				for _, in := range c.Interfaces {
					if in.Owned {
						continue
					}
					was := parseHostBridgeConfig([]byte(state.PreSDNInterfaces), in.Device)
					now := parseHostBridgeConfig(mustRead(hostInterfacesPath), in.Device)
					if was.Exists && (was.Mode != now.Mode || was.Address != now.Address || was.Gateway != now.Gateway) {
						_ = sdnSetAddressing(HostBridgeConfig{Name: in.Device, Mode: was.Mode, Address: was.Address, Gateway: was.Gateway, DNS: was.DNS})
					} else if !was.Exists && now.Exists && now.Mode != "manual" {
						// The Firewall gave it its stanza: take the address back.
						_ = sdnSetAddressing(HostBridgeConfig{Name: in.Device, Mode: "manual"})
					}
				}
			}
		}
	}
	if c != nil {
		sdnReleaseIncusBridges(c)
		for _, in := range c.Interfaces {
			if in.Disabled && !in.Owned {
				var res SDNApplyResult
				_ = sdnReleaseLink(in, &res) // the Firewall no longer holds it down
			}
		}
	}
	sdnUndoRouting(c, state.PreSDNDefaultRoute)
	sdnRun.Run(nil, "nft", "delete", "table", "ip", sdn.TableName) //nolint:errcheck — absent is fine
	sdnRun.Run(nil, "rm", "-f", sdnSysctlPath)                     //nolint:errcheck
	if v := state.PreSDNSysctl["net.ipv4.ip_forward"]; v != "" {
		sdnRun.Run(nil, "sysctl", "-w", "net.ipv4.ip_forward="+v) //nolint:errcheck
	}
	if state.NftablesServiceEnabled {
		sdnRun.Run(nil, "systemctl", "enable", "nftables.service") //nolint:errcheck
	}
	if err := SDNRemoveUnit(); err != nil {
		return err
	}
	state.Enabled = false
	return st.SaveState(state)
}

// SDNNftablesServiceEnabled reports whether Debian's nftables.service is
// enabled (recorded at enable time; Disable turns it back on).
func SDNNftablesServiceEnabled() bool {
	out, _ := sdnRun.Run(nil, "systemctl", "is-enabled", "nftables.service")
	return strings.TrimSpace(string(out)) == "enabled"
}

// SDNPackagesInstalled reports whether the runtime tools are present.
func SDNPackagesInstalled() bool {
	return binaryPresent("nft") && binaryPresent("ifup")
}

// sdnPackageChecks lists the packages the Firewall's features use (ifupdown
// is not here: switching a server to it is the VMs & Containers setup's job).
var sdnPackageChecks = []struct {
	pkg     string
	present func() bool
}{
	{"nftables", func() bool { return binaryPresent("nft") }},
	{"conntrack", func() bool { return binaryPresent("conntrack") }}, // traffic statistics, live connections, failover
	{"dnsmasq-base", SDNDnsmasqInstalled},
	{"wireguard-tools", SDNWireGuardInstalled},
	{"suricata", SDNSuricataInstalled},
	{"ppp", SDNPPPInstalled},
	{"iputils-arping", func() bool { return binaryPresent("arping") }}, // virtual IPs: conflict probe and move announcement
	{"ddclient", SDNDDClientInstalled},                                 // dynamic DNS
}

// SDNMissingPackages returns the Firewall packages not installed yet, so
// enabling the Firewall installs them all at once (the services they back
// stay off until configured).
func SDNMissingPackages() []string {
	out := []string{}
	for _, c := range sdnPackageChecks {
		if !c.present() {
			out = append(out, c.pkg)
		}
	}
	return out
}

// SDNRefreshRuleset reloads the firewall from the confirmed config (portal
// start): a new version may compile safer rules than the ones loaded at
// boot, and so may the service files (DHCP/DNS, WireGuard keys, Suricata).
// Links are not touched. Skipped while a change waits for confirmation or
// in safe mode (the boot unit decided).
func SDNRefreshRuleset(st sdn.Store, env sdn.Env) error {
	state, err := st.LoadState()
	if err != nil || !state.Enabled {
		return nil
	}
	if _, ok := SDNPendingRevert(st); ok || SDNSafeModeReason() != "" {
		return nil
	}
	c, err := st.LoadConfirmed()
	if err != nil {
		return err
	}
	script, err := sdn.Compile(c, env)
	if err != nil {
		return err
	}
	if _, err = sdnRun.Run([]byte(script), "nft", "-f", "-"); err != nil {
		return err
	}
	// The service files too (a new version may render them differently);
	// only what changed is restarted.
	var res SDNApplyResult
	if chg, wg, err := sdnServiceFiles(nil, c); err == nil {
		sdnApplyServices(c, chg, wg, nil, &res)
	}
	if conf, thr, err := sdnIDSFiles(c); err == nil {
		sdnApplyIDS(c, conf, thr, &res)
	}
	if ch, err := sdnDDNSFiles(c); err == nil {
		sdnApplyDDNS(ch, &res)
	}
	for _, w := range res.Warnings {
		log.Printf("[sdn] %s", w)
	}
	return nil
}
