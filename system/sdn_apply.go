package system

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"zfsnas/internal/sdn"
)

// Paths are vars so tests can redirect them.
var (
	sdnSysctlPath  = "/etc/sysctl.d/90-znas-sdn.conf"
	sdnSysClassNet = "/sys/class/net"
)

// sdnSetAddressing edits the IPv4 addressing of an adopted interface's own
// stanza (the existing host-bridge editor works on any stanza).
var sdnSetAddressing = SetHostBridgeConfig

// sdnNoLinkOps is set while -sdn-boot reverts an unconfirmed change: before
// network-pre nothing is up yet and networking.service brings every stanza
// up right after, so only files and the ruleset may change.
var sdnNoLinkOps bool

// sdnBestEffortLinks is set while a revert runs: an interface step that
// fails (no DHCP lease in time, a VLAN that will not come up) becomes a
// warning so the target's ruleset still loads — a revert must never stop
// half-way with the unconfirmed firewall in place.
var sdnBestEffortLinks bool

// linkErr returns err, or records it as a warning in best-effort mode.
func linkErr(res *SDNApplyResult, err error) error {
	if err == nil || !sdnBestEffortLinks {
		return err
	}
	res.Warnings = append(res.Warnings, err.Error())
	return nil
}

// SDNApplyResult tells the caller what was bounced and what went wrong in a
// non-fatal way.
type SDNApplyResult struct {
	ChangedDevices []string `json:"changed_devices"`
	Warnings       []string `json:"warnings"`
}

// SDNApply moves the kernel from prev to next: interfaces first (removed
// VLANs down, file rewritten, new/changed ones up), then sysctls, then the
// firewall in one atomic nft transaction. Only interfaces whose stanza
// changed are bounced, so a rule edit never touches a link. The caller
// handles rollback (apply prev over next) on error.
func SDNApply(prev, next *sdn.Config, env sdn.Env) (SDNApplyResult, error) {
	var res SDNApplyResult
	sdnSyncIncusKept(next)
	script, err := sdn.Compile(next, env)
	if err != nil {
		return res, err
	}

	prevOwned := ownedByID(prev)
	nextOwned := ownedByID(next)
	var down, up []sdn.Interface
	for id, p := range prevOwned {
		n, ok := nextOwned[id]
		if !ok || sdn.RenderOwned(n)+sdnPPPKey(n) != sdn.RenderOwned(p)+sdnPPPKey(p) {
			down = append(down, p)
		}
	}
	for id, n := range nextOwned {
		p, ok := prevOwned[id]
		if !ok || sdn.RenderOwned(n)+sdnPPPKey(n) != sdn.RenderOwned(p)+sdnPPPKey(p) {
			up = append(up, n)
		}
	}
	sortIfaces(down)
	sortIfaces(up)

	// Adopted interfaces whose addressing changed: rewrite their own stanza
	// and bounce them (the management interface only when its address
	// itself changed — renaming it never does).
	var readdress []sdn.Interface
	for _, n := range next.Interfaces {
		if n.Owned || n.Kind == "incus" || n.Disabled {
			continue
		}
		var p *sdn.Interface
		if prev != nil {
			p = prev.InterfaceByID(n.ID)
		}
		if p != nil && (p.IPv4Mode != n.IPv4Mode || p.IPv4 != n.IPv4 || p.Gateway != n.Gateway) {
			readdress = append(readdress, n)
		} else if n.IPv4Mode != "none" && sdnStanzaDiffers(n) {
			// Newly adopted with an address it does not have yet, or its
			// stanza drifted from the configuration: the Firewall owns it.
			readdress = append(readdress, n)
		}
	}

	if sdnNoLinkOps {
		down, up = nil, nil
	}
	if err := sdnHostNetConflicts(prev, next); err != nil {
		return res, err
	}
	if conflicts := sdnVLANConflicts(prev, next, string(mustRead(hostInterfacesPath))); len(conflicts) > 0 {
		return res, fmt.Errorf("VLAN %s already exists outside the Firewall (created by VMs & Containers or by hand) — adopt its bridge instead of creating it again", strings.Join(conflicts, ", "))
	}
	for _, in := range down {
		for _, dev := range ownedDevices(in, true) {
			sdnRun.Run(nil, "ifdown", "--force", dev) //nolint:errcheck — may already be down
		}
	}
	cur, err := os.ReadFile(hostInterfacesPath)
	if err != nil {
		return res, err
	}
	if spliced := sdn.SpliceOwned(string(cur), next.Interfaces); spliced != string(cur) {
		if err := sdnWriteInterfaces(hostInterfacesPath, []byte(spliced)); err != nil {
			if err := linkErr(&res, fmt.Errorf("write interfaces: %w", err)); err != nil {
				return res, err
			}
		}
	}
	if err := sdnWritePPP(next); err != nil {
		if err := linkErr(&res, fmt.Errorf("PPPoE files: %w", err)); err != nil {
			return res, err
		}
	}
	// The portal user may not be able to list the peers folder.
	if prev != nil {
		for _, p := range prev.Interfaces {
			if p.Kind == "pppoe" && next.InterfaceByID(p.ID) == nil {
				sdnRemoveFile(filepath.Join(sdnPPPDir, "peers", sdn.PPPoEPeerName(p.ID))) //nolint:errcheck — may be gone already
			}
		}
	}
	// Before ifup: a tunnel's stanza runs "wg setconf" on its key file.
	svcChanged, wgChanged, err := sdnServiceFiles(prev, next)
	if err != nil {
		if err := linkErr(&res, fmt.Errorf("DHCP/DNS/WireGuard files: %w", err)); err != nil {
			return res, err
		}
	}
	ddnsChanged, err := sdnDDNSFiles(next)
	if err != nil {
		res.Warnings = append(res.Warnings, "dynamic DNS file: "+err.Error())
	}
	idsConfChanged, idsThrChanged, err := sdnIDSFiles(next)
	if err != nil {
		if err := linkErr(&res, fmt.Errorf("intrusion detection files: %w", err)); err != nil {
			return res, err
		}
	}
	for _, in := range readdress {
		mode := in.IPv4Mode
		if mode == "none" {
			mode = "manual"
		}
		// Keep the stanza's DNS servers: the host-bridge editor rewrites
		// dns-nameservers from what it is given.
		var dns []string
		if b, err := os.ReadFile(hostInterfacesPath); err == nil {
			cur := parseHostBridgeConfig(b, in.Device)
			dns = cur.DNS
			if !cur.Exists {
				// Adopted without a stanza of its own: add one to edit.
				stub := strings.TrimRight(string(b), "\n") + fmt.Sprintf("\n\nauto %s\niface %s inet manual\n", in.Device, in.Device)
				if err := sdnWriteInterfaces(hostInterfacesPath, []byte(stub)); err != nil {
					if err := linkErr(&res, fmt.Errorf("%s: %w", in.Name, err)); err != nil {
						return res, err
					}
					continue
				}
			}
		}
		if err := sdnSetAddressing(HostBridgeConfig{Name: in.Device, Mode: mode, Address: in.IPv4, Gateway: in.Gateway, DNS: dns}); err != nil {
			if err := linkErr(&res, fmt.Errorf("%s: %w", in.Name, err)); err != nil {
				return res, err
			}
			continue
		}
		if sdnNoLinkOps {
			continue
		}
		sdnRun.Run(nil, "ifdown", "--force", in.Device) //nolint:errcheck
		if _, err := sdnRun.Run(nil, "ifup", in.Device); err != nil {
			if err := linkErr(&res, err); err != nil {
				return res, err
			}
		}
		res.ChangedDevices = append(res.ChangedDevices, in.Device)
	}
	for _, in := range up {
		for _, dev := range ownedDevices(in, false) {
			if _, err := sdnRun.Run(nil, "ifup", dev); err != nil {
				if err := linkErr(&res, err); err != nil {
					return res, err
				}
			}
			res.ChangedDevices = append(res.ChangedDevices, dev)
		}
	}

	if !sdnNoLinkOps {
		if err := sdnApplyIncus(prev, next, &res); err != nil {
			return res, err
		}
	}
	if !sdnNoLinkOps {
		if err := sdnApplyDisabled(prev, next, &res); err != nil {
			return res, err
		}
	}
	if w := sdnApplySysctl(next); w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	if _, err := sdnRun.Run([]byte(script), "nft", "-f", "-"); err != nil {
		return res, err
	}
	broughtUp := map[string]bool{}
	for _, in := range up {
		broughtUp[in.Device] = true
	}
	if !sdnNoLinkOps {
		// after the links (an ifup above flushed the addresses it bounced)
		res.Warnings = append(res.Warnings, SDNReconcileVIPs(next)...)
		for _, err := range SDNSyncStaticRoutes(next) {
			res.Warnings = append(res.Warnings, "local route: "+err.Error())
		}
		sdnApplyServices(next, svcChanged, wgChanged, broughtUp, &res)
		sdnApplyIDS(next, idsConfChanged, idsThrChanged, &res)
		sdnApplyDDNS(ddnsChanged, &res)
	}
	// A full ruleset is loaded again: safe mode (set at boot, root-owned in
	// /run) is over.
	if SDNSafeModeReason() != "" {
		sdnRun.Run(nil, "rm", "-f", filepath.Join(sdnRunDir, "safemode")) //nolint:errcheck
	}
	return res, nil
}

func ownedByID(c *sdn.Config) map[string]sdn.Interface {
	m := map[string]sdn.Interface{}
	if c == nil {
		return m
	}
	for _, in := range c.Interfaces {
		if in.Owned && !in.Disabled {
			m[in.ID] = in
		}
	}
	return m
}

func sortIfaces(xs []sdn.Interface) {
	sort.Slice(xs, func(i, j int) bool { return xs[i].Device < xs[j].Device })
}

// ownedDevices lists the kernel devices of an owned interface in bring-up
// order (VLAN then its bridge), or bring-down order when down is true.
func ownedDevices(in sdn.Interface, down bool) []string {
	devs := []string{in.Device}
	if in.AllowVMs {
		devs = append(devs, sdn.BridgeDeviceName(in.Device))
	}
	if down {
		for i, j := 0, len(devs)-1; i < j; i, j = i+1, j-1 {
			devs[i], devs[j] = devs[j], devs[i]
		}
	}
	return devs
}

// sdnSysctlText renders the sysctl drop-in: forwarding, conntrack byte
// accounting (traffic statistics) and IPv6 off on every SDN device (the
// feature is IPv4-only; an unfiltered IPv6 address must never appear).
func sdnSysctlText(c *sdn.Config) string {
	var b strings.Builder
	b.WriteString("# Managed by ZNAS SDN — rewritten on every apply and at boot.\n")
	b.WriteString("net.ipv4.ip_forward = 1\n")
	b.WriteString("net.netfilter.nf_conntrack_acct = 1\n")
	seen := map[string]bool{}
	for _, in := range c.Interfaces {
		for _, d := range []string{in.Device, in.L3Device()} {
			if d != "" && !seen[d] {
				seen[d] = true
				fmt.Fprintf(&b, "net.ipv6.conf.%s.disable_ipv6 = 1\n", d)
			}
		}
	}
	return b.String()
}

// sdnApplySysctl writes and loads the drop-in. Failures are warnings: keys
// for devices that do not exist yet (VLANs at early boot) are expected to
// fail, and their stanzas' post-up lines cover them.
func sdnApplySysctl(c *sdn.Config) string {
	sdnRun.Run(nil, "modprobe", "nf_conntrack") //nolint:errcheck — built in on some kernels
	if err := sdnWriteFile(sdnSysctlPath, []byte(sdnSysctlText(c))); err != nil {
		return "sysctl: " + err.Error()
	}
	if _, err := sdnRun.Run(nil, "sysctl", "-e", "-p", sdnSysctlPath); err != nil {
		return "sysctl: " + err.Error()
	}
	return ""
}

// SDNEnvFor builds the compiler environment from the portal settings: the
// anti-lockout rule must cover every port the portal listens on, plus SSH.
func SDNEnvFor(port int, bindPort443 bool, configDir string) sdn.Env {
	env := sdn.Env{SSHPort: 22, CountryCIDRs: SDNCountryCIDRsFunc(configDir)}
	if port > 0 {
		env.PortalPorts = append(env.PortalPorts, port)
	} else {
		env.PortalPorts = append(env.PortalPorts, 8443)
	}
	if bindPort443 {
		env.PortalPorts = append(env.PortalPorts, 443)
	}
	return env
}

func mustRead(p string) []byte {
	b, _ := os.ReadFile(p)
	return b
}

// SDNRefreshCountryCache stores the networks of every country the config
// uses, so the boot unit can compile country rules before the pool holding
// the geo database is mounted.
func SDNRefreshCountryCache(configDir string, c *sdn.Config, env sdn.Env) {
	if env.CountryCIDRs == nil {
		return
	}
	codes := map[string]bool{}
	for _, r := range c.Rules {
		for _, e := range []sdn.Endpoint{r.Source, r.Destination} {
			switch e.Type {
			case "countries":
				for _, cc := range strings.Split(e.Value, ",") {
					codes[cc] = true
				}
			case "group":
				if g := c.GroupByID(e.Value); g != nil && g.Kind == "countries" {
					for _, cc := range g.Members {
						codes[cc] = true
					}
				}
			}
		}
	}
	m := map[string][]string{}
	for cc := range codes {
		if v, err := env.CountryCIDRs(cc); err == nil {
			m[cc] = v
		}
	}
	_ = SDNSaveCountryCache(configDir, m)
}

// sdnStanzaDiffers: the port's own stanza (if any) does not give it the
// addressing the Firewall configuration asks for.
func sdnStanzaDiffers(n sdn.Interface) bool {
	cur := parseHostBridgeConfig(mustRead(hostInterfacesPath), n.Device)
	if !cur.Exists {
		return true
	}
	mode := cur.Mode
	if mode == "manual" {
		mode = "none"
	}
	if mode != n.IPv4Mode {
		return true
	}
	return n.IPv4Mode == "static" && (cur.Address != n.IPv4 || cur.Gateway != n.Gateway)
}

// sdnApplyDisabled takes the links of newly disabled adopted interfaces down
// and releases the ones enabled again or removed from the Firewall while
// disabled. Their stanza is not ours to delete, so the gateway monitor keeps
// them down afterwards (sdnHoldDisabledDown). Owned interfaces need none of
// this: being disabled, they have no stanza and no device.
func sdnApplyDisabled(prev, next *sdn.Config, res *SDNApplyResult) error {
	was := map[string]bool{}
	if prev != nil {
		for _, p := range prev.Interfaces {
			if p.Disabled && !p.Owned {
				was[p.ID] = true
			}
		}
	}
	for _, in := range next.Interfaces {
		off := was[in.ID]
		delete(was, in.ID)
		switch {
		case in.Owned || in.Disabled == off:
		case in.Disabled:
			if in.Kind != "incus" {
				sdnRun.Run(nil, "ifdown", "--force", in.Device) //nolint:errcheck — may have no stanza
			}
			if err := linkErr(res, sdnLinkSet(in.Device, "down")); err != nil {
				return err
			}
			res.ChangedDevices = append(res.ChangedDevices, in.Device)
		default:
			if err := sdnReleaseLink(in, res); err != nil {
				return err
			}
		}
	}
	if prev != nil {
		for _, p := range prev.Interfaces {
			if was[p.ID] {
				if err := sdnReleaseLink(p, res); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func sdnLinkSet(dev, state string) error {
	_, err := sdnRun.Run(nil, "ip", "link", "set", "dev", dev, state)
	return err
}

func sdnReleaseLink(in sdn.Interface, res *SDNApplyResult) error {
	if err := linkErr(res, sdnLinkSet(in.Device, "up")); err != nil {
		return err
	}
	// ifup puts back the default route the link lost when it went down.
	if in.Kind != "incus" && parseHostBridgeConfig(mustRead(hostInterfacesPath), in.Device).Exists {
		if _, err := sdnRun.Run(nil, "ifup", in.Device); err != nil {
			if err := linkErr(res, err); err != nil {
				return err
			}
		}
	}
	res.ChangedDevices = append(res.ChangedDevices, in.Device)
	return nil
}

// sdnHoldDisabledDown puts a disabled adopted interface back down when
// something brought it up: networking at boot ("auto"), Incus.
func sdnHoldDisabledDown(c *sdn.Config) {
	for _, in := range c.Interfaces {
		if !in.Disabled || in.Owned {
			continue
		}
		b, err := os.ReadFile(filepath.Join(sdnSysClassNet, in.Device, "flags"))
		if err != nil {
			continue
		}
		if f, err := strconv.ParseInt(strings.TrimPrefix(strings.TrimSpace(string(b)), "0x"), 16, 64); err == nil && f&1 != 0 {
			log.Printf("[sdn] %s is disabled: taking its link down", in.Device)
			sdnLinkSet(in.Device, "down") //nolint:errcheck — tried again next round
		}
	}
}
