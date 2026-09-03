package system

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/config"
)

// bridgeKernelStanzaTail emits the kernel-version-dependent tail of the
// `iface vmbr0 inet static|dhcp` block — i.e. MAC pinning plus the
// bridge_ports / bridge_stp / bridge_fd lines, conditionally followed by
// VLAN-aware filtering directives.
//
// Two shapes, selected by k7 (true ⇒ kernel ≥ 7.0):
//
//   - Kernel ≤ 6.x — historical shape that ZNAS shipped before May 2026:
//     `hwaddress ether <MAC>` for MAC pinning, `bridge-vlan-aware yes` +
//     `bridge-vids 2-4094` for per-port VLAN filtering on vmbr0.
//   - Kernel ≥ 7.0 — kernel-safe shape: MAC pinning via
//     `pre-up /usr/sbin/ip link set <br> address <MAC>` (the 7.0 bridge
//     code rejects `hwaddress ether` with EADDRINUSE when the slaved
//     port already has the same MAC). VLAN-aware directives are
//     **deliberately omitted**: 7.0 has a regression in the per-port
//     `vlan_filtering` path that drops VID 1 (the default PVID, i.e.
//     untagged management traffic) the moment any explicit VID is added
//     to the slaved port — confirmed live on a test host
//     (Ubuntu 26.04 + kernel 7.0.0-15-generic, May 2026): the SSH
//     session dropped instantly when running `bridge vlan add dev
//     <nic> vid 2-4094` after enabling `vlan_filtering=1`.
//
// VLAN tagging on kernel ≥ 7.0 is still available through ZNAS'
// "Compute Networking" mode, which uses 8021q sub-interfaces (e.g.
// enp2s0f0.500) on the physical NIC with one bridge per VLAN — that
// path doesn't depend on bridge VLAN filtering and is unaffected.
//
// Pulled out of rewriteInterfacesForBridges so unit tests can pin both
// shapes without depending on the test runner's actual kernel.
func bridgeKernelStanzaTail(c bridgeCandidate, k7 bool) string {
	var b strings.Builder
	if c.MAC != "" {
		if k7 {
			// MUST be post-up, NOT pre-up: ifupdown creates the bridge during
			// the pre-up phase (the bridge_ports if-pre-up.d hook), and a
			// stanza `pre-up` runs BEFORE that hook — so `ip link set <bridge>`
			// at pre-up fails "Cannot find device", which ABORTS the whole
			// bridge bring-up and the static/DHCP IP is never applied →
			// the host disconnects (confirmed live on znas3, kernel 7.0.0-22,
			// June 2026: /etc/network/interfaces.bad). post-up runs after the
			// bridge exists AND after the IP is applied, and `|| true` makes
			// the MAC-pin non-fatal so it can NEVER take the host's network
			// down — worst case the bridge keeps its auto-assigned MAC.
			fmt.Fprintf(&b, "    post-up /usr/sbin/ip link set %s address %s || true\n", c.Bridge, c.MAC)
		} else {
			fmt.Fprintf(&b, "    hwaddress ether %s\n", c.MAC)
		}
	}
	fmt.Fprintf(&b, "    bridge_ports %s\n    bridge_stp off\n    bridge_fd 0\n", c.NIC)
	if !k7 {
		b.WriteString("    bridge-vlan-aware yes\n    bridge-vids 2-4094\n")
	}
	return b.String()
}

// kernelGTE7 returns true when the running Linux kernel's major version is
// >= 7. Used by the bridge emitter (Step 3) to pick a kernel-7.0-safe shape
// — the 7.0 cycle introduced regressions in `hwaddress ether` and per-port
// `vlan_filtering` handling that lock hosts out at boot if the older
// directives are written. Cached; the kernel doesn't change at runtime.
//
// Failure to read /proc/sys/kernel/osrelease is treated as ≤ 6.x — better
// to emit the historical config (works on every Linux ZNAS has shipped on
// before May 2026) than to silently drop MAC pinning + VLAN filtering on
// a host where they would have worked.
var (
	kernel7Once  sync.Once
	kernel7Cache bool
)

func kernelGTE7() bool {
	kernel7Once.Do(func() {
		data, err := os.ReadFile("/proc/sys/kernel/osrelease")
		if err != nil {
			return
		}
		v := strings.TrimSpace(string(data))
		// Format: "<major>.<minor>.<patch>-<rest>" — we only need major.
		dot := strings.IndexByte(v, '.')
		if dot <= 0 {
			return
		}
		maj, err := strconv.Atoi(v[:dot])
		if err != nil {
			return
		}
		if maj >= 7 {
			kernel7Cache = true
		}
	})
	return kernel7Cache
}

// lxdBinaryPath returns the absolute path to the incus daemon CLI binary
// (used by `sudo incus admin init`), checking /usr/bin (Debian) then /usr/sbin
// (Ubuntu, future-proof — Incus is currently deb-only on Debian).
func lxdBinaryPath() string {
	for _, p := range []string{"/usr/bin/incus", "/usr/sbin/incus"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "incus" // fallback to PATH
}

// LXDEnablePrereqResult is returned by LXDEnableCheckPrereqs.
//
// 6.5.6: OS is now a 2-state ✓/✗. Ubuntu 26.04+ is first-class supported
// (same install path as Debian 13: apt incus + EnsureOVMFCompat for the
// OVMF naming difference). Older Ubuntu remains a hard blocker because
// Incus packages diverge in those repos and the netplan migration step
// has only been validated on 26.04.
//
// 6.6.26: the feature is no longer gated behind --experimental, so the OS
// check is tightened to match what is actually validated: a *real* Debian
// 13+ (Proxmox VE reports ID=debian but ships a customised kernel/network
// stack and is rejected) or Ubuntu 26.04+. A new Hardware Requirements
// prerequisite (HardwareOK) hard-blocks hosts without CPU virtualization
// support or with ≤4 GB RAM.
//
// NetworkCanFix=true tells the UI to surface the "Switch to systemd
// Networking" button on the Network row — set when netplan is the only
// network configuration on the host (see netplan_migrate.go).
type LXDEnablePrereqResult struct {
	SudoAllOK     bool     `json:"sudo_all_ok"`
	SudoersOK     bool     `json:"sudoers_ok"`
	StaticIPOK    bool     `json:"static_ip_ok"`
	NetworkOK     bool     `json:"network_ok"`
	NetworkCanFix bool     `json:"network_can_fix,omitempty"`
	OSSupported   bool     `json:"os_supported"`
	HardwareOK    bool     `json:"hardware_ok"`
	HasPools      bool     `json:"has_pools"`
	AllOK         bool     `json:"all_ok"`
	SudoAllNote   string   `json:"sudo_all_note,omitempty"`
	SudoersNote   string   `json:"sudoers_note,omitempty"`
	StaticIPNote  string   `json:"static_ip_note,omitempty"`
	NetworkNote   string   `json:"network_note,omitempty"`
	OSNote        string   `json:"os_note,omitempty"`
	HardwareNote  string   `json:"hardware_note,omitempty"`
	PoolsNote     string   `json:"pools_note,omitempty"`
	ZFSPools      []string `json:"zfs_pools"`
}

// LXDEnableStepStatus tracks one step of the enablement job.
type LXDEnableStepStatus struct {
	ID     int    `json:"id"`
	Label  string `json:"label"`
	Status string `json:"status"` // "pending" | "running" | "done" | "error"
	Error  string `json:"error,omitempty"`
}

// LXDEnableJob tracks a running LXD-enable operation.
type LXDEnableJob struct {
	mu     sync.Mutex
	Status string                `json:"status"` // "running" | "done" | "error"
	Error  string                `json:"error,omitempty"`
	Steps  []LXDEnableStepStatus `json:"steps"`
	Lines  []string              `json:"lines"`
	cancel context.CancelFunc
}

func (j *LXDEnableJob) log(line string) {
	j.mu.Lock()
	j.Lines = append(j.Lines, line)
	j.mu.Unlock()
}

func (j *LXDEnableJob) setStep(id int, status, errMsg string) {
	j.mu.Lock()
	for i := range j.Steps {
		if j.Steps[i].ID == id {
			j.Steps[i].Status = status
			j.Steps[i].Error = errMsg
			break
		}
	}
	j.mu.Unlock()
}

func (j *LXDEnableJob) Cancel() {
	if j.cancel != nil {
		j.cancel()
	}
}

func (j *LXDEnableJob) Snapshot() LXDEnableJob {
	j.mu.Lock()
	defer j.mu.Unlock()
	steps := make([]LXDEnableStepStatus, len(j.Steps))
	copy(steps, j.Steps)
	lines := make([]string, len(j.Lines))
	copy(lines, j.Lines)
	return LXDEnableJob{Status: j.Status, Error: j.Error, Steps: steps, Lines: lines}
}

// LXDEnableCheckPrereqs validates all four prerequisites for enabling VMs & Containers.
func LXDEnableCheckPrereqs() LXDEnablePrereqResult {
	res := LXDEnablePrereqResult{}

	// 0. Sudo all: enabling virtualization touches many commands not covered by
	// the hardened sudoers template (incus admin init, netplan/ifupdown rewrites,
	// service control). It is therefore MANDATORY to hold unrestricted sudo while
	// enabling — the user can re-apply hardening from Requisites → Hardening once the
	// feature is on. A "Switch to sudo all" button is offered on the row.
	sudo := CheckSudoAccess()
	if sudo.Type == "all" || sudo.Type == "root" {
		res.SudoAllOK = true
	} else {
		res.SudoAllNote = "Hardened sudoers detected. Enabling virtualization requires full passwordless sudo — click \"Switch to sudo all\". You can re-apply hardening afterwards from Requisites → Hardening."
	}

	// 1. Sudoers: can we run apt-get? (root, all, or hardened with ZFSNAS_APT)
	switch sudo.Type {
	case "root", "all":
		res.SudoersOK = true
	case "hardened":
		// Check that ZFSNAS_APT (apt-get *) is present
		missing := false
		for _, m := range sudo.MissingCommands {
			if strings.Contains(m, "apt-get") {
				missing = true
				break
			}
		}
		if missing {
			res.SudoersNote = "Hardened sudoers is missing apt-get commands (ZFSNAS_APT). Apply the full sudoers template from the Requisites → Hardening tab first."
		} else {
			res.SudoersOK = true
		}
	default:
		res.SudoersNote = "No sudo access detected. The service account needs passwordless sudo to install packages."
	}

	// 2. Network: /etc/network/interfaces exists and netplan is not the
	// authoritative network manager. When netplan is the *only* config
	// (Ubuntu default), the user can click "Switch to systemd Networking"
	// — NetworkCanFix=true tells the UI to show that button.
	//
	// Mixed state (both /etc/network/interfaces and /etc/netplan/*.yaml
	// present) is OK as long as systemd-networkd is inactive — netplan
	// only takes effect through networkd, and many migrated hosts still
	// have the dormant YAMLs sitting in /etc/netplan/. Hard-failing in
	// that case sends users in circles after a successful migration +
	// uninstall + re-enable cycle.
	_, ifupErr := os.Stat("/etc/network/interfaces")
	netplanFiles, _ := filepath.Glob("/etc/netplan/*.yaml")
	hasIfupdown := ifupErr == nil
	hasNetplan := len(netplanFiles) > 0
	netplanActive := hasNetplan && systemdNetworkdActive()
	switch {
	case hasIfupdown && !hasNetplan:
		res.NetworkOK = true
	case hasIfupdown && hasNetplan && !netplanActive:
		// Dormant netplan YAMLs alongside an authoritative ifupdown setup
		// — accept and just inform the user.
		res.NetworkOK = true
		res.NetworkNote = "Netplan YAML files exist in /etc/netplan/ but systemd-networkd is inactive — ifupdown is authoritative."
	case hasIfupdown && hasNetplan:
		// systemd-networkd is actually running — both configs would compete.
		res.NetworkNote = "Both /etc/network/interfaces and /etc/netplan/*.yaml present and systemd-networkd is active. This feature requires only ifupdown — disable systemd-networkd or remove the netplan files."
	case !hasIfupdown && hasNetplan:
		res.NetworkNote = "Netplan configuration detected (/etc/netplan/*.yaml). This feature requires ifupdown — click \"Switch to systemd Networking\" on the right to migrate."
		res.NetworkCanFix = true
	case systemdNetworkdActive():
		// Raw systemd-networkd (no netplan, no ifupdown) — the stock Debian
		// default. The migration handles this case too, so offer the same
		// "Switch to systemd Networking" button.
		res.NetworkNote = "systemd-networkd manages the network directly. This feature requires ifupdown — click \"Switch to systemd Networking\" to migrate."
		res.NetworkCanFix = true
	default:
		res.NetworkNote = "/etc/network/interfaces not found. This feature requires the ifupdown networking system."
	}

	// 3. OS is a *real* Debian 13+, or Ubuntu ≥ 26.04 (both first-class
	// supported). Proxmox VE reports ID=debian in /etc/os-release but ships a
	// customised kernel and network stack that the Incus install + netplan
	// migration have not been validated against — it is detected and rejected.
	osRelease := readOSRelease()
	id := osRelease["ID"]
	switch {
	case isProxmoxHost():
		res.OSNote = "Proxmox VE detected. This feature requires a standard Debian 13+ or Ubuntu 26.04+ host — Proxmox's customised kernel and network stack are not supported."
	case strings.EqualFold(id, "debian") && debianVersionAtLeast(osRelease["VERSION_ID"], 13):
		// Debian 13 (trixie) and newer. Debian testing/sid carry no
		// VERSION_ID — debianVersionAtLeast treats that as a newer rolling
		// release and allows it (see helper).
		res.OSSupported = true
	case strings.EqualFold(id, "ubuntu") && ubuntuVersionAtLeast(osRelease["VERSION_ID"], 26, 4):
		// Ubuntu 26.04+ uses the same Incus install path as Debian
		// (apt install incus + EnsureOVMFCompat for the OVMF naming
		// difference). Older Ubuntu stays blocked: their Incus packages
		// are too divergent and the netplan migration step has only been
		// validated on 26.04.
		res.OSSupported = true
	default:
		name := osRelease["PRETTY_NAME"]
		if name == "" {
			name = osRelease["NAME"]
		}
		if name == "" {
			name = osRelease["ID"]
		}
		if name == "" {
			name = "unknown OS"
		}
		res.OSNote = fmt.Sprintf("Detected: %s. This feature requires Debian 13+ (non-Proxmox) or Ubuntu 26.04+.", name)
	}

	// 3b. Hardware Requirements: the host CPU must support hardware
	// virtualization (VT-x / AMD-V) and have more than 4 GB of RAM. Both are
	// hard blockers — without VT-x/AMD-V QEMU/KVM cannot run accelerated VMs,
	// and ≤4 GB leaves no headroom once the host, ZFS ARC and a guest are
	// accounted for. (v6.6.26.)
	cpuOK := hostVirtSupport()
	ram := GetHardwareInfo().TotalRAMBytes
	ramOK := ram > minVirtRAMBytes
	switch {
	case cpuOK && ramOK:
		res.HardwareOK = true
	case !cpuOK && !ramOK:
		res.HardwareNote = fmt.Sprintf("CPU virtualization (VT-x/AMD-V) is unavailable and only %.1f GB RAM detected (more than 4 GB required).", float64(ram)/1e9)
	case !cpuOK:
		res.HardwareNote = "CPU virtualization (VT-x/AMD-V) is not available — enable it in the BIOS/UEFI, or run on hardware that supports it."
	default:
		res.HardwareNote = fmt.Sprintf("Only %.1f GB RAM detected. VMs & Containers require more than 4 GB.", float64(ram)/1e9)
	}

	// 4. At least one ZFS pool
	pools, err := GetAllPools()
	if err == nil && len(pools) > 0 {
		res.HasPools = true
		for _, p := range pools {
			res.ZFSPools = append(res.ZFSPools, p.Name)
		}
	} else {
		res.PoolsNote = "No ZFS storage pools found. Create a pool first before enabling VMs & Containers."
	}

	// 5. Static IP: a DHCP-assigned primary interface causes the host to change
	// IP during the netplan→ifupdown migration and again when vmbr0 is created
	// (the bridge presents a different DHCP identity). Requiring a static address
	// up front — keeping the IP the host already has — sidesteps the churn
	// entirely. Detection is renderer-agnostic: the live `ip -j addr` "dynamic"
	// flag tells us whether the address came from DHCP.
	if snap, err := primaryNetSnapshot(); err == nil && snap != nil {
		if snap.IsDHCP {
			res.StaticIPNote = "Primary interface " + snap.Name + " uses a DHCP address. A static IP is required before enabling virtualization — click \"Configure Static IP\"."
		} else {
			res.StaticIPOK = true
		}
	} else {
		// Could not determine the primary interface — don't hard-block on a
		// detection gap, but surface a note so the user knows it was skipped.
		res.StaticIPOK = true
		res.StaticIPNote = "Could not determine the primary network interface; static-IP check skipped."
	}

	res.AllOK = res.SudoAllOK && res.SudoersOK && res.StaticIPOK &&
		res.NetworkOK && res.OSSupported && res.HardwareOK && res.HasPools
	return res
}

// primaryNetSnapshot returns the live snapshot of the host's primary management
// interface — the ether device carrying the default route with a global IPv4.
// Used by the static-IP prerequisite to detect DHCP and to pre-fill the
// "Configure Static IP" popup.
func primaryNetSnapshot() (*liveDeviceSnapshot, error) {
	addrOut, err := exec.Command("ip", "-j", "addr").Output()
	if err != nil {
		return nil, fmt.Errorf("ip -j addr: %w", err)
	}
	var ifaces []ipAddrLite
	if err := json.Unmarshal(addrOut, &ifaces); err != nil {
		return nil, fmt.Errorf("parse ip addr: %w", err)
	}
	// Collect ether devices that carry a global IPv4 and are not enslaved to a
	// bridge/bond (master set) — those are the management-NIC candidates.
	var names []string
	for _, ifc := range ifaces {
		if ifc.LinkType != "ether" || ifc.Master != "" {
			continue
		}
		for _, a := range ifc.AddrInfo {
			if a.Family == "inet" && a.Scope == "global" {
				names = append(names, ifc.IfName)
				break
			}
		}
	}
	snaps, err := snapshotLiveNet(names)
	if err != nil {
		return nil, err
	}
	// Prefer the device that owns the default route; fall back to the first
	// device with an IPv4 address.
	var fallback *liveDeviceSnapshot
	for i := range snaps {
		s := &snaps[i]
		if s.IPv4 == "" {
			continue
		}
		if s.Gateway != "" {
			return s, nil
		}
		if fallback == nil {
			fallback = s
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, fmt.Errorf("no primary IPv4 interface found")
}

// EnableNetConfig is the pre-fill payload for the "Configure Static IP" popup:
// the primary interface plus its current (DHCP-assigned) address/gateway/DNS,
// so the user can simply confirm the same values to reserve them statically.
type EnableNetConfig struct {
	Iface   string   `json:"iface"`
	Address string   `json:"address"` // CIDR, e.g. "192.168.2.20/24"
	Gateway string   `json:"gateway"`
	DNS     []string `json:"dns"`
	IsDHCP  bool     `json:"is_dhcp"`
}

// GetEnableNetConfig returns the live primary-interface config for the popup.
func GetEnableNetConfig() (*EnableNetConfig, error) {
	snap, err := primaryNetSnapshot()
	if err != nil {
		return nil, err
	}
	return &EnableNetConfig{
		Iface:   snap.Name,
		Address: snap.IPv4,
		Gateway: snap.Gateway,
		DNS:     snap.DNS,
		IsDHCP:  snap.IsDHCP,
	}, nil
}

// netplanIsAuthoritative reports whether netplan (via systemd-networkd) is the
// host's live network manager — the case on a fresh Ubuntu install. When true,
// the static-IP apply writes a netplan drop-in; otherwise it edits
// /etc/network/interfaces (ifupdown).
func netplanIsAuthoritative() bool {
	files, _ := filepath.Glob("/etc/netplan/*.yaml")
	return len(files) > 0 && systemdNetworkdActive()
}

// SetEnableStaticIP reconfigures the host's primary interface to a static
// address in whatever renderer is currently authoritative, then applies it.
// After this the interface's address is no longer DHCP-dynamic, so the
// netplan→ifupdown migration and the vmbr0 bridge inherit a stable address —
// removing the DHCP IP churn behind v6.6.9 issues #13 and #14. Keeping the same
// IP the host already has means the apply does not drop the session.
func SetEnableStaticIP(iface, addrCIDR, gateway string, dns []string) error {
	iface = strings.TrimSpace(iface)
	addrCIDR = strings.TrimSpace(addrCIDR)
	gateway = strings.TrimSpace(gateway)
	if iface == "" || addrCIDR == "" {
		return fmt.Errorf("interface and address are required")
	}
	if _, _, err := net.ParseCIDR(addrCIDR); err != nil {
		return fmt.Errorf("address must be CIDR (e.g. 192.168.2.20/24): %w", err)
	}
	if gateway != "" && net.ParseIP(gateway) == nil {
		return fmt.Errorf("invalid gateway %q", gateway)
	}
	var cleanDNS []string
	for _, d := range dns {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if net.ParseIP(d) == nil {
			return fmt.Errorf("invalid DNS server %q", d)
		}
		cleanDNS = append(cleanDNS, d)
	}

	if netplanIsAuthoritative() {
		return writeNetplanStaticAndApply(iface, addrCIDR, gateway, cleanDNS)
	}
	// Raw systemd-networkd (no netplan, no /etc/network/interfaces) — the stock
	// Debian default. Writing the ifupdown file here fails because /etc/network/
	// doesn't even exist yet ("open /etc/network/interfaces: no such file or
	// directory"); instead pin the address in a systemd-networkd .network file.
	// (v6.6.26.)
	if _, err := os.Stat("/etc/network/interfaces"); err != nil && systemdNetworkdActive() {
		return writeNetworkdStaticAndApply(iface, addrCIDR, gateway, cleanDNS)
	}
	return writeIfupdownStaticAndApply(iface, addrCIDR, gateway, cleanDNS)
}

// writeNetworkdStaticAndApply pins the interface to a static address via a
// systemd-networkd .network file and reconfigures the link. Used on hosts that
// run raw systemd-networkd (no netplan, no ifupdown) — the common stock-Debian
// case. The numeric "10-" prefix sorts the file ahead of the distro's default
// "<iface>.network" so networkd picks it (only the first matching file applies).
// Keeping the same address the host already holds means the link does not drop.
func writeNetworkdStaticAndApply(iface, addrCIDR, gateway string, dns []string) error {
	var b strings.Builder
	b.WriteString("# Written by ZNAS — static IP for " + iface + " (set before enabling virtualization).\n")
	b.WriteString("[Match]\nName=" + iface + "\n\n[Network]\nDHCP=no\n")
	b.WriteString("Address=" + addrCIDR + "\n")
	if gateway != "" {
		b.WriteString("Gateway=" + gateway + "\n")
	}
	for _, d := range dns {
		b.WriteString("DNS=" + d + "\n")
	}
	path := "/etc/systemd/network/10-znas-static-" + iface + ".network"
	if err := writeInterfacesFile(path, []byte(b.String())); err != nil {
		return fmt.Errorf("write networkd config: %w", err)
	}
	// Reload unit files, then reconfigure just this link so the static address
	// takes effect without a full networkd restart.
	exec.Command("sudo", "networkctl", "reload").Run() //nolint:errcheck
	if out, err := exec.Command("sudo", "networkctl", "reconfigure", iface).CombinedOutput(); err != nil {
		return fmt.Errorf("networkctl reconfigure %s: %s: %w", iface, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// writeNetplanStaticAndApply drops a high-priority netplan file pinning the
// interface to a static address (overriding the installer's dhcp4: true for the
// same device) and runs `netplan apply`.
func writeNetplanStaticAndApply(iface, addrCIDR, gateway string, dns []string) error {
	var y strings.Builder
	y.WriteString("# Written by ZNAS — static IP for " + iface + " (set before enabling virtualization).\n")
	y.WriteString("network:\n  version: 2\n  renderer: networkd\n  ethernets:\n")
	y.WriteString("    " + iface + ":\n")
	y.WriteString("      dhcp4: false\n      dhcp6: false\n")
	y.WriteString("      addresses:\n        - " + addrCIDR + "\n")
	if gateway != "" {
		y.WriteString("      routes:\n        - to: default\n          via: " + gateway + "\n")
	}
	if len(dns) > 0 {
		y.WriteString("      nameservers:\n        addresses:\n")
		for _, d := range dns {
			y.WriteString("          - " + d + "\n")
		}
	}
	const path = "/etc/netplan/90-znas-static.yaml"
	if err := writeInterfacesFile(path, []byte(y.String())); err != nil {
		return fmt.Errorf("write netplan: %w", err)
	}
	// netplan ≥ 24.04 refuses to apply a world-readable config.
	exec.Command("sudo", "chmod", "600", path).Run() //nolint:errcheck
	if out, err := exec.Command("sudo", "netplan", "apply").CombinedOutput(); err != nil {
		return fmt.Errorf("netplan apply: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// writeIfupdownStaticAndApply rewrites the interface's stanza in
// /etc/network/interfaces to a static configuration and restarts networking.
func writeIfupdownStaticAndApply(iface, addrCIDR, gateway string, dns []string) error {
	const path = "/etc/network/interfaces"
	existing, _ := readPossiblyRoot(path)
	updated := rewriteIfaceStanzaStatic(string(existing), iface, addrCIDR, gateway, dns)
	if err := writeInterfacesFile(path, []byte(updated)); err != nil {
		return fmt.Errorf("write interfaces: %w", err)
	}
	if out, err := exec.Command("sudo", "systemctl", "restart", "networking").CombinedOutput(); err != nil {
		return fmt.Errorf("restart networking: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// rewriteIfaceStanzaStatic replaces (or appends) the `iface <name> inet ...`
// stanza in an /etc/network/interfaces file with a static configuration,
// preserving every other stanza. The matched stanza's indented option lines are
// dropped and replaced with ours; the `auto <name>` line is ensured.
func rewriteIfaceStanzaStatic(content, iface, addrCIDR, gateway string, dns []string) string {
	var block strings.Builder
	block.WriteString("auto " + iface + "\n")
	block.WriteString("iface " + iface + " inet static\n")
	block.WriteString("    address " + addrCIDR + "\n")
	if gateway != "" {
		block.WriteString("    gateway " + gateway + "\n")
	}
	if len(dns) > 0 {
		block.WriteString("    dns-nameservers " + strings.Join(dns, " ") + "\n")
	}

	ifaceRe := regexp.MustCompile(`^\s*iface\s+` + regexp.QuoteMeta(iface) + `\s+inet\s+\w+`)
	autoRe := regexp.MustCompile(`^\s*auto\s+` + regexp.QuoteMeta(iface) + `\s*$`)
	var out []string
	replaced := false
	lines := strings.Split(content, "\n")
	for i := 0; i < len(lines); i++ {
		ln := lines[i]
		if autoRe.MatchString(ln) {
			continue // our block re-adds the auto line
		}
		if ifaceRe.MatchString(ln) {
			if !replaced {
				out = append(out, strings.TrimRight(block.String(), "\n"))
				replaced = true
			}
			// Skip this iface line and its indented option lines.
			for i+1 < len(lines) {
				nxt := lines[i+1]
				if nxt == "" || (len(nxt) > 0 && (nxt[0] == ' ' || nxt[0] == '\t')) {
					i++
					continue
				}
				break
			}
			continue
		}
		out = append(out, ln)
	}
	res := strings.Join(out, "\n")
	if !replaced {
		if res != "" && !strings.HasSuffix(res, "\n") {
			res += "\n"
		}
		res += "\n" + block.String()
	}
	return res
}

// ScheduleServiceRestartForIncus restarts the zfsnas service shortly after
// virtualization is enabled, so a fresh systemd start re-runs initgroups and the
// non-root service account picks up its new `incus-admin` group membership.
// Without this the running process keeps its stale supplementary groups and
// every direct `incus` call fails until a manual restart (v6.6.9 issue #15).
// No-op when running as root (root already reaches the daemon).
func ScheduleServiceRestartForIncus() {
	if os.Getuid() == 0 {
		return
	}
	go func() {
		// Give the enable modal a moment to render the "done" state before the
		// portal drops for its restart.
		time.Sleep(3 * time.Second)
		exec.Command("sudo", "systemctl", "restart", "zfsnas").Run() //nolint:errcheck
	}()
}

// systemdNetworkdActive returns true when systemd-networkd is currently
// running and managing the network. Used to distinguish "active netplan"
// (which would compete with ifupdown) from "dormant netplan YAMLs left
// behind after a migration" (harmless).
func systemdNetworkdActive() bool {
	out, err := exec.Command("/usr/bin/systemctl", "is-active", "systemd-networkd").Output()
	if err != nil {
		// is-active returns non-zero for inactive/failed/dead — treat
		// every error as "not active" rather than blocking the user.
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}

// ubuntuVersionAtLeast parses a VERSION_ID like "26.04" / "24.10" and reports
// whether it is ≥ minMajor.minMinor. Returns false on any parse failure so a
// malformed /etc/os-release defaults to the conservative "block" behaviour.
func ubuntuVersionAtLeast(versionID string, minMajor, minMinor int) bool {
	parts := strings.SplitN(versionID, ".", 2)
	if len(parts) == 0 {
		return false
	}
	major, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return false
	}
	if major > minMajor {
		return true
	}
	if major < minMajor {
		return false
	}
	if len(parts) < 2 {
		return false
	}
	minor, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return false
	}
	return minor >= minMinor
}

// minVirtRAMBytes is the RAM floor for the Hardware Requirements prerequisite.
// "More than 4 GB" is expressed in decimal GB (4×10⁹) so a host with 4 GiB of
// physical RAM (MemTotal ≈ 4.0–4.1×10⁹ after kernel reservation) passes, while a
// box with 4 GB or less fails. (v6.6.26.)
const minVirtRAMBytes uint64 = 4 * 1000 * 1000 * 1000

// debianVersionAtLeast parses a Debian VERSION_ID like "13" / "12" and reports
// whether its major number is ≥ minMajor. Debian testing/sid carry NO VERSION_ID
// in /etc/os-release (they are rolling releases newer than the last stable), so
// an empty/unparseable value is treated as "newer than any released stable" and
// allowed. Returns false only for a parseable version below the floor.
func debianVersionAtLeast(versionID string, minMajor int) bool {
	versionID = strings.TrimSpace(versionID)
	if versionID == "" {
		return true // testing/sid — newer rolling release
	}
	parts := strings.SplitN(versionID, ".", 2)
	major, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return true // unparseable on a Debian host ⇒ assume newer/rolling
	}
	return major >= minMajor
}

// isProxmoxHost reports whether the running host is Proxmox VE. Proxmox is
// Debian-based and reports ID=debian in /etc/os-release, so it must be detected
// out-of-band: the /etc/pve cluster filesystem, the pveversion CLI, or the
// proxmox-ve meta-package. Any one is sufficient.
func isProxmoxHost() bool {
	if _, err := os.Stat("/etc/pve"); err == nil {
		return true
	}
	if _, err := os.Stat("/usr/bin/pveversion"); err == nil {
		return true
	}
	if installed, _ := packageInfo("proxmox-ve"); installed {
		return true
	}
	return false
}

// hostVirtSupport reports whether the host CPU supports hardware virtualization
// AND the KVM device node is present. It requires both: a vmx (Intel) or svm
// (AMD) flag in /proc/cpuinfo proves the CPU is capable, and /dev/kvm proves the
// kernel exposes KVM (the flag can be present while VT is disabled in BIOS, in
// which case /dev/kvm is absent). (v6.6.26.)
func hostVirtSupport() bool {
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return false
	}
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "flags") && !strings.HasPrefix(line, "Features") {
			continue
		}
		// Match whole-word vmx/svm to avoid false positives in longer tokens.
		for _, fl := range strings.Fields(line) {
			if fl == "vmx" || fl == "svm" {
				return true
			}
		}
	}
	return false
}

func readOSRelease() map[string]string {
	m := map[string]string{}
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return m
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		k := line[:idx]
		v := strings.Trim(line[idx+1:], `"'`)
		m[k] = v
	}
	return m
}

// NewLXDEnableJob creates a fresh job with the four steps pre-populated.
func NewLXDEnableJob(cancel context.CancelFunc) *LXDEnableJob {
	return &LXDEnableJob{
		Status: "running",
		cancel: cancel,
		Steps: []LXDEnableStepStatus{
			{ID: 1, Label: "Install Incus and QEMU packages", Status: "pending"},
			{ID: 2, Label: "Initialise Incus", Status: "pending"},
			{ID: 3, Label: "Configure physical NIC bridges", Status: "pending"},
			{ID: 4, Label: "Install chrony (time synchronisation)", Status: "pending"},
			{ID: 5, Label: "Enable memory compression (zram, Balanced profile)", Status: "pending"},
			{ID: 6, Label: "Enable VMs & Container metrics listener", Status: "pending"},
		},
	}
}

// LXDEnableFeature runs all four enablement steps and updates job state throughout.
// It is designed to be called in a goroutine.
func LXDEnableFeature(ctx context.Context, storagePool string, job *LXDEnableJob) {
	done := func(err error) {
		job.mu.Lock()
		if err != nil {
			job.Status = "error"
			job.Error = err.Error()
		} else {
			job.Status = "done"
		}
		job.mu.Unlock()
	}

	// Step 1 — Install packages
	if err := lxdStep1Packages(ctx, job); err != nil {
		done(err)
		return
	}

	// Step 2 — Initialise LXD
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "znas"
	}
	if err := lxdStep2Init(ctx, storagePool, hostname, job); err != nil {
		done(err)
		return
	}

	// Step 3 — Configure NIC bridges
	// One NAT network per physical link-up NIC (host-nat, host-nat2, …),
	// created alongside the vmbrN LAN bridges so both options exist for guests.
	lxdEnsureHostNatNetworks(ctx, job)
	if err := lxdStep3Bridges(ctx, job); err != nil {
		done(err)
		return
	}

	// Step 4 — Chrony
	if err := lxdStep4Chrony(ctx, job); err != nil {
		done(err)
		return
	}

	// Step 5 — Memory compression (best-effort polish, never fails the job)
	lxdStep5MemComp(ctx, job)

	// Step 6 — VM/Container metrics listener (best-effort polish)
	lxdStep6Metrics(ctx, job)

	done(nil)
}

// runCmdLog runs a sudo command, streaming each output line into job.
// writeInterfacesFile writes data to path, using direct file I/O when running
// as root and "sudo tee" otherwise. The hardened sudoers template grants no
// dedicated entry for /etc/network/interfaces, so this only succeeds when the
// process is root or has unrestricted sudo (NOPASSWD: ALL).
func writeInterfacesFile(path string, data []byte) error {
	// A `bridge_ports` / `bridge-vlan-aware` stanza is inert at boot without
	// bridge-utils, whose /etc/network/if-pre-up.d/bridge hook is what actually
	// creates the bridge — a bridge that was created live via iproute2 (no
	// bridge-utils needed) can't be recreated by ifupdown at the next boot, so
	// networking.service dies with "Cannot find device <bridge>" and the host
	// comes up with no network (observed on a fresh Debian 13). bridge-utils is
	// in the virt-enable package set, but the bridge write and that install are
	// separate steps with no ordering guarantee, so we make them atomic here:
	// every bridge/VLAN write ensures its ifupdown helper package first. Same
	// story for `vlan-raw-device` and the `vlan` package. Idempotent.
	ensureIfupdownHelperPkgs(string(data))
	if os.Getuid() == 0 {
		return os.WriteFile(path, data, 0644)
	}
	cmd := exec.Command("sudo", "/usr/bin/tee", path)
	cmd.Stdin = strings.NewReader(string(data))
	cmd.Stdout = nil
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ensureIfupdownHelperPkgs installs the ifupdown helper packages a bridge or
// VLAN stanza needs to come up at boot, if the config being written uses them
// and they are missing. Best-effort: apt-get is granted via ZFSNAS_APT so this
// works on hardened hosts, but a transient failure (apt lock, offline mirror)
// is non-fatal — the caller still writes the file and the daemon logs surface
// any later `ifup` failure. Called from writeInterfacesFile so no bridge/VLAN
// write can outrun its dependency.
func ensureIfupdownHelperPkgs(content string) {
	var need []string
	for _, pkg := range ifupdownHelperPkgsFor(content) {
		if !pkgInstalled(pkg) {
			need = append(need, pkg)
		}
	}
	if len(need) == 0 {
		return
	}
	exec.Command("sudo", append([]string{"/usr/bin/apt-get", "install", "-y"}, need...)...).Run() //nolint:errcheck
}

// ifupdownHelperPkgsFor returns the ifupdown helper packages an interfaces
// stanza needs to come up at boot: bridge-utils for a bridge stanza
// (bridge_ports / bridge-vlan-aware), vlan for an 802.1q sub-interface
// (vlan-raw-device). Pure — separated from the apt side effect so it's unit
// testable.
func ifupdownHelperPkgsFor(content string) []string {
	var pkgs []string
	if strings.Contains(content, "bridge_ports") || strings.Contains(content, "bridge-vlan-aware") {
		pkgs = append(pkgs, "bridge-utils")
	}
	if strings.Contains(content, "vlan-raw-device") {
		pkgs = append(pkgs, "vlan")
	}
	return pkgs
}

func runCmdLog(ctx context.Context, job *LXDEnableJob, name string, args ...string) error {
	full := append([]string{"sudo"}, append([]string{name}, args...)...)
	job.log("$ " + strings.Join(full, " "))
	cmd := exec.CommandContext(ctx, "sudo", append([]string{name}, args...)...)
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		pw.Close()
		pr.Close()
		return err
	}
	pw.Close()
	scanner := bufio.NewScanner(pr)
	for scanner.Scan() {
		job.log(scanner.Text())
	}
	pr.Close()
	return cmd.Wait()
}

// ── Step 1: packages ──────────────────────────────────────────────────────────

func lxdStep1Packages(ctx context.Context, job *LXDEnableJob) error {
	job.setStep(1, "running", "")
	pkgs := []string{
		// Incus 6.0+ ships in Debian 13 main. The five sub-packages cover
		// daemon (incus-base + incus), client (incus-client), the in-VM
		// agent (incus-agent), and the integration tooling (incus-extra).
		"incus", "incus-base", "incus-client", "incus-extra", "incus-agent",
		"bridge-utils",
		// qemu-system-x86 is the actual binary (same on Debian and Ubuntu).
		// We deliberately do NOT pull `qemu-kvm`: on Debian 13 it's a
		// transition metapackage that just depends on qemu-system-x86, but
		// on Ubuntu (24.04+) it became a virtual package with multiple
		// providers (qemu-system-x86 vs qemu-system-x86-hwe), and apt
		// refuses to auto-resolve, breaking the install with
		// `E: Package 'qemu-kvm' has no installation candidate`.
		"qemu-system-x86",
		"dnsmasq-base",
		"swtpm",       // required for VMs with virtual TPM devices
		"ovmf",        // UEFI firmware for x86 VMs (OVMF_CODE.4MB.fd)
		"sshpass",     // required for InterLink push operations
		"genisoimage", // mkisofs implementation Incus uses to build the
		// agent:config ISO on the fly when an image declares
		// image.requirements.cdrom_agent=true (AlmaLinux 10,
		// Rocky, CentOS Stream, RHEL-family in general).
		// Without this, those VMs fail to start with
		// "Neither mkisofs nor genisoimage could be found".
		"sanoid", // provides /usr/sbin/syncoid — ZFS-aware incremental snapshot
		// streaming used by the per-VM/Container Backups feature. Installed with
		// the feature so the "Backups" button works out of the box instead of
		// needing a separate trip to Requisites → ZFS Replication.
	}
	job.log("Running apt-get update…")
	if err := runCmdLog(ctx, job, "/usr/bin/apt-get", "update"); err != nil {
		job.setStep(1, "error", "apt-get update failed: "+err.Error())
		return fmt.Errorf("apt-get update: %w", err)
	}
	job.log("Installing packages: " + strings.Join(pkgs, " "))
	args := append([]string{"install", "-y"}, pkgs...)
	if err := runCmdLog(ctx, job, "/usr/bin/apt-get", args...); err != nil {
		job.setStep(1, "error", "package install failed: "+err.Error())
		return fmt.Errorf("apt-get install: %w", err)
	}

	// Create cross-distro OVMF symlinks (Ubuntu ↔ Debian naming difference).
	job.log("Creating OVMF firmware compatibility symlinks…")
	EnsureOVMFCompat()

	job.setStep(1, "done", "")
	return nil
}

// EnsureOVMFCompat creates bidirectional symlinks between Ubuntu and Debian
// OVMF firmware file names so VMs can start on either distro after a push.
//
//	Ubuntu: /usr/share/OVMF/OVMF_CODE.4MB.fd
//	Debian: /usr/share/OVMF/OVMF_CODE_4M.fd
func EnsureOVMFCompat() {
	pairs := [][2]string{
		{"/usr/share/OVMF/OVMF_CODE.4MB.fd", "/usr/share/OVMF/OVMF_CODE_4M.fd"},
		{"/usr/share/OVMF/OVMF_VARS.4MB.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"},
	}
	for _, p := range pairs {
		a, b := p[0], p[1]
		aOK := fileExists(a)
		bOK := fileExists(b)
		switch {
		case aOK && !bOK:
			exec.Command("sudo", "/usr/bin/ln", "-sf", a, b).Run() //nolint:errcheck
		case bOK && !aOK:
			exec.Command("sudo", "/usr/bin/ln", "-sf", b, a).Run() //nolint:errcheck
		}
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ── Step 2: incus admin init ─────────────────────────────────────────────────

// lxdIsInitialized returns true when Incus already has at least one storage
// pool, meaning a previous `incus admin init` (or manual setup) was done.
func lxdIsInitialized() bool {
	out, err := exec.Command("incus", "storage", "list", "--format", "csv").Output()
	return err == nil && len(strings.TrimSpace(string(out))) > 0
}

// lxdRemoveStaleHostNatBridge deletes a leftover UNMANAGED `host-nat` kernel
// bridge so a re-enable's preseed can create the managed network cleanly. It is
// a no-op when host-nat is a managed Incus network (a live setup — never touch
// it) or when no such device exists. Best-effort.
func lxdRemoveStaleHostNatBridge(job *LXDEnableJob) {
	// If host-nat is a MANAGED incus network, it belongs to a working setup —
	// leave it alone.
	if out, err := exec.Command("incus", "network", "list", "--format", "json").Output(); err == nil {
		var nets []struct {
			Name    string `json:"name"`
			Managed bool   `json:"managed"`
		}
		if json.Unmarshal(out, &nets) == nil {
			for _, n := range nets {
				if n.Name == "host-nat" && n.Managed {
					return
				}
			}
		}
	}
	// Unmanaged (or daemon unreachable). If a kernel bridge device exists, it's a
	// leftover from a prior enable — delete it.
	if exec.Command("ip", "link", "show", "dev", "host-nat").Run() != nil {
		return // no such device — nothing to clean up
	}
	job.log("Removing leftover unmanaged host-nat bridge from a previous attempt…")
	if out, err := exec.Command("sudo", "/usr/sbin/ip", "link", "delete", "dev", "host-nat").CombinedOutput(); err != nil {
		job.log("  (could not delete host-nat bridge, continuing): " + strings.TrimSpace(string(out)))
	}
}

// runLXCLog runs an incus command (no sudo) and streams its output into the
// job log.
func runLXCLog(ctx context.Context, job *LXDEnableJob, args ...string) error {
	job.log("$ incus " + strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, "incus", args...)
	out, err := cmd.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			job.log(line)
		}
	}
	return err
}

func lxdStep2Init(ctx context.Context, storagePool, hostname string, job *LXDEnableJob) error {
	job.setStep(2, "running", "")

	// Add the service account to the incus-admin group first (non-fatal — may
	// already be done). incus-admin grants full daemon access; the read-only
	// `incus` group is not enough for the mutations ZNAS performs.
	job.log("Ensuring service account is in the " + HVUserGroup + " group…")
	if err := runCmdLog(ctx, job, "/usr/sbin/usermod", "-a", "-G", HVUserGroup, "zfsnas"); err != nil {
		job.log("Warning: usermod returned error (may already be in group): " + err.Error())
	}

	// Remove a leftover UNMANAGED `host-nat` bridge from a previous enable. After
	// a disable/uninstall the incus DB record is gone, but the kernel bridge
	// device lingers (nothing tears it down — not the uninstall, not a reboot
	// necessarily). On re-enable the preseed then tries to create the managed
	// host-nat over the existing kernel device and fails with "Failed to update
	// local member network host-nat … Network not found". Delete the stale device
	// first — but only when it's unmanaged, so a live managed network is never
	// touched. (6.6.26.)
	lxdRemoveStaleHostNatBridge(job)

	var err error
	if lxdIsInitialized() {
		job.log("Incus is already initialised — applying incremental configuration…")
		err = lxdConfigureExisting(ctx, storagePool, hostname, job)
	} else {
		err = lxdInitFreshPreseed(ctx, storagePool, hostname, job)
	}
	if err != nil {
		return err
	}

	// Generate incus client cert for cross-server VM push (idempotent).
	job.log("Generating incus client certificate for VM push…")
	if certErr := LXDEnsureClientCert(); certErr != nil {
		job.log("Warning: could not generate incus client cert: " + certErr.Error())
	} else {
		job.log("Incus client certificate ready.")
	}

	// Image remotes: the default `images:` remote (linuxcontainers.org)
	// already ships Ubuntu container + VM images for every supported
	// release (lookup with `incus image list images: ubuntu`), so no
	// extra remotes are added here.
	//
	// 6.5.6 explicitly removes any leftover `ubuntu` / `ubuntu-daily`
	// remotes added by previous releases. Canonical no longer publishes
	// LXD/Incus-format streams at https://cloud-images.ubuntu.com — the
	// JSON only contains aws/gce/azure cloud-native variants now and
	// those simplestreams remotes return empty image lists in the Create
	// VM/Container wizard. Removing them keeps the wizard's remote
	// dropdown accurate.
	cleanupDeadImageRemotes(ctx, job)

	// ZNAS' preseed creates `host-nat` as the managed NAT bridge, but a
	// host that previously ran `incus admin init --auto` (or an older
	// ZNAS release) will also have an `incusbr0` lying around — sometimes
	// with a kernel-level IP that the network-list UI surfaces, making
	// it look like a second NAT network. Remove it if it isn't being
	// used by anything; users get a single, named NAT.
	cleanupRedundantIncusbr0(ctx, job)

	return nil
}

// cleanupRedundantIncusbr0 removes the leftover `incusbr0` bridge that
// `incus admin init --auto` (or older ZNAS releases) used to create with
// its own NAT subnet. ZNAS' preseed creates `host-nat` as the canonical
// managed NAT, so a co-existing `incusbr0` is at best confusing (two
// "NAT" entries in the network list) and at worst a routing-priority
// problem.
//
// We refuse to remove it when:
//   - it doesn't exist (nothing to do)
//   - its name is `host-nat` (we'd be deleting our own bridge)
//   - Incus reports it has any users (`used_by` non-empty) — someone
//     attached an instance/profile to it explicitly; leave it alone.
//
// On the delete path we try the Incus-managed form first; if that
// errors because the bridge is unmanaged at the kernel level (no
// matching network entry to delete), we fall back to `ip link delete`
// to take the kernel bridge down. Either way, the entry stops showing
// in the UI.
func cleanupRedundantIncusbr0(ctx context.Context, job *LXDEnableJob) {
	const target = "incusbr0"

	// Quick existence probe via `incus network show`. Non-zero exit → not
	// known to Incus AT ALL; fall through to the kernel-link probe.
	knownToIncus := exec.Command("incus", "network", "show", target).Run() == nil

	// Pull a JSON view to learn whether anything is using it.
	if knownToIncus {
		out, err := exec.Command("incus", "network", "list", "--format", "json").Output()
		if err == nil {
			var raw []struct {
				Name   string   `json:"name"`
				UsedBy []string `json:"used_by"`
			}
			if json.Unmarshal(out, &raw) == nil {
				for _, n := range raw {
					if n.Name == target && len(n.UsedBy) > 0 {
						job.log(fmt.Sprintf("Skipping %s cleanup: %d user(s) reference it.", target, len(n.UsedBy)))
						return
					}
				}
			}
		}
	}

	// Kernel-link probe. If the device doesn't exist there either, we're
	// fully clean — nothing to do.
	linkOut, _ := exec.Command("ip", "link", "show", "dev", target).Output()
	if len(linkOut) == 0 && !knownToIncus {
		return
	}

	job.log("Removing redundant " + target + " bridge (host-nat is the canonical NAT now)…")

	// Incus-side delete first. Tolerate failure — the bridge may be a
	// pure kernel object with no Incus record.
	if knownToIncus {
		_ = runLXCLog(ctx, job, "network", "delete", target)
	}

	// Kernel-link delete cleans up the bridge interface itself when the
	// network was unmanaged (no `incus network` record but a real bridge
	// device with an IP that the UI surfaced). Best-effort.
	if exec.Command("ip", "link", "show", "dev", target).Run() == nil {
		out, err := exec.Command("sudo", "/usr/sbin/ip", "link", "delete", "dev", target).CombinedOutput()
		if err != nil {
			job.log("Warning: " + target + " kernel link still present: " + strings.TrimSpace(string(out)))
		}
	}
}

// cleanupDeadImageRemotes removes the legacy `ubuntu` / `ubuntu-daily`
// remotes if they are present. Idempotent — `incus remote remove`
// returns non-zero when the remote is absent, which we silently tolerate.
func cleanupDeadImageRemotes(ctx context.Context, job *LXDEnableJob) {
	for _, name := range []string{"ubuntu", "ubuntu-daily"} {
		out, _ := exec.Command("incus", "remote", "list", "--format", "csv").Output()
		if !strings.Contains(string(out), name+",") {
			continue
		}
		job.log("Removing legacy image remote " + name + " (no longer publishes Incus-compatible streams)…")
		if err := runLXCLog(ctx, job, "remote", "remove", name); err != nil {
			job.log("Warning: could not remove " + name + " remote: " + err.Error())
		}
	}
}

// lxdInitFreshPreseed runs `sudo incus admin init --preseed` for a brand-new
// Incus installation. Dataset name "LXD-<hostname>" is kept for historical
// continuity with portal versions ≤ 6.4.x that ran LXD; a name change today
// would force every existing host to recreate its storage pool.
func lxdInitFreshPreseed(ctx context.Context, storagePool, hostname string, job *LXDEnableJob) error {
	dataset := storagePool + "/LXD-" + hostname
	preseed := fmt.Sprintf(`config:
  core.https_address: ':8444'
networks:
- name: host-nat
  type: bridge
  config:
    ipv4.address: auto
    ipv6.address: none
storage_pools:
- name: default
  driver: zfs
  config:
    source: %s
profiles:
- name: default
  config: {}
  description: ""
  devices:
    eth0:
      name: eth0
      network: host-nat
      type: nic
    root:
      path: /
      pool: default
      type: disk
projects:
- config:
    features.images: "true"
    features.networks: "true"
    features.profiles: "true"
    features.storage.volumes: "true"
  description: Default Incus project
  name: default
`, dataset)

	// Pre-flight: a leftover dataset from a prior failed init is the #1 cause
	// of `incus admin init --preseed` returning "Provided ZFS pool (or dataset)
	// isn't empty". Detect and clean it up before init so the wizard works on
	// retry without manual zfs commands.
	if datasetExistsAndIncusEmpty(dataset) {
		job.log("Found pre-existing empty Incus dataset " + dataset + " from a previous attempt — destroying so init can proceed.")
		out, err := exec.Command("sudo", "/usr/sbin/zfs", "destroy", "-r", dataset).CombinedOutput()
		if err != nil {
			msg := "stale dataset " + dataset + " could not be removed: " + strings.TrimSpace(string(out)) +
				" — destroy it manually with `sudo zfs destroy -r " + dataset + "` and retry"
			job.setStep(2, "error", msg)
			return fmt.Errorf("preseed cleanup: %s", msg)
		}
	}

	lxdBin := lxdBinaryPath()

	// Gate the preseed on the daemon being ready. Right after `apt install
	// incus` on a fresh Ubuntu 26.04 host, incus.socket is registered with
	// systemd but the incusd process is still starting; calling
	// `incus admin init` in that window can block silently on the unix
	// socket connect. `waitready` triggers socket activation explicitly
	// and returns as soon as the daemon answers — or with a clear error
	// after `--timeout`. 120 s matches the Ubuntu Incus package's own
	// `ExecStartPost=incusd waitready --timeout=120` so we never wait
	// longer than the system would have on its own.
	job.log("Waiting for the Incus daemon socket (incus admin waitready, max 120 s)…")
	waitCtx, waitCancel := context.WithTimeout(ctx, 130*time.Second)
	if out, err := exec.CommandContext(waitCtx, "sudo", lxdBin, "admin", "waitready", "--timeout=120").CombinedOutput(); err != nil {
		waitCancel()
		errMsg := lastNonEmptyLine(string(out))
		if errMsg == "" {
			errMsg = err.Error()
		}
		full := "incus admin waitready failed (daemon not responding): " + errMsg
		job.setStep(2, "error", full)
		return fmt.Errorf("incus admin waitready: %s", errMsg)
	}
	waitCancel()

	// Clear any leftover `host-nat` network from a previous attempt. The
	// fresh-vs-existing decision keys on storage pools (lxdIsInitialized), so a
	// daemon that still has the host-nat network in its DB but no storage pool —
	// e.g. after a disable/re-enable cycle, or a half-completed prior init — lands
	// HERE on the fresh-preseed path. `incus admin init --preseed` then tries to
	// UPDATE the existing host-nat instead of creating it and dies with
	// "Failed to update local member network \"host-nat\" … Network not found".
	// Deleting it first makes the preseed create it cleanly. Best-effort: a
	// "not found" (the normal fresh case) or in-use error is ignored — if it's
	// genuinely in use the daemon wasn't fresh and the preseed will report that.
	// Wrap the preseed itself in a hard timeout so a stuck init can't sit
	// silently forever. 5 minutes is generous — on a healthy host the
	// preseed is sub-second; if it's still running at 5 min something
	// systemic is wrong (network drop, ZFS pool unresponsive, etc.) and
	// the user is better off seeing a clear error than the spinner.
	job.log("Running incus admin init --preseed (" + lxdBin + ")…")
	initCtx, initCancel := context.WithTimeout(ctx, 5*time.Minute)
	defer initCancel()
	cmd := exec.CommandContext(initCtx, "sudo", lxdBin, "admin", "init", "--preseed")
	cmd.Stdin = strings.NewReader(preseed)

	// Stream stderr line-by-line into the activity log instead of using
	// CombinedOutput. The buffered form held back any progress incus
	// emits so the UI couldn't tell apart "still working" from "stuck"
	// — a real production failure (Ubuntu 26.04, fresh install,
	// May 2026) lost SSH while this call was outstanding and
	// the activity panel had no clue why.
	stderrPipe, perr := cmd.StderrPipe()
	if perr != nil {
		job.setStep(2, "error", "stderr pipe: "+perr.Error())
		return fmt.Errorf("stderr pipe: %w", perr)
	}
	stdoutPipe, perr := cmd.StdoutPipe()
	if perr != nil {
		job.setStep(2, "error", "stdout pipe: "+perr.Error())
		return fmt.Errorf("stdout pipe: %w", perr)
	}
	if err := cmd.Start(); err != nil {
		job.setStep(2, "error", "start: "+err.Error())
		return fmt.Errorf("start: %w", err)
	}
	var (
		combined strings.Builder
		combMu   sync.Mutex
		drained  sync.WaitGroup
	)
	streamReader := func(r io.Reader) {
		defer drained.Done()
		buf := bufio.NewScanner(r)
		buf.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for buf.Scan() {
			line := buf.Text()
			if line == "" {
				continue
			}
			job.log(line)
			combMu.Lock()
			combined.WriteString(line)
			combined.WriteByte('\n')
			combMu.Unlock()
		}
	}
	drained.Add(2)
	go streamReader(stderrPipe)
	go streamReader(stdoutPipe)
	err := cmd.Wait()
	drained.Wait()
	if err != nil {
		// Distinguish a context-timeout from a real init error so the
		// surfaced message matches the actual failure mode.
		errMsg := lastNonEmptyLine(combined.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		if initCtx.Err() == context.DeadlineExceeded {
			full := "incus admin init timed out after 5 minutes (daemon may have hung — check `incus admin sql global \"select * from instances\"` and the system journal). Cleanup any stale dataset under " + dataset + " and retry."
			job.setStep(2, "error", full)
			return fmt.Errorf("incus admin init: timeout: %s", errMsg)
		}
		full := "incus admin init failed: " + errMsg
		job.setStep(2, "error", full)
		return fmt.Errorf("incus admin init: %s", errMsg)
	}
	job.setStep(2, "done", "")
	return nil
}

// datasetExistsAndIncusEmpty returns true when the named dataset exists AND
// Incus has no storage pool registered yet. The combination indicates a stale
// dataset left behind by a previous failed `incus admin init` run.
func datasetExistsAndIncusEmpty(dataset string) bool {
	// Probe dataset existence. Use absolute path because /usr/sbin is not on
	// the systemd-spawned service's PATH by default.
	if err := exec.Command("/usr/sbin/zfs", "list", "-H", "-o", "name", dataset).Run(); err != nil {
		return false
	}
	// Probe Incus storage list. Run via sudo because the running zfsnas
	// service was added to the `incus-admin` group earlier in the same job
	// (`usermod -a -G incus-admin zfsnas`), but the kernel only refreshes
	// supplementary groups when the process re-execs. Without sudo here,
	// `incus storage list` fails with "permission denied", the function
	// returns false (conservative), the stale-dataset cleanup is skipped,
	// and the preseed init then dies with "isn't empty". Sudo bypasses
	// the group check entirely.
	out, err := exec.Command("sudo", lxdBinaryPath(), "storage", "list", "--format", "csv").Output()
	if err != nil {
		// If we still can't query incus (daemon down, etc.), be
		// conservative and leave the dataset alone.
		return false
	}
	return len(strings.TrimSpace(string(out))) == 0
}

// lastNonEmptyLine returns the last non-empty line of s. Used to surface
// the most actionable error message when a CLI tool prints multiple lines.
func lastNonEmptyLine(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		// Find end-of-line backwards.
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l != "" {
			return l
		}
	}
	return ""
}

// lxdConfigureExisting applies incremental configuration to an already-initialised LXD:
// HostNatNetworkName returns the name of the i-th NAT network: the first is
// plain `host-nat` (the canonical one, referenced by the default profile and
// by older setups), and subsequent ones are numbered from 2 — `host-nat2`,
// `host-nat3`, … There is one per physical link-up NIC, mirroring the
// vmbr0/vmbr1/… LAN bridges, so a guest can be put behind NAT on the same
// physical port it would otherwise be bridged onto.
func HostNatNetworkName(i int) string {
	if i <= 0 {
		return "host-nat"
	}
	return fmt.Sprintf("host-nat%d", i+1)
}

// IsHostNatNetwork reports whether a network name is one of ours (host-nat,
// host-nat2, …). Used wherever the canonical name used to be compared
// literally — those places must keep treating the numbered ones as internal.
func IsHostNatNetwork(name string) bool {
	if name == "host-nat" {
		return true
	}
	if !strings.HasPrefix(name, "host-nat") {
		return false
	}
	for _, r := range name[len("host-nat"):] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(name) > len("host-nat")
}

// physicalLinkUpNICs lists physical NICs that currently have carrier — the
// same rule the appliance image uses when it decides which ports to bridge.
func physicalLinkUpNICs() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if name == "lo" || virtualIfRe.MatchString(name) {
			continue
		}
		if _, err := os.Stat("/sys/class/net/" + name + "/device"); err != nil {
			continue // not a physical device
		}
		car, err := os.ReadFile("/sys/class/net/" + name + "/carrier")
		if err != nil || strings.TrimSpace(string(car)) != "1" {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// nicHasIPv4 reports whether a physical NIC is carrying an IPv4 address —
// either directly, or through the bridge it is enslaved to. On the appliance
// every cabled port is a bridge member and the BRIDGE holds the lease, so
// asking the NIC alone would always answer "no".
func nicHasIPv4(nic string) bool {
	if hasIPv4Addr(nic) {
		return true
	}
	if master, err := os.Readlink("/sys/class/net/" + nic + "/master"); err == nil {
		return hasIPv4Addr(master[strings.LastIndex(master, "/")+1:])
	}
	return false
}

func hasIPv4Addr(iface string) bool {
	out, err := exec.Command("ip", "-4", "-o", "addr", "show", "dev", iface).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "inet ")
}

// physicalUplinkNICs is physicalLinkUpNICs narrowed to the ports that actually
// reach a network: up, cabled AND addressed. A NAT network exists to give
// guests a way out, so pairing one with a port that has no address of its own
// would be pairing it with nothing.
func physicalUplinkNICs() []string {
	var out []string
	for _, n := range physicalLinkUpNICs() {
		if nicHasIPv4(n) {
			out = append(out, n)
		}
	}
	return out
}

// HostNatUplinkKey is the Incus network config key recording which physical
// port a NAT network was created for. The pairing cannot be derived later —
// a NAT bridge has no physical port — so it is written down at creation.
const HostNatUplinkKey = "user.zfsnas.uplink"

// lxdEnsureHostNatNetworks creates one NAT network per physical link-up NIC,
// named by HostNatNetworkName. Each gets its own auto-allocated subnet, so a
// guest can be attached to the NAT that corresponds to a given port. Existing
// networks are left untouched.
func lxdEnsureHostNatNetworks(ctx context.Context, job *LXDEnableJob) {
	nics := physicalUplinkNICs()
	if len(nics) == 0 {
		nics = []string{""} // always provide the canonical host-nat
	}
	for i, nic := range nics {
		name := HostNatNetworkName(i)
		out, _ := exec.Command("incus", "network", "show", name).Output()
		if len(strings.TrimSpace(string(out))) > 0 {
			job.log(name + " already exists.")
			// Networks created before the pairing was recorded show up with no
			// uplink at all; fill it in rather than leaving them unlabelled.
			if nic != "" && !strings.Contains(string(out), HostNatUplinkKey) {
				_ = runLXCLog(ctx, job, "network", "set", name, HostNatUplinkKey, nic)
			}
			continue
		}
		job.log("Creating NAT bridge " + name + " for " + nic + "…")
		args := []string{"network", "create", name,
			"ipv4.address=auto", "ipv4.nat=true", "ipv6.address=none"}
		if nic != "" {
			args = append(args, HostNatUplinkKey+"="+nic)
		}
		if err := runLXCLog(ctx, job, args...); err != nil {
			job.log("Warning: could not create " + name + ": " + err.Error())
		}
	}
}

// sets core.https_address and ensures the host-nat bridge exists.
func lxdConfigureExisting(ctx context.Context, storagePool, hostname string, job *LXDEnableJob) error {
	// Set API listen address
	job.log("Setting core.https_address to :8444…")
	if err := runLXCLog(ctx, job, "config", "set", "core.https_address", ":8444"); err != nil {
		job.log("Warning: could not set core.https_address: " + err.Error())
	}

	// Ensure host-nat bridge exists
	out, _ := exec.Command("incus", "network", "show", "host-nat").Output()
	if len(strings.TrimSpace(string(out))) == 0 {
		job.log("Creating host-nat bridge…")
		if err := runLXCLog(ctx, job, "network", "create", "host-nat",
			"ipv4.address=auto", "ipv6.address=none"); err != nil {
			job.log("Warning: could not create host-nat bridge: " + err.Error())
		}
	} else {
		job.log("host-nat bridge already exists.")
	}

	// Ensure default profile uses host-nat for eth0
	job.log("Updating default profile to use host-nat…")
	if err := runLXCLog(ctx, job, "profile", "device", "add", "default", "eth0", "nic",
		"nictype=bridged", "parent=host-nat", "name=eth0"); err != nil {
		// device may already exist — try set instead
		if err2 := runLXCLog(ctx, job, "profile", "device", "set", "default", "eth0", "network=host-nat"); err2 != nil {
			job.log("Warning: could not update default profile eth0: " + err2.Error())
		}
	}
	// Ensure default profile has root disk
	if err := runLXCLog(ctx, job, "profile", "device", "add", "default", "root", "disk",
		"path=/", "pool=default"); err != nil {
		job.log("Note: root disk device may already exist in default profile.")
	}

	// Ensure default storage pool exists pointing at chosen ZFS pool
	poolOut, _ := exec.Command("incus", "storage", "show", "default").Output()
	if len(strings.TrimSpace(string(poolOut))) == 0 {
		dataset := storagePool + "/LXD-" + hostname
		job.log("Creating default storage pool on " + dataset + "…")
		if err := runLXCLog(ctx, job, "storage", "create", "default", "zfs",
			"source="+dataset); err != nil {
			job.setStep(2, "error", "create storage pool: "+err.Error())
			return fmt.Errorf("create storage pool: %w", err)
		}
	} else {
		job.log("Default storage pool already exists.")
	}

	job.setStep(2, "done", "")
	return nil
}

// ── Step 3: network bridges ───────────────────────────────────────────────────

type bridgeCandidate struct {
	NIC     string
	MAC     string // L2 address of the source NIC, copied to the bridge to preserve DHCP leases
	IP      string
	Prefix  int
	Gateway string
	Bridge  string
	IsDHCP  bool // when true, the bridge is written as `inet dhcp` instead of `inet static`
}

func lxdStep3Bridges(ctx context.Context, job *LXDEnableJob) error {
	job.setStep(3, "running", "")

	candidates, err := detectBridgeCandidates()
	if err != nil {
		job.setStep(3, "error", "detect NICs: "+err.Error())
		return fmt.Errorf("detect bridge candidates: %w", err)
	}
	if len(candidates) == 0 {
		job.log("No unconfigured physical NICs with IPv4 addresses found; skipping bridge setup.")
		job.setStep(3, "done", "")
		return nil
	}

	for _, c := range candidates {
		job.log(fmt.Sprintf("Will bridge %s → %s (%s/%d gw %s)", c.NIC, c.Bridge, c.IP, c.Prefix, c.Gateway))
	}

	// /etc/network/interfaces edits go through writeInterfacesFile, which uses
	// in-process I/O when running as root and falls back to "sudo tee" / "sudo
	// cp" under blanket NOPASSWD: ALL. There is no dedicated sudo entry for this
	// path under the hardened template, so hardened deployments must run the
	// portal as root.
	sudoMode := CheckSudoAccess().Type
	if sudoMode != "root" && sudoMode != "all" {
		job.setStep(3, "error", "editing /etc/network/interfaces requires running as root or having unrestricted sudo (sudo-all)")
		return fmt.Errorf("editing /etc/network/interfaces requires running as root or having unrestricted sudo (sudo-all)")
	}

	// Backup existing interfaces file
	backupPath := "/etc/network/interfaces.bak"
	job.log("Backing up /etc/network/interfaces to " + backupPath)
	content, err := os.ReadFile("/etc/network/interfaces")
	if err != nil {
		job.setStep(3, "error", "read interfaces: "+err.Error())
		return fmt.Errorf("read /etc/network/interfaces: %w", err)
	}
	if err := writeInterfacesFile(backupPath, content); err != nil {
		job.log("Warning: backup failed: " + err.Error())
	}

	newContent := rewriteInterfacesForBridges(string(content), candidates)

	job.log("Writing new /etc/network/interfaces…")
	if err := writeInterfacesFile("/etc/network/interfaces", []byte(newContent)); err != nil {
		job.setStep(3, "error", "write interfaces: "+err.Error())
		return fmt.Errorf("write /etc/network/interfaces: %w", err)
	}

	// Pin a stable DHCP Client-ID for each bridge that uses DHCP. With
	// `hwaddress ether <mac>` the bridge inherits the source NIC's MAC,
	// but dhcpcd's default RFC-4361 Client-ID embeds a freshly-generated
	// DUID with a creation timestamp — so the DHCP server still sees a
	// "new" client and hands out a different lease. Writing a Type-1
	// hardware-address client-id (`01:<mac>`) for the bridge name makes
	// the same lease come back, keeping the host's IP stable across the
	// bridge step. Best-effort.
	if err := pinDhcpcdBridgeClientIDs(candidates, func(s string) { job.log(s) }); err != nil {
		job.log("Warning: could not pin dhcpcd client-id for bridge(s): " + err.Error() + " (IP may change)")
	}

	// Restart networking
	job.log("Restarting networking (your connection may briefly drop)…")
	if err := runCmdLog(ctx, job, "/usr/bin/systemctl", "restart", "networking"); err != nil {
		job.setStep(3, "error", "restart networking: "+err.Error())
		return fmt.Errorf("restart networking: %w", err)
	}

	job.setStep(3, "done", "")
	return nil
}

// dhcpcdBridgeMarkerStart and dhcpcdBridgeMarkerEnd wrap the bridge-step
// section of /etc/dhcpcd.conf so it can be re-written idempotently across
// repeated enable/uninstall cycles without bloating the file.
const (
	dhcpcdBridgeMarkerStart = "# >>> ZNAS bridge step — vmbrN clientid pinning >>>"
	dhcpcdBridgeMarkerEnd   = "# <<< ZNAS bridge step — vmbrN clientid pinning <<<"
)

// pinDhcpcdBridgeClientIDs writes per-bridge `clientid` directives into
// /etc/dhcpcd.conf so dhcpcd presents the SAME identifier to the DHCP
// server it would have presented for the underlying NIC (Type-1 hardware
// address: `01:<mac>`). Without this, the bridge step gets a new lease
// even though the bridge inherits the NIC's L2 address.
func pinDhcpcdBridgeClientIDs(cands []bridgeCandidate, log func(string)) error {
	const path = "/etc/dhcpcd.conf"
	var block strings.Builder
	block.WriteString(dhcpcdBridgeMarkerStart + "\n")
	wrote := 0
	for _, c := range cands {
		if !c.IsDHCP || c.MAC == "" {
			continue
		}
		// `formatDhcpcdClientID` lives in netplan_migrate.go and converts
		// "10666af8c2f0" to "10:66:6a:f8:c2:f0" — but we already have the
		// MAC in colon form here, so prefix `01:` directly.
		fmt.Fprintf(&block, "interface %s\n    clientid 01:%s\n", c.Bridge, c.MAC)
		wrote++
		log(fmt.Sprintf("    %s ← clientid 01:%s (matches inherited MAC, keeps DHCP lease stable)",
			c.Bridge, c.MAC))
	}
	block.WriteString(dhcpcdBridgeMarkerEnd + "\n")
	if wrote == 0 {
		return nil
	}

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	stripped := stripBlockBetweenMarkers(string(existing), dhcpcdBridgeMarkerStart, dhcpcdBridgeMarkerEnd)
	stripped = strings.TrimRight(stripped, "\n") + "\n\n"
	out := stripped + block.String()
	return writeRoot(path, []byte(out), 0o644)
}

// ipAddrIface is a minimal parse of one entry from `ip -j addr`.
type ipAddrIface struct {
	IfName   string   `json:"ifname"`
	LinkType string   `json:"link_type"`
	Address  string   `json:"address"` // L2 address, used to keep DHCP leases stable when bridging
	Flags    []string `json:"flags"`
	Master   string   `json:"master"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Dynamic   bool   `json:"dynamic,omitempty"` // true on DHCP-assigned addresses
	} `json:"addr_info"`
}

// ipRouteEntry is a minimal parse of one entry from `ip -j route`.
type ipRouteEntry struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway,omitempty"`
	Dev     string `json:"dev"`
}

// virtualIfRe matches names that are clearly not physical NICs.
var virtualIfRe = regexp.MustCompile(`^(vmbr|lxdbr|br-|virbr|docker|tap|tun|dummy|lo|bond|team)`)

// ifupdownNICIsDHCP reports whether /etc/network/interfaces declares the
// given NIC as `inet dhcp`. Used as a fallback when the runtime
// `addr_info[].dynamic` flag is missing (e.g. the lease has been renewed
// manually with a static address). Returns false on any read/parse failure
// — defaults to "treat as static" which preserves the existing IP as a
// safer fallback than guessing DHCP wrong.
func ifupdownNICIsDHCP(nic string) bool {
	data, err := os.ReadFile("/etc/network/interfaces")
	if err != nil {
		return false
	}
	want := "iface " + nic + " inet "
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, want) {
			continue
		}
		mode := strings.TrimSpace(strings.TrimPrefix(t, want))
		// Stanza may continue with extra tokens; check only the first.
		if i := strings.IndexAny(mode, " \t"); i >= 0 {
			mode = mode[:i]
		}
		return mode == "dhcp"
	}
	return false
}

func detectBridgeCandidates() ([]bridgeCandidate, error) {
	// Get all interfaces
	addrOut, err := exec.Command("ip", "-j", "addr").Output()
	if err != nil {
		return nil, fmt.Errorf("ip -j addr: %w", err)
	}
	var ifaces []ipAddrIface
	if err := json.Unmarshal(addrOut, &ifaces); err != nil {
		return nil, fmt.Errorf("parse ip addr: %w", err)
	}

	// Find default gateway and which interface it's on
	routeOut, _ := exec.Command("ip", "-j", "route").Output()
	var routes []ipRouteEntry
	_ = json.Unmarshal(routeOut, &routes)
	gwByDev := map[string]string{}
	for _, r := range routes {
		if r.Dst == "default" && r.Gateway != "" {
			if _, exists := gwByDev[r.Dev]; !exists {
				gwByDev[r.Dev] = r.Gateway
			}
		}
	}

	var candidates []bridgeCandidate
	bridgeIdx := 0
	for _, iface := range ifaces {
		if iface.LinkType != "ether" {
			continue
		}
		if virtualIfRe.MatchString(iface.IfName) {
			continue
		}
		if strings.Contains(iface.IfName, ".") {
			continue // VLAN sub-interface
		}
		if iface.Master != "" {
			continue // already enslaved to a bridge
		}
		// Must be a physical device (has /sys/class/net/<name>/device symlink)
		if _, err := os.Stat("/sys/class/net/" + iface.IfName + "/device"); err != nil {
			continue
		}
		// Must already be a bridge member or have an IP we can move.
		// Capture both the address and whether it was DHCP-assigned so the
		// bridge stanza preserves the original mode (DHCP→DHCP, static→static)
		// — otherwise a host on DHCP gets pinned to whatever IP it happened
		// to hold at enable time, and DHCP can later lease that IP elsewhere.
		ip := ""
		prefix := 0
		isDHCP := false
		for _, a := range iface.AddrInfo {
			if a.Family == "inet" {
				ip = a.Local
				prefix = a.PrefixLen
				isDHCP = a.Dynamic
				break
			}
		}
		// Cross-check against /etc/network/interfaces for the source NIC's
		// stanza — if the file already says `inet dhcp`, trust that over the
		// runtime flag (more reliable for hosts where the address became
		// non-dynamic mid-session, e.g. after a manual edit).
		if !isDHCP && ifupdownNICIsDHCP(iface.IfName) {
			isDHCP = true
		}
		if ip == "" {
			continue
		}
		bridge := fmt.Sprintf("vmbr%d", bridgeIdx)
		bridgeIdx++
		candidates = append(candidates, bridgeCandidate{
			NIC:     iface.IfName,
			MAC:     iface.Address,
			IP:      ip,
			Prefix:  prefix,
			Gateway: gwByDev[iface.IfName],
			Bridge:  bridge,
			IsDHCP:  isDHCP,
		})
	}
	return candidates, nil
}

// rewriteInterfacesForBridges removes existing NIC stanzas and appends
// a manual NIC stanza + bridge stanza for each candidate, preserving
// dns-nameservers, dns-search, and mtu from the original NIC stanza.
func rewriteInterfacesForBridges(content string, candidates []bridgeCandidate) string {
	nicSet := map[string]bool{}
	for _, c := range candidates {
		nicSet[c.NIC] = true
	}

	// Per-NIC preserved settings extracted from stripped stanzas.
	type nicMeta struct {
		dns    string // dns-nameservers value
		search string // dns-search value
		mtu    string // mtu value
	}
	nicMetas := map[string]*nicMeta{}
	for _, c := range candidates {
		nicMetas[c.NIC] = &nicMeta{}
	}

	lines := strings.Split(content, "\n")
	var kept []string
	inSkip := false
	currentNIC := ""

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect start of a stanza we want to remove
		if !inSkip {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				kw := fields[0]
				name := fields[1]
				if (kw == "auto" || kw == "allow-hotplug" || kw == "iface" || kw == "mapping") && nicSet[name] {
					inSkip = true
					currentNIC = name
					continue
				}
			}
		}

		if inSkip {
			// Collect preserved settings from the skipped stanza
			if meta, ok := nicMetas[currentNIC]; ok && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
				fields := strings.Fields(trimmed)
				if len(fields) >= 2 {
					switch fields[0] {
					case "dns-nameservers":
						meta.dns = strings.Join(fields[1:], " ")
					case "dns-search":
						meta.search = strings.Join(fields[1:], " ")
					case "mtu":
						meta.mtu = fields[1]
					}
				}
			}

			if trimmed == "" {
				inSkip = false
				currentNIC = ""
				kept = append(kept, line)
			} else if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				continue
			} else {
				inSkip = false
				currentNIC = ""
				fields := strings.Fields(trimmed)
				if len(fields) >= 2 {
					kw := fields[0]
					name := fields[1]
					if (kw == "auto" || kw == "allow-hotplug" || kw == "iface" || kw == "mapping") && nicSet[name] {
						inSkip = true
						currentNIC = name
						continue
					}
				}
				kept = append(kept, line)
			}
			continue
		}
		kept = append(kept, line)
	}

	result := strings.TrimRight(strings.Join(kept, "\n"), "\n") + "\n"

	for _, c := range candidates {
		meta := nicMetas[c.NIC]
		nicBlock := fmt.Sprintf("\nauto %s\niface %s inet manual\n", c.NIC, c.NIC)
		if meta != nil && meta.mtu != "" {
			nicBlock += fmt.Sprintf("    mtu %s\n", meta.mtu)
		}
		// Preserve the source NIC's addressing mode on the bridge: if the
		// host was on DHCP, write `inet dhcp` so the bridge keeps renewing
		// its lease; if it was static, write `inet static` with the captured
		// address/gateway/DNS. Pinning a DHCP host to its current IP
		// silently breaks if the DHCP server later leases that IP elsewhere.
		var bridgeBlock string
		if c.IsDHCP {
			bridgeBlock = fmt.Sprintf("\nauto %s\niface %s inet dhcp\n", c.Bridge, c.Bridge)
			// dns-nameservers under inet dhcp is a no-op without resolvconf;
			// kept off so we don't suggest a config the system won't apply.
		} else {
			bridgeBlock = fmt.Sprintf("\nauto %s\niface %s inet static\n    address %s/%d\n",
				c.Bridge, c.Bridge, c.IP, c.Prefix)
			if c.Gateway != "" {
				bridgeBlock += fmt.Sprintf("    gateway %s\n", c.Gateway)
			}
			if meta != nil && meta.dns != "" {
				bridgeBlock += fmt.Sprintf("    dns-nameservers %s\n", meta.dns)
			}
			if meta != nil && meta.search != "" {
				bridgeBlock += fmt.Sprintf("    dns-search %s\n", meta.search)
			}
		}
		if meta != nil && meta.mtu != "" {
			bridgeBlock += fmt.Sprintf("    mtu %s\n", meta.mtu)
		}
		bridgeBlock += bridgeKernelStanzaTail(c, kernelGTE7())
		result += nicBlock + bridgeBlock
	}
	return result
}

// ── Step 4: chrony ────────────────────────────────────────────────────────────

func lxdStep4Chrony(ctx context.Context, job *LXDEnableJob) error {
	job.setStep(4, "running", "")
	// Check if chrony is already installed
	if _, err := exec.LookPath("chronyc"); err == nil {
		job.log("chrony is already installed; skipping.")
		job.setStep(4, "done", "")
		return nil
	}
	job.log("Installing chrony…")
	if err := runCmdLog(ctx, job, "/usr/bin/apt-get", "install", "-y", "chrony"); err != nil {
		job.setStep(4, "error", "chrony install failed: "+err.Error())
		return fmt.Errorf("install chrony: %w", err)
	}
	job.setStep(4, "done", "")
	return nil
}

// ── Step 5: memory compression (zram-tools, Balanced profile) ─────────────────
//
// Best-effort: a failure here does not fail the overall LXD-enable job; the
// core feature still works without zram. The Balanced profile (PercentRAM=25,
// algorithm=zstd) is the same default the Settings → Virtualization →
// Memory Compression card recommends for VM hosts.
func lxdStep5MemComp(ctx context.Context, job *LXDEnableJob) {
	job.setStep(5, "running", "")

	if !MemCompPrereqsInstalled() {
		job.log("Installing zram-tools…")
		if err := InstallMemCompPrereqs(func(line string) { job.log(line) }); err != nil {
			job.log("Warning: zram-tools install failed: " + err.Error())
			job.setStep(5, "error", "zram-tools install failed: "+err.Error())
			return
		}
	} else {
		job.log("zram-tools already installed.")
	}

	cur := GetMemCompStatus()
	if cur.Enabled {
		job.log("Memory compression already enabled — leaving existing configuration in place.")
		job.setStep(5, "done", "")
		return
	}

	job.log("Enabling memory compression with Balanced profile (25% RAM, zstd)…")
	if _, err := ApplyMemCompConfig(MemCompConfig{Enabled: true, PercentRAM: 25, Algorithm: "zstd"}); err != nil {
		job.log("Warning: enable memory compression failed: " + err.Error())
		job.setStep(5, "error", "enable memory compression failed: "+err.Error())
		return
	}
	job.setStep(5, "done", "")
}

// ── Step 6: VM/Container metrics listener ─────────────────────────────────────
//
// Best-effort: turns on Incus' Prometheus endpoint on the loopback and flips
// LXDMetricsEnabled in app config so the portal scraper picks it up across
// restarts.
func lxdStep6Metrics(ctx context.Context, job *LXDEnableJob) {
	job.setStep(6, "running", "")

	job.log("Enabling Incus metrics listener on " + LXDMetricsAddress + "…")
	if _, _, err := EnableLXDMetricsListener(); err != nil {
		job.log("Warning: enable metrics listener failed: " + err.Error())
		job.setStep(6, "error", "enable metrics listener failed: "+err.Error())
		return
	}

	cfg, err := config.LoadAppConfig()
	if err != nil {
		job.log("Warning: load app config: " + err.Error())
		job.setStep(6, "error", "load app config: "+err.Error())
		return
	}
	cfg.LXDMetricsEnabled = true
	if err := config.SaveAppConfig(cfg); err != nil {
		job.log("Warning: save app config: " + err.Error())
		job.setStep(6, "error", "save app config: "+err.Error())
		return
	}
	job.log("Metrics listener enabled and persisted.")
	job.setStep(6, "done", "")
}
