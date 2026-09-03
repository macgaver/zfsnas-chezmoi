package system

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// BridgeMember is an instance (VM or container) attached to an LXD bridge.
type BridgeMember struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "virtual-machine" | "container"
	Status      string `json:"status"`
	Description string `json:"description"`
	DeviceName  string `json:"device_name"` // NIC device name inside the instance
	IPv4        string `json:"ipv4"`        // IP on this bridge (empty if stopped or unknown)
	Image       string `json:"image"`
	CPULimit    string `json:"cpu_limit"`
	MemoryLimit string `json:"memory_limit"`
	RootPool    string `json:"root_pool"` // LXD storage pool name for the root disk
}

// GetBridgeMembers returns instances attached to the named LXD bridge with their IPs.
func GetBridgeMembers(bridge string) ([]BridgeMember, error) {
	// Get network detail to find used_by list.
	netOut, err := exec.Command("incus", "query", "/1.0/networks/"+bridge).Output()
	if err != nil {
		return nil, fmt.Errorf("lxc query network: %w", err)
	}
	var net struct {
		UsedBy []string `json:"used_by"`
	}
	if err := json.Unmarshal(netOut, &net); err != nil {
		return nil, err
	}

	// Incus's `used_by` lists one entry per *usage* of the network, so a
	// VM with two NICs on the same bridge appears twice. Dedup by name
	// (the first occurrence wins) so the members table shows one row
	// per instance — matching the storage-pool members handler below.
	seen := map[string]bool{}
	var members []BridgeMember
	for _, uri := range net.UsedBy {
		if !strings.Contains(uri, "/1.0/instances/") {
			continue
		}
		instName := uri[strings.LastIndex(uri, "/")+1:]
		if seen[instName] {
			continue
		}
		seen[instName] = true

		// Get instance config: type, description, devices, expanded_config (volatile MACs).
		cfgOut, err := exec.Command("incus", "query", "/1.0/instances/"+instName).Output()
		if err != nil {
			continue
		}
		var inst struct {
			Type           string                       `json:"type"`
			Description    string                       `json:"description"`
			Status         string                       `json:"status"`
			Devices        map[string]map[string]string `json:"devices"`
			Config         map[string]string            `json:"config"`
			ExpandedConfig map[string]string            `json:"expanded_config"`
		}
		if err := json.Unmarshal(cfgOut, &inst); err != nil {
			continue
		}

		// Find which LXD device name maps to this bridge and its volatile MAC.
		devName := ""
		devMAC := ""
		for dev, cfg := range inst.Devices {
			if cfg["type"] != "nic" {
				continue
			}
			if cfg["network"] == bridge || cfg["parent"] == bridge {
				devName = dev
				// MAC may be set explicitly on the device or stored as volatile.
				devMAC = cfg["hwaddr"]
				if devMAC == "" && inst.ExpandedConfig != nil {
					devMAC = inst.ExpandedConfig["volatile."+dev+".hwaddr"]
				}
				break
			}
		}

		img := inst.Config["image.description"]
		if img == "" {
			img = strings.TrimSpace(inst.Config["image.os"] + " " + inst.Config["image.version"])
		}
		rootPool := ""
		for _, dev := range inst.Devices {
			if dev["type"] == "disk" && dev["path"] == "/" && dev["pool"] != "" {
				rootPool = dev["pool"]
				break
			}
		}
		m := BridgeMember{
			Name:        instName,
			Type:        inst.Type,
			Status:      inst.Status,
			Description: inst.Description,
			DeviceName:  devName,
			Image:       img,
			CPULimit:    inst.ExpandedConfig["limits.cpu"],
			MemoryLimit: inst.ExpandedConfig["limits.memory"],
			RootPool:    rootPool,
		}

		// Get IP from instance state if running.
		if inst.Status == "Running" && devName != "" {
			stateOut, err := exec.Command("incus", "query", "/1.0/instances/"+instName+"/state").Output()
			if err == nil {
				var state struct {
					Network map[string]struct {
						HWAddr    string `json:"hwaddr"`
						Addresses []struct {
							Family  string `json:"family"`
							Address string `json:"address"`
							Scope   string `json:"scope"`
						} `json:"addresses"`
					} `json:"network"`
				}
				if err := json.Unmarshal(stateOut, &state); err == nil {
					// First try direct name match (works for containers).
					// Fall back to MAC match (needed for VMs where OS may rename the NIC).
					iface, ok := state.Network[devName]
					if !ok && devMAC != "" {
						for _, netIface := range state.Network {
							if strings.EqualFold(netIface.HWAddr, devMAC) {
								iface = netIface
								ok = true
								break
							}
						}
					}
					if ok {
						for _, a := range iface.Addresses {
							if a.Family == "inet" && a.Scope == "global" {
								m.IPv4 = a.Address
								break
							}
						}
					}
				}
			}
		}

		members = append(members, m)
	}
	return members, nil
}

// LXDNetwork represents a single LXD network as returned by lxc network list/show.
type LXDNetwork struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"` // "bridge", "physical", "vlan", etc.
	Managed     bool              `json:"managed"`
	Description string            `json:"description"`
	State       string            `json:"state"` // "Created" | ""
	IPv4        string            `json:"ipv4"`
	IPv6        string            `json:"ipv6"`
	Config      map[string]string `json:"config"`
	UsedBy      []string          `json:"used_by"` // raw /1.0/instances/... URIs
	VMCount     int               `json:"vm_count"`
	// Ports are the interfaces enslaved to this bridge (its bridge_ports),
	// read from the kernel. Without them the bridges table cannot say WHICH
	// physical NIC a bridge is actually carrying traffic on — the appliance
	// ships vmbr0/vmbr1/… and they are indistinguishable otherwise.
	Ports []string `json:"ports"`
	// Uplink is the physical NIC traffic leaves through for a NAT network.
	// A NAT bridge has no NIC enslaved to it — Incus masquerades onto the
	// host's default route — so without this the table could only say
	// "internal", which does not answer "which port does this actually use".
	// UplinkVia is the interface the default route points at (often a bridge,
	// e.g. vmbr0), and Uplink is the physical port under it.
	Uplink    string `json:"uplink"`
	UplinkVia string `json:"uplink_via"`
	// UplinkPinned is true when Uplink is the port the network was created
	// for (recorded on the network) rather than a guess from today's default
	// route. The UI says different things about the two.
	UplinkPinned bool `json:"uplink_pinned"`
	NAT          bool `json:"nat"`
}

// LXDNetworkCreateRequest holds parameters for creating a new LXD bridge network.
type LXDNetworkCreateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	BridgeType  string `json:"bridge_type"` // "nat" | "vlan" | "plain" | "isolated"
	MTU         int    `json:"mtu"`         // 0 = default (1500)
	// nat + isolated fields
	IPv4Address string `json:"ipv4_address"` // e.g. "10.10.10.1/24"
	IPv4NAT     bool   `json:"ipv4_nat"`
	IPv4DHCP    bool   `json:"ipv4_dhcp"`    // isolated only: hand out IPs from the CIDR (no NAT either way)
	IPv6Address string `json:"ipv6_address"` // e.g. "fd00::1/64" or "" for none
	IPv6NAT     bool   `json:"ipv6_nat"`
	// vlan/plain fields
	ParentInterface string `json:"parent_interface"` // e.g. "enxa0cec8cd42e7"
	VLANTag         int    `json:"vlan_tag"`         // >0 = create VLAN sub-interface
	VLANIfaceName   string `json:"vlan_iface_name"`  // optional override; auto-generated if empty
}

// LXDNetworkEditRequest holds editable fields for an existing LXD network.
type LXDNetworkEditRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Config      map[string]string `json:"config"`
}

// ListLXDNetworks returns all LXD networks with full detail.
func ListLXDNetworks() ([]LXDNetwork, error) {
	out, err := exec.Command("incus", "network", "list", "--format", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("lxc network list: %w", err)
	}
	var raw []struct {
		Name        string            `json:"name"`
		Type        string            `json:"type"`
		Managed     bool              `json:"managed"`
		Description string            `json:"description"`
		Status      string            `json:"status"`
		Config      map[string]string `json:"config"`
		UsedBy      []string          `json:"used_by"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	nets := make([]LXDNetwork, 0, len(raw))
	for _, r := range raw {
		n := LXDNetwork{
			Name:        r.Name,
			Type:        r.Type,
			Managed:     r.Managed,
			Description: r.Description,
			State:       r.Status,
			Config:      r.Config,
			UsedBy:      r.UsedBy,
		}
		if r.Config != nil {
			n.IPv4 = r.Config["ipv4.address"]
			n.IPv6 = r.Config["ipv6.address"]
		}
		// For unmanaged OS bridges LXD reports no IP; read it directly from the kernel.
		if !r.Managed && r.Type == "bridge" && n.IPv4 == "" {
			n.IPv4 = osBridgeIPv4(r.Name)
		}
		for _, u := range r.UsedBy {
			if strings.Contains(u, "/1.0/instances/") {
				n.VMCount++
			}
		}
		if r.Type == "bridge" {
			n.Ports = bridgePorts(r.Name)
			n.NAT = r.Config["ipv4.nat"] == "true" || r.Config["ipv6.nat"] == "true"
			if n.NAT {
				n.Uplink, n.UplinkVia = natUplinkFor(r.Name, r.Config)
				n.UplinkPinned = r.Config[HostNatUplinkKey] != ""
			}
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// parseDefaultRouteIface pulls the device out of `ip route show default`
// output, e.g. "default via 192.168.2.1 dev vmbr0 onlink" → "vmbr0".
// Split out from the command call so it can be tested without a host route.
func parseDefaultRouteIface(routeOutput string) string {
	for _, line := range strings.Split(routeOutput, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		for i := 0; i < len(f)-1; i++ {
			if f[i] == "dev" {
				return f[i+1]
			}
		}
	}
	return ""
}

// natUplinkFor returns the physical NIC a NAT network belongs to, plus the
// interface its traffic currently leaves by.
//
// The pairing is recorded on the network when it is created (one host-nat per
// addressed port), because it cannot be worked out afterwards: a NAT bridge has
// no physical port of its own. Without that key every NAT network would answer
// with whatever the default route says today — which is why two of them used to
// name the same NIC.
func natUplinkFor(name string, cfg map[string]string) (phys, via string) {
	_, defVia := natUplink()
	if nic := cfg[HostNatUplinkKey]; nic != "" {
		return nic, defVia
	}
	// Networks created before the key existed: our own are numbered in the same
	// order as the ports they were made for, so recover the pairing from the
	// position rather than showing the same NIC for all of them.
	if i := hostNatIndex(name); i >= 0 {
		if nics := physicalUplinkNICs(); i < len(nics) {
			return nics[i], defVia
		}
	}
	return natUplink()
}

// hostNatIndex maps host-nat → 0, host-nat2 → 1, … and -1 for anything else.
func hostNatIndex(name string) int {
	if !IsHostNatNetwork(name) {
		return -1
	}
	if name == "host-nat" {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimPrefix(name, "host-nat"))
	if err != nil || n < 2 {
		return -1
	}
	return n - 1
}

// natUplink returns the physical NIC the host's default route leaves through,
// plus the interface the route names (which is usually a bridge).
func natUplink() (phys, via string) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", ""
	}
	via = parseDefaultRouteIface(string(out))
	if via == "" {
		return "", ""
	}
	// If the route leaves through a bridge, the interesting answer is the
	// physical port underneath it, not the bridge name the user already sees.
	for _, p := range bridgePorts(via) {
		if !strings.HasPrefix(p, "veth") && !strings.HasPrefix(p, "tap") {
			return p, via
		}
	}
	return via, via
}

// bridgePorts lists the interfaces enslaved to a bridge, from
// /sys/class/net/<bridge>/brif. Empty for anything that is not a live kernel
// bridge (a managed network that has not been brought up yet, for instance).
func bridgePorts(name string) []string {
	entries, err := os.ReadDir("/sys/class/net/" + name + "/brif")
	if err != nil {
		return nil
	}
	ports := make([]string, 0, len(entries))
	for _, e := range entries {
		ports = append(ports, e.Name())
	}
	sort.Strings(ports)
	return ports
}

// osBridgeIPv4 returns the first IPv4 CIDR assigned to an OS bridge interface
// (e.g. "192.168.1.20/24"), or "" if none is found.
func osBridgeIPv4(name string) string {
	out, err := exec.Command("ip", "-4", "-j", "addr", "show", "dev", name).Output()
	if err != nil {
		return ""
	}
	var addrs []struct {
		AddrInfo []struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(out, &addrs); err != nil || len(addrs) == 0 {
		return ""
	}
	for _, a := range addrs[0].AddrInfo {
		if a.Local != "" {
			return fmt.Sprintf("%s/%d", a.Local, a.PrefixLen)
		}
	}
	return ""
}

// GetLXDNetwork returns detail for a single LXD network.
func GetLXDNetwork(name string) (LXDNetwork, error) {
	out, err := exec.Command("incus", "query", "/1.0/networks/"+name).Output()
	if err != nil {
		return LXDNetwork{}, fmt.Errorf("lxc network show: %w", err)
	}
	var r struct {
		Name        string            `json:"name"`
		Type        string            `json:"type"`
		Managed     bool              `json:"managed"`
		Description string            `json:"description"`
		Status      string            `json:"status"`
		Config      map[string]string `json:"config"`
		UsedBy      []string          `json:"used_by"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return LXDNetwork{}, err
	}
	n := LXDNetwork{
		Name:        r.Name,
		Type:        r.Type,
		Managed:     r.Managed,
		Description: r.Description,
		State:       r.Status,
		Config:      r.Config,
		UsedBy:      r.UsedBy,
	}
	if r.Config != nil {
		n.IPv4 = r.Config["ipv4.address"]
		n.IPv6 = r.Config["ipv6.address"]
	}
	for _, u := range r.UsedBy {
		if strings.Contains(u, "/1.0/instances/") {
			n.VMCount++
		}
	}
	return n, nil
}

// vlanIfaceName returns the kernel VLAN sub-interface name: <parent>-vlan<vid>.
// Linux interface names are limited to 15 characters (IFNAMSIZ-1), so the
// parent is truncated from the right if the full name would exceed that limit.
func vlanIfaceName(parent string, vid int) string {
	suffix := fmt.Sprintf("-v%d", vid)
	maxParent := 15 - len(suffix)
	if maxParent < 1 {
		maxParent = 1
	}
	p := parent
	if len(p) > maxParent {
		p = p[:maxParent]
	}
	return p + suffix
}

// znasManagedVLANComment is the marker written around ZNAS-created VLAN stanzas.
const znasManagedVLANStart = "# znas-managed-vlan-start"
const znasManagedVLANEnd = "# znas-managed-vlan-end"

// insertVLANStanzaAfterParent splices a ready-formatted VLAN stanza into the
// interfaces file directly below the parent NIC's stanza, so the VLAN
// sub-interfaces come up before ifup-a walks the bridge stanza further down.
// `stanza` is expected to already begin and end with newlines.
//
// If the parent NIC's `iface` line isn't found (rare; e.g. a hand-rolled
// interfaces file), the stanza is appended at the end — matching the old
// behaviour so we never silently lose the entry.
func insertVLANStanzaAfterParent(content, parent, stanza string) string {
	marker := "iface " + parent + " "
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), marker) {
			continue
		}
		// Walk forward to the end of the parent's stanza — the first
		// blank line, or the next stanza keyword.
		end := i + 1
		for end < len(lines) {
			t := strings.TrimSpace(lines[end])
			if t == "" ||
				strings.HasPrefix(t, "auto ") ||
				strings.HasPrefix(t, "allow-hotplug ") ||
				strings.HasPrefix(t, "iface ") ||
				strings.HasPrefix(t, "mapping ") {
				break
			}
			end++
		}
		head := strings.Join(lines[:end], "\n")
		tail := strings.Join(lines[end:], "\n")
		return head + "\n" + stanza + tail
	}
	return content + stanza
}

// forceRemoveVLANKernelInterface brings down and removes a kernel VLAN interface if it exists.
func forceRemoveVLANKernelInterface(iface string) {
	data, _ := os.ReadFile("/proc/net/dev")
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), iface+":") {
			found = true
			break
		}
	}
	if !found {
		return
	}
	exec.Command("sudo", "/sbin/ip", "link", "set", iface, "down").CombinedOutput()
	exec.Command("sudo", "/sbin/ip", "link", "del", iface).CombinedOutput()
}

// writeVLANInterfaceStanza appends a VLAN sub-interface stanza to /etc/network/interfaces.
func writeVLANInterfaceStanza(parent string, vid int) error {
	return writeVLANInterfaceStanzaCustom(parent, vid, vlanIfaceName(parent, vid))
}

// writeVLANInterfaceStanzaCustom is like writeVLANInterfaceStanza but uses a caller-supplied iface name.
func writeVLANInterfaceStanzaCustom(parent string, vid int, iface string) error {

	// If the kernel interface already exists (stale from a previous run), remove it
	// so that lxc network create doesn't fail with "already exists".
	forceRemoveVLANKernelInterface(iface)

	stanza := fmt.Sprintf(`
%s name=%s vid=%d
auto %s
iface %s inet manual
    pre-up ip link add link %s name %s type vlan id %d
    post-down ip link del %s
%s
`, znasManagedVLANStart, iface, vid,
		iface, iface, parent, iface, vid, iface,
		znasManagedVLANEnd)

	// Read current file.
	existing, _ := os.ReadFile("/etc/network/interfaces")

	// Remove any existing stanza for this iface before rewriting (handles re-create).
	if strings.Contains(string(existing), "auto "+iface) {
		removeVLANInterfaceStanza(iface)
		existing, _ = os.ReadFile("/etc/network/interfaces")
	}

	// Position the new VLAN stanza right after the parent NIC stanza so it
	// precedes the bridge stanza further down. `ifup -a` walks the file
	// top-to-bottom; on Ubuntu 26.04 a bridge stanza carrying a
	// `dns-nameservers` directive can stall ifup for ~270 s (three 90-s
	// resolvectl calls into a not-yet-ready systemd-resolved), and
	// networking.service hits its 5-minute deadline before reaching any
	// stanza below the bridge. Appending VLAN stanzas at the end meant
	// they routinely never came up at boot — leaving every vmbr0-* bridge
	// without an uplink and every guest on those bridges isolated. By
	// placing the VLAN block above the bridge, `ifup` brings the VLAN
	// sub-interfaces up cleanly (they have no dns-* directives, so no
	// resolvectl hang) before it ever touches the bridge stanza.
	newContent := insertVLANStanzaAfterParent(string(existing), parent, stanza)

	// /etc/network/interfaces edits go through writeInterfacesFile (root → direct
	// I/O; sudo-all → "sudo tee"); the hardened sudoers template grants no entry
	// for this path, so neither hardened nor "none" mode can write it.
	sudoMode := CheckSudoAccess().Type
	if sudoMode != "root" && sudoMode != "all" {
		return fmt.Errorf("editing /etc/network/interfaces requires running as root or having unrestricted sudo (sudo-all)")
	}
	if err := writeInterfacesFile("/etc/network/interfaces", []byte(newContent)); err != nil {
		return fmt.Errorf("write interfaces: %w", err)
	}

	// Bring the interface up immediately.
	if out, err := exec.Command("sudo", "/usr/sbin/ifup", iface).CombinedOutput(); err != nil {
		_ = out
	}
	return nil
}

// DeleteVLANInterface removes a kernel VLAN sub-interface and, if present, its
// ZNAS-managed /etc/network/interfaces stanza.
func DeleteVLANInterface(name string) error {
	// Remove stanza if ZNAS wrote one (best-effort; may already be gone from a
	// failed create rollback).
	existing, _ := os.ReadFile("/etc/network/interfaces")
	if strings.Contains(string(existing), " name="+name+" ") {
		removeVLANInterfaceStanza(name)
	}
	forceRemoveVLANKernelInterface(name)
	return nil
}

// removeVLANInterfaceStanza removes ZNAS-managed VLAN stanzas for the given iface
// from /etc/network/interfaces and brings the interface down.
func removeVLANInterfaceStanza(iface string) {
	existing, err := os.ReadFile("/etc/network/interfaces")
	if err != nil {
		return
	}
	content := string(existing)

	// Find and remove the znas-managed block containing this iface name.
	for {
		startIdx := strings.Index(content, znasManagedVLANStart)
		if startIdx < 0 {
			break
		}
		endIdx := strings.Index(content[startIdx:], znasManagedVLANEnd)
		if endIdx < 0 {
			break
		}
		block := content[startIdx : startIdx+endIdx+len(znasManagedVLANEnd)]
		if strings.Contains(block, " name="+iface+" ") {
			// Remove this block plus any surrounding blank lines.
			content = strings.Replace(content, block, "", 1)
			content = strings.ReplaceAll(content, "\n\n\n", "\n\n")
		} else {
			break
		}
	}

	// Best-effort write; succeeds when running as root or with sudo-all.
	if mode := CheckSudoAccess().Type; mode == "root" || mode == "all" {
		_ = writeInterfacesFile("/etc/network/interfaces", []byte(content))
	}

	// Best-effort bring-down.
	exec.Command("sudo", "/usr/sbin/ifdown", iface).CombinedOutput()
}

// setLXDNetworkDescription sets the description of an LXD network via the REST API.
// lxc network set does not accept description as a config key; PATCH /1.0/networks
// is the correct approach.
func setLXDNetworkDescription(name, description string) error {
	payload := fmt.Sprintf(`{"description":%q}`, description)
	if out, err := exec.Command("incus", "query", "--wait", "-X", "PATCH",
		"/1.0/networks/"+name, "-d", payload).CombinedOutput(); err != nil {
		return fmt.Errorf("set description: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// CreateLXDNetwork creates a new LXD bridge network and, for VLAN-backed bridges,
// writes the necessary /etc/network/interfaces stanza.

// hostManagedBridgeSource reports which host network config file defines a
// bridge of this name ("" when none does). Used to stop an Incus managed
// network from colliding with a bridge netplan/ifupdown already owns.
// Overridable in tests.
var (
	netplanDirForTest     = "/etc/netplan"
	interfacesFileForTest = "/etc/network/interfaces"
)

func hostManagedBridgeSource(name string) string {
	if name == "" {
		return ""
	}
	// netplan: the bridge appears as a key under `bridges:`; matching the
	// name followed by a colon is enough to spot it in any of the yaml files.
	if entries, err := os.ReadDir(netplanDirForTest); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			path := netplanDirForTest + "/" + e.Name()
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(b), "\n") {
				if strings.TrimSpace(line) == name+":" {
					return path
				}
			}
		}
	}
	// ifupdown: `iface <name> inet …`
	if b, err := os.ReadFile(interfacesFileForTest); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "iface" && f[1] == name {
				return interfacesFileForTest
			}
		}
	}
	return ""
}

func CreateLXDNetwork(req LXDNetworkCreateRequest) error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	// Refuse to take over a bridge the HOST already manages (netplan or
	// /etc/network/interfaces). Incus would happily create a managed network
	// of the same name and put its own address on that interface: the box
	// then has two managers for one bridge, the host's DHCP lease disappears
	// and — when it is the LAN bridge — the portal becomes unreachable. The
	// USB appliance ships vmbr0/vmbr1 configured this way, so this is a live
	// footgun there, not a theoretical one.
	if owner := hostManagedBridgeSource(req.Name); owner != "" {
		return fmt.Errorf("%q is already a host-managed bridge (defined in %s). "+
			"Creating an Incus network with the same name would take the interface over and "+
			"drop its address — pick a different name, or attach instances to %q directly",
			req.Name, owner, req.Name)
	}

	mtuArg := ""
	if req.MTU > 0 && req.MTU != 1500 {
		mtuArg = fmt.Sprintf("bridge.mtu=%d", req.MTU)
	}

	switch req.BridgeType {
	case "nat":
		ipv4 := req.IPv4Address
		if ipv4 == "" {
			ipv4 = "none"
		}
		ipv6 := req.IPv6Address
		if ipv6 == "" {
			ipv6 = "none"
		}
		args := []string{"network", "create", req.Name,
			"ipv4.address=" + ipv4,
			fmt.Sprintf("ipv4.nat=%v", req.IPv4NAT),
			"ipv6.address=" + ipv6,
		}
		if ipv6 != "none" {
			args = append(args, fmt.Sprintf("ipv6.nat=%v", req.IPv6NAT))
		}
		if mtuArg != "" {
			args = append(args, mtuArg)
		}
		if out, err := exec.Command("incus", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("lxc network create: %s", strings.TrimSpace(string(out)))
		}
		if req.Description != "" {
			if err := setLXDNetworkDescription(req.Name, req.Description); err != nil {
				return err
			}
		}

	case "vlan":
		if req.ParentInterface == "" {
			return fmt.Errorf("parent interface is required for VLAN bridge")
		}
		if req.VLANTag < 1 || req.VLANTag > 4094 {
			return fmt.Errorf("VLAN tag must be 1-4094")
		}
		vlanIface := req.VLANIfaceName
		if vlanIface == "" {
			vlanIface = vlanIfaceName(req.ParentInterface, req.VLANTag)
		}
		if len(vlanIface) > 15 {
			return fmt.Errorf("VLAN interface name %q exceeds 15-character Linux limit", vlanIface)
		}
		if req.Name == vlanIface {
			return fmt.Errorf("bridge name cannot be the same as the VLAN interface name (%s)", vlanIface)
		}
		if err := writeVLANInterfaceStanzaCustom(req.ParentInterface, req.VLANTag, vlanIface); err != nil {
			return err
		}
		args := []string{"network", "create", req.Name,
			"bridge.external_interfaces=" + vlanIface,
			"ipv4.address=none",
			"ipv6.address=none",
		}
		if mtuArg != "" {
			args = append(args, mtuArg)
		}
		if out, err := exec.Command("incus", args...).CombinedOutput(); err != nil {
			removeVLANInterfaceStanza(vlanIface)
			return fmt.Errorf("lxc network create: %s", strings.TrimSpace(string(out)))
		}
		if req.Description != "" {
			if err := setLXDNetworkDescription(req.Name, req.Description); err != nil {
				return err
			}
		}

	case "isolated":
		// Internal-only virtual switch for VMs/CTs: no uplink, no NAT, no
		// physical interface. With a CIDR the host holds the bridge IP (and
		// dnsmasq can hand out leases when ipv4_dhcp); with none it is a pure
		// L2 segment — guests bring their own addressing.
		ipv4 := req.IPv4Address
		if ipv4 == "" {
			ipv4 = "none"
		}
		args := []string{"network", "create", req.Name,
			"ipv4.address=" + ipv4,
			"ipv6.address=none",
		}
		if ipv4 != "none" {
			args = append(args, "ipv4.nat=false")
			args = append(args, fmt.Sprintf("ipv4.dhcp=%v", req.IPv4DHCP))
		}
		if mtuArg != "" {
			args = append(args, mtuArg)
		}
		if out, err := exec.Command("incus", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("lxc network create: %s", strings.TrimSpace(string(out)))
		}
		if req.Description != "" {
			if err := setLXDNetworkDescription(req.Name, req.Description); err != nil {
				return err
			}
		}

	case "plain":
		if req.ParentInterface == "" {
			return fmt.Errorf("parent interface is required for plain bridge")
		}
		// A NIC can only be a port of one bridge: Incus would silently steal
		// it from its current master, cutting the host's uplink if that
		// master carries the management IP.
		if m := ifaceMaster(req.ParentInterface); m != "" {
			return fmt.Errorf("interface %s is already a port of %q — moving it into a new bridge would disconnect %q (and possibly this server). Pick a free interface, or create a VLAN bridge on top of %s instead", req.ParentInterface, m, m, req.ParentInterface)
		}
		args := []string{"network", "create", req.Name,
			"bridge.external_interfaces=" + req.ParentInterface,
			"ipv4.address=none",
			"ipv6.address=none",
		}
		if mtuArg != "" {
			args = append(args, mtuArg)
		}
		if out, err := exec.Command("incus", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("lxc network create: %s", strings.TrimSpace(string(out)))
		}
		if req.Description != "" {
			if err := setLXDNetworkDescription(req.Name, req.Description); err != nil {
				return err
			}
		}

	default:
		return fmt.Errorf("unknown bridge type: %s", req.BridgeType)
	}
	return nil
}

// EditLXDNetwork updates description and config keys of an existing LXD network.
func EditLXDNetwork(req LXDNetworkEditRequest) error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	if err := setLXDNetworkDescription(req.Name, req.Description); err != nil {
		return err
	}
	// Apply config keys in a safe order: *address keys FIRST. Dependent keys
	// (ipv4.dhcp/nat, ipv4.dhcp.ranges, dns.*) are rejected by Incus unless the
	// address is already set, and Go map iteration is random — so without this
	// ordering a single edit could intermittently fail with e.g.
	// "Cannot use ipv4.dhcp when ipv4.address is unset".
	keys := make([]string, 0, len(req.Config))
	for k := range req.Config {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ai, aj := strings.Contains(keys[i], "address"), strings.Contains(keys[j], "address")
		if ai != aj {
			return ai // address keys sort first
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		v := req.Config[k]
		if v == "" {
			if out, err := exec.Command("incus", "network", "unset", req.Name, k).CombinedOutput(); err != nil {
				return fmt.Errorf("unset %s: %s", k, strings.TrimSpace(string(out)))
			}
		} else {
			if out, err := exec.Command("incus", "network", "set", req.Name, k, v).CombinedOutput(); err != nil {
				return fmt.Errorf("set %s: %s", k, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

// DeleteLXDNetwork deletes an LXD network. If the network had a ZNAS-managed VLAN
// sub-interface, that stanza is also removed from /etc/network/interfaces.
// Profile references to the network are automatically removed before deletion.
func DeleteLXDNetwork(name string) error {
	// Get network detail first so we can check for VLAN external interfaces.
	net, err := GetLXDNetwork(name)
	if err != nil {
		return err
	}
	if net.VMCount > 0 {
		return fmt.Errorf("network is in use by %d running instance(s)", net.VMCount)
	}

	// Detach the network from any profiles that reference it.
	// LXD counts profile references as "in use" even when no VMs exist.
	for _, ref := range net.UsedBy {
		if !strings.Contains(ref, "/1.0/profiles/") {
			continue
		}
		profileName := ref[strings.LastIndex(ref, "/")+1:]
		// Find which device in this profile uses our network.
		if out, e := exec.Command("incus", "profile", "show", profileName).Output(); e == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				// Matches "network: <name>" inside a devices block.
				if line == "network: "+name {
					// The device name is the previous non-empty parent key — easier to
					// just remove any nic device whose network matches.
					removeProfileNICByNetwork(profileName, name)
					break
				}
			}
		}
	}

	externalIface := ""
	if net.Config != nil {
		externalIface = net.Config["bridge.external_interfaces"]
	}

	if out, err := exec.Command("incus", "network", "delete", name).CombinedOutput(); err != nil {
		return fmt.Errorf("lxc network delete: %s", strings.TrimSpace(string(out)))
	}

	// Remove VLAN stanza if ZNAS created it.
	if externalIface != "" {
		existing, _ := os.ReadFile("/etc/network/interfaces")
		if strings.Contains(string(existing), "# znas-managed-vlan-start") &&
			strings.Contains(string(existing), " name="+externalIface+" ") {
			removeVLANInterfaceStanza(externalIface)
		}
	}
	return nil
}

// removeProfileNICByNetwork removes any NIC device from a profile that has
// "network: <networkName>" in its config (used before deleting an LXD network).
func removeProfileNICByNetwork(profileName, networkName string) {
	out, err := exec.Command("incus", "profile", "show", profileName, "--format", "json").Output()
	if err != nil {
		return
	}
	var profile struct {
		Devices map[string]map[string]string `json:"devices"`
	}
	if json.Unmarshal(out, &profile) != nil {
		return
	}
	for devName, dev := range profile.Devices {
		if dev["type"] == "nic" && dev["network"] == networkName {
			exec.Command("incus", "profile", "device", "remove", profileName, devName).Run() //nolint:errcheck
		}
	}
}

// isVLANSubIface returns true if iface looks like a ZNAS-generated VLAN
// sub-interface of the form <parent>-v<digits>.
func isVLANSubIface(iface string) bool {
	idx := strings.LastIndex(iface, "-v")
	if idx < 0 {
		return false
	}
	rest := iface[idx+2:]
	if len(rest) == 0 {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// SetInterfaceMTU sets the MTU on a host network interface via `ip link set`.
func SetInterfaceMTU(iface string, mtu int) error {
	if mtu < 576 || mtu > 9000 {
		return fmt.Errorf("MTU must be between 576 and 9000")
	}
	out, err := exec.Command("sudo", "ip", "link", "set", iface, "mtu", fmt.Sprintf("%d", mtu)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link set mtu: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// GetInterfaceMTU reads the current MTU for a host network interface.
func GetInterfaceMTU(iface string) (int, error) {
	data, err := os.ReadFile("/sys/class/net/" + iface + "/mtu")
	if err != nil {
		return 0, err
	}
	mtu, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", new(int))
	if err != nil || mtu == 0 {
		return 0, fmt.Errorf("could not parse MTU")
	}
	var v int
	fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &v)
	return v, nil
}

// ifaceMaster returns the name of the bridge (or bond) the interface is
// currently enslaved to, read from /sys/class/net/<iface>/master, or "" when
// the interface is free.
func ifaceMaster(iface string) string {
	target, err := os.Readlink("/sys/class/net/" + iface + "/master")
	if err != nil {
		return ""
	}
	if i := strings.LastIndexByte(target, '/'); i >= 0 {
		target = target[i+1:]
	}
	return target
}

// PhysicalInterface describes a host NIC offered as a bridge parent. Master is
// the bridge/bond the NIC is currently enslaved to ("" when free) — attaching
// such a NIC to a new plain bridge would steal it from that master and can
// take the host off the network.
type PhysicalInterface struct {
	Name   string `json:"name"`
	Master string `json:"master,omitempty"`
}

// ListPhysicalInterfaces returns non-virtual, non-loopback network interfaces
// suitable for use as the parent of a VLAN or plain external bridge.
func ListPhysicalInterfaces() ([]PhysicalInterface, error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	skip := []string{"lo", "lxd", "incus", "veth", "tap", "virbr", "docker", "br-", "vmbr0-"}
	var names []PhysicalInterface
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ":") {
			continue
		}
		iface := strings.SplitN(line, ":", 2)[0]
		iface = strings.TrimSpace(iface)
		if iface == "" {
			continue
		}
		bad := strings.Contains(iface, "-vlan") || isVLANSubIface(iface)
		if !bad {
			for _, pfx := range skip {
				if strings.HasPrefix(iface, pfx) {
					bad = true
					break
				}
			}
		}
		if !bad {
			// The name-prefix skip list misses user-named bridges (vmbr0,
			// mybr…): a bridge can't be the parent of another bridge, so
			// detect them structurally. Wi-Fi NICs can't be bridge ports
			// either (802.11 rejects enslaving without 4addr mode).
			if _, err := os.Stat("/sys/class/net/" + iface + "/bridge"); err == nil {
				bad = true
			} else if _, err := os.Stat("/sys/class/net/" + iface + "/wireless"); err == nil {
				bad = true
			}
		}
		if !bad {
			names = append(names, PhysicalInterface{Name: iface, Master: ifaceMaster(iface)})
		}
	}
	return names, nil
}

// BridgeStats holds cumulative rx/tx byte counters read from /proc/net/dev.
type BridgeStats struct {
	Interface string        `json:"interface"`
	RxBytes   int64         `json:"rx_bytes"`
	TxBytes   int64         `json:"tx_bytes"`
	Members   []BridgeStats `json:"members,omitempty"`
}

// readIfaceBytes reads rx_bytes and tx_bytes for a single interface from a
// pre-read /proc/net/dev byte slice. Returns (rx, tx, ok).
func readIfaceBytes(data []byte, iface string) (int64, int64, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		colon := strings.IndexByte(line, ':')
		if colon < 0 || strings.TrimSpace(line[:colon]) != iface {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 9 {
			return 0, 0, false
		}
		var rx, tx int64
		fmt.Sscanf(fields[0], "%d", &rx)
		fmt.Sscanf(fields[8], "%d", &tx)
		return rx, tx, true
	}
	return 0, 0, false
}

// bridgePhysMembers returns the physical/VLAN member interfaces of a bridge by
// reading /sys/class/net/<bridge>/brif/. Virtual kernel links (veth*, tap*,
// macvtap*) used by containers and VMs are excluded; only real uplink
// interfaces such as eth0, eth0.100, bond0, etc. are returned.
func bridgePhysMembers(bridge string) []string {
	entries, err := os.ReadDir("/sys/class/net/" + bridge + "/brif")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "veth") ||
			strings.HasPrefix(name, "tap") ||
			strings.HasPrefix(name, "macvtap") {
			continue
		}
		out = append(out, name)
	}
	return out
}

// GetBridgeStats reads /proc/net/dev and returns cumulative rx/tx byte counters
// for the named bridge interface plus any physical/VLAN member interfaces.
func GetBridgeStats(iface string) (BridgeStats, error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return BridgeStats{}, err
	}
	rx, tx, ok := readIfaceBytes(data, iface)
	if !ok {
		return BridgeStats{}, fmt.Errorf("interface %q not found in /proc/net/dev", iface)
	}
	result := BridgeStats{Interface: iface, RxBytes: rx, TxBytes: tx}
	for _, member := range bridgePhysMembers(iface) {
		mrx, mtx, mok := readIfaceBytes(data, member)
		if mok {
			result.Members = append(result.Members, BridgeStats{Interface: member, RxBytes: mrx, TxBytes: mtx})
		}
	}
	return result, nil
}

// LXDStoragePool describes an LXD storage pool.
type LXDStoragePool struct {
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	Driver        string            `json:"driver"`
	Status        string            `json:"status"`
	Config        map[string]string `json:"config"`
	Source        string            `json:"source"`
	InstanceCount int               `json:"instance_count"`
}

// LXDListStoragePoolInfos returns all LXD storage pools with full detail.
func LXDListStoragePoolInfos() ([]LXDStoragePool, error) {
	out, err := exec.Command("incus", "storage", "list", "--format", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("lxc storage list: %w", err)
	}
	var raw []struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Driver      string            `json:"driver"`
		Status      string            `json:"status"`
		Config      map[string]string `json:"config"`
		UsedBy      []string          `json:"used_by"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	pools := make([]LXDStoragePool, 0, len(raw))
	for _, r := range raw {
		count := 0
		for _, u := range r.UsedBy {
			if strings.Contains(u, "/1.0/instances/") {
				count++
			}
		}
		source := ""
		if r.Config != nil {
			source = r.Config["source"]
		}
		pools = append(pools, LXDStoragePool{
			Name:          r.Name,
			Description:   r.Description,
			Driver:        r.Driver,
			Status:        r.Status,
			Config:        r.Config,
			Source:        source,
			InstanceCount: count,
		})
	}
	return pools, nil
}

// GetStoragePoolMembers returns instances that live on the named LXD storage pool.
func GetStoragePoolMembers(pool string) ([]BridgeMember, error) {
	poolOut, err := exec.Command("incus", "query", "/1.0/storage-pools/"+pool).Output()
	if err != nil {
		// The datastore may be a ZFS pool with no matching Incus storage pool
		// (e.g. a backup-only destination), or a pool on a server that has no
		// instances at all. Either way there are no VM/container members to show —
		// return an empty list rather than surfacing a raw "exit status 1" error.
		if DebugMode {
			log.Printf("[lxd] storage-pool %q has no queryable Incus pool (%v) — returning no members", pool, err)
		}
		return []BridgeMember{}, nil
	}
	var poolData struct {
		UsedBy []string `json:"used_by"`
	}
	if err := json.Unmarshal(poolOut, &poolData); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var members []BridgeMember
	for _, uri := range poolData.UsedBy {
		if !strings.Contains(uri, "/1.0/instances/") {
			continue
		}
		instName := uri[strings.LastIndex(uri, "/")+1:]
		if seen[instName] {
			continue
		}
		seen[instName] = true
		cfgOut, err := exec.Command("incus", "query", "/1.0/instances/"+instName).Output()
		if err != nil {
			continue
		}
		var inst struct {
			Type            string                       `json:"type"`
			Description     string                       `json:"description"`
			Status          string                       `json:"status"`
			Config          map[string]string            `json:"config"`
			ExpandedConfig  map[string]string            `json:"expanded_config"`
			ExpandedDevices map[string]map[string]string `json:"expanded_devices"`
		}
		if err := json.Unmarshal(cfgOut, &inst); err != nil {
			continue
		}
		img := inst.Config["image.description"]
		if img == "" {
			img = strings.TrimSpace(inst.Config["image.os"] + " " + inst.Config["image.version"])
		}
		rootPool := pool // we already know the pool; use it as fallback
		for _, dev := range inst.ExpandedDevices {
			if dev["type"] == "disk" && dev["path"] == "/" && dev["pool"] != "" {
				rootPool = dev["pool"]
				break
			}
		}
		m := BridgeMember{
			Name:        instName,
			Type:        inst.Type,
			Status:      inst.Status,
			Description: inst.Description,
			Image:       img,
			CPULimit:    inst.ExpandedConfig["limits.cpu"],
			MemoryLimit: inst.ExpandedConfig["limits.memory"],
			RootPool:    rootPool,
		}
		if inst.Status == "Running" {
			stateOut, err2 := exec.Command("incus", "query", "/1.0/instances/"+instName+"/state").Output()
			if err2 == nil {
				var state struct {
					Network map[string]struct {
						Addresses []struct {
							Family  string `json:"family"`
							Address string `json:"address"`
							Scope   string `json:"scope"`
						} `json:"addresses"`
					} `json:"network"`
				}
				if json.Unmarshal(stateOut, &state) == nil {
				outer:
					for dev, iface := range state.Network {
						if dev == "lo" {
							continue
						}
						for _, addr := range iface.Addresses {
							if addr.Family == "inet" && addr.Scope == "global" {
								m.IPv4 = addr.Address
								break outer
							}
						}
					}
				}
			}
		}
		members = append(members, m)
	}
	return members, nil
}

// LXDCreateStoragePool creates a new ZFS-backed LXD storage pool.
func LXDCreateStoragePool(name, zfsDataset string) error {
	out, err := exec.Command("incus", "storage", "create", name, "zfs", "source="+zfsDataset).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// LXDDeleteStoragePool deletes an LXD storage pool.
func LXDDeleteStoragePool(name string) error {
	out, err := exec.Command("incus", "storage", "delete", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// LXDStoragePoolEditRequest holds the fields the user may change on an existing pool.
type LXDStoragePoolEditRequest struct {
	Description           string `json:"description"`
	VolumeSize            string `json:"volume_size"`              // volume.size
	RemoveSnapshotsOnFull *bool  `json:"remove_snapshots_on_full"` // volume.zfs.remove_snapshots
	UseRefquota           *bool  `json:"use_refquota"`             // volume.zfs.use_refquota
}

// LXDEditStoragePool applies editable settings to an existing LXD storage pool via
// PATCH /1.0/storage-pools/<name>.
func LXDEditStoragePool(name string, req LXDStoragePoolEditRequest) error {
	cfg := map[string]string{}
	if req.VolumeSize != "" {
		cfg["volume.size"] = req.VolumeSize
	}
	if req.RemoveSnapshotsOnFull != nil {
		if *req.RemoveSnapshotsOnFull {
			cfg["volume.zfs.remove_snapshots"] = "true"
		} else {
			cfg["volume.zfs.remove_snapshots"] = "false"
		}
	}
	if req.UseRefquota != nil {
		if *req.UseRefquota {
			cfg["volume.zfs.use_refquota"] = "true"
		} else {
			cfg["volume.zfs.use_refquota"] = "false"
		}
	}
	payload := map[string]interface{}{
		"description": req.Description,
		"config":      cfg,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	out, err := exec.Command("incus", "query", "--request", "PATCH",
		"/1.0/storage-pools/"+name, "--data", string(data)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}
