package system

// Compatibility between the Firewall (SDN) and the VMs & Containers feature:
// adopting Incus-managed L2 bridges, refusing VLAN name collisions both ways,
// and marking Firewall-owned networks on the Infrastructure page.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"zfsnas/internal/sdn"
)

// sdnIncusNetKey reads one config key of an Incus network ("" if absent).
var sdnIncusNetKey = func(name, key string) string {
	if !IncusUsable() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "incus", "network", "get", name, key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// sdnIncusSetAddr gives an adopted Incus bridge the Firewall's address (or
// none). Incus' own DHCP, NAT, DNS and firewall stay off on it — an address
// on a managed bridge otherwise silently starts dnsmasq DHCP+NAT — and the
// network is tagged user.znas.sdn so Infrastructure shows it as the
// Firewall's.
func sdnIncusSetAddr(dev string, in *sdn.Interface) error {
	if in == nil { // released
		if _, err := sdnRun.Run(nil, "incus", "network", "set", dev, "ipv4.address=none"); err != nil {
			return err
		}
		sdnRun.Run(nil, "incus", "network", "unset", dev, "user.znas.sdn") //nolint:errcheck
		return nil
	}
	addr := "none"
	if in.IPv4Mode == "static" {
		addr = in.IPv4
	}
	_, err := sdnRun.Run(nil, "incus", "network", "set", dev, "ipv4.address="+addr, "ipv4.nat=false", "ipv4.dhcp=false",
		"ipv4.firewall=false", "dns.mode=none", "ipv6.address=none", "user.znas.sdn=true")
	return err
}

// sdnReleaseIncusBridges hands adopted bridges back to VMs & Containers when
// the Firewall is turned off. A kept one never left Incus.
func sdnReleaseIncusBridges(c *sdn.Config) {
	for _, in := range c.Interfaces {
		if in.Kind == "incus" && !in.IncusKeep {
			_ = sdnIncusSetAddr(in.Device, nil)
		}
	}
}

// sdnSyncIncusKept reads what Incus has on the networks that keep their
// settings. An unanswered address (Incus down, address removed) leaves the
// interface as it is. Returns whether anything changed.
func sdnSyncIncusKept(c *sdn.Config) bool {
	changed := false
	for i := range c.Interfaces {
		in := &c.Interfaces[i]
		if !in.IncusKeep {
			continue
		}
		addr := sdnIncusNetKey(in.Device, "ipv4.address")
		if addr == "" || addr == "none" {
			continue
		}
		dhcp := sdnIncusNetKey(in.Device, "ipv4.dhcp") != "false"
		dns := sdnIncusNetKey(in.Device, "dns.mode") != "none"
		if in.IPv4 != addr || in.IncusDHCP != dhcp || in.IncusDNS != dns {
			in.IPv4, in.IncusDHCP, in.IncusDNS = addr, dhcp, dns
			changed = true
		}
	}
	return changed
}

// SDNIncusNetworkChanged brings the Firewall up to date after an Incus network
// it uses was edited in VMs & Containers.
func SDNIncusNetworkChanged(name, user string) error {
	if sdnConfigDir == "" {
		return nil
	}
	if state, _ := (sdn.Store{Dir: sdnConfigDir}).LoadState(); !state.Enabled {
		return nil
	}
	return sdnInstanceChange(user, "Incus network "+name+" changed", func(c *sdn.Config) bool {
		return sdnSyncIncusKept(c)
	})
}

// FirewallUsesNetwork refuses deleting an Incus network the Firewall has
// rules for, whoever owns its addressing.
func FirewallUsesNetwork(name string) error {
	if sdnConfigDir == "" {
		return nil
	}
	st := sdn.Store{Dir: sdnConfigDir}
	if state, _ := st.LoadState(); !state.Enabled {
		return nil
	}
	c, err := st.LoadConfirmed()
	if err != nil {
		return nil
	}
	for _, in := range c.Interfaces {
		if in.Kind == "incus" && in.Device == name {
			return fmt.Errorf("%s is used by the Firewall as %s — remove it from Firewall → Interfaces first", name, in.Name)
		}
	}
	return nil
}

// sdnApplyIncus brings adopted Incus bridges from prev to next.
func sdnApplyIncus(prev, next *sdn.Config, res *SDNApplyResult) error {
	was := map[string]sdn.Interface{}
	if prev != nil {
		for _, in := range prev.Interfaces {
			if in.Kind == "incus" && !in.IncusKeep {
				was[in.ID] = in
			}
		}
	}
	for _, in := range next.Interfaces {
		if in.Kind != "incus" || in.IncusKeep {
			continue
		}
		p, ok := was[in.ID]
		delete(was, in.ID)
		if ok && p.Device == in.Device && p.IPv4Mode == in.IPv4Mode && p.IPv4 == in.IPv4 {
			continue
		}
		if ok && p.Device != in.Device {
			if err := linkErr(res, sdnIncusSetAddr(p.Device, nil)); err != nil {
				return err
			}
		}
		in := in
		if err := linkErr(res, sdnIncusSetAddr(in.Device, &in)); err != nil {
			return fmt.Errorf("%s: %w", in.Name, err)
		}
		res.ChangedDevices = append(res.ChangedDevices, in.Device)
	}
	for _, p := range was {
		if err := linkErr(res, sdnIncusSetAddr(p.Device, nil)); err != nil {
			return err
		}
	}
	return nil
}

// sdnVLANConflicts lists the new SDN VLANs whose device another owner
// already defines (the VMs & Containers feature, a hand edit) or that exists
// in the kernel without being SDN's.
func sdnVLANConflicts(prev, next *sdn.Config, file string) []string {
	ours := map[string]bool{}
	for _, d := range sdn.OwnedIfaces(file) {
		ours[d] = true
	}
	had := map[string]bool{}
	if prev != nil {
		for _, in := range prev.Interfaces {
			if in.Owned {
				had[in.ID] = true
			}
		}
	}
	var out []string
	for _, in := range next.Interfaces {
		if !in.Owned || in.Disabled || had[in.ID] || ours[in.Device] {
			continue
		}
		if _, err := os.Stat(sdnSysClassNet + "/" + in.Device); err == nil || definedIn(file, in.Device) {
			out = append(out, in.Device)
		}
	}
	return out
}

func definedIn(file, dev string) bool {
	for _, m := range ifaceDefRe.FindAllStringSubmatch(file, -1) {
		if m[1] == dev {
			return true
		}
	}
	return false
}

// sdnConfigDir is the portal config dir (set at startup by
// SDNSetConfigDir) — ownership checks read the Firewall's confirmed config
// from it.
var sdnConfigDir string

// firewallOwnedNames: everything defined inside the SDN blocks, plus every
// device the enabled Firewall manages (adopted ports and bridges too —
// it rewrites their addressing).
func firewallOwnedNames() map[string]bool {
	m := map[string]bool{}
	if b, err := os.ReadFile(hostInterfacesPath); err == nil {
		for _, d := range sdn.OwnedIfaces(string(b)) {
			m[d] = true
		}
	}
	if sdnConfigDir != "" {
		st := sdn.Store{Dir: sdnConfigDir}
		if state, _ := st.LoadState(); state.Enabled {
			if c, err := st.LoadConfirmed(); err == nil {
				for _, in := range c.Interfaces {
					if in.IncusKeep {
						continue // Incus still owns it
					}
					m[in.Device], m[in.L3Device()] = true, true
				}
			}
		}
	}
	return m
}

// markFirewallOwned flags the networks the Firewall manages: its own
// bridges/VLANs (ifupdown blocks) and adopted Incus bridges (user.znas.sdn).
func markFirewallOwned(nets []LXDNetwork) {
	owned := firewallOwnedNames()
	for i := range nets {
		if owned[nets[i].Name] || nets[i].Config["user.znas.sdn"] == "true" {
			nets[i].FirewallOwned = true
		}
	}
}

// FirewallOwnsNetwork refuses Infrastructure edits of a Firewall-owned
// network: two owners would fight over its addressing.
func FirewallOwnsNetwork(name string) error {
	if firewallOwnedNames()[name] || sdnIncusNetKey(name, "user.znas.sdn") == "true" {
		return fmt.Errorf("%s is managed by the Firewall — change it from Firewall → Interfaces", name)
	}
	return nil
}

// sdnVLANOwnedByFirewall refuses a VLAN device the Firewall already defines
// (VMs & Containers side of the name-collision check).
func sdnVLANOwnedByFirewall(dev string) error {
	if firewallOwnedNames()[dev] {
		return fmt.Errorf("VLAN %s already exists — it is managed by the Firewall (Firewall → Interfaces); attach VMs to it there with \"Allow VMs\"", dev)
	}
	return nil
}
