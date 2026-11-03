package sdn

import (
	"fmt"
	"net/netip"
	"strings"
)

// VirtualIP is an extra address of an interface, inside that interface's own
// network. It is not this server's own address: it can be released here and
// taken up by another server (a gateway address the clients keep using)
// without touching either server's management address.
type VirtualIP struct {
	Address     string `json:"address"` // plain IPv4 address; the prefix is the interface's
	Description string `json:"description,omitempty"`
	// ForClients: DHCP on this network hands it out as the clients' gateway
	// (and DNS server when DNS answers there) instead of the interface address.
	ForClients bool `json:"for_clients,omitempty"`
}

const maxVirtualIPs = 8

// VIPPrefixes returns the interface's virtual IPs with the interface's prefix
// length (how they are added to the device).
func (in Interface) VIPPrefixes() []netip.Prefix {
	pfx, err := netip.ParsePrefix(in.IPv4)
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, v := range in.VirtualIPs {
		if a, err := netip.ParseAddr(v.Address); err == nil {
			out = append(out, netip.PrefixFrom(a, pfx.Bits()))
		}
	}
	return out
}

// clientsVIP is the virtual IP DHCP hands out on that interface ("" = none).
func (in *Interface) clientsVIP() string {
	if in == nil || in.IPv4Mode != "static" {
		return ""
	}
	for _, v := range in.VirtualIPs {
		if v.ForClients {
			return v.Address
		}
	}
	return ""
}

// validateVIPs checks every interface's virtual IPs: inside its network, not
// its network or broadcast address, not an address used anywhere else in the
// configuration, outside its DHCP range and reservations.
func (c *Config) validateVIPs(add func(path, format string, a ...any)) {
	used := map[netip.Addr]string{}
	for _, in := range c.Interfaces {
		if pfx, err := netip.ParsePrefix(in.IPv4); err == nil && in.IPv4Mode == "static" {
			used[pfx.Addr()] = in.Name
		}
	}
	for i, in := range c.Interfaces {
		if len(in.VirtualIPs) == 0 {
			continue
		}
		p := fmt.Sprintf("interfaces[%d].virtual_ips", i)
		pfx, err := netip.ParsePrefix(in.IPv4)
		if in.IPv4Mode != "static" || err != nil || in.Kind == "pppoe" || in.Kind == "wireguard" {
			add(p, "%s needs a static address of its own to carry virtual IPs", in.Name)
			continue
		}
		if len(in.VirtualIPs) > maxVirtualIPs {
			add(p, "%s: at most %d virtual IPs", in.Name, maxVirtualIPs)
			continue
		}
		net := pfx.Masked()
		var dhcp *DHCPServer
		for k := range c.DHCP {
			if c.DHCP[k].Interface == in.ID && c.DHCP[k].Enabled {
				dhcp = &c.DHCP[k]
			}
		}
		forClients := 0
		for k, v := range in.VirtualIPs {
			vp := fmt.Sprintf("%s[%d]", p, k)
			a, err := netip.ParseAddr(strings.TrimSpace(v.Address))
			switch {
			case err != nil || !a.Is4() || strings.Contains(v.Address, "/"):
				add(vp+".address", "enter an IPv4 address, e.g. %s", net.Addr().Next())
				continue
			case !net.Contains(a):
				add(vp+".address", "%s must be inside %s, the network of %s", a, net, in.Name)
				continue
			case a == net.Addr() || (net.Bits() < 31 && a == lastAddr(net)):
				add(vp+".address", "%s is the network or broadcast address of %s", a, net)
				continue
			case used[a] != "":
				add(vp+".address", "%s is already used by %s", a, used[a])
				continue
			case len(v.Description) > 80:
				add(vp+".description", "description: at most 80 characters")
				continue
			}
			if dhcp != nil {
				inPool := false
				for _, p := range dhcp.Pools() {
					inPool = inPool || (!a.Less(p[0]) && !p[1].Less(a))
				}
				if inPool {
					add(vp+".address", "%s is inside the DHCP range %s – %s: a client could get it (exclude it from the range to use it here)", a, dhcp.RangeStart, dhcp.RangeEnd)
					continue
				}
				for _, r := range dhcp.Reservations {
					if r.IP == a.String() {
						add(vp+".address", "%s is reserved by DHCP for %s", a, r.MAC)
					}
				}
			}
			used[a] = in.Name + " (virtual IP)"
			if v.ForClients {
				forClients++
			}
		}
		if forClients > 1 {
			add(p, "%s: only one virtual IP can be handed out to the clients", in.Name)
		}
	}
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
