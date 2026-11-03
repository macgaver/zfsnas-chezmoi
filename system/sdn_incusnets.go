package system

// Incus networks with their own address (host-nat): Incus gives them their
// address, DHCP, DNS and NAT, so the Firewall leaves them alone and shows
// them read-only on its Interfaces and DHCP & DNS pages.

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// SDNIncusLease is a device with an address from Incus' DHCP.
type SDNIncusLease struct {
	Hostname string `json:"hostname"`
	MAC      string `json:"mac"`
	Address  string `json:"address"`
	Type     string `json:"type"` // dynamic | static
}

// SDNIncusNet is what Incus does on one of its networks.
type SDNIncusNet struct {
	Name       string          `json:"name"`
	Address    string          `json:"address"` // the network's gateway, CIDR
	NAT        bool            `json:"nat"`
	DHCP       bool            `json:"dhcp"`
	DHCPRanges []string        `json:"dhcp_ranges,omitempty"` // "first-last"
	DNS        bool            `json:"dns"`
	Domain     string          `json:"domain"`
	Instances  int             `json:"instances"`
	Leases     []SDNIncusLease `json:"leases"`
}

// Hooks (tests replace them).
var (
	sdnIncusNetList   = ListLXDNetworks
	sdnIncusLeasesRaw = func(name string) ([]byte, error) {
		return exec.Command("incus", "query", "/1.0/networks/"+name+"/leases").Output()
	}
)

// SDNIncusNetworks lists Incus' networks with an address of their own
// (none when VMs & Containers is not in use).
func SDNIncusNetworks() []SDNIncusNet {
	if !IncusUsable() {
		return []SDNIncusNet{}
	}
	nets, err := sdnIncusNetList()
	if err != nil {
		return []SDNIncusNet{}
	}
	return sdnIncusNetsFrom(nets, func(name string) []SDNIncusLease {
		b, err := sdnIncusLeasesRaw(name)
		if err != nil {
			return nil
		}
		return parseIncusLeases(b)
	})
}

func sdnIncusNetsFrom(nets []LXDNetwork, leases func(string) []SDNIncusLease) []SDNIncusNet {
	out := []SDNIncusNet{}
	for _, n := range nets {
		cf := n.Config
		addr := cf["ipv4.address"]
		// pure L2 bridges and the Firewall's own networks are not Incus' to describe
		if !n.Managed || n.Type != "bridge" || addr == "" || addr == "none" || cf["user.znas.sdn"] == "true" {
			continue
		}
		in := SDNIncusNet{Name: n.Name, Address: addr, NAT: cf["ipv4.nat"] == "true",
			DHCP: cf["ipv4.dhcp"] != "false", DNS: cf["dns.mode"] != "none", Domain: cf["dns.domain"], Leases: []SDNIncusLease{}}
		if in.Domain == "" {
			in.Domain = "incus"
		}
		if in.DHCP {
			if r := cf["ipv4.dhcp.ranges"]; r != "" {
				for _, s := range strings.Split(r, ",") {
					in.DHCPRanges = append(in.DHCPRanges, strings.TrimSpace(s))
				}
			} else if r := sdnIncusDefaultRange(addr); r != "" {
				in.DHCPRanges = []string{r}
			}
		}
		for _, u := range n.UsedBy {
			if strings.HasPrefix(u, "/1.0/instances/") {
				in.Instances++
			}
		}
		if ls := leases(n.Name); ls != nil {
			in.Leases = ls
		}
		out = append(out, in)
	}
	return out
}

// sdnIncusDefaultRange: Incus hands out the whole subnet but the gateway.
func sdnIncusDefaultRange(cidr string) string {
	gw, ipn, err := net.ParseCIDR(cidr)
	if err != nil || gw.To4() == nil {
		return ""
	}
	ones, bits := ipn.Mask.Size()
	if bits-ones < 2 {
		return ""
	}
	base := binaryBE32(ipn.IP.To4())
	first, last, g := base+1, base|(1<<(bits-ones)-1)-1, binaryBE32(gw.To4())
	if g == first {
		first++
	} else if g == last {
		last--
	}
	ip := func(n uint32) string {
		return fmt.Sprintf("%d.%d.%d.%d", byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return ip(first) + "-" + ip(last)
}

// parseIncusLeases reads `incus query /1.0/networks/X/leases`: the devices'
// IPv4 addresses (not the gateway's entry, not IPv6).
func parseIncusLeases(b []byte) []SDNIncusLease {
	var raw []struct {
		Hostname  string `json:"hostname"`
		HWAddress string `json:"hwaddr"`
		Address   string `json:"address"`
		Type      string `json:"type"`
	}
	out := []SDNIncusLease{}
	if json.Unmarshal(b, &raw) != nil {
		return out
	}
	for _, l := range raw {
		if l.Type == "gateway" || l.Type == "uplink" || strings.Contains(l.Address, ":") {
			continue
		}
		out = append(out, SDNIncusLease{Hostname: l.Hostname, MAC: l.HWAddress, Address: l.Address, Type: l.Type})
	}
	return out
}
