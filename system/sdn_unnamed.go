package system

// The inside addresses with no name: not in the DHCP leases and reservations,
// not a DNS override, no Incus DNS name and no reverse DNS record. The DHCP &
// DNS page lets the admin name them.

import (
	"sync"
	"time"

	"zfsnas/internal/sdn"
)

// SDNUnnamedHost is one address without a name, with what hints at what it is.
type SDNUnnamedHost struct {
	Interface  string `json:"interface"`
	Network    string `json:"network"`
	Color      string `json:"color,omitempty"`
	Domain     string `json:"domain,omitempty"` // the name's domain on this network
	IP         string `json:"ip"`
	MAC        string `json:"mac,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	MACPrivate bool   `json:"mac_private,omitempty"`
	Kind       string `json:"kind"`
	Instance   string `json:"instance,omitempty"` // VM or container
	OS         string `json:"os,omitempty"`
	Peer       string `json:"peer,omitempty"` // VPN client
	Note       string `json:"note,omitempty"`
	Port       string `json:"port,omitempty"`
	Status     string `json:"status"`
	// Binding: "lease" the name follows the MAC, "reserved" it goes on the
	// reservation, "static" it is a DNS record for this address.
	Binding string `json:"binding"`
}

// sdnPTRChunk: SDNHostNames answers 16 addresses per call.
const sdnPTRChunk = 16

// sdnReverseNames asks reverse DNS about every address at once, so a first
// look costs one lookup timeout however many there are (answers are cached).
func sdnReverseNames(c *sdn.Config, ips []string, now time.Time) map[string]string {
	out := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < len(ips); i += sdnPTRChunk {
		end := min(i+sdnPTRChunk, len(ips))
		wg.Add(1)
		go func(part []string) {
			defer wg.Done()
			got := SDNHostNames(c, part, now)
			mu.Lock()
			for ip, n := range got {
				if n.FQDN != "" {
					out[ip] = n.FQDN
				}
			}
			mu.Unlock()
		}(ips[i:end])
	}
	wg.Wait()
	return out
}

func SDNUnnamedHosts(c *sdn.Config) []SDNUnnamedHost {
	now := time.Now()
	topo := SDNTopologyNow(c)
	incus := map[string]bool{} // address with a name from Incus' DNS
	if IncusUsable() {
		for _, n := range SDNIncusNetworks() {
			if !n.DNS {
				continue
			}
			for _, l := range n.Leases {
				if l.Hostname != "" {
					incus[l.Address] = true
				}
			}
		}
	}
	domains := map[string]string{}
	for _, d := range c.DHCP {
		domains[d.Interface] = c.DHCPDomain(d)
	}
	local := sdnLocalNames(c)
	var ask []string
	for _, n := range topo.Networks {
		for _, h := range n.Hosts {
			if h.IP == "" || incus[h.IP] {
				continue
			}
			if _, fqdn := local(h.IP); fqdn == "" {
				ask = append(ask, h.IP)
			}
		}
	}
	return sdnUnnamedFrom(topo, sdnReverseNames(c, ask, now), func(ip string) bool {
		_, fqdn := local(ip)
		return incus[ip] || fqdn != ""
	}, domains, c.DNS.Domain)
}

func sdnUnnamedFrom(topo SDNTopology, reverse map[string]string, known func(string) bool, domains map[string]string, dnsDomain string) []SDNUnnamedHost {
	out := []SDNUnnamedHost{}
	for _, n := range topo.Networks {
		dom, ok := domains[n.ID]
		if !ok || dom == "" {
			dom = dnsDomain
		}
		// A device's old address lingers in the neighbour table after it moves:
		// its MAC has a lease elsewhere, so that address is not a host to name.
		leased := map[string]bool{}
		for _, h := range n.Hosts {
			if h.MAC != "" && (h.Addressing == "lease" || h.Addressing == "reserved") {
				leased[h.MAC] = true
			}
		}
		for _, h := range n.Hosts {
			if h.IP == "" || reverse[h.IP] != "" || known(h.IP) {
				continue
			}
			if h.Addressing == "static" && h.Kind == "device" && leased[h.MAC] {
				continue
			}
			u := SDNUnnamedHost{Interface: n.ID, Network: n.Name, Color: n.Color, Domain: dom, IP: h.IP, MAC: h.MAC, Vendor: h.Vendor,
				MACPrivate: h.MACPrivate, Kind: h.Kind, OS: h.OS, Note: h.Note, Port: h.Port, Status: h.Status, Binding: "static"}
			switch h.Kind {
			case "vm", "container":
				u.Instance = h.Name
			case "vpn":
				u.Peer = h.Name
			}
			// A name can only follow a device its DHCP server is this
			// Firewall's: Incus leases are Incus' own.
			if n.DHCP != nil && n.DHCP.Server == "Firewall" && n.DHCP.Enabled && h.MAC != "" {
				switch h.Addressing {
				case "lease":
					u.Binding = "lease"
				case "reserved":
					u.Binding = "reserved"
				}
			}
			out = append(out, u)
		}
	}
	return out
}
