package system

// Finding a card's address when the name of the guest's interface doesn't
// help, and identifying an instance by the MAC of one of its cards.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// lxdGuestIPByMAC is the first global IPv4 on any guest interface with this
// MAC, in a stable order (a VLAN or a bridge on the card shares its MAC).
func lxdGuestIPByMAC(network map[string]lxdStateNetwork, mac string) string {
	if mac == "" {
		return ""
	}
	best := ""
	bestName := ""
	for name, iface := range network {
		if !strings.EqualFold(iface.HWAddr, mac) {
			continue
		}
		for _, a := range iface.Addresses {
			if a.Family == "inet" && a.Scope == "global" {
				if best == "" || name < bestName {
					best, bestName = a.Address, name
				}
				break
			}
		}
	}
	return best
}

// Hook (tests replace it).
var lxdHostSeen = func() map[string]string {
	seen := map[string]string{}
	// Weakest first: the DHCP leases, which name the address the device was
	// given, override what the neighbour table last heard.
	var neigh []sdnTopoNeigh
	_ = json.Unmarshal(sdnHostIPJSON("-4", "neigh", "show"), &neigh)
	for _, n := range neigh {
		state := ""
		if len(n.State) > 0 {
			state = n.State[0]
		}
		if n.LLAddr != "" && state != "FAILED" && state != "INCOMPLETE" {
			seen[strings.ToLower(n.LLAddr)] = n.Dst
		}
	}
	files, _ := filepath.Glob(filepath.Join(sdnLeaseDir, "znas-sdn-*.leases"))
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) >= 3 {
				seen[strings.ToLower(f[1])] = f[2]
			}
		}
	}
	return seen
}

// lxdFillHostSeenIPs completes the cards the guest said nothing about.
func lxdFillHostSeenIPs(nics []LXDNICConfig) {
	var seen map[string]string
	for i := range nics {
		if nics[i].CurrentIP != "" || nics[i].MAC == "" {
			continue
		}
		if seen == nil {
			seen = lxdHostSeen()
		}
		if ip := seen[strings.ToLower(nics[i].MAC)]; ip != "" {
			nics[i].CurrentIP, nics[i].IPSource = ip, "host"
		}
	}
}

// LXDInstanceOwner is the VM or container holding a card.
type LXDInstanceOwner struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Status string `json:"status"`
	OS     string `json:"os,omitempty"`
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
	NIC    string `json:"nic,omitempty"`
	Bridge string `json:"bridge,omitempty"`
}

// LXDInstanceByMAC finds this server's instance with a card of this MAC.
func LXDInstanceByMAC(mac string) *LXDInstanceOwner {
	if !IncusUsable() {
		return nil
	}
	b := sdnTopoInstancesRaw()
	if b == nil {
		return nil
	}
	return lxdOwnerOf(parseTopoInstances(b), mac)
}

func lxdOwnerOf(list []sdnTopoInstance, mac string) *LXDInstanceOwner {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if mac == "" {
		return nil
	}
	for _, in := range list {
		for _, nic := range in.NICs {
			if nic.MAC == mac {
				return &LXDInstanceOwner{Name: in.Name, Type: in.Type, Status: in.Status, OS: in.OS, CPU: in.CPU, Memory: in.Memory, NIC: nic.Name, Bridge: nic.Bridge}
			}
		}
	}
	return nil
}
