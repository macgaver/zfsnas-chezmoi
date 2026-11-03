package system

// Virtual IPs (Firewall → Interfaces): extra addresses of an interface that
// can move between servers. They are not written to /etc/network/interfaces
// — ifup would raise them at boot even while another server holds them —
// but kept on the device by the portal: added after a duplicate-address
// probe, announced with a gratuitous ARP so the clients' caches follow at
// once, re-added when a link restart flushed them, removed when deleted.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/sdn"
)

// SDNVIP is one virtual IP as the device sees it.
type SDNVIP struct {
	State  string    `json:"state"`         // active | conflict | error
	MAC    string    `json:"mac,omitempty"` // conflict: who answers for it
	Error  string    `json:"error,omitempty"`
	Device string    `json:"device"`
	Since  time.Time `json:"since"`
}

var (
	sdnHaveArping = func() bool { return binaryPresent("arping") }
	// sdnVIPPing makes the kernel resolve ip on dev (fallback probe without arping).
	sdnVIPPing = func(dev, ip string) {
		_ = exec.Command("ping", "-c", "1", "-W", "1", "-I", dev, ip).Run()
	}
	sdnVIPMu     sync.Mutex
	sdnVIPStatus = map[string]SDNVIP{}
	arpReplyRe   = regexp.MustCompile(`(?i)reply from \S+ \[([0-9a-f:]{17})\]`)
)

func sdnVIPStatePath() string { return filepath.Join(sdnConfigDir, "sdn", "vips-applied.json") }

// SDNVIPStatus returns the state of every configured virtual IP.
func SDNVIPStatus() map[string]SDNVIP {
	sdnVIPMu.Lock()
	defer sdnVIPMu.Unlock()
	out := make(map[string]SDNVIP, len(sdnVIPStatus))
	for k, v := range sdnVIPStatus {
		out[k] = v
	}
	return out
}

type sdnVIPEntry struct {
	Device string `json:"device"`
	Prefix string `json:"prefix"` // 192.168.2.1/24
}

// SDNReconcileVIPs brings the devices in line with the configuration (nil:
// remove every virtual IP the portal added). Returns warnings for the apply.
func SDNReconcileVIPs(c *sdn.Config) []string {
	sdnVIPMu.Lock()
	defer sdnVIPMu.Unlock()
	want := map[string]sdnVIPEntry{} // key: device|prefix
	if c != nil {
		for _, in := range c.Interfaces {
			if in.IPv4Mode != "static" || in.Disabled {
				continue
			}
			for _, p := range in.VIPPrefixes() {
				e := sdnVIPEntry{Device: in.L3Device(), Prefix: p.String()}
				want[e.Device+"|"+e.Prefix] = e
			}
		}
	}
	var applied []sdnVIPEntry
	if b, err := os.ReadFile(sdnVIPStatePath()); err == nil {
		_ = json.Unmarshal(b, &applied)
	}
	if len(want) == 0 && len(applied) == 0 {
		sdnVIPStatus = map[string]SDNVIP{}
		return nil
	}
	var warns []string
	keep := map[string]sdnVIPEntry{}
	for _, e := range applied {
		if _, ok := want[e.Device+"|"+e.Prefix]; ok {
			continue
		}
		sdnRun.Run(nil, "ip", "addr", "del", e.Prefix, "dev", e.Device) //nolint:errcheck — may be gone already
	}
	status := map[string]SDNVIP{}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	present := map[string]map[string]bool{}
	for _, k := range keys {
		e := want[k]
		p := netip.MustParsePrefix(e.Prefix)
		ip := p.Addr().String()
		prev := sdnVIPStatus[ip]
		st := SDNVIP{Device: e.Device, Since: prev.Since}
		if present[e.Device] == nil {
			present[e.Device] = sdnDeviceAddrs(e.Device)
		}
		switch {
		case present[e.Device][ip]:
			st.State = "active"
			keep[k] = e
		default:
			if mac := sdnAddrInUse(e.Device, ip); mac != "" {
				st.State, st.MAC = "conflict", mac
				if prev.State != "conflict" || prev.MAC != mac {
					warns = append(warns, fmt.Sprintf("virtual IP %s not added: %s already answers for it on %s (another server still holds it?)", ip, mac, e.Device))
				}
				break
			}
			if _, err := sdnRun.Run(nil, "ip", "addr", "add", e.Prefix, "dev", e.Device); err != nil {
				st.State, st.Error = "error", err.Error()
				warns = append(warns, fmt.Sprintf("virtual IP %s: %v", ip, err))
				break
			}
			st.State = "active"
			keep[k] = e
			log.Printf("[sdn] virtual IP %s added on %s", e.Prefix, e.Device)
			if sdnHaveArping() {
				// Tell the network the address is here now (its caches may
				// still point at the server that held it).
				sdnRun.Run(nil, "arping", "-U", "-c", "2", "-I", e.Device, ip) //nolint:errcheck
			}
		}
		if st.State != prev.State || st.Since.IsZero() {
			st.Since = time.Now()
		}
		status[ip] = st
	}
	sdnVIPStatus = status
	out := make([]sdnVIPEntry, 0, len(keep))
	for _, k := range keys {
		if e, ok := keep[k]; ok {
			out = append(out, e)
		}
	}
	if b, err := json.Marshal(out); err == nil && sdnConfigDir != "" {
		_ = os.MkdirAll(filepath.Dir(sdnVIPStatePath()), 0755)
		_ = os.WriteFile(sdnVIPStatePath(), b, 0644)
	}
	return warns
}

// sdnDeviceAddrs lists the IPv4 addresses on dev.
func sdnDeviceAddrs(dev string) map[string]bool {
	out := map[string]bool{}
	b, _ := sdnRun.Run(nil, "ip", "-4", "-j", "addr", "show", "dev", dev)
	var links []struct {
		AddrInfo []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(b, &links) == nil {
		for _, l := range links {
			for _, a := range l.AddrInfo {
				out[a.Local] = true
			}
		}
	}
	return out
}

// sdnAddrInUse returns the MAC of a host answering ARP for ip on dev ("" =
// free). arping's duplicate-address probe when installed; otherwise a ping
// and the neighbour table — ARP is answered even by hosts that drop pings.
func sdnAddrInUse(dev, ip string) string {
	if sdnHaveArping() {
		b, _ := sdnRun.Run(nil, "arping", "-D", "-c", "2", "-w", "3", "-I", dev, ip)
		if m := arpReplyRe.FindStringSubmatch(string(b)); m != nil {
			return strings.ToLower(m[1])
		}
		return ""
	}
	sdnVIPPing(dev, ip)
	b, _ := sdnRun.Run(nil, "ip", "-4", "-j", "neigh", "show", "to", ip, "dev", dev)
	var ns []struct {
		LLAddr string   `json:"lladdr"`
		State  []string `json:"state"`
	}
	if json.Unmarshal(b, &ns) != nil {
		return ""
	}
	for _, n := range ns {
		failed := false
		for _, s := range n.State {
			if s == "FAILED" || s == "INCOMPLETE" {
				failed = true
			}
		}
		if n.LLAddr != "" && !failed {
			return strings.ToLower(n.LLAddr)
		}
	}
	return ""
}

// StartSDNVIPKeeper re-checks the virtual IPs every 30 seconds (a link
// restart flushes them; a conflict may have cleared). confirmed returns the
// applied configuration, nil when the Firewall is off.
func StartSDNVIPKeeper(st sdn.Store, confirmed func() *sdn.Config) {
	go func() {
		for {
			if c := confirmed(); c != nil || sdnVIPsApplied() {
				if unlock, err := st.Lock(); err == nil { // not in the middle of an apply
					SDNReconcileVIPs(confirmed())
					unlock()
				}
			}
			time.Sleep(30 * time.Second)
		}
	}()
}

func sdnVIPsApplied() bool {
	b, err := os.ReadFile(sdnVIPStatePath())
	return err == nil && len(strings.TrimSpace(string(b))) > 2
}
