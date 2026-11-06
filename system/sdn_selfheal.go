package system

// Self-repair, part of the gateway monitor daemon so it works without the
// portal and on servers with no gateway to monitor. Every 10 s:
//   - a tunnel that is down is brought back (it may have failed at boot);
//   - a site we dial gets its address from DNS, again each time it stops
//     answering: WireGuard itself looks a name up once, and gives up on a
//     silent peer after 90 s until something sends a packet;
//   - dynamic DNS is told of a new address at once and retried until the
//     provider has it, instead of at ddclient's next 5-minute check.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"zfsnas/internal/sdn"
)

const (
	sdnHealEvery = 10 * time.Second
	// sdnHandshakeStale: WireGuard renews a live session every 2 minutes.
	sdnHandshakeStale = 3 * time.Minute
	sdnNudgeEvery     = time.Minute
	sdnHealMaxPause   = 5 * time.Minute
)

// sdnLookupIP returns a name's addresses, IPv4 first.
var sdnLookupIP = func(ctx context.Context, host string) ([]string, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var v4, v6 []string
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	return append(v4, v6...), nil
}

// SDNHealPeer is what the monitor knows of a site we dial.
type SDNHealPeer struct {
	Note     string    `json:"note,omitempty"`     // waiting_dns | connecting
	Address  string    `json:"address,omitempty"`  // address now in use
	Error    string    `json:"error,omitempty"`    // why DNS did not answer
	Previous string    `json:"previous,omitempty"` // address before the last change
	Changed  time.Time `json:"changed,omitempty"`  // when the address last changed
}

// SDNHealTunnel is one tunnel's repair state.
type SDNHealTunnel struct {
	Note    string                 `json:"note,omitempty"` // restarting
	Error   string                 `json:"error,omitempty"`
	Retries int                    `json:"retries,omitempty"`
	Peers   map[string]SDNHealPeer `json:"peers,omitempty"` // by public key
}

// SDNHealState is /run/znas-sdn/selfheal.json.
type SDNHealState struct {
	Updated time.Time                `json:"updated"`
	Tunnels map[string]SDNHealTunnel `json:"tunnels"`
}

func sdnHealPath() string { return filepath.Join(sdnRunDir, "selfheal.json") }

// SDNHealStatus reads the published state; an old one (daemon stopped) says
// nothing about now.
func SDNHealStatus() SDNHealState {
	var s SDNHealState
	if b, err := os.ReadFile(sdnHealPath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	if time.Since(s.Updated) > 2*time.Minute {
		return SDNHealState{}
	}
	return s
}

// sdnLinkFlags: whether the device exists, and whether its link is set up.
func sdnLinkFlags(dev string) (exists, up bool) {
	b, err := os.ReadFile(filepath.Join(sdnSysClassNet, dev, "flags"))
	if err != nil {
		return false, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(b)), "0x")), 16, 32)
	return err == nil, err == nil && n&1 != 0
}

type sdnHealRetry struct {
	next  time.Time
	pause time.Duration
	tries int
}

// due says whether a retry may run now, and if so schedules the next one.
func (r *sdnHealRetry) due(now time.Time, first time.Duration) bool {
	if now.Before(r.next) {
		return false
	}
	switch {
	case r.pause == 0:
		r.pause = first
	case r.pause*2 > sdnHealMaxPause:
		r.pause = sdnHealMaxPause
	default:
		r.pause *= 2
	}
	r.next = now.Add(r.pause)
	r.tries++
	return true
}

type sdnHealer struct {
	tunnels  map[string]*sdnHealRetry
	errs     map[string]string
	nudged   map[string]time.Time
	changes  map[string]SDNHealPeer
	ddnsTry  sdnHealRetry
	ddnsAddr map[string]string
	ddnsSeen map[string]SDNDDNSHost // hostname → last cache entry seen
	cfgDir   string                 // "" = do not write the history (tests)
}

// ddnsChange turns a ddclient cache entry that changed into a history event.
// The first sighting of a name only sets the baseline: it is not news.
func ddnsChange(name string, prev SDNDDNSHost, seen bool, cur SDNDDNSHost, now time.Time) *SDNEvent {
	if !seen || (prev.IP == cur.IP && prev.Status == cur.Status) {
		return nil
	}
	good := cur.Status == "good" || cur.Status == "nochg"
	switch {
	case good && prev.IP != cur.IP && prev.IP != "":
		return &SDNEvent{At: now, Kind: "ddns_ok", Severity: "info", Name: name, Text: name + " updated: " + prev.IP + " → " + cur.IP}
	case good && prev.IP != cur.IP:
		return &SDNEvent{At: now, Kind: "ddns_ok", Severity: "info", Name: name, Text: name + " updated: now " + cur.IP}
	case good:
		return &SDNEvent{At: now, Kind: "ddns_ok", Severity: "info", Name: name, Text: name + " update works again (" + cur.IP + ")"}
	case cur.Status != "" && cur.Status != prev.Status:
		return &SDNEvent{At: now, Kind: "ddns_failed", Severity: "error", Name: name, Text: name + " update failed: the provider answered \"" + cur.Status + "\""}
	}
	return nil
}

func newSDNHealer() *sdnHealer {
	return &sdnHealer{tunnels: map[string]*sdnHealRetry{}, errs: map[string]string{}, nudged: map[string]time.Time{},
		changes: map[string]SDNHealPeer{}, ddnsAddr: map[string]string{}, ddnsSeen: map[string]SDNDDNSHost{}}
}

// cycle repairs what it can for config c, and returns the state to publish.
func (h *sdnHealer) cycle(c *sdn.Config, now time.Time) SDNHealState {
	st := SDNHealState{Updated: now, Tunnels: map[string]SDNHealTunnel{}}
	for _, in := range c.Interfaces {
		if in.Kind != "wireguard" || in.Disabled {
			continue
		}
		st.Tunnels[in.ID] = h.tunnel(c, in, now)
	}
	h.ddns(c, now)
	return st
}

func (h *sdnHealer) tunnel(c *sdn.Config, in sdn.Interface, now time.Time) SDNHealTunnel {
	if _, err := sdnWGFile(c, in.ID); err != nil {
		log.Printf("[sdn-heal] %s: key file: %v", in.Name, err)
	}
	r := h.tunnels[in.ID]
	if r == nil {
		r = &sdnHealRetry{}
		h.tunnels[in.ID] = r
	}
	exists, up := sdnLinkFlags(in.Device)
	if !exists || !up {
		if r.due(now, 30*time.Second) {
			log.Printf("[sdn-heal] %s: tunnel is down, bringing it back (attempt %d)", in.Name, r.tries)
			h.errs[in.ID] = ""
			// A failed ifup leaves the device behind, and ifupdown's record
			// of it, and its "ip link add" then fails every time.
			sdnRun.Run(nil, "ifdown", "--force", in.Device)        //nolint:errcheck
			sdnRun.Run(nil, "ip", "link", "del", "dev", in.Device) //nolint:errcheck
			if _, err := sdnRun.Run(nil, "ifup", in.Device); err != nil {
				h.errs[in.ID] = err.Error()
				log.Printf("[sdn-heal] %s: %v", in.Name, err)
			}
			exists, up = sdnLinkFlags(in.Device)
		}
		if !exists || !up {
			return SDNHealTunnel{Note: "restarting", Error: h.errs[in.ID], Retries: r.tries}
		}
	}
	*r = sdnHealRetry{}
	ends := parseWGPairs(in.Device, "endpoints")
	shakes := parseWGPairs(in.Device, "latest-handshakes")
	t := SDNHealTunnel{Peers: map[string]SDNHealPeer{}}
	missing := false
	for _, p := range c.WGPeers {
		if p.Tunnel != in.ID || !p.Enabled {
			continue
		}
		cur, known := ends[p.PublicKey]
		if !known {
			missing = true
			continue
		}
		if p.Endpoint != "" {
			hs, _ := strconv.ParseInt(shakes[p.PublicKey], 10, 64)
			t.Peers[p.PublicKey] = h.peer(in, p, cur, hs, now)
		}
	}
	if missing {
		log.Printf("[sdn-heal] %s: peers missing from the kernel, reloading them", in.Name)
		if _, err := sdnRun.Run(nil, "wg", "syncconf", in.Device, sdnWGPath(in.ID)); err != nil {
			t.Error = err.Error()
		}
	}
	return t
}

// parseWGPairs reads `wg show <dev> <what>`: public key, tab, value.
func parseWGPairs(dev, what string) map[string]string {
	b, _ := sdnRun.Run(nil, "wg", "show", dev, what)
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "\t"); ok {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

func (h *sdnHealer) peer(in sdn.Interface, p sdn.WGPeer, cur string, handshake int64, now time.Time) SDNHealPeer {
	s := h.changes[p.PublicKey] // keeps the last change on show
	s.Note, s.Error = "", ""
	if cur != "(none)" {
		s.Address = cur
	} else {
		s.Address = ""
	}
	// Connected: leave it alone, whatever DNS says.
	if handshake > 0 && now.Sub(time.Unix(handshake, 0)) < sdnHandshakeStale {
		return s
	}
	s.Note = "connecting"
	host, port, err := net.SplitHostPort(p.Endpoint)
	if err != nil {
		return s
	}
	addrs := []string{host}
	if sdn.WGEndpointIsName(p.Endpoint) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		addrs, err = sdnLookupIP(ctx, host)
		cancel()
		if err == nil && len(addrs) == 0 {
			err = &net.DNSError{Err: "no address", Name: host}
		}
		if err != nil {
			s.Error = err.Error()
			if cur == "(none)" {
				s.Note = "waiting_dns"
			}
			// An address we have may still work.
			if cur != "(none)" {
				h.nudge(in, p, cur, now)
			}
			return s
		}
	}
	want := ""
	for _, a := range addrs {
		if e := net.JoinHostPort(a, port); e == cur {
			want = e
			break
		}
	}
	if want != "" {
		h.nudge(in, p, want, now)
		return s
	}
	want = net.JoinHostPort(addrs[0], port)
	if ap, err := netip.ParseAddrPort(want); err == nil {
		want = ap.String()
	}
	log.Printf("[sdn-heal] %s: %s: address now %s (was %s)", in.Name, p.Name, want, cur)
	h.setEndpoint(in, p, want)
	h.nudged[p.PublicKey] = now
	if cur != "(none)" {
		s.Previous = cur
	}
	s.Changed, s.Address = now, want
	h.changes[p.PublicKey] = SDNHealPeer{Previous: s.Previous, Changed: now}
	return s
}

// nudge makes a silent peer try again.
func (h *sdnHealer) nudge(in sdn.Interface, p sdn.WGPeer, endpoint string, now time.Time) {
	if p.Keepalive <= 0 || now.Sub(h.nudged[p.PublicKey]) < sdnNudgeEvery {
		return
	}
	h.nudged[p.PublicKey] = now
	h.setEndpoint(in, p, endpoint)
}

// setEndpoint turns the keepalive off and on around the address: that is
// what makes the kernel send a packet now. Otherwise a peer that has given
// up stays silent until the machine has something to send through it.
func (h *sdnHealer) setEndpoint(in sdn.Interface, p sdn.WGPeer, endpoint string) {
	args := []string{"set", in.Device, "peer", p.PublicKey, "endpoint", endpoint}
	if p.Keepalive > 0 {
		sdnRun.Run(nil, "wg", "set", in.Device, "peer", p.PublicKey, "persistent-keepalive", "off") //nolint:errcheck
		args = append(args, "persistent-keepalive", strconv.Itoa(p.Keepalive))
	}
	if _, err := sdnRun.Run(nil, "wg", args...); err != nil {
		log.Printf("[sdn-heal] %s: %s: %v", in.Name, p.Name, err)
	}
}

// sdnDDNSRefused: the provider said no. Asking more often does not help and
// can get the account blocked; ddclient's own 5-minute check goes on.
var sdnDDNSRefused = map[string]bool{"badauth": true, "nohost": true, "notfqdn": true, "abuse": true, "numhost": true, "badagent": true, "!donator": true}

// ddns restarts ddclient, which checks at startup, when a name is behind.
func (h *sdnHealer) ddns(c *sdn.Config, now time.Time) {
	// Lost, or written by an older version.
	if changed, err := sdnDDNSFiles(c); err != nil {
		log.Printf("[sdn-heal] dynamic DNS: %v", err)
	} else if changed && sdn.RenderDDClient(c) != "" {
		sdnRun.Run(nil, "systemctl", "restart", sdnDDNSUnitName) //nolint:errcheck
	}
	if _, err := os.Stat(sdnDDClientConf); err != nil {
		return
	}
	b, err := os.ReadFile(sdnDDClientCache)
	if err != nil && !os.IsNotExist(err) {
		return
	}
	cache := parseDDClientCache(string(b))
	for _, e := range c.DDNS {
		pv, ok := sdn.DDNSProviders[e.Provider]
		if !e.Enabled || !ok {
			continue
		}
		for _, name := range e.Hostnames {
			cur, known := cache[strings.TrimSuffix(name, pv.Suffix)]
			if !known {
				continue
			}
			prev, seen := h.ddnsSeen[name]
			h.ddnsSeen[name] = cur
			if ev := ddnsChange(name, prev, seen, cur, now); ev != nil && h.cfgDir != "" {
				if err := SDNRecordEvent(h.cfgDir, *ev); err != nil {
					log.Printf("[sdn-events] %v", err)
				}
			}
		}
	}
	var why []string
	for _, e := range c.DDNS {
		pv, ok := sdn.DDNSProviders[e.Provider]
		gw := c.GatewayByID(e.Gateway)
		if !e.Enabled || !ok || gw == nil {
			continue
		}
		in := c.InterfaceByID(gw.Interface)
		if in == nil || in.Disabled {
			continue
		}
		addr := sdnGatewayIfaceAddr(in.L3Device())
		if addr == "" {
			continue // not connected yet: nothing to send
		}
		moved := h.ddnsAddr[e.ID] != "" && h.ddnsAddr[e.ID] != addr
		h.ddnsAddr[e.ID] = addr
		for _, name := range e.Hostnames {
			st, known := cache[strings.TrimSuffix(name, pv.Suffix)]
			switch {
			case sdnDDNSRefused[st.Status]:
			case !known:
				why = append(why, name+" never sent")
			case e.IPSource == "web":
				if moved || (st.Status != "good" && st.Status != "nochg" && st.Status != "") {
					why = append(why, name+" "+st.Status)
				}
			case st.IP != addr:
				why = append(why, name+" has "+st.IP+", address is "+addr)
			case st.Status != "good" && st.Status != "nochg" && st.Status != "":
				why = append(why, name+" "+st.Status)
			}
		}
	}
	if len(why) == 0 {
		h.ddnsTry = sdnHealRetry{}
		return
	}
	// Just over min-error-interval: ddclient skips a retry sooner than that.
	if h.ddnsTry.due(now, 70*time.Second) {
		sort.Strings(why)
		log.Printf("[sdn-heal] dynamic DNS: %s: updating now (attempt %d)", strings.Join(why, "; "), h.ddnsTry.tries)
		if _, err := sdnRun.Run(nil, "systemctl", "restart", sdnDDNSUnitName); err != nil {
			log.Printf("[sdn-heal] dynamic DNS: %v", err)
		}
	}
}

// sdnHealLoop runs the repairs for as long as the daemon lives.
func sdnHealLoop(st sdn.Store) {
	h := newSDNHealer()
	h.cfgDir = st.Dir
	routeErrs := "[]"
	for {
		state, _ := st.LoadState()
		_, aerr := st.LoadApplying()
		if state.Enabled && aerr != nil { // an apply brings links up and down itself
			if c, err := st.LoadConfirmed(); err == nil {
				// Routes die with their link, and at boot the links come up after us.
				if errs := SDNSyncStaticRoutes(c); fmt.Sprint(errs) != routeErrs {
					routeErrs = fmt.Sprint(errs)
					if len(errs) > 0 {
						log.Printf("[sdn] local routes: %v", errs)
					}
				}
				s := h.cycle(c, time.Now())
				if b, err := json.Marshal(s); err == nil {
					_ = os.MkdirAll(sdnRunDir, 0755)
					tmp := sdnHealPath() + ".tmp"
					if os.WriteFile(tmp, b, 0644) == nil {
						_ = os.Rename(tmp, sdnHealPath())
					}
				}
			}
		}
		time.Sleep(sdnHealEvery)
	}
}
