package handlers

// Firewall → intrusion detection (Phase 5): engine status, rule updates,
// alerts list, and ZNAS alert notifications for serious IDS alerts.

import (
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/alerts"
	"zfsnas/internal/config"
	"zfsnas/internal/geoip"
	"zfsnas/internal/ids"
	"zfsnas/internal/sdn"
	"zfsnas/system"
)

// HandleSDNIDSStatus — GET /api/sdn/ids/status
func HandleSDNIDSStatus(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"installed":          system.SDNSuricataInstalled(),
		"running":            system.SDNIDSRunning(),
		"update":             system.SDNIDSReadState(),
		"sources":            sdn.IDSSources,
		"default_categories": sdn.IDSDefaultCategories,
	})
}

// HandleSDNIDSUpdate — POST /api/sdn/ids/update: download the rules now
// (in the background; the status shows progress).
func HandleSDNIDSUpdate(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := sdnStoreFor(appCfg).LoadConfirmed()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !c.IDS.Enabled {
			jsonErr(w, http.StatusBadRequest, "intrusion detection is off — turn it on and apply first")
			return
		}
		go system.SDNIDSUpdate(c) //nolint:errcheck — reported in the status
		jsonOK(w, map[string]bool{"started": true})
	}
}

type sdnIDSAlertView struct {
	ids.Group
	SrcCC     string `json:"src_cc,omitempty"`
	SrcCity   string `json:"src_city,omitempty"`
	DstCC     string `json:"dst_cc,omitempty"`
	Interface string `json:"interface,omitempty"` // Firewall interface id of in_iface
	Incoming  bool   `json:"incoming"`            // the source is outside
	Dir       string `json:"dir"`                 // in (from the Internet) | out (to the Internet) | internal
	Open      bool   `json:"open"`                // in: a targeted port is open in the firewall; out/internal: always true
}

// sdnIsLocalAddr: an address of this server (stubbed in tests).
var sdnIsLocalAddr = system.SDNIsLocalAddr

// sdnIDSClassify orients an alert (src = who started the connection) and,
// for one started from the Internet, tells whether it targeted a port the
// firewall lets in — the rest are probes the firewall dropped anyway.
func sdnIDSClassify(c *sdn.Config, env sdn.Env, ifaceID, src, dst, proto string, ports []int) (dir string, open bool) {
	outside := func(s string) bool {
		a, err := netip.ParseAddr(s)
		return err == nil && geoip.IsPublic(a) && !sdnIsLocalAddr(a)
	}
	switch {
	case outside(src):
		dir = "in"
	case outside(dst):
		return "out", true
	default:
		return "internal", true
	}
	if c == nil {
		return dir, true
	}
	p := strings.ToLower(proto)
	if p != "tcp" && p != "udp" {
		return dir, c.PortOpen(ifaceID, p, 0, env)
	}
	for _, port := range ports {
		if c.PortOpen(ifaceID, p, port, env) {
			return dir, true
		}
	}
	return dir, false
}

// HandleSDNIDSAlerts — GET /api/sdn/ids/alerts?hours=24
func HandleSDNIDSAlerts(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
		if hours <= 0 || hours > 24*30 {
			hours = 24
		}
		c, _ := sdnStoreFor(appCfg).LoadConfirmed()
		byDev := map[string]string{}
		if c != nil {
			for _, in := range c.Interfaces {
				byDev[in.Device], byDev[in.L3Device()] = in.ID, in.ID
			}
		}
		geo, env := system.SDNGeo(), sdnEnvFor(appCfg)
		out := []sdnIDSAlertView{}
		for _, g := range system.SDNIDSStore().List(time.Now().Add(-time.Duration(hours) * time.Hour)) {
			v := sdnIDSAlertView{Group: g, Interface: byDev[g.InIface]}
			if a, err := netip.ParseAddr(g.Src); err == nil {
				in := geo.Lookup(a)
				v.SrcCC, v.SrcCity, v.Incoming = in.CountryCode, in.City, geoip.IsPublic(a)
			}
			if a, err := netip.ParseAddr(g.Dst); err == nil {
				v.DstCC = geo.Lookup(a).CountryCode
			}
			ports := g.Ports
			if len(ports) == 0 {
				ports = []int{g.DstPort}
			}
			v.Dir, v.Open = sdnIDSClassify(c, env, v.Interface, g.Src, g.Dst, g.Proto, ports)
			v.Incoming = v.Dir == "in"
			out = append(out, v)
		}
		jsonOK(w, out)
	}
}

// HandleSDNHostNames — GET /api/sdn/ids/names?ip=…&ip=… (up to 16): the
// inside name and reverse-DNS name of each address, for the alert cards.
func HandleSDNHostNames(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, _ := sdnStoreFor(appCfg).LoadConfirmed()
		jsonOK(w, system.SDNHostNames(c, r.URL.Query()["ip"], time.Now()))
	}
}

// HandleSDNHostInfo — GET /api/sdn/hostinfo?ip=…[&live=1]: everything known
// about one inside address (the Firewall tables' hover card). live=1 answers
// only what changes by the second, for the open card's refresh.
func HandleSDNHostInfo(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := netip.ParseAddr(r.URL.Query().Get("ip"))
		if err != nil || !a.Is4() {
			jsonErr(w, http.StatusBadRequest, "not an IPv4 address")
			return
		}
		if r.URL.Query().Get("live") != "" {
			jsonOK(w, system.SDNHostLiveNow(a, time.Now()))
			return
		}
		c, err := sdnStoreFor(appCfg).LoadConfirmed()
		if err != nil {
			c = &sdn.Config{}
		}
		jsonOK(w, system.SDNHostInfoFor(c, a, time.Now()))
	}
}

// sdnIDSNotifier decides which alerts become ZNAS notifications: severity
// at or above the chosen level, once per signature and source an hour, and
// at most 20 an hour in all.
type sdnIDSNotifier struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	window time.Time
	count  int
}

func (n *sdnIDSNotifier) want(e ids.Event, level int, now time.Time) bool {
	if level <= 0 || e.Severity <= 0 || e.Severity > level {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.seen == nil {
		n.seen = map[string]time.Time{}
	}
	if now.Sub(n.window) > time.Hour {
		n.window, n.count = now, 0
		for k, t := range n.seen {
			if now.Sub(t) > time.Hour {
				delete(n.seen, k)
			}
		}
	}
	k := strconv.Itoa(e.SID) + "|" + e.Src
	if t, ok := n.seen[k]; ok && now.Sub(t) < time.Hour {
		return false
	}
	if n.count >= 20 {
		return false
	}
	n.seen[k] = now
	n.count++
	return true
}

// StartSDNIDSAlerts hooks the alert stream to ZNAS notifications.
func StartSDNIDSAlerts(appCfg *config.AppConfig) {
	var mu sync.Mutex
	level, loaded := 0, time.Time{}
	var cfg *sdn.Config
	n := &sdnIDSNotifier{}
	system.SDNIDSOnAlert = func(e ids.Event) {
		mu.Lock()
		if time.Since(loaded) > time.Minute {
			level, loaded, cfg = 0, time.Now(), nil
			if c, err := sdnStoreFor(appCfg).LoadConfirmed(); err == nil && c.IDS.Enabled {
				level, cfg = c.IDS.AlertSeverity, c
			}
		}
		lv, c := level, cfg
		mu.Unlock()
		// A probe of a closed port from the Internet: the firewall dropped it — no notification.
		if c != nil {
			ifaceID := ""
			for _, in := range c.Interfaces {
				if in.Device == e.InIface || in.L3Device() == e.InIface {
					ifaceID = in.ID
				}
			}
			if _, open := sdnIDSClassify(c, sdnEnvFor(appCfg), ifaceID, e.Src, e.Dst, e.Proto, []int{e.DstPort}); !open {
				return
			}
		}
		if !n.want(e, lv, time.Now()) {
			return
		}
		sev := map[int]string{1: "high", 2: "medium", 3: "low"}[e.Severity]
		behind := func(public, inside string) string { // the inside host behind our public address (NAT)
			if inside == "" {
				return public
			}
			return inside + " (via " + public + ")"
		}
		body := fmt.Sprintf("%s (signature %d, %s severity)\n%s:%d → %s:%d %s on %s at %s.\nCategory: %s",
			e.Signature, e.SID, sev, behind(e.Src, e.SrcInside), e.SrcPort, behind(e.Dst, e.DstInside), e.DstPort, e.Proto, e.InIface, e.Time.Local().Format("15:04:05"), e.Category)
		go func() {
			if err := alerts.Send(alerts.EventIDS, "IDS: "+e.Signature, "Firewall IDS Alert", body); err != nil {
				log.Printf("[alerts] ids: %v", err)
			}
		}()
	}
}
