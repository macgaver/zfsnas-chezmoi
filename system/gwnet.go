package system

// Gateway traffic for the Network Focus top headers: the interface of the
// default route (the Internet link — a PPPoE link on a Firewall router), its
// download (received) and upload (sent) rates, sampled every 3 s like the
// disk I/O of the Storage Focus headers.

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/rrd"
)

// GatewayNet is the latest gateway traffic sample.
type GatewayNet struct {
	Iface     string `json:"iface"`          // "" = no default route
	Name      string `json:"name,omitempty"` // the name the admin gave it (Firewall), else none
	Addr      string `json:"addr,omitempty"` // its first IPv4 address
	SpeedMbps int    `json:"speed_mbps"`     // link speed, 0 = unknown (PPPoE, tunnels)
	Ready     bool   `json:"ready"`          // two samples taken on this interface
	RxBps     int64  `json:"rx_bps"`         // download, bits/s
	TxBps     int64  `json:"tx_bps"`         // upload, bits/s
	// Highest rates seen on this interface, given when the link speed is
	// unknown: the stored history or this sampler, whichever is higher.
	MaxRxBps int64     `json:"max_rx_bps,omitempty"`
	MaxTxBps int64     `json:"max_tx_bps,omitempty"`
	At       time.Time `json:"at"`
}

// procRouteDefaultIface reads /proc/net/route: the up default route with
// the lowest metric.
func procRouteDefaultIface(s string) string {
	best, bestMetric := "", int64(-1)
	for i, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, _ := strconv.ParseInt(f[3], 16, 64)
		if flags&1 == 0 { // RTF_UP
			continue
		}
		m, _ := strconv.ParseInt(f[6], 10, 64)
		if bestMetric < 0 || m < bestMetric {
			best, bestMetric = f[0], m
		}
	}
	return best
}

type gwNetHist struct {
	rx, tx float64
	at     time.Time
}

// gwNetHistEvery: the history changes slowly, and reading it is not free.
const gwNetHistEvery = 10 * time.Minute

// saneNetMax is the highest believable rate, Mbit/s.
func saneNetMax(vals []float64) float64 {
	best := 0.0
	for _, v := range vals {
		if v > best && v < rrd.MaxNetMbps {
			best = v
		}
	}
	return best
}

// diskRates are a disk's read and write MB/s and busy % between two readings;
// none when a counter went backwards (device re-attached).
func diskRates(cur, prev diskstatSample, dtSec float64) (readMBps, writeMBps, busy float64, ok bool) {
	if cur.sectorsRead < prev.sectorsRead || cur.sectorsWritten < prev.sectorsWritten || cur.msIO < prev.msIO || dtSec <= 0 {
		return 0, 0, 0, false
	}
	readMBps = float64(cur.sectorsRead-prev.sectorsRead) * 512 / 1_048_576 / dtSec
	writeMBps = float64(cur.sectorsWritten-prev.sectorsWritten) * 512 / 1_048_576 / dtSec
	busy = float64(cur.msIO-prev.msIO) / (dtSec * 1000) * 100
	if busy > 100 {
		busy = 100
	}
	return readMBps, writeMBps, busy, true
}

// netRateMbps is the rate between two byte counters; none when the counter
// went backwards (interface re-created, PPPoE reconnect).
func netRateMbps(cur, prev uint64, dtSec float64) (float64, bool) {
	if cur < prev || dtSec <= 0 {
		return 0, false
	}
	return float64(cur-prev) * 8 / 1_000_000 / dtSec, true
}

type gwNetSampler struct {
	mu     sync.Mutex
	sysNet string
	route  func() string
	addr   func(iface string) string
	// history gives the highest rx, tx in the stored history, Mbit/s; false
	// while the history is not open yet.
	history func(iface string) (float64, float64, bool)
	hist    map[string]gwNetHist
	live    map[string][2]int64 // highest rates sampled here, by interface
	prev    struct {
		iface  string
		rx, tx int64
		at     time.Time
		ok     bool
	}
	last GatewayNet
}

func (s *gwNetSampler) counter(iface, name string) (int64, bool) {
	b, err := os.ReadFile(filepath.Join(s.sysNet, iface, "statistics", name))
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n, err == nil
}

func (s *gwNetSampler) sample(now time.Time) {
	iface := s.route()
	g := GatewayNet{Iface: iface, At: now}
	if iface != "" {
		g.Addr = s.addr(iface)
		if b, err := os.ReadFile(filepath.Join(s.sysNet, iface, "speed")); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 {
				g.SpeedMbps = n
			}
		}
	}
	rx, ok1 := s.counter(iface, "rx_bytes")
	tx, ok2 := s.counter(iface, "tx_bytes")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live == nil {
		s.live, s.hist = map[string][2]int64{}, map[string]gwNetHist{}
	}
	p := &s.prev
	if iface != "" && ok1 && ok2 {
		if p.ok && p.iface == iface && rx >= p.rx && tx >= p.tx {
			if dt := now.Sub(p.at).Seconds(); dt > 0 {
				g.RxBps, g.TxBps, g.Ready = int64(float64(rx-p.rx)*8/dt), int64(float64(tx-p.tx)*8/dt), true
			}
		}
		p.iface, p.rx, p.tx, p.at, p.ok = iface, rx, tx, now, true
	} else {
		p.ok = false
	}
	if g.Ready {
		l := s.live[iface]
		s.live[iface] = [2]int64{max(l[0], g.RxBps), max(l[1], g.TxBps)}
	}
	if iface != "" && g.SpeedMbps == 0 && s.history != nil {
		h, ok := s.hist[iface]
		if !ok || now.Sub(h.at) >= gwNetHistEvery {
			if rx, tx, ok := s.history(iface); ok {
				h = gwNetHist{rx, tx, now}
				s.hist[iface] = h
			}
		}
		l := s.live[iface]
		g.MaxRxBps, g.MaxTxBps = max(int64(h.rx*1e6), l[0]), max(int64(h.tx*1e6), l[1])
	}
	s.last = g
}

func (s *gwNetSampler) snapshot() GatewayNet {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// gwNetHistoryMax: the highest believable rates stored for an interface,
// over every tier of the performance history.
func gwNetHistoryMax(iface string) (float64, float64, bool) {
	db := GetGlobalPerfDB()
	if db == nil {
		return 0, 0, false
	}
	top := func(key string) float64 {
		var vals []float64
		for tier := 0; tier <= 2; tier++ {
			for _, x := range db.Query(tier, key) {
				vals = append(vals, x.Max)
			}
		}
		return saneNetMax(vals)
	}
	return top("net_" + iface + "_rx"), top("net_" + iface + "_tx"), true
}

var gwNet = &gwNetSampler{sysNet: "/sys/class/net", history: gwNetHistoryMax,
	route: func() string {
		b, _ := os.ReadFile("/proc/net/route")
		return procRouteDefaultIface(string(b))
	},
	addr: func(iface string) string {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return ""
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				return n.String()
			}
		}
		return ""
	}}

// StartGatewayNetSampler samples the gateway every 3 s (the header poll).
func StartGatewayNetSampler() {
	go func() {
		gwNet.sample(time.Now())
		for range time.NewTicker(3 * time.Second).C {
			gwNet.sample(time.Now())
		}
	}()
}

// GetGatewayNet is the latest sample.
func GetGatewayNet() GatewayNet { return gwNet.snapshot() }
