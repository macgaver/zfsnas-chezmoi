package system

// Figures for the OPNsense-compatible endpoints (homepage.dev "opnsense"
// widget): CPU and memory as the first lines of FreeBSD top, and the
// interfaces' byte counters with "wan" = the default-route interface.

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/capacityrrd"
)

var opnCPU = struct {
	sync.Mutex
	prev *cpuStat
	at   time.Time
	idle float64
}{idle: 100}

// opnIdle: % CPU idle since the last call (≥ 1 s apart), or over 250 ms
// when there is no recent reading.
func opnIdle() float64 {
	opnCPU.Lock()
	defer opnCPU.Unlock()
	now := time.Now()
	if opnCPU.prev == nil || now.Sub(opnCPU.at) > time.Minute {
		opnCPU.prev, opnCPU.at = readCPUStat(), now
		time.Sleep(250 * time.Millisecond)
		now = time.Now()
	} else if now.Sub(opnCPU.at) < time.Second {
		return opnCPU.idle
	}
	cur := readCPUStat()
	if cur != nil && opnCPU.prev != nil && cur.total > opnCPU.prev.total {
		opnCPU.idle = float64(cur.idle-opnCPU.prev.idle) * 100 / float64(cur.total-opnCPU.prev.total)
	}
	opnCPU.prev, opnCPU.at = cur, now
	return opnCPU.idle
}

func opnMeminfo() map[string]uint64 {
	m := map[string]uint64{}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		m[k] = n * 1024
	}
	return m
}

// opnSize is top's size: 812M, 3.2G.
func opnSize(b uint64) string {
	if b >= 1<<30 {
		return fmt.Sprintf("%.1fG", float64(b)/(1<<30))
	}
	return fmt.Sprintf("%dM", b>>20)
}

// OPNsenseActivityHeaders are top's header lines. The widget reads the idle
// % on line 3 and what precedes " Active," on line 4: the memory in use
// (total − available), which is what "used" means on Linux.
func OPNsenseActivityHeaders() []string {
	idle := opnIdle()
	m := opnMeminfo()
	used := uint64(0)
	if m["MemTotal"] > m["MemAvailable"] {
		used = m["MemTotal"] - m["MemAvailable"]
	}
	load := "0.00 0.00 0.00"
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) >= 3 {
			load = strings.Join(f[:3], " ")
		}
	}
	return []string{
		fmt.Sprintf("last pid: 0;  load averages:  %s  %s", load, time.Now().Format("15:04:05")),
		"0 processes",
		fmt.Sprintf("CPU: %4.1f%% user,  0.0%% nice,  0.0%% system,  0.0%% interrupt, %4.1f%% idle", 100-idle, idle),
		fmt.Sprintf("Mem: %s Active, %s Inact, %s Wired, %s Free", opnSize(used), opnSize(m["Inactive"]), opnSize(m["Buffers"]), opnSize(m["MemFree"])),
		fmt.Sprintf("Swap: %s Total, %s Free", opnSize(m["SwapTotal"]), opnSize(m["SwapFree"])),
		"",
	}
}

// OPNsenseIface is one interface's counters.
type OPNsenseIface struct {
	Name            string `json:"name"`
	Device          string `json:"device"`
	BytesReceived   int64  `json:"bytes received"`
	BytesTransmit   int64  `json:"bytes transmitted"`
	PacketsReceived int64  `json:"packets received"`
	PacketsTransmit int64  `json:"packets transmitted"`
}

// rrdMbitSeconds sums a rate series (Mbit/s, the global performance RRD)
// over [from, now) as Mbit·s, from the finest tier that still covers each
// part: 5-min points (a week), then 30-min buckets (30 days), then daily
// ones (UTC days, prorated). A 5-min point stands for its 5 minutes; a
// short hole between two (a portal restart: ≤ 2 h) counts at their mean
// rate, and the coarser buckets count at their mean over the whole bucket.
// Longer outages count as no traffic.
func rrdMbitSeconds(t0, t1, t2 []capacityrrd.CapSample, from, now int64) float64 {
	const s0, s1, s2 = 300, 1800, 86400
	up := func(ts, step int64) int64 { return (ts + step - 1) / step * step }
	sum := 0.0
	end := int64(math.MaxInt64) // what the finer tiers already cover starts here
	if len(t0) > 0 {
		if t0[0].TS > from && len(t1) > 0 {
			end = up(t0[0].TS, s1) // the 30-min bucket under it comes from tier 1
		} else if t0[0].TS > from {
			end = t0[0].TS
		} else {
			end = from
		}
		var prev *capacityrrd.CapSample
		for i := range t0 {
			x := &t0[i]
			if x.TS < end || x.TS < from {
				continue
			}
			sum += x.Avg * s0
			if prev != nil {
				if gap := x.TS - prev.TS - s0; gap > 0 && gap <= 7200 {
					sum += float64(gap) * (x.Avg + prev.Avg) / 2
				}
			}
			prev = x
		}
		// since the newest point (up to one more period)
		if prev != nil && now > prev.TS+s0 {
			sum += float64(min(now-prev.TS-s0, s0)) * prev.Avg
		}
	}
	if end <= from {
		return sum
	}
	end1 := end
	if len(t1) > 0 {
		if t1[0].TS > from {
			end1 = up(t1[0].TS, s2)
		} else {
			end1 = from
		}
		for _, x := range t1 {
			if x.TS >= from && x.TS >= end1 && x.TS < end {
				sum += x.Avg * s1
			}
		}
	}
	if end1 <= from {
		return sum
	}
	lim := min(end1, end)
	for _, x := range t2 {
		a, b := max(x.TS, from), min(x.TS+s2, lim)
		if b <= a {
			continue
		}
		sum += x.Avg * float64(b-a)
	}
	return sum
}

// monthStart is the 1st of now's month, 00:00 local time.
func monthStart(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
}

// wanMonthBytes: bytes received and sent on iface since the 1st of the
// month, from the global performance RRD.
func wanMonthBytes(iface string, now time.Time) (rx, tx int64, ok bool) {
	db := GetGlobalPerfDB()
	if db == nil || iface == "" {
		return 0, 0, false
	}
	from := monthStart(now).Unix()
	f := func(dir string) int64 {
		k := "net_" + iface + "_" + dir
		return int64(rrdMbitSeconds(db.Query(0, k), db.Query(1, k), db.Query(2, k), from, now.Unix()) * 1e6 / 8)
	}
	return f("rx"), f("tx"), true
}

// OPNsenseInterfaces: every interface by its Linux name (its counters), plus
// "wan" for the default-route one (the Internet link) with the bytes since
// the 1st of the month from the RRD history; its counters when there is no
// history.
func OPNsenseInterfaces() map[string]OPNsenseIface {
	out := map[string]OPNsenseIface{}
	rd := func(dev, n string) int64 {
		b, _ := os.ReadFile(filepath.Join("/sys/class/net", dev, "statistics", n))
		v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		return v
	}
	ents, _ := os.ReadDir("/sys/class/net")
	for _, e := range ents {
		d := e.Name()
		out[d] = OPNsenseIface{Name: d, Device: d,
			BytesReceived: rd(d, "rx_bytes"), BytesTransmit: rd(d, "tx_bytes"),
			PacketsReceived: rd(d, "rx_packets"), PacketsTransmit: rd(d, "tx_packets")}
	}
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		if gw := procRouteDefaultIface(string(b)); gw != "" {
			if x, ok := out[gw]; ok {
				x.Name = "WAN"
				if rx, tx, ok := wanMonthBytes(gw, time.Now()); ok {
					x.BytesReceived, x.BytesTransmit = rx, tx
				}
				out["wan"] = x
			}
		}
	}
	return out
}
