package handlers

import (
	"net/http"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"zfsnas/internal/capacityrrd"
	"zfsnas/system"
)

// lxd_workload.go — backs the "Workload" tab on the Performance page.
// One endpoint aggregates the existing per-instance RRDs into four
// per-metric maps so the frontend can pick the top-10 contributors and
// render stacked area charts without making N HTTP requests.
//
// No new RRD storage is introduced: this is a query-time aggregator
// over the same DBs already written by the LXD metrics collector.

// physicalDiskRe matches whole block devices the guest sees as real
// hardware (sda, vda, nvme0n1, …) plus the Incus-side device names that
// appear for VMs without a guest agent (`dev-incus_root`, etc.).
// Partitions, dm-*, loop\d+, and QEMU's `/machine/system.flash*` firmware
// blockers are excluded so summed disk I/O isn't double-counted or
// padded with idle pseudo-devices.
var physicalDiskRe = regexp.MustCompile(`^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|dev-(?:incus|lxd)_[A-Za-z0-9._-]+)$`)

// ifaceExcludeRe / ifaceAllowRe mirror the frontend _isPhysicalIface so the
// VM/Container Net column + its popup list only the guest's real uplink NICs —
// not loopback, veth/tap/bridge/docker/overlay or other virtual plumbing that
// Incus also reports (and that accumulates as stale RRD keys over an instance's
// life). A device must NOT match the exclude set AND must match the allow set.
var ifaceExcludeRe = regexp.MustCompile(`(?i)^(lo|docker|br-|virbr|veth|vnet|tap|tun|cali|flannel|wg|vxlan|geneve|fwbr|fwln|fwpr|bond\d|vlan\d|kube|cni|ovs|gre|lxcbr|lxdbr|incbr|incusbr)`)
var ifaceAllowRe = regexp.MustCompile(`(?i)^(enp|ens|eno|enx|eth\d|em\d|p\dp\d|wlp|wlan|wls)`)

func isPhysicalIface(dev string) bool {
	if dev == "" || ifaceExcludeRe.MatchString(dev) {
		return false
	}
	return ifaceAllowRe.MatchString(dev)
}

// HandleLXDWorkloadPerf serves the per-instance RRD samples for the
// metrics shown on the Workload tab — cpu, mem, net_rx, net_tx, disk_r,
// disk_w — keyed by instance name. Network and disk samples are summed
// across all relevant devices per instance before being returned (so a
// VM with three zvols contributes a single disk_w line, not three).
//
// GET /api/incus/workload-perf?tier=0&since=<unix>
//
// Response:
//
//	{
//	  "tier":      0,
//	  "instances": ["vm1", "vm2", …],
//	  "metrics":   {
//	    "cpu":     { "vm1": [{ts,avg,min,max,n}, …], … },
//	    "mem":     { "vm1": […], … },
//	    "net_rx":  { … },
//	    "net_tx":  { … },
//	    "disk_r":  { … },
//	    "disk_w":  { … },
//	  }
//	}
func HandleLXDWorkloadPerf(w http.ResponseWriter, r *http.Request) {
	tier, _ := strconv.Atoi(r.URL.Query().Get("tier"))
	if tier < 0 || tier > 2 {
		tier = 0
	}
	var since int64
	if s := r.URL.Query().Get("since"); s != "" {
		since, _ = strconv.ParseInt(s, 10, 64)
	}

	instances := system.ListLXDMetricInstances()
	metrics := map[string]map[string][]capacityrrd.CapSample{
		"cpu":    {},
		"mem":    {},
		"net_rx": {},
		"net_tx": {},
		"disk_r": {},
		"disk_w": {},
	}

	for _, name := range instances {
		db := system.GetLXDInstanceMetricsDB(name)
		if db == nil {
			continue
		}
		keys := db.Keys()

		// Single-series gauges/rates.
		if hasKey(keys, "cpu") {
			metrics["cpu"][name] = querySamples(db, tier, "cpu", since)
		}
		if hasKey(keys, "mem") {
			metrics["mem"][name] = querySamples(db, tier, "mem", since)
		}

		// Network: sum across every device matching net_rx:* / net_tx:*.
		// No physical-NIC filter on the server side — we'd need the guest's
		// idea of "physical" which isn't recoverable from the metric name
		// alone. The frontend's _isPhysicalIface filter happens to allow
		// every label Incus typically emits anyway (enp*, ens*, eth*).
		if rx := sumKeys(db, tier, keys, "net_rx:", nil, since); rx != nil {
			metrics["net_rx"][name] = rx
		}
		if tx := sumKeys(db, tier, keys, "net_tx:", nil, since); tx != nil {
			metrics["net_tx"][name] = tx
		}

		// Disk: only sum physical-disk devices so we don't double-count
		// the same I/O across sda + sda1 + dm-0.
		if rd := sumKeys(db, tier, keys, "disk_r:", physicalDiskRe, since); rd != nil {
			metrics["disk_r"][name] = rd
		}
		if wr := sumKeys(db, tier, keys, "disk_w:", physicalDiskRe, since); wr != nil {
			metrics["disk_w"][name] = wr
		}
	}

	jsonOK(w, map[string]any{
		"tier":      tier,
		"instances": instances,
		"metrics":   metrics,
	})
}

// --- v6.6.16: per-instance "latest sample" snapshot for the table columns ---

// instMetricsFS is one filesystem entry in the snapshot.
type instMetricsFS struct {
	Mountpoint string  `json:"mountpoint"`
	Used       float64 `json:"used"`
	Size       float64 `json:"size"`
	Pct        float64 `json:"pct"`
}

// instMetricsNIC / instMetricsDisk are per-device rate entries (bytes/s).
type instMetricsNIC struct {
	Device string  `json:"device"`
	RxBps  float64 `json:"rx_bps"`
	TxBps  float64 `json:"tx_bps"`
}
type instMetricsDisk struct {
	Device string  `json:"device"`
	RBps   float64 `json:"r_bps"`
	WBps   float64 `json:"w_bps"`
}

// instMetricsSummary is the latest-sample rollup for one instance, consumed
// by the VM/Container table metric columns (VCPU / RAM / Filesystem / Net /
// Disk-IO) and their hover popups.
type instMetricsSummary struct {
	CPUPct      float64           `json:"cpu_pct"` // raw: % of one host CPU (frontend normalizes by vCPU count)
	MemUsed     float64           `json:"mem_used"`
	MemTotal    float64           `json:"mem_total"`
	MemPct      float64           `json:"mem_pct"`     // 0–100 (0 when total unknown)
	Filesystems []instMetricsFS   `json:"filesystems"` // every real FS, sorted fullest-first
	TopFSPct    float64           `json:"top_fs_pct"`
	TopFSMount  string            `json:"top_fs_mount"`
	NICs        []instMetricsNIC  `json:"nics"`
	NetMbps     float64           `json:"net_mbps"` // Σ non-loopback rx+tx · 8 / 1e6
	Disks       []instMetricsDisk `json:"disks"`
	DiskIOMbps  float64           `json:"diskio_mbps"` // Σ whole-disk r+w / 1e6
	TS          int64             `json:"ts"`          // unix time of the newest sample seen
}

// HandleLXDInstancesMetrics returns the newest-sample metric rollup for every
// instance that has a per-instance RRD, so the VM/Container tables can render
// the VCPU/RAM/Filesystem %-bars and the Net/Disk-IO numbers in one request.
//
// GET /api/lxd/instances-metrics
//
//	{ "host_cpus": 8, "instances": { "<name>": instMetricsSummary, … } }
//
// CPU is returned raw (% of one host CPU); the frontend normalizes it to the
// instance's allocated vCPU count (falling back to host_cpus). Rate series
// (cpu/net/disk) reflect the last 5-minute scrape; offline instances keep
// their last-known filesystem values, while the frontend blanks the rate
// columns based on power state.
func HandleLXDInstancesMetrics(w http.ResponseWriter, r *http.Request) {
	out := map[string]*instMetricsSummary{}
	for _, name := range system.ListLXDMetricInstances() {
		db := system.GetLXDInstanceMetricsDB(name)
		if db == nil {
			continue
		}
		keys := db.Keys()
		s := &instMetricsSummary{}

		if v, ts, ok := latestSample(db, "cpu"); ok {
			s.CPUPct = v
			if ts > s.TS {
				s.TS = ts
			}
		}
		if v, ts, ok := latestSample(db, "mem"); ok {
			s.MemUsed = v
			if ts > s.TS {
				s.TS = ts
			}
		}
		if v, _, ok := latestSample(db, "mem_total"); ok {
			s.MemTotal = v
		}
		if s.MemTotal > 0 {
			s.MemPct = clampPct(s.MemUsed / s.MemTotal * 100)
		}

		// Filesystems: pair fs_used:<mp> / fs_size:<mp>.
		for _, k := range keys {
			mp := strings.TrimPrefix(k, "fs_used:")
			if mp == k {
				continue
			}
			used, ts, ok := latestSample(db, k)
			if !ok {
				continue
			}
			size, _, _ := latestSample(db, "fs_size:"+mp)
			pct := 0.0
			if size > 0 {
				pct = clampPct(used / size * 100)
			}
			s.Filesystems = append(s.Filesystems, instMetricsFS{Mountpoint: mp, Used: used, Size: size, Pct: pct})
			if pct > s.TopFSPct {
				s.TopFSPct = pct
				s.TopFSMount = mp
			}
			if ts > s.TS {
				s.TS = ts
			}
		}
		sort.Slice(s.Filesystems, func(i, j int) bool { return s.Filesystems[i].Pct > s.Filesystems[j].Pct })

		// NICs: pair net_rx:<dev> / net_tx:<dev>. Sum non-loopback for the headline.
		nicSeen := map[string]bool{}
		for _, k := range keys {
			var dev string
			if d := strings.TrimPrefix(k, "net_rx:"); d != k {
				dev = d
			} else if d := strings.TrimPrefix(k, "net_tx:"); d != k {
				dev = d
			} else {
				continue
			}
			if nicSeen[dev] {
				continue
			}
			nicSeen[dev] = true
			// Only the guest's real uplink NICs — drop loopback/veth/bridge/etc.
			if !isPhysicalIface(dev) {
				continue
			}
			rx, ts1, _ := latestSample(db, "net_rx:"+dev)
			tx, ts2, _ := latestSample(db, "net_tx:"+dev)
			s.NICs = append(s.NICs, instMetricsNIC{Device: dev, RxBps: rx, TxBps: tx})
			s.NetMbps += (rx + tx) * 8 / 1e6
			if ts1 > s.TS {
				s.TS = ts1
			}
			if ts2 > s.TS {
				s.TS = ts2
			}
		}
		sort.Slice(s.NICs, func(i, j int) bool {
			return (s.NICs[i].RxBps + s.NICs[i].TxBps) > (s.NICs[j].RxBps + s.NICs[j].TxBps)
		})

		// Disks: pair disk_r:<dev> / disk_w:<dev>. Sum whole-disk devices only.
		diskSeen := map[string]bool{}
		for _, k := range keys {
			var dev string
			if d := strings.TrimPrefix(k, "disk_r:"); d != k {
				dev = d
			} else if d := strings.TrimPrefix(k, "disk_w:"); d != k {
				dev = d
			} else {
				continue
			}
			if diskSeen[dev] {
				continue
			}
			diskSeen[dev] = true
			// Only whole real block devices — drop loop*, dm-*, partitions and
			// QEMU firmware blockers so the popup matches the Monitor disk chart.
			if !physicalDiskRe.MatchString(dev) {
				continue
			}
			rd, ts1, _ := latestSample(db, "disk_r:"+dev)
			wr, ts2, _ := latestSample(db, "disk_w:"+dev)
			s.Disks = append(s.Disks, instMetricsDisk{Device: dev, RBps: rd, WBps: wr})
			s.DiskIOMbps += (rd + wr) / 1e6
			if ts1 > s.TS {
				s.TS = ts1
			}
			if ts2 > s.TS {
				s.TS = ts2
			}
		}
		sort.Slice(s.Disks, func(i, j int) bool {
			return (s.Disks[i].RBps + s.Disks[i].WBps) > (s.Disks[j].RBps + s.Disks[j].WBps)
		})

		out[name] = s
	}

	jsonOK(w, map[string]any{
		"host_cpus": runtime.NumCPU(),
		"instances": out,
	})
}

// latestSample returns the newest Tier-0 sample's avg value + timestamp for a
// series. ok is false when the series has no samples.
func latestSample(db *capacityrrd.DB, key string) (float64, int64, bool) {
	samples := db.Query(0, key)
	if len(samples) == 0 {
		return 0, 0, false
	}
	last := samples[len(samples)-1]
	return last.Avg, last.TS, true
}

func clampPct(p float64) float64 {
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}

func hasKey(keys []string, want string) bool {
	for _, k := range keys {
		if k == want {
			return true
		}
	}
	return false
}

// querySamples returns the samples for one series, filtered to those at or
// after `since` (0 = all). Mirrors the cut logic in HandleLXDInstancePerf.
func querySamples(db *capacityrrd.DB, tier int, key string, since int64) []capacityrrd.CapSample {
	samples := db.Query(tier, key)
	if since > 0 {
		cut := len(samples)
		for i, s := range samples {
			if s.TS >= since {
				cut = i
				break
			}
		}
		samples = samples[cut:]
	}
	if samples == nil {
		samples = []capacityrrd.CapSample{}
	}
	return samples
}

// sumKeys aggregates samples across every series whose key starts with
// `prefix`. When `deviceFilter` is non-nil it must match the part of the
// key after the prefix. Samples are aligned by timestamp; any timestamp
// present in at least one series ends up in the result with summed avg /
// min / max / n values. Returns nil when no matching series exists.
func sumKeys(db *capacityrrd.DB, tier int, keys []string, prefix string, deviceFilter *regexp.Regexp, since int64) []capacityrrd.CapSample {
	type accum struct {
		min, avg, max float64
		n             int
	}
	bag := map[int64]*accum{}
	matched := 0
	for _, k := range keys {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if deviceFilter != nil && !deviceFilter.MatchString(k[len(prefix):]) {
			continue
		}
		matched++
		for _, s := range querySamples(db, tier, k, since) {
			a := bag[s.TS]
			if a == nil {
				a = &accum{}
				bag[s.TS] = a
			}
			a.min += s.Min
			a.avg += s.Avg
			a.max += s.Max
			if s.N > a.n {
				a.n = s.N
			}
		}
	}
	if matched == 0 {
		return nil
	}
	ts := make([]int64, 0, len(bag))
	for k := range bag {
		ts = append(ts, k)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	out := make([]capacityrrd.CapSample, 0, len(ts))
	for _, t := range ts {
		a := bag[t]
		out = append(out, capacityrrd.CapSample{TS: t, Min: a.min, Avg: a.avg, Max: a.max, N: a.n})
	}
	return out
}
