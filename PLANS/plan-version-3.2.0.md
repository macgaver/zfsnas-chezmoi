# Version 3.2.0 — Plan

## Goals
1. **Y-axis units** on dashboard 24h charts: Network → Mbit/s, Disk I/O → MB/s
2. **Per-NIC network chart**: 2 lines (RX + TX) per external interface instead of aggregated totals

---

## Feature 1 — Y-axis units

### Problem
Dashboard charts (`dash-chart-net`, `dash-chart-disk`) currently store and display in KB/s with no unit label on the Y axis (only in tooltips).

### Backend changes — `system/metrics_collector.go`

**Network:** Change storage unit from KB/s to Mbit/s.
- Old: `float64(deltaBytes) / 1024 / dtSec` → `net_rx_kbps`
- New: `float64(deltaBytes) * 8 / 1_000_000 / dtSec` → `net_rx_mbps`
- Note: uses SI Mbit (1 Mbit = 10⁶ bits), consistent with NIC speed ratings.
- Rename RRD series keys from `net_rx_kbps`/`net_tx_kbps` to `net_rx_mbps`/`net_tx_mbps`.

**Disk I/O:** Change storage unit from KB/s to MB/s.
- Old: `sectors * 512 / 1024 / dtSec` → `disk_read_kbps`
- New: `sectors * 512 / 1_048_576 / dtSec` → `disk_read_mbps` (MiB/s, but labelled MB/s)
- Rename RRD series keys from `disk_read_kbps`/`disk_write_kbps` to `disk_read_mbps`/`disk_write_mbps`.

> Old KB/s series remain in the JSON file but are simply ignored — no migration needed.

### Backend changes — `handlers/dashboard.go`

Update `allMetricSeries` to reference the renamed keys:
```go
"net_rx_mbps", "net_tx_mbps",
"disk_read_mbps", "disk_write_mbps",
```

### Frontend changes — `static/index.html`

**`_dashChartOpts()`** — add Y-axis unit label to ticks:
```js
ticks: {
  callback: val => yMax === 100 ? val + '%' : val.toFixed(1) + ' ' + yLabel,
}
```

**`_renderDashboardCharts()`** — update keys and labels:
```js
const netRx = data.net_rx_mbps || [];
const netTx = data.net_tx_mbps || [];
const diskR = data.disk_read_mbps  || [];
const diskW = data.disk_write_mbps || [];
```

Dataset labels and chart Y-label args:
- Network: `'RX Mbit/s'`, `'TX Mbit/s'`, yLabel = `'Mbit/s'`
- Disk:    `'Read MB/s'`, `'Write MB/s'`, yLabel = `'MB/s'`

Update the live I/O bar at the top of the page (section "Disk I/O charts"):
- `initIOCharts()`: `makeChart('io-chart-read', 'MB/s')`, `makeChart('io-chart-write', 'MB/s')`
- `_ioChartOptions()`: tooltip callback uses `MB/s`
- `updateIOCharts()`: data values come from `/api/sysinfo/diskio` which returns `read_kbps`/`write_kbps` — divide by 1024 before pushing to buffer to convert to MB/s.
- Update label `<div class="io-chart-label">Read KB/s</div>` → `Read MB/s` / `Write MB/s` in HTML.

---

## Feature 2 — Per-NIC network chart

### Design decisions
- **External interface filter** (name-prefix exclusion):
  - Exclude: `lo`, any starting with `docker`, `veth`, `virbr`, `br-`, `tun`, `tap`, `vxlan`, `dummy`
  - Include: everything else (`eth*`, `en*`, `ens*`, `enp*`, `eno*`, `em*`, `wlan*`, `bond*`, etc.)
- **RRD series naming:** `net_{iface}_rx` / `net_{iface}_tx` (in Mbit/s, no unit suffix in key)
- **Dynamic discovery:** frontend detects NIC names from API response keys, no hardcoding.
- **Color palette:** paired colors per NIC index:
  - NIC 0: RX `#32d74b` (green), TX `#ff9f0a` (orange)  ← same as current
  - NIC 1: RX `#64d2ff` (cyan),  TX `#bf5af2` (purple)
  - NIC 2: RX `#ff453a` (red),   TX `#ffd60a` (yellow)
  - NIC 3+: cycle through a fallback palette

### Backend changes — `system/metrics_collector.go`

1. Add `isExternalInterface(name string) bool`:
```go
func isExternalInterface(name string) bool {
    exclude := []string{"lo", "docker", "veth", "virbr", "br-", "tun", "tap", "vxlan", "dummy"}
    for _, pfx := range exclude {
        if strings.HasPrefix(name, pfx) {
            return false
        }
    }
    return true
}
```

2. Update `readNetStats()` — apply filter:
```go
if !isExternalInterface(iface) { continue }
```
(loopback is already filtered; this adds the rest.)

3. Replace aggregated recording with per-interface recording:
```go
// Old: single net_rx_mbps / net_tx_mbps
// New: one series per NIC
for iface, cur := range curNet {
    if prev, ok := prevNet[iface]; ok {
        rx := float64(cur.rxBytes-prev.rxBytes) * 8 / 1_000_000 / dtSec
        tx := float64(cur.txBytes-prev.txBytes) * 8 / 1_000_000 / dtSec
        db.Record("net_"+iface+"_rx", rx, now)
        db.Record("net_"+iface+"_tx", tx, now)
    }
}
```

4. Add `GetNetInterfaces() []string` to expose the known external NIC list to the handler:
```go
var knownNetIfaces []string  // set once during first sample, or updated each tick

// During collection, track which ifaces were seen:
ifaces := make([]string, 0)
for iface := range curNet { ifaces = append(ifaces, iface) }
sort.Strings(ifaces)
knownNetIfaces = ifaces
```

### Backend changes — `handlers/dashboard.go`

Update `allMetricSeries` to be dynamic for network:
- Remove hardcoded `net_rx_mbps`/`net_tx_mbps`.
- In `HandleGetDashboardMetrics`, ask `system.GetNetInterfaces()` and add `net_{iface}_rx` / `net_{iface}_tx` for each.
- Keep disk and CPU/mem series static.

```go
func HandleGetDashboardMetrics(w http.ResponseWriter, r *http.Request) {
    db := system.GetMetricsDB()
    ...
    keys := buildMetricKeys()  // includes dynamic net_* keys
    ...
    // Also return iface list so frontend can discover them:
    result["_net_ifaces"] = buildIfaceList()  // []string as JSON
    jsonOK(w, result)
}
```

Alternative simpler approach: return all series in the RRD that start with `net_` — the RRD `Series` map already contains them. Add a `DB.Keys() []string` method that returns all known series keys.

**Preferred approach: DB.Keys() + frontend pattern match**

Add to `rrd.go`:
```go
func (db *DB) Keys() []string {
    db.mu.Lock(); defer db.mu.Unlock()
    keys := make([]string, 0, len(db.data.Series))
    for k := range db.data.Series { keys = append(keys, k) }
    return keys
}
```

In `HandleGetDashboardMetrics`, build `keys` by scanning `db.Keys()` for `net_*_rx` and `net_*_tx` patterns, plus static CPU/mem/disk keys.

### Frontend changes — `static/index.html`

**Legend (HTML section):**
Replace static `▬ RX / ▬ TX` spans with a `<div id="dash-net-legend">` placeholder, populated dynamically from JS.

**`_renderDashboardCharts(data)`:**
```js
// Discover NIC names from response keys: net_{iface}_rx
const nicNames = Object.keys(data)
  .filter(k => k.startsWith('net_') && k.endsWith('_rx'))
  .map(k => k.slice(4, -3))   // strip "net_" prefix and "_rx" suffix
  .sort();

const NIC_RX_COLORS = ['#32d74b','#64d2ff','#ff453a','#a78bfa'];
const NIC_TX_COLORS = ['#ff9f0a','#bf5af2','#ffd60a','#34d399'];

const netDatasets = [];
const legendItems = [];

nicNames.forEach((iface, i) => {
    const rxData = data['net_'+iface+'_rx'] || [];
    const txData = data['net_'+iface+'_tx'] || [];
    const rxD = _buildTimeline([...rxData, ...txData], rxData);  // share timeline
    // actually build shared timeline from all nic data combined...
    const rxColor = NIC_RX_COLORS[i % NIC_RX_COLORS.length];
    const txColor = NIC_TX_COLORS[i % NIC_TX_COLORS.length];
    netDatasets.push(_dashDS(iface+' RX', rxColor, rxD.dataArrays[0], false));
    netDatasets.push(_dashDS(iface+' TX', txColor, txD.dataArrays[0], false));
    legendItems.push(`<span style="color:${rxColor}">▬ ${iface} RX</span>`);
    legendItems.push(`<span style="color:${txColor}">▬ ${iface} TX</span>`);
});

// Update legend DOM
document.getElementById('dash-net-legend').innerHTML = legendItems.join(' ');

// Build chart with all datasets
_makeDashChart('dash-chart-net', netDatasets, sharedLabels, 'Mbit/s', null);
```

Note: `_buildTimeline` needs to accept multiple series arrays to compute a merged label set — or we reuse the timestamp of the first available series. Simplest: use any one NIC's RX series for the labels, and map all others to the same grid.

**Info-tip update:**
Update `data-tip` on the Network I/O card to reflect per-NIC display and Mbit/s units.

---

## Files Changed Summary

| File | Change |
|------|--------|
| `system/metrics_collector.go` | Unit conversion (Mbit/s, MB/s), per-NIC series, `isExternalInterface()`, `GetNetInterfaces()` |
| `handlers/dashboard.go` | Dynamic `net_*` series discovery, update static series names |
| `internal/rrd/rrd.go` | Add `Keys() []string` method |
| `static/index.html` | Y-axis unit callbacks, dynamic NIC legend, per-NIC datasets, rename series keys, disk I/O bar label fix |

---

## Notes / Edge Cases

- **Single NIC:** Behaves identically to before, just with proper Mbit/s label.
- **NIC appears/disappears:** RRD keeps the old series forever (harmless ring buffer). Frontend only renders NICs present in the latest API response.
- **No NICs detected (all filtered):** Chart renders empty gracefully.
- **`br0` as real interface:** Will be included since `br0` doesn't match `br-` prefix. Correct for typical NAS bridge setups.
- **Existing metrics.rrd.json:** Old `net_rx_kbps`/`net_tx_kbps`/`disk_read_kbps`/`disk_write_kbps` keys remain in the file but are never queried. They will age out naturally as the file is overwritten over time (or can be manually deleted to reclaim ~4 KB).
- **`_buildTimeline` with multiple series for labels:** Use the first discovered NIC's RX series for the shared time grid. Other NICs' data is mapped onto the same grid independently — same logic as current `_buildTimeline` called per series, but share a single `labels` array.
