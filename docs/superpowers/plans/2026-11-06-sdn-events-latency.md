# Firewall Event History + Gateway Latency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A persistent, plain-language firewall event history (Routing card and an Activity & Events "SDN" tab), a gateway latency figure in the Network Focus header, and a Performance "Networking" tab with a gateway latency RRD graph.

**Architecture:** The root gateway daemon (`znas-sdn-gw`) records the events and keeps the RTT ring. Event sources are the pppd journal, gateway monitor events, DDNS cache changes, safe mode and auto-revert. Events go to `config/sdn/events.jsonl` (0644). The RTT ring goes to `/run/znas-sdn/gw-rtt.json`. The portal only reads these files. Its 5-minute collector rolls the ring into `global_perf.rrd.json` as `gwrtt_<gatewayID>` with true min/avg/max.

**Tech Stack:** Go stdlib, gorilla/mux, inline SPA JS (Chart.js already loaded).

**Spec:** `docs/superpowers/specs/2026-11-06-sdn-events-latency-design.md`

## Global Constraints

- No new Go module deps. No `confirm()/alert()/prompt()`. No raw `<select>`.
- Show gateways and interfaces by their given names (`ifLabel`/gateway `Name`).
- Every UI piece is hidden unless `window._sdnEnabled`.
- Version → `6.11.6` (`internal/version/version.go`).
- Do not revert the existing uncommitted edits in `static/index.html`, `static/net-header.js` or `system/vmnet_live*.go`.
- Do not deploy to .3 (production). Test on the lab VM `znas-sdnlab` only.
- No git commands.

## Review Focus

1. A pppd PID whose `/proc/<pid>` is gone (pppd restarted): the event is still recorded, using the fallback name. → Task 2 test `TestPPPGatewayFallback`.
2. The daemon restarts in the middle of an outage: catch-up must not duplicate events already stored. → Task 2 test `TestPPPCatchUpSkipsStored`.
3. A truncated last line in `events.jsonl` (crash mid-write): reads skip it and appends still work. → Task 1 test `TestEventsCorruptLine`.
4. RTT ring with no answered pings in a 5-min window: no RRD sample (no zeros). → Task 4 test `TestRTTWindowAllLost`.
5. A ddclient cache that is missing, then appears: no "updated" event for an IP it already had at daemon start. → Task 3 test `TestDDNSFirstSightNoEvent`.

---

### Task 1: Event store

**Files:**
- Create: `system/sdn_events.go`
- Test: `system/sdn_events_test.go`

**Interfaces:**
- Produces:
  - `type SDNEvent struct {At time.Time "at"; Kind, Severity, GatewayID, Name, Text string; DownFor int64 "down_for,omitempty"}` (json snake_case).
  - Kinds: `ppp_down`, `ppp_retry_failed`, `ppp_auth_failed`, `ppp_up`, `gw_down`, `gw_up`, `gw_failover`, `gw_reconnect`, `ddns_ok`, `ddns_failed`, `safe_mode`, `auto_revert`.
  - `func SDNEventCategory(kind string) string` returns `gateway`, `ddns` or `system`.
  - `func SDNEventsPath(configDir string) string` returns `<configDir>/sdn/events.jsonl`.
  - `func SDNRecordEvent(configDir string, e SDNEvent) error`: append (mode 0644). Once there are more than 1100 lines, rewrite keeping the newest 1000. Mutex-protected.
  - `func SDNReadEvents(configDir, category string, limit int) []SDNEvent`: newest first; `category` is `""`/`all` or one of the three.

- [ ] Tests:
  - `TestEventsAppendAndRead`: newest first, limit honoured, category filter.
  - `TestEventsCap`: after 1101 records, 1000 remain and the newest is kept.
  - `TestEventsCorruptLine`: a half line at the end is skipped, the next append is readable.
- [ ] Implement; `go test ./system -run TestEvents`.

### Task 2: pppd journal watcher

**Files:**
- Create: `system/sdn_pppwatch.go`
- Test: `system/sdn_pppwatch_test.go`

**Interfaces:**
- Consumes: Task 1.
- Produces:
  - `type pppLine struct{At time.Time; PID int; Msg string}`
  - `type pppWatcher struct` holding per-PID state: `iface`, `lastIP`, `downAt`, `pendingReason`.
  - `func (w *pppWatcher) feed(l pppLine) []SDNEvent`: pure; maps the PID to a gateway via the injectable `w.resolve func(pid int) (gwID, name string)`.
  - `func sdnPPPWatchLoop(configDir string, st sdn.Store)`: runs `journalctl -t pppd -f -o json --since <newest stored ppp_* At + 1s, or "-10min">`, parses `__REALTIME_TIMESTAMP`, `_PID` and `MESSAGE`, and drops lines with `At <= newest stored`.
  - Restarts `journalctl` on exit after 5 s.
  - `resolve` reads `/proc/<pid>/cmdline` for `call znas-<id>`, then the config interface `<id>`, then the gateway whose `Interface` matches. Fallback: the only PPPoE gateway, else name `PPPoE`.
- Classifier (message → effect):
  - `No response to N echo-requests` → reason "ISP stopped answering (no reply to N echo requests)".
  - `LCP terminated by peer` → reason "ISP ended the session".
  - `Connection terminated.` → emit `ppp_down` (warn) with the pending reason, else "connection lost". Set `downAt`.
  - `Timeout waiting for PADO packets` → `ppp_retry_failed` (warn) "Reconnect attempt failed: ISP did not answer (no PADO)".
  - `PAP authentication failed` / `CHAP authentication failed` → `ppp_auth_failed` (error).
  - `local  IP address X` → `ppp_up` (info): "PPPoE link up: public IP X" + " (was Y)" if Y differs + ", down for <dur>" when `downAt` is set. `DownFor` = seconds.
- [ ] Tests (fixture = the 2026-11-05 20:10–20:12:55 lines):
  - `TestPPPOutageSequence`: exactly `ppp_down`, 3× `ppp_retry_failed`, `ppp_up` with DownFor=139 (20:10:36→20:12:55) and text containing "was 174.92.237.165".
  - `TestPPPGatewayFallback`
  - `TestPPPCatchUpSkipsStored`
  - `TestPPPAuthFailed`
- [ ] Start `go sdnPPPWatchLoop(...)` from `SDNGatewayMonitor`. The daemon must know `configDir`: use `st.Dir`.

### Task 3: Monitor, DDNS and system events into the store

**Files:**
- Modify: `system/sdn_gwmon.go` (where `m.events` are appended), `system/sdn_selfheal.go` (`ddns`), and the safe-mode/auto-revert sites (`system/sdn_boot.go`, `main_sdn.go` revert).
- Test: `system/sdn_events_sources_test.go`

**Interfaces:**
- Produces:
  - `func (m *gwMonitor) addEvent(e GWEvent)`, which appends to `m.events` and also calls `SDNRecordEvent` with `gw_<kind>`. `gw_up` carries `DownFor` from the matching `gw_down`.
  - `m.configDir string` field.
  - DDNS: healer keeps `ddnsSeen map[host]struct{ip,status}`. On the first sighting it only records state. Afterwards:
    - IP change with status good/nochg → `ddns_ok` "<host> updated: OLD → NEW".
    - Status change to a non-good status → `ddns_failed` "<host> update failed: <status>".
- [ ] Tests: `TestGWEventRecorded` (down then up gives DownFor), `TestDDNSChange`, `TestDDNSFirstSightNoEvent`.

### Task 4: RTT ring + gatewaynet fields

**Files:**
- Modify: `system/sdn_gwmon.go`, the `HandleGetGatewayNet` handler and its system struct.
- Create: `system/sdn_gwrtt.go`
- Test: `system/sdn_gwrtt_test.go`

**Interfaces:**
- Produces:
  - `type RTTPoint struct{TS int64 "ts"; MS *float64 "ms"}` (nil = lost).
  - `type GWRTTFile map[string][]RTTPoint` (gateway ID → last 15 min), written to `/run/znas-sdn/gw-rtt.json` each cycle in which a probe ran.
  - `func SDNGatewayRTT() GWRTTFile`
  - `func RTTWindow(pts []RTTPoint, from, to int64) (min, avg, max float64, n int)`: n=0 when nothing was answered.
  - gatewaynet JSON gains `monitored bool`, `rtt_ms float64`, `rtt_ok bool`, `loss float64`, `monitor_target string`, `gateway_id string`, for the active gateway in `gateways.json`.
- [ ] Tests: `TestRTTRingTrim15m`, `TestRTTWindow`, `TestRTTWindowAllLost`.

### Task 5: RRD RecordAgg + collector

**Files:**
- Modify: `internal/capacityrrd/capacityrrd.go`, `internal/rrd/plausible.go`, `system/global_perf_collector.go`
- Test: `internal/capacityrrd/recordagg_test.go`

**Interfaces:**
- Produces:
  - `func (db *DB) RecordAgg(key string, mn, avg, mx float64, n int, now time.Time)`: tier 0 stores them as given. Tiers 1/2 roll up min-of-mins, n-weighted mean, and max-of-maxes, so pending buckets keep CapSamples next to the raw floats.
  - `Plausible("gwrtt_*", v)` is true for 0 ≤ v ≤ 10000.
  - Collector: every 5 min, for each ID in `SDNGatewayRTT()`, `RTTWindow(now-300,now)`; if n>0, `RecordAgg("gwrtt_"+id, ...)`.
- [ ] Test `TestRecordAggRollup`: two tier-0 aggs (1/2/3, n=10) and (2/5/9, n=30) in the same 30-min bucket; after the rollup, tier1 = min 1, avg 4.25, max 9.

### Task 6: API

**Files:**
- Create: `handlers/sdn_events.go`
- Modify: `handlers/router.go`

**Interfaces:**
- `GET /api/sdn/events?category=all|gateway|ddns|system&limit=N` (default 200, max 1000) → `{"events":[SDNEvent...]}`, wrapped in `fwView`.
- `GET /api/sdn/gateway-rtt?id=<gwID>` → `{"points":[RTTPoint...]}`, wrapped in `fwView`.
- `/api/perf/...`: the existing global perf series endpoint already returns all keys. Verify `gwrtt_` keys pass through; display names come from `/api/sdn/config` gateways.

### Task 7: UI: Routing card + Activity SDN tab

**Files:** `static/sdn-gw-nat.js` (Routing page), `static/index.html` (activity tab strip + pane + `switchActivityTab`).

- Shared renderer `window._sdnEventsTable(events)` (in `sdn-gw-nat.js`):
  - columns Time (`Nov 5 20:10:30`) · Gateway/Name · Event · Details
  - severity dot (info = ok colour, warn = amber, error = red)
  - empty state "No events recorded yet."
- Routing card "Gateway Status History": `category=gateway&limit=50` plus a "Show all" link → `showPage('activity')` then `switchActivityTab('sdn')`.
- SDN tab: chips All · Gateways · Dynamic DNS · System, 200 per page, "Load more". The button is `display:none` unless `_sdnEnabled`.

### Task 8: UI: header latency figure

**Files:** `static/net-header.js`, `static/style.css`, `static/index.html` (a `<button id="net-rtt">` between the gauges).

- `#net-rtt` absolutely positioned at top-centre of the gauge row, font 11px mono, shown only when `last.monitored`.
- Text `${cur}/${avg}ms` with one decimal. When `!rtt_ok`, show `—` in red.
- The average is accumulated per page load over received polls with `rtt_ok`, and reset in `reset()` and `_resetNetHeader`.
- On click, a popover (reuse the `vn-tip` styles) containing:
  - a canvas sparkline of `/api/sdn/gateway-rtt?id=` points, with lost points as gaps
  - the copy "X ms is the current latency to <target>; Y ms is the average since you opened this page."
  - the target hint ("the ISP's side of the PPPoE link" when the target equals the PPP peer) and loss %
  - closes on an outside click or Esc.

### Task 9: UI: Performance Networking tab + latency graph

**Files:** `static/index.html` (perf tab strip, `switchPerfTab`, the render code around `dash-net-list`).

- Tab button `perf-tab-btn-networking` "Networking" after Global, shown only when `_sdnEnabled`. Pane `perf-tab-networking`.
- When shown, `#dash-net-list` is moved (DOM move, the same element) into the pane. When the Firewall is off, it moves back to Global.
- The latency card `#dash-gwrtt-card` comes first in the pane:
  - one dataset per `gwrtt_*` key, labelled with the gateway name
  - y-axis in ms
  - follows `_perfAgg` and the existing range/zoom handling like the net charts
  - hidden when there are no gwrtt keys with samples.

### Task 10: Version, full verification, lab

- [ ] Version `6.11.6`; `gofmt -l .` empty; `go vet ./...`; `go test ./...`.
- [ ] Deploy to the lab VM (`znas-sdnlab`, which has `sdnlab-ppp`):
  - stop the PPPoE server for about 60 s, then restart it
  - check that the Routing card and the SDN tab show down / retry / up with the downtime
  - enable monitoring and check the header figure, the popover, and the Networking tab after ≥10 min

## Changes from the plan made during the build (2026-11-06)

- gatewaynet carries one nested `latency` object (`gateway_id, name, rtt_ms, ok, loss, target, target_is_peer, ts`) instead of flat fields.
- Redial failures are throttled:
  - 3 are recorded one by one, then a summary every 15 min in the first hour, hourly for the rest of the first day, then every 6 h.
  - `ppp_up` says how many attempts failed.
  - Reason: the lab's ISP3 had been down for 27 h and would have flooded the 1000-event cap.
- Extra pppd reasons:
  - "Modem hangup" before "Connection terminated." means the ISP closed the connection.
  - SIGHUP means the redial was requested by the monitor.
  - SIGTERM means stopped by the system.
  - Stale reasons are cleared on redial and reconnect.
- The daemon reloads `/run/znas-sdn/gw-rtt.json` at start, so an upgrade keeps the 15-minute graph.
- Global perf API returns `gateways: {gwrtt_<id>: name}` for the legend.
- Networking is a view of the Global data (same range, Avg/Min/Max and zoom controls), not a separate loader.
