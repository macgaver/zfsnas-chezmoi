# Firewall event history, gateway latency header and Networking performance tab

Date: 2026-11-06 · Target version: 6.11.6 · Status: approved 2026-11-06

## Why

On 2026-11-05 at 20:10 the house lost internet for about 2½ minutes. The cause
(PPPoE session dropped by the ISP, three redials ignored, back with a new
public IP, dynamic DNS updated) was found only by reading pppd lines in the
host journal. Gateway monitoring was off on .3, so the portal recorded
nothing. The user wants:

> "just simple history of important event that will inform the user about
> downtime and reasons"

plus a way to see gateway latency at a glance and over time.

## Goals

1. **Firewall event history**: a persistent, plain-language list of important
   events (time, gateway/name, what happened, reason). It works even when
   gateway monitoring is off.
2. **Routing page** (`fw-gateways`, `static/sdn-gw-nat.js`): a
   "Gateway Status History" table with gateway and PPPoE events, newest first.
3. **Activity & Events** (top-right button): a new **SDN** tab, visible only
   when the Firewall is enabled, listing *all* firewall events.
4. **Header latency figure**: in Network Focus (full) mode, a small
   `1.4/3.6ms` between the two dials, without taking extra space.
5. **Performance → Networking tab** (only when the Firewall is enabled): the
   network graphs move out of Global into a new Networking tab. A gateway
   latency RRD graph comes first in that tab.

## Non-goals

- No editing or deleting events, and no export.
- No new email/alert event types. The existing `firewall_events` alerts stay
  as they are.
- No latency figure in the compact header mode (no dials there). *(builder
  call; the user did not object)*
- No change to how/when gateway monitoring pings.

## Anti-goals (would be a failure even if it "works")

- An empty history after an outage because monitoring was off. PPPoE events
  must come from pppd itself.
- Events lost on reboot or on a portal restart.
- The header getting taller or the dials moving to fit the figure.
- Lint noise: the Suricata "can't reopen interface" flood must not become
  events.

## 1. Event history

### Sources

All recording happens in the **gateway daemon** (`znas-sdn-gw`, root,
`system/sdn_gwmon.go` + `sdn_selfheal.go`). It keeps running when the portal
restarts.

| Source | Event | Text (example) |
|---|---|---|
| pppd journal (`journalctl -t pppd -f -o json`) | `ppp_down` | "PPPoE link down: ISP stopped answering (no reply to 3 echo requests)" |
| | | "PPPoE link down: ISP ended the session" (LCP terminated by peer) |
| | `ppp_retry_failed` | "Reconnect attempt failed: ISP did not answer (no PADO)" |
| | `ppp_auth_failed` | "Login refused by ISP (PAP/CHAP authentication failed)" |
| | `ppp_up` | "PPPoE link up: public IP 174.92.235.203 (was 174.92.237.165), down for 2 min 25 s" |
| gateway monitor (existing `GWEvent`) | `gw_down`, `gw_up`, `gw_failover`, `gw_reconnect` | same wording as the existing alerts |
| dynamic DNS (ddclient cache, compared each healer cycle) | `ddns_ok` | "chezmoi.ca updated: 174.92.237.165 → 174.92.235.203" |
| | `ddns_failed` | "chezmoi.ca update failed: badauth" |
| boot / apply | `safe_mode`, `auto_revert` | existing reasons, reused |

- **Mapping pppd to a gateway:** each pppd runs as `pppd call znas-<id>`. The
  PID from the journal record is resolved via `/proc/<pid>/cmdline` to the
  interface `<id>`, then to the gateway that uses it, and the user-given name
  is shown. If that fails (e.g. pppd already exited), fall back to the only
  PPPoE interface, or show "PPPoE".
- **Message pairing:** "Connection terminated" / "Modem hangup" right after an
  echo failure are merged into the single `ppp_down`. The previous public IP
  comes from the last `ppp_up` or, at daemon start, from the interface address.
- **Downtime:** `ppp_up` and `gw_up` carry `down_for` seconds when a matching
  down event is known.
- **Startup catch-up:** on start, the daemon replays pppd journal lines since
  the newest stored event (`--since`), so nothing is lost across a daemon
  restart or reboot.

### Storage

- `config/sdn/events.jsonl`: one JSON object per line
  `{at, kind, severity(info|warn|error), gateway_id, name, text, down_for?}`,
  mode 0644 so the portal (user `zfsnas`) can read it.
- Capped at 1000 lines. Trim on write once it exceeds about 1100.
- Written only by the daemon. The portal only reads.

### API

`GET /api/sdn/events?scope=gateway|all&limit=N`. Requires Auth +
`view_firewall`; works through InterLink relay like the other `/api/sdn/*`
reads.

## 2. Routing page: "Gateway Status History"

A card at the bottom of the Routing page. It has a table with columns
**Time · Gateway · Event · Details**. Severity is shown as a coloured dot.
Times are shown as `Nov 5 20:10:30`. The table shows the newest 50, with a
"Show all" link that opens the SDN tab of Activity & Events. Same look as the
other `fw-` tables.

## 3. Activity & Events → SDN tab

- A tab button `SDN` (id `act-tab-sdn`), shown only when
  `window._sdnEnabled`.
- Same columns as above for all event kinds, newest first, 200 per page with
  "Load more".
- A filter chip row: All · Gateways · Dynamic DNS · System.

## 4. Header latency figure

- **Data:** `/api/sysinfo/gatewaynet` gains `rtt_ms`, `loss`,
  `monitor_target` and `monitored` for the gateway currently carrying the
  default route. These are read from `/run/znas-sdn/gateways.json`.
- **Display:** a small `1.4/3.6ms` absolutely positioned in the free space at
  the top between `#net-gauge-down` and `#net-gauge-up`. It is shown only when
  `monitored`. A failed latest ping shows `—/3.6ms` in red.
  - The first value is the latest RTT.
  - The second is the average of every RTT this page has seen since it was
    opened. It resets on reload and on `_resetNetHeader` (InterLink switch).
- **Click:** a popover in the same style as the existing header popups
  (`vn-` tip). It contains:
  - a line graph of the last 15 minutes of RTT (gaps for unanswered pings)
  - the sentence: "1.4 ms is the current latency to <target>; 3.6 ms is the
    average since you opened this page."
  - the target and its meaning ("the ISP's side of the PPPoE link" when it is
    the PPP peer)
  - the loss %
- **15-minute history:** the daemon keeps an in-memory ring of
  `{ts, rtt_ms|null}` per monitored gateway, covering 15 min. It writes the
  ring to `/run/znas-sdn/gw-rtt.json`. The ring is exposed via
  `GET /api/sdn/gateway-rtt?id=` (or included in the gatewaynet response if
  it is small enough; builder's call).

## 5. Performance → Networking tab

- When `window._sdnEnabled`, a **Networking** tab button sits after Global.
  `#dash-net-list` (the per-interface Network I/O graphs) is rendered there
  instead of in Global. With the Firewall off, nothing changes.
- **Gateway latency graph**, first in the tab:
  - **Collection:** the portal's 5-minute global perf collector reads the RTT
    ring and, for each monitored gateway, records the min/avg/max of the
    answered pings in the past 5 minutes under `gwrtt_<gatewayID>`.
  - New `capacityrrd.RecordAgg(key, min, avg, max, n, now)` so the 5-min slot
    keeps the true spread and not one value. Tier 1/2 aggregation takes
    min-of-mins / mean-of-avgs / max-of-maxes.
  - Nothing is recorded when monitoring is off.
  - **Display:** one chart, one line per gateway (user-given name in the
    legend). It follows the page's existing Avg/Min/Max selector and time
    ranges, with the same interval and history as the other RRD graphs.
  - The card is shown only if at least one `gwrtt_*` series has data.
  - `rrd.Plausible` accepts 0–10000 ms for `gwrtt_` keys.

## Constraints

- No new Go module dependencies. No browser `confirm/alert`. Custom dropdowns
  only. Interfaces and gateways are shown by their given names.
- New WS/long-lived connections: none.
- New `/api/sdn/*` reads must be in the relay forwarding lists and survive the
  relay soft refresh.
- Sudoers: the daemon is root, so nothing is needed. The portal only reads
  0644 files.
- Version → 6.11.6.
- Uncommitted user work in `static/index.html`, `static/net-header.js` and
  `system/vmnet_live*.go`: edit around it and never revert it.

## Testing

- **Unit:**
  - pppd line classifier (fixtures from the 2026-11-05 journal)
  - pairing/downtime
  - jsonl cap
  - DDNS change detection
  - `RecordAgg` tier roll-up
  - RTT ring window
- **Lab** (znas-sdnlab on .3, which has `sdnlab-ppp`): drop the PPPoE server
  to produce down/retry/up and check both tables. Turn on monitoring and check
  the header figure, the popover and the Networking tab after ≥10 min.
- **Not deployed to .3 (production) unless asked.**

## Calls made by the builder (please check)

- Recording lives in the gateway daemon, not the portal.
- A 1000-event cap; stored in `config/sdn/events.jsonl`.
- Routing card shows 50; the SDN tab shows all, with filter chips.
- No latency figure in compact header mode.
- The latency ring is in `/run`, so it is lost on reboot. The 5-min RRD
  persists.
- One latency line per gateway, following the existing Avg/Min/Max selector — **decided by the user (option a)**
  (rather than 3 lines per gateway).
