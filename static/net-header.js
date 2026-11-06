// ZNAS — top header modes (user menu → Top header):
//   Storage focus, full     — capacity bar + disk I/O charts (the original)
//   Storage focus, compact  — one row
//   Network focus, full     — the gateway's live traffic + two speedtest dials
//   Network focus, compact  — one row, two equalizer lines of squares
// The gateway is the interface of the default route; rates come from
// /api/sysinfo/gatewaynet every 3 s, like the disk I/O of the storage header.
// The red marks are the highest rates since this login.
(function () {
  'use strict';

  const LS_MODE = 'znas_header_mode';
  const LS_OLD = 'znas_compact_header';      // the earlier on/off toggle
  const SS_PEAK = 'znas_net_peak';           // highest rates of this login
  const MODES = ['storage-full', 'storage-compact', 'network-full', 'network-compact'];
  const POINTS = 30;                         // same window as the disk I/O charts
  const DL = '#64d2ff', UL = '#bf5af2';      // the Firewall's in/out colours

  let mode = 'storage-full';
  let timer = null, chart = null;
  const buf = { down: new Array(POINTS).fill(null), up: new Array(POINTS).fill(null) };
  let last = null;                           // latest sample
  let peak = { iface: '', down: 0, up: 0 };

  // ── units ──
  function fmtBits(bps, short) {
    bps = Number(bps || 0);
    if (!bps) return short ? { n: '0', u: 'Mbit/s' } : '0';
    const u = bps >= 1e9 ? ['Gbit/s', 1e9] : bps >= 1e6 ? ['Mbit/s', 1e6] : ['Kbit/s', 1e3];
    const v = bps / u[1];
    const n = v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2);
    return short ? { n, u: u[0] } : n + ' ' + u[0];
  }
  function fmtMbps(m) { return m >= 1000 ? (m / 1000) + 'G' : String(m); }

  // ── the dial's scale, speedtest-like: uneven ticks, equal spacing ──
  // 0, 0.5 %, 1 %, 5 %, 10 %, 25 %, 50 %, 75 %, 100 % of the link speed (1 Gbit/s
  // when unknown: PPPoE, tunnels) — for 1 Gbit/s: 0 5 10 50 100 250 500 750 1000.
  const FRACS = [0, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 0.75, 1];
  function ticksMbps() {
    const top = (last && last.speed_mbps) || 1000;
    return FRACS.map(f => Math.round(top * f * 100) / 100);
  }
  function pos(bps) { // 0..1 along the scale
    const t = ticksMbps(), m = bps / 1e6;
    if (m <= 0) return 0;
    for (let i = 1; i < t.length; i++) {
      if (m <= t[i]) return (i - 1 + (m - t[i - 1]) / (t[i] - t[i - 1])) / (t.length - 1);
    }
    return 1;
  }

  // ── modes ──
  function applyMode(m) {
    mode = MODES.includes(m) ? m : 'storage-full';
    const b = document.body;
    b.classList.toggle('compact-header', mode.endsWith('compact'));
    b.classList.toggle('net-header', mode.startsWith('network'));
    document.querySelectorAll('#user-menu-dropdown .um-hdr').forEach(x => x.classList.toggle('on', x.dataset.hdr === mode));
    if (mode.startsWith('network')) start(); else stop();
    if (mode === 'network-full') vnStart(); else vnStop();
    if (window._tkClose) window._tkClose();
  }
  window.setHeaderMode = function (m) {
    applyMode(m);
    try { localStorage.setItem(LS_MODE, mode); } catch (_) {}
    if (typeof window._onHeaderModeSet === 'function') window._onHeaderModeSet(mode);
    if (typeof window.closeUserMenu === 'function') window.closeUserMenu();
  };
  window.getHeaderMode = () => mode;
  // Per-server header (user settings): switches without touching this
  // device's saved default.
  window.applyHeaderMode = function (m) { if (MODES.includes(m) && m !== mode) applyMode(m); };

  function savedMode() {
    try {
      const m = localStorage.getItem(LS_MODE);
      if (m) return m;
      return localStorage.getItem(LS_OLD) === 'true' ? 'storage-compact' : 'storage-full';
    } catch (_) { return 'storage-full'; }
  }

  // ── polling (only while a network header is shown) ──
  function start() {
    if (timer) return;
    loadPeak();
    poll();
    timer = setInterval(poll, 3000);
    vnStart();
  }
  function stop() {
    clearInterval(timer); timer = null;
    vnStop();
  }
  async function poll() {
    if (document.hidden) return;
    let d;
    try {
      const r = await fetch('/api/sysinfo/gatewaynet');
      if (!r.ok) return;
      d = await r.json();
    } catch (_) { return; }
    if (last && last.iface !== d.iface) reset(); // failover or another server
    last = d;
    rttNote(d.latency);
    if (d.ready) {
      shift(buf.down, d.rx_bps); shift(buf.up, d.tx_bps);
      // with the stack shown, the dials and their maximum follow its blocks
      if (!vnGauges()) notePeak(d.iface, d.rx_bps, d.tx_bps);
    }
    draw();
  }
  function shift(a, v) { a.shift(); a.push(v); }
  function notePeak(iface, down, up) {
    if (peak.iface !== iface) peak = { iface, down: 0, up: 0 };
    peak.down = Math.max(peak.down, down); peak.up = Math.max(peak.up, up);
    savePeak();
  }
  // The dials' value: in Network Focus (full) with the stack shown, the
  // gateway total of its newest block (same interval, same counters as the
  // graph and its popup), else the 3 s gateway poll.
  function vnGauges() { return vnShown() && VN.pts.length > 0; }
  function gaugeVal(which) {
    if (vnGauges()) { const p = VN.pts[VN.pts.length - 1]; return (which === 'down' ? p.total_down : p.total_up) || 0; }
    const d = last || {};
    return d.ready ? (which === 'down' ? d.rx_bps : d.tx_bps) : 0;
  }
  function reset() {
    buf.down.fill(null); buf.up.fill(null);
    last = null;
    RTT.sum = 0; RTT.n = 0; RTT.ts = 0; RTT.gw = '';
    if (chart) { chart.data.datasets.forEach(ds => { ds.data = []; }); chart.update('none'); }
  }
  // An InterLink switch shows another server: its gateway, its traffic.
  window._resetNetHeader = function () {
    reset();
    peak = { iface: '', down: 0, up: 0 };
    savePeak();
    vnReset();
    if (timer) { poll(); vnPoll(); }
  };
  function loadPeak() {
    try { const p = JSON.parse(sessionStorage.getItem(SS_PEAK) || 'null'); if (p && typeof p.down === 'number') peak = p; } catch (_) {}
  }
  function savePeak() {
    try { sessionStorage.setItem(SS_PEAK, JSON.stringify(peak)); } catch (_) {}
  }
  // a new login starts the maxima over
  window._clearNetPeak = function () { peak = { iface: '', down: 0, up: 0 }; try { sessionStorage.removeItem(SS_PEAK); } catch (_) {} };

  // ── drawing ──
  function draw() {
    const d = last || {};
    // the interface by the name it was given (Firewall), else its Linux name
    const nm = d.name || d.iface;
    const devTip = d.name && d.iface ? `Linux interface: ${d.iface}` : '';
    const sum = document.getElementById('net-summary');
    if (sum) {
      sum.textContent = !d.iface ? 'No default route'
        : [nm, d.addr ? d.addr.split('/')[0] : '', d.speed_mbps ? 'link ' + fmtBits(d.speed_mbps * 1e6)
          : (d.max_rx_bps || d.max_tx_bps ? `max seen ${fmtBits(d.max_rx_bps)} down, ${fmtBits(d.max_tx_bps)} up` : '')].filter(Boolean).join(' · ');
      sum.title = devTip;
    }
    const ci = document.getElementById('net-chart-iface');
    if (ci) { ci.textContent = d.iface ? '· ' + nm : ''; ci.title = devTip; }
    const empty = document.getElementById('net-empty');
    if (empty) empty.style.display = last && !d.iface ? 'flex' : 'none';
    if (mode === 'network-full') { if (!vnShown()) drawChart(); drawGauge('down'); drawGauge('up'); }
    rttDraw();
    if (mode === 'network-compact') { drawEq('down'); drawEq('up'); }
  }

  function cssVar(n, fb) { return getComputedStyle(document.body).getPropertyValue(n).trim() || fb; }

  function drawChart() {
    const cv = document.getElementById('net-chart');
    if (!cv || typeof window.Chart !== 'function') return;
    if (!chart) {
      const grid = cssVar('--border', 'rgba(255,255,255,0.08)'), tick = cssVar('--text-3', '#8e8e93');
      chart = new window.Chart(cv, {
        type: 'line',
        data: { labels: new Array(POINTS).fill(''), datasets: [
          { label: 'Download', data: [], borderColor: DL, backgroundColor: DL + '33', fill: true, borderWidth: 2, pointRadius: 0, tension: 0.3 },
          { label: 'Upload', data: [], borderColor: UL, backgroundColor: UL + '22', fill: true, borderWidth: 2, pointRadius: 0, tension: 0.3 },
        ] },
        options: {
          animation: false, responsive: true, maintainAspectRatio: false,
          interaction: { mode: 'index', intersect: false },
          plugins: { legend: { display: false },
            tooltip: { callbacks: { title: items => { const i = items[0].dataIndex; return Math.round((POINTS - 1 - i) * 3) + ' s ago'; },
              label: c => ' ' + c.dataset.label + ': ' + fmtBits(c.raw) } } },
          scales: { x: { display: false },
            y: { beginAtZero: true, grid: { color: grid }, border: { display: false },
              ticks: { color: tick, font: { size: 10 }, maxTicksLimit: 3, callback: v => fmtBits(v) } } },
        },
      });
    }
    chart.data.datasets[0].data = buf.down.slice();
    chart.data.datasets[1].data = buf.up.slice();
    chart.update('none');
  }

  // A 270° dial: track, coloured arc up to the value, needle, ticks, and a
  // red mark at the highest rate since this login.
  function drawGauge(which) {
    const el = document.getElementById('net-gauge-' + which);
    if (!el) return;
    const d = last || {};
    const v = gaugeVal(which);
    const pk = peak.iface === d.iface ? peak[which] : 0;
    const col = which === 'down' ? DL : UL;
    const W = 132, H = 126, cx = 66, cy = 58, r = 48;
    const A0 = 135, SPAN = 270; // degrees, clockwise from +x
    const pt = (f, rr) => { const a = (A0 + SPAN * f) * Math.PI / 180; return [cx + rr * Math.cos(a), cy + rr * Math.sin(a)]; };
    const arc = (f0, f1, rr) => {
      const [x0, y0] = pt(f0, rr), [x1, y1] = pt(f1, rr);
      return `M${x0.toFixed(2)} ${y0.toFixed(2)} A${rr} ${rr} 0 ${SPAN * (f1 - f0) > 180 ? 1 : 0} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
    };
    const f = pos(v), fp = pos(pk);
    const ticks = ticksMbps();
    let tickSvg = '';
    ticks.forEach((t, i) => {
      const ff = i / (ticks.length - 1);
      const [x0, y0] = pt(ff, r - 9), [x1, y1] = pt(ff, r - 5), [tx, ty] = pt(ff, r - 17);
      tickSvg += `<line x1="${x0.toFixed(1)}" y1="${y0.toFixed(1)}" x2="${x1.toFixed(1)}" y2="${y1.toFixed(1)}" class="ng-tick"/>`;
      if (i % 2 === 0 || i === ticks.length - 1) tickSvg += `<text x="${tx.toFixed(1)}" y="${(ty + 3).toFixed(1)}" class="ng-tl">${fmtMbps(t)}</text>`;
    });
    const [nx, ny] = pt(f, r - 14);
    const [p0x, p0y] = pt(fp, r - 7), [p1x, p1y] = pt(fp, r + 7);
    const val = fmtBits(v, true);
    // value and unit on one line under the arc's ends, the name under it
    const nm = which === 'down' ? 'DOWNLOAD' : 'UPLOAD', nmW = nm.length * 6.4, x0 = cx - (nmW + 9) / 2;
    const tri = which === 'down' ? `M${x0.toFixed(1)} ${cy + 57}h7l-3.5 5z` : `M${x0.toFixed(1)} ${cy + 62}h7l-3.5 -5z`;
    el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="${which === 'down' ? 'Download' : 'Upload'} ${fmtBits(v)}, highest ${fmtBits(pk)}">
      <defs><linearGradient id="ng-g-${which}" x1="0" y1="1" x2="1" y2="0"><stop offset="0" stop-color="${col}" stop-opacity=".55"/><stop offset="1" stop-color="${col}"/></linearGradient></defs>
      <path d="${arc(0, 1, r)}" class="ng-track"/>
      ${f > 0.002 ? `<path d="${arc(0, Math.max(f, 0.003), r)}" stroke="url(#ng-g-${which})" class="ng-val"/>` : ''}
      ${tickSvg}
      ${pk > 0 ? `<line x1="${p0x.toFixed(1)}" y1="${p0y.toFixed(1)}" x2="${p1x.toFixed(1)}" y2="${p1y.toFixed(1)}" class="ng-peak"><title>Highest since login: ${fmtBits(pk)}</title></line>` : ''}
      <line x1="${cx}" y1="${cy}" x2="${nx.toFixed(1)}" y2="${ny.toFixed(1)}" class="ng-needle" stroke="${col}"/>
      <circle cx="${cx}" cy="${cy}" r="4" fill="${col}"/>
      <text x="${cx}" y="${cy + 49}" class="ng-v">${d.iface ? val.n : '—'}<tspan class="ng-u" dx="3">${val.u}</tspan></text>
      <path d="${tri}" fill="${col}"/>
      <text x="${(x0 + 10).toFixed(1)}" y="${cy + 62}" class="ng-n" fill="${col}">${nm}</text>
    </svg>
    <div class="ng-max" title="The red mark: the highest rate since you logged in"><span class="ng-mk"></span>max ${pk ? fmtBits(pk) : '—'}</div>`;
  }

  // Compact: a line of squares filling the width left in the header, green →
  // yellow → red along the same scale as the dials; the square at the session
  // maximum stays lit.
  const SQ_MIN = 4;
  function eqCount(el) {
    const sq = el.firstElementChild;
    const w = sq ? sq.offsetWidth : 9, gap = 2;
    return Math.max(SQ_MIN, Math.floor((el.clientWidth + gap) / (w + gap)));
  }
  function drawEq(which) {
    const el = document.getElementById('net-eq-' + which), vEl = document.getElementById('net-eq-' + which + '-v');
    if (!el) return;
    const d = last || {};
    const v = d.ready ? (which === 'down' ? d.rx_bps : d.tx_bps) : 0;
    const pk = peak.iface === d.iface ? peak[which] : 0;
    // the text first: its width decides what is left for the squares
    if (vEl) vEl.textContent = d.iface ? `${fmtBits(v)} (max ${fmtBits(pk)})` : '—';
    if (!el.children.length) el.innerHTML = '<i class="g"></i>';
    const n = eqCount(el);
    if (el.children.length !== n) {
      el.innerHTML = Array.from({ length: n }, (_, i) => `<i class="${i < n * 0.625 ? 'g' : i < n * 0.8125 ? 'y' : 'r'}"></i>`).join('');
    }
    const lit = v > 0 ? Math.max(1, Math.round(pos(v) * n)) : 0;
    const pkAt = pk > 0 ? Math.max(1, Math.round(pos(pk) * n)) - 1 : -1;
    Array.from(el.children).forEach((sq, i) => {
      sq.classList.toggle('on', i < lit);
      sq.classList.toggle('pk', i === pkAt && i >= lit);
    });
    el.title = `${d.name || d.iface || 'Gateway'} — ${which === 'down' ? 'download' : 'upload'} ${fmtBits(v)} · highest since login ${fmtBits(pk)}`;
  }
  // a new browser size: refit the squares at once
  if (window.ResizeObserver) {
    const fit = () => { if (mode === 'network-compact') { drawEq('down'); drawEq('up'); } };
    window.addEventListener('DOMContentLoaded', () => {
      const e = document.getElementById('net-eq');
      if (e) new ResizeObserver(fit).observe(e);
    });
  }


  // ── Network Focus (full): the top 10 devices or instances, stacked blocks ──
  // One block per 5 s (the first 5 every 2 s, to fill in quickly), 15 minutes
  // across. Upload above the line, download under it, each line in its own
  // colour, and "Other" (the gateway's traffic those 10 do not explain) in
  // grey, so a column's height is the gateway's traffic. With the Firewall on,
  // the 10 are the gateway's busiest inside devices (FQDN, else IP); without
  // it, the busiest instances. The server chooses them once and keeps them.
  // Hover a column: that moment, the gateway's total and every line.
  const VN = { timer: null, roster: 0, hosts: [], pts: [], last: 0, iface: '', mode: '', on: false, denied: false, hover: -1, tip: null, seq: 0 };
  const VN_COLS = 180, VN_STEP = 5, VN_FAST = 2, VN_FAST_N = 5;
  const VN_PAL = ['#ff9f0a', '#30d158', '#ff453a', '#ffd60a', '#5e5ce6', '#ff6fb5', '#63e6be', '#c69c6d', '#b5e853', '#3a7bd5'];
  const VN_OTHER = '#8e8e93';
  function vnShown() { return VN.on && mode === 'network-full'; }
  // every 2 s until the first blocks are in, then every 5 s
  function vnStart() {
    if (VN.timer || mode !== 'network-full' || VN.denied) return;
    const tick = async () => {
      if (!document.hidden) await vnPoll();
      if (!VN.timer) return;
      VN.timer = setTimeout(tick, (VN.pts.length < VN_FAST_N ? VN_FAST : VN_STEP) * 1000);
    };
    VN.timer = setTimeout(tick, 0);
  }
  function vnStop() { clearTimeout(VN.timer); VN.timer = null; vnHideTip(); }
  function vnReset() { VN.roster = 0; VN.hosts = []; VN.pts = []; VN.last = 0; VN.on = false; VN.denied = false; vnHideTip(); vnShow(); }
  async function vnPoll() {
    const seq = ++VN.seq;
    let d;
    try {
      const r = await fetch('/api/sysinfo/vmnet-live?since=' + (VN.roster ? VN.last : 0));
      if (seq !== VN.seq) return;
      if (r.status === 403) { VN.denied = true; VN.on = false; vnStop(); vnShow(); return; }
      if (!r.ok) return;
      d = await r.json();
    } catch (_) { return; }
    if (seq !== VN.seq) return;
    if (d.roster !== VN.roster) {
      // new choice of instances (the server restarted its sampler): start over
      if (VN.roster && VN.last) { VN.roster = d.roster; VN.pts = []; VN.last = 0; vnPoll(); return; }
      VN.roster = d.roster; VN.pts = [];
    }
    VN.hosts = d.hosts || []; VN.iface = d.iface || ''; VN.mode = d.mode || '';
    const fresh = [];
    for (const p of d.data || []) if (p.ts > VN.last) { VN.pts.push(p); fresh.push(p); VN.last = p.ts; }
    if (VN.pts.length > VN_COLS) VN.pts.splice(0, VN.pts.length - VN_COLS);
    VN.on = !!d.available && VN.hosts.length > 0;
    vnShow();
    if (VN.on) {
      vnDraw(); vnTop(); if (VN.hover >= 0) vnTip();
      // the dials move with the blocks: same interval, same totals
      const gw = (last && last.iface) || VN.iface;
      if (gw === VN.iface) fresh.forEach(p => notePeak(gw, p.total_down || 0, p.total_up || 0));
      if (vnShown()) { drawGauge('down'); drawGauge('up'); }
    }
  }
  // the instance stack, or the gateway line chart when there is no instance
  function vnShow() {
    const on = vnShown();
    const set = (id, v) => { const e = document.getElementById(id); if (e) e.style.display = v; };
    set('vn-chart', on ? '' : 'none'); set('net-chart', on ? 'none' : '');
    set('net-key-vn', on ? '' : 'none'); set('net-key-gw', on ? 'none' : '');
    // the stack needs no title row (the arrows on its scale say which side
    // is which): it takes that height too
    const wrap = document.querySelector('#net-bar .net-chart-wrap');
    if (wrap) wrap.classList.toggle('vn-on', on);
    set('vn-top', on ? '' : 'none');
    const t = document.getElementById('net-chart-title');
    if (t) t.textContent = !on ? 'Gateway traffic' : VN.mode === 'devices' ? 'Top devices' : 'Top instances';
    if (!on && mode === 'network-full') drawChart();
  }
  // column index (0 = oldest, VN_COLS-1 = newest) of the i-th point: blocks
  // sit side by side, the newest at the right edge
  function vnCol(i) { return VN_COLS - VN.pts.length + i; }
  function vnGeom(cv) {
    const W = cv.clientWidth, H = cv.clientHeight;
    let maxU = 1, maxD = 1;
    for (const p of VN.pts) {
      const su = p.up.reduce((a, b) => a + b, 0) + p.other_up, sd = p.down.reduce((a, b) => a + b, 0) + p.other_down;
      maxU = Math.max(maxU, su); maxD = Math.max(maxD, sd);
    }
    // the zero line splits the height by the busier side, each side keeping a fifth
    const share = Math.min(0.8, Math.max(0.2, maxU / (maxU + maxD)));
    const top = 2, bot = H - 2, zero = Math.round(top + (bot - top) * share);
    return { W, H, top, bot, zero, maxU, maxD, cw: W / VN_COLS };
  }
  function vnDraw() {
    const cv = document.getElementById('vn-chart');
    if (!cv || !cv.clientWidth) return;
    const dpr = window.devicePixelRatio || 1;
    const g = vnGeom(cv);
    if (cv.width !== Math.round(g.W * dpr) || cv.height !== Math.round(g.H * dpr)) { cv.width = Math.round(g.W * dpr); cv.height = Math.round(g.H * dpr); }
    const x = cv.getContext('2d');
    x.setTransform(dpr, 0, 0, dpr, 0, 0);
    x.clearRect(0, 0, g.W, g.H);
    const gap = g.cw >= 3 ? 1 : 0, bw = Math.max(1, g.cw - gap);
    const hu = (g.zero - g.top) / g.maxU, hd = (g.bot - g.zero) / g.maxD;
    for (let pi = 0; pi < VN.pts.length; pi++) {
      const p = VN.pts[pi], c = vnCol(pi);
      if (c < 0) continue;
      const x0 = c * g.cw;
      let y = g.zero;
      const segUp = (v, col) => { if (v <= 0) return; const h = v * hu; x.fillStyle = col; x.fillRect(x0, y - h, bw, h); y -= h; };
      p.up.forEach((v, i) => segUp(v, VN_PAL[i % VN_PAL.length]));
      x.globalAlpha = 0.55; segUp(p.other_up, VN_OTHER); x.globalAlpha = 1;
      y = g.zero;
      const segDn = (v, col) => { if (v <= 0) return; const h = v * hd; x.fillStyle = col; x.fillRect(x0, y, bw, h); y += h; };
      x.globalAlpha = 0.72; p.down.forEach((v, i) => segDn(v, VN_PAL[i % VN_PAL.length]));
      x.globalAlpha = 0.4; segDn(p.other_down, VN_OTHER); x.globalAlpha = 1;
    }
    // the zero line, the hovered column, the scale
    x.fillStyle = cssVar('--border', 'rgba(128,128,128,.3)');
    x.fillRect(0, g.zero, g.W, 1);
    if (VN.hover >= 0) {
      x.strokeStyle = cssVar('--text', '#fff'); x.lineWidth = 1;
      x.strokeRect(VN.hover * g.cw + 0.5, g.top - 1.5, Math.max(1, g.cw - 1), g.bot - g.top + 3);
    }
    x.font = '10px system-ui, -apple-system, sans-serif';
    x.fillStyle = cssVar('--text-3', '#8e8e93');
    x.textBaseline = 'top'; x.fillText('↑ ' + fmtBits(g.maxU), 4, g.top + 1);
    x.textBaseline = 'bottom'; x.fillText('↓ ' + fmtBits(g.maxD), 4, g.bot - 1);
    x.textAlign = 'right'; x.fillText('now', g.W - 3, g.bot - 1);
    x.textAlign = 'left';
  }
  // A short name: the FQDN's first label, the IP when there is no name.
  function vnShort(h) {
    const n = String(h.name || h.ip || '');
    return /^[\d.]+$/.test(n) || n.includes(':') ? n : n.split('.')[0];
  }
  // compact bits/s for the legend: 950k, 12.3M, 1.25G
  function vnBits(v) {
    v = Number(v || 0);
    if (v <= 0) return '0';
    const [d, u] = v >= 1e9 ? [1e9, 'G'] : v >= 1e6 ? [1e6, 'M'] : [1e3, 'k'];
    const x = v / d;
    return (x >= 100 ? x.toFixed(0) : x >= 10 ? x.toFixed(1) : x.toFixed(2)) + u;
  }
  // The legend beside the stack: each line's average and highest upload and
  // download over the blocks shown (weighted by block length), busiest first,
  // as many rows as the height allows, in the stack's colours.
  function vnTop() {
    const el = document.getElementById('vn-top');
    if (!el || !vnShown() || el.offsetParent === null) return;
    const n = VN.hosts.length, sumU = new Array(n).fill(0), sumD = new Array(n).fill(0);
    const maxU = new Array(n).fill(0), maxD = new Array(n).fill(0);
    let secs = 0;
    for (const p of VN.pts) {
      const w = p.step_sec || VN_STEP;
      secs += w;
      for (let i = 0; i < n; i++) {
        const u = p.up[i] || 0, d = p.down[i] || 0;
        sumU[i] += u * w; sumD[i] += d * w;
        if (u > maxU[i]) maxU[i] = u;
        if (d > maxD[i]) maxD[i] = d;
      }
    }
    const rows = VN.hosts.map((h, i) => ({ h, i, au: secs ? sumU[i] / secs : 0, ad: secs ? sumD[i] / secs : 0, mu: maxU[i], md: maxD[i] }))
      .sort((a, b) => (b.au + b.ad) - (a.au + a.ad) || a.i - b.i);
    const ROW = 15, fit = Math.max(1, Math.floor((el.clientHeight - ROW - 2) / ROW));
    const pair = (a, m, cls) => `<span class="vt-v ${cls}">${a > 0 ? `<b>${vnBits(a)}</b>` : '<span class="vt-z">0</span>'} / ${m > 0 ? vnBits(m) : '<span class="vt-z">0</span>'}</span>`;
    el.innerHTML = `<div class="vt-r vt-h"><span></span><span title="Busiest over the last 15 minutes">Top ${Math.min(fit, rows.length)}</span><span class="vt-v">\u2191 avg / max</span><span class="vt-v">\u2193 avg / max</span></div>`
      + rows.slice(0, fit).map(r => `<div class="vt-r" title="${esc(r.h.ip && r.h.ip !== r.h.name ? r.h.name + ' · ' + r.h.ip : r.h.name)}${r.h.type === 'server' ? ' (this server)' : ''}">
        <span class="vt-sw" style="background:${VN_PAL[r.i % VN_PAL.length]}"></span><span class="vt-n">${esc(vnShort(r.h))}</span>${pair(r.au, r.mu, 'vt-ul')}${pair(r.ad, r.md, 'vt-dl')}</div>`).join('');
  }
  function vnHideTip() {
    VN.hover = -1;
    if (VN.tip) { VN.tip.remove(); VN.tip = null; }
  }
  function vnTip(ev) {
    const cv = document.getElementById('vn-chart');
    if (!cv) return;
    if (ev) {
      const r = cv.getBoundingClientRect();
      VN.hover = Math.max(0, Math.min(VN_COLS - 1, Math.floor((ev.clientX - r.left) / (r.width / VN_COLS))));
      VN.mx = ev.clientX; VN.my = ev.clientY;
    }
    const p = VN.pts[VN.hover - (VN_COLS - VN.pts.length)];
    if (!p) { if (VN.tip) { VN.tip.remove(); VN.tip = null; } vnDraw(); return; } // not filled in yet
    const ts = p.ts;
    if (!VN.tip) { VN.tip = document.createElement('div'); VN.tip.className = 'vn-tip'; document.body.appendChild(VN.tip); }
    const ago = Math.max(0, VN.last - ts), when = new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const agoTxt = ago < 60 ? ago + ' s ago' : Math.floor(ago / 60) + ' min ' + (ago % 60 ? (ago % 60) + ' s ' : '') + 'ago';
    const rate = v => v > 0 ? fmtBits(v) : '<span class="vn-z">0</span>';
    // a device by its FQDN (its IP when none is known); this server says so
    const label = h => esc(h.name) + (h.type === 'server' ? ' <span class="vn-z">(this server)</span>' : '');
    const hint = h => esc(h.ip && h.ip !== h.name ? h.name + ' · ' + h.ip : h.name);
    let body;
    if (!p) body = '<div class="vn-r"><span></span><span class="vn-z">No sample for this moment</span><span></span><span></span></div>';
    else {
      // busiest at that moment first (download + upload); each keeps its colour
      const tot = i => (p.down[i] || 0) + (p.up[i] || 0);
      const order = VN.hosts.map((_, i) => i).sort((a, b) => tot(b) - tot(a) || a - b);
      body = order.map(i => [VN.hosts[i], i]).map(([h, i]) => `<div class="vn-r"><span class="vn-sw" style="background:${VN_PAL[i % VN_PAL.length]}"></span><span class="vn-n" title="${hint(h)}">${label(h)}</span><span class="vn-dl">↓ ${rate(p.down[i])}</span><span class="vn-ul">↑ ${rate(p.up[i])}</span></div>`).join('')
        + `<div class="vn-r vn-other"><span class="vn-sw" style="background:${VN_OTHER}"></span><span class="vn-n" title="The gateway's traffic not explained by the ${VN.mode === 'devices' ? 'devices' : 'instances'} above">Other</span><span class="vn-dl">↓ ${rate(p.other_down)}</span><span class="vn-ul">↑ ${rate(p.other_up)}</span></div>`;
    }
    const nm = (last && last.iface === VN.iface && last.name) || VN.iface || 'Gateway';
    const per = p && p.step_sec && p.step_sec !== VN_STEP ? ` · ${p.step_sec} s block` : '';
    VN.tip.innerHTML = `<div class="vn-h"><div class="vn-t">${when} · ${agoTxt}${per}</div>
      <div class="vn-tot"><span>${esc(nm)} total</span><span class="vn-dl"><b>↓ ${p ? fmtBits(p.total_down) : '—'}</b></span><span class="vn-ul"><b>↑ ${p ? fmtBits(p.total_up) : '—'}</b></span></div></div>
      <div class="vn-rows">${body}</div>`;
    const w = VN.tip.offsetWidth, h = VN.tip.offsetHeight;
    let lx = VN.mx + 14, ly = VN.my + 14;
    if (lx + w > window.innerWidth - 8) lx = VN.mx - w - 14;
    if (ly + h > window.innerHeight - 8) ly = Math.max(8, window.innerHeight - h - 8);
    VN.tip.style.left = Math.max(8, lx) + 'px'; VN.tip.style.top = ly + 'px';
    vnDraw();
  }
  window.addEventListener('DOMContentLoaded', () => {
    const cv = document.getElementById('vn-chart');
    if (!cv) return;
    cv.addEventListener('pointermove', e => { if (VN.on) vnTip(e); });
    cv.addEventListener('pointerdown', e => { if (VN.on) vnTip(e); });
    cv.addEventListener('pointerleave', e => { if (e.pointerType === 'mouse') { vnHideTip(); vnDraw(); } });
    if (window.ResizeObserver) new ResizeObserver(() => { if (vnShown()) { vnDraw(); vnTop(); } }).observe(cv);
  });
  document.addEventListener('click', e => { if (VN.tip && e.target.id !== 'vn-chart') { vnHideTip(); vnDraw(); } });

  // ── top talkers popup: hover a dial or an equalizer line (mouse), or tap ──
  // The busiest inside devices on the Internet right now. Polled only while
  // open. A device keeps its colour whatever its rank.
  const TK = { pop: null, dir: 'down', anchor: null, pinned: false, timer: null, poll: null, data: null, denied: false, seq: 0 };
  const TK_N = 8;
  const esc = v => (typeof window.esc === 'function' ? window.esc(v) : String(v == null ? '' : v).replace(/[&<>"']/g, c => '&#' + c.charCodeAt(0) + ';'));
  function tkColor(ip) {
    let h = 0;
    for (const ch of String(ip)) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    return `var(--fw-c${(h % TK_N) + 1})`;
  }
  function fmtBytes(n) {
    n = Number(n || 0);
    const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
    return (i ? n.toFixed(n >= 100 ? 0 : 1) : n) + ' ' + u[i];
  }
  const arrow = (dir, size) => `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${dir === 'down' ? '<path d="M12 5v14"/><path d="m5 12 7 7 7-7"/>' : '<path d="M12 19V5"/><path d="m5 12 7-7 7 7"/>'}</svg>`;
  function tkSpark(vals, color) {
    const W = 96, H = 26, n = 30;
    const v = (vals || []).slice(-n);
    if (v.length < 2) return `<svg class="tk-spark" width="${W}" height="${H}" aria-hidden="true"></svg>`;
    const max = Math.max(1, ...v), step = W / (n - 1), x0 = W - (v.length - 1) * step;
    const pts = v.map((y, i) => `${(x0 + i * step).toFixed(1)},${(H - 2 - (H - 4) * y / max).toFixed(1)}`);
    return `<svg class="tk-spark" width="${W}" height="${H}" aria-hidden="true"><polygon points="${x0.toFixed(1)},${H} ${pts.join(' ')} ${W},${H}" style="fill:${color};opacity:.18"/><polyline points="${pts.join(' ')}" fill="none" style="stroke:${color}" stroke-width="1.5" stroke-linejoin="round"/></svg>`;
  }
  function tkRow(h, total) {
    const down = TK.dir === 'down', main = down ? h.down_bps : h.up_bps;
    const col = tkColor(h.ip), share = total ? Math.round(100 * main / total) : 0;
    const title = h.name || h.fqdn || h.ip;
    const v = fmtBits(main, true);
    return `<div class="tk-row">
      <span class="tk-av" style="background:${col}">${esc(String(title).charAt(0).toUpperCase())}</span>
      <div class="tk-main">
        <div class="tk-l1"><b class="tk-name" title="${esc(title)}">${esc(title)}</b><span class="tk-rate"><b>${v.n}</b> ${v.u}</span></div>
        <div class="tk-l2"><span class="tk-ip">${esc(h.ip)}</span>${h.fqdn && h.fqdn !== title ? `<span class="tk-fqdn" title="${esc(h.fqdn)}">${esc(h.fqdn)}</span>` : ''}<span class="tk-sh" title="Share of all devices' ${down ? 'download' : 'upload'} right now">${share}%</span></div>
        <div class="tk-bar"><i style="width:${Math.max(main ? 2 : 0, share)}%;background:${col}"></i></div>
        <div class="tk-l3">
          <span class="tk-st tk-dl" title="Download now">${arrow('down', 11)}${fmtBits(h.down_bps)}</span>
          <span class="tk-st tk-ul" title="Upload now">${arrow('up', 11)}${fmtBits(h.up_bps)}</span>
          <span class="tk-st" title="Highest ${down ? 'download' : 'upload'} since this popup started watching">peak ${fmtBits(down ? h.peak_down_bps : h.peak_up_bps)}</span>
          <span class="tk-st" title="Open Internet connections, and the data they carried so far">${h.conns} conn · ${fmtBytes(h.down_bytes + h.up_bytes)}</span>
        </div>
      </div>
      ${tkSpark(down ? h.spark_down : h.spark_up, col)}
    </div>`;
  }
  function tkRender() {
    if (!TK.pop) return;
    const d = TK.data, down = TK.dir === 'down';
    const total = d ? (down ? d.down_bps : d.up_bps) : 0;
    let body;
    if (TK.denied) body = '<div class="tk-msg">Your account cannot see the Firewall\'s statistics.</div>';
    else if (d && !d.available) body = '<div class="tk-msg"><b>Available with the Firewall.</b><br>The per-device view comes from the traffic this server routes: turn on the Firewall in Router mode to see it.</div>';
    else if (!d || !d.ready) body = '<div class="tk-msg"><span class="tk-pulse"></span>Measuring…</div>';
    else if (!d.talkers.length) body = '<div class="tk-msg">No device is using the Internet right now.</div>';
    else body = d.talkers.map(h => tkRow(h, total)).join('');
    const seg = k => `<button type="button" data-tkdir="${k}" class="${TK.dir === k ? 'on' : ''}">${arrow(k, 12)}${k === 'down' ? 'Top downloaders' : 'Top uploaders'}</button>`;
    const list = TK.pop.querySelector('.tk-list');
    const keep = list ? list.scrollTop : 0;
    TK.pop.innerHTML = `<div class="tk-h" style="--tk-acc:${down ? DL : UL}"><div class="tk-seg">${seg('down')}${seg('up')}</div>
        <div class="tk-total"><span class="tk-pulse"></span>All devices <b>${d && d.ready ? fmtBits(total) : '—'}</b></div></div>
      <div class="tk-list">${body}</div>
      <div class="tk-f">Inside devices using the Internet · live, every 3 s</div>`;
    TK.pop.querySelector('.tk-list').scrollTop = keep;
    TK.pop.querySelectorAll('[data-tkdir]').forEach(b => b.onclick = e => {
      e.stopPropagation();
      if (TK.dir !== b.dataset.tkdir) { TK.dir = b.dataset.tkdir; TK.data = null; tkRender(); tkPoll(); }
    });
  }
  async function tkPoll() {
    const seq = ++TK.seq, dir = TK.dir;
    try {
      const r = await fetch('/api/sdn/top-talkers?dir=' + dir);
      if (seq !== TK.seq || !TK.pop) return;
      TK.denied = r.status === 403;
      if (r.ok) TK.data = await r.json();
      tkRender();
      // the first look only takes the baseline: the rates follow right after
      if (r.ok && TK.data.available && !TK.data.ready) setTimeout(() => { if (TK.pop && seq === TK.seq) tkPoll(); }, 1100);
    } catch (_) {}
  }
  function tkPlace() {
    if (!TK.pop || !TK.anchor) return;
    const r = TK.anchor.getBoundingClientRect(), w = TK.pop.offsetWidth;
    TK.pop.style.left = Math.max(8, Math.min(r.left + r.width / 2 - w / 2, window.innerWidth - w - 8)) + 'px';
    TK.pop.style.top = (r.bottom + 6) + 'px';
    TK.pop.style.maxHeight = Math.max(200, window.innerHeight - r.bottom - 18) + 'px';
  }
  function tkOpen(anchor, dir, pinned) {
    clearTimeout(TK.timer);
    TK.anchor = anchor; TK.pinned = !!pinned;
    if (TK.dir !== dir) { TK.dir = dir; TK.data = null; }
    if (!TK.pop) {
      TK.pop = document.createElement('div');
      TK.pop.className = 'tk-pop'; TK.pop.setAttribute('role', 'dialog'); TK.pop.setAttribute('aria-label', 'Top Internet users');
      TK.pop.onpointerenter = e => { if (e.pointerType === 'mouse') clearTimeout(TK.timer); };
      TK.pop.onpointerleave = e => { if (e.pointerType === 'mouse') tkLeave(); };
      document.body.appendChild(TK.pop);
      TK.poll = setInterval(() => { if (!document.hidden) tkPoll(); }, 3000);
    }
    tkRender(); tkPlace(); tkPoll();
  }
  function tkClose() {
    clearTimeout(TK.timer); clearInterval(TK.poll); TK.seq++;
    if (TK.pop) TK.pop.remove();
    TK.pop = TK.anchor = TK.poll = null; TK.pinned = false; TK.data = null;
  }
  window._tkClose = tkClose;
  function tkLeave() {
    clearTimeout(TK.timer);
    if (!TK.pinned) TK.timer = setTimeout(tkClose, 280);
  }
  function tkTarget(el) {
    if (!el || !el.closest) return null;
    const g = el.closest('.net-gauge');
    if (g) return { el: g, dir: g.id === 'net-gauge-up' ? 'up' : 'down' };
    const row = el.closest('.net-eq-row');
    if (row) return { el: row, dir: row.querySelector('#net-eq-up') ? 'up' : 'down' };
    return null;
  }
  document.addEventListener('pointerover', e => {
    if (e.pointerType !== 'mouse') return;
    const t = tkTarget(e.target);
    if (!t) return;
    clearTimeout(TK.timer);
    if (TK.pinned || (TK.pop && TK.anchor === t.el)) return;
    TK.timer = setTimeout(() => tkOpen(t.el, t.dir, false), TK.pop ? 0 : 200);
  });
  document.addEventListener('pointerout', e => {
    if (e.pointerType !== 'mouse') return;
    const t = tkTarget(e.target);
    if (!t || (e.relatedTarget && t.el.contains(e.relatedTarget))) return;
    if (TK.pop) tkLeave(); else clearTimeout(TK.timer);
  });
  // click / tap: pins it (iPad has no hover); again or elsewhere closes it
  document.addEventListener('click', e => {
    const t = tkTarget(e.target);
    if (t) {
      if (TK.pop && TK.anchor === t.el && TK.pinned) tkClose();
      else tkOpen(t.el, t.dir, true);
      return;
    }
    if (TK.pop && !TK.pop.contains(e.target)) tkClose();
  });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && TK.pop) tkClose(); });
  window.addEventListener('resize', tkPlace);

  // ── gateway latency between the dials ──
  // "1.4/3.6ms": the latest ping of the gateway carrying the traffic (when
  // the Firewall monitors it) / the average of the pings this page has seen
  // since it was opened. A click shows the last 15 minutes.
  const RTT = { sum: 0, n: 0, ts: 0, gw: '', pop: null, pts: null, seq: 0 };
  const fmtMs = v => (v >= 100 ? Math.round(v) : v.toFixed(1));
  function rttNote(L) {
    if (!L) return;
    if (RTT.gw !== L.gateway_id) { RTT.sum = 0; RTT.n = 0; RTT.ts = 0; RTT.gw = L.gateway_id; }
    if (L.ts && L.ts !== RTT.ts) {
      RTT.ts = L.ts;
      if (L.ok) { RTT.sum += L.rtt_ms; RTT.n++; }
    }
  }
  function rttDraw() {
    const el = document.getElementById('net-rtt');
    if (!el) return;
    const L = last && last.latency;
    if (mode !== 'network-full' || !L) { el.style.display = 'none'; if (RTT.pop) rttClose(); return; }
    const avg = RTT.n ? fmtMs(RTT.sum / RTT.n) : '—';
    el.innerHTML = L.ok ? `${fmtMs(L.rtt_ms)}<span class="net-rtt-s">/</span>${avg}<span class="net-rtt-u">ms</span>`
      : `<span class="net-rtt-bad">—</span><span class="net-rtt-s">/</span>${avg}<span class="net-rtt-u">ms</span>`;
    el.title = `Latency of ${L.name}: now / average since you opened this page. Click for the last 15 minutes.`;
    el.style.display = '';
    if (RTT.pop) rttRender();
  }
  async function rttFetch() {
    const L = last && last.latency;
    if (!L) return;
    const seq = ++RTT.seq;
    try {
      const r = await fetch('/api/sdn/gateway-rtt?id=' + encodeURIComponent(L.gateway_id));
      if (!r.ok || seq !== RTT.seq) return;
      RTT.pts = ((await r.json()) || {}).points || [];
      if (RTT.pop) rttRender();
    } catch (_) {}
  }
  function rttGraph(pts) {
    const W = 360, H = 110, PL = 34, PB = 16, PT = 6, now = Math.floor(Date.now() / 1000), from = now - 900;
    const vals = pts.filter(p => p.ms != null).map(p => p.ms);
    if (!vals.length) return `<div class="net-rtt-empty">${pts.length ? 'No ping answered in the last 15 minutes.' : 'No ping recorded yet.'}</div>`;
    const max = Math.max(1, ...vals) * 1.15;
    const X = ts => PL + (Math.max(from, ts) - from) / 900 * (W - PL - 4), Y = v => PT + (1 - v / max) * (H - PT - PB);
    let d = '', pen = false, lost = '';
    pts.forEach(p => {
      if (p.ts < from) return;
      if (p.ms == null) { pen = false; lost += `<line x1="${X(p.ts).toFixed(1)}" x2="${X(p.ts).toFixed(1)}" y1="${PT}" y2="${H - PB}" class="net-rtt-lost"/>`; return; }
      d += (pen ? 'L' : 'M') + X(p.ts).toFixed(1) + ' ' + Y(p.ms).toFixed(1);
      pen = true;
    });
    const grid = [0, 0.5, 1].map(f => { const v = max / 1.15 * f, y = Y(v); return `<line x1="${PL}" x2="${W - 4}" y1="${y.toFixed(1)}" y2="${y.toFixed(1)}" class="net-rtt-grid"/><text x="${PL - 4}" y="${(y + 3).toFixed(1)}" class="net-rtt-ax" text-anchor="end">${fmtMs(v)}</text>`; }).join('');
    const xl = [15, 10, 5, 0].map(m => `<text x="${X(now - m * 60).toFixed(1)}" y="${H - 3}" class="net-rtt-ax" text-anchor="${m === 15 ? 'start' : m ? 'middle' : 'end'}">${m ? '-' + m + ' min' : 'now'}</text>`).join('');
    return `<svg viewBox="0 0 ${W} ${H}" class="net-rtt-svg" role="img" aria-label="Gateway latency, last 15 minutes">${grid}${lost}<path d="${d}" class="net-rtt-line"/>${xl}</svg>`;
  }
  function rttRender() {
    const L = last && last.latency;
    if (!RTT.pop || !L) return;
    const avg = RTT.n ? fmtMs(RTT.sum / RTT.n) + ' ms' : 'not known yet';
    const cur = L.ok ? fmtMs(L.rtt_ms) + ' ms' : 'no answer';
    const tgt = esc(L.target || 'the gateway') + (L.target_is_peer ? ' (the ISP’s side of the PPPoE link)' : '');
    RTT.pop.innerHTML = `<div class="vn-h"><div class="vn-t">Gateway latency · last 15 minutes</div>
        <div class="vn-tot"><span>${esc(L.name)}</span><span><b>${esc(cur)}</b> now</span><span><b>${esc(avg)}</b> avg</span></div></div>
      <div class="net-rtt-body">${RTT.pts ? rttGraph(RTT.pts) : '<div class="net-rtt-empty">Loading…</div>'}
        <p><b>${esc(cur)}</b> is the current latency: the time the latest ping to ${tgt} took to come back.
        <b>${esc(avg)}</b> is the average of the pings seen since you opened this page.</p>
        <p class="vn-z">Loss over the last checks: ${L.loss || 0} %. Red lines are pings that got no answer.</p></div>`;
  }
  function rttPlace() {
    const el = document.getElementById('net-rtt');
    if (!RTT.pop || !el) return;
    const r = el.getBoundingClientRect(), w = RTT.pop.offsetWidth;
    RTT.pop.style.left = Math.max(8, Math.min(r.left + r.width / 2 - w / 2, window.innerWidth - w - 8)) + 'px';
    RTT.pop.style.top = (r.bottom + 6) + 'px';
  }
  function rttOpen() {
    if (RTT.pop) return;
    if (typeof window._tkClose === 'function') window._tkClose();
    RTT.pop = document.createElement('div');
    RTT.pop.className = 'vn-tip net-rtt-pop'; RTT.pop.setAttribute('role', 'dialog'); RTT.pop.setAttribute('aria-label', 'Gateway latency');
    document.body.appendChild(RTT.pop);
    RTT.pts = null;
    rttRender(); rttPlace(); rttFetch();
    RTT.timer = setInterval(() => { if (!document.hidden) rttFetch(); }, 3000);
  }
  function rttClose() {
    clearInterval(RTT.timer); RTT.seq++;
    if (RTT.pop) RTT.pop.remove();
    RTT.pop = null; RTT.pts = null;
  }
  document.addEventListener('click', e => {
    const b = e.target && e.target.closest && e.target.closest('#net-rtt');
    if (b) { if (RTT.pop) rttClose(); else rttOpen(); return; }
    if (RTT.pop && !RTT.pop.contains(e.target)) rttClose();
  });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && RTT.pop) rttClose(); });
  window.addEventListener('resize', rttPlace);

  // Apply before first paint (the script sits at the end of <body>).
  applyMode(savedMode());
})();
