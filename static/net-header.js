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
    if (window._tkClose) window._tkClose();
  }
  window.setHeaderMode = function (m) {
    applyMode(m);
    try { localStorage.setItem(LS_MODE, mode); } catch (_) {}
    if (typeof window.closeUserMenu === 'function') window.closeUserMenu();
  };
  window.getHeaderMode = () => mode;

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
  }
  function stop() {
    clearInterval(timer); timer = null;
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
    if (d.ready) {
      shift(buf.down, d.rx_bps); shift(buf.up, d.tx_bps);
      if (peak.iface !== d.iface) peak = { iface: d.iface, down: 0, up: 0 };
      peak.down = Math.max(peak.down, d.rx_bps); peak.up = Math.max(peak.up, d.tx_bps);
      savePeak();
    }
    draw();
  }
  function shift(a, v) { a.shift(); a.push(v); }
  function reset() {
    buf.down.fill(null); buf.up.fill(null);
    last = null;
    if (chart) { chart.data.datasets.forEach(ds => { ds.data = []; }); chart.update('none'); }
  }
  // An InterLink switch shows another server: its gateway, its traffic.
  window._resetNetHeader = function () {
    reset();
    peak = { iface: '', down: 0, up: 0 };
    savePeak();
    if (timer) poll();
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
    if (mode === 'network-full') { drawChart(); drawGauge('down'); drawGauge('up'); }
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
    const v = d.ready ? (which === 'down' ? d.rx_bps : d.tx_bps) : 0;
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

  // Apply before first paint (the script sits at the end of <body>).
  applyMode(savedMode());
})();
