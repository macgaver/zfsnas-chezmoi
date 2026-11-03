// ZNAS Firewall — DNS reports (Monitor → DNS queries): what the Local DNS
// server answered, from its query log (Local DNS → "Collect advanced
// metrics"). Dashboard (totals, queries and clients over time, query types,
// who answered, top domains and clients) and the query log, with allow/block.
(function () {
  'use strict';

  let F = null;
  const R = {
    tab: 'dash', range: '24h',
    data: null,                       // GET /api/sdn/dns/report
    log: [], names: {}, more: false,  // GET /api/sdn/dns/queries
    q: { domain: '', client: '', status: '' },
  };
  // categorical slots (validated: dark #1c1c1e and light #ffffff surfaces)
  const CAT = ['--fw-c1', '--fw-c2', '--fw-c3', '--fw-c4', '--fw-c5', '--fw-c6', '--fw-c7', '--fw-c8'];
  const cat = i => `var(${CAT[i % CAT.length]})`;

  const fmtN = n => Number(n || 0).toLocaleString();
  const pct = (a, b) => b ? (100 * a / b).toFixed(a && a / b < 0.1 ? 1 : 0) + '%' : '0%';
  const name = ip => (R.names[ip] ? `${F.E(R.names[ip])} <span class="fw-dns-ip">${F.E(ip)}</span>` : `<span class="fw-mono">${F.E(ip)}</span>`);
  const nameText = ip => R.names[ip] ? `${R.names[ip]} (${ip})` : ip;

  async function load() {
    if (R.tab === 'dash') {
      const r = await F.api('GET', '/api/sdn/dns/report?range=' + R.range);
      if (r.ok) { R.data = r.data; R.names = Object.assign({}, R.names, r.data.names || {}); }
      return;
    }
    await loadLog(false);
  }
  async function loadLog(older) {
    const p = new URLSearchParams({ limit: '200' });
    for (const k of ['domain', 'client', 'status']) if (R.q[k]) p.set(k, R.q[k]);
    if (older && R.log.length) p.set('before', String(R.log[R.log.length - 1].t));
    const r = await F.api('GET', '/api/sdn/dns/queries?' + p);
    if (!r.ok) return;
    const list = r.data.queries || [];
    R.log = older ? R.log.concat(list) : list;
    R.more = list.length === 200;
    R.names = Object.assign({}, R.names, r.data.names || {});
    if (!R.data) { const s = await F.api('GET', '/api/sdn/dns/report?range=24h'); if (s.ok) R.data = s.data; }
  }
  // no redraw while a filter is being typed in, or older entries are shown
  async function poll() {
    if (document.activeElement && document.activeElement.closest && document.activeElement.closest('#page-fw-dns input')) return false;
    if (R.tab === 'log' && R.log.length > 200) return false;
    await load();
  }

  // ── time labels ──
  function tLabel(t, step, long) {
    const d = new Date(t * 1000);
    if (step >= 86400) return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    const hm = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    return step >= 3600 || long ? d.toLocaleDateString(undefined, { weekday: 'short', day: 'numeric' }) + ' ' + hm : hm;
  }
  function tRange(t, step) {
    const a = tLabel(t, step, true), b = new Date((t + step) * 1000);
    if (step >= 86400) return a;
    return a + ' – ' + b.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }

  // ── stacked bars over time (one column per point, hover per column) ──
  function bars(id, points, series, step) {
    const n = points.length;
    if (!n) return '<div class="fw-empty">No data yet.</div>';
    const tot = points.map(p => series.reduce((a, s) => a + (s.v(p) || 0), 0));
    const max = Math.max(1, ...tot);
    const W = 1000, H = 160, cw = W / n, gap = Math.min(2, cw * 0.25);
    let rects = '';
    points.forEach((p, i) => {
      let y = H;
      series.forEach((s, k) => {
        const v = s.v(p) || 0;
        if (!v) return;
        const h = Math.max(1, H * v / max);
        // 1px surface gap between stacked segments
        rects += `<rect x="${(i * cw + gap / 2).toFixed(2)}" y="${(y - h).toFixed(2)}" width="${(cw - gap).toFixed(2)}" height="${Math.max(0.5, h - (k ? 1 : 0)).toFixed(2)}" fill="${s.color}"/>`;
        y -= h;
      });
    });
    const ticks = 6, every = Math.max(1, Math.round(n / ticks));
    let axis = '';
    // the first label starts at the edge instead of being cut by it
    for (let i = 0; i < n; i += every) axis += `<span style="left:${i ? (100 * (i + 0.5) / n).toFixed(2) + '%' : '0;transform:none'}">${F.E(tLabel(points[i].t, step))}</span>`;
    return `<div class="fw-dns-chart" data-chart="${id}">
      <div class="fw-dns-ymax">${fmtN(max)}</div>
      <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="${F.E(series.map(s => s.label).join(', '))} over time">
        <line x1="0" y1="${H - 0.5}" x2="${W}" y2="${H - 0.5}" class="fw-dns-base"/>
        <line x1="0" y1="0.5" x2="${W}" y2="0.5" class="fw-dns-grid"/><line x1="0" y1="${H / 2}" x2="${W}" y2="${H / 2}" class="fw-dns-grid"/>
        ${rects}<rect class="fw-dns-hover" x="0" y="0" width="0" height="${H}"/></svg>
      <div class="fw-dns-axis">${axis}</div></div>`;
  }
  const charts = {};
  function wireChart(root, id, points, series, step) {
    const el = root.querySelector(`[data-chart="${id}"]`);
    if (!el) return;
    charts[id] = { points, series, step };
    const svg = el.querySelector('svg'), hv = el.querySelector('.fw-dns-hover');
    const tip = tipEl();
    const at = e => { const r = svg.getBoundingClientRect(); return Math.min(points.length - 1, Math.max(0, Math.floor((e.clientX - r.left) / r.width * points.length))); };
    svg.addEventListener('mousemove', e => {
      const i = at(e), p = points[i], cw = 1000 / points.length;
      hv.setAttribute('x', (i * cw).toFixed(2)); hv.setAttribute('width', cw.toFixed(2));
      const rows = series.map(s => [s, s.v(p) || 0]).filter(([, v]) => v || series.length <= 3);
      tip.innerHTML = `<div class="fw-tip-h">${F.E(tRange(p.t, step))}</div>` + rows.map(([s, v]) =>
        `<div class="fw-r"><span><span class="fw-sw" style="background:${s.color}"></span>${F.E(s.label)}</span><b>${fmtN(v)}</b></div>`).join('')
        + (series.length > 1 ? `<div class="fw-r fw-dns-tipsum"><span>Total</span><b>${fmtN(series.reduce((a, s) => a + (s.v(p) || 0), 0))}</b></div>` : '');
      tip.style.display = 'block';
      const w = tip.offsetWidth, h = tip.offsetHeight;
      let x = e.clientX + 14, y = e.clientY + 14;
      if (x + w > window.innerWidth - 8) x = e.clientX - w - 14;
      if (y + h > window.innerHeight - 8) y = e.clientY - h - 14;
      tip.style.left = x + 'px'; tip.style.top = y + 'px';
    });
    svg.addEventListener('mouseleave', () => { tip.style.display = 'none'; hv.setAttribute('width', 0); });
  }
  function tipEl() {
    let t = document.getElementById('fw-dns-tip');
    if (!t) { t = document.createElement('div'); t.id = 'fw-dns-tip'; t.className = 'fw-dns-tip'; document.body.appendChild(t); }
    return t;
  }

  // ── donut + legend (the legend carries every value: no colour alone) ──
  function donut(title, entries, info) {
    const total = entries.reduce((a, [, v]) => a + v, 0);
    let top = entries.slice().sort((a, b) => b[1] - a[1]);
    if (top.length > 8) { const rest = top.slice(7).reduce((a, [, v]) => a + v, 0); top = top.slice(0, 7).concat([['Other', rest]]); }
    const r = 42, C = 2 * Math.PI * r;
    let off = 0, arcs = '';
    top.forEach(([, v], i) => {
      const len = C * v / Math.max(1, total);
      const g = top.length > 1 ? Math.min(2, len / 2) : 0; // 2px surface gap between slices
      arcs += `<circle r="${r}" cx="60" cy="60" fill="none" stroke="${cat(i)}" stroke-width="16" stroke-dasharray="${Math.max(0, len - g).toFixed(2)} ${(C - Math.max(0, len - g)).toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}"/>`;
      off += len;
    });
    return `<div class="fw-card fw-dns-donut"><div class="fw-card-h"><span class="fw-name">${F.E(title)}</span>${info || ''}</div>
      ${total ? `<div class="fw-dns-donut-b"><svg viewBox="0 0 120 120" width="120" height="120" role="img" aria-label="${F.E(title)}"><g transform="rotate(-90 60 60)">${arcs}</g>
        <text x="60" y="58" text-anchor="middle" class="fw-dns-dt">${fmtN(total)}</text><text x="60" y="74" text-anchor="middle" class="fw-dns-ds">queries</text></svg>
        <div class="fw-dns-legend">${top.map(([k, v], i) => `<div class="fw-dns-lg"><span class="fw-sw" style="background:${cat(i)}"></span><span class="fw-dns-lk">${k}</span><b>${fmtN(v)}</b><span class="fw-dns-lp">${pct(v, total)}</span></div>`).join('')}</div></div>`
        : '<div class="fw-empty">No queries in this range.</div>'}</div>`;
  }

  // ── top lists ──
  function topCard(title, rows, color, kind, info) {
    const max = Math.max(1, ...rows.map(r => r.n));
    return `<div class="fw-card fw-dns-top"><div class="fw-card-h"><span class="fw-name">${F.E(title)}</span>${info || ''}</div>
      ${rows.length ? `<table class="fw-table fw-dns-tt"><tbody>${rows.map(r => `<tr data-go="${kind}" data-k="${F.E(r.key)}" title="Show these queries">
        <td class="fw-dns-tk">${kind.startsWith('client') ? name(r.key) : F.E(r.key)}</td>
        <td class="fw-dns-tn">${fmtN(r.n)}</td>
        <td class="fw-dns-tb"><div style="width:${Math.max(2, 100 * r.n / max).toFixed(1)}%;background:${color}"></div></td></tr>`).join('')}</tbody></table>`
        : '<div class="fw-empty">Nothing yet.</div>'}</div>`;
  }

  const UPSTREAM = { cache: 'Cache (answered here)', blocklist: 'Blocklist', local: 'Local names' };
  const TIP = {
    total: ['Total queries', '<p>Every name lookup the Local DNS server received from the devices of your networks, in the chosen range.</p>'],
    blocked: ['Queries blocked', '<p>Lookups of a domain on one of your <b>blocklists</b> or in your <b>blocked domains</b>. The device got <code>0.0.0.0</code> (or <code>::</code>) and could not reach it.</p>'],
    percent: ['Percent blocked', '<p>The share of all queries that were blocked. Ad-heavy apps and smart TVs often push it to 10–30%.</p>'],
    lists: ['Domains on blocklists', '<p>How many domains are blocked right now: all your blocklists and blocked domains together, minus your allowed domains. The lists are fetched every day.</p>'],
    over: ['Queries over time', '<p>Lookups per period, split into allowed and blocked. Hover a column for the exact numbers.</p><p>24 h: 10-minute columns · 7 and 30 days: hourly · 1 year: daily.</p>'],
    clients: ['Client activity', '<p>Lookups per period for the busiest devices of the range. A device suddenly very active can be an update, a backup — or something misbehaving.</p>'],
    types: ['Query types', '<ul><li><b>A</b> / <b>AAAA</b>: IPv4 / IPv6 address of a name</li><li><b>HTTPS</b> / <b>SVCB</b>: connection hints (browsers)</li><li><b>PTR</b>: the name of an address (reverse)</li><li><b>MX</b>, <b>TXT</b>, <b>SRV</b>: mail, text and service records</li></ul>'],
    answered: ['Answered by', '<p>Where the answers came from: the <b>upstream servers</b> (forwarded), the <b>cache</b> (asked recently, answered at once), <b>local names</b> (this router\'s host names and the devices of your DHCP networks) or the <b>blocklist</b>.</p>'],
    topd: ['Top allowed domains', '<p>The domains looked up most often and answered. Click one to see who asked.</p>'],
    topb: ['Top blocked domains', '<p>The blocked domains devices try most. If one breaks something you need, allow it from the query log or in Local DNS → Allowed domains.</p>'],
    topc: ['Top clients', '<p>The devices that send the most lookups. Names come from DHCP leases and VMs & Containers.</p>'],
    topcb: ['Top blocked clients', '<p>The devices that hit the blocklists most — usually the ones with the most ads and trackers.</p>'],
    log: ['Query log', '<p>The newest lookups (up to 100,000), newest first. <b>Status</b>: <b>Forwarded</b> (asked upstream), <b>Cached</b>, <b>Local</b> (a name this router knows), <b>Blocked</b>.</p><p><b>Allow</b> / <b>Block</b> add the domain to Local DNS\' allowed or blocked domains — in the draft: <b>Apply</b> to take effect.</p>'],
  };
  const tip = k => F.info(TIP[k][0], TIP[k][1]);

  function dashHTML() {
    const d = R.data, s = d && d.report;
    if (!s) return '<div class="fw-empty">Loading…</div>';
    const pts = s.series || [];
    const clients = (s.client_series && s.client_series.clients) || [];
    const cpts = pts.map((p, i) => Object.assign({ t: p.t }, ...clients.map((c, j) => ({ ['c' + j]: ((s.client_series.points || [])[i] || [])[j] || 0 }))));
    const bl = d.blocklist || {};
    const ups = Object.entries(s.upstreams || {}).map(([k, v]) => [F.E(UPSTREAM[k] || k), v]);
    const types = Object.entries(s.types || {}).map(([k, v]) => [F.E(k), v]);
    return `
      <div class="fw-kpis fw-dns-kpis">
        <div class="fw-kpi"><div class="fw-kpi-bar" style="background:var(--fw-in)"></div><div class="fw-kpi-l">Total queries ${tip('total')}</div><div class="fw-kpi-v">${fmtN(s.total)}</div><div class="fw-kpi-d">${fmtN(s.clients)} client${s.clients === 1 ? '' : 's'}</div></div>
        <div class="fw-kpi"><div class="fw-kpi-bar" style="background:var(--fw-blk)"></div><div class="fw-kpi-l">Queries blocked ${tip('blocked')}</div><div class="fw-kpi-v">${fmtN(s.blocked)}</div><div class="fw-kpi-d">${fmtN(s.cached)} from the cache · ${fmtN(s.forwarded)} forwarded</div></div>
        <div class="fw-kpi"><div class="fw-kpi-bar" style="background:var(--fw-blk)"></div><div class="fw-kpi-l">Percent blocked ${tip('percent')}</div><div class="fw-kpi-v">${pct(s.blocked, s.total)}</div><div class="fw-kpi-d">${fmtN(s.local)} answered locally</div></div>
        <div class="fw-kpi"><div class="fw-kpi-bar" style="background:var(--accent-3)"></div><div class="fw-kpi-l">Domains on blocklists ${tip('lists')}</div><div class="fw-kpi-v">${bl.blocking ? fmtN(bl.domains) : '—'}</div><div class="fw-kpi-d">${bl.blocking ? (bl.built && !String(bl.built).startsWith('0001') ? 'updated ' + F.E(new Date(bl.built).toLocaleString()) : 'first download pending') : 'no blocklist'}</div></div>
      </div>
      <div class="fw-card fw-dns-wide"><div class="fw-card-h"><span class="fw-name">Queries over time</span>${tip('over')}
        <span class="fw-dns-key"><span class="fw-sw" style="background:var(--fw-in)"></span>Allowed <span class="fw-sw" style="background:var(--fw-blk)"></span>Blocked</span></div>
        ${bars('q', pts, [{ label: 'Allowed', color: 'var(--fw-in)', v: p => p.allowed }, { label: 'Blocked', color: 'var(--fw-blk)', v: p => p.blocked }], s.step)}</div>
      <div class="fw-card fw-dns-wide"><div class="fw-card-h"><span class="fw-name">Client activity over time</span>${tip('clients')}
        <span class="fw-dns-key">${clients.map((c, j) => `<span class="fw-sw" style="background:${cat(j)}"></span>${F.E(R.names[c] || c)}`).join(' ')}</span></div>
        ${bars('c', cpts, clients.map((c, j) => ({ label: nameText(c), color: cat(j), v: p => p['c' + j] })), s.step)}</div>
      <div class="fw-dns-2">${donut('Query types', types, tip('types'))}${donut('Answered by', ups, tip('answered'))}</div>
      <div class="fw-dns-2">
        ${topCard('Top allowed domains', s.top_domains || [], 'var(--fw-in)', 'domain', tip('topd'))}
        ${topCard('Top blocked domains', s.top_blocked || [], 'var(--fw-blk)', 'domain-blocked', tip('topb'))}
        ${topCard('Top clients', s.top_clients || [], 'var(--fw-in)', 'client', tip('topc'))}
        ${topCard('Top blocked clients', s.top_clients_blocked || [], 'var(--fw-blk)', 'client-blocked', tip('topcb'))}
      </div>`;
  }

  const STATUS = { forwarded: ['Forwarded', 'ok'], cached: ['Cached', 'ok'], local: ['Local', 'ok'], blocked: ['Blocked', 'blk'], '': ['No answer', 'none'] };
  function logHTML() {
    const c = F.cfg(), admin = F.isAdmin();
    const allow = new Set((c.dns && c.dns.allow) || []), deny = new Set((c.dns && c.dns.deny) || []);
    const rows = R.log.map(q => {
      const [lbl, cls] = STATUS[q.status] || [q.status, 'ok'];
      const ans = q.status === 'forwarded' && q.upstream ? `${F.E(q.reply || '')} <span class="fw-dns-ip">via ${F.E(q.upstream)}</span>` : F.E(q.reply || '');
      let act = '';
      if (admin) {
        if (q.status === 'blocked') act = allow.has(q.domain) ? '<span class="fw-badge none">allowed (draft)</span>' : `<button class="fw-icon-btn" data-allow="${F.E(q.domain)}">${F.icon('check', 12)}Allow</button>`;
        else if (q.type !== 'PTR') act = deny.has(q.domain) ? '<span class="fw-badge none">blocked (draft)</span>' : `<button class="fw-icon-btn danger" data-block="${F.E(q.domain)}">${F.icon('x', 12)}Block</button>`;
      }
      return `<tr><td class="fw-dns-time" data-v="${q.t}">${F.E(new Date(q.t * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }))}</td>
        <td>${F.E(q.type)}</td><td class="fw-dns-dom">${F.E(q.domain)}</td><td>${name(q.client)}</td>
        <td><span class="fw-dns-st ${cls}">${F.E(lbl)}</span></td><td class="fw-dns-ans">${ans}</td><td>${act}</td></tr>`;
    }).join('');
    return `<div class="fw-card fw-dns-filters">
        <div class="fw-field"><label>Domain contains</label><input type="text" id="fwq-dom" value="${F.E(R.q.domain)}" placeholder="e.g. google"></div>
        <div class="fw-field"><label>Client</label><div id="fwq-cl"></div></div>
        <div class="fw-field"><label>Status</label><div id="fwq-st"></div></div>
        ${tip('log')}</div>
      <div class="fw-tcard"><div class="fw-tscroll"><table class="fw-table fw-dns-log"><thead><tr><th>Time</th><th>Type</th><th>Domain</th><th>Client</th><th>Status</th><th>Answer</th><th></th></tr></thead>
        <tbody>${rows || '<tr><td colspan="7" style="color:var(--text-3)">No query matches.</td></tr>'}</tbody></table></div>
        ${R.more ? '<div style="text-align:center;padding:10px"><button class="fw-icon-btn" id="fwq-more">Show older queries</button></div>' : ''}</div>`;
  }

  function html() {
    const d = R.data;
    const c = F.cfg && F.cfg();
    const dnsOn = c && c.dns && c.dns.enabled;
    const banner = d && !d.metrics
      ? `<div class="fw-safemode" style="background:rgba(255,214,10,.10);border-color:rgba(255,214,10,.4)">${F.icon('info', 16)}<div><b>Advanced metrics are off.</b> ${dnsOn ? 'Turn on <b>Collect advanced metrics</b> in Local DNS to fill these reports' : 'Turn on Local DNS, then <b>Collect advanced metrics</b>'}${d.report && d.report.total ? ' — what was collected before is still shown.' : '.'}</div><span style="flex:1"></span>${F.isAdmin() ? '<button class="fw-btn" id="fwq-go-dns">Open Local DNS</button>' : ''}</div>`
      : '';
    return `${banner}
      <div class="fw-dns-bar"><div id="fwq-tab"></div>${R.tab === 'dash' ? '<div id="fwq-range"></div>' : ''}<span style="flex:1"></span>
        <span class="fw-sub">${d && d.collecting ? '<span style="color:var(--accent-3)">●</span> collecting · refreshed every 10 s' : ''}</span></div>
      ${R.tab === 'dash' ? dashHTML() : logHTML()}`;
  }

  function goLog(filter) {
    R.tab = 'log';
    R.q = Object.assign({ domain: '', client: '', status: '' }, filter);
    R.log = [];
    loadLog(false).then(F.rerender);
  }

  function wire(root) {
    F.seg(root.querySelector('#fwq-tab'), [['dash', 'Dashboard'], ['log', 'Query log']], R.tab, v => {
      R.tab = v;
      load().then(F.rerender);
    });
    const rg = root.querySelector('#fwq-range');
    if (rg) F.seg(rg, [['24h', '24 hours'], ['7d', '7 days'], ['30d', '30 days'], ['1y', '1 year']], R.range, v => { R.range = v; load().then(F.rerender); });
    const go = root.querySelector('#fwq-go-dns');
    if (go) go.onclick = () => window.showPage('fw-dhcp');
    if (R.tab === 'dash' && R.data && R.data.report) {
      const s = R.data.report, pts = s.series || [], clients = (s.client_series && s.client_series.clients) || [];
      wireChart(root, 'q', pts, [{ label: 'Allowed', color: 'var(--fw-in)', v: p => p.allowed }, { label: 'Blocked', color: 'var(--fw-blk)', v: p => p.blocked }], s.step);
      const cpts = pts.map((p, i) => Object.assign({ t: p.t }, ...clients.map((c, j) => ({ ['c' + j]: ((s.client_series.points || [])[i] || [])[j] || 0 }))));
      wireChart(root, 'c', cpts, clients.map((c, j) => ({ label: nameText(c), color: cat(j), v: p => p['c' + j] })), s.step);
      root.querySelectorAll('[data-go]').forEach(tr => tr.onclick = () => {
        const k = tr.dataset.k, g = tr.dataset.go;
        goLog(g === 'domain' ? { domain: k, status: 'allowed' } : g === 'domain-blocked' ? { domain: k, status: 'blocked' }
          : g === 'client' ? { client: k } : { client: k, status: 'blocked' });
      });
    }
    if (R.tab === 'log') {
      const dom = root.querySelector('#fwq-dom');
      let t = 0;
      dom.oninput = () => { clearTimeout(t); t = setTimeout(() => { R.q.domain = dom.value.trim(); loadLog(false).then(() => { F.rerender(); const d2 = document.getElementById('fwq-dom'); if (d2) { d2.focus(); d2.setSelectionRange(d2.value.length, d2.value.length); } }); }, 400); };
      const seen = new Set(), opts = [{ value: '', label: 'All clients' }];
      const clientIPs = ((R.data && R.data.report && R.data.report.top_clients) || []).map(x => x.key).concat(R.log.map(q => q.client));
      if (R.q.client) clientIPs.unshift(R.q.client);
      clientIPs.forEach(ip => { if (!seen.has(ip)) { seen.add(ip); opts.push({ value: ip, label: R.names[ip] || ip, hint: R.names[ip] ? ip : '' }); } });
      F.picker(root.querySelector('#fwq-cl'), opts, R.q.client, v => { R.q.client = v; loadLog(false).then(F.rerender); });
      F.seg(root.querySelector('#fwq-st'), [['', 'All'], ['allowed', 'Allowed'], ['blocked', 'Blocked'], ['cached', 'Cached'], ['local', 'Local']], R.q.status,
        v => { R.q.status = v; loadLog(false).then(F.rerender); });
      const more = root.querySelector('#fwq-more');
      if (more) more.onclick = () => loadLog(true).then(F.rerender);
      root.querySelectorAll('[data-allow]').forEach(b => b.onclick = () => F.saveDraft(n => {
        const d = b.dataset.allow;
        n.dns.allow = Array.from(new Set((n.dns.allow || []).concat([d])));
        n.dns.deny = (n.dns.deny || []).filter(x => x !== d);
      }).then(ok => { if (ok) F.toast(`${b.dataset.allow} will be allowed — Apply to take effect`, 'success'); }));
      root.querySelectorAll('[data-block]').forEach(b => b.onclick = () => F.saveDraft(n => {
        const d = b.dataset.block;
        n.dns.deny = Array.from(new Set((n.dns.deny || []).concat([d])));
        n.dns.allow = (n.dns.allow || []).filter(x => x !== d);
      }).then(ok => { if (ok) F.toast(`${b.dataset.block} will be blocked — Apply to take effect`, 'success'); }));
    }
  }

  function register() {
    if (typeof window.sdnRegisterPage !== 'function' || !window.sdnFW || !window.sdnFW.info) { setTimeout(register, 200); return; }
    F = window.sdnFW;
    window.sdnRegisterPage('fw-dns', { load, render: html, wire, pollMs: 10000, poll });
  }
  register();
})();
