/*
 * Firewall → Intrusion detection and IDS alerts (SDN phase 5). Spec: PLANS/spec-sdn-firewall.md §11.4.
 *
 * Suricata watches the chosen interfaces (default: the WANs) in alert-only
 * mode with free rule sets. Settings are part of the firewall draft (Apply as
 * usual); rule downloads run on the server (first enable, then daily).
 * Alerts: GET /api/sdn/ids/alerts — "Block source" adds a block rule to the
 * draft, "Suppress" silences the signature (draft too).
 */
(function () {
  'use strict';

  let F = null;
  let st = null;            // GET /api/sdn/ids/status
  let alerts = [];          // GET /api/sdn/ids/alerts
  let hours = 24, sevFilter = 3, search = '';
  // Filtering bar: alerts on closed ports (probes the firewall dropped) and
  // direction. Remembered in this browser (a per-viewer convenience).
  const pref = (k, d) => { try { return localStorage.getItem('znas-fw-ids-' + k) || d; } catch (e) { return d; } };
  const keep = (k, v) => { try { localStorage.setItem('znas-fw-ids-' + k, v); } catch (e) { /* storage blocked */ } };
  let portsF = pref('ports', 'open'); // open | all
  let dirF = pref('dir', 'all');      // all | in | out
  let netF = pref('net', '');         // '' (all networks) | interface id
  let ipF = '';                       // only the alerts about this address (from Local Topo or the address card)
  const about = (a, ip) => [a.src, a.dst, a.src_inside, a.dst_inside].includes(ip);
  const passes = a => (portsF === 'all' || a.open !== false) && (dirF === 'all' || a.dir === dirF) && netMatch(a) && (!ipF || about(a, ipF));
  // Opens IDS alerts on everything about one address over 7 days — what the
  // Local Topo count and the address card count. The remembered filters are
  // widened for this visit only.
  window.fwIDSFocus = ip => {
    ipF = ip; hours = 168; sevFilter = 3; search = ''; portsF = 'all'; dirF = 'all'; netF = '';
    if (typeof switchSidebarMode === 'function') switchSidebarMode('firewall');
    window.showPage('fw-ids');
  };
  const visible = () => {
    const q = search.toLowerCase();
    return alerts.filter(a => passes(a) && a.severity <= sevFilter && (!q || [a.signature, a.src, a.dst, a.src_inside, a.dst_inside, a.category, a.sid,
      ...[a.src, a.dst, a.src_inside, a.dst_inside].map(nameOf)].join(' ').toLowerCase().includes(q)));
  };

  // ── networks (Filtering bar) ───────────────────────────────────────────
  // Every routed network with its own subnet (not the Internet links). An
  // alert belongs to a network when one of its addresses — or the inside
  // host behind the NAT — is in that subnet.
  const ip2n = a => a.split('.').reduce((n, o) => n * 256 + (Number(o) || 0), 0);
  const v4 = ip => !!ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip);
  const inNet = (ip, cidr) => {
    const [base, bits] = cidr.split('/'), size = 2 ** (32 - Number(bits));
    return v4(ip) && Math.floor(ip2n(ip) / size) === Math.floor(ip2n(base) / size);
  };
  const netOf = cidr => {
    const [base, bits] = cidr.split('/'), size = 2 ** (32 - Number(bits)), n = Math.floor(ip2n(base) / size) * size;
    return [24, 16, 8, 0].map(sh => Math.floor(n / 2 ** sh) % 256).join('.') + '/' + bits;
  };
  const networks = () => ((F.cfg() && F.cfg().interfaces) || []).filter(i => i.role !== 'wan' && i.ipv4_mode === 'static' && i.ipv4 && i.ipv4.includes('/'))
    .map(i => ({ id: i.id, name: i.name, color: i.color, cidr: netOf(i.ipv4) }));
  const inNetwork = (a, n) => [a.src, a.dst, a.src_inside, a.dst_inside].some(ip => inNet(ip, n.cidr));
  function netMatch(a) {
    if (!netF) return true;
    const n = networks().find(x => x.id === netF);
    return !n || inNetwork(a, n); // its interface is gone: show everything
  }
  // Internal (private) addresses: shown by their DNS name when it has one.
  const internal = ip => v4(ip) && (/^(10|127)\./.test(ip) || /^192\.168\./.test(ip) || /^169\.254\./.test(ip)
    || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) || /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip));
  const nameOf = ip => { const n = ip && names[ip]; return n && n !== 'pending' ? (n.fqdn || '') : ''; };

  const SEV = { 1: ['High', 'blk'], 2: ['Medium', 'amber'], 3: ['Low', 'none'] };
  const ifaceById = id => F.cfg().interfaces.find(i => i.id === id);
  const ids = () => {
    const c = F.cfg();
    c.ids = c.ids || {};
    ['interfaces', 'sources', 'categories', 'suppressed'].forEach(k => { c.ids[k] = c.ids[k] || []; });
    return c.ids;
  };

  async function loadStatus() {
    const r = await F.api('GET', '/api/sdn/ids/status');
    st = r.ok ? r.data : null;
  }
  async function loadAlerts() {
    const r = await F.api('GET', '/api/sdn/ids/alerts?hours=' + hours);
    alerts = r.ok ? (r.data || []) : [];
    // internal names before the table is drawn (local DNS answers fast)
    const ips = new Set();
    alerts.forEach(a => [a.src, a.dst, a.src_inside, a.dst_inside].forEach(ip => { if (internal(ip) && names[ip] === undefined) ips.add(ip); }));
    const list = [...ips].slice(0, 256), chunks = [];
    for (let i = 0; i < list.length; i += 16) chunks.push(list.slice(i, i + 16));
    await Promise.all(chunks.map(loadNames));
  }

  // ── address card (hover the Source → destination cell) ─────────────────
  // Inside and public address of each side, with the inside name (instance,
  // DHCP lease) and the reverse-DNS name, fetched once per address.
  const names = {}; // ip → {name, fqdn} | 'pending'
  async function loadNames(ips) {
    const want = ips.filter(ip => ip && names[ip] === undefined);
    if (!want.length) return;
    want.forEach(ip => { names[ip] = 'pending'; });
    const r = await F.api('GET', '/api/sdn/ids/names?' + want.map(ip => 'ip=' + encodeURIComponent(ip)).join('&'));
    want.forEach(ip => { names[ip] = (r.ok && r.data && r.data[ip]) || {}; });
  }
  function cardHTML(a) {
    const nm = ip => {
      const n = names[ip];
      if (n === 'pending' || n === undefined) return '<small class="fw-ipc-n">looking up…</small>';
      const parts = [n.name, n.fqdn && n.fqdn !== n.name ? n.fqdn : ''].filter(Boolean);
      return `<small class="fw-ipc-n">${parts.length ? parts.map(F.E).join(' · ') : 'no name found'}</small>`;
    };
    const row = (label, ip, extra) => `<div class="fw-ipc-row"><span class="fw-ipc-l">${label}</span><span><b class="fw-mono">${F.E(ip)}</b>${extra || ''}${nm(ip)}</span></div>`;
    const where = (cc, city) => cc ? ` <span class="fw-ipc-geo">${F.flagOf(cc)} ${F.E([city, F.ccName(cc)].filter(Boolean).join(', '))}</span>` : '';
    const side = (title, ip, inside, cc, city) => `<div class="fw-ipc-h">${title}</div>`
      + (inside ? row('Inside', inside) + row('Public', ip, ' <span class="fw-natb">NAT</span>') : row(cc ? 'Internet' : 'Address', ip, where(cc, city)));
    return side('Source <small>(started the connection)</small>', a.src, a.src_inside, a.src_cc, a.src_city)
      + side('Destination', a.dst, a.dst_inside, a.dst_cc, '');
  }
  function wireCards(root, list) {
    let card = document.getElementById('fw-ipcard');
    if (!card) { card = document.createElement('div'); card.id = 'fw-ipcard'; card.className = 'fw-tip fw-ipcard'; document.body.appendChild(card); }
    card.style.display = 'none';
    let cur = null;
    const place = td => {
      const r = td.getBoundingClientRect(), w = card.offsetWidth, h = card.offsetHeight;
      let x = r.left, y = r.bottom + 6;
      if (x + w > window.innerWidth - 8) x = window.innerWidth - w - 8;
      if (y + h > window.innerHeight - 8) y = Math.max(8, r.top - h - 6);
      card.style.left = Math.max(8, x) + 'px'; card.style.top = y + 'px';
    };
    const show = td => {
      const a = list[Number(td.dataset.ipcard)];
      if (!a) return;
      cur = td;
      card.innerHTML = cardHTML(a); card.style.display = 'block'; place(td);
      loadNames([a.src, a.src_inside, a.dst, a.dst_inside]).then(() => { if (cur === td && document.body.contains(td)) { card.innerHTML = cardHTML(a); place(td); } });
    };
    const hide = () => { cur = null; card.style.display = 'none'; };
    root.querySelectorAll('[data-ipcard]').forEach(td => {
      td.addEventListener('mouseenter', () => show(td));
      td.addEventListener('mouseleave', hide);
      td.addEventListener('click', ev => { if (ev.target.closest('button')) return; cur === td ? hide() : show(td); }); // touch screens
    });
  }

  // ── settings page ──────────────────────────────────────────────────────
  function settingsHTML() {
    const s = ids(), admin = F.isAdmin(), c = F.cfg(), fwOn = (F.status() || {}).enabled;
    const idle = () => { const w = (s.interfaces || []).length ? c.interfaces.filter(i => s.interfaces.includes(i.id)) : c.interfaces.filter(i => i.role === 'wan'); return w.length > 0 && w.every(i => i.disabled); };
    if (!st) return '<div class="fw-empty">Loading…</div>';
    const u = st.update || {};
    const wans = c.interfaces.filter(i => i.role === 'wan');
    const watched = s.interfaces.length ? s.interfaces.map(ifaceById).filter(Boolean) : wans;
    const groups = (u.groups && u.groups.length ? u.groups : st.default_categories).slice().sort();
    const label = g => g.replace(/^emerging-/, '').replace(/_/g, ' ');
    const upd = u.running ? 'Downloading rules…' : (u.updated_at && !u.updated_at.startsWith('0001')
      ? `Rules from ${F.fmtTime(u.updated_at)} · ${F.fmtCount(u.rules_enabled || 0)} active` : 'No rules downloaded yet');
    return `
      ${!st.installed ? `<div class="fw-safemode" style="background:rgba(255,214,10,.10);border-color:rgba(255,214,10,.4)">${F.icon('info', 16)}<div>Intrusion detection needs the <b>suricata</b> package on this server.</div><span style="flex:1"></span>${admin ? '<button class="fw-btn" id="fw-ids-install">Install</button>' : ''}</div>` : ''}
      <div class="fw-card" style="flex-direction:row;align-items:center;gap:14px;flex-wrap:wrap">
        <div style="flex:1;min-width:240px"><b>Intrusion detection (Suricata)</b><div style="color:var(--text-3);font-size:12.5px;margin-top:3px">Inspects the traffic of the watched interfaces and raises alerts — it never blocks by itself. Use “Block” on an alert to add firewall rules.</div></div>
        <span class="fw-gwstate ${s.enabled ? (st.running ? 'up' : 'down') : 'none'}">${s.enabled ? (st.running ? 'Running' : (fwOn ? 'Not running' : 'On')) : 'Off'}</span>
        ${admin ? `<div id="fw-ids-en"></div>` : ''}
      </div>
      ${s.enabled && idle() ? `<div class="fw-note" style="margin:6px 2px 0">${F.icon('info', 12)} Not running: every interface it watches is disabled. It starts again when one is enabled.</div>` : ''}
      ${s.enabled ? '' : `<div class="fw-note" style="margin:6px 2px 0">${F.icon('info', 12)} Plan for about 1 CPU core and 500 MB–1 GB of memory with the default categories; every extra category or rule set adds to it.</div>`}
      ${u.error ? `<div class="fw-safemode" style="margin-top:10px">${F.icon('info', 16)}<div><b>Last rule download failed</b> — ${F.E(u.error)}</div></div>` : ''}
      <div class="fw-cards" style="margin-top:12px">
        <div class="fw-card"><div class="fw-card-h">${F.icon('network', 15)}<span class="fw-name">Watched interfaces</span></div>
          <div class="fw-chips">${watched.map(i => `<span class="fw-pillx"><span class="fw-cdot" style="background:${F.C(i.color)}"></span>${F.E(i.name)}</span>`).join('') || '<span class="fw-note">No WAN yet</span>'}</div>
          <div class="fw-note">${s.interfaces.length ? 'Chosen by you.' : 'Every WAN interface (default).'}</div>
          ${admin ? `<div class="fw-card-actions"><button class="fw-icon-btn" id="fw-ids-if">${F.icon('pencil', 12)}Choose</button></div>` : ''}</div>
        <div class="fw-card"><div class="fw-card-h">${F.icon('bell', 15)}<span class="fw-name">Notifications</span></div>
          <div style="font-size:12.5px;color:var(--text-2)">Send a ZNAS alert for IDS alerts of this severity or higher (Settings → Alerts → “Firewall intrusion detection”).</div>
          <div id="fw-ids-sev" style="margin-top:8px"></div></div>
        <div class="fw-card"><div class="fw-card-h">${F.icon('refresh', 15)}<span class="fw-name">Rules</span></div>
          <div style="font-size:12.5px;color:var(--text-2)">${F.E(upd)}</div>
          <div class="fw-note">Updated every day from the free sets below.</div>
          ${admin ? `<div class="fw-card-actions"><button class="fw-icon-btn" id="fw-ids-upd" ${s.enabled && fwOn && !u.running ? '' : 'disabled'} title="${s.enabled ? '' : 'Turn intrusion detection on and apply first'}">${F.icon('download', 12)}Update now</button></div>` : ''}</div>
      </div>
      <div class="fw-tcard" style="margin-top:14px"><div class="fw-tch"><h3>Rule sets</h3><span class="fw-sub">ET Open is always used · free sets only</span></div>
        <div style="padding:10px 14px;display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:6px">${st.sources.map(src => `
          <label class="fw-cbx" style="margin:0"><input type="checkbox" data-src="${F.E(src.name)}" ${s.sources.includes(src.name) ? 'checked' : ''} ${admin ? '' : 'disabled'}>
          <span><b style="color:var(--text)">${F.E(src.name)}</b><br><small style="color:var(--text-3)">${F.E(src.summary)}</small></span></label>`).join('')}</div></div>
      <div class="fw-tcard" style="margin-top:14px"><div class="fw-tch"><h3>ET Open categories</h3><span class="fw-sub">${s.categories.length} chosen${u.groups && u.groups.length ? '' : ' · the full list appears after the first download'}</span></div>
        <div style="padding:10px 14px" class="fw-chips">${groups.map(g => `<button type="button" class="fw-ichip${s.categories.includes(g) ? ' on' : ''}" data-cat="${F.E(g)}" ${admin ? '' : 'disabled'}>${F.E(label(g))}</button>`).join('')}</div></div>
      <div class="fw-tcard" style="margin-top:14px"><div class="fw-tch"><h3>Suppressed signatures</h3><span class="fw-sub">added from the IDS alerts page</span></div>
        <div class="fw-tscroll"><table class="fw-table"><thead><tr><th>Signature id</th><th>Only for</th><th>Note</th><th></th></tr></thead><tbody>
        ${s.suppressed.map((x, k) => `<tr><td class="fw-mono">${F.E(x.sid)}</td><td class="fw-mono">${F.E(x.ip || 'everyone')}</td><td>${F.E(x.note || '')}</td>
          <td>${admin ? `<button class="fw-icon-btn" data-unsup="${k}">${F.icon('trash', 12)}</button>` : ''}</td></tr>`).join('') || '<tr><td colspan="4" style="color:var(--text-3)">None.</td></tr>'}
        </tbody></table></div></div>`;
  }

  function wireSettings(root) {
    const s = ids();
    const inst = root.querySelector('#fw-ids-install');
    if (inst) inst.onclick = async () => {
      inst.disabled = true; inst.textContent = 'Installing…';
      const r = await F.api('POST', '/api/prereqs/install', { package: 'suricata' });
      if (r.ok) { F.toast('suricata installed', 'success'); await loadStatus(); F.rerender(); }
      else { inst.disabled = false; inst.textContent = 'Install'; F.toast((r.data && r.data.error) || 'Install failed', 'error'); }
    };
    const en = root.querySelector('#fw-ids-en');
    if (en) F.seg(en, [['off', 'Off'], ['on', 'On']], s.enabled ? 'on' : 'off', v => F.saveDraft(n => { n.ids = n.ids || {}; n.ids.enabled = v === 'on'; }));
    const sev = root.querySelector('#fw-ids-sev');
    if (sev) {
      if (F.isAdmin()) F.seg(sev, [['0', 'Never'], ['1', 'High'], ['2', 'Medium+'], ['3', 'All']], String(s.alert_severity || 0), v => F.saveDraft(n => { n.ids.alert_severity = Number(v); }));
      else sev.innerHTML = `<span class="fw-badge none">${['never', 'high', 'medium and high', 'all'][s.alert_severity || 0]}</span>`;
    }
    root.querySelectorAll('[data-src]').forEach(cb => cb.onchange = () => F.saveDraft(n => {
      const set = new Set(n.ids.sources || []);
      cb.checked ? set.add(cb.dataset.src) : set.delete(cb.dataset.src);
      n.ids.sources = [...set];
    }));
    root.querySelectorAll('[data-cat]').forEach(b => b.onclick = () => F.saveDraft(n => {
      const set = new Set(n.ids.categories || []);
      set.has(b.dataset.cat) ? set.delete(b.dataset.cat) : set.add(b.dataset.cat);
      n.ids.categories = [...set];
    }));
    root.querySelectorAll('[data-unsup]').forEach(b => b.onclick = () => F.saveDraft(n => { n.ids.suppressed.splice(Number(b.dataset.unsup), 1); }));
    const ifb = root.querySelector('#fw-ids-if');
    if (ifb) ifb.onclick = () => {
      let sel = s.interfaces.slice();
      const box = document.createElement('div');
      box.innerHTML = '<p style="margin-top:0">None chosen = every WAN interface.</p><div class="fw-chips" id="fw-ids-ifc"></div>';
      F.ifaceChips(box.querySelector('#fw-ids-ifc'), sel, v => { sel = v; });
      F.modal({ title: 'Watched interfaces', body: box, buttons: [{ label: 'Cancel' },
        { label: 'Save to draft', cls: 'btn-primary', onClick: close => { close(); F.saveDraft(n => { n.ids.interfaces = sel; }); } }] });
    };
    const ub = root.querySelector('#fw-ids-upd');
    if (ub) ub.onclick = async () => {
      ub.disabled = true;
      const r = await F.api('POST', '/api/sdn/ids/update');
      if (!r.ok) F.toast((r.data && r.data.error) || 'Could not start', 'error');
      else { F.toast('Rule download started', 'success'); setTimeout(async () => { await loadStatus(); F.rerender(); }, 1500); }
    };
  }

  // ── alerts page ────────────────────────────────────────────────────────
  function alertsHTML() {
    const s = ids(), admin = F.isAdmin();
    const base = alerts.filter(passes), list = visible();
    const n = sv => base.filter(a => a.severity === sv).reduce((t, a) => t + a.count, 0);
    const closed = alerts.filter(a => a.open === false && (dirF === 'all' || a.dir === dirF)).length;
    const suppressed = sid => s.suppressed.some(x => x.sid === sid);
    // this group is silenced (for everyone, or for one of its two addresses)
    const silenced = a => s.suppressed.some(x => x.sid === a.sid && (!x.ip || x.ip === a.src || x.ip === a.dst));
    const blocked = ip => F.cfg().rules.some(r => r.action !== 'allow' && !r.interface && r.source && r.source.type === 'cidr' && (r.source.value === ip || r.source.value === ip + '/32'));
    const flag = cc => cc ? `<span class="fw-flag" title="${F.E(F.ccName(cc))}">${F.flagOf(cc)}</span>` : '';
    // Behind NAT: the inside host replaces our public address.
    // internal address → its DNS name when found (the address stays in the tooltip)
    const shown = ip => { const n = internal(ip) && nameOf(ip); return n && window.fwHostName ? window.fwHostName(n, ip) : (n ? `<span title="${F.E(ip)}">${F.E(n)}</span>` : F.E(ip)); };
    const host = (ip, inside) => inside ? `${shown(inside)}<span class="fw-natb">NAT</span>` : shown(ip);
    const rows = list.map((a, k) => {
      const [sl, sc] = SEV[a.severity] || ['?', 'none'];
      const i = ifaceById(a.interface);
      return `<tr><td data-v="${a.severity}"><span class="fw-sevb ${sc}">${sl}</span></td>
        <td style="white-space:normal;min-width:220px;max-width:340px"><div style="color:var(--text)">${F.E(a.signature)}</div><small style="color:var(--text-3)">${F.E(a.category || '')} · sid ${F.E(a.sid)}</small>${silenced(a) ? ' <span class="fw-badge none" title="This signature is suppressed: no new alert once the suppression is applied. Those seen before stay in the history.">suppressed</span>' : ''}</td>
        <td class="fw-mono fw-ipcell" data-v="${F.E(a.src_inside || a.src)}" data-ipcard="${k}"><div>${flag(a.src_cc)}${host(a.src, a.src_inside)} ${a.dir === 'internal' ? '<span class="fw-dir" style="margin-left:4px;background:var(--surface2);color:var(--text-3)">internal</span>' : `<span class="fw-dir ${a.incoming ? 'in' : 'out'}" style="margin-left:4px">${a.incoming ? '→ in' : 'out →'}</span>`}${a.dir === 'in' && a.open === false ? ' <span class="fw-badge none" title="No forward or allow rule opens this port: the firewall dropped it">closed port</span>' : ''}</div>
          <div style="margin-top:3px">${flag(a.dst_cc)}${host(a.dst, a.dst_inside)}${a.port_count > 1
          ? ` <small title="${F.E((a.ports || []).join(', ') + (a.port_count > (a.ports || []).length ? ', …' : ''))}" style="color:var(--accent-warn)">${F.E(a.port_count)} ports</small>`
          : (a.dst_port ? ':' + F.E(a.dst_port) : '')} <small style="color:var(--text-3)">${F.E(a.proto)}</small></div></td>
        <td>${i ? `<span class="fw-pillx"><span class="fw-cdot" style="background:${F.C(i.color)}"></span>${F.E(i.name)}</span>` : F.E(typeof window.ifLabel === 'function' ? window.ifLabel(a.in_iface) : a.in_iface)}</td>
        <td class="fw-mono" data-v="${a.count || 0}">${F.E(F.fmtCount(a.count))}</td><td data-v="${new Date(a.last).getTime() || 0}" title="First seen ${F.E(F.fmtTime(a.first))}">${F.E(F.fmtTime(a.last))}</td>
        <td>${admin ? `<span style="display:inline-flex;gap:4px">
          <button class="fw-icon-btn" data-block="${k}" ${blocked(a.incoming ? a.src : a.dst) ? 'disabled title="Already blocked"' : ''} title="Block all traffic with ${F.E(a.incoming ? a.src : a.dst)}">${F.icon('x-circle', 12)}Block</button>
          <button class="fw-icon-btn" data-sup="${k}" ${suppressed(a.sid) ? 'disabled title="Already suppressed"' : 'title="Stop alerting on this signature"'}>${F.icon('eye-off', 12)}</button></span>` : ''}</td></tr>`;
    }).join('');
    return `
      ${!s.enabled ? `<div class="fw-safemode" style="background:rgba(255,214,10,.10);border-color:rgba(255,214,10,.4)">${F.icon('info', 16)}<div>Intrusion detection is off — turn it on in <a href="#" onclick="showPage('fw-suricata');return false">Intrusion detection</a>.</div></div>` : ''}
      <div class="fw-filterbar"><span class="fw-filterbar-l">${F.icon('filter', 13)}Filtering</span>
        ${ipF ? `<span class="fw-ipchip">About <b>${nameOf(ipF) && window.fwHostName ? window.fwHostName(nameOf(ipF), ipF) : `<span class="fw-ipi" data-ip="${F.E(ipF)}">${F.E(ipF)}</span>`}</b><button type="button" id="fw-ids-ipx" title="Show every address" aria-label="Show every address">${F.icon('x', 12)}</button></span>` : ''}
        <div id="fw-ids-portsf"></div><div id="fw-ids-dirf"></div><div id="fw-ids-netf" class="fw-quick"></div>
        <span class="fw-sub">${portsF === 'open' && closed ? `${F.E(closed)} alert group${closed > 1 ? 's' : ''} on closed ports hidden — the firewall dropped those probes` : ''}</span></div>
      <div class="fw-kpis" style="margin-bottom:12px">
        ${[1, 2, 3].map(sv => `<div class="fw-kpi"><div class="fw-kpi-bar" style="background:${['', 'var(--fw-blk)', 'var(--accent-warn)', 'var(--text-3)'][sv]}"></div><div class="fw-kpi-l">${SEV[sv][0]} severity</div><div class="fw-kpi-v">${F.E(F.fmtCount(n(sv)))}</div><div class="fw-kpi-d">alerts, last ${hours < 48 ? hours + ' h' : hours / 24 + ' days'}</div></div>`).join('')}
        <div class="fw-kpi"><div class="fw-kpi-bar" style="background:var(--accent-2)"></div><div class="fw-kpi-l">Distinct sources</div><div class="fw-kpi-v">${new Set(base.map(a => a.src)).size}</div><div class="fw-kpi-d">${base.length} alert groups</div></div>
      </div>
      <div class="fw-tcard"><div class="fw-tch"><h3>Alerts</h3><span class="fw-sub">grouped by signature, source and destination</span><span style="flex:1"></span>
        <div id="fw-ids-sevf"></div><div id="fw-ids-range"></div>
        <input class="fw-search" id="fw-ids-q" placeholder="Search signature, address…" value="${F.E(search)}" style="max-width:220px">
        ${admin ? `<div class="fw-dd" id="fw-ids-dd"><button class="fw-btn" id="fw-ids-more" title="More">${F.icon('more-vertical', 14)}</button></div>` : ''}</div>
        <div class="fw-tscroll"><table class="fw-table" data-sort="ids"><thead><tr><th data-asc>Severity</th><th>Signature</th><th>Source → destination</th><th>Interface</th><th>Count</th><th>Last seen</th><th></th></tr></thead>
        <tbody>${rows || `<tr><td colspan="7" style="color:var(--text-3)">${alerts.length ? 'Nothing matches the filters.' : 'No alert in this period.'}</td></tr>`}</tbody></table></div></div>`;
  }

  function wireAlerts(root) {
    F.seg(root.querySelector('#fw-ids-portsf'), [['all', 'All ports'], ['open', 'Only open ports']], portsF, v => { portsF = v; keep('ports', v); F.rerender(); });
    F.seg(root.querySelector('#fw-ids-dirf'), [['all', 'All'], ['in', 'From Internet'], ['out', 'To Internet']], dirF, v => { dirF = v; keep('dir', v); F.rerender(); });
    const nb = root.querySelector('#fw-ids-netf'), nets = networks();
    if (nb) {
      const count = n => alerts.filter(a => inNetwork(a, n)).length;
      F.picker(nb, [{ value: '', label: 'All networks', section: 'Networks' }]
        .concat(nets.map(n => ({ value: n.id, label: n.name, color: n.color, hint: n.cidr + ' · ' + count(n) + (count(n) === 1 ? ' alert' : ' alerts'), section: 'Networks' }))),
        netF, v => { netF = v; keep('net', v); F.rerender(); }, { width: 360, placeholder: 'All networks' }); // a network since removed: everything is shown
      const btn = nb.querySelector('.fw-picker-btn');
      if (btn) btn.insertAdjacentHTML('afterbegin', F.icon('layers', 13)), btn.classList.toggle('fw-quick-on', nets.some(n => n.id === netF));
    }
    F.seg(root.querySelector('#fw-ids-sevf'), [['1', 'High'], ['2', 'Medium+'], ['3', 'All']], String(sevFilter), v => { sevFilter = Number(v); F.rerender(); });
    F.seg(root.querySelector('#fw-ids-range'), [['24', '24 h'], ['168', '7 days'], ['720', '30 days']], String(hours), async v => { hours = Number(v); await loadAlerts(); F.rerender(); });
    const ipx = root.querySelector('#fw-ids-ipx');
    if (ipx) ipx.onclick = () => { ipF = ''; portsF = pref('ports', 'open'); dirF = pref('dir', 'all'); netF = pref('net', ''); F.rerender(); };
    const qi = root.querySelector('#fw-ids-q');
    qi.oninput = () => { search = qi.value; const pos = qi.selectionStart; F.rerender(); const n = document.getElementById('fw-ids-q'); if (n) { n.focus(); n.setSelectionRange(pos, pos); } };
    const list = visible();
    wireCards(root, list);
    wireClear(root);
    root.querySelectorAll('[data-block]').forEach(b => b.onclick = () => {
      const a = list[Number(b.dataset.block)];
      // The outside party: for a response alert (a LAN client fetched
      // something bad) the "source" is the outside server.
      const ip = a.incoming ? a.src : a.dst;
      F.modal({ title: `Block ${ip}?`, body: `<p>Adds two rules at the top of <b>Any interface</b>: nothing may reach <span class="fw-mono">${F.E(ip)}</span> and nothing from it is accepted. They take effect when you <b>Apply</b>; connections already open end when they go idle.</p>`,
        buttons: [{ label: 'Cancel' }, { label: 'Add the rules', cls: 'btn-danger', onClick: close => { close(); F.saveDraft(n => {
          const desc = ('IDS: ' + a.signature).slice(0, 120);
          const mk = (src, dst) => ({ id: F.newId(), enabled: true, interface: '', action: 'block', protocol: 'any', log: false, source: src, destination: dst, description: desc });
          const rules = [mk({ type: 'cidr', value: ip }, { type: 'any' }), mk({ type: 'any' }, { type: 'cidr', value: ip })];
          const at = n.rules.findIndex(r => !r.interface);
          at < 0 ? n.rules.unshift(...rules) : n.rules.splice(at, 0, ...rules);
        }).then(ok => { if (ok) F.toast('Block rules added to the draft — Apply to enforce them', 'success'); }); } }] });
    });
    root.querySelectorAll('[data-sup]').forEach(b => b.onclick = () => {
      const a = list[Number(b.dataset.sup)];
      const box = document.createElement('div');
      box.innerHTML = `<p style="margin-top:0"><b>${F.E(a.signature)}</b> (sid ${F.E(a.sid)})</p><div id="fw-sup-who"></div>`;
      let who = 'all';
      F.seg(box.querySelector('#fw-sup-who'), [['all', 'For everyone'], ['ip', 'Only for ' + (a.incoming ? a.src : a.dst)]], who, v => { who = v; });
      F.modal({ title: 'Suppress this signature', body: box, buttons: [{ label: 'Cancel' }, { label: 'Suppress', cls: 'btn-primary', onClick: close => { close(); F.saveDraft(n => {
        n.ids.suppressed = n.ids.suppressed || [];
        n.ids.suppressed.push({ sid: a.sid, ip: who === 'ip' ? (a.incoming ? a.src : a.dst) : '', note: a.signature.slice(0, 80) });
      }).then(ok => { if (ok) F.toast('Suppression added to the draft — Apply to use it', 'success'); }); } }] });
    });
  }

  // ── ⋮ on the table title: forget alerts ────────────────────────────────
  function wireClear(root) {
    const btn = root.querySelector('#fw-ids-more');
    if (!btn) return;
    btn.onclick = e => {
      e.stopPropagation();
      const dd = btn.closest('.fw-dd');
      if (dd.querySelector('.fw-menu')) { dd.querySelector('.fw-menu').remove(); return; }
      const nSup = ids().suppressed.length;
      const m = document.createElement('div');
      m.className = 'fw-menu';
      m.style.minWidth = '330px'; m.style.whiteSpace = 'nowrap';
      m.innerHTML = `<div class="fw-menu-item${nSup ? '' : ' fw-off'}" data-m="suppressed" ${nSup ? '' : 'title="No signature is suppressed"'}>${F.icon('eye-off')}Delete the alerts of suppressed signatures</div>
        <div class="fw-menu-sep"></div>
        <div class="fw-menu-item fw-danger" data-m="all">${F.icon('trash')}Delete all IDS alert history</div>`;
      dd.appendChild(m);
      m.onclick = ev => ev.stopPropagation();
      m.querySelectorAll('[data-m]').forEach(it => it.onclick = () => {
        if (it.classList.contains('fw-off')) return;
        m.remove();
        confirmClear(it.dataset.m);
      });
      setTimeout(() => document.addEventListener('click', function off() { m.remove(); document.removeEventListener('click', off); }), 0);
    };
  }
  function confirmClear(scope) {
    const all = scope === 'all';
    F.modal({ title: all ? 'Delete all IDS alert history?' : 'Delete the alerts of suppressed signatures?',
      body: all
        ? '<p>Every alert recorded on this server, over the last 30 days, is deleted. New alerts keep coming in. This cannot be undone.</p>'
        : `<p>The alerts of the ${F.E(ids().suppressed.length)} suppressed signature${ids().suppressed.length > 1 ? 's' : ''} are deleted from the history, over the last 30 days. A suppression for one address only deletes that address's alerts.</p><p>Suppressions still in the draft count too: they stop new alerts only once applied.</p>`,
      buttons: [{ label: 'Cancel' }, { label: 'Delete', cls: 'btn-danger', onClick: async (close, b) => {
        b.disabled = true;
        const r = await F.api('DELETE', '/api/sdn/ids/alerts?scope=' + scope);
        b.disabled = false;
        if (!r.ok) { F.toast((r.data && r.data.error) || 'Not deleted', 'error'); return; }
        close();
        const n = (r.data && r.data.deleted) || 0;
        F.toast(n ? `${F.fmtCount(n)} alert group${n > 1 ? 's' : ''} deleted` : 'Nothing to delete', 'success');
        await loadAlerts(); F.rerender();
      } }] });
  }

  function register() {
    if (typeof window.sdnRegisterPage !== 'function' || !window.sdnFW || !window.sdnFW.ifaceChips) { setTimeout(register, 200); return; }
    F = window.sdnFW;
    window.sdnRegisterPage('fw-suricata', { load: loadStatus, render: settingsHTML, wire: wireSettings, pollMs: 8000, poll: loadStatus });
    window.sdnRegisterPage('fw-ids', { load: async () => { await Promise.all([loadAlerts(), F.loadCountries()]); }, render: alertsHTML, wire: wireAlerts, pollMs: 15000,
      poll: async () => { if (document.querySelector('#fw-ids-netf .fw-picker-pop, #fw-ids-dd .fw-menu')) return false; await loadAlerts(); } }); // a menu open: don't redraw under it
  }
  register();
})();
