/*
 * Firewall → Gateways and NAT (SDN phase 3). Spec: PLANS/spec-sdn-firewall.md §7, §11.1.
 *
 * Gateways: Internet links in failover order, with the live state published
 * by the gateway monitor daemon (GET /api/sdn/gateways, polled every 3 s).
 * NAT: port forwards (manual ones edited here; VM/container ones shown here
 * and edited in the instance editor) and outbound NAT with the outgoing
 * gateway of your choice. Every edit goes to the draft, like the other pages.
 */
(function () {
  'use strict';

  let F = null;            // window.sdnFW (sdn.js helpers), set at register time
  let gwState = null;      // GET /api/sdn/gateways
  let natTab = 'forwards';
  let liveRoutes = null;   // GET /api/sdn/routes
  let appliedRoutes = null; // routes of the applied configuration

  const PROTO = { tcp: 'TCP', udp: 'UDP', tcpudp: 'TCP+UDP', any: 'Any', icmp: 'ICMP' };
  const ifaceById = id => F.cfg().interfaces.find(i => i.id === id);
  const gwById = id => F.cfg().gateways.find(g => g.id === id);
  const sortedGws = () => F.cfg().gateways.slice().sort((a, b) => a.priority - b.priority);
  const ifacePill = id => {
    const i = ifaceById(id);
    return `<span class="fw-pillx"><span class="fw-cdot" style="background:${F.C(i && i.color)}"></span>${F.E(i ? i.name : '(deleted interface)')}</span>`;
  };
  const cb = (id, label, checked) => `<label class="fw-cbx"><input type="checkbox" id="${id}" ${checked ? 'checked' : ''}>${label}</label>`;

  // Errors for one config path prefix → first message into the matching field.
  const ifName = d => (typeof window.ifLabel === 'function' ? window.ifLabel(d) : d) || '';
  function showErrors(root, errs, prefix, map, fallback) {
    root.querySelectorAll('.fw-err').forEach(e => { e.textContent = ''; });
    const mine = errs.filter(e => e.path.startsWith(prefix));
    if (!mine.length) return false;
    const field = mine[0].path.slice(prefix.length).replace(/^\./, '').split(/[.[]/)[0];
    const el = root.querySelector(map[field] || fallback);
    if (el) el.textContent = mine[0].message;
    return true;
  }

  // Source/destination endpoint editor (same choices as the rule drawer).
  function endpointEditor(el, ep, isDst, onChange) {
    ep = F.clone(ep || { type: 'any' });
    let sel = ep.type === 'cidr' ? 'cidr:' : (ep.type === 'countries' ? 'countries:' : ep.type + ':' + (ep.value || ''));
    let codes = ep.type === 'countries' ? (ep.value || '').split(',').filter(Boolean) : [];
    el.innerHTML = `<div data-p></div><input type="text" data-v placeholder="203.0.113.0/24" style="margin-top:6px"><div class="fw-chips" data-cc style="margin-top:6px"></div>
      ${cb('', 'Everything except this', !!ep.not).replace('id=""', 'data-not')}`;
    const inp = el.querySelector('[data-v]'), not = el.querySelector('[data-not]');
    if (ep.type === 'cidr') inp.value = ep.value || '';
    const read = () => {
      const [type, value] = sel.split(/:(.*)/s);
      const out = { type };
      if (type === 'cidr') out.value = inp.value.trim();
      else if (type === 'countries') out.value = codes.join(',');
      else if (value) out.value = value;
      if (type !== 'any' && not.checked) out.not = true;
      inp.style.display = type === 'cidr' ? '' : 'none';
      // always shown (as in the rule editor); meaningless — so greyed — for Any
      not.disabled = type === 'any';
      not.parentElement.style.opacity = type === 'any' ? '.45' : '';
      not.parentElement.title = type === 'any' ? 'Choose something other than Any to invert it' : '';
      onChange(out);
    };
    const drawCC = () => {
      const box = el.querySelector('[data-cc]');
      box.style.display = sel === 'countries:' ? '' : 'none';
      if (sel !== 'countries:') return;
      box.innerHTML = codes.map((c, k) => `<span class="fw-chip">${F.flagOf(c)} ${F.E(F.ccName(c))}<button data-rm="${k}" title="Remove">${F.icon('x', 11)}</button></span>`).join('') + '<span data-add style="min-width:200px;display:inline-block"></span>';
      box.querySelectorAll('[data-rm]').forEach(b => b.onclick = () => { codes.splice(Number(b.dataset.rm), 1); drawCC(); read(); });
      F.picker(box.querySelector('[data-add]'), F.countryOptions(), '', v => { if (!codes.includes(v)) codes.push(v); drawCC(); read(); }, { placeholder: '+ Add a country…', search: true });
    };
    F.picker(el.querySelector('[data-p]'), F.endpointOptions(isDst), sel, v => { sel = v; drawCC(); read(); }, { search: true });
    inp.oninput = read; not.onchange = read;
    F.loadCountries().then(drawCC);
    read();
  }

  // Interface multi-select as toggle chips.
  function ifaceChips(el, selected, onChange, filter) {
    const list = F.cfg().interfaces.filter(filter || (() => true));
    const draw = () => {
      el.innerHTML = list.length ? list.map(i => `<button type="button" class="fw-ichip${selected.includes(i.id) ? ' on' : ''}" data-i="${F.E(i.id)}">
        <span class="fw-cdot" style="background:${F.C(i.color)}"></span>${F.E(i.name)}${i.role === 'wan' ? '<small>WAN</small>' : ''}</button>`).join('')
        : '<span class="fw-note">No interface yet.</span>';
      el.querySelectorAll('[data-i]').forEach(b => b.onclick = () => {
        const id = b.dataset.i;
        selected = selected.includes(id) ? selected.filter(x => x !== id) : [...selected, id];
        draw(); onChange(selected);
      });
    };
    draw();
  }

  function drawer(title, sentence, bodyHTML, footHTML) {
    const bg = document.createElement('div'); bg.className = 'fw-drawer-bg';
    const dr = document.createElement('div'); dr.className = 'fw-drawer';
    dr.innerHTML = `<div class="fw-drawer-h"><h3>${F.E(title)}</h3><div class="fw-sentence" data-sent>${sentence || ''}</div></div>
      <div class="fw-drawer-b">${bodyHTML}<div class="fw-err" data-err></div></div><div class="fw-drawer-f">${footHTML}</div>`;
    document.body.appendChild(bg); document.body.appendChild(dr);
    const close = () => { bg.remove(); dr.remove(); };
    bg.onclick = close;
    return { dr, close, q: s => dr.querySelector(s) };
  }

  let gwTicks = 0;
  // ── Gateways ───────────────────────────────────────────────────────────
  async function loadGw() {
    const r = await F.api('GET', '/api/sdn/gateways');
    gwState = r.ok ? r.data : null;
  }
  async function loadRoutes() {
    const r = await F.api('GET', '/api/sdn/routes');
    if (r.ok) liveRoutes = (r.data && r.data.routes) || [];
    const a = await F.api('GET', '/api/sdn/config');
    if (a.ok) appliedRoutes = ((a.data && (a.data.config || a.data)) || {}).routes || [];
  }
  const liveGw = id => ((gwState && gwState.gateways) || []).find(g => g.id === id);
  const monitorStale = () => {
    if (!F.cfg().gateways.length) return false;
    if (!gwState || !gwState.updated || gwState.updated.startsWith('0001')) return true;
    return Date.now() - new Date(gwState.updated).getTime() > 20000;
  };

  function gwUse(id) {
    const c = F.cfg();
    return c.rules.filter(r => r.gateway === id).length + c.snat_rules.filter(r => r.gateway === id).length;
  }

  function gatewaysHTML() {
    const c = F.cfg(), list = sortedGws(), admin = F.isAdmin();
    const st = F.status() || {};
    const wanIfaces = c.interfaces.filter(i => i.kind !== 'wireguard');
    const cards = list.map((g, k) => {
      const L = liveGw(g.id) || {};
      const i = ifaceById(g.interface);
      let state = 'down', label = 'Down';
      if (!L.id) { state = 'none'; label = st.enabled ? 'Waiting for the monitor' : 'Not applied yet'; }
      else if (!L.hop) { state = 'down'; label = 'No route yet'; }
      else if (!g.monitor) { state = 'none'; label = 'Not monitored'; }
      else if (L.up) { state = 'up'; label = 'Online'; }
      const hop = L.hop ? (L.hop.via ? L.hop.via : 'point-to-point') + ' via ' + ifName(L.hop.dev) : '—';
      const n = gwUse(g.id);
      return `<div class="fw-card fw-gw${L.active ? ' fw-gw-active' : ''}" data-id="${F.E(g.id)}">
        <div class="fw-stripe" style="background:${F.C(i && i.color)}"></div>
        <div class="fw-card-h"><span class="fw-prio" title="Failover order">${k + 1}</span>
          <span class="fw-name">${F.E(g.name)}</span>
          ${L.active ? `<span class="fw-badge wan" title="Carries the Internet traffic: the default route goes through this gateway">${F.icon('globe', 11)}Active</span>` : ''}
          <span class="fw-gwstate ${state}">${F.E(label)}</span></div>
        <div class="fw-kv"><span>Interface</span><span style="display:flex;gap:6px;align-items:center;min-width:0"><i class="fw-cdot" style="width:8px;height:8px;border-radius:50%;flex:none;background:${F.C(i && i.color)}"></i><span style="color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${F.E(i ? i.name : '')}">${F.E(i ? i.name : '(deleted interface)')}</span></span>
          <span>Next hop</span><span class="fw-mono" title="${F.E(hop)}">${F.E(g.address ? g.address : (L.hop ? (L.hop.via || ifName(L.hop.dev)) + ' (auto)' : 'automatic'))}</span>
          <span>Latency</span><span class="fw-mono">${g.monitor && L.up && L.rtt_ms ? F.E(L.rtt_ms.toFixed(1) + ' ms') : '—'}</span>
          <span>Loss</span><span class="fw-mono">${g.monitor && L.id ? F.E((L.loss || 0) + ' %') : '—'}</span>
          <span>Checks</span><span>${g.monitor ? `${g.probe_pings > 1 ? g.probe_pings + ' pings' : 'ping'} to ${F.E(L.target || g.monitor_ip || g.address || 'the gateway')} every ${g.probe_every || 2} s` : 'not monitored — always considered up'}</span>
          ${g.monitor && i && i.kind === 'pppoe' ? `<span>On failure</span><span style="color:var(--accent-warn)" title="Failed tests hang up this PPPoE link and dial it again">reconnects PPPoE</span>` : ''}</div>
        ${L.reconnect_held ? `<div class="fw-note" style="margin-top:8px;color:var(--accent-warn)">${F.E(L.target || 'This address')} has never answered, so ZNAS is not reconnecting. It says nothing about the link: choose another address to test.</div>` : ''}
        ${admin ? `<div class="fw-card-actions">
          <button class="fw-icon-btn" data-up="${F.E(g.id)}" ${k === 0 ? 'disabled' : ''} title="Prefer this gateway">${F.icon('arrow-up', 12)}</button>
          <button class="fw-icon-btn" data-down="${F.E(g.id)}" ${k === list.length - 1 ? 'disabled' : ''} title="Use this gateway later">${F.icon('arrow-down', 12)}</button>
          <span style="flex:1"></span>
          <button class="fw-icon-btn" data-edit="${F.E(g.id)}">${F.icon('pencil', 12)}Edit</button>
          <button class="fw-icon-btn danger" data-del="${F.E(g.id)}" ${n ? 'disabled' : ''} title="${n ? `Used by ${n} rule${n > 1 ? 's' : ''}` : 'Remove'}">${F.icon('trash', 12)}Remove</button></div>` : ''}
      </div>`;
    }).join('');
    const events = ((gwState && gwState.events) || []).slice(-8).reverse();
    const evLabel = e => ({ down: `${e.name} went down`, up: `${e.name} is back up`, failover: `Internet traffic moved to ${e.name}`, reconnect: `${e.name} failed its ping tests: PPPoE reconnecting` }[e.kind] || e.kind);
    return `
      <div class="fw-section-h" style="font-size:15px;font-weight:600;color:var(--text);margin:0 0 8px">Gateways</div>
      ${monitorStale() && st.enabled ? `<div class="fw-safemode" style="background:rgba(255,214,10,.10);border-color:rgba(255,214,10,.4)">${F.icon('info', 16)}<div><b style="color:var(--accent-warn)">The gateway monitor is not reporting</b> — failover is not active. Apply the configuration, or check the <span class="fw-mono">znas-sdn-gw</span> service.</div></div>` : ''}
      <div class="fw-note" style="margin-bottom:10px">Traffic to the Internet uses the first gateway that is online. When a monitored gateway fails its health checks, traffic moves to the next one, and comes back after a minute of good health. A monitored PPPoE link is also hung up and dialled again.</div>
      ${!wanIfaces.length ? `<div class="fw-empty">No interface yet — add one on the Interfaces page to add a gateway.</div>` : ''}
      <div class="fw-cards">${cards}${admin && wanIfaces.length ? `<div class="fw-card fw-add-card" id="fw-add-gw">${F.icon('plus', 22)}<span>New gateway</span><span style="font-size:11.5px">An Internet link on any interface</span></div>` : ''}</div>
      ${events.length ? `<div class="fw-card" style="margin-top:14px"><b>Recent events</b><div class="fw-gwev">${events.map(e => `<div><span class="fw-dot ${e.kind === 'down' ? 'amber' : ''}"></span>${F.E(evLabel(e))}<span class="fw-t">${F.E(F.fmtTime(e.at, true))}</span></div>`).join('')}</div></div>` : ''}
      ${routesHTML()}`;
  }

  // ── Local routes ───────────────────────────────────────────────────────
  // The kernel prints a /32 without its mask; the config is normalized alike.
  const kernelDst = d => d === '0.0.0.0/0' ? 'default' : d;
  const routeLive = r => {
    const i = ifaceById(r.interface);
    return (liveRoutes || []).find(x => x.protocol === 'znas' && x.dst === kernelDst(r.destination) && (x.metric || 0) === (r.metric || 0) && (x.gateway || '') === (r.via || '') && i && x.dev === F.l3(i));
  };
  function routeState(r) {
    const i = ifaceById(r.interface);
    if (!r.enabled) return ['none', 'Off'];
    if (i && i.disabled) return ['none', 'Interface disabled'];
    if (!liveRoutes) return ['none', '—'];
    if (routeLive(r)) return ['up', 'Active'];
    return ['down', appliedRoutes && !appliedRoutes.some(x => x.id === r.id && x.destination === r.destination && (x.via || '') === (r.via || '') && (x.metric || 0) === (r.metric || 0) && x.interface === r.interface && x.enabled) ? 'Not applied yet' : 'Waiting'];
  }
  // Routes in the kernel that nothing on this page wrote: everything but the
  // links' own networks, DHCP and router advertisements, and our own routes.
  // Each stays with what owns it: the monitor for the default while there are
  // gateways, the tunnel for its peers' networks; the rest can be taken over.
  function systemRoutes() {
    const c = F.cfg(), list = c.routes || [];
    return (liveRoutes || []).filter(x => !['kernel', 'dhcp', 'ra', 'redirect', 'znas'].includes(x.protocol || '')
      && !list.some(r => kernelDst(r.destination) === x.dst && (r.metric || 0) === (x.metric || 0)))
      .map(x => {
        const i = c.interfaces.find(y => F.l3(y) === x.dev);
        if (i && i.kind === 'wireguard') return { x, i, owner: 'wireguard' };
        if (x.dst === 'default' && (c.gateways || []).length) {
          return { x, i, owner: 'gateway', gw: (c.gateways || []).find(g => i && g.interface === i.id) };
        }
        return { x, i, owner: i ? 'system' : 'outside' };
      });
  }
  const systemRouteById = key => systemRoutes().find(s => `${s.x.dst}|${s.x.metric || 0}` === key);
  function systemRouteRow(s, admin) {
    const { x, i } = s;
    const gw = s.gw && s.gw.name;
    const [state, tip, note] = {
      gateway: ['Gateway', 'The gateway monitor keeps this route and moves it when a link fails.', gw ? `Default gateway, from ${gw}` : 'Default gateway, from the gateways'],
      wireguard: ['Tunnel', 'Written for the networks behind this tunnel\'s peers.', 'Networks of the tunnel\'s peers'],
      system: ['System', 'Not managed by the Firewall yet. Edit takes it over, then it is kept here.', x.source ? `Written by /etc/network/interfaces (${x.source})` : 'Set outside the Firewall'],
      outside: ['System', 'Its interface is not on the Firewall\'s Interfaces page, so it cannot be managed here.', 'On an interface the Firewall does not manage'],
    }[s.owner];
    const key = `${x.dst}|${x.metric || 0}`;
    let btn = '';
    if (admin && s.owner === 'system') btn = `<button class="fw-icon-btn" data-rt-adopt="${F.E(key)}">${F.icon('pencil', 12)}Edit</button>`;
    if (admin && s.owner === 'gateway' && s.gw) btn = `<button class="fw-icon-btn" data-edit="${F.E(s.gw.id)}">${F.icon('pencil', 12)}Edit gateway</button>`;
    if (admin && s.owner === 'wireguard') btn = `<button class="fw-icon-btn" onclick="showPage('fw-wireguard')">${F.icon('pencil', 12)}Edit tunnel</button>`;
    return `<tr>
        <td><span class="fw-gwstate none" title="${F.E(tip)}">${state}</span></td>
        <td class="fw-mono">${F.E(x.dst === 'default' ? 'default (0.0.0.0/0)' : x.dst)}</td>
        <td class="fw-mono">${F.E(x.gateway || 'on the link')}</td>
        <td>${i ? ifacePill(i.id) : F.E(x.dev)}</td>
        <td class="fw-mono">${F.E(x.metric || 0)}</td>
        <td>${F.E(note)}</td>
        ${admin ? `<td style="text-align:right">${btn}</td>` : ''}</tr>`;
  }
  function routesHTML() {
    const c = F.cfg(), admin = F.isAdmin(), list = c.routes || [];
    const sys = systemRoutes();
    const rows = list.map(r => {
      const [cls, label] = routeState(r);
      return `<tr>
        <td><span class="fw-gwstate ${cls}" title="${label === 'Waiting' ? 'Not in the routing table right now: its interface is down, or its router is not reachable on that network. ZNAS tries again every 10 seconds.' : ''}">${F.E(label)}</span></td>
        <td class="fw-mono">${F.E(r.destination === '0.0.0.0/0' ? 'default (0.0.0.0/0)' : r.destination)}</td>
        <td class="fw-mono">${F.E(r.via || 'on the link')}</td>
        <td>${ifacePill(r.interface)}</td>
        <td class="fw-mono">${F.E(r.metric || 0)}</td>
        <td>${F.E(r.description || '')}</td>
        ${admin ? `<td style="text-align:right"><button class="fw-icon-btn" data-rt-toggle="${F.E(r.id)}">${r.enabled ? 'Turn off' : 'Turn on'}</button>
          <button class="fw-icon-btn" data-rt-edit="${F.E(r.id)}">${F.icon('pencil', 12)}Edit</button>
          <button class="fw-icon-btn danger" data-rt-del="${F.E(r.id)}" title="Remove">${F.icon('trash', 12)}</button></td>` : ''}</tr>`;
    }).join('');
    const live = (liveRoutes || []).map(x => `<tr><td class="fw-mono">${F.E(x.dst)}</td><td class="fw-mono">${F.E(x.gateway || 'on the link')}</td><td>${F.E(ifName(x.dev))}</td><td class="fw-mono">${F.E(x.metric || 0)}</td><td>${F.E(x.protocol === 'znas' ? 'Local route' : x.protocol === 'kernel' ? 'Network of the interface' : (x.protocol || 'static'))}</td></tr>`).join('');
    return `<div class="fw-section-h" style="font-size:15px;font-weight:600;color:var(--text);margin:22px 0 8px;display:flex;align-items:center;gap:10px">Local routes<span style="flex:1"></span>${admin ? `<button class="fw-btn" id="fw-add-rt">${F.icon('plus', 12)}Add route</button>` : ''}</div>
      <div class="fw-note" style="margin-bottom:10px">Tells this server which router leads to a network that is not directly connected, such as a network behind another router on your LAN. Routes take effect when you apply, come back by themselves after a reboot or when their interface returns, and are kept with the Firewall's backups. They only choose the path: your firewall rules still decide what may pass.</div>
      <div class="fw-card" style="padding:0">${list.length || sys.length ? `<div class="fw-tscroll"><table class="fw-table"><thead><tr><th>State</th><th>Destination</th><th>Next hop</th><th>Interface</th><th>Metric</th><th>Description</th>${admin ? '<th></th>' : ''}</tr></thead><tbody>${rows}${sys.map(s => systemRouteRow(s, admin)).join('')}</tbody></table></div>` : '<div class="fw-empty">No local route yet.</div>'}</div>
      ${live ? `<details id="fw-live-routes" style="margin-top:12px"${routesOpen ? ' open' : ''}><summary style="cursor:pointer;color:var(--text-2);font-size:13px">All routes in use on this server (${(liveRoutes || []).length})</summary>
        <div class="fw-card" style="padding:0;margin-top:8px"><div class="fw-tscroll"><table class="fw-table"><thead><tr><th>Destination</th><th>Next hop</th><th>Interface</th><th>Metric</th><th>Source</th></tr></thead><tbody>${live}</tbody></table></div></div></details>` : ''}`;
  }
  let routesOpen = false;

  // adopt: a route found in the kernel, prefilled; saving makes it a local route.
  function editRoute(existing, adopt) {
    const c = F.cfg();
    const r = existing ? F.clone(existing) : adopt
      ? { id: F.newId(), enabled: true, destination: adopt.x.dst === 'default' ? '0.0.0.0/0' : adopt.x.dst, via: adopt.x.gateway || '', interface: adopt.i.id, metric: adopt.x.metric || 0, description: '' }
      : { id: F.newId(), enabled: true, destination: '', via: '', interface: '', metric: 0, description: '' };
    const src = existing ? ((liveRoutes || []).find(x => x.dst === kernelDst(existing.destination) && x.source) || {}).source : adopt && adopt.x.source;
    const box = document.createElement('div');
    box.innerHTML = `
      ${r.destination === '0.0.0.0/0' ? '<div class="fw-note" style="margin-bottom:10px">This is the default gateway: a wrong next hop can cut this server off. Like any Firewall change, it is undone by itself if you do not confirm it after applying.</div>' : ''}
      ${src ? `<div class="fw-note" style="margin-bottom:10px">Also written by <span class="fw-mono">/etc/network/interfaces</span> (${F.E(src)}). This setting wins over it. If you remove this route or turn it off, the one in that file comes back.</div>` : ''}
      <div class="fw-field"><label>Destination network</label><input type="text" id="fwr-dst" value="${F.E(r.destination)}" placeholder="10.20.0.0/16, or one address"><div class="fw-err" id="fwr-dst-err"></div></div>
      <div class="fw-field"><label>Interface</label><div id="fwr-if"></div><div class="fw-err" id="fwr-if-err"></div></div>
      <div class="fw-field">${F.lab('Next hop', 'Next hop', '<p>The address of the router that leads to this network. It must be inside the network of the interface.</p><p>Leave it empty when the destination is directly on that link, as on a tunnel.</p>')}<input type="text" id="fwr-via" value="${F.E(r.via || '')}" placeholder="e.g. 192.168.2.254 — empty = directly on the link"><div class="fw-err" id="fwr-via-err"></div></div>
      <div class="fw-field">${F.lab('Metric', 'Metric', '<p>When two routes lead to the same destination, the lower number is used. Leave it at 0 unless you have a backup route.</p>')}<input type="number" min="0" max="65535" id="fwr-metric" value="${F.E(r.metric || 0)}"><div class="fw-err" id="fwr-metric-err"></div></div>
      <div class="fw-field"><label>Description (optional)</label><input type="text" id="fwr-desc" maxlength="80" value="${F.E(r.description || '')}"><div class="fw-err" id="fwr-desc-err"></div></div>
      ${cb('fwr-en', 'Enabled', r.enabled)}`;
    F.picker(box.querySelector('#fwr-if'), c.interfaces.map(i => ({ value: i.id, label: i.name, color: i.color, hint: i.disabled ? 'disabled' : (i.ipv4 || i.ipv4_mode) })), r.interface, v => { r.interface = v; }, { placeholder: 'Choose an interface…' });
    F.modal({ title: existing || adopt ? 'Edit local route' : 'New local route', body: box, width: 520, buttons: [
      { label: 'Cancel' },
      { label: existing || adopt ? 'Save' : 'Add', cls: 'btn-primary', onClick: async close => {
        const v = s => box.querySelector(s).value.trim();
        r.destination = v('#fwr-dst'); r.via = v('#fwr-via'); r.metric = Number(v('#fwr-metric')) || 0; r.description = v('#fwr-desc'); r.enabled = box.querySelector('#fwr-en').checked;
        const next = F.clone(c);
        next.routes = next.routes || [];
        const k = next.routes.findIndex(x => x.id === r.id);
        if (k >= 0) next.routes[k] = r; else next.routes.push(r);
        const at = k >= 0 ? k : next.routes.length - 1;
        if (showErrors(box, await F.validate(next), `routes[${at}]`, { destination: '#fwr-dst-err', interface: '#fwr-if-err', via: '#fwr-via-err', metric: '#fwr-metric-err', description: '#fwr-desc-err' }, '#fwr-dst-err')) return;
        close();
        F.saveDraft(n => { n.routes = next.routes; });
      } },
    ] });
  }

  function wireRoutes(root) {
    const add = root.querySelector('#fw-add-rt');
    if (add) add.onclick = () => editRoute(null);
    const byId = id => (F.cfg().routes || []).find(r => r.id === id);
    root.querySelectorAll('[data-rt-adopt]').forEach(b => b.onclick = () => editRoute(null, systemRouteById(b.dataset.rtAdopt)));
    root.querySelectorAll('[data-rt-edit]').forEach(b => b.onclick = () => editRoute(byId(b.dataset.rtEdit)));
    root.querySelectorAll('[data-rt-toggle]').forEach(b => b.onclick = () => F.saveDraft(n => { const r = n.routes.find(x => x.id === b.dataset.rtToggle); if (r) r.enabled = !r.enabled; }));
    root.querySelectorAll('[data-rt-del]').forEach(b => b.onclick = () => {
      const r = byId(b.dataset.rtDel);
      F.modal({ title: `Remove the route to ${r.destination}?`, body: '<p>When you apply, this server no longer knows that way to this network.</p>',
        buttons: [{ label: 'Cancel' }, { label: 'Remove', cls: 'btn-danger', onClick: close => { close(); F.saveDraft(n => { n.routes = n.routes.filter(x => x.id !== r.id); }); } }] });
    });
    const d = root.querySelector('#fw-live-routes');
    if (d) d.ontoggle = () => { routesOpen = d.open; };
  }

  function wireGateways(root) {
    wireRoutes(root);
    const add = root.querySelector('#fw-add-gw');
    if (add) add.onclick = () => editGateway(null);
    root.querySelectorAll('[data-edit]').forEach(b => b.onclick = () => editGateway(gwById(b.dataset.edit)));
    const move = (id, d) => F.saveDraft(n => {
      const l = n.gateways.slice().sort((a, b) => a.priority - b.priority);
      const k = l.findIndex(g => g.id === id);
      if (k + d < 0 || k + d >= l.length) return false;
      [l[k], l[k + d]] = [l[k + d], l[k]];
      l.forEach((g, j) => { g.priority = j + 1; });
      n.gateways = l;
    });
    root.querySelectorAll('[data-up]').forEach(b => b.onclick = () => move(b.dataset.up, -1));
    root.querySelectorAll('[data-down]').forEach(b => b.onclick = () => move(b.dataset.down, 1));
    root.querySelectorAll('[data-del]').forEach(b => b.onclick = () => {
      const g = gwById(b.dataset.del);
      const dd = (F.cfg().ddns || []).filter(e => e.gateway === g.id).length;
      F.modal({ title: `Remove ${g.name}?`, body: `<p>Traffic stops using this Internet link when you apply.</p>${dd ? `<p>Its ${dd} dynamic DNS entr${dd > 1 ? 'ies are' : 'y is'} removed with it.</p>` : ''}`,
        buttons: [{ label: 'Cancel' }, { label: 'Remove', cls: 'btn-danger', onClick: close => { close(); F.saveDraft(n => {
          n.gateways = n.gateways.filter(x => x.id !== g.id);
          n.ddns = (n.ddns || []).filter(e => e.gateway !== g.id); // its dynamic DNS names go with it
        }); } }] });
    });
  }

  async function editGateway(existing) {
    const c = F.cfg();
    const links = await F.liveLinks();
    const g = existing ? F.clone(existing) : { id: F.newId(), name: '', interface: '', address: '', priority: F.nextGwPriority(c), monitor: true };
    const box = document.createElement('div');
    box.innerHTML = `
      <div class="fw-field"><label>Interface</label><div id="fwg-if"></div><div class="fw-err" id="fwg-if-err"></div>
        <button class="fw-icon-btn" type="button" id="fwg-newppp" style="margin-top:8px">${F.icon('plus', 12)}New PPPoE link</button></div>
      <div class="fw-field"><label>Name</label><input type="text" id="fwg-name" value="${F.E(g.name)}" placeholder="e.g. Fibre — ISP 1"></div>
      <div class="fw-field"><label>Gateway address</label><input type="text" id="fwg-addr" value="${F.E(g.address || '')}" placeholder="empty = automatic (DHCP lease or PPPoE peer)"><div class="fw-err" id="fwg-addr-err"></div></div>
      <div class="fw-field">${F.lab('Priority', 'Priority', '<p>Traffic to the Internet uses the online gateway with the lowest number; 1 is tried first. A gateway already at this number moves down one.</p>')}<input type="number" min="1" id="fwg-prio" value="${F.E(g.priority)}"><div class="fw-err" id="fwg-prio-err"></div></div>
      <div class="fw-field"><label>Health checks</label>${cb('fwg-mon', 'Test this gateway with pings', g.monitor).replace('class="fw-cbx"', 'class="fw-cbx" style="text-transform:none;letter-spacing:0;font-size:13px;color:var(--text);display:flex;gap:8px;align-items:center"')}
        <div id="fwg-mon-f" style="margin-top:8px">
          <div id="fwg-warn"></div>
          <div class="fw-field"><label>Address to ping</label><div id="fwg-tgt"></div>
            <input type="text" id="fwg-mip" style="margin-top:6px" value="${F.E(g.monitor_ip || '')}" placeholder="Custom address, e.g. 9.9.9.9"><div class="fw-err" id="fwg-mon-err"></div>
            <div style="display:flex;gap:10px;align-items:center;margin-top:8px"><button class="fw-icon-btn" type="button" id="fwg-test" style="flex:none">Test</button><span id="fwg-test-r" style="font-size:12.5px;color:var(--text-2)"></span></div></div>
          <div class="fw-row2" style="grid-template-columns:repeat(2,1fr)">
            <div class="fw-field">${F.lab('Test every (seconds)', 'Test interval', '<p>How often a test runs, from 2 to 3600 seconds. Longer intervals notice a failure later and react less to short losses.</p>')}<input type="number" id="fwg-every" min="2" max="3600" value="${F.E(g.probe_every || (existing && existing.monitor ? 2 : 10))}"><div class="fw-err" id="fwg-every-err"></div></div>
            <div class="fw-field">${F.lab('Pings per test', 'Number of pings', '<p>How many pings each test sends, half a second apart, from 1 to 10. The test passes if any one is answered, so more pings ride out a lost packet.</p>')}<input type="number" id="fwg-pings" min="1" max="10" value="${F.E(g.probe_pings || (existing && existing.monitor ? 1 : 3))}"><div class="fw-err" id="fwg-pings-err"></div></div>
          </div>
          <div class="fw-row2" style="grid-template-columns:repeat(3,1fr)">
            <div class="fw-field"><label>Down at loss %</label><input type="number" id="fwg-loss" min="1" max="100" value="${F.E(g.loss_pct || '')}" placeholder="50"></div>
            <div class="fw-field"><label>or silent for (s)</label><input type="number" id="fwg-downs" min="2" value="${F.E(g.down_secs || '')}" placeholder="10"></div>
            <div class="fw-field"><label>Back after (s)</label><input type="number" id="fwg-hold" min="0" value="${F.E(g.hold_secs || '')}" placeholder="60"></div>
          </div>
          <div class="fw-note" id="fwg-sum"></div></div>
        <div class="fw-note" id="fwg-off-note" style="margin-top:8px"></div></div>`;
    // Any interface of the Firewall, and network ports not added to it yet
    // (saving adds them). A tunnel only when it was made a WAN.
    const portOf = dev => links.find(l => l.device === dev) || {};
    const known = new Set(c.interfaces.map(i => i.device));
    const ifOpts = [
      ...c.interfaces.filter(i => i.kind !== 'wireguard' || i.role === 'wan').map(i => ({ value: i.id, label: i.name, color: i.color,
        disabled: i.ipv4_mode === 'none' && i.id !== g.interface,
        hint: i.disabled ? 'disabled' : ({ pppoe: 'PPPoE', dhcp: 'DHCP', static: i.ipv4 }[i.ipv4_mode] || 'no address: set one on the Interfaces page') })),
      ...links.filter(l => l.adoptable && !known.has(l.device) && (l.kind === 'physical' || l.kind === 'bridge')).map(l => {
        const mode = l.cfg_mode && l.cfg_mode !== 'manual' ? l.cfg_mode : ((l.ipv4 || []).length ? 'static' : '');
        return { value: 'port:' + l.device, label: l.device, disabled: !mode, section: 'Not in the Firewall yet',
          hint: mode ? 'added to the Firewall as a WAN' : 'no address' };
      }),
    ];
    F.picker(box.querySelector('#fwg-if'), ifOpts, g.interface, v => {
      g.interface = v;
      setTimeout(() => { drawTgt(); sync(); });
      const nm = box.querySelector('#fwg-name'), addr = box.querySelector('#fwg-addr');
      const i = ifaceById(v), dev = v.startsWith('port:') ? v.slice(5) : (i && i.device);
      if (!nm.value) nm.value = (i && i.name) || dev || '';
      if (!addr.value && !existing) addr.value = (i && i.gateway) || portOf(dev).cfg_gateway || '';
    }, { placeholder: 'Choose an interface…' });
    // Default gateway, or an address of the admin's choice.
    let tgtMode = g.monitor && g.monitor_ip ? 'custom' : 'gateway';
    const liveIP = () => { const L = liveGw(g.id) || {}; return L.gateway_ip || ''; };
    const isPPP = () => { const i = ifaceById(g.interface); return !!i && i.kind === 'pppoe'; };
    const num = (s, d) => Number(box.querySelector(s).value) || d;
    const drawTgt = () => {
      const ip = box.querySelector('#fwg-addr').value.trim() || liveIP();
      F.picker(box.querySelector('#fwg-tgt'), [
        { value: 'gateway', label: 'Default gateway IP', hint: ip || (isPPP() ? "the provider's end of the link" : 'found automatically') },
        { value: 'custom', label: 'Custom address', hint: 'type it below' },
      ], tgtMode, v => { tgtMode = v; sync(); });
    };
    // Save stays off while the test is on until this exact address has answered.
    let testKey = '', testOK = false, testSeq = 0, testTimer = 0, dlg = null;
    const testInput = () => ({ interface: g.interface || '', address: box.querySelector('#fwg-addr').value.trim(),
      target: tgtMode === 'custom' ? box.querySelector('#fwg-mip').value.trim() : '' });
    const paintSave = () => {
      const b = dlg && dlg.foot.querySelector('#fwg-save');
      if (!b) return;
      const blocked = box.querySelector('#fwg-mon').checked && !testOK;
      b.disabled = blocked;
      b.title = blocked ? 'Saving needs a successful ping test, or turn off the test' : '';
    };
    const testMsg = (html, color) => { const r = box.querySelector('#fwg-test-r'); r.innerHTML = html; r.style.color = color || 'var(--text-2)'; };
    const runTest = async () => {
      const inp = testInput(), seq = ++testSeq;
      clearTimeout(testTimer);
      testOK = false; paintSave();
      if (!inp.interface) return testMsg('Choose an interface to test.');
      if (tgtMode === 'custom' && !/^\d{1,3}(\.\d{1,3}){3}$/.test(inp.target)) return testMsg('Type the address to test.');
      testMsg('Testing…');
      const r = await F.api('POST', '/api/sdn/gateways/test', Object.assign({ pings: Math.min(num('#fwg-pings', 1), 10) }, inp));
      if (seq !== testSeq) return;
      const d = r.data || {};
      testOK = !!(r.ok && d.ok);
      if (testOK) testMsg(`${F.icon('check', 12)} <span class="fw-mono">${F.E(d.target)}</span> answered${d.rtt_ms ? ' in ' + F.E(d.rtt_ms.toFixed(1)) + ' ms' : ''}.`, 'var(--fw-ok, #30d158)');
      else testMsg(`${F.E(d.error || 'The test could not run.')} You can save once it passes, or with the test turned off.`, 'var(--accent-warn)');
      paintSave();
    };
    // Tested again whenever what it tests changes.
    const refreshTest = () => {
      paintSave();
      if (!box.querySelector('#fwg-mon').checked) { testSeq++; clearTimeout(testTimer); return; }
      const key = JSON.stringify([tgtMode, testInput()]);
      if (key === testKey) return;
      testKey = key; testOK = false; testSeq++; paintSave();
      clearTimeout(testTimer);
      testMsg('Testing…');
      testTimer = setTimeout(runTest, 500);
    };
    box.querySelector('#fwg-test').onclick = () => { testKey = JSON.stringify([tgtMode, testInput()]); runTest(); };
    const sync = () => {
      const on = box.querySelector('#fwg-mon').checked, ppp = isPPP();
      box.querySelector('#fwg-mon-f').style.display = on ? '' : 'none';
      box.querySelector('#fwg-mip').style.display = tgtMode === 'custom' ? '' : 'none';
      const every = num('#fwg-every', 2), pings = num('#fwg-pings', 1), silent = Math.max(num('#fwg-downs', 10), every); const loss = num('#fwg-loss', 50);
      const tgt = tgtMode === 'custom' ? (box.querySelector('#fwg-mip').value.trim() || 'the custom address') : (box.querySelector('#fwg-addr').value.trim() || liveIP() || 'the default gateway IP');
      const result = ppp ? 'ZNAS hangs up this PPPoE link and dials it again' : 'traffic moves to the next gateway';
      box.querySelector('#fwg-warn').innerHTML = ppp ? `<div class="fw-safemode" style="background:rgba(255,214,10,.10);border-color:rgba(255,214,10,.4);margin-bottom:10px">${F.icon('alert-triangle', 16)}<div><b style="color:var(--accent-warn)">Failed pings disconnect your Internet.</b> When the tests fail, this PPPoE link is hung up and dialled again. Everyone on the network loses the Internet during the redial, usually under 30 seconds. Open connections drop, and your provider may give you a new public address.<br><br>A failed ping does not always mean a broken link: a server on the Internet like 1.1.1.1 can stop answering while your link is fine, and you would get a reconnect for nothing. Your provider's <b style="color:var(--text)">default gateway IP</b> is the closest address, so it is usually the better test. Some providers don't answer pings: if the address has never answered, ZNAS does not reconnect and tells you on the gateway card.</div></div>` : '';
      box.querySelector('#fwg-sum').innerHTML = `<b>With these settings:</b> every ${every} s, ${pings} ping${pings > 1 ? 's' : ''} to <span class="fw-mono">${F.E(tgt)}</span>. A test fails when ${pings > 1 ? 'none of them is' : 'it is not'} answered. The gateway counts as down after ${silent} s with no answer, which takes at least two failed tests in a row, or when ${loss} % of the last 5 tests failed. Then ${result}.${ppp ? ' If that does not help, it waits 1 minute before trying again, then twice as long each time, up to 30 minutes.' : ''}`;
      const off = box.querySelector('#fwg-off-note');
      off.style.display = !on ? '' : 'none';
      refreshTest();
      off.textContent = ppp ? 'Not tested: this gateway is always considered up. The PPPoE link still reconnects by itself if the provider stops answering at link level (no reply for about 30 seconds).' : 'Not tested: this gateway is always considered up, and traffic never moves away from it.';
    };
    box.querySelector('#fwg-mon').onchange = () => { testKey = ''; sync(); };
    ['#fwg-every', '#fwg-pings', '#fwg-downs', '#fwg-mip', '#fwg-addr'].forEach(s => { box.querySelector(s).oninput = sync; });
    drawTgt(); sync();
    dlg = F.modal({ title: existing ? `Edit ${existing.name}` : 'New gateway', body: box, width: 560, buttons: [
      { label: 'Cancel' },
      { label: existing ? 'Save' : 'Add', id: 'fwg-save', cls: 'btn-primary', onClick: async close => {
        if (box.querySelector('#fwg-mon').checked && !testOK) return;
        const v = s => box.querySelector(s).value.trim();
        g.name = v('#fwg-name') || ((ifaceById(g.interface) || {}).name || 'Gateway');
        g.address = v('#fwg-addr'); g.monitor = box.querySelector('#fwg-mon').checked; g.monitor_ip = tgtMode === 'custom' ? v('#fwg-mip') : '';
        g.probe_every = Number(v('#fwg-every')) || 0; g.probe_pings = Number(v('#fwg-pings')) || 0;
        if (g.monitor && tgtMode === 'custom' && !g.monitor_ip) { box.querySelector('#fwg-mon-err').textContent = 'Type the address to ping'; return; }
        g.loss_pct = Number(v('#fwg-loss')) || 0; g.down_secs = Number(v('#fwg-downs')) || 0; g.hold_secs = Number(v('#fwg-hold')) || 0;
        if (!g.interface) { box.querySelector('#fwg-if-err').textContent = 'Choose the interface of this Internet link'; return; }
        const prio = Number(v('#fwg-prio'));
        if (!(prio >= 1)) { box.querySelector('#fwg-prio-err').textContent = 'The priority is a number from 1'; return; }
        const next = F.clone(c);
        if (g.interface.startsWith('port:')) {
          const dev = g.interface.slice(5), L = portOf(dev), id = F.newId();
          const mode = L.cfg_mode && L.cfg_mode !== 'manual' ? L.cfg_mode : 'static';
          next.interfaces.push({ id, name: dev, color: F.PALETTE[next.interfaces.length % F.PALETTE.length], kind: L.incus ? 'incus' : (L.kind === 'bridge' ? 'bridge' : 'physical'), incus_keep: !!L.incus_keep, device: dev, role: 'wan',
            ipv4_mode: mode, ipv4: mode === 'static' ? (L.cfg_address || (L.ipv4 || [])[0] || '') : '', gateway: mode === 'static' ? (L.cfg_gateway || '') : '', mtu: 0, allow_vms: false, owned: false });
          g.interface = id;
        }
        const k = next.gateways.findIndex(x => x.id === g.id);
        if (k >= 0) next.gateways[k] = g; else next.gateways.push(g);
        F.setGwPriority(next.gateways, g, prio);
        const at = k >= 0 ? k : next.gateways.length - 1;
        if (showErrors(box, await F.validate(next), `gateways[${at}]`, { interface: '#fwg-if-err', address: '#fwg-addr-err', priority: '#fwg-prio-err', monitor_ip: '#fwg-mon-err', probe_every: '#fwg-every-err', probe_pings: '#fwg-pings-err', loss_pct: '#fwg-mon-err', down_secs: '#fwg-mon-err', hold_secs: '#fwg-mon-err' }, '#fwg-addr-err')) return;
        close();
        F.saveDraft(n => { n.gateways = next.gateways; n.interfaces = next.interfaces; });
      } },
    ] });
    paintSave();
    box.querySelector('#fwg-newppp').onclick = () => { dlg.close(); F.editInterface(null, 'pppoe'); };
  }

  // ── NAT ────────────────────────────────────────────────────────────────
  function fwdState(f) {
    if (!f.enabled) return ['off', 'Off'];
    if (!(f.interfaces || []).length) return ['paused', f.instance ? 'Paused — choose an interface in the instance editor' : 'Paused — no interface'];
    if (!f.target) return ['wait', 'Waiting for the instance address'];
    return ['on', ''];
  }

  function natHTML() {
    const c = F.cfg(), admin = F.isAdmin();
    const tabs = [['forwards', 'Port forwards', c.port_forwards.length], ['outbound', 'Outbound NAT', c.snat_rules.length]];
    const head = `<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
      <div class="fw-tabs">${tabs.map(t => `<button class="fw-tab${t[0] === natTab ? ' on' : ''}" data-ntab="${t[0]}">${F.E(t[1])}<span class="fw-n">${t[2]}</span></button>`).join('')}</div>
      <span style="flex:1"></span>
      ${admin ? (natTab === 'forwards'
        ? `<button class="fw-btn fw-apply" id="fw-new-pf" style="font-weight:600">${F.icon('plus', 13)}New port forward</button>`
        : `<button class="fw-btn fw-apply" id="fw-new-sn" style="font-weight:600" ${c.settings.outbound_nat === 'automatic' || !c.settings.outbound_nat ? 'disabled title="Switch to Hybrid or Manual to add your own rules"' : ''}>${F.icon('plus', 13)}New outbound rule</button>`) : ''}
    </div>`;
    return head + (natTab === 'forwards' ? forwardsHTML(c) : outboundHTML(c));
  }

  function forwardsHTML(c) {
    if (!c.port_forwards.length) return `<div class="fw-rules"><div class="fw-empty">No port forward yet. Forwards of VMs and containers appear here too — publish them from the instance editor.</div></div>`;
    const mode = c.settings.mode || 'monitor';
    return `${mode !== 'router' ? `<div class="fw-note" style="margin:10px 0">Port forwards work in Monitor mode too: they translate, nothing else is filtered.</div>` : ''}
      <div class="fw-rules">${c.port_forwards.map((f, idx) => {
        const [st, why] = fwdState(f);
        const ifs = (f.interfaces || []).map(ifacePill).join(' ');
        return `<div class="fw-nat-row${st === 'on' ? '' : ' fw-dim'}" data-pf="${idx}" title="${F.E(why)}">
          <span class="fw-toggle${f.enabled ? ' on' : ''}" ${f.instance ? '' : `data-pftoggle="${idx}"`}></span>
          <span class="fw-proto">${F.E(PROTO[f.protocol] || f.protocol)}</span>
          <span class="fw-flow">${ifs || '<span class="fw-badge none">no interface</span>'}<span class="fw-port">: ${F.E(f.pub_ports)}</span>
            ${f.source && f.source.type !== 'any' ? `<span class="fw-note">from ${F.E(F.epLabel(f.source))}</span>` : ''}
            <span class="fw-arrow">→</span>
            <span class="fw-pillx fw-mono">${f.target ? F.E(f.target) : '…'}:${F.E(f.target_ports)}</span>
            ${f.reflection ? `<span class="fw-badge none" title="Inside clients can use the public address too">reflection</span>` : ''}</span>
          <span class="fw-desc">${f.instance ? `<span class="fw-badge lan">${F.icon('server', 11)}${F.E(f.instance)} · ${F.E(f.nic)}</span>` : F.E(f.description)}</span>
          <span class="fw-pfst ${st}">${st === 'on' ? '' : F.E({ off: 'off', paused: 'paused', wait: 'waiting' }[st])}</span>
          ${F.rowActs('pf', idx, !!f.instance)}
        </div>`;
      }).join('')}</div>`;
  }

  function outboundHTML(c) {
    const mode = c.settings.outbound_nat || 'automatic';
    const lans = c.interfaces.filter(i => i.role !== 'wan' && i.ipv4_mode === 'static');
    const wans = c.interfaces.filter(i => i.role === 'wan');
    const desc = { automatic: 'Every inside network is translated to the address of the WAN interface it leaves through. Right for almost everyone.',
      hybrid: 'Your rules below come first; whatever they do not match is translated automatically.',
      manual: 'Only your rules below translate. Anything they do not match leaves with its inside address (usually unreachable).' }[mode];
    const auto = mode !== 'manual' ? `<div class="fw-card" style="margin-top:12px"><b>Automatic rules</b>
      <div class="fw-note" style="margin-top:4px">${lans.length && wans.length ? lans.map(l => `<div>${ifacePill(l.id)} <span class="fw-mono">${F.E(l.ipv4)}</span> → ${wans.map(w => ifacePill(w.id)).join(' or ')} address</div>`).join('') : 'Nothing to translate yet (needs a WAN interface and an inside network with a static address).'}</div></div>` : '';
    const rows = c.snat_rules.map((r, idx) => {
      const g = r.gateway ? gwById(r.gateway) : null;
      const tr = { iface: 'interface address', ip: r.translate_ip, none: 'no translation' }[r.translate] || r.translate;
      return `<div class="fw-nat-row${r.enabled ? '' : ' fw-dim'}" data-sn="${idx}">
        <span class="fw-toggle${r.enabled ? ' on' : ''}" data-sntoggle="${idx}"></span>
        <span class="fw-proto">${F.E(PROTO[r.protocol] || r.protocol)}</span>
        <span class="fw-flow"><span class="fw-pillx">${F.E(F.epLabel(r.source))}</span><span class="fw-arrow">→</span><span class="fw-pillx">${F.E(F.epLabel(r.destination))}</span>${r.dst_ports ? `<span class="fw-port">: ${F.E(r.dst_ports)}</span>` : ''}
          <span class="fw-note">via <b>${F.E(g ? g.name : (r.gateway ? '(deleted gateway)' : 'normal routing'))}</b>${r.only_this_gateway ? ' only' : ''} as ${F.E(tr)}</span></span>
        <span class="fw-desc">${F.E(r.description)}</span><span></span>${F.rowActs('sn', idx)}</div>`;
    }).join('');
    return `<div class="fw-card" style="flex-direction:row;align-items:center;gap:14px;flex-wrap:wrap;margin-top:12px">
        <div style="flex:1;min-width:240px"><b>Mode</b><div class="fw-note" style="margin-top:3px">${F.E(desc)}</div></div><div id="fw-onat-seg"></div></div>
      ${mode !== 'automatic' ? `<div class="fw-rules" style="margin-top:12px">${rows || '<div class="fw-empty">No outbound rule yet.</div>'}</div>` : ''}
      ${auto}`;
  }

  function wireNAT(root) {
    root.querySelectorAll('[data-ntab]').forEach(b => b.onclick = () => { natTab = b.dataset.ntab; F.rerender(); });
    const seg = root.querySelector('#fw-onat-seg');
    if (seg) {
      if (F.isAdmin()) F.seg(seg, [['automatic', 'Automatic'], ['hybrid', 'Hybrid'], ['manual', 'Manual']], F.cfg().settings.outbound_nat || 'automatic',
        v => F.saveDraft(n => { n.settings.outbound_nat = v; }));
      else seg.innerHTML = `<span class="fw-badge none">${F.E(F.cfg().settings.outbound_nat || 'automatic')}</span>`;
    }
    const npf = root.querySelector('#fw-new-pf');
    if (npf) npf.onclick = () => editForward(null);
    const nsn = root.querySelector('#fw-new-sn');
    if (nsn) nsn.onclick = () => editSNAT(null);
    root.querySelectorAll('[data-pftoggle]').forEach(t => t.onclick = e => {
      e.stopPropagation(); if (!F.isAdmin()) return;
      const i = Number(t.dataset.pftoggle);
      F.saveDraft(n => { n.port_forwards[i].enabled = !n.port_forwards[i].enabled; });
    });
    root.querySelectorAll('[data-sntoggle]').forEach(t => t.onclick = e => {
      e.stopPropagation(); if (!F.isAdmin()) return;
      const i = Number(t.dataset.sntoggle);
      F.saveDraft(n => { n.snat_rules[i].enabled = !n.snat_rules[i].enabled; });
    });
    const act = (sel, fn) => root.querySelectorAll(sel).forEach(b => b.onclick = e => { e.stopPropagation(); fn(Number(Object.values(b.dataset)[0])); });
    act('[data-pfedit]', i => { const f = F.cfg().port_forwards[i]; if (f.instance) instanceForwardInfo(f); else editForward(i); });
    act('[data-pfclone]', i => editForward(null, i));
    act('[data-snedit]', i => editSNAT(i));
    act('[data-snclone]', i => editSNAT(null, i));
    root.querySelectorAll('[data-pf]').forEach(r => r.onclick = () => {
      const f = F.cfg().port_forwards[Number(r.dataset.pf)];
      if (f.instance) instanceForwardInfo(f); else if (F.isAdmin()) editForward(Number(r.dataset.pf));
    });
    root.querySelectorAll('[data-sn]').forEach(r => r.onclick = () => F.isAdmin() && editSNAT(Number(r.dataset.sn)));
  }

  function instanceForwardInfo(f) {
    const [st, why] = fwdState(f);
    F.modal({ title: `Port forward of ${f.instance}`, width: 520, body: `
      <p>This forward belongs to the instance <b>${F.E(f.instance)}</b> (network card <span class="fw-mono">${F.E(f.nic)}</span>). Change it — ports, interfaces, address — in its editor under VMs &amp; Containers.</p>
      <div class="fw-kv"><span>Public</span><span>${(f.interfaces || []).map(ifacePill).join(' ') || 'no interface'} : ${F.E(f.pub_ports)} ${F.E(PROTO[f.protocol] || f.protocol)}</span>
        <span>Inside</span><span class="fw-mono">${F.E(f.target || 'not known yet')}:${F.E(f.target_ports)}${f.target_auto ? ' <span class="fw-note">(follows the instance address)</span>' : ''}</span>
        <span>State</span><span>${st === 'on' ? 'Active' : F.E(why || st)}</span></div>`,
      buttons: [{ label: 'Close' }, ...(typeof window.openLXDEditModal === 'function' && F.isAdmin() ? [{ label: 'Open the instance editor', cls: 'btn-primary', onClick: close => {
        close();
        if (typeof window.switchSidebarMode === 'function') window.switchSidebarMode('compute');
        window.openLXDEditModal(f.instance);
      } }] : [])] });
  }

  // from: index of a forward to clone (new forward prefilled from it, placed right below).
  function editForward(idx, from) {
    const c = F.cfg();
    const cloned = idx == null && from != null && c.port_forwards[from];
    const f = cloned ? Object.assign(F.clone(c.port_forwards[from]), { id: F.newId(), description: F.cloneDesc(c.port_forwards[from].description) }) : idx == null ? { id: F.newId(), enabled: true, interfaces: c.interfaces.filter(i => i.role === 'wan').slice(0, 1).map(i => i.id), protocol: 'tcp',
      pub_ports: '', source: { type: 'any' }, target: '', target_ports: '', reflection: false, description: '' } : F.clone(c.port_forwards[idx]);
    const sentence = () => {
      const on = (f.interfaces || []).map(id => (ifaceById(id) || {}).name || '?').join(', ') || 'no interface';
      return `Connections to <b>${F.E(on)}</b> port <b>${F.E(f.pub_ports || '…')}</b> (${F.E(PROTO[f.protocol])})${f.source.type !== 'any' ? ` from <b>${F.E(F.epLabel(f.source))}</b>` : ''} go to <b>${F.E(f.target || '…')}:${F.E(f.target_ports || f.pub_ports || '…')}</b>.`;
    };
    const d = drawer(cloned ? 'New port forward (clone)' : (idx == null ? 'New port forward' : 'Edit port forward'), '', `
      <div class="fw-field"><label>Published on</label><div class="fw-chips" id="fwp-if"></div><div class="fw-err" id="fwp-if-err"></div></div>
      <div class="fw-field"><label>Protocol</label><div id="fwp-proto"></div></div>
      <div class="fw-row2"><div class="fw-field"><label>Public port(s)</label><input type="text" id="fwp-pub" value="${F.E(f.pub_ports)}" placeholder="443 or 16261-16263"><div class="fw-err" id="fwp-pub-err"></div></div>
        <div class="fw-field"><label>Inside port(s)</label><input type="text" id="fwp-tp" value="${F.E(f.target_ports)}" placeholder="same as public"><div class="fw-err" id="fwp-tp-err"></div></div></div>
      <div class="fw-field"><label>Inside address</label><input type="text" id="fwp-tgt" value="${F.E(f.target)}" placeholder="10.128.8.20"><div id="fwp-tgt-pick" style="margin-top:6px"></div><div class="fw-err" id="fwp-tgt-err"></div></div>
      <div class="fw-field"><label>Allowed from</label><div id="fwp-src"></div><div class="fw-err" id="fwp-src-err"></div></div>
      <div class="fw-field"><label>Description</label><input type="text" id="fwp-desc" value="${F.E(f.description)}" placeholder="e.g. Web server"></div>
      ${cb('fwp-refl', 'Reflection — inside devices can use the public address too', f.reflection)}
      ${cb('fwp-en', 'Enabled', f.enabled)}`,
      `${idx != null ? `<button class="btn btn-ghost" id="fwp-del" style="margin-right:auto;color:var(--fw-blk)">Delete</button>` : ''}<button class="btn btn-ghost" id="fwp-cancel">Cancel</button><button class="btn btn-primary" id="fwp-save">${idx == null ? 'Add' : 'Save'}</button>`);
    const { q } = d;
    const upd = () => {
      f.pub_ports = q('#fwp-pub').value.replace(/\s+/g, ''); f.target = q('#fwp-tgt').value.trim();
      f.target_ports = q('#fwp-tp').value.replace(/\s+/g, '') || f.pub_ports;
      f.description = q('#fwp-desc').value; f.reflection = q('#fwp-refl').checked; f.enabled = q('#fwp-en').checked;
      d.dr.querySelector('[data-sent]').innerHTML = sentence();
    };
    ifaceChips(q('#fwp-if'), f.interfaces || [], v => { f.interfaces = v; upd(); });
    // Known devices: DHCP reservations and current leases (DHCP & DNS page).
    F.api('GET', '/api/sdn/dhcp/leases').then(r => {
      const seen = new Set(), opts = [];
      F.cfg().dhcp.forEach(dh => (dh.reservations || []).forEach(rv => { if (!seen.has(rv.ip)) { seen.add(rv.ip); opts.push({ value: rv.ip, label: (rv.hostname || rv.mac) + '  ' + rv.ip, section: 'Reserved', hint: rv.mac }); } }));
      ((r.ok && r.data) || []).forEach(l => { if (!seen.has(l.ip)) { seen.add(l.ip); opts.push({ value: l.ip, label: (l.hostname || l.mac) + '  ' + l.ip, section: 'DHCP leases', hint: l.mac }); } });
      const el = q('#fwp-tgt-pick');
      if (!opts.length || !el) return;
      F.picker(el, opts, '', v => { q('#fwp-tgt').value = v; upd(); }, { placeholder: 'or pick a device on your networks…', search: true });
    });
    F.seg(q('#fwp-proto'), [['tcp', 'TCP'], ['udp', 'UDP'], ['tcpudp', 'TCP+UDP']], f.protocol, v => { f.protocol = v; upd(); });
    endpointEditor(q('#fwp-src'), f.source, false, ep => { f.source = ep; upd(); });
    d.dr.querySelectorAll('input').forEach(i => i.addEventListener('input', upd));
    d.dr.querySelectorAll('input[type=checkbox]').forEach(i => i.addEventListener('change', upd));
    upd();
    q('#fwp-cancel').onclick = d.close;
    if (idx != null) q('#fwp-del').onclick = () => { d.close(); F.saveDraft(n => { n.port_forwards.splice(idx, 1); }); };
    q('#fwp-save').onclick = async () => {
      upd();
      if (!f.interfaces.length) { q('#fwp-if-err').textContent = 'Choose at least one interface'; return; }
      const next = F.clone(F.cfg());
      const at = idx == null ? (cloned ? from + 1 : next.port_forwards.length) : idx;
      if (idx == null) next.port_forwards.splice(at, 0, f); else next.port_forwards[at] = f;
      if (showErrors(d.dr, await F.validate(next), `port_forwards[${at}]`, { interfaces: '#fwp-if-err', pub_ports: '#fwp-pub-err', target: '#fwp-tgt-err', target_ports: '#fwp-tp-err', source: '#fwp-src-err', protocol: '#fwp-pub-err' }, '[data-err]')) return;
      d.close();
      F.saveDraft(n => { n.port_forwards = next.port_forwards; });
    };
  }

  function editSNAT(idx, from) {
    const c = F.cfg(), gws = sortedGws();
    const cloned = idx == null && from != null && c.snat_rules[from];
    const r = cloned ? Object.assign(F.clone(c.snat_rules[from]), { id: F.newId(), description: F.cloneDesc(c.snat_rules[from].description) }) : idx == null ? { id: F.newId(), enabled: true, source: { type: 'any' }, destination: { type: 'any' }, protocol: 'any', dst_ports: '',
      gateway: gws.length === 1 ? gws[0].id : '', only_this_gateway: false, translate: 'iface', translate_ip: '', description: '' } : F.clone(c.snat_rules[idx]);
    const sentence = () => {
      const g = r.gateway ? gwById(r.gateway) : null;
      const tr = { iface: 'the address of its interface', ip: r.translate_ip || '…', none: 'its own address (no translation)' }[r.translate];
      return `Traffic from <b>${F.E(F.epLabel(r.source))}</b> to <b>${F.E(F.epLabel(r.destination))}</b>${r.dst_ports ? ` port <b>${F.E(r.dst_ports)}</b>` : ''} leaves through <b>${F.E(g ? g.name : 'normal routing')}</b>${r.only_this_gateway ? ' only' : ''} as <b>${F.E(tr)}</b>.`;
    };
    const d = drawer(cloned ? 'New outbound rule (clone)' : (idx == null ? 'New outbound rule' : 'Edit outbound rule'), '', `
      <div class="fw-field"><label>From (inside)</label><div id="fws-src"></div><div class="fw-err" id="fws-src-err"></div></div>
      <div class="fw-field"><label>To</label><div id="fws-dst"></div><div class="fw-err" id="fws-dst-err"></div></div>
      <div class="fw-field"><label>Protocol</label><div id="fws-proto"></div></div>
      <div class="fw-field" id="fws-ports-f"><label>Destination port(s)</label><input type="text" id="fws-ports" value="${F.E(r.dst_ports || '')}" placeholder="empty = all"></div>
      <div class="fw-field"><label>Outgoing gateway</label><div id="fws-gw"></div>${cb('fws-only', 'Only this gateway — block instead of failing over when it is down', r.only_this_gateway)}<div class="fw-err" id="fws-gw-err"></div></div>
      <div class="fw-field"><label>Translate to</label><div id="fws-tr"></div><input type="text" id="fws-tip" value="${F.E(r.translate_ip || '')}" placeholder="203.0.113.10" style="margin-top:6px"><div class="fw-err" id="fws-tip-err"></div></div>
      <div class="fw-field"><label>Description</label><input type="text" id="fws-desc" value="${F.E(r.description)}" placeholder="e.g. Mail server out of ISP 2"></div>
      ${cb('fws-en', 'Enabled', r.enabled)}`,
      `${idx != null ? `<button class="btn btn-ghost" id="fws-del" style="margin-right:auto;color:var(--fw-blk)">Delete</button>` : ''}<button class="btn btn-ghost" id="fws-cancel">Cancel</button><button class="btn btn-primary" id="fws-save">${idx == null ? 'Add' : 'Save'}</button>`);
    const { q } = d;
    const upd = () => {
      r.dst_ports = ['tcp', 'udp', 'tcpudp'].includes(r.protocol) ? q('#fws-ports').value.replace(/\s+/g, '') : '';
      r.translate_ip = r.translate === 'ip' ? q('#fws-tip').value.trim() : '';
      r.only_this_gateway = !!r.gateway && q('#fws-only').checked;
      r.description = q('#fws-desc').value; r.enabled = q('#fws-en').checked;
      q('#fws-ports-f').style.display = ['tcp', 'udp', 'tcpudp'].includes(r.protocol) ? '' : 'none';
      q('#fws-tip').style.display = r.translate === 'ip' ? '' : 'none';
      q('#fws-only').parentElement.style.display = r.gateway ? '' : 'none';
      d.dr.querySelector('[data-sent]').innerHTML = sentence();
    };
    endpointEditor(q('#fws-src'), r.source, false, ep => { r.source = ep; upd(); });
    endpointEditor(q('#fws-dst'), r.destination, true, ep => { r.destination = ep; upd(); });
    F.seg(q('#fws-proto'), [['any', 'Any'], ['tcp', 'TCP'], ['udp', 'UDP'], ['tcpudp', 'TCP+UDP'], ['icmp', 'ICMP']], r.protocol, v => { r.protocol = v; upd(); });
    F.picker(q('#fws-gw'), [...(gws.length > 1 ? [] : [{ value: '', label: 'Normal routing' }]), ...gws.map(g => ({ value: g.id, label: g.name, hint: 'priority ' + g.priority }))],
      r.gateway, v => { r.gateway = v; upd(); }, { placeholder: 'Choose the gateway…' });
    F.seg(q('#fws-tr'), [['iface', 'Interface address'], ['ip', 'Another address'], ['none', 'No translation']], r.translate, v => { r.translate = v; upd(); });
    d.dr.querySelectorAll('input').forEach(i => i.addEventListener('input', upd));
    d.dr.querySelectorAll('input[type=checkbox]').forEach(i => i.addEventListener('change', upd));
    upd();
    q('#fws-cancel').onclick = d.close;
    if (idx != null) q('#fws-del').onclick = () => { d.close(); F.saveDraft(n => { n.snat_rules.splice(idx, 1); }); };
    q('#fws-save').onclick = async () => {
      upd();
      const next = F.clone(F.cfg());
      const at = idx == null ? (cloned ? from + 1 : next.snat_rules.length) : idx;
      if (idx == null) next.snat_rules.splice(at, 0, r); else next.snat_rules[at] = r;
      if (showErrors(d.dr, await F.validate(next), `snat_rules[${at}]`, { source: '#fws-src-err', destination: '#fws-dst-err', gateway: '#fws-gw-err', translate_ip: '#fws-tip-err', translate: '#fws-tip-err' }, '[data-err]')) return;
      d.close();
      F.saveDraft(n => { n.snat_rules = next.snat_rules; });
    };
  }

  function register() {
    if (typeof window.sdnRegisterPage !== 'function' || !window.sdnFW) { setTimeout(register, 200); return; }
    F = window.sdnFW;
    // Shared with sdn-services.js.
    Object.assign(F, { drawer, showErrors, ifaceChips, endpointEditor, cb });
    window.sdnRegisterPage('fw-gateways', {
      load: async () => { await Promise.all([loadGw(), loadRoutes()]); },
      // Gateway state moves by the second; routes only move on an Apply or a
      // failover, so on slow links they are read every fifth tick (15 s).
      render: gatewaysHTML, wire: wireGateways, pollMs: 3000, poll: async () => { await Promise.all([loadGw(), ++gwTicks % 5 ? null : loadRoutes()]); },
    });
    window.sdnRegisterPage('fw-nat', {
      load: async () => { await F.loadCountries(); },
      render: natHTML, wire: wireNAT,
    });
  }
  register();
})();
