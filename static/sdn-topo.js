/*
 * Firewall → Monitor → Local Topo: one dense page about the networks this
 * Firewall manages. Uplinks → the Firewall → a trunk → each network → its
 * hosts, grouped by the bridge port they were seen on. Data: GET /api/sdn/topology.
 * Addresses carry .fw-ipi, so the inside address card opens on them.
 */
(function () {
  'use strict';
  let F = null, T = null, failed = '', q = '', view = 'all', ro = null;
  const E = s => F.E(s);
  const icon = (n, s) => F.icon(n, s || 13);

  const fmtRate = n => {
    n = +n || 0;
    if (n < 1000) return n ? Math.round(n) + ' b/s' : '0';
    const u = ['kb/s', 'Mb/s', 'Gb/s']; let i = -1;
    while (n >= 1000 && i < 2) { n /= 1000; i++; }
    return (n < 100 ? n.toFixed(1) : Math.round(n)) + ' ' + u[i];
  };
  const fmtBytes = n => {
    n = +n || 0;
    const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
    while (n >= 1000 && i < 4) { n /= 1000; i++; }
    return (i && n < 100 ? n.toFixed(1) : Math.round(n)) + ' ' + u[i];
  };
  const fmtSpeed = m => (!m || m < 0 ? '' : m >= 1000 ? (m / 1000).toString().replace(/\.0$/, '') + ' Gb/s' : m + ' Mb/s');
  const until = t => {
    const s = Math.round((new Date(t).getTime() - Date.now()) / 1000);
    if (!isFinite(s) || new Date(t).getFullYear() < 2000) return '';
    if (s <= 0) return 'expired';
    return s < 3600 ? Math.max(1, Math.round(s / 60)) + ' min' : s < 86400 ? Math.round(s / 3600) + ' h' : Math.round(s / 86400) + ' d';
  };
  const ago = t => {
    const s = Math.round((Date.now() - new Date(t).getTime()) / 1000);
    if (!isFinite(s) || new Date(t).getFullYear() < 2000) return 'never';
    return s < 60 ? s + ' s ago' : s < 3600 ? Math.round(s / 60) + ' min ago' : s < 86400 ? Math.round(s / 3600) + ' h ago' : Math.round(s / 86400) + ' d ago';
  };

  const KIND = {
    'this-server': ['shield', 'This ZNAS server'], vip: ['link', 'Virtual IP on this server'], router: ['network', 'Router'],
    vm: ['server', 'Virtual machine'], container: ['box', 'Container'], vpn: ['lock', 'VPN client'], device: ['monitor', 'Device'],
  };
  const STATUS = { online: 'Online', idle: 'Idle', offline: 'Offline', unknown: 'No recent contact' };
  const ADDR = { reserved: 'Reserved DHCP address', lease: 'DHCP lease', incus: 'Incus DHCP', static: 'Fixed address, not from DHCP', vpn: 'VPN tunnel address', self: 'Address of this server' };

  const isInst = h => h.kind === 'vm' || h.kind === 'container';
  function viewMatch(h) {
    switch (view) {
      case 'online': return h.status === 'online' || h.status === 'idle';
      case 'inst': return isInst(h);
      case 'dhcp': return h.addressing === 'lease' || h.addressing === 'reserved' || h.addressing === 'incus';
      case 'alert': return h.ids_alerts > 0;
    }
    return true;
  }
  const searchText = h => [h.name, h.ip, h.mac, h.vendor, h.port, h.note, h.os, KIND[h.kind] && KIND[h.kind][1]].filter(Boolean).join(' ').toLowerCase();

  function hostTitle(h) {
    const L = [(KIND[h.kind] || KIND.device)[1] + ' · ' + STATUS[h.status], ADDR[h.addressing]];
    if (h.expires && h.addressing === 'lease') { const u = until(h.expires); if (u) L.push('Lease ends in ' + u); }
    if (h.mac) L.push('MAC ' + h.mac + (h.mac_private ? ' (private, chosen by the device)' : h.vendor ? ' · ' + h.vendor : ''));
    if (h.port) L.push('Seen on port ' + h.port);
    if (h.inst_status) L.push(h.inst_status + (h.os ? ' · ' + h.os : '') + (h.cpu ? ' · ' + h.cpu + ' CPU' : '') + (h.memory ? ' · ' + h.memory : ''));
    if (h.kind === 'vpn') { L.push('Last handshake ' + ago(h.handshake)); if (h.endpoint) L.push('From ' + h.endpoint); if (h.networks && h.networks.length) L.push('Behind it: ' + h.networks.join(', ')); }
    if (h.note) L.push(h.note);
    if (h.bytes_24h) L.push(fmtBytes(h.bytes_24h) + ' in the last 24 hours');
    if (h.conns) L.push(h.conns + ' open connections');
    if (h.dns_queries) L.push(h.dns_queries + ' recent DNS lookups, ' + h.dns_blocked + ' blocked');
    if (h.ids_alerts) L.push(h.ids_alerts + ' IDS alerts in 7 days, ' + h.ids_high + ' high severity');
    if (h.forwards) L.push(h.forwards + ' port forwards reach it');
    return L.filter(Boolean).join('\n');
  }

  function hostRow(h) {
    const k = KIND[h.kind] || KIND.device;
    const name = h.name || h.vendor || (h.mac_private ? 'Private device' : 'Unknown device');
    const sub = h.addressing === 'self' ? h.note || '' : h.name && h.vendor && !isInst(h) ? h.vendor : isInst(h) ? (h.kind === 'vm' ? 'VM' : 'CT') + (h.os ? ' · ' + h.os : '') : h.kind === 'vpn' ? (h.networks && h.networks.length ? h.networks.join(', ') : '') : h.note || '';
    const chips = (h.addressing === 'reserved' ? '<em class="tp-c" title="Reserved DHCP address">R</em>' : '')
      + (h.forwards ? `<em class="tp-c fwd" title="Port forwards reach it">${h.forwards} FWD</em>` : '')
      + (h.ids_alerts ? `<em class="tp-c ids" title="IDS alerts in 7 days">${F.fmtCount(h.ids_alerts)} IDS</em>` : '');
    const activity = T.ready && (h.down_bps > 999 || h.up_bps > 999)
      ? `<span class="tp-rate live" title="Download, upload right now"><b>↓</b>${fmtRate(h.down_bps)} <b>↑</b>${fmtRate(h.up_bps)}</span>`
      : h.bytes_24h ? `<span class="tp-rate" title="Traffic in the last 24 hours">${fmtBytes(h.bytes_24h)}</span>` : '<span class="tp-rate"></span>';
    const addr = h.ip ? `<span class="tp-ip"><span class="fw-ipi fw-mono" data-ip="${E(h.ip)}">${E(h.ip)}</span></span>` : `<span class="fw-mono tp-ip tp-dim">${h.inst_status === 'Running' ? 'no address' : 'stopped'}</span>`;
    return `<div class="tp-h s-${E(h.status)}" data-s="${E(searchText(h))}" data-v="${viewMatch(h) ? 1 : 0}" title="${E(hostTitle(h))}">
      <i class="tp-dot" aria-label="${E(STATUS[h.status])}"></i><span class="tp-k">${icon(k[0], 12)}</span>
      <span class="tp-n"><span>${E(name)}</span>${sub ? `<small>${E(sub)}</small>` : ''}</span>${chips}${activity}${addr}</div>`;
  }

  // Hosts of a network, grouped by the port they came through: physical ports
  // first, then everything on virtual ports, then what no port has reported.
  function hostGroups(n) {
    const ports = new Map((n.ports || []).map(p => [p.name, p]));
    const groups = new Map();
    const add = (key, label, h) => { if (!groups.has(key)) groups.set(key, { label, hosts: [] }); groups.get(key).hosts.push(h); };
    n.hosts.forEach(h => {
      const p = ports.get(h.port);
      if (p && !p.virtual) add('0' + p.name, `${p.name}${fmtSpeed(p.speed_mbps) ? ' · ' + fmtSpeed(p.speed_mbps) : ''}`, h);
      else if (p || isInst(h)) add('1', 'Virtual ports · VMs & containers', h);
      else if (h.addressing === 'self') add('2', 'This server', h);
      else add('3', n.ports && n.ports.length ? 'Port not seen recently' : n.kind === 'wireguard' ? 'VPN clients' : 'On this network', h);
    });
    const keys = [...groups.keys()].sort();
    const multi = keys.length > 1 || (n.ports || []).some(p => !p.virtual);
    return keys.map(k => { const g = groups.get(k);
      return `<div class="tp-group">${multi && g.label ? `<div class="tp-gh">${E(g.label)}<span>${g.hosts.length}</span></div>` : ''}${g.hosts.map(hostRow).join('')}</div>`; }).join('');
  }

  function poolBar(d) {
    if (!d.pool_size) return '';
    const pct = Math.min(100, d.pool_used / d.pool_size * 100);
    return `<div class="tp-pool" title="${d.pool_used} of ${d.pool_size} pool addresses in use"><span class="tp-pool-l">Pool</span><div class="tp-bar"><i class="${pct > 90 ? 'hot' : ''}" style="width:${Math.max(pct ? 3 : 0, pct).toFixed(1)}%"></i></div><span class="fw-mono">${d.pool_used}/${d.pool_size}</span></div>`;
  }

  function netNode(n) {
    const kind = n.kind === 'wireguard' ? 'WireGuard' : n.kind === 'vlan' ? 'VLAN ' + n.vlan : n.kind === 'incus' ? 'Incus bridge' : n.kind === 'bridge' ? 'Bridge' : 'Port';
    const d = n.dhcp, up = n.state === 'up' || n.state === 'unknown';
    const state = n.disabled ? '<span class="tp-state off">disabled</span>' : !up ? `<span class="tp-state off">link ${E(n.state || 'down')}</span>` : '';
    const dhcpDown = d && d.enabled && d.stopped;
    const dhcp = d ? `<div class="tp-line ${dhcpDown ? 'off' : d.enabled ? 'ok' : 'tp-dim'}"${d.error ? ` title="${E(d.error)}"` : ''}>${dhcpDown ? 'DHCP not running' : d.enabled ? `DHCP ${E(d.server === 'Incus' ? 'by Incus' : 'on')}` : 'DHCP off'}${d.lease_hours ? ' · ' + d.lease_hours + ' h' : ''}${d.reservations ? ' · ' + d.reservations + ' reserved' : ''}</div>` : '<div class="tp-line tp-dim">No DHCP</div>';
    const routes = d && d.routes && d.routes.length ? `<div class="tp-line tp-dim" title="Routes this DHCP server sends to its clients">${d.routes.map(r => `→ ${E(r.network)} via ${E(r.via)}`).join('<br>')}</div>` : '';
    const stats = `<div class="tp-rx"><span title="Received by this server on the network"><b>RX</b> ${T.ready ? fmtRate(n.rx_bits) : '—'}</span><span title="Sent by this server on the network"><b>TX</b> ${T.ready ? fmtRate(n.tx_bits) : '—'}</span></div>`;
    const meta = [fmtSpeed(n.speed_mbps), n.mtu && n.mtu !== 1500 ? 'MTU ' + n.mtu : ''].filter(Boolean).join(' · ');
    return `<div class="tp-node" data-node="${E(n.id)}" style="--net:${F.C(n.color)}">
      <div class="tp-node-h"><span class="tp-name">${E(n.name)}</span>${state}</div>
      <div class="tp-line fw-mono">${E(kind)} · ${E(n.address || 'no address')}</div>
      ${meta ? `<div class="tp-line tp-dim">${E(meta)}</div>` : ''}${dhcp}${d ? poolBar(d) : ''}${routes}${stats}</div>`;
  }

  function netPanel(n) {
    const on = n.hosts.filter(h => h.status === 'online' || h.status === 'idle').length;
    const inst = n.hosts.filter(isInst).length;
    const fwd = n.forwards.length ? `<div class="tp-fwds"><div class="tp-gh">Port forwards<span>${n.forwards.length}</span></div>${n.forwards.map(f =>
      `<div class="tp-fwd${f.active ? '' : ' off'}"><span class="fw-mono">${E(f.proto)} ${E(f.public)} → ${E(f.target)}${f.target_ports && f.target_ports !== f.public ? ':' + E(f.target_ports) : ''}</span><small>${E(f.description || '')}</small></div>`).join('')}</div>` : '';
    return `<div class="tp-panel" data-panel="${E(n.id)}" style="--net:${F.C(n.color)}">
      <div class="tp-panel-h"><span class="tp-sw"></span><b>${E(n.name)}</b><span class="fw-mono">${E(n.cidr || '')}</span><span class="tp-sp"></span>
        <span>${on}/${n.hosts.length} up${inst ? ` · ${inst} VM/CT` : ''}</span></div>
      ${n.hosts.length ? `<div class="tp-hosts">${hostGroups(n)}</div>` : '<div class="tp-none">Nothing seen on this network yet</div>'}${fwd}
      <div class="tp-none tp-nomatch" style="display:none">No host matches the filter</div></div>`;
  }

  function netsCard() {
    const row = n => {
      const on = n.hosts.filter(h => h.status === 'online' || h.status === 'idle').length;
      const inst = n.hosts.filter(isInst).length;
      const desc = [`${n.hosts.length} hosts`, inst ? `${inst} VM/CT` : '', n.dhcp && n.dhcp.enabled ? 'DHCP' : '', n.vlan ? 'VLAN ' + n.vlan : ''].filter(Boolean).join(' · ');
      const st = n.disabled ? ['Disabled', 'off'] : on ? ['Live', 'ok'] : ['Quiet', 'dim'];
      return `<tr><td><span class="tp-sw" style="--net:${F.C(n.color)}"></span>${E(n.name)}</td><td class="fw-mono">${E(n.cidr || '—')}</td><td class="tp-dim">${E(desc)}</td><td class="tp-st ${st[1]}">${st[0]}</td></tr>`;
    };
    return `<div class="tp-card"><div class="tp-ct">Networks · ${E(T.host)} is the gateway on each</div>
      <table class="tp-nets"><tbody>${T.networks.map(row).join('')}</tbody></table>
      <div class="tp-legend">
        <span><i class="tp-dot s-online"></i>Online</span><span><i class="tp-dot s-idle"></i>Idle</span><span><i class="tp-dot s-unknown"></i>No recent contact</span><span><i class="tp-dot s-offline"></i>Offline</span>
        <span><svg width="26" height="6"><line x1="0" y1="3" x2="26" y2="3" stroke="var(--text-2)" stroke-width="3" stroke-dasharray="5 3"/></svg>Trunk, one stripe per network</span>
        <span><svg width="26" height="6"><line x1="0" y1="3" x2="26" y2="3" stroke="var(--text-2)" stroke-width="2" stroke-dasharray="2 3"/></svg>Tunnel or standby</span>
        <span>Thicker line = more traffic</span>
      </div></div>`;
  }

  function policyCard() {
    const act = a => a === 'allow' ? 'allow' : 'block';
    const line = n => {
      const p = n.policy;
      const lines = (p.lines || []).map(l => { const i = l.indexOf('|'); return `<div class="tp-pl"><span class="tp-act ${act(l.slice(0, i))}">${E(l.slice(0, i))}</span>${E(l.slice(i + 1))}</div>`; }).join('');
      return `<div class="tp-pol"><div class="tp-pol-h"><span class="tp-sw" style="--net:${F.C(n.color)}"></span><b>${E(n.name)}</b><span class="tp-dim">${p.allow} allow · ${p.block} block${p.off ? ` · ${p.off} off` : ''}${n.forwards.length ? ` · ${n.forwards.length} forwards` : ''}</span></div>${lines}</div>`;
    };
    const any = T.any_rules;
    return `<div class="tp-card"><div class="tp-ct">Firewall policy · ${T.mode === 'monitor' ? 'monitor only, nothing is filtered' : 'filtering'} · NAT ${E(T.outbound_nat || '')}</div>
      ${any.allow + any.block ? `<div class="tp-pol"><div class="tp-pol-h"><b>Any interface</b><span class="tp-dim">${any.allow} allow · ${any.block} block</span></div></div>` : ''}
      ${T.networks.map(line).join('')}
      <div class="tp-svc"><span class="${T.dns_running ? 'ok' : 'tp-dim'}">DNS ${T.dns_running ? 'running' : 'stopped'}${T.dns_domain ? ' · ' + E(T.dns_domain) : ''}</span><span class="${T.ids_enabled ? 'ok' : 'tp-dim'}">IDS ${T.ids_enabled ? 'on' : 'off'}</span></div></div>`;
  }

  function routesCard() {
    if (!T.routes.length) return '';
    return `<div class="tp-card"><div class="tp-ct">Local routes</div>${T.routes.map(r =>
      `<div class="tp-route${r.enabled ? '' : ' off'}"><span class="fw-mono">${E(r.destination)}</span><span class="fw-mono tp-dim">${r.via ? 'via ' + E(r.via) : 'on link'}</span><span class="tp-dim">${E(r.network || '')}</span></div>`).join('')}</div>`;
  }

  function edge() {
    const up = T.uplinks.map((u, i) => {
      const g = u.gateways.find(x => x.active) || u.gateways[0];
      const active = u.gateways.some(x => x.active);
      const down = u.gateways.length && !u.gateways.some(x => x.up);
      const line = g ? `${E(g.name)}${g.monitor && g.up ? ` · ${g.rtt_ms ? g.rtt_ms.toFixed(1) + ' ms' : 'no reply yet'}${g.loss ? ' · ' + g.loss + '% loss' : ''}` : ''}` : '';
      const st = u.disabled ? ['off', 'disabled'] : down ? ['off', 'down'] : active ? ['ok', 'active'] : ['tp-dim', 'standby'];
      return `<div class="tp-node tp-up" data-uplink="${i}" data-active="${active ? 1 : 0}" data-rate="${u.rx_bits + u.tx_bits}" style="--net:${F.C(u.color)}" data-dev="${E(u.device)}">
        <div class="tp-node-h"><span class="tp-name">${E(u.name)}</span></div>
        <div class="tp-line fw-mono">${E((u.address || 'no address').replace(/\/\d+$/, ''))} · ${E(u.device)}${fmtSpeed(u.speed_mbps) ? ' · ' + fmtSpeed(u.speed_mbps) : ''}</div>
        <div class="tp-line ${st[0]}">${st[1]}${line ? ' · ' + line : ''}</div>
        <div class="tp-rx"><span><b>↓</b> ${T.ready ? fmtRate(u.rx_bits) : '—'}</span><span><b>↑</b> ${T.ready ? fmtRate(u.tx_bits) : '—'}</span></div></div>`;
    }).join('');
    return `<div class="tp-edge"><div class="tp-ups">${up || '<div class="tp-none">No Internet link</div>'}</div>
      <div class="tp-node tp-fw" id="tp-fw"><div class="tp-node-h"><span class="tp-name">${E(T.host)}</span></div>
        <div class="tp-line">ZNAS Firewall</div><div class="tp-line ${T.mode === 'monitor' ? 'warn' : 'ok'}">${T.mode === 'monitor' ? 'monitor only' : 'filtering · routing'}</div>
        <div class="tp-rx"><span title="Downloaded by every inside host"><b>↓</b> ${T.ready ? fmtRate(T.down_bps) : '—'}</span><span title="Uploaded by every inside host"><b>↑</b> ${T.ready ? fmtRate(T.up_bps) : '—'}</span></div></div></div>`;
  }

  function kpis() {
    const hosts = T.networks.flatMap(n => n.hosts).filter(h => h.addressing !== 'self');
    const on = hosts.filter(h => h.status === 'online' || h.status === 'idle').length;
    const inst = hosts.filter(isInst);
    const leases = T.networks.reduce((a, n) => a + (n.dhcp ? n.dhcp.pool_used : 0), 0);
    const pool = T.networks.reduce((a, n) => a + (n.dhcp ? n.dhcp.pool_size : 0), 0);
    const conns = hosts.reduce((a, h) => a + h.conns, 0);
    const dq = hosts.reduce((a, h) => a + h.dns_queries, 0), db = hosts.reduce((a, h) => a + h.dns_blocked, 0);
    const ids = hosts.reduce((a, h) => a + h.ids_alerts, 0), high = hosts.reduce((a, h) => a + h.ids_high, 0);
    const tile = (l, v, d, cls) => `<div class="tp-kpi${cls ? ' ' + cls : ''}"><small>${l}</small><b>${v}</b><span>${d}</span></div>`;
    return `<div class="tp-kpis">
      ${tile('Networks', T.networks.length, `${T.uplinks.length} Internet ${T.uplinks.length === 1 ? 'link' : 'links'}`)}
      ${tile('Hosts up', `${on}<i>/${hosts.length}</i>`, 'online or idle')}
      ${tile('VMs &amp; containers', `${inst.filter(h => h.inst_status === 'Running').length}<i>/${inst.length}</i>`, 'running')}
      ${tile('DHCP pool', `${leases}<i>/${pool}</i>`, 'addresses in use')}
      ${tile('Download', T.ready ? fmtRate(T.down_bps) : '—', 'inside hosts, now')}
      ${tile('Upload', T.ready ? fmtRate(T.up_bps) : '—', 'inside hosts, now')}
      ${tile('Connections', F.fmtCount(conns), 'open now')}
      ${tile('DNS blocked', F.fmtCount(db), `of ${F.fmtCount(dq)} recent lookups`)}
      ${tile('IDS alerts', F.fmtCount(ids), `${F.fmtCount(high)} high, 7 days`, high ? 'alert' : '')}
    </div>`;
  }

  function render() {
    if (failed && !T) return `<div class="fw-empty">${E(failed)}</div>`;
    if (!T) return '<div class="fw-empty">Loading…</div>';
    const VIEWS = [['all', 'All'], ['online', 'Up'], ['inst', 'VMs & containers'], ['dhcp', 'DHCP'], ['alert', 'IDS alerts']];
    return `<div class="tp-root">${kpis()}
      <div class="tp-bar-row"><input id="tp-q" class="input" placeholder="Filter: name, address, MAC, maker, port…" value="${E(q)}" autocomplete="off">
        <div class="tp-seg">${VIEWS.map(v => `<button class="${view === v[0] ? 'on' : ''}" data-view="${v[0]}">${E(v[1])}</button>`).join('')}</div>
        <span class="tp-sp"></span><span class="tp-dim tp-at">Updated ${new Date(T.at).toLocaleTimeString()}</span></div>
      <div class="tp-canvas" id="tp-canvas"><svg class="tp-wires" id="tp-wires" aria-hidden="true"></svg>
        <div class="tp-left">${netsCard()}${policyCard()}${edge()}${routesCard()}</div>
        <div class="tp-right">${T.networks.map(n => `<div class="tp-row" data-net="${E(n.id)}" data-kind="${E(n.kind)}" data-off="${n.disabled ? 1 : 0}" data-rate="${n.rx_bits + n.tx_bits}" data-dev="${E(n.l3)}">${netNode(n)}${netPanel(n)}</div>`).join('') || '<div class="tp-none">No inside network yet</div>'}</div>
      </div></div>`;
  }

  // Filter without a redraw, so typing keeps its focus.
  function applyFilter(root) {
    const needle = q.trim().toLowerCase();
    root.querySelectorAll('.tp-panel').forEach(panel => {
      let shown = 0;
      panel.querySelectorAll('.tp-group').forEach(g => {
        let n = 0;
        g.querySelectorAll('.tp-h').forEach(r => {
          const ok = r.dataset.v === '1' && (!needle || r.dataset.s.includes(needle));
          r.style.display = ok ? '' : 'none';
          if (ok) n++;
        });
        g.style.display = n ? '' : 'none';
        shown += n;
      });
      const none = panel.querySelector('.tp-nomatch'), has = panel.querySelector('.tp-h');
      if (none) none.style.display = has && !shown ? '' : 'none';
    });
    drawWires(root);
  }

  // ── wires ───────────────────────────────────────────────────────────────
  const widthOf = bits => Math.min(6, 2 + Math.log10(1 + (+bits || 0) / 1e5) * 1.5);
  function drawWires(root) {
    const svg = root.querySelector('#tp-wires'), cv = root.querySelector('#tp-canvas'), fw = root.querySelector('#tp-fw');
    if (!svg || !cv || !fw) return;
    if (getComputedStyle(svg).display === 'none') return;
    const box = cv.getBoundingClientRect();
    svg.setAttribute('width', box.width); svg.setAttribute('height', box.height);
    const rel = el => { const r = el.getBoundingClientRect(); return { l: r.left - box.left, r: r.right - box.left, t: r.top - box.top, b: r.bottom - box.top, m: (r.top + r.bottom) / 2 - box.top }; };
    const out = [];
    const seg = (d, color, w, extra) => out.push(`<path d="${d}" fill="none" stroke="${color}" stroke-width="${w.toFixed(1)}" stroke-linecap="round" stroke-linejoin="round" ${extra || ''}/>`);
    const label = (x, y, text, anchor) => out.push(`<text x="${x}" y="${y}" text-anchor="${anchor}" class="tp-wl">${E(text)}</text>`);
    const f = rel(fw);

    // uplinks → Firewall
    root.querySelectorAll('.tp-up').forEach((u, i, all) => {
      const a = rel(u), active = u.dataset.active === '1';
      const y = f.m + (i - (all.length - 1) / 2) * 12, mx = (a.r + f.l) / 2;
      const color = active ? getComputedStyle(u).getPropertyValue('--net').trim() : 'var(--text-3)';
      seg(`M${a.r} ${a.m}H${mx}V${y}H${f.l}`, color, active ? widthOf(u.dataset.rate) : 1.6, active ? '' : 'stroke-dasharray="3 4"');
    });

    // the trunk: Firewall → every network
    const rows = [...root.querySelectorAll('.tp-row')];
    if (rows.length) {
      const nodes = rows.map(r => rel(r.querySelector('.tp-node')));
      const right = root.querySelector('.tp-right').getBoundingClientRect().left - box.left;
      const tx = right - 92;
      const ys = nodes.map(n => n.t + 22);
      const top = Math.min(f.m, ...ys), bot = Math.max(f.m, ...ys);
      const colors = rows.map(r => getComputedStyle(r.querySelector('.tp-node')).getPropertyValue('--net').trim());
      seg(`M${f.r} ${f.m}H${tx}`, 'var(--text-2)', 4);
      seg(`M${tx} ${top}V${bot}`, 'var(--text-3)', 5);
      const n = colors.length, dash = 7;
      colors.forEach((c, i) => seg(`M${tx} ${top}V${bot}`, c, 3, `stroke-linecap="butt" stroke-dasharray="${dash} ${dash * (n - 1) || dash}" stroke-dashoffset="${-i * dash}"`));
      rows.forEach((r, i) => {
        const a = nodes[i], y = ys[i], tunnel = r.dataset.kind === 'wireguard', off = r.dataset.off === '1';
        const w = off ? 1.4 : widthOf(r.dataset.rate);
        const c = off ? 'var(--text-3)' : colors[i];
        const dash2 = tunnel || off ? 'stroke-dasharray="3 4"' : '';
        seg(`M${tx} ${y}H${a.l}`, c, w, dash2);
        if (!off && +r.dataset.rate > 1000) seg(`M${tx} ${y}H${a.l}`, 'rgba(255,255,255,.75)', Math.max(1, w - 1.5), 'class="tp-flow" stroke-dasharray="2 12"');
        label(a.l - 4, y - 5, r.dataset.dev.length > 15 ? r.dataset.dev.slice(0, 14) + '…' : r.dataset.dev, 'end');
        const p = rel(r.querySelector('.tp-panel'));
        if (p.l > a.r) seg(`M${a.r} ${y}H${p.l}`, c, w, dash2);
      });
    }
    svg.innerHTML = out.join('');
  }

  function wire(root) {
    const input = root.querySelector('#tp-q');
    if (input) input.oninput = () => { q = input.value; applyFilter(root); };
    root.querySelectorAll('[data-view]').forEach(b => b.onclick = () => { view = b.dataset.view; F.rerender(); });
    applyFilter(root);
    const cv = root.querySelector('#tp-canvas');
    if (ro) ro.disconnect();
    if (cv && window.ResizeObserver) { ro = new ResizeObserver(() => drawWires(root)); ro.observe(cv); }
  }

  async function load() {
    const r = await F.api('GET', '/api/sdn/topology');
    if (r.ok) { T = r.data; failed = ''; } else failed = (r.data && r.data.error) || 'The topology could not be read';
  }
  const busy = () => { const a = document.activeElement; return !!(a && a.id === 'tp-q'); };

  function register() {
    if (typeof window.sdnRegisterPage !== 'function' || !window.sdnFW || !window.sdnFW.info) { setTimeout(register, 200); return; }
    F = window.sdnFW;
    window.sdnRegisterPage('fw-topo', { load, render, wire, busy, pollMs: 5000, poll: load });
  }
  register();
})();
