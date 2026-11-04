/*
 * Firewall → the inside address card. Internal addresses on every Firewall page
 * get a dotted underline; hovering one (tapping on a touch
 * screen) opens a card with what GET /api/sdn/hostinfo knows about it.
 */
(function () {
  'use strict';
  const INTERNAL = /(^|[^\d.])((?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])|169\.254)\.\d{1,3}\.\d{1,3})(?!\d|\.\d|\/(?!32\b))/g;
  const INTERNAL_ONE = /^(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])|169\.254)\.\d{1,3}\.\d{1,3}$/;
  const valid = ip => ip.split('.').every(o => +o <= 255);
  const SKIP = 'button,select,option,textarea,input,script,style,svg,.fw-ipi';
  const E = s => (typeof window.esc === 'function' ? window.esc(s) : String(s == null ? '' : s));
  const icon = (n, size) => (typeof window.znasIcon === 'function' ? window.znasIcon(n, { size: size || 14 }) : '');

  // A name shown in place of an internal address (its DNS name, a DHCP or
  // VM name) opens the same card as the address itself.
  window.fwHostName = (name, ip, cls) => (ip && name && name !== ip && INTERNAL_ONE.test(ip))
    ? `<span class="fw-ipi${cls ? ' ' + cls : ''}" data-ip="${E(ip)}" title="${E(ip)}">${E(name)}</span>`
    : (cls ? `<span class="${cls}">${E(name || ip || '')}</span>` : E(name || ip || ''));
  // ── marking the addresses ───────────────────────────────────────────────
  function mark(root) {
    const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const found = [];
    for (let n = walk.nextNode(); n; n = walk.nextNode()) {
      if (/\d\.\d/.test(n.nodeValue) && !n.parentElement.closest(SKIP)) found.push(n);
    }
    found.forEach(n => {
      const text = n.nodeValue;
      let last = 0, frag = null;
      INTERNAL.lastIndex = 0;
      for (let m = INTERNAL.exec(text); m; m = INTERNAL.exec(text)) {
        if (!valid(m[2])) continue;
        frag = frag || document.createDocumentFragment();
        const at = m.index + m[1].length;
        frag.append(text.slice(last, at));
        const s = document.createElement('span');
        s.className = 'fw-ipi'; s.dataset.ip = m[2]; s.textContent = m[2];
        frag.append(s);
        last = at + m[2].length;
      }
      if (frag) { frag.append(text.slice(last)); n.replaceWith(frag); }
    });
  }
  let queued = false;
  const scan = () => {
    queued = false;
    document.querySelectorAll('[id^="page-fw-"]:not(.hidden)').forEach(mark);
  };
  new MutationObserver(() => {
    if (!queued && document.querySelector('[id^="page-fw-"]:not(.hidden)')) { queued = true; setTimeout(scan, 80); }
  }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['class'] });

  // ── formatting ──────────────────────────────────────────────────────────
  const fmtBytes = n => {
    n = +n || 0;
    const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0;
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
    return (i && n < 100 ? n.toFixed(1) : Math.round(n)) + ' ' + u[i];
  };
  const fmtBps = n => {
    n = +n || 0;
    const u = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s'];
    let i = 0;
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
    return (i && n < 100 ? n.toFixed(1) : Math.round(n)) + ' ' + u[i];
  };
  const fmtN = n => (+n || 0).toLocaleString();
  const ago = t => {
    const ms = Date.now() - (typeof t === 'number' ? t * 1000 : new Date(t).getTime());
    if (!isFinite(ms)) return '';
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 60) return 'just now';
    if (s < 3600) return Math.round(s / 60) + ' min ago';
    if (s < 86400) return Math.round(s / 3600) + ' h ago';
    return Math.round(s / 86400) + ' d ago';
  };
  const until = t => {
    const s = Math.round((new Date(t).getTime() - Date.now()) / 1000);
    if (!isFinite(s)) return '';
    if (s <= 0) return 'expired';
    if (s < 3600) return 'in ' + Math.max(1, Math.round(s / 60)) + ' min';
    if (s < 86400) return 'in ' + Math.round(s / 3600) + ' h';
    return 'in ' + Math.round(s / 86400) + ' d';
  };
  const F = () => window.sdnFW || {};
  const flag = cc => (cc && F().flagOf ? F().flagOf(cc) + ' ' : '');
  const spark = (pts, color) => {
    if (!pts || pts.length < 2) return '';
    const max = Math.max(1, ...pts), w = 120, h = 26;
    const line = pts.map((v, i) => `${(i / (pts.length - 1) * w).toFixed(1)},${(h - 1 - v / max * (h - 3)).toFixed(1)}`).join(' ');
    return `<svg class="fw-hc-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><polygon points="0,${h} ${line} ${w},${h}" fill="${color}" opacity=".16"/><polyline points="${line}" fill="none" stroke="${color}" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>`;
  };

  // ── the card ────────────────────────────────────────────────────────────
  const ROLE = {
    'this-server': ['server', 'This ZNAS server'], gateway: ['network', 'Network gateway'],
    instance: ['box', 'VM or container'], vpn: ['lock', 'VPN client'], device: ['monitor', 'Device'],
  };
  const STATE = {
    REACHABLE: ['on', 'Online'], DELAY: ['on', 'Online'], PROBE: ['on', 'Checking'], PERMANENT: ['on', 'Online'],
    STALE: ['idle', 'Idle'], FAILED: ['off', 'Not answering'], INCOMPLETE: ['off', 'Not answering'],
  };
  const row = (label, val, cls) => (val === '' || val == null ? '' : `<div class="fw-hc-k">${E(label)}</div><div class="fw-hc-v${cls ? ' ' + cls : ''}">${val}</div>`);
  // go: a title that opens the page with everything about this address
  const section = (ic, title, body, note, go) => body ? `<section class="fw-hc-s"><h4>${icon(ic, 13)}${go ? `<button type="button" class="fw-hc-go" data-hc-go="${E(go)}" title="Show all of them">${E(title)}${icon('chevron-right', 12)}</button>` : `<span>${E(title)}</span>`}${note ? `<small>${E(note)}</small>` : ''}</h4>${body}</section>` : '';

  function liveHTML(l) {
    const tile = (cls, ic, label, v, peak, pts, color) => `<div class="fw-hc-tile ${cls}"><div class="fw-hc-tl">${icon(ic, 12)}${label}</div><b>${l.ready ? fmtBps(v) : '—'}</b><small>${l.ready && peak ? 'peak ' + fmtBps(peak) : '&nbsp;'}</small>${spark(pts, color)}</div>`;
    const conn = c => {
      const d = c.dir === 'in' ? ['arrow-down', 'Started by the other side'] : c.dir === 'out' ? ['arrow-up', 'Started by this address'] : ['arrow-right', 'Between inside networks'];
      return `<div class="fw-hc-li"><span class="fw-hc-dir" title="${E(d[1])}">${icon(d[0], 11)}</span><span class="fw-hc-grow"><span class="fw-mono">${flag(c.cc)}${E(c.peer || '—')}${c.port ? ':' + c.port : ''}</span>${c.org || c.city ? `<small>${E([c.city, c.org].filter(Boolean).join(' · '))}</small>` : ''}</span><span class="fw-hc-num">${fmtBytes(c.bytes_in + c.bytes_out)}</span></div>`;
    };
    return `<div class="fw-hc-tiles">${tile('in', 'arrow-down', 'Download', l.down_bps, l.peak_down_bps, l.spark_down, 'var(--fw-in)')}${tile('out', 'arrow-up', 'Upload', l.up_bps, l.peak_up_bps, l.spark_up, 'var(--fw-out)')}</div>`
      + (l.conns ? `<div class="fw-hc-conns">${l.top.map(conn).join('')}</div>` : '<div class="fw-hc-none">No open connection</div>');
  }

  // A VM or container MAC no instance of this server has: another ZNAS server's?
  function ownerHTML(a) {
    if (!a) return section('box', 'VM or container', '<div class="fw-hc-none">Looking on the other ZNAS servers…</div>');
    if (a.owner) {
      const o = a.owner;
      return section('box', 'VM or container', `<div class="fw-hc-kv">${row('ZNAS server', E(a.server || ''))}${row('Name', E(o.name))}${row('Type', o.type === 'virtual-machine' ? 'Virtual machine' : o.type === 'container' ? 'Container' : '')}${row('Status', E(o.status || ''))}${row('System', E(o.os || ''))}${row('CPU', E(o.cpu || ''))}${row('Memory', E(fmtMem(o.memory)))}${row('Network card', o.nic ? E(o.nic + (o.bridge ? ' on ' + o.bridge : '')) : '')}</div>`);
    }
    const none = a.asked ? `Virtual card, not found on ${a.asked} other ZNAS ${a.asked === 1 ? 'server' : 'servers'}` : 'Virtual card, no other ZNAS server to ask';
    return section('box', 'VM or container', `<div class="fw-hc-none">${none}${a.failed ? ` (${a.failed} did not answer)` : ''}</div>`);
  }
  const fmtMem = m => m || '';
  async function loadOwner(ip, c) {
    if (c.data.owner) return;
    const r = await fetch('/api/sdn/hostinfo/owner?mac=' + encodeURIComponent(c.data.mac), { credentials: 'same-origin' }).catch(() => null);
    if (!r || !r.ok) { c.data.owner = { asked: 0, failed: 1 }; } else c.data.owner = await r.json();
    if (openIP !== ip) return;
    const el = document.getElementById('fw-hc-owner');
    if (el) { el.innerHTML = ownerHTML(c.data.owner); place(); }
  }

  function cardHTML(h) {
    const [ric, rlabel] = ROLE[h.role] || ROLE.device;
    const st = STATE[h.state];
    const netPill = h.network ? `<span class="fw-hc-pill"><span class="fw-hc-dot" style="background:${E(h.network.color || 'var(--text-3)')}"></span>${E(h.network.name)}</span>` : '';
    const vendor = h.mac_private ? '<span class="fw-hc-priv">Private address, chosen by the device</span>'
      : h.vendor ? `<b>${E(h.vendor)}</b>` : h.mac ? '<span class="fw-hc-dim">Maker not listed</span>' : '';
    const macHero = h.mac ? `<div class="fw-hc-mac"><div><small>MAC address</small><span class="fw-mono">${E(h.mac)}</span></div><div><small>Maker</small>${vendor}</div><em>${E(h.mac_source || '')}</em></div>`
      : `<div class="fw-hc-mac none"><div><small>MAC address</small><span class="fw-hc-dim">${h.via ? 'Behind a router, so its MAC is not visible here' : 'Not seen on the network yet'}</span></div></div>`;
    const inst = h.instance;
    const identity = row('Host name', h.name ? E(h.name) : '') + row('Full name', h.fqdn && h.fqdn !== h.name ? E(h.fqdn) : '', 'fw-mono')
      + row('Also known as', h.dns_names.filter(n => n !== h.name).map(E).join(', ')) + row('VPN client', h.vpn_peer ? E(h.vpn_peer) : '')
      + row('Virtual IP', h.virtual_ip ? 'Yes' : '');
    const instance = inst ? row('Name', E(inst.name)) + row('Type', inst.type === 'virtual-machine' ? 'Virtual machine' : inst.type === 'container' ? 'Container' : '')
      + row('Status', E(inst.status || '')) + row('System', E(inst.os || '')) + row('CPU', E(inst.cpu || '')) + row('Memory', E(inst.memory || '')) : '';
    const n = h.network;
    const network = (n ? row('Network', netPill) + row('Subnet', E(n.cidr || ''), 'fw-mono') + row('VLAN', n.vlan ? String(n.vlan) : '') + row('Role', n.role === 'wan' ? 'Internet' : n.role === 'lan' ? 'Internal' : '') : '')
      + row('Port', h.device && !(n && (n.name === h.device || n.device === h.device)) ? (typeof window.ifLabelHTML === 'function' ? window.ifLabelHTML(h.device) : E(h.device)) : '') + row('Reached via', h.via ? E(h.via) : '', 'fw-mono');
    const d = h.dhcp;
    const dhcp = d ? row('Type', d.reserved ? 'Reserved address' : d.leased ? 'Dynamic lease' : 'In the pool, not leased') + row('Served by', E(d.server || ''))
      + row('Asked for', E(d.hostname || '')) + row('Expires', d.expires && d.leased ? E(until(d.expires)) : '') + row('Note', E(d.description || '')) : '';
    const tr = h.traffic;
    const traffic = tr.bytes_in || tr.bytes_out || tr.sessions ? `<div class="fw-hc-trio"><div><small>Received</small><b>${fmtBytes(tr.bytes_in)}</b></div><div><small>Sent</small><b>${fmtBytes(tr.bytes_out)}</b></div><div><small>Sessions</small><b>${fmtN(tr.sessions)}</b></div></div>`
      + tr.top.map(p => `<div class="fw-hc-li"><span class="fw-hc-grow"><span class="fw-mono">${flag(p.cc)}${E(p.remote)}</span>${p.org || p.city ? `<small>${E([p.city, p.org].filter(Boolean).join(' · '))}</small>` : ''}</span><span class="fw-hc-num">${fmtBytes(p.bytes)}</span></div>`).join('') : '';
    const dn = h.dns;
    const maxD = Math.max(1, ...dn.top.map(x => x.n));
    const dns = dn.queries ? `<div class="fw-hc-trio"><div><small>Lookups</small><b>${fmtN(dn.queries)}</b></div><div><small>Blocked</small><b class="${dn.blocked ? 'blk' : ''}">${fmtN(dn.blocked)}</b></div><div><small>Latest</small><b>${E(ago(dn.last))}</b></div></div>`
      + dn.top.map(x => `<div class="fw-hc-bar"><i style="width:${(x.n / maxD * 100).toFixed(0)}%"></i><span>${E(x.key)}</span><b>${fmtN(x.n)}</b></div>`).join('') : '';
    const sev = s => s === 1 ? ['high', 'High'] : s === 2 ? ['med', 'Medium'] : ['low', 'Low'];
    const ids = h.ids.alerts ? `<div class="fw-hc-trio two"><div><small>Alerts</small><b>${fmtN(h.ids.alerts)}</b></div><div><small>High severity</small><b class="${h.ids.high ? 'blk' : ''}">${fmtN(h.ids.high)}</b></div></div>`
      + h.ids.top.map(a => `<div class="fw-hc-li"><span class="fw-hc-sev ${sev(a.severity)[0]}">${sev(a.severity)[1]}</span><span class="fw-hc-grow"><span>${E(a.signature)}</span><small>${fmtN(a.count)} ${a.count === 1 ? 'time' : 'times'} · ${E(ago(a.last))}</small></span></div>`).join('') : '';
    const act = { allow: 'Allow', block: 'Block', reject: 'Reject' };
    const fw = (h.groups.length ? `<div class="fw-hc-tags">${h.groups.map(g => `<span>${E(g)}</span>`).join('')}</div>` : '')
      + h.forwards.map(f => `<div class="fw-hc-li${f.enabled ? '' : ' off'}"><span class="fw-hc-act fwd">Forward</span><span class="fw-hc-grow"><span class="fw-mono">${E(f.proto)} ${E(f.public)} → ${E(f.target || f.public)}</span>${f.description ? `<small>${E(f.description)}</small>` : ''}</span></div>`).join('')
      + h.rules.slice(0, 5).map(r => `<div class="fw-hc-li${r.enabled ? '' : ' off'}"><span class="fw-hc-act ${E(r.action)}">${E(act[r.action] || r.action)}</span><span class="fw-hc-grow">${E(r.description || 'Rule without a description')}</span></div>`).join('')
      + (h.rules.length > 5 ? `<div class="fw-hc-none">and ${h.rules.length - 5} more rules</div>` : '');
    return `<header class="fw-hc-head">
        <div class="fw-hc-avatar r-${E(h.role)}">${icon(ric, 22)}</div>
        <div class="fw-hc-title"><div class="fw-hc-name${h.name ? '' : ' fw-mono'}">${E(h.name || h.ip)}</div><div class="fw-hc-sub">${h.name ? `<span class="fw-mono">${E(h.ip)}</span> · ` : ''}${E(rlabel)}</div></div>
        ${st ? `<span class="fw-hc-state ${st[0]}"><i></i>${st[1]}</span>` : ''}
      </header>${macHero}
      <div class="fw-hc-grid">
        ${section('tag', 'Identity', identity ? `<div class="fw-hc-kv">${identity}</div>` : '')}
        ${section('network', 'Network', network ? `<div class="fw-hc-kv">${network}</div>` : '')}
        ${section('box', 'VM or container', instance ? `<div class="fw-hc-kv">${instance}</div>` : '')}
        ${h.mac_hypervisor ? `<div id="fw-hc-owner">${ownerHTML(h.owner)}</div>` : ''}
        ${section('link', 'DHCP', dhcp ? `<div class="fw-hc-kv">${dhcp}</div>` : '')}
      </div>
      <section class="fw-hc-s"><h4>${icon('arrow-up-down', 13)}<span>Right now</span><small id="fw-hc-conncount">${connCount(h.live)}</small></h4><div id="fw-hc-live">${liveHTML(h.live)}</div></section>
      ${section('clock', 'Last 24 hours', traffic, tr.remotes ? fmtN(tr.remotes) + (tr.remotes === 1 ? ' destination' : ' destinations') : '')}
      ${section('search', 'DNS lookups', dns, dn.first ? 'since ' + ago(dn.first) : '', 'dns')}
      ${section('alert-triangle', 'Intrusion detection', ids, 'last 7 days', 'ids')}
      ${section('shield', 'Firewall', fw)}`;
  }
  const connCount = l => l.conns ? `${fmtN(l.conns)} open · ${fmtN(l.tcp)} TCP · ${fmtN(l.udp)} UDP` : '';

  // ── showing it ──────────────────────────────────────────────────────────
  const cache = {}; // ip → {at, data}
  let card = null, anchor = null, openIP = '', showT = 0, hideT = 0, pollT = 0, mx = 0, my = 0;

  function place() {
    if (!card || !anchor) return;
    const r = anchor.getBoundingClientRect(), w = card.offsetWidth, h = card.offsetHeight, m = 8;
    let x = r.right + 10, y = r.top - 16;
    if (x + w > innerWidth - m) x = r.left - w - 10;
    if (x < m) x = Math.max(m, Math.min(innerWidth - w - m, r.left));
    if (y + h > innerHeight - m) y = innerHeight - h - m;
    card.style.left = x + 'px'; card.style.top = Math.max(m, y) + 'px';
  }
  function close() {
    clearTimeout(showT); clearTimeout(hideT); clearInterval(pollT);
    pollT = 0; anchor = null; openIP = '';
    if (card) card.style.display = 'none';
  }
  async function refreshLive(ip) {
    const r = await fetch('/api/sdn/hostinfo?live=1&ip=' + encodeURIComponent(ip), { credentials: 'same-origin' }).catch(() => null);
    if (!r || !r.ok || openIP !== ip) return;
    const l = await r.json();
    const box = document.getElementById('fw-hc-live'), n = document.getElementById('fw-hc-conncount');
    if (box) box.innerHTML = liveHTML(l);
    if (n) n.textContent = connCount(l);
  }
  // A page refresh rebuilds its table under the card: follow the same address
  // under the pointer, close when the pointer has gone elsewhere.
  function followAnchor() {
    if (!anchor || document.contains(anchor)) return;
    const el = document.elementFromPoint(mx, my);
    if (el && card.contains(el)) return;
    const a = el && el.closest('.fw-ipi');
    if (a && a.dataset.ip === openIP) anchor = a;
    else if (matchMedia('(hover: hover)').matches) close();
  }
  async function open(el) {
    const ip = el.dataset.ip;
    if (!card) {
      card = document.createElement('div');
      card.className = 'fw-hostcard'; card.style.display = 'none';
      card.addEventListener('mouseenter', () => clearTimeout(hideT));
      card.addEventListener('mouseleave', () => { hideT = setTimeout(close, 220); });
      card.addEventListener('click', e => {
        const g = e.target.closest('[data-hc-go]');
        if (!g) return;
        const ip = openIP, fn = g.dataset.hcGo === 'dns' ? window.fwDNSFocus : window.fwIDSFocus;
        close();
        if (fn && ip) fn(ip);
      });
      document.body.append(card);
    }
    document.querySelectorAll('.fw-ipcard').forEach(c => { c.style.display = 'none'; }); // the IDS page's own card
    clearInterval(pollT);
    anchor = el; openIP = ip;
    card.innerHTML = `<div class="fw-hc-load"><span class="fw-mono">${E(ip)}</span><small>Looking up…</small></div>`;
    card.style.display = 'block'; card.scrollTop = 0; place();
    let c = cache[ip];
    if (!c || Date.now() - c.at > 30000) {
      const r = await fetch('/api/sdn/hostinfo?ip=' + encodeURIComponent(ip), { credentials: 'same-origin' }).catch(() => null);
      if (openIP !== ip) return;
      if (!r || !r.ok) { card.innerHTML = `<div class="fw-hc-load"><span class="fw-mono">${E(ip)}</span><small>No information available</small></div>`; place(); return; }
      c = cache[ip] = { at: Date.now(), data: await r.json() };
      if (openIP !== ip) return;
    }
    card.innerHTML = cardHTML(c.data); place();
    if (c.data.mac_hypervisor) loadOwner(ip, c);
    pollT = setInterval(() => { followAnchor(); if (openIP) refreshLive(openIP); }, 3000);
    refreshLive(ip);
  }
  document.addEventListener('mousemove', e => { mx = e.clientX; my = e.clientY; }, { passive: true });
  document.addEventListener('mouseover', e => {
    const a = e.target.closest && e.target.closest('.fw-ipi');
    if (!a) return;
    clearTimeout(hideT); clearTimeout(showT);
    if (a === anchor) return;
    if (a.dataset.ip === openIP) { anchor = a; return; }
    showT = setTimeout(() => open(a), 280);
  });
  document.addEventListener('mouseout', e => {
    const a = e.target.closest && e.target.closest('.fw-ipi');
    if (!a) return;
    clearTimeout(showT);
    if (anchor) hideT = setTimeout(close, 220);
  });
  // Touch screens: a tap opens it, a tap elsewhere closes it. A tap on an
  // address must not also trigger its row.
  document.addEventListener('click', e => {
    const touch = !matchMedia('(hover: hover)').matches;
    const a = e.target.closest && e.target.closest('.fw-ipi');
    if (a && touch) { e.preventDefault(); e.stopPropagation(); if (a.dataset.ip !== openIP) open(a); return; }
    if (touch && anchor && card && !card.contains(e.target)) close();
  }, true);
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && anchor) close(); });
  window.addEventListener('hashchange', close);
})();
