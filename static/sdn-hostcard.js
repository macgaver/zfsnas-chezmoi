/*
 * Firewall → the inside address card. Internal addresses on every Firewall page
 * get a dotted underline; hovering one (tapping on a touch
 * screen) opens a card with what GET /api/sdn/hostinfo knows about it.
 */
(function () {
  'use strict';
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
  // Every IPv4 address in the text: internal ones get the inside card, public
  // ones the Internet address card. Others (loopback, multicast, documentation
  // ranges…) stay plain.
  const ANY = /(^|[^\d.])(\d{1,3}(?:\.\d{1,3}){3})(?!\d|\.\d|\/(?!32\b))/g;
  const NOT_PUBLIC = /^(?:0\.|127\.|2(?:2[4-9]|[3-5]\d)\.|192\.0\.[02]\.|198\.1[89]\.|198\.51\.100\.|203\.0\.113\.)/;
  const kindOf = ip => !valid(ip) ? '' : INTERNAL_ONE.test(ip) ? 'in' : NOT_PUBLIC.test(ip) ? '' : 'pub';
  window.fwIsPublicIP = ip => kindOf(String(ip || '')) === 'pub';
  function mark(root) {
    const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const found = [];
    for (let n = walk.nextNode(); n; n = walk.nextNode()) {
      if (/\d\.\d/.test(n.nodeValue) && !n.parentElement.closest(SKIP)) found.push(n);
    }
    found.forEach(n => {
      const text = n.nodeValue;
      let last = 0, frag = null;
      ANY.lastIndex = 0;
      for (let m = ANY.exec(text); m; m = ANY.exec(text)) {
        const kind = kindOf(m[2]);
        if (!kind) continue;
        frag = frag || document.createDocumentFragment();
        const at = m.index + m[1].length;
        frag.append(text.slice(last, at));
        const s = document.createElement('span');
        s.className = 'fw-ipi'; s.dataset.ip = m[2]; s.textContent = m[2];
        if (kind === 'pub') s.dataset.pub = '1';
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


  // ── the Internet address card ───────────────────────────────────────────
  const isAdmin = () => typeof currentUser !== 'undefined' && currentUser && currentUser.role === 'admin';
  const SVC = {
    greynoise: ['GreyNoise', 'Is it an Internet-wide scanner, and is it known as harmful?'],
    shodan: ['Shodan', 'Its open ports, names, tags and known vulnerabilities (Shodan InternetDB)'],
    abuseipdb: ['AbuseIPDB', 'Abuse reports from other networks and a confidence score'],
  };
  function verdictOf(d) {
    if (d.lists.length) return ['off', 'On a blocklist'];
    const loaded = (d.list_state || []).some(l => l.entries);
    return loaded ? ['on', 'Not on blocklists'] : null;
  }
  function extHTML(svc, v, ip) {
    if (!v) return '';
    if (v.error) return `<div class="fw-hc-none fw-hc-err">${E(v.error)}</div>`;
    if (v.loading) return '<div class="fw-hc-none">Asking…</div>';
    const link = (href, t) => `<a class="fw-hc-link" href="${E(href)}" target="_blank" rel="noopener noreferrer">${E(t)}${icon('external-link', 11)}</a>`;
    if (svc === 'greynoise') {
      if (!v.found) return `<div class="fw-hc-none">Not seen scanning the Internet, and not a known business service.</div>`;
      const cls = v.classification === 'malicious' ? 'block' : v.classification === 'benign' ? 'allow' : '';
      return `<div class="fw-hc-kv">${row('Verdict', `<span class="fw-hc-act ${cls}">${E(v.classification || 'unknown')}</span>`)}${row('Scans the Internet', v.noise ? 'Yes' : 'No')}${row('Known service', v.riot ? 'Yes (common business service)' : '')}${row('Name', v.name && v.name !== 'unknown' ? E(v.name) : '')}${row('Last seen', E(v.last_seen || ''))}</div>${v.link ? link(v.link, 'Open in GreyNoise') : ''}`;
    }
    if (svc === 'shodan') {
      if (!v.found) return '<div class="fw-hc-none">Shodan knows nothing about this address.</div>';
      const vulns = v.vulns || [];
      return `<div class="fw-hc-kv">${row('Open ports', (v.ports || []).length ? E(v.ports.join(', ')) : 'None seen', 'fw-mono')}${row('Names', E((v.hostnames || []).slice(0, 4).join(', ')))}${row('Software', E((v.cpes || []).slice(0, 3).map(c => c.replace(/^cpe:\/[aho]:/, '').replace(/:/g, ' ')).join(', ')))}${row('Known CVEs', vulns.length ? `<b class="blk">${vulns.length}</b> ${E(vulns.slice(0, 4).join(', '))}${vulns.length > 4 ? '…' : ''}` : '')}</div>${(v.tags || []).length ? `<div class="fw-hc-tags" style="margin-top:6px">${v.tags.map(t => `<span>${E(t)}</span>`).join('')}</div>` : ''}${link('https://www.shodan.io/host/' + ip, 'Open in Shodan')}`;
    }
    const sc = +v.abuseConfidenceScore || 0, col = sc >= 50 ? 'var(--fw-blk)' : sc >= 15 ? '#ff9f0a' : '#30d158';
    return `<div class="fw-hc-score"><div><i style="width:${Math.max(2, sc)}%;background:${col}"></i></div><b style="color:${col}">${sc}%</b><small>abuse confidence</small></div>
      <div class="fw-hc-kv">${row('Reports', `${fmtN(v.totalReports)}${v.numDistinctUsers ? ` from ${fmtN(v.numDistinctUsers)} reporters` : ''} (90 days)`)}${row('Last report', v.lastReportedAt ? E(ago(v.lastReportedAt)) : '')}${row('Usage', E(v.usageType || ''))}${row('Provider', E(v.isp || ''))}${row('Domain', E(v.domain || ''))}${row('Tor', v.isTor ? 'Yes' : '')}${row('Allow-listed', v.isWhitelisted ? 'Yes' : '')}</div>${link('https://www.abuseipdb.com/check/' + ip, 'Open in AbuseIPDB')}`;
  }
  function pubCardHTML(d, ext) {
    const g = d.geo || {}, rd = d.rdap, v = verdictOf(d);
    const ptr = d.ptr.length ? d.ptr[0].name : '';
    const place = [g.city, g.country || g.cc].filter(Boolean).join(', ');
    const hero = `<div class="fw-hc-mac"><div><small>Network</small><b>${E(g.as_org || (rd && rd.org) || '—')}</b>${g.asn ? `<div class="fw-hc-dim fw-mono">AS${E(g.asn)}</div>` : ''}</div><div><small>Location</small><b>${flag(g.cc)}${E(place || 'Unknown')}</b></div></div>`;
    const rev = d.ptr.length ? d.ptr.map(p => `<div class="fw-hc-li"><span class="fw-hc-grow fw-mono">${E(p.name)}</span><span class="fw-hc-act ${p.confirmed ? 'allow' : ''}" title="${p.confirmed ? 'This name resolves back to the address' : 'This name does not resolve back to the address: it may be forged'}">${p.confirmed ? 'confirmed' : 'not confirmed'}</span></div>`).join('')
      : `<div class="fw-hc-none">${E(d.ptr_error || 'No reverse name')}</div>`;
    const reg = rd ? `<div class="fw-hc-kv">${row('Owner', E(rd.org || ''))}${row('Block', E(rd.name || ''))}${row('Range', E(rd.cidr || rd.range || ''), 'fw-mono')}${row('Country', rd.country ? flag(rd.country) + E(rd.country) : '')}${row('Abuse contact', rd.abuse ? `<a class="fw-hc-link" href="mailto:${E(rd.abuse)}">${E(rd.abuse)}</a>` : '')}${row('Registered', E(rd.created || ''))}${row('Changed', E(rd.updated || ''))}</div>`
      : `<div class="fw-hc-none">${E(d.rdap_error || 'No registry answer')}</div>`;
    const ls = d.list_state || [], loaded = ls.filter(l => l.entries);
    const newest = loaded.reduce((a, l) => (l.updated > a ? l.updated : a), '');
    const lists = d.lists.length ? d.lists.map(h => `<div class="fw-hc-li"><span class="fw-hc-act block">Listed</span><span class="fw-hc-grow"><span>${E(h.name)}</span><small title="${E(h.about)}">${E(h.entry)} · ${E(h.about)}</small></span></div>`).join('')
      : loaded.length ? `<div class="fw-hc-none" style="padding-top:0">Not on ${E(loaded.map(l => l.name).join(', '))}.</div>`
      : '<div class="fw-hc-none" style="padding-top:0">The lists are not downloaded yet: they come with the location databases (daily).</div>';
    const btns = Object.keys(SVC).map(k => {
      const off = !d.services[k];
      return `<button type="button" class="fw-hc-svc${ext[k] && !ext[k].error ? ' on' : ''}" data-ext="${k}" title="${E(SVC[k][1] + (off ? ' (needs a free API key)' : ''))}"${off && !isAdmin() ? ' disabled' : ''}>${E(SVC[k][0])}${off ? icon('key', 11) : ''}</button>`;
    }).join('');
    const results = Object.keys(SVC).filter(k => ext[k]).map(k => `<div class="fw-hc-ext"><h5>${E(SVC[k][0])}</h5>${extHTML(k, ext[k], d.ip)}</div>`).join('');
    return `<header class="fw-hc-head">
        <div class="fw-hc-avatar r-public">${icon('globe', 22)}</div>
        <div class="fw-hc-title"><div class="fw-hc-name${ptr ? '' : ' fw-mono'}">${E(ptr || d.ip)}</div><div class="fw-hc-sub">${ptr ? `<span class="fw-mono">${E(d.ip)}</span> · ` : ''}Internet address</div></div>
        ${v ? `<span class="fw-hc-state ${v[0]}"><i></i>${v[1]}</span>` : ''}
      </header>${hero}
      ${section('search', 'Reverse DNS', rev, 'PTR, checked forward')}
      ${section('file-text', 'Registry', reg, rd && rd.registry ? 'RDAP · ' + rd.registry : 'RDAP')}
      ${section('shield', 'Blocklists', lists, newest ? 'updated ' + ago(newest) : '')}
      <section class="fw-hc-s"><h4>${icon('globe', 13)}<span>Ask online</span><small>sends this address to the service</small></h4><div class="fw-hc-svcs">${btns}</div>${results}</section>`;
  }
  function keyDialog(after) {
    if (typeof window.sdnModal !== 'function') return;
    const box = document.createElement('div');
    box.innerHTML = `<p style="margin-top:0">AbuseIPDB is free for 1,000 checks a day with an account: <a href="https://www.abuseipdb.com/register" target="_blank" rel="noopener noreferrer">sign up</a>, then create a key under <a href="https://www.abuseipdb.com/account/api" target="_blank" rel="noopener noreferrer">API</a>.</p>
      <div class="fw-field"><label>API key</label><input type="password" id="fwk-abuse" autocomplete="new-password" placeholder="The key AbuseIPDB shows"></div>
      <div id="fwk-res" style="min-height:18px;margin-top:8px;font-size:12.5px;color:var(--fw-blk)"></div>`;
    const m = window.sdnModal({ title: 'AbuseIPDB key', body: box, buttons: [
      { label: 'Cancel' },
      { label: 'Save', cls: 'btn-primary', onClick: async (close, b) => {
        const k = box.querySelector('#fwk-abuse').value.trim();
        if (!k) { box.querySelector('#fwk-res').textContent = 'Paste the key first'; return; }
        b.disabled = true;
        const r = await fetch('/api/sdn/ipinfo/keys', { method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ abuseipdb_key: k }) }).catch(() => null);
        b.disabled = false;
        if (!r || !r.ok) { box.querySelector('#fwk-res').textContent = 'Not saved'; return; }
        close(); after();
      } }] });
    setTimeout(() => { const i = m && m.body.querySelector('#fwk-abuse'); if (i) i.focus(); }, 50);
    // the card sits above dialogs: out of the way until this one closes
    if (card && m) {
      card.style.visibility = 'hidden';
      const t = setInterval(() => { if (!document.body.contains(m.el)) { clearInterval(t); if (card) card.style.visibility = ''; } }, 250);
    }
  }
  async function askExt(ip, svc) {
    const c = cache['pub:' + ip];
    if (!c) return;
    c.ext = c.ext || {};
    if (!c.data.services[svc]) {
      if (isAdmin()) keyDialog(() => { c.data.services[svc] = true; askExt(ip, svc); });
      return;
    }
    if (c.ext[svc] && !c.ext[svc].error) { delete c.ext[svc]; redrawPub(ip); return; } // a second click folds it
    c.ext[svc] = { loading: true }; redrawPub(ip);
    const r = await fetch(`/api/sdn/ipinfo/ext?service=${svc}&ip=${encodeURIComponent(ip)}`, { credentials: 'same-origin' }).catch(() => null);
    let v = null;
    try { v = r ? await r.json() : null; } catch (e) { v = null; }
    c.ext[svc] = r && r.ok && v ? v : { error: (v && v.error) || 'No answer' };
    redrawPub(ip);
  }
  function redrawPub(ip) {
    const c = cache['pub:' + ip];
    if (!card || openIP !== ip || !c) return;
    const top = card.scrollTop;
    card.innerHTML = pubCardHTML(c.data, c.ext || {}); card.scrollTop = top; place();
  }

  // ── showing it ──────────────────────────────────────────────────────────
  const cache = {}; // ip → {at, data}
  // pinned: the user clicked inside the card (asked a service…): it stays
  // until a click elsewhere or Escape, even when the pointer leaves it.
  let card = null, anchor = null, openIP = '', showT = 0, hideT = 0, pollT = 0, mx = 0, my = 0, pinned = false;
  // The last input was a finger or a pen (iPad, iPhone): the card stays until
  // a tap elsewhere. iOS also sends mouse events after a tap, and an iPad with
  // a trackpad says it can hover, so neither of those may close it.
  let touchMode = !matchMedia('(hover: hover)').matches;
  document.addEventListener('pointerdown', e => { touchMode = e.pointerType !== 'mouse'; }, true);
  document.addEventListener('pointermove', e => { if (e.pointerType === 'mouse') touchMode = false; }, { passive: true }); // a real mouse or trackpad

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
    pollT = 0; anchor = null; openIP = ''; pinned = false;
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
    if (touchMode) {
      // no pointer to follow: the same address anywhere on the page, else the
      // card simply stays where it is
      const same = [...document.querySelectorAll('.fw-ipi')].find(x => x.dataset.ip === openIP);
      if (same) anchor = same;
      return;
    }
    const el = document.elementFromPoint(mx, my);
    if (pinned || (el && card.contains(el))) return;
    const a = el && el.closest('.fw-ipi');
    if (a && a.dataset.ip === openIP) anchor = a;
    else close();
  }
  async function open(el) {
    const ip = el.dataset.ip;
    if (!card) {
      card = document.createElement('div');
      card.className = 'fw-hostcard'; card.style.display = 'none';
      card.addEventListener('mouseenter', () => clearTimeout(hideT));
      card.addEventListener('mouseleave', () => { if (!touchMode && !pinned) hideT = setTimeout(close, 220); });
      card.addEventListener('click', e => {
        const x = e.target.closest('[data-ext]');
        if (x) { pinned = true; clearTimeout(hideT); askExt(openIP, x.dataset.ext); return; }
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
    anchor = el; openIP = ip; pinned = false;
    card.innerHTML = `<div class="fw-hc-load"><span class="fw-mono">${E(ip)}</span><small>Looking up…</small></div>`;
    card.style.display = 'block'; card.scrollTop = 0; place();
    if (el.dataset.pub) {
      let c = cache['pub:' + ip];
      if (!c || Date.now() - c.at > 600000) {
        const r = await fetch('/api/sdn/ipinfo?ip=' + encodeURIComponent(ip), { credentials: 'same-origin' }).catch(() => null);
        if (openIP !== ip) return;
        if (!r || !r.ok) { card.innerHTML = `<div class="fw-hc-load"><span class="fw-mono">${E(ip)}</span><small>No information available</small></div>`; place(); return; }
        c = cache['pub:' + ip] = { at: Date.now(), data: await r.json(), ext: (c && c.ext) || {} };
        if (openIP !== ip) return;
      }
      card.innerHTML = pubCardHTML(c.data, c.ext); place();
      pollT = setInterval(followAnchor, 3000);
      return;
    }
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
    if (touchMode) return; // iOS's mouse events after a tap
    const a = e.target.closest && e.target.closest('.fw-ipi');
    if (!a) return;
    clearTimeout(hideT); clearTimeout(showT);
    if (a === anchor) return;
    if (a.dataset.ip === openIP) { anchor = a; return; }
    showT = setTimeout(() => open(a), 280);
  });
  document.addEventListener('mouseout', e => {
    if (touchMode) return;
    const a = e.target.closest && e.target.closest('.fw-ipi');
    if (!a) return;
    clearTimeout(showT);
    if (anchor && !pinned) hideT = setTimeout(close, 220);
  });
  // Touch screens: a tap opens it, a tap elsewhere closes it. A tap on an
  // address must not also trigger its row.
  document.addEventListener('click', e => {
    const touch = touchMode;
    const a = e.target.closest && e.target.closest('.fw-ipi');
    if (a && touch) { e.preventDefault(); e.stopPropagation(); if (a.dataset.ip !== openIP) open(a); return; }
    if ((touch || pinned) && anchor && card && !card.contains(e.target) && !e.target.closest('.modal-backdrop')) close();
  }, true);
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && anchor) close(); });
  window.addEventListener('hashchange', close);
  // another page of the app (the side menu, a link): the card goes with it
  if (typeof window.showPage === 'function' && !window.showPage._fwHc) {
    const orig = window.showPage;
    window.showPage = function () { close(); return orig.apply(this, arguments); };
    window.showPage._fwHc = true;
  }
})();
