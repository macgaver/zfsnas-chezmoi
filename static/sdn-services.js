/*
 * Firewall → DHCP & DNS and WireGuard (SDN phase 4). Spec: PLANS/spec-sdn-firewall.md §11.2, §11.3.
 *
 * DHCP & DNS: one dnsmasq of our own (unit znas-sdn-dns) serves the LAN
 * interfaces you choose; DHCP hostnames are registered in DNS. Live leases
 * come from GET /api/sdn/dhcp/leases ("Make static" turns one into a
 * reservation).
 * WireGuard: a tunnel is an interface of kind "wireguard" (its key is made on
 * the server at draft save and never reaches the browser). "Generate for me"
 * peers get a key pair from POST /api/sdn/wireguard/keys: the client config
 * and QR code are shown once, only the public key is stored.
 */
(function () {
  'use strict';

  let F = null;
  let svc = null;          // GET /api/sdn/services
  let leases = [];         // GET /api/sdn/dhcp/leases
  let unnamed = null;      // GET /api/sdn/unnamed-hosts (null = not read yet)
  let unnamedTick = 0;
  const unnamedTyped = {}; // ip → what the admin typed, across page refreshes
  let incusNets = [];      // GET /api/sdn/incus-networks (Incus' own DHCP/DNS: read-only)
  let wgLive = {};         // GET /api/sdn/wireguard/status

  const ifaceById = id => F.cfg().interfaces.find(i => i.id === id);
  const lanIfaces = () => F.cfg().interfaces.filter(i => i.role !== 'wan' && i.kind !== 'wireguard' && i.ipv4_mode === 'static');
  const tunnels = () => F.cfg().interfaces.filter(i => i.kind === 'wireguard');
  const dot = i => `<span class="fw-cdot" style="background:${F.C(i && i.color)}"></span>`;
  const ipOf = cidr => String(cidr || '').split('/')[0];

  // IPv4 helpers (tunnel/peer address suggestions).
  const ip2n = s => s.split('.').reduce((a, x) => a * 256 + Number(x), 0);
  const n2ip = n => [24, 16, 8, 0].map(b => Math.floor(n / 2 ** b) % 256).join('.');
  const listOf = s => s.split(/[\s,]+/).filter(Boolean);
  const cidrOK = s => { const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)(?:\/(\d+))?$/.exec(s); return !!m && m.slice(1, 5).every(x => Number(x) <= 255) && (m[5] === undefined || (Number(m[5]) >= 1 && Number(m[5]) <= 32)); };
  const netOf = cidr => { const [a, b] = String(cidr).split('/'); const bits = Number(b); const size = 2 ** (32 - bits); return { base: Math.floor(ip2n(a) / size) * size, size, bits }; };

  function fmtBytes(n) {
    n = Number(n || 0);
    const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
    return (i ? n.toFixed(1) : n) + ' ' + u[i];
  }
  function ago(iso) {
    if (!iso || iso.startsWith('0001')) return 'never';
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 90) return Math.round(s) + ' s ago';
    if (s < 5400) return Math.round(s / 60) + ' min ago';
    if (s < 172800) return Math.round(s / 3600) + ' h ago';
    return Math.round(s / 86400) + ' days ago';
  }

  async function install(pkg, btn) {
    btn.disabled = true; btn.textContent = 'Installing…';
    const r = await F.api('POST', '/api/prereqs/install', { package: pkg });
    if (r.ok) { F.toast(pkg + ' installed', 'success'); await loadSvc(); F.rerender(); }
    else { btn.disabled = false; btn.textContent = 'Install'; F.toast((r.data && r.data.error) || 'Install failed', 'error'); }
  }
  const installBanner = (what, pkg) => `<div class="fw-safemode" style="background:rgba(255,214,10,.10);border-color:rgba(255,214,10,.4)">${F.icon('info', 16)}
    <div>${what} needs the <b>${F.E(pkg)}</b> package on this server.</div><span style="flex:1"></span>${F.isAdmin() ? `<button class="fw-btn" data-install="${F.E(pkg)}">Install</button>` : ''}</div>`;

  async function loadSvc() {
    const r = await F.api('GET', '/api/sdn/services');
    svc = r.ok ? r.data : null;
  }

  // ── DHCP & DNS ─────────────────────────────────────────────────────────
  async function loadDHCP() {
    const [, r, inc] = await Promise.all([loadSvc(), F.api('GET', '/api/sdn/dhcp/leases'), F.api('GET', '/api/sdn/incus-networks')]);
    leases = r.ok ? (r.data || []) : [];
    incusNets = inc.ok ? (inc.data || []) : [];
    // The heavier of the page's reads, and slow to change: once a minute.
    if (unnamed === null || unnamedTick++ % 6 === 0) await loadUnnamed();
  }
  async function loadUnnamed() {
    const r = await F.api('GET', '/api/sdn/unnamed-hosts');
    if (r.ok) unnamed = r.data || [];
  }

  // ── Unknown Internal IP/FQDN matching ──
  // What a draft already says about an address, until it is applied.
  function pendingName(c, h) {
    const d = c.dhcp.find(x => x.interface === h.interface);
    const mac = (h.mac || '').toLowerCase();
    if (d && mac) {
      const n = (d.names || []).find(x => x.mac === mac);
      if (n) return n.hostname;
      const r = d.reservations.find(x => x.mac === mac && x.hostname);
      if (r) return r.hostname;
    }
    const s = c.dns.hosts.find(x => x.ip === h.ip);
    return s ? s.name : '';
  }
  const KIND_LABEL = { 'this-server': 'This server', vip: 'Virtual IP', router: 'Router', vm: 'Virtual machine', container: 'Container', vpn: 'VPN client', device: 'Device' };
  const BIND = {
    lease: ['DHCP', 'The name goes with this MAC address, so it follows the device if its address changes. It reaches DNS once applied.'],
    reserved: ['Reserved', 'The name is added to this device\'s DHCP reservation.'],
    static: ['Static', 'A fixed DNS record for this address. If the device moves to another address, the record stays here.'],
  };
  const suggestName = h => (h.instance || h.peer || '').toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63);
  function unnamedHTML(c, admin) {
    if (unnamed === null) return '';
    const rows = unnamed.map(h => {
      const pending = pendingName(c, h);
      const [bind, bindTip] = BIND[h.binding] || BIND.static;
      const what = h.instance ? `<b>${F.E(h.instance)}</b> <span class="fw-sub">${F.E(KIND_LABEL[h.kind] || '')}${h.os ? ' · ' + F.E(h.os) : ''}</span>`
        : h.peer ? `<b>${F.E(h.peer)}</b> <span class="fw-sub">VPN client</span>`
        : h.kind !== 'device' ? `<b>${F.E(KIND_LABEL[h.kind] || h.kind)}</b>${h.note ? ` <span class="fw-sub">${F.E(h.note)}</span>` : ''}`
        : h.mac_private ? '<span class="fw-sub">Private MAC, chosen by the device</span>'
        : h.vendor ? F.E(h.vendor) : `<span class="fw-sub">${h.mac ? 'Maker not listed' : 'Never seen on the network'}</span>`;
      const typed = unnamedTyped[h.ip] != null ? unnamedTyped[h.ip] : suggestName(h);
      const suffix = h.domain ? `<span class="fw-un-dom fw-mono">.${F.E(h.domain)}</span>` : '';
      const set = pending ? `<span class="fw-badge lan" style="text-transform:none" title="In the draft: Apply to make it real">${F.E(pending)} — not applied</span>`
        : admin ? `<span class="fw-un-set"><input type="text" class="input fw-un-in" data-unip="${F.E(h.ip)}" value="${F.E(typed)}" placeholder="name" maxlength="${h.binding === 'static' ? 253 : 63}" aria-label="Name for ${F.E(h.ip)}">${suffix}<button class="fw-icon-btn" data-unset="${F.E(h.ip)}">Set</button></span>` : '';
      return `<tr><td><span class="fw-pillx"><span class="fw-cdot" style="background:${F.C(h.color)}"></span>${F.E(h.network)}</span></td>
        <td class="fw-mono">${F.E(h.ip)}</td><td>${what}</td><td class="fw-mono">${F.E(h.mac || '—')}</td>
        <td><span class="fw-badge none" title="${F.E(bindTip)}">${bind}</span></td><td>${set}</td></tr>`;
    }).join('');
    const named = c.dhcp.flatMap(d => (d.names || []).map(n => ({ d, n })));
    const namedRows = named.map(({ d, n }) => {
      const i = c.interfaces.find(x => x.id === d.interface);
      return `<div class="fw-un-named"><span class="fw-mono">${F.E(n.hostname)}</span><span class="fw-sub">${F.E(i ? i.name : '')} · <span class="fw-mono">${F.E(n.mac)}</span></span>${admin ? `<button class="fw-icon-btn" data-unrm="${F.E(n.mac)}" data-if="${F.E(d.interface)}">Remove</button>` : ''}</div>`;
    }).join('');
    return `<div class="fw-tcard" style="margin-top:18px"><div class="fw-tch"><h3>Unknown Internal IP/FQDN matching</h3>
        ${F.info('Unknown Internal IP/FQDN matching', '<p>Addresses on your networks with no name: no DHCP host name, no DNS record here and no reverse DNS answer.</p><ul><li><b>DHCP:</b> the name follows the device\'s MAC address, whatever address it leases next.</li><li><b>Reserved:</b> the name goes on its reservation.</li><li><b>Static:</b> a fixed DNS record for the address, for anything DHCP here does not hand out.</li></ul><p>A device using a private MAC can change it, and then loses its name. Names reach DNS after Apply.</p>')}
        <span class="fw-sub">${unnamed.length} address${unnamed.length === 1 ? '' : 'es'} · refreshed every minute</span></div>
      <div class="fw-tscroll"><table class="fw-table"><thead><tr><th>Network</th><th>Address</th><th>What it may be</th><th>MAC</th><th>Type</th><th>Name</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="6" style="color:var(--text-3)">Every address has a name.</td></tr>'}</tbody></table></div>
      ${named.length ? `<div class="fw-un-list"><div class="fw-sub">Names following a device (${named.length})</div>${namedRows}</div>` : ''}</div>`;
  }
  function saveUnnamed(h, typed) {
    let name = typed.trim().replace(/\.$/, '');
    if (h.domain && name.toLowerCase().endsWith('.' + h.domain.toLowerCase())) name = name.slice(0, -h.domain.length - 1);
    if (!name) { F.toast('Enter a name', 'error'); return; }
    const label = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(name);
    if (h.binding !== 'static' && !label) { F.toast(`Letters, digits and - only${h.domain ? `: the domain .${h.domain} is added for you` : ''}`, 'error'); return; }
    if (h.binding === 'static' && !/^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(name)) { F.toast('Letters, digits, dots and - only', 'error'); return; }
    F.saveDraft(n => {
      if (h.binding === 'static') {
        n.dns.hosts.push({ name: label && h.domain ? name + '.' + h.domain : name, ip: h.ip });
        return;
      }
      const d = n.dhcp.find(x => x.interface === h.interface);
      if (!d) return false;
      const mac = h.mac.toLowerCase();
      if (h.binding === 'reserved') {
        const r = d.reservations.find(x => x.mac === mac);
        if (!r) return false;
        r.hostname = name;
      } else {
        d.names = d.names || [];
        d.names.push({ mac, hostname: name });
      }
    }).then(ok => { if (ok) { delete unnamedTyped[h.ip]; F.toast(`${name} is in the draft — Apply to make it real`, 'success'); } });
  }

  // Why a network's DHCP server is not running ("" when it is, or when the
  // configuration was not applied yet).
  function dhcpDown(id) {
    const d = F.cfg().dhcp.find(x => x.interface === id), st = F.status() || {};
    const n = svc && svc.dhcp && svc.dhcp[id];
    if (!d || !d.enabled || !st.enabled || !n) return '';
    return n.running && !n.error ? '' : (n.error || 'not running');
  }

  function dhcpHTML() {
    const c = F.cfg(), admin = F.isAdmin(), dns = c.dns;
    const st = F.status() || {};
    const used = c.dns.enabled || c.dhcp.some(d => d.enabled);
    const nets = lanIfaces();
    const running = svc && svc.dns_running;
    const cards = nets.map(i => {
      const d = c.dhcp.find(x => x.interface === i.id);
      const on = d && d.enabled;
      const n = leases.filter(l => l.interface === i.id).length;
      const dnsHere = dns.enabled && dns.interfaces.includes(i.id);
      return `<div class="fw-card">
        <div class="fw-stripe" style="background:${F.C(i.color)}"></div>
        <div class="fw-card-h"><span class="fw-name">${F.E(i.name)}</span>
          <span class="fw-gwstate ${on ? 'up' : 'none'}">${on ? 'DHCP on' : 'DHCP off'}</span>
          ${dhcpDown(i.id) ? `<span class="fw-badge" style="background:rgba(255,69,58,.14);color:var(--fw-blk);margin-left:6px" title="${F.E(dhcpDown(i.id))}">not running</span>` : ''}</div>
        <div class="fw-kv"><span>Network</span><span class="fw-mono">${F.E(i.ipv4)}</span>
          <span>Range</span><span class="fw-mono">${on ? F.E(d.range_start + ' – ' + d.range_end) + ((d.exclude || []).length ? `<br><span style="color:var(--text-3)">except ${F.E(d.exclude.join(', '))}</span>` : '') : '—'}</span>
          <span>Lease</span><span>${on ? F.E(d.lease_hours + ' h') : '—'}</span>
          <span>Address check</span><span>${on ? (d.no_ping ? 'off' : 'on (ping first)') : '—'}</span>
          <span>Gateway</span><span class="fw-mono">${on ? F.E(d.gateway || ipOf(i.ipv4)) : '—'}</span>
          <span>DNS given</span><span class="fw-mono">${on ? F.E(d.dns_servers.length ? d.dns_servers.join(', ') : (dnsHere ? ipOf(i.ipv4) + ' (this router)' : '—')) : '—'}</span>
          ${on && (d.ntp_servers || []).length ? `<span>NTP given</span><span class="fw-mono">${F.E(d.ntp_servers.join(', '))}</span>` : ''}
          ${on && (d.routes || []).length ? `<span>Routes</span><span class="fw-mono">${d.routes.map(r => F.E(r.network + ' via ' + r.via)).join('<br>')}</span>` : ''}
          <span>Reserved</span><span>${d ? d.reservations.length : 0} address${d && d.reservations.length === 1 ? '' : 'es'} · ${n} lease${n === 1 ? '' : 's'}</span></div>
        ${admin ? `<div class="fw-card-actions"><button class="fw-icon-btn" data-dhcp="${F.E(i.id)}">${F.icon('pencil', 12)}${d ? 'Edit' : 'Set up DHCP'}</button></div>` : ''}
      </div>`;
    }).join('');
    const leaseRows = leases.slice().sort((a, b) => (a.interface || '').localeCompare(b.interface || '') || ip2n(a.ip) - ip2n(b.ip)).map(l => {
      const i = ifaceById(l.interface);
      const d = c.dhcp.find(x => x.interface === l.interface);
      const reserved = d && d.reservations.some(r => r.mac === l.mac.toLowerCase());
      const exp = !l.expires || l.expires.startsWith('0001') ? 'never' : F.fmtTime(l.expires);
      return `<tr><td>${i ? `<span class="fw-pillx">${dot(i)}${F.E(i.name)}</span>` : '—'}</td><td>${F.E(l.hostname || '—')}</td>
        <td class="fw-mono">${F.E(l.ip)}</td><td class="fw-mono">${F.E(l.mac)}</td><td>${F.E(exp)}</td>
        <td>${reserved ? '<span class="fw-badge lan">reserved</span>' : (admin && d ? `<button class="fw-icon-btn" data-static="${F.E(l.mac)}" data-ip="${F.E(l.ip)}" data-host="${F.E(l.hostname || '')}" data-if="${F.E(l.interface)}">${F.icon('pin', 12)}Make static</button>` : '')}</td></tr>`;
    }).join('');
    // Incus networks (host-nat): Incus' own dnsmasq serves them; shown, not changed here.
    const incusTag = n => admin
      ? `<button type="button" class="fw-badge none fw-incus-link" data-incus-net="${F.E(n.name)}" title="Incus runs DHCP and DNS on this network. Click to edit ${F.E(n.name)} under Infrastructure, Networking.">Incus</button>`
      : `<span class="fw-badge none" title="Incus runs DHCP and DNS on this network. It is changed under Infrastructure, Networking.">Incus</span>`;
    const incusPill = n => `<span class="fw-pillx">${dot(null)}${F.E(n.name)}</span> ${incusTag(n)}`;
    const incusCards = incusNets.map(n => `<div class="fw-card fw-incus-card">
        <div class="fw-stripe" style="background:var(--text-3)"></div>
        <div class="fw-card-h"><span class="fw-name">${F.E(n.name)}</span>
          ${incusTag(n)}
          <span class="fw-gwstate ${n.dhcp ? 'up' : 'none'}" style="margin-left:auto">${n.dhcp ? 'DHCP on' : 'DHCP off'}</span></div>
        <div class="fw-kv"><span>Network</span><span class="fw-mono">${F.E(n.address)}</span>
          <span>Range</span><span class="fw-mono">${n.dhcp && (n.dhcp_ranges || []).length ? F.E(n.dhcp_ranges.map(x => x.replace('-', ' – ')).join(', ')) : '—'}</span>
          <span>Gateway</span><span class="fw-mono">${F.E(ipOf(n.address))}${n.nat ? ' · NAT' : ''}</span>
          <span>DNS</span><span>${n.dns ? `<span class="fw-mono">name.${F.E(n.domain)}</span>, answered by Incus` : 'off'}</span>
          <span>Leases</span><span>${n.leases.length} device${n.leases.length === 1 ? '' : 's'}</span></div>
      </div>`).join('');
    const incusRows = incusNets.flatMap(n => n.leases.map(l => ({ n, l }))).sort((a, b) => a.n.name.localeCompare(b.n.name) || ip2n(a.l.address) - ip2n(b.l.address))
      .map(({ n, l }) => `<tr><td>${incusPill(n)}</td><td>${F.E(l.hostname || '—')}</td>
        <td class="fw-mono">${F.E(l.address)}</td><td class="fw-mono">${F.E(l.mac || '—')}</td><td>—</td>
        <td>${l.type === 'static' ? '<span class="fw-badge lan" title="Fixed in the instance\'s settings (VMs &amp; Containers)">reserved</span>' : ''}</td></tr>`).join('');
    const nLeases = leases.length + incusNets.reduce((a, n) => a + n.leases.length, 0);
    const dnsNets = dns.interfaces.map(id => ifaceById(id)).filter(Boolean);
    return `
      ${svc && !svc.dnsmasq_installed ? installBanner('DHCP and DNS', 'dnsmasq-base') : ''}
      ${used && st.enabled && svc && svc.dnsmasq_installed && svc.dns_configured && !running ? `<div class="fw-safemode">${F.icon('info', 16)}<div><b>DNS is not running</b> — check the <span class="fw-mono">znas-sdn-dns</span> service.</div></div>` : ''}
      <div class="fw-note" style="margin-bottom:10px">One DHCP server per network, from this router. Devices that get an address here are registered in DNS by name${dns.domain ? ` (<span class="fw-mono">name.${F.E(dns.domain)}</span>)` : ''}. DHCP and DNS are allowed through the firewall automatically on the networks they serve.</div>
      <h3 style="margin:14px 0 8px;font-size:13px">DHCP</h3>
      ${nets.length || incusNets.length ? `<div class="fw-cards">${cards}${incusCards}</div>` : '<div class="fw-empty">No network with a static address yet — DHCP serves LAN interfaces that have their own address (Interfaces page).</div>'}
      <h3 style="margin:18px 0 8px;font-size:13px">DNS</h3>
      <div class="fw-card">
        <div class="fw-card-h">${F.icon('globe', 15)}<span class="fw-name">Local DNS</span>
          <span class="fw-gwstate ${dns.enabled ? 'up' : 'none'}">${dns.enabled ? 'On' : 'Off'}</span>
          ${dns.enabled && st.enabled ? `<span class="fw-badge ${running ? 'lan' : 'none'}" style="margin-left:8px">${running ? 'running' : 'not running'}</span>` : ''}</div>
        <div class="fw-kv"><span>Answers on</span><span>${dnsNets.length ? dnsNets.map(i => `<span class="fw-pillx">${dot(i)}${F.E(i.name)}</span>`).join(' ') : '—'}</span>
          <span>Upstream</span><span class="fw-mono">${F.E(dns.upstreams.length ? dns.upstreams.join(', ') : 'this server\'s resolvers')}</span>
          <span>Local domain</span><span class="fw-mono">${F.E(dns.domain || '—')}</span>
          <span>Host names</span><span>${dns.hosts.length} override${dns.hosts.length === 1 ? '' : 's'}</span>
          <span>Forwarding</span><span>${dns.forwards.length ? dns.forwards.map(f => F.E(f.domain + ' → ' + f.server)).join(', ') : '—'}</span>
          <span>Blocklists</span><span>${(dns.blocklists || []).filter(l => l.enabled).length} list${(dns.blocklists || []).filter(l => l.enabled).length === 1 ? '' : 's'} · ${(dns.allow || []).length} allowed · ${(dns.deny || []).length} blocked domain${(dns.deny || []).length === 1 ? '' : 's'}</span>
          <span>Advanced metrics</span><span>${dns.metrics ? `on — <a href="#" onclick="showPage('fw-dns');return false">see the reports</a>` : 'off'}</span></div>
        ${admin ? `<div class="fw-card-actions"><button class="fw-icon-btn" id="fw-dns-edit">${F.icon('pencil', 12)}Edit</button></div>` : ''}
      </div>
      ${unnamedHTML(c, admin)}
      <div class="fw-tcard" style="margin-top:18px"><div class="fw-tch"><h3>Leases</h3><span class="fw-sub">${nLeases} device${nLeases === 1 ? '' : 's'} · refreshed every 10 s</span></div>
        <div class="fw-tscroll"><table class="fw-table"><thead><tr><th>Network</th><th>Host name</th><th>Address</th><th>MAC</th><th>Expires</th><th></th></tr></thead>
        <tbody>${leaseRows + incusRows || '<tr><td colspan="6" style="color:var(--text-3)">No lease yet.</td></tr>'}</tbody></table></div></div>`;
  }

  function wireDHCP(root) {
    root.querySelectorAll('[data-install]').forEach(b => b.onclick = () => install(b.dataset.install, b));
    root.querySelectorAll('[data-dhcp]').forEach(b => b.onclick = () => editDHCP(b.dataset.dhcp));
    root.querySelectorAll('[data-incus-net]').forEach(b => b.onclick = () => openBridgeEditorFromFirewall(b.dataset.incusNet));
    const de = root.querySelector('#fw-dns-edit');
    if (de) de.onclick = editDNS;
    root.querySelectorAll('.fw-un-in').forEach(i => {
      i.oninput = () => { unnamedTyped[i.dataset.unip] = i.value; };
      i.onkeydown = e => { if (e.key === 'Enter') { const h = unnamed.find(x => x.ip === i.dataset.unip); if (h) saveUnnamed(h, i.value); } };
    });
    root.querySelectorAll('[data-unset]').forEach(b => b.onclick = () => {
      const h = unnamed.find(x => x.ip === b.dataset.unset), i = root.querySelector(`.fw-un-in[data-unip="${b.dataset.unset}"]`);
      if (h && i) saveUnnamed(h, i.value);
    });
    root.querySelectorAll('[data-unrm]').forEach(b => b.onclick = () => F.saveDraft(n => {
      const d = n.dhcp.find(x => x.interface === b.dataset.if);
      if (!d) return false;
      d.names = (d.names || []).filter(x => x.mac !== b.dataset.unrm);
    }).then(ok => { if (ok) F.toast('Name removed from the draft — Apply to take effect', 'success'); }));
    root.querySelectorAll('[data-static]').forEach(b => b.onclick = () => F.saveDraft(n => {
      const d = n.dhcp.find(x => x.interface === b.dataset.if);
      if (!d) return false;
      d.reservations = d.reservations || [];
      const mac = b.dataset.static.toLowerCase();
      // A name that was following this device moves onto its reservation.
      const had = (d.names || []).find(x => x.mac === mac);
      if (had) d.names = d.names.filter(x => x !== had);
      d.reservations.push({ mac, ip: b.dataset.ip, hostname: had ? had.hostname : (b.dataset.host || '').replace(/[^A-Za-z0-9-]/g, '').slice(0, 63) });
    }).then(ok => { if (ok) F.toast('Reservation added to the draft — Apply to keep it', 'success'); }));
  }

  // ── DHCP "i" cards ──
  const TIP = {
    serve: ['Serve DHCP', '<p>This router hands out addresses automatically to the devices of this network.</p><p>Turn it off to keep these settings but stop answering — for example while another DHCP server is still in charge of the network.</p>'],
    range: ['Address range', '<p>The addresses handed out to devices that have no reservation, from the first to the last.</p><p>Keep it away from addresses set by hand on devices (servers, printers, switches): leave those outside the range, or exclude them below.</p>'],
    exclude: ['Excluded addresses', '<p>Addresses inside the range that are <b>never handed out</b> — a block kept for devices configured by hand, or for a virtual IP.</p><p>Single addresses or first-last ranges, separated by commas:<code class="fw-ex">10.0.0.120-10.0.0.129, 10.0.0.140</code></p><p>One wide range with a few holes is the same as several ranges.</p>'],
    lease: ['Lease time', '<p>How long a device keeps its address before it must ask again. Devices renew at half the time.</p><ul><li><b>Short (1–4 h)</b>: changes (DNS, gateway, routes) reach devices quickly — useful during a migration.</li><li><b>Long (24 h and more)</b>: less DHCP traffic; devices that come and go keep their address longer.</li></ul>'],
    gw: ['Gateway handed out', '<p>The router devices send their traffic to, for other networks and the Internet (DHCP option 3).</p><p>Empty: this router\'s address in this network — or its virtual IP when that one is marked <b>clients\' gateway</b>.</p>'],
    dns: ['DNS servers handed out', '<p>The name servers devices use, in order of preference (DHCP option 6). Most devices try the next one when the first does not answer.</p><p>Several: separate them with commas, e.g. <code>10.0.0.1, 1.1.1.1</code>.</p><p>Empty: this router, when Local DNS answers on this network.</p>'],
    ntp: ['Time servers (NTP)', '<p>Time servers devices may use to set their clock (DHCP option 42).</p><p><b>Addresses only</b> — DHCP cannot hand out names like <code>pool.ntp.org</code>.</p><p>Windows, macOS and phones usually ignore it and keep their own time server; Linux, network equipment, cameras and printers often use it.</p>'],
    domain: ['Domain', '<p>The DNS suffix devices add to short names: with <code>home.lan</code>, looking up <code>nas</code> also tries <code>nas.home.lan</code> (DHCP option 15).</p><p>Empty: the Local DNS domain.</p>'],
    routes: ['Routes handed out', '<p>Networks devices reach through <b>another router</b> in this network than the gateway — a VPN box, or another site\'s router: <code>10.20.0.0/16 via 10.0.0.254</code>.</p><p>Sent as DHCP options 121 and 249 (Windows). A device that receives routes ignores the plain gateway option, so the default route through the gateway is always added at the end.</p><p>The router must be in this network.</p>'],
    res: ['Reserved addresses', '<p>A device, recognised by its MAC address, always gets the same address. The address can be inside or outside the range — outside is cleaner. The name is registered in Local DNS.</p><p>Under <b>Options</b>, the device can get its own gateway, DNS servers or lease time instead of the network\'s — for example a camera sent to another gateway, or a server with a 7-day lease.</p>'],
    rgw: ['Gateway for this device', '<p>Replaces the network\'s gateway for this device only. With routes on the network, its default route uses this gateway too.</p><p>Empty: the network\'s gateway.</p>'],
    rdns: ['DNS servers for this device', '<p>Replaces the network\'s DNS servers for this device only. Several: separate them with commas.</p><p>Empty: the network\'s DNS servers.</p>'],
    rlease: ['Lease time for this device', '<p>Replaces the network\'s lease time for this device only, in hours (1 to 8760).</p><p>Empty: the network\'s lease time.</p>'],
    check: ['Address check before offering', '<p>Before offering an address that is not reserved, this server <b>pings</b> it. If a device answers, the address is skipped and another one is offered.</p><p>Useful while a network moves from another DHCP server: devices still holding an address from the old server are not given away twice.</p><ul><li>Waits up to <b>3 s</b> for an answer (fixed in dnsmasq), only when offering a new address. A device that renews its own address is not delayed.</li><li>An address that did not answer is not pinged again for 30 s.</li><li>Devices that block ping (Windows firewall on public networks, some IoT) are not seen. Most devices also check the address themselves and refuse it if it is in use.</li></ul><p>Each network has its own DHCP server, so the check is set per network: on for a network moving from another DHCP server, off where new devices join all day (a guest network) and the 3 s matter.</p>'],
  };
  const tip = (k, label) => F.lab(label, TIP[k][0], TIP[k][1]);
  // The range minus the excluded addresses (same as the server's Pools()).
  function poolsOf(start, end, exText) {
    const ok = a => /^\d+\.\d+\.\d+\.\d+$/.test(a);
    if (!ok(start) || !ok(end) || ip2n(end) < ip2n(start)) return null;
    const ex = ipList(exText).map(e => e.split('-')).filter(p => p.every(ok)).map(p => [ip2n(p[0]), ip2n(p[1] || p[0])]).filter(p => p[1] >= p[0]).sort((a, b) => a[0] - b[0]);
    const out = [];
    let cur = ip2n(start); const last = ip2n(end);
    for (const [a, b] of ex) {
      if (a > cur && cur <= Math.min(a - 1, last)) out.push([cur, Math.min(a - 1, last)]);
      cur = Math.max(cur, b + 1);
      if (cur > last) return out;
    }
    out.push([cur, last]);
    return out;
  }
  const ipList = v => String(v || '').split(/[\s,;]+/).filter(Boolean);
  // What a reserved address gets instead of the network's settings.
  const resOwn = r => [r.gateway && 'gateway ' + r.gateway, (r.dns_servers || []).length && 'DNS ' + r.dns_servers.join(', '), r.lease_hours && r.lease_hours + ' h lease'].filter(Boolean);

  function editDHCP(ifId) {
    const c = F.cfg(), i = ifaceById(ifId);
    const idx = c.dhcp.findIndex(x => x.interface === ifId);
    const net = netOf(i.ipv4), own = ip2n(ipOf(i.ipv4));
    // Suggest the upper part of the network, away from the router's address.
    const lo = net.base + Math.max(1, Math.floor(net.size / 2)), hi = net.base + net.size - 2;
    const d = idx >= 0 ? F.clone(c.dhcp[idx]) : { interface: ifId, enabled: true, range_start: n2ip(lo === own ? lo + 1 : lo), range_end: n2ip(hi), lease_hours: 12, gateway: '', dns_servers: [], domain: '', reservations: [] };
    const dnsHere = c.dns.enabled && c.dns.interfaces.includes(ifId);
    const dr = F.drawer(`DHCP on ${i.name}`, `Hands out addresses in <b class="fw-mono">${F.E(i.ipv4)}</b>`, `
      <div class="fw-lab">${F.cb('fwd-en', 'Serve DHCP on this network', d.enabled)}${F.info(TIP.serve[0], TIP.serve[1])}</div>
      <div class="fw-row2" style="margin-top:12px"><div class="fw-field">${tip('range', 'First address')}<input type="text" id="fwd-start" value="${F.E(d.range_start)}"><div class="fw-err" id="fwd-start-err"></div></div>
        <div class="fw-field"><div class="fw-lab"><label>Last address</label></div><input type="text" id="fwd-end" value="${F.E(d.range_end)}"><div class="fw-err" id="fwd-end-err"></div></div></div>
      <div class="fw-field">${tip('exclude', 'Excluded addresses — optional')}<input type="text" id="fwd-ex" value="${F.E((d.exclude || []).join(', '))}" placeholder="e.g. ${F.E(n2ip(lo + 20))}-${F.E(n2ip(lo + 29))}, ${F.E(n2ip(lo + 40))}">
        <div class="fw-pools" id="fwd-pools"></div><div class="fw-err" id="fwd-ex-err"></div></div>
      <div class="fw-lab" style="margin:-2px 0 14px">${F.cb('fwd-ping', 'Check an address is free before offering it (ping, up to 3 s)', !d.no_ping)}${F.info(TIP.check[0], TIP.check[1])}</div>
      <div class="fw-row2"><div class="fw-field">${tip('lease', 'Lease time (hours)')}<input type="number" id="fwd-lease" min="1" max="8760" value="${F.E(d.lease_hours)}"><div class="fw-err" id="fwd-lease-err"></div></div>
        <div class="fw-field">${tip('gw', 'Gateway handed out')}<input type="text" id="fwd-gw" value="${F.E(d.gateway || '')}" placeholder="${F.E(ipOf(i.ipv4))} (this router)"><div class="fw-err" id="fwd-gw-err"></div></div></div>
      <div class="fw-field">${tip('dns', 'DNS servers handed out')}<input type="text" id="fwd-dns" value="${F.E(d.dns_servers.join(', '))}" placeholder="${dnsHere ? F.E(ipOf(i.ipv4)) + ' (this router)' : 'e.g. 1.1.1.1, 9.9.9.9 — or turn on DNS for this network'}"><div class="fw-err" id="fwd-dns-err"></div></div>
      <div class="fw-field">${tip('ntp', 'Time servers (NTP) — optional')}<input type="text" id="fwd-ntp" value="${F.E((d.ntp_servers || []).join(', '))}" placeholder="e.g. ${F.E(ipOf(i.ipv4))}, 162.159.200.1 — addresses, not names"><div class="fw-err" id="fwd-ntp-err"></div></div>
      <div class="fw-field">${tip('domain', 'Domain')}<input type="text" id="fwd-dom" value="${F.E(d.domain || '')}" placeholder="${F.E(c.dns.domain || 'e.g. home.lan')} (the DNS local domain)"><div class="fw-err" id="fwd-dom-err"></div></div>
      <div class="fw-field">${tip('routes', 'Routes handed out')}
        <div class="fw-note" style="margin:0 0 6px">Networks the clients reach through another router in this network. The default route through the gateway is always sent with them.</div>
        <div id="fwd-routes" class="fw-dlist"></div>
        <button type="button" class="fw-icon-btn" id="fwd-rt-add">${F.icon('plus', 12)}Add a route</button><div class="fw-err" id="fwd-rt-err"></div></div>
      <div class="fw-field">${tip('res', 'Reserved addresses')}
        <div class="fw-note" style="margin:0 0 6px">A device always gets the same address. Under <b>Options</b>, it can get its own gateway, DNS servers or lease time.</div>
        <div id="fwd-res" class="fw-dlist"></div>
        <button type="button" class="fw-icon-btn" id="fwd-res-add">${F.icon('plus', 12)}Reserve an address</button><div class="fw-err" id="fwd-res-err"></div></div>`,
      `${idx >= 0 ? '<button class="fw-btn" id="fwd-del" style="margin-right:auto">Remove</button>' : ''}<button class="fw-btn" id="fwd-cancel">Cancel</button><button class="fw-btn fw-apply" id="fwd-save">Save to draft</button>`);
    const q = dr.q;
    // Rows are read back into d.routes / d.reservations before any re-draw.
    d.routes = d.routes || [];
    const sub = n2ip(net.base + 254 < net.base + net.size - 1 ? net.base + 254 : net.base + net.size - 2);
    const drawRoutes = () => {
      q('#fwd-routes').innerHTML = d.routes.map((r, k) => `<div class="fw-drow" data-rt="${k}">
        <input type="text" data-f="network" value="${F.E(r.network)}" placeholder="10.20.0.0/16" aria-label="Network">
        <span class="fw-darrow">via</span>
        <input type="text" data-f="via" value="${F.E(r.via)}" placeholder="${F.E(sub)}" aria-label="Router">
        <button type="button" class="fw-rbtn" data-rtdel="${k}" title="Remove">${F.icon('x', 12)}</button></div>`).join('');
      q('#fwd-routes').querySelectorAll('[data-rtdel]').forEach(b => b.onclick = () => { readRows(); d.routes.splice(Number(b.dataset.rtdel), 1); drawRoutes(); });
    };
    const open = new Set();
    const drawRes = () => {
      q('#fwd-res').innerHTML = d.reservations.map((r, k) => {
        const own = resOwn(r);
        return `<div class="fw-dres" data-res="${k}"><div class="fw-drow">
          <input type="text" data-f="mac" value="${F.E(r.mac)}" placeholder="aa:bb:cc:dd:ee:ff" aria-label="MAC address" class="fw-mono">
          <input type="text" data-f="ip" value="${F.E(r.ip)}" placeholder="${F.E(n2ip(net.base + 10))}" aria-label="Address">
          <input type="text" data-f="hostname" value="${F.E(r.hostname || '')}" placeholder="name" aria-label="Name">
          <button type="button" class="fw-icon-btn${own.length ? ' on' : ''}" data-resopt="${k}" title="${own.length ? F.E(own.join(' · ')) : 'Own gateway, DNS servers or lease time'}">${F.icon('sliders', 12)}Options${own.length ? ` <b>${own.length}</b>` : ''}</button>
          <button type="button" class="fw-rbtn" data-resdel="${k}" title="Remove">${F.icon('x', 12)}</button></div>
          ${open.has(k) ? `<div class="fw-dopt">
            <div class="fw-field">${tip('rgw', 'Gateway')}<input type="text" data-f="gateway" value="${F.E(r.gateway || '')}" placeholder="the network's"></div>
            <div class="fw-field">${tip('rdns', 'DNS servers')}<input type="text" data-f="dns_servers" value="${F.E((r.dns_servers || []).join(', '))}" placeholder="the network's"></div>
            <div class="fw-field">${tip('rlease', 'Lease (hours)')}<input type="number" data-f="lease_hours" min="1" max="8760" value="${r.lease_hours || ''}" placeholder="${F.E(q('#fwd-lease') ? q('#fwd-lease').value : d.lease_hours)}"></div></div>` : ''}</div>`;
      }).join('');
      q('#fwd-res').querySelectorAll('[data-resdel]').forEach(b => b.onclick = () => { readRows(); const k = Number(b.dataset.resdel); d.reservations.splice(k, 1); open.clear(); drawRes(); });
      q('#fwd-res').querySelectorAll('[data-resopt]').forEach(b => b.onclick = () => { readRows(); const k = Number(b.dataset.resopt); open.has(k) ? open.delete(k) : open.add(k); drawRes(); });
    };
    const readRows = () => {
      q('#fwd-routes').querySelectorAll('[data-rt]').forEach(row => {
        const r = d.routes[Number(row.dataset.rt)];
        r.network = row.querySelector('[data-f=network]').value.trim(); r.via = row.querySelector('[data-f=via]').value.trim();
      });
      q('#fwd-res').querySelectorAll('[data-res]').forEach(row => {
        const r = d.reservations[Number(row.dataset.res)], v = f => row.querySelector(`[data-f=${f}]`);
        r.mac = v('mac').value.trim().toLowerCase(); r.ip = v('ip').value.trim(); r.hostname = v('hostname').value.trim();
        if (v('gateway')) {
          r.gateway = v('gateway').value.trim(); r.dns_servers = ipList(v('dns_servers').value); r.lease_hours = Number(v('lease_hours').value) || 0;
        }
      });
    };
    drawRoutes(); drawRes();
    const showPools = () => {
      const p = poolsOf(q('#fwd-start').value.trim(), q('#fwd-end').value.trim(), q('#fwd-ex').value);
      const n = p ? p.reduce((a, [x, y]) => a + y - x + 1, 0) : 0;
      q('#fwd-pools').innerHTML = !p ? '' : (!p.length ? 'Nothing left to hand out.'
        : `Handed out: <span class="fw-mono">${p.map(([x, y]) => x === y ? n2ip(x) : n2ip(x) + ' – ' + n2ip(y)).join(', ')}</span> · ${n} address${n === 1 ? '' : 'es'}`);
    };
    ['#fwd-start', '#fwd-end', '#fwd-ex'].forEach(id => q(id).addEventListener('input', showPools));
    showPools();
    q('#fwd-rt-add').onclick = () => { readRows(); d.routes.push({ network: '', via: '' }); drawRoutes(); q(`#fwd-routes [data-rt="${d.routes.length - 1}"] input`).focus(); };
    q('#fwd-res-add').onclick = () => { readRows(); d.reservations.push({ mac: '', ip: '', hostname: '' }); drawRes(); q(`#fwd-res [data-res="${d.reservations.length - 1}"] input`).focus(); };
    q('#fwd-cancel').onclick = dr.close;
    if (idx >= 0) q('#fwd-del').onclick = () => { dr.close(); F.saveDraft(n => { n.dhcp = n.dhcp.filter(x => x.interface !== ifId); }); };
    q('#fwd-save').onclick = async () => {
      d.enabled = q('#fwd-en').checked;
      d.range_start = q('#fwd-start').value.trim(); d.range_end = q('#fwd-end').value.trim();
      d.exclude = ipList(q('#fwd-ex').value);
      d.no_ping = !q('#fwd-ping').checked;
      d.lease_hours = Number(q('#fwd-lease').value) || 12;
      d.gateway = q('#fwd-gw').value.trim();
      d.dns_servers = ipList(q('#fwd-dns').value);
      d.ntp_servers = ipList(q('#fwd-ntp').value);
      d.domain = q('#fwd-dom').value.trim();
      readRows();
      // rows left empty are dropped, not reported
      d.routes = d.routes.filter(r => r.network || r.via);
      d.reservations = d.reservations.filter(r => r.mac || r.ip || r.hostname);
      const next = F.clone(c);
      const at = idx >= 0 ? idx : next.dhcp.push(d) - 1;
      next.dhcp[at] = d;
      const errs = await F.validate(next);
      dr.dr.querySelectorAll('.fw-drow.bad').forEach(e => e.classList.remove('bad'));
      if (F.showErrors(dr.dr, errs, `dhcp[${at}]`, { range_start: '#fwd-start-err', range_end: '#fwd-end-err', lease_hours: '#fwd-lease-err',
        gateway: '#fwd-gw-err', dns_servers: '#fwd-dns-err', ntp_servers: '#fwd-ntp-err', exclude: '#fwd-ex-err', domain: '#fwd-dom-err', routes: '#fwd-rt-err', reservations: '#fwd-res-err', interface: '[data-err]' }, '[data-err]')) {
        // point at the row: the drawer redraws from d, now without empty rows
        drawRoutes(); drawRes();
        const m = (errs.find(e => e.path.startsWith(`dhcp[${at}]`)) || {}).path.match(/\.(routes|reservations)\[(\d+)\]/);
        if (m) {
          const row = q(m[1] === 'routes' ? `#fwd-routes [data-rt="${m[2]}"]` : `#fwd-res [data-res="${m[2]}"] .fw-drow`);
          if (row) row.classList.add('bad');
          if (m[1] === 'reservations' && /\.(gateway|dns_servers|lease_hours)$/.test(errs.find(e => e.path.startsWith(`dhcp[${at}]`)).path) && !open.has(Number(m[2]))) {
            open.add(Number(m[2])); drawRes(); q(`#fwd-res [data-res="${m[2]}"] .fw-drow`).classList.add('bad');
          }
        }
        return;
      }
      dr.close();
      F.saveDraft(n => { n.dhcp = next.dhcp; });
    };
  }

  const DNSTIP = {
    on: ['Local DNS', '<p>This router answers name lookups for the devices of the networks you pick, forwards the rest to the upstream servers, and keeps answers in a cache.</p><p>The devices of your DHCP networks are registered by name automatically.</p>'],
    nets: ['Answers on', '<p>The networks whose devices may ask this router. Never a WAN: an open resolver on the Internet gets abused.</p><p>DHCP on these networks hands out this router as the DNS server (unless you set others there).</p>'],
    up: ['Upstream servers', '<p>Where lookups this router cannot answer go — e.g. <code>1.1.1.1, 9.9.9.9</code>. Empty: this server\'s own resolvers.</p>'],
    dom: ['Local domain', '<p>The domain of your networks\' devices: with <code>home.lan</code>, a device named <code>nas</code> answers as <code>nas</code> and <code>nas.home.lan</code>. Names in it are never asked upstream.</p><p>A network can have its own domain in its DHCP settings.</p>'],
    hosts: ['Host names', '<p>Names you fix by hand, one per line: <code>nas 10.0.0.5</code>. A short name also answers in the local domain.</p>'],
    fwd: ['Send a domain to another server', '<p>Conditional forwarding: lookups of a domain go to a server of your choice — e.g. a company domain to its own DNS server over a VPN: <code>corp.example 10.0.0.33</code>.</p>'],
    metrics: ['Collect advanced metrics', '<p>Every lookup is recorded — when, which device, which name, and what happened (forwarded, from the cache, blocked) — for the reports in <b>Monitor → DNS queries</b>: totals, top domains and devices, the query log.</p><p>Recorded in memory and saved with the Firewall statistics (the pool chosen on the Traffic page). Turn it off and nothing more is recorded.</p>'],
    lists: ['Blocklists', '<p>Lists of domains to block — ads, trackers, malware — fetched from their address every day. Hosts files (<code>0.0.0.0 name</code>), plain domain lists and Adblock lists (<code>||name^</code>) are read.</p><p>A blocked name gets <code>0.0.0.0</code> / <code>::</code>, so the device cannot reach it. Only the exact names on the lists are blocked, as with Pi-hole.</p><p>A list that cannot be fetched keeps its last good version.</p>'],
    allow: ['Allowed domains', '<p>Never blocked, even when a list has them — for the one domain a list gets wrong. One per line.</p>'],
    deny: ['Blocked domains', '<p>Always blocked, list or not. One per line.</p>'],
  };
  const dtip = (k, label) => F.lab(label, DNSTIP[k][0], DNSTIP[k][1]);
  const POPULAR = [
    { url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', label: 'StevenBlack — ads & malware (hosts)', desc: 'StevenBlack unified hosts' },
    { url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt', label: 'HaGeZi Multi NORMAL — ads, trackers, malware', desc: 'HaGeZi Multi NORMAL' },
  ];
  const agoText = iso => (!iso || String(iso).startsWith('0001')) ? '' : ago(iso);

  function editDNS() {
    const c = F.cfg(), dns = F.clone(c.dns);
    dns.blocklists = dns.blocklists || []; dns.allow = dns.allow || []; dns.deny = dns.deny || [];
    let blState = { lists: {} };
    const ta = (id, rows, val, ph) => `<textarea id="${id}" rows="${rows}" spellcheck="false" style="width:100%;font-family:var(--font-mono,monospace);font-size:12px;background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:8px" placeholder="${ph}">${F.E(val)}</textarea>`;
    const dr = F.drawer('Local DNS', 'Answers name lookups for the networks you pick, with DHCP host names registered', `
      <div class="fw-lab">${F.cb('fwn-en', 'Turn on DNS', dns.enabled)}${F.info(DNSTIP.on[0], DNSTIP.on[1])}</div>
      <div class="fw-field" style="margin-top:12px">${dtip('nets', 'Answers on')}<div id="fwn-if" class="fw-chips"></div><div class="fw-err" id="fwn-if-err"></div></div>
      <div class="fw-field">${dtip('up', 'Upstream servers')}<input type="text" id="fwn-up" value="${F.E(dns.upstreams.join(', '))}" placeholder="empty = this server's resolvers · e.g. 1.1.1.1, 9.9.9.9"><div class="fw-err" id="fwn-up-err"></div></div>
      <div class="fw-field">${dtip('dom', 'Local domain')}<input type="text" id="fwn-dom" value="${F.E(dns.domain || '')}" placeholder="e.g. home.lan — devices answer as name.home.lan"><div class="fw-err" id="fwn-dom-err"></div></div>
      <div class="fw-field">${dtip('hosts', 'Host names — one per line: name  address')}
        ${ta('fwn-hosts', 4, dns.hosts.map(h => h.name + '  ' + h.ip).join('\n'), 'nas  10.128.8.5')}<div class="fw-err" id="fwn-hosts-err"></div></div>
      <div class="fw-field">${dtip('fwd', 'Send a domain to another server — one per line: domain  server')}
        ${ta('fwn-fwd', 3, dns.forwards.map(f => f.domain + '  ' + f.server).join('\n'), 'corp.example  10.128.8.33')}<div class="fw-err" id="fwn-fwd-err"></div></div>
      <h4 class="fw-dns-h4">Reports</h4>
      <div class="fw-lab">${F.cb('fwn-metrics', 'Collect advanced metrics (Monitor → DNS queries)', !!dns.metrics)}${F.info(DNSTIP.metrics[0], DNSTIP.metrics[1])}</div>
      <h4 class="fw-dns-h4">Blocking</h4>
      <div class="fw-field">${dtip('lists', 'Blocklists')}
        <div id="fwn-lists" class="fw-dlist"></div>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          <button type="button" class="fw-icon-btn" id="fwn-list-add">${F.icon('plus', 12)}Add a list</button>
          <button type="button" class="fw-icon-btn" id="fwn-list-pop">${F.icon('list', 12)}Add a popular list</button>
          ${F.isAdmin() ? `<button type="button" class="fw-icon-btn" id="fwn-list-now" title="Download every list again now (the saved ones)">${F.icon('refresh-cw', 12)}Update lists now</button>` : ''}
        </div><div id="fwn-pop" class="fw-dns-pops"></div><div class="fw-err" id="fwn-lists-err"></div></div>
      <div class="fw-row2"><div class="fw-field">${dtip('allow', 'Allowed domains')}${ta('fwn-allow', 4, dns.allow.join('\n'), 'one per line')}<div class="fw-err" id="fwn-allow-err"></div></div>
        <div class="fw-field">${dtip('deny', 'Blocked domains')}${ta('fwn-deny', 4, dns.deny.join('\n'), 'one per line')}<div class="fw-err" id="fwn-deny-err"></div></div></div>`,
      '<button class="fw-btn" id="fwn-cancel">Cancel</button><button class="fw-btn fw-apply" id="fwn-save">Save to draft</button>');
    const q = dr.q;
    F.ifaceChips(q('#fwn-if'), dns.interfaces.slice(), v => { dns.interfaces = v; }, i => i.role !== 'wan');
    const readLists = () => q('#fwn-lists').querySelectorAll('[data-bl]').forEach(row => {
      const l = dns.blocklists[Number(row.dataset.bl)];
      l.url = row.querySelector('[data-f=url]').value.trim(); l.enabled = row.querySelector('[data-f=en]').checked;
    });
    const drawLists = () => {
      q('#fwn-lists').innerHTML = dns.blocklists.map((l, k) => {
        const st = (l.id && blState.lists[l.id]) || null;
        const info = !st ? (l.id ? 'not downloaded yet (after Apply)' : 'downloaded after Apply')
          : st.error ? `<span style="color:var(--fw-blk)">${F.E(st.error)}</span>${st.domains ? ` — keeps ${st.domains.toLocaleString()} domains from ${F.E(agoText(st.updated))}` : ''}`
          : `${st.domains.toLocaleString()} domains · updated ${F.E(agoText(st.updated))}`;
        return `<div class="fw-dres" data-bl="${k}"><div class="fw-drow">
          <input type="checkbox" data-f="en" ${l.enabled ? 'checked' : ''} title="Use this list" style="flex:none;width:auto">
          <input type="text" data-f="url" value="${F.E(l.url)}" placeholder="https://…" aria-label="List address" class="fw-mono" style="font-size:12px">
          <button type="button" class="fw-rbtn" data-bldel="${k}" title="Remove">${F.icon('x', 12)}</button></div>
          <div class="fw-pools" style="margin:2px 0 0 26px">${l.description ? F.E(l.description) + ' · ' : ''}${info}</div></div>`;
      }).join('');
      q('#fwn-lists').querySelectorAll('[data-bldel]').forEach(b => b.onclick = () => { readLists(); dns.blocklists.splice(Number(b.dataset.bldel), 1); q('#fwn-lists-err').textContent = ''; drawLists(); });
    };
    drawLists();
    F.api('GET', '/api/sdn/dns/blocklists').then(r => { if (r.ok) { blState = r.data || { lists: {} }; blState.lists = blState.lists || {}; readLists(); drawLists(); } });
    q('#fwn-list-add').onclick = () => { readLists(); dns.blocklists.push({ url: '', enabled: true }); drawLists(); q(`#fwn-lists [data-bl="${dns.blocklists.length - 1}"] [data-f=url]`).focus(); };
    q('#fwn-list-pop').onclick = () => {
      readLists();
      const box = q('#fwn-pop');
      if (box.innerHTML) { box.innerHTML = ''; return; }
      const have = new Set(dns.blocklists.map(l => l.url));
      box.innerHTML = `<div class="fw-note" style="margin:0 0 6px">Well-known lists, kept up to date by their authors. Start with one: several lists block more, and break more.</div>` +
        POPULAR.map((p, i) => `<div class="fw-dns-pop"><div><b>${F.E(p.label)}</b><div class="fw-mono">${F.E(p.url)}</div></div>
          ${have.has(p.url) ? '<span class="fw-badge none">added</span>' : `<button type="button" class="fw-icon-btn" data-pop="${i}">${F.icon('plus', 12)}Add</button>`}</div>`).join('');
      box.querySelectorAll('[data-pop]').forEach(b => b.onclick = () => {
        readLists();
        const p = POPULAR[Number(b.dataset.pop)];
        dns.blocklists.push({ url: p.url, enabled: true, description: p.desc });
        box.innerHTML = ''; drawLists();
      });
    };
    const now = q('#fwn-list-now');
    if (now) now.onclick = async () => {
      now.disabled = true;
      const r = await F.api('POST', '/api/sdn/dns/blocklists/update');
      F.toast(r.ok ? 'Downloading the lists…' : ((r.data && r.data.error) || 'Update failed'), r.ok ? 'success' : 'error');
      setTimeout(async () => { const s = await F.api('GET', '/api/sdn/dns/blocklists'); if (s.ok) { blState = s.data; blState.lists = blState.lists || {}; readLists(); drawLists(); } now.disabled = false; }, 4000);
    };
    q('#fwn-cancel').onclick = dr.close;
    const pairs = t => t.split('\n').map(l => l.trim()).filter(Boolean).map(l => l.split(/[\s,]+/));
    const lines = t => t.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
    q('#fwn-save').onclick = async () => {
      dns.enabled = q('#fwn-en').checked;
      dns.upstreams = q('#fwn-up').value.split(/[\s,]+/).filter(Boolean);
      dns.domain = q('#fwn-dom').value.trim();
      dns.hosts = pairs(q('#fwn-hosts').value).map(([name, ip]) => ({ name: name || '', ip: ip || '' }));
      dns.forwards = pairs(q('#fwn-fwd').value).map(([domain, server]) => ({ domain: domain || '', server: server || '' }));
      dns.metrics = q('#fwn-metrics').checked;
      readLists();
      dns.blocklists = dns.blocklists.filter(l => l.url);
      dns.allow = lines(q('#fwn-allow').value); dns.deny = lines(q('#fwn-deny').value);
      const next = F.clone(c); next.dns = dns;
      const errs = await F.validate(next);
      const dhcpErr = errs.find(e => e.path.startsWith('dhcp[') && e.path.endsWith('dns_servers'));
      if (F.showErrors(dr.dr, errs, 'dns', { interfaces: '#fwn-if-err', upstreams: '#fwn-up-err', domain: '#fwn-dom-err', hosts: '#fwn-hosts-err', forwards: '#fwn-fwd-err',
        blocklists: '#fwn-lists-err', allow: '#fwn-allow-err', deny: '#fwn-deny-err' }, '[data-err]')) { drawLists(); return; }
      if (dhcpErr) { dr.q('[data-err]').textContent = dhcpErr.message + ' (DHCP hands out this router as DNS there)'; return; }
      dr.close();
      F.saveDraft(n => { n.dns = dns; });
    };
  }

  // ── WireGuard ──────────────────────────────────────────────────────────
  async function loadWG() {
    const [, r] = await Promise.all([loadSvc(), F.api('GET', '/api/sdn/wireguard/status')]);
    wgLive = r.ok ? (r.data || {}) : {};
  }

  function wireguardHTML() {
    const c = F.cfg(), admin = F.isAdmin(), st = F.status() || {};
    const cards = tunnels().map(t => {
      const L = wgLive[t.id];
      const peers = c.wg_peers.filter(p => p.tunnel === t.id);
      const rows = peers.map(p => {
        const lp = ((L && L.peers) || []).find(x => x.public_key === p.public_key) || {};
        const fresh = lp.last_handshake && !lp.last_handshake.startsWith('0001') && Date.now() - new Date(lp.last_handshake).getTime() < 180000;
        const heal = (L && L.heal && L.heal.peers && L.heal.peers[p.public_key]) || {};
        const healNote = !p.enabled || fresh ? '' : heal.note === 'waiting_dns' ? 'Waiting for DNS, retrying' : heal.note === 'connecting' ? 'Trying to connect' : '';
        const healChanged = heal.changed && !heal.changed.startsWith('0001') && heal.previous ? `Address changed ${ago(heal.changed)}, was ${heal.previous}` : '';
        return `<tr class="${p.enabled ? '' : 'fw-dim'}"><td><span class="fw-state ${fresh ? 'up' : 'down'}" title="${fresh ? 'connected' : 'no recent handshake'}"></span> ${F.E(p.name || '(no name)')}${p.endpoint ? ' <span class="fw-badge none">site</span>' : ''}</td>
          <td class="fw-mono">${F.E(p.allowed_ips.join(', '))}</td>
          <td class="fw-mono">${lp.endpoint ? (lp.country ? `<span class="fw-flag">${F.flagOf(lp.country)}</span>` : '') + F.E(lp.endpoint) : '—'}${healChanged ? `<div class="fw-wg-note">${F.E(healChanged)}</div>` : ''}</td>
          <td>${F.E(ago(lp.last_handshake))}${healNote ? `<div class="fw-wg-note warn" title="${F.E(heal.error || '')}">${F.E(healNote)}</div>` : ''}</td><td>↓ ${F.E(fmtBytes(lp.rx_bytes))} · ↑ ${F.E(fmtBytes(lp.tx_bytes))}</td>
          <td>${admin ? `<button class="fw-icon-btn" data-peer="${F.E(p.id)}">${F.icon('pencil', 12)}</button>` : ''}</td></tr>`;
      }).join('');
      return `<div class="fw-card" style="grid-column:1/-1">
        <div class="fw-stripe" style="background:${F.C(t.color)}"></div>
        <div class="fw-card-h"><span class="fw-name">${F.E(t.name)}</span>
          <span class="fw-gwstate ${L && L.up ? 'up' : 'none'}">${L && L.up ? 'Up' : (!st.enabled ? 'Off' : L && L.heal && L.heal.note === 'restarting' ? 'Down, retrying' : 'Not applied yet')}</span></div>
        <div class="fw-kv"><span>Address</span><span class="fw-mono">${F.E(t.ipv4)}</span>
          <span>Listens on</span><span class="fw-mono">UDP ${F.E(t.wg_listen_port)}${t.wg_endpoint ? ' · clients use ' + F.E(t.wg_endpoint) : ''}</span>
          <span>Public key</span><span class="fw-mono" style="overflow:hidden;text-overflow:ellipsis" title="${F.E(t.wg_public_key || '')}">${F.E(t.wg_public_key || 'made when you save')}${t.wg_public_key ? ` <button class="fw-icon-btn" data-copy="${F.E(t.wg_public_key)}" title="Copy">${F.icon('copy', 11)}</button>` : ''}</span>
          <span>Device</span><span class="fw-mono">${F.E(t.device)}</span></div>
        <div class="fw-tscroll" style="margin-top:10px"><table class="fw-table"><thead><tr><th>Peer</th><th>Addresses</th><th>Connected from</th><th>Last handshake</th><th>Traffic</th><th></th></tr></thead>
          <tbody>${rows || '<tr><td colspan="6" style="color:var(--text-3)">No peer yet.</td></tr>'}</tbody></table></div>
        ${admin ? `<div class="fw-card-actions"><button class="fw-icon-btn" data-addpeer="${F.E(t.id)}">${F.icon('plus', 12)}Add a device or site</button>
          <span style="flex:1"></span><button class="fw-icon-btn" data-tedit="${F.E(t.id)}">${F.icon('pencil', 12)}Edit</button>
          <button class="fw-icon-btn danger" data-tdel="${F.E(t.id)}">${F.icon('trash', 12)}Remove</button></div>` : ''}
      </div>`;
    }).join('');
    return `
      ${svc && !svc.wireguard_installed ? installBanner('WireGuard', 'wireguard-tools') : ''}
      <div class="fw-note" style="margin-bottom:10px">A tunnel is a network like the others: give it rules on the Rules page. Its port is only reachable from the Internet if a WAN rule allows it (offered when you create the tunnel).</div>
      <div class="fw-cards">${cards}${admin ? `<div class="fw-card fw-add-card" id="fw-add-tun">${F.icon('plus', 22)}<span>New tunnel</span><span style="font-size:11.5px">For your phones and laptops, or to join another site</span></div>` : ''}</div>`;
  }

  function wireWireGuard(root) {
    root.querySelectorAll('[data-install]').forEach(b => b.onclick = () => install(b.dataset.install, b));
    const add = root.querySelector('#fw-add-tun');
    if (add) add.onclick = () => editTunnel(null);
    root.querySelectorAll('[data-tedit]').forEach(b => b.onclick = () => editTunnel(ifaceById(b.dataset.tedit)));
    root.querySelectorAll('[data-addpeer]').forEach(b => b.onclick = () => editPeer(b.dataset.addpeer, null));
    root.querySelectorAll('[data-peer]').forEach(b => b.onclick = () => { const p = F.cfg().wg_peers.find(x => x.id === b.dataset.peer); editPeer(p.tunnel, p); });
    root.querySelectorAll('[data-copy]').forEach(b => b.onclick = () => { navigator.clipboard && navigator.clipboard.writeText(b.dataset.copy); F.toast('Copied', 'success'); });
    root.querySelectorAll('[data-tdel]').forEach(b => b.onclick = () => {
      const t = ifaceById(b.dataset.tdel), c = F.cfg();
      const refs = c.rules.filter(r => r.interface !== t.id && [r.source, r.destination].some(e => (e.type === 'iface_net' || e.type === 'iface_addr') && e.value === t.id)).length;
      if (refs) { F.modal({ title: `${t.name} is used`, body: `<p>${refs} rule${refs > 1 ? 's' : ''} on other networks refer to this tunnel. Change them first (Rules page).</p>`, buttons: [{ label: 'OK', cls: 'btn-primary' }] }); return; }
      F.modal({ title: `Remove ${t.name}?`, body: '<p>The tunnel, its peers and its rules are removed when you apply. Connected devices lose the VPN.</p>',
        buttons: [{ label: 'Cancel' }, { label: 'Remove', cls: 'btn-danger', onClick: close => { close(); F.saveDraft(n => {
          n.interfaces = n.interfaces.filter(x => x.id !== t.id);
          n.wg_peers = n.wg_peers.filter(p => p.tunnel !== t.id);
          n.rules = n.rules.filter(r => r.interface !== t.id);
          n.dns.interfaces = n.dns.interfaces.filter(x => x !== t.id);
        }); } }] });
    });
  }

  // A /24 used by nothing: Firewall interfaces and every address on the
  // server (Incus bridges, Docker…).
  function freeTunnelNet(hostAddrs) {
    const used = [...F.cfg().interfaces.filter(i => i.ipv4_mode === 'static').map(i => i.ipv4), ...hostAddrs].filter(a => /\/\d+$/.test(a)).map(netOf);
    for (let k = 66; k < 250; k++) {
      const base = ip2n(`10.${k}.0.0`);
      if (!used.some(u => u.base < base + 256 && base < u.base + u.size)) return `10.${k}.0.1/24`;
    }
    return '10.66.0.1/24';
  }

  async function editTunnel(existing) {
    const c = F.cfg();
    const lv = existing ? null : await F.api('GET', '/api/sdn/interfaces/live');
    const hostAddrs = lv && lv.ok ? (lv.data || []).flatMap(l => l.ipv4 || []) : [];
    const ports = tunnels().map(t => t.wg_listen_port);
    let port = 51820; while (ports.includes(port)) port++;
    const t = existing ? F.clone(existing) : { id: F.newId(), name: '', color: F.PALETTE[c.interfaces.length % F.PALETTE.length], kind: 'wireguard', role: 'lan',
      ipv4_mode: 'static', ipv4: freeTunnelNet(hostAddrs), wg_listen_port: port, wg_endpoint: '', owned: true };
    const wans = c.interfaces.filter(i => i.role === 'wan');
    let codes = [];
    const dr = F.drawer(existing ? `Edit ${existing.name}` : 'New WireGuard tunnel', 'A VPN network: each device or site gets an address in it', `
      <div class="fw-field"><label>Name</label><input type="text" id="fwt-name" value="${F.E(t.name)}" placeholder="e.g. Road warriors"><div class="fw-err" id="fwt-name-err"></div></div>
      <div class="fw-row2"><div class="fw-field"><label>Tunnel address</label><input type="text" id="fwt-ip" value="${F.E(t.ipv4)}"><div class="fw-err" id="fwt-ip-err"></div></div>
        <div class="fw-field"><label>UDP port</label><input type="number" id="fwt-port" min="1" max="65535" value="${F.E(t.wg_listen_port)}"><div class="fw-err" id="fwt-port-err"></div></div></div>
      <div class="fw-field"><label>Clients connect to</label><input type="text" id="fwt-ep" value="${F.E(t.wg_endpoint || '')}" placeholder="your public IP or DNS name, e.g. vpn.example.com"><div class="fw-err" id="fwt-ep-err"></div></div>
      ${existing ? '<div class="fw-note">Changing the address or port means every device needs a new configuration.</div>' : `
      <div class="fw-field" style="margin-top:6px"><label>Firewall</label>
        ${wans.length ? F.cb('fwt-wanrule', `Allow UDP <span id="fwt-pl">${port}</span> from the Internet on ${F.E(wans.map(w => w.name).join(', '))}`, true) : '<div class="fw-note">No WAN interface yet: no rule to add for the Internet.</div>'}
        <div id="fwt-cc" class="fw-chips" style="margin:6px 0 0 24px"></div>
        ${F.cb('fwt-allrule', 'Let devices and sites on the tunnel reach every network and the Internet', true)}</div>`}`,
      '<button class="fw-btn" id="fwt-cancel">Cancel</button><button class="fw-btn fw-apply" id="fwt-save">Save to draft</button>');
    const q = dr.q;
    q('#fwt-cancel').onclick = dr.close;
    const pl = q('#fwt-pl');
    if (pl) q('#fwt-port').oninput = () => { pl.textContent = q('#fwt-port').value; };
    const drawCC = () => {
      const box = q('#fwt-cc'); if (!box) return;
      box.innerHTML = '<span style="font-size:12px;color:var(--text-3)">Only from:</span>' + (codes.length ? codes.map((cc, k) => `<span class="fw-chip">${F.flagOf(cc)} ${F.E(F.ccName(cc))}<button data-rm="${k}" title="Remove">${F.icon('x', 11)}</button></span>`).join('') : '<span class="fw-chip">any country</span>') + '<span data-add style="min-width:180px;display:inline-block"></span>';
      box.querySelectorAll('[data-rm]').forEach(b => b.onclick = () => { codes.splice(Number(b.dataset.rm), 1); drawCC(); });
      F.picker(box.querySelector('[data-add]'), F.countryOptions(), '', v => { if (!codes.includes(v)) codes.push(v); drawCC(); }, { placeholder: '+ Limit to a country…', search: true });
    };
    if (q('#fwt-cc')) F.loadCountries().then(drawCC);
    q('#fwt-save').onclick = async () => {
      t.name = q('#fwt-name').value.trim(); t.ipv4 = q('#fwt-ip').value.trim();
      t.wg_listen_port = Number(q('#fwt-port').value); t.wg_endpoint = q('#fwt-ep').value.trim();
      if (!t.name) { q('#fwt-name-err').textContent = 'Give the tunnel a name'; return; }
      const next = F.clone(c);
      const at = existing ? next.interfaces.findIndex(i => i.id === t.id) : next.interfaces.push(t) - 1;
      next.interfaces[at] = t;
      if (!existing) {
        if (q('#fwt-wanrule') && q('#fwt-wanrule').checked) {
          wans.forEach(w => next.rules.push({ id: F.newId(), enabled: true, interface: w.id, action: 'allow', protocol: 'udp',
            source: codes.length ? { type: 'countries', value: codes.join(',') } : { type: 'any' }, destination: { type: 'this_znas' },
            dst_ports: String(t.wg_listen_port), log: false, description: `WireGuard ${t.name}` }));
        }
        if (q('#fwt-allrule').checked) {
          // Source "any": WireGuard only accepts from a peer the addresses it
          // was given (its tunnel address and, for a site, its networks).
          next.rules.push({ id: F.newId(), enabled: true, interface: t.id, action: 'allow', protocol: 'any', source: { type: 'any' },
            destination: { type: 'any' }, log: false, description: `${t.name} peers may go anywhere` });
        }
      }
      // The key is made by the server on save: validate without it.
      const errs = (await F.validate(next)).filter(e => !e.path.endsWith('wg_private_key'));
      if (F.showErrors(dr.dr, errs, `interfaces[${at}]`, { ipv4: '#fwt-ip-err', ipv4_mode: '#fwt-ip-err', wg_listen_port: '#fwt-port-err', wg_endpoint: '#fwt-ep-err', name: '#fwt-name-err' }, '[data-err]')) return;
      if (errs.length && errs.some(e => e.path.startsWith('rules['))) { dr.q('[data-err]').textContent = errs.find(e => e.path.startsWith('rules[')).message; return; }
      dr.close();
      F.saveDraft(n => { n.interfaces = next.interfaces; n.rules = next.rules; });
    };
  }

  function nextPeerIP(t, c) {
    const net = netOf(t.ipv4), own = ip2n(ipOf(t.ipv4));
    const used = new Set(c.wg_peers.filter(p => p.tunnel === t.id).flatMap(p => p.allowed_ips).filter(a => a.endsWith('/32')).map(a => ip2n(ipOf(a))));
    for (let n = net.base + 1; n < net.base + net.size - 1; n++) if (n !== own && !used.has(n)) return n2ip(n) + '/32';
    return '';
  }

  function editPeer(tunId, existing) {
    const c = F.cfg(), t = ifaceById(tunId);
    const p = existing ? F.clone(existing) : { id: F.newId(), tunnel: tunId, name: '', enabled: true, public_key: '', allowed_ips: [nextPeerIP(t, c)], endpoint: '', keepalive: 0 };
    let kind = p.endpoint || p.allowed_ips.length > 1 ? 'site' : 'device';
    let keyMode = existing ? 'own' : 'gen';
    let routes = 'all';
    const dnsOnTunnel = c.dns.enabled && c.dns.interfaces.includes(tunId);
    const myNets = c.interfaces.filter(i => i.role !== 'wan' && i.ipv4_mode === 'static' && i.id !== tunId).map(i => { const n = netOf(i.ipv4); return { name: i.name, cidr: n2ip(n.base) + '/' + n.bits }; });
    const dr = F.drawer(existing ? `Edit ${existing.name || 'peer'}` : `Add to ${t.name}`, '', `
      <div class="fw-field"><label>What is it?</label><div id="fwp-kind"></div></div>
      <div class="fw-field"><label>Name</label><input type="text" id="fwp-name" value="${F.E(p.name)}" placeholder="e.g. Alex's phone"><div class="fw-err" id="fwp-name-err"></div></div>
      <div class="fw-field"><label>Tunnel address</label><input type="text" id="fwp-ip" value="${F.E(p.allowed_ips[0] || '')}"><div class="fw-err" id="fwp-ip-err"></div></div>
      <div id="fwp-site"><div class="fw-field"><label>Its networks (routed through the tunnel)</label><input type="text" id="fwp-nets" value="${F.E(p.allowed_ips.slice(1).join(', '))}" placeholder="e.g. 10.40.0.0/24"><div class="fw-err" id="fwp-nets-err"></div></div>
        <div class="fw-row2"><div class="fw-field"><label>Its address (to dial it)</label><input type="text" id="fwp-ep" value="${F.E(p.endpoint || '')}" placeholder="host:port — empty = it dials us"><div class="fw-err" id="fwp-ep-err"></div></div>
        <div class="fw-field"><label>Keepalive (s)</label><input type="number" id="fwp-ka" min="0" value="${F.E(p.keepalive || '')}" placeholder="25"><div class="fw-err" id="fwp-ka-err"></div></div></div></div>
      <div class="fw-field"><label>Key</label><div id="fwp-keymode"></div>
        <input type="text" id="fwp-pub" value="${F.E(p.public_key || '')}" placeholder="its public key (from the WireGuard app)" style="margin-top:6px"><div class="fw-err" id="fwp-pub-err"></div></div>
      <div id="fwp-gen"><div class="fw-field"><label>The device sends through the tunnel</label><div id="fwp-routes"></div></div>
        <div class="fw-field" id="fwp-reach">${F.lab('Networks it sends here', 'Networks it sends here', '<p>The networks the device or site sends through the tunnel. The tunnel network is always included.</p><p>This only sets its routing. What it may reach is decided by the tunnel\'s rules on the Rules page.</p>')}
          ${myNets.map((n, k) => F.cb('fwp-net' + k, `${F.E(n.name)} <span class="fw-mono">${F.E(n.cidr)}</span>`, true)).join('')}
          <input type="text" id="fwp-extra" placeholder="Other networks, e.g. 10.40.0.0/24, 172.16.5.0/24" style="margin-top:6px"><div class="fw-err" id="fwp-extra-err"></div></div>
        <div class="fw-field">${F.lab('DNS servers (optional)', 'DNS servers', '<p>Written to the configuration: the device uses them while the tunnel is up. Separate several with commas. Empty = it keeps its own DNS servers.</p>')}
          <input type="text" id="fwp-dns" value="${F.E(dnsOnTunnel ? ipOf(t.ipv4) : '')}" placeholder="e.g. 192.168.2.1, 1.1.1.1"><div class="fw-err" id="fwp-dns-err"></div></div>
        <div class="fw-note">The configuration and its QR code are shown once, right after you save. Its private key is never stored on the router.</div></div>
      ${existing ? F.cb('fwp-en', 'Enabled', p.enabled) : ''}`,
      `${existing ? '<button class="fw-btn" id="fwp-del" style="margin-right:auto">Remove</button>' : ''}<button class="fw-btn" id="fwp-cancel">Cancel</button><button class="fw-btn fw-apply" id="fwp-save">Save to draft</button>`);
    const q = dr.q;
    const sync = () => {
      q('#fwp-site').style.display = kind === 'site' ? '' : 'none';
      q('#fwp-pub').style.display = keyMode === 'own' ? '' : 'none';
      q('#fwp-gen').style.display = keyMode === 'gen' ? '' : 'none';
      q('#fwp-routes').parentElement.style.display = kind === 'device' ? '' : 'none';
      q('#fwp-reach').style.display = kind === 'site' || routes === 'mine' ? '' : 'none';
    };
    F.seg(q('#fwp-kind'), [['device', 'A phone or computer'], ['site', 'Another site (network)']], kind, v => { kind = v; if (v === 'site' && !q('#fwp-ka').value) q('#fwp-ka').value = 25; sync(); });
    F.seg(q('#fwp-keymode'), existing ? [['own', 'Its public key']] : [['gen', 'Generate for me'], ['own', 'I have its public key']], keyMode, v => { keyMode = v; sync(); });
    F.seg(q('#fwp-routes'), [['all', 'All its traffic'], ['mine', 'Only traffic to chosen networks']], routes, v => { routes = v; sync(); });
    sync();
    q('#fwp-cancel').onclick = dr.close;
    if (existing) q('#fwp-del').onclick = () => { dr.close(); F.saveDraft(n => { n.wg_peers = n.wg_peers.filter(x => x.id !== p.id); }); };
    q('#fwp-save').onclick = async () => {
      p.name = q('#fwp-name').value.trim();
      const ips = [q('#fwp-ip').value.trim()].filter(Boolean);
      if (kind === 'site') ips.push(...q('#fwp-nets').value.split(/[\s,]+/).filter(Boolean));
      p.allowed_ips = ips;
      p.endpoint = kind === 'site' ? q('#fwp-ep').value.trim() : '';
      p.keepalive = kind === 'site' ? Number(q('#fwp-ka').value) || 0 : 0;
      if (existing) p.enabled = q('#fwp-en').checked;
      let gen = null, allowed = null, dns = [];
      if (keyMode === 'gen') {
        q('#fwp-extra-err').textContent = q('#fwp-dns-err').textContent = '';
        const extra = listOf(q('#fwp-extra').value);
        const badNet = extra.find(a => !cidrOK(a));
        if (badNet) { q('#fwp-extra-err').textContent = `${badNet} is not an IPv4 network, e.g. 10.40.0.0/24`; return; }
        dns = listOf(q('#fwp-dns').value);
        const badDNS = dns.find(a => a.includes('/') || !cidrOK(a));
        if (badDNS) { q('#fwp-dns-err').textContent = `${badDNS} is not an IPv4 address`; return; }
        if (kind === 'site' || routes === 'mine') {
          const nets = [...myNets.filter((n, k) => q('#fwp-net' + k).checked).map(n => n.cidr), ...extra.map(a => { const n = netOf(a.includes('/') ? a : a + '/32'); return n2ip(n.base) + '/' + n.bits; })];
          if (kind === 'device' && !nets.length) { q('#fwp-extra-err').textContent = 'Tick a network or enter one'; return; }
          allowed = [...new Set(nets)];
        }
        if (!t.wg_endpoint) { q('#fwp-pub-err').textContent = 'Set "Clients connect to" on the tunnel first (Edit) — the configuration needs it.'; return; }
        const r = await F.api('POST', '/api/sdn/wireguard/keys');
        if (!r.ok) { q('#fwp-pub-err').textContent = (r.data && r.data.error) || 'Could not make a key'; return; }
        gen = r.data; p.public_key = gen.public_key; p.preshared_key = gen.preshared_key;
      } else p.public_key = q('#fwp-pub').value.trim();
      const next = F.clone(c);
      const at = existing ? next.wg_peers.findIndex(x => x.id === p.id) : next.wg_peers.push(p) - 1;
      next.wg_peers[at] = p;
      if (F.showErrors(dr.dr, await F.validate(next), `wg_peers[${at}]`, { name: '#fwp-name-err', public_key: '#fwp-pub-err', allowed_ips: kind === 'site' ? '#fwp-nets-err' : '#fwp-ip-err',
        endpoint: '#fwp-ep-err', keepalive: '#fwp-ka-err', preshared_key: '#fwp-pub-err' }, '[data-err]')) return;
      dr.close();
      const ok = await F.saveDraft(n => { n.wg_peers = next.wg_peers; });
      if (ok && gen) showClientConfig(t, p, gen, allowed, dns);
    };
  }

  function showClientConfig(t, p, gen, allowed, dns) {
    const tun = ifaceById(t.id) || t; // public key made by the server on save
    const ep = /:\d+$/.test(tun.wg_endpoint) ? tun.wg_endpoint : tun.wg_endpoint + ':' + tun.wg_listen_port;
    const net = netOf(tun.ipv4);
    // null = all traffic; otherwise the tunnel network + the given networks.
    allowed = allowed ? [...new Set([n2ip(net.base) + '/' + net.bits, ...allowed])] : ['0.0.0.0/0'];
    const text = `[Interface]
PrivateKey = ${gen.private_key}
Address = ${p.allowed_ips[0]}
${dns.length ? `DNS = ${dns.join(', ')}\n` : ''}
[Peer]
PublicKey = ${tun.wg_public_key}
PresharedKey = ${gen.preshared_key}
Endpoint = ${ep}
AllowedIPs = ${allowed.join(', ')}
PersistentKeepalive = 25
`;
    let qr = '';
    if (typeof qrcode !== 'undefined') {
      const g = qrcode(0, 'L'); g.addData(text); g.make();
      qr = g.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
    }
    const box = document.createElement('div');
    box.innerHTML = `<p style="margin-top:0">Scan it with the WireGuard app, or download the file. <b>This is the only time it is shown</b> — the router keeps only the public key. It works once you <b>Apply</b>.</p>
      ${qr ? `<div style="background:#fff;padding:10px;border-radius:10px;width:min(280px,100%);margin:0 auto 12px">${qr}</div>` : ''}
      <pre style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px;font-size:11.5px;white-space:pre-wrap;word-break:break-all;max-height:220px;overflow:auto">${F.E(text)}</pre>`;
    const fname = ((p.name || 'peer').replace(/[^A-Za-z0-9_-]+/g, '-').slice(0, 15) || 'peer') + '.conf';
    F.modal({ title: `${p.name || 'Peer'} — WireGuard configuration`, body: box, width: 560, buttons: [
      { label: 'Download ' + fname, onClick: () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' })); a.download = fname; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); } },
      { label: 'Done', cls: 'btn-primary' }] });
  }

  function register() {
    if (typeof window.sdnRegisterPage !== 'function' || !window.sdnFW || !window.sdnFW.drawer) { setTimeout(register, 200); return; }
    F = window.sdnFW;
    window.sdnRegisterPage('fw-dhcp', { load: loadDHCP, render: dhcpHTML, wire: wireDHCP, pollMs: 10000, poll: loadDHCP,
      busy: () => !!(document.activeElement && document.activeElement.classList.contains('fw-un-in')) });
    window.sdnRegisterPage('fw-wireguard', { load: async () => { await Promise.all([loadWG(), F.loadCountries()]); }, render: wireguardHTML, wire: wireWireGuard, pollMs: 5000, poll: loadWG });
  }
  register();
})();
