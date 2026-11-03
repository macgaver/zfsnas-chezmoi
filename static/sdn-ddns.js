/*
 * Firewall → Dynamic DNS. ddclient (unit znas-sdn-ddns) keeps names at a DNS
 * provider pointed at a gateway's public address: one card per gateway, each
 * with its own names, so every Internet link can be reached by name. Status
 * per name comes from GET /api/sdn/ddns/status (ddclient's cache).
 */
(function () {
  'use strict';

  let F = null;
  let st = null;     // GET /api/sdn/ddns/status
  let live = [];     // GET /api/sdn/interfaces/live

  // Provider fields, as the editor asks for them (keys = sdn.DDNSProviders).
  const PROVIDERS = {
    cloudflare: { label: 'Cloudflare', pass: 'API token', passHint: 'A token with the Zone → DNS → Edit permission for this zone', zone: true, hosts: 'home.example.com, vpn.example.com' },
    duckdns: { label: 'DuckDNS', pass: 'Token', hosts: 'myhome.duckdns.org' },
    noip: { label: 'No-IP', user: 'User name', pass: 'Password', hosts: 'myhome.ddns.net' },
    dyn: { label: 'Dyn', user: 'User name', pass: 'Updater client key', hosts: 'myhome.dyndns.org' },
    namecheap: { label: 'Namecheap', user: 'Domain', userPh: 'example.com', pass: 'Dynamic DNS password', hosts: 'home.example.com' },
    ovh: { label: 'OVH', user: 'DynHost login', pass: 'Password', hosts: 'home.example.com' },
    custom: { label: 'Other (dyndns2 protocol)', user: 'User name', pass: 'Password', server: true, hosts: 'home.example.net' },
  };
  const STATUS = {
    good: ['up', 'Updated'], nochg: ['up', 'Up to date'], noconnect: ['down', 'Cannot reach the provider'],
    badauth: ['down', 'Wrong user name or token'], nohost: ['down', 'Name unknown to the provider'], notfqdn: ['down', 'Not a full host name'],
    abuse: ['down', 'Blocked by the provider (too many updates)'], numhost: ['down', 'Too many names'], dnserr: ['down', 'Provider DNS error'],
    failed: ['down', 'Update failed'], '911': ['down', 'Provider problem — retrying later'],
  };

  const ifaceById = id => F.cfg().interfaces.find(i => i.id === id);
  const sortedGws = () => F.cfg().gateways.slice().sort((a, b) => a.priority - b.priority);
  const dot = i => `<span class="fw-cdot" style="background:${F.C(i && i.color)}"></span>`;
  const isPrivate = ip => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|169\.254\.)/.test(ip || '');

  function ifaceAddr(i) {
    if (!i) return '';
    const L = live.find(l => l.device === F.l3(i)) || {};
    return ((L.ipv4 || [])[0] || '').split('/')[0];
  }

  async function load() {
    const [a, b] = await Promise.all([F.api('GET', '/api/sdn/ddns/status'), F.api('GET', '/api/sdn/interfaces/live')]);
    st = a.ok ? a.data : null;
    live = b.ok ? (b.data || []) : [];
  }

  function stateOf(e, h) {
    const s = F.status() || {};
    const applied = st && st.entries && st.entries[e.id];
    if (!e.enabled) return ['none', 'Off', ''];
    if (!s.enabled || !applied) return ['none', 'Not applied yet', ''];
    const x = applied[h];
    if (!x || !x.status) return ['none', 'Waiting for the first check', ''];
    const [cls, label] = STATUS[x.status] || ['down', x.status];
    const when = x.updated && !x.updated.startsWith('0001') ? 'updated ' + F.fmtTime(x.updated) : (x.checked && !x.checked.startsWith('0001') ? 'checked ' + F.fmtTime(x.checked) : '');
    return [cls, label, [x.ip, when].filter(Boolean).join(' · ')];
  }

  function html() {
    const c = F.cfg(), admin = F.isAdmin(), s = F.status() || {};
    const gws = sortedGws();
    const used = (c.ddns || []).some(e => e.enabled);
    const cards = gws.map(g => {
      const i = ifaceById(g.interface);
      const addr = ifaceAddr(i);
      const entries = (c.ddns || []).filter(e => e.gateway === g.id);
      const rows = entries.map(e => {
        const p = PROVIDERS[e.provider] || { label: e.provider };
        const names = e.hostnames.map(h => {
          const [cls, label, sub] = stateOf(e, h);
          return `<div class="fw-ddns-h"><span class="fw-mono">${F.E(h)}</span><span class="fw-gwstate ${cls}">${F.E(label)}</span>${sub ? `<span class="fw-ddns-sub">${F.E(sub)}</span>` : ''}</div>`;
        }).join('');
        return `<tr data-id="${F.E(e.id)}"><td>${names}${e.description ? `<div class="fw-ddns-sub">${F.E(e.description)}</div>` : ''}</td>
          <td>${F.E(p.label)}</td><td>${e.ip_source === 'web' ? 'Seen from the Internet' : 'Interface address'}</td>
          <td style="text-align:right;white-space:nowrap">${admin ? `<button class="fw-icon-btn" data-edit="${F.E(e.id)}">${F.icon('pencil', 12)}Edit</button>
            <button class="fw-icon-btn danger" data-del="${F.E(e.id)}">${F.icon('trash', 12)}Remove</button>` : ''}</td></tr>`;
      }).join('');
      return `<div class="fw-card fw-ddns-card" data-gw="${F.E(g.id)}">
        <div class="fw-stripe" style="background:${F.C(i && i.color)}"></div>
        <div class="fw-card-h"><span class="fw-name">${F.E(g.name)}</span>
          <span class="fw-pillx">${dot(i)}${F.E(i ? i.name : '(deleted interface)')}</span>
          <span style="flex:1"></span>
          <span class="fw-ddns-addr" title="Address on the gateway's interface">${addr ? `${F.icon('globe', 12)}<span class="fw-mono">${F.E(addr)}</span>${isPrivate(addr) ? ' <span class="fw-badge none" title="A private address: a modem in front of this server does NAT. Use “Seen from the Internet” for this gateway\'s names.">private</span>' : ''}` : 'no address yet'}</span></div>
        ${entries.length ? `<div class="fw-tscroll"><table class="fw-table"><thead><tr><th>Names</th><th>Provider</th><th>Address sent</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
          : '<div class="fw-empty" style="padding:10px 0">No dynamic DNS name for this gateway.</div>'}
        ${admin ? `<div class="fw-card-actions"><button class="fw-icon-btn" data-add="${F.E(g.id)}">${F.icon('plus', 12)}Add dynamic DNS</button></div>` : ''}
      </div>`;
    }).join('');
    return `
      ${st && !st.installed ? `<div class="fw-safemode" style="background:rgba(255,214,10,.10);border-color:rgba(255,214,10,.4)">${F.icon('info', 16)}
        <div>Dynamic DNS needs the <b>ddclient</b> package on this server.</div><span style="flex:1"></span>${admin ? '<button class="fw-btn" data-install="ddclient">Install</button>' : ''}</div>` : ''}
      ${used && s.enabled && st && st.installed && Object.keys(st.entries || {}).length && !st.running ? `<div class="fw-safemode">${F.icon('info', 16)}<div><b>Dynamic DNS is not running</b> — check the <span class="fw-mono">znas-sdn-ddns</span> service.</div></div>` : ''}
      <div class="fw-note" style="margin-bottom:10px">Keeps host names at your DNS provider pointed at this router's public address. Each gateway has its own names, which follow that link's address even while traffic uses another gateway. The address is checked every 5 minutes; the provider is only called when it changed.</div>
      ${gws.length ? `<div class="fw-ddns-list">${cards}</div>` : '<div class="fw-empty">No gateway yet — add your Internet links on the Routing page first.</div>'}`;
  }

  function wire(root) {
    root.querySelectorAll('[data-install]').forEach(b => b.onclick = async () => {
      b.disabled = true; b.textContent = 'Installing…';
      const r = await F.api('POST', '/api/prereqs/install', { package: 'ddclient' });
      if (r.ok) { F.toast('ddclient installed', 'success'); await load(); F.rerender(); }
      else { b.disabled = false; b.textContent = 'Install'; F.toast((r.data && r.data.error) || 'Install failed', 'error'); }
    });
    root.querySelectorAll('[data-add]').forEach(b => b.onclick = () => edit(null, b.dataset.add));
    root.querySelectorAll('[data-edit]').forEach(b => b.onclick = () => edit(b.dataset.edit));
    root.querySelectorAll('[data-del]').forEach(b => b.onclick = () => {
      const e = F.cfg().ddns.find(x => x.id === b.dataset.del);
      F.modal({ title: `Remove ${e.hostnames.join(', ')}?`, body: '<p>This router stops updating these names when you apply. The records stay at the provider with their last address.</p>',
        buttons: [{ label: 'Cancel' }, { label: 'Remove', cls: 'btn-danger', onClick: close => { close(); F.saveDraft(n => { n.ddns = n.ddns.filter(x => x.id !== e.id); }); } }] });
    });
  }

  function edit(id, gwId) {
    const c = F.cfg();
    const idx = id ? c.ddns.findIndex(x => x.id === id) : -1;
    const g0 = c.gateways.find(x => x.id === gwId);
    const addr0 = g0 ? ifaceAddr(ifaceById(g0.interface)) : '';
    const e = idx >= 0 ? F.clone(c.ddns[idx]) : { id: F.newId(), enabled: true, gateway: gwId, provider: 'cloudflare', hostnames: [], login: '', password: '', zone: '', server: '', ip_source: isPrivate(addr0) ? 'web' : '', description: '' };
    const dr = F.drawer(idx >= 0 ? 'Edit dynamic DNS' : 'New dynamic DNS', 'Keeps names pointed at a gateway\'s public address', `
      ${F.cb('fwy-en', 'Update these names', e.enabled)}
      <div class="fw-field" style="margin-top:12px"><label>Gateway</label><div id="fwy-gw"></div><div class="fw-err" id="fwy-gw-err"></div></div>
      <div class="fw-field"><label>Provider</label><div id="fwy-pv"></div><div class="fw-err" id="fwy-pv-err"></div></div>
      <div class="fw-field" data-f="zone"><label>Zone</label><input type="text" id="fwy-zone" placeholder="example.com"><div class="fw-err" id="fwy-zone-err"></div></div>
      <div class="fw-field"><label>Host names</label><input type="text" id="fwy-hosts" spellcheck="false"><div class="fw-hint" style="font-size:11.5px;color:var(--text-3);margin-top:3px">Several names at the same provider: separate them with commas.</div><div class="fw-err" id="fwy-hosts-err"></div></div>
      <div class="fw-field" data-f="server"><label>Update server</label><input type="text" id="fwy-server" placeholder="dyndns.example.net — always over HTTPS"><div class="fw-err" id="fwy-server-err"></div></div>
      <div class="fw-field" data-f="user"><label data-l="user">User name</label><input type="text" id="fwy-user" autocomplete="off" spellcheck="false"><div class="fw-err" id="fwy-user-err"></div></div>
      <div class="fw-field"><label data-l="pass">Password</label><input type="password" id="fwy-pass" autocomplete="new-password"><div class="fw-hint" data-l="passHint" style="font-size:11.5px;color:var(--text-3);margin-top:3px"></div><div class="fw-err" id="fwy-pass-err"></div></div>
      <div class="fw-field"><label>Address sent</label><div id="fwy-src"></div><div class="fw-hint" id="fwy-src-h" style="font-size:11.5px;color:var(--text-3);margin-top:5px"></div><div class="fw-err" id="fwy-src-err"></div></div>
      <div class="fw-field"><label>Description</label><input type="text" id="fwy-desc" placeholder="optional"></div>`,
      '<button class="fw-btn" id="fwy-cancel">Cancel</button><button class="fw-btn fw-apply" id="fwy-save">Save to draft</button>');
    const q = dr.q;
    q('#fwy-zone').value = e.zone || ''; q('#fwy-hosts').value = e.hostnames.join(', '); q('#fwy-server').value = e.server || '';
    q('#fwy-user').value = e.login || ''; q('#fwy-desc').value = e.description || '';
    q('#fwy-pass').placeholder = e.password_set ? 'unchanged — type to replace' : '';
    const srcHint = () => {
      const g = c.gateways.find(x => x.id === e.gateway), a = g ? ifaceAddr(ifaceById(g.interface)) : '';
      q('#fwy-src-h').textContent = e.ip_source === 'web'
        ? 'Asks a public service which address this router comes from. Use it when a modem in front of this server does NAT. It reflects the gateway carrying the traffic at that moment.'
        : `The address on the gateway's interface${a ? ` (now ${a}${isPrivate(a) ? ' — private: a modem does NAT, choose “Seen from the Internet”' : ''})` : ''}.`;
    };
    const fields = () => {
      const p = PROVIDERS[e.provider] || PROVIDERS.custom;
      dr.dr.querySelector('[data-f="zone"]').style.display = p.zone ? '' : 'none';
      dr.dr.querySelector('[data-f="server"]').style.display = p.server ? '' : 'none';
      dr.dr.querySelector('[data-f="user"]').style.display = p.user ? '' : 'none';
      dr.dr.querySelector('[data-l="user"]').textContent = p.user || '';
      q('#fwy-user').placeholder = p.userPh || '';
      dr.dr.querySelector('[data-l="pass"]').textContent = p.pass;
      dr.dr.querySelector('[data-l="passHint"]').textContent = p.passHint || '';
      q('#fwy-hosts').placeholder = p.hosts;
    };
    F.picker(q('#fwy-gw'), sortedGws().map(g => { const i = ifaceById(g.interface); return { value: g.id, label: g.name, color: i && i.color, hint: i ? i.name : '' }; }),
      e.gateway, v => { e.gateway = v; srcHint(); });
    F.picker(q('#fwy-pv'), Object.keys(PROVIDERS).map(k => ({ value: k, label: PROVIDERS[k].label })), e.provider, v => { e.provider = v; fields(); });
    F.seg(q('#fwy-src'), [['', 'Interface address'], ['web', 'Seen from the Internet']], e.ip_source || '', v => { e.ip_source = v; srcHint(); });
    fields(); srcHint();
    q('#fwy-cancel').onclick = dr.close;
    q('#fwy-save').onclick = async () => {
      const p = PROVIDERS[e.provider] || {};
      e.enabled = q('#fwy-en').checked;
      e.hostnames = q('#fwy-hosts').value.split(/[\s,]+/).filter(Boolean);
      e.zone = p.zone ? q('#fwy-zone').value.trim() : '';
      e.server = p.server ? q('#fwy-server').value.trim() : '';
      e.login = p.user ? q('#fwy-user').value.trim() : '';
      const pw = q('#fwy-pass').value;
      if (pw) { e.password = pw; e.password_set = false; }
      e.description = q('#fwy-desc').value.trim();
      const next = F.clone(c);
      next.ddns = next.ddns || [];
      const at = idx >= 0 ? idx : next.ddns.push(e) - 1;
      next.ddns[at] = e;
      if (F.showErrors(dr.dr, await F.validate(next), `ddns[${at}]`, { gateway: '#fwy-gw-err', provider: '#fwy-pv-err', zone: '#fwy-zone-err', hostnames: '#fwy-hosts-err',
        server: '#fwy-server-err', login: '#fwy-user-err', password: '#fwy-pass-err', ip_source: '#fwy-src-err' }, '[data-err]')) return;
      dr.close();
      F.saveDraft(n => { n.ddns = next.ddns; });
    };
  }

  function register() {
    if (typeof window.sdnRegisterPage !== 'function' || !window.sdnFW || !window.sdnFW.drawer) { setTimeout(register, 200); return; }
    F = window.sdnFW;
    window.sdnRegisterPage('fw-ddns', { load, render: html, wire, pollMs: 15000, poll: load });
  }
  register();
})();
