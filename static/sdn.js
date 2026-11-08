/*
 * ZNAS Firewall mode (SDN — routing & firewall). Spec: PLANS/spec-sdn-firewall.md
 *
 * Every edit goes to the server-side draft (PUT /api/sdn/draft with the
 * revision it was based on). Nothing touches the router until Apply, which can
 * arm a 30 s auto-revert that only "All good — keep it" disarms (off by
 * default; the last choice is remembered for the browser session).
 * The countdown is owned by the server, so reloading the page re-opens it
 * with the real remaining time.
 *
 * Loaded after index.html's inline script; uses its globals (showPage,
 * showToast, esc, currentUser, znasIcon, _sidebarMode).
 */
(function () {
  'use strict';

  const COUNTDOWN = 30;
  const PALETTE = ['#64d2ff', '#bf5af2', '#30d158', '#ff9f0a', '#ff375f', '#5e5ce6', '#ffd60a', '#40c8e0', '#ac8e68'];
  const PAGES = {
    'fw-topo':      { title: 'Local Topo' },
    'fw-traffic':   { title: 'Traffic & GeoMap' },
    'fw-live':      { title: 'Live connections' },
    'fw-ids':       { title: 'IDS alerts' },
    'fw-dns':       { title: 'DNS queries' },
    'fw-interfaces':{ title: 'Interfaces' },
    'fw-rules':     { title: 'Rules' },
    'fw-nat':       { title: 'NAT' },
    'fw-gateways':  { title: 'Routing' },
    'fw-groups':    { title: 'Groups & countries' },
    'fw-dhcp':      { title: 'DHCP & DNS' },
    'fw-wireguard': { title: 'WireGuard' },
    'fw-ddns':      { title: 'Dynamic DNS' },
    'fw-suricata':  { title: 'Intrusion detection' },
  };

  let status = null;       // GET /api/sdn/status
  let draft = null;        // GET /api/sdn/draft
  let live = [];           // GET /api/sdn/interfaces/live
  let incusNets = [];      // GET /api/sdn/incus-networks (host-nat: read-only)
  let counters = {};       // GET /api/sdn/counters
  let page = 'fw-interfaces';
  // Pages implemented in other files (sdn-traffic.js) register here.
  const registered = {};
  window.sdnRegisterPage = (name, impl) => {
    registered[name] = impl;
    // Shown before it registered (reload straight onto it): its data load
    // and poll never started — start them now.
    const el = document.getElementById('page-' + name);
    if (page === name && el && !el.classList.contains('hidden')) onShowPage(name);
  };
  let rulesTab = 'all';
  let pollTimer = null;
  let countdownTimer = null;

  // ── helpers ────────────────────────────────────────────────────────────
  const E = s => (typeof window.esc === 'function' ? window.esc(s) : String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'));
  // Colours reach style attributes: only #rrggbb passes (stored XSS guard).
  const C = c => (/^#[0-9a-f]{6}$/i.test(c || '') ? c : '#888888');
  const icon = (n, size) => (typeof window.znasIcon === 'function' ? window.znasIcon(n, { size: size || 14 }) : '');
  const me = () => (typeof currentUser !== 'undefined' ? currentUser : null); // top-level let in index.html, not a window property
  const isAdmin = () => !!me() && me().role === 'admin';
  const toast = (m, t) => (typeof window.showToast === 'function' ? window.showToast(m, t) : null);
  const cfg = () => {
    const c = (draft && draft.config) || {};
    c.interfaces = c.interfaces || []; c.groups = c.groups || []; c.rules = c.rules || []; c.settings = c.settings || {};
    c.gateways = c.gateways || []; c.routes = c.routes || []; c.port_forwards = c.port_forwards || []; c.snat_rules = c.snat_rules || [];
    c.dhcp = c.dhcp || []; c.wg_peers = c.wg_peers || [];
    c.dns = c.dns || {}; ['interfaces', 'upstreams', 'hosts', 'forwards'].forEach(k => { c.dns[k] = c.dns[k] || []; });
    c.dhcp.forEach(d => { d.reservations = d.reservations || []; d.dns_servers = d.dns_servers || []; });
    c.groups.forEach(g => { g.members = g.members || []; });
    return c;
  };
  const clone = o => JSON.parse(JSON.stringify(o));
  const newId = () => Array.from(crypto.getRandomValues(new Uint8Array(4))).map(b => b.toString(16).padStart(2, '0')).join('');

  async function api(method, url, body) {
    const opt = { method, headers: {}, credentials: 'same-origin' };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    let res;
    try { res = await fetch(url, opt); } catch (e) { return { ok: false, status: 0, data: { error: 'The server is not reachable' } }; }
    let data = null;
    try { data = await res.json(); } catch (_) {}
    return { ok: res.ok, status: res.status, data };
  }

  function fmtTime(iso, seconds) {
    const d = new Date(iso);
    const p = n => String(n).padStart(2, '0');
    return `${p(d.getHours())}:${p(d.getMinutes())}${seconds ? ':' + p(d.getSeconds()) : ''} ${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
  }
  function fmtCount(n) {
    n = Number(n || 0);
    if (n >= 1e9) return (n / 1e9).toFixed(1) + 'G';
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
    return String(n);
  }
  function fmtBps(b) {
    b = Number(b || 0) * 8;
    if (b >= 1e9) return (b / 1e9).toFixed(1) + ' Gb/s';
    if (b >= 1e6) return (b / 1e6).toFixed(1) + ' Mb/s';
    if (b >= 1e3) return (b / 1e3).toFixed(0) + ' kb/s';
    return b.toFixed(0) + ' b/s';
  }
  function spark(values, color, w, h) {
    w = w || 70; h = h || 18;
    if (!values || values.length < 2) return `<svg class="fw-spark" width="${w}" height="${h}"></svg>`;
    const v = values.slice(-48), m = Math.max(1, ...v);
    const pts = v.map((x, i) => `${(i * (w / (v.length - 1))).toFixed(1)},${(h - 1 - (h - 2) * x / m).toFixed(1)}`).join(' ');
    return `<svg class="fw-spark" width="${w}" height="${h}"><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.4"/></svg>`;
  }

  // Modal built on the app's .modal-backdrop/.modal classes (no browser popups).
  // ── "i" information popovers ────────────────────────────────────────────
  // info(title, html) is a small round button; it opens a card with the
  // title and the explanation: on click (touch) or hover (mouse), closed by
  // a click elsewhere, Esc or scrolling. lab(text, title, html) is a field
  // label followed by its button (kept outside <label>: a button inside a
  // label becomes the label's control).
  const INFO = new Map();
  function info(title, html) {
    INFO.set(title, html);
    return `<button type="button" class="fw-info" data-info="${E(title)}" aria-label="About: ${E(title)}" aria-haspopup="dialog"></button>`;
  }
  const lab = (text, title, html) => `<div class="fw-lab"><label>${text}</label>${info(title, html)}</div>`;
  let infoPop = null, infoBtn = null, infoTimer = 0, infoAt = 0;
  function closeInfo() {
    clearTimeout(infoTimer);
    if (infoPop) infoPop.remove();
    if (infoBtn) infoBtn.classList.remove('open');
    infoPop = infoBtn = null;
  }
  function openInfo(btn, byHover) {
    const html = INFO.get(btn.dataset.info);
    if (!html) return;
    closeInfo();
    infoBtn = btn; btn.classList.add('open'); infoAt = Date.now();
    infoPop = document.createElement('div');
    infoPop.className = 'fw-infopop'; infoPop.setAttribute('role', 'dialog');
    if (byHover) infoPop.dataset.hover = '1';
    infoPop.innerHTML = `<div class="fw-infopop-h">${icon('info', 14)}<span>${E(btn.dataset.info)}</span></div><div class="fw-infopop-b">${html}</div>`;
    document.body.appendChild(infoPop);
    const r = btn.getBoundingClientRect(), w = Math.min(340, window.innerWidth - 24);
    infoPop.style.width = w + 'px';
    const h = infoPop.offsetHeight;
    let top = r.bottom + 8;
    if (top + h > window.innerHeight - 12 && r.top - h - 8 > 12) top = r.top - h - 8;
    infoPop.style.left = Math.min(Math.max(12, r.left + r.width / 2 - w / 2), window.innerWidth - w - 12) + 'px';
    infoPop.style.top = Math.max(12, top) + 'px';
    infoPop.onmouseenter = () => clearTimeout(infoTimer);
    infoPop.onmouseleave = () => { if (infoPop && infoPop.dataset.hover) infoTimer = setTimeout(closeInfo, 250); };
  }
  document.addEventListener('click', e => {
    const b = e.target.closest && e.target.closest('.fw-info');
    if (b) {
      e.preventDefault(); e.stopPropagation();
      // a click pins a card opened by hovering; a second click closes it
      if (infoBtn === b && infoPop && infoPop.dataset.hover) delete infoPop.dataset.hover;
      else if (infoBtn === b) closeInfo();
      else openInfo(b, false);
      return;
    }
    if (infoPop && !infoPop.contains(e.target)) closeInfo();
  }, true);
  const canHover = window.matchMedia && window.matchMedia('(hover: hover) and (pointer: fine)').matches;
  if (canHover) {
    document.addEventListener('mouseover', e => {
      const b = e.target.closest && e.target.closest('.fw-info');
      if (!b) return;
      clearTimeout(infoTimer);
      if (infoBtn !== b) infoTimer = setTimeout(() => openInfo(b, true), 250);
    });
    document.addEventListener('mouseout', e => {
      const b = e.target.closest && e.target.closest('.fw-info');
      if (!b) return;
      clearTimeout(infoTimer);
      if (infoPop && infoPop.dataset.hover) infoTimer = setTimeout(closeInfo, 250);
    });
  }
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && infoPop) { e.stopPropagation(); closeInfo(); } }, true);
  // a scroll closes it — not the one that brought the button into view
  document.addEventListener('scroll', e => { if (infoPop && !infoPop.contains(e.target) && Date.now() - infoAt > 400) closeInfo(); }, true);

  function modal({ title, body, buttons, width, locked }) {
    const bg = document.createElement('div');
    bg.className = 'modal-backdrop';
    bg.innerHTML = `<div class="modal" style="max-width:${width || 520}px;width:100%;">
      <div class="modal-header"><h3>${E(title)}</h3>${locked ? '' : `<button class="modal-close">${icon('x', 16)}</button>`}</div>
      <div class="modal-body"></div><div class="modal-footer"></div></div>`;
    const bodyEl = bg.querySelector('.modal-body');
    if (typeof body === 'string') bodyEl.innerHTML = body; else if (body) bodyEl.appendChild(body);
    const close = () => bg.remove();
    if (!locked) {
      bg.addEventListener('click', e => { if (e.target === bg) close(); });
      bg.querySelector('.modal-close').onclick = close;
    }
    const foot = bg.querySelector('.modal-footer');
    (buttons || []).forEach(b => {
      const btn = document.createElement('button');
      btn.className = 'btn ' + (b.cls || 'btn-ghost');
      btn.textContent = b.label;
      if (b.id) btn.id = b.id;
      btn.onclick = () => b.onClick ? b.onClick(close, btn) : close();
      foot.appendChild(btn);
    });
    document.body.appendChild(bg);
    return { el: bg, body: bodyEl, close, foot };
  }

  // Button + popover picker (custom dropdown rule). options: [{value,label,section,disabled,hint,color}]
  function picker(el, options, value, onChange, opts) {
    opts = opts || {};
    const render = () => {
      const cur = options.find(o => o.value === value);
      el.innerHTML = `<div class="fw-picker"><button type="button" class="fw-picker-btn">${cur && cur.color ? `<span class="fw-cdot" style="width:9px;height:9px;border-radius:50%;background:${C(cur.color)}"></span>` : ''}<span>${E(cur ? cur.label : (opts.placeholder || 'Choose…'))}</span><span class="fw-caret">${icon('chevron-down', 13)}</span></button></div>`;
      el.querySelector('button').onclick = e => { e.stopPropagation(); open(); };
    };
    const open = () => {
      document.querySelectorAll('.fw-picker-pop').forEach(p => p.remove());
      const pop = document.createElement('div');
      pop.className = 'fw-picker-pop';
      const searchable = options.length > 8 || opts.search;
      pop.innerHTML = (searchable ? '<input type="text" placeholder="Search…">' : '') + '<div class="fw-picker-list"></div>';
      el.querySelector('.fw-picker').appendChild(pop);
      // Float above the page (fixed) so a modal's scrolling body can't clip
      // the list; open upward when there is more room above the button. The
      // visual viewport excludes an on-screen keyboard.
      const place = () => {
      const r = el.querySelector('.fw-picker-btn').getBoundingClientRect();
      const vv = window.visualViewport;
      const vTop = vv ? vv.offsetTop : 0, vBottom = vv ? vv.offsetTop + vv.height : window.innerHeight;
      const below = vBottom - r.bottom - 12, above = r.top - vTop - 12;
      const up = below < 220 && above > below;
      Object.assign(pop.style, { position: 'fixed', left: r.left + 'px', right: 'auto', width: Math.max(r.width, opts.width || 220) + 'px',
        top: up ? 'auto' : (r.bottom + 4) + 'px', bottom: up ? (window.innerHeight - r.top + 4) + 'px' : 'auto',
        maxHeight: Math.max(160, Math.min(360, up ? above : below)) + 'px', zIndex: 1000 });
      // An ancestor with a transform/filter makes "fixed" relative to it: correct by the measured offset.
      const pr = pop.getBoundingClientRect();
      const dx = pr.left - r.left, dy = up ? pr.bottom - (r.top - 4) : pr.top - (r.bottom + 4);
      if (Math.abs(dx) > 1) pop.style.left = (r.left - dx) + 'px';
      if (Math.abs(dy) > 1) { if (up) pop.style.bottom = (window.innerHeight - r.top + 4 + dy) + 'px'; else pop.style.top = (r.bottom + 4 - dy) + 'px'; }
      };
      place();
      // Touch screens: focusing the search box brings up the keyboard, which
      // scrolls the page and resizes the viewport — that must not close the list.
      // An iPad with a trackpad reports a mouse-like pointer, hence maxTouchPoints.
      const touch = navigator.maxTouchPoints > 0;
      // A mouse or trackpad press blurs the search box before its click lands;
      // on an iPad that moves the viewport under the press.
      pop.onmousedown = e => { if (e.target.tagName !== 'INPUT') e.preventDefault(); };
      let closed = false;
      const close = () => {
        if (closed) return;
        closed = true;
        pop.remove();
        document.removeEventListener('click', off); window.removeEventListener('scroll', off, true); window.removeEventListener('resize', off);
      };
      const list = pop.querySelector('.fw-picker-list');
      const draw = q => {
        let sec = null, html = '';
        options.filter(o => !q || o.label.toLowerCase().includes(q)).forEach(o => {
          if (o.section && o.section !== sec) { sec = o.section; html += `<div class="fw-picker-sec">${E(sec)}</div>`; }
          html += `<div class="fw-picker-opt${o.value === value ? ' on' : ''}${o.disabled ? ' dis' : ''}" data-v="${E(o.value)}">${o.color ? `<span style="width:9px;height:9px;border-radius:50%;background:${C(o.color)}"></span>` : ''}${E(o.label)}${o.hint ? `<small>${E(o.hint)}</small>` : ''}</div>`;
        });
        list.innerHTML = html || '<div class="fw-empty">No match</div>';
        list.querySelectorAll('.fw-picker-opt:not(.dis)').forEach(d => d.onclick = e => {
          e.stopPropagation();
          value = d.dataset.v; close(); render(); onChange(value);
        });
      };
      draw('');
      const inp = pop.querySelector('input');
      if (inp) { inp.oninput = () => draw(inp.value.toLowerCase()); inp.onclick = e => e.stopPropagation(); if (!touch) setTimeout(() => inp.focus(), 0); }
      // A fixed list would drift away from its button: close on outside click,
      // on any scroll outside the list, and on resize; on touch screens follow
      // the button instead, only an outside tap closes.
      function off(e) {
        if (!pop.isConnected) return close(); // another picker opened
        if (e.type !== 'click') {
          if (e.target instanceof Node && pop.contains(e.target)) return;
          if (touch) return place();
        }
        close();
      }
      setTimeout(() => { document.addEventListener('click', off); window.addEventListener('scroll', off, true); window.addEventListener('resize', off); }, 0);
    };
    render();
    return { set: v => { value = v; render(); } };
  }

  // Edit + Clone buttons at the end of a rule/NAT row (admins only; the cell stays for the grid).
  function rowActs(kind, idx, noClone) {
    if (!isAdmin()) return '<span></span>';
    return `<span class="fw-rowacts"><button type="button" class="fw-rbtn" data-${kind}edit="${idx}" title="Edit">${icon('pencil', 14)}</button>${noClone ? '' : `<button type="button" class="fw-rbtn" data-${kind}clone="${idx}" title="Clone — opens a new rule prefilled from this one">${icon('copy', 14)}</button>`}</span>`;
  }

  const cloneDesc = d => d ? (/ \(copy\)$/.test(d) ? d : d + ' (copy)') : '';

  function seg(el, items, value, onChange) {
    el.innerHTML = `<div class="fw-seg">${items.map(i => `<button type="button" data-v="${E(i[0])}" class="${i[0] === value ? 'on' : ''}">${E(i[1])}</button>`).join('')}</div>`;
    el.querySelectorAll('button').forEach(b => b.onclick = () => {
      el.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b));
      onChange(b.dataset.v);
    });
  }

  // ── status / draft ─────────────────────────────────────────────────────
  async function loadStatus() {
    const r = await api('GET', '/api/sdn/status');
    status = r.ok ? r.data : null;
    window._sdnEnabled = !!(status && status.enabled);
    // interface names may have changed (Apply, revert, restore)
    if (typeof window._loadIfNames === 'function') window._loadIfNames();
    if (typeof window._sdnFwdReset === 'function') window._sdnFwdReset();
    window._sdnMode = status && status.mode;
    syncModeButton();
    renderOptFeatRow();
    if (status && status.pending && isAdmin() && !document.getElementById('fw-countdown')) {
      openCountdown(status.pending.seconds_left);
    }
    return status;
  }

  async function loadDraft() {
    const r = await api('GET', '/api/sdn/draft');
    if (r.ok) draft = r.data;
    return draft;
  }

  // Save the draft: mutate a copy, PUT it with the revision it was based on.
  async function saveDraft(mutator) {
    if (!draft) await loadDraft();
    const next = clone(cfg());
    if (mutator(next) === false) return false;
    const r = await api('PUT', '/api/sdn/draft', { base_revision: draft.revision, config: next });
    if (r.status === 409) {
      modal({ title: 'Someone else changed the firewall', body: `<p>${E(r.data && r.data.error)}</p><p>Their changes are loaded now; please redo your edit.</p>`,
        buttons: [{ label: 'OK', cls: 'btn-primary' }] });
      await loadDraft(); renderPage();
      return false;
    }
    if (!r.ok) { toast((r.data && r.data.error) || 'Could not save', 'error'); return false; }
    draft = r.data;
    renderPage();
    return true;
  }

  // Validate the whole draft config; returns errors keyed by path.
  async function validate(conf) {
    const r = await api('POST', '/api/sdn/validate', conf);
    return (r.ok && r.data && r.data.errors) || [];
  }

  // ── sidebar mode + nav ─────────────────────────────────────────────────
  function syncModeButton() {
    const btn = document.getElementById('mode-btn-firewall');
    const sel = document.getElementById('sidebar-mode-selector');
    const can = canView();
    if (btn) btn.style.display = window._sdnEnabled && can ? '' : 'none';
    if (sel && window._sdnEnabled && can) sel.style.display = '';
    if (!window._sdnEnabled && typeof _sidebarMode !== 'undefined' && _sidebarMode === 'firewall' && typeof window._applySidebarModeUI === 'function') {
      window._applySidebarModeUI('storage');
      if (typeof window.showPage === 'function') window.showPage('dashboard');
    }
    if (typeof window._mSyncVmsTab === 'function') window._mSyncVmsTab();
  }
  function canView() {
    const u = me();
    if (!u) return false;
    if (u.role === 'admin' || u.role === 'read-only' || u.role === 'readonly') return true;
    return !!(u.standard_perms && u.standard_perms.view_firewall);
  }

  function ensurePages() {
    const anchor = document.getElementById('page-lxd-networks') || document.getElementById('page-dashboard');
    if (!anchor) return;
    Object.keys(PAGES).forEach(name => {
      if (document.getElementById('page-' + name)) return;
      const d = document.createElement('div');
      d.className = 'page hidden';
      d.id = 'page-' + name;
      d.innerHTML = '<div class="fw-page"></div>';
      anchor.parentNode.appendChild(d);
    });
  }

  // Called by showPage() for every fw-* page.
  function onShowPage(name) {
    const reg = registered[name];
    if (reg && document.getElementById('page-' + name)) {
      page = name;
      clearInterval(pollTimer); pollTimer = null;
      renderPage();
      Promise.all([loadDraft(), loadStatus(), reg.load(() => { if (page === name) renderPage(); })]).then(renderPage);
      // a poll returning false skips the redraw (e.g. a drop-down is open)
      if (reg.pollMs) pollTimer = setInterval(async () => { if (page === name && !document.hidden && (await reg.poll()) !== false) renderPage(); }, reg.pollMs);
      return;
    }
    if (!document.getElementById('page-' + name)) {
      // showPage() ran before our containers existed and fell back to the
      // dashboard: create them and show the requested page for real.
      ensurePages();
      if (document.getElementById('page-' + name)) { window.showPage(name); return; }
    }
    page = name;
    clearInterval(pollTimer); pollTimer = null;
    renderPage();
    Promise.all([loadDraft(), loadStatus()]).then(renderPage);
    if (name === 'fw-interfaces') {
      let n = 0;
      const tick = () => { const slow = !(n++ % 3); // status: virtual IP states
        return Promise.all([api('GET', '/api/sdn/interfaces/live'), slow ? loadStatus() : null, slow ? api('GET', '/api/sdn/incus-networks') : null])
          .then(([r, , inc]) => { if (inc && inc.ok) incusNets = inc.data || []; if (r.ok) { live = r.data || []; if (page === 'fw-interfaces') renderPage(); } }); };
      tick();
      pollTimer = setInterval(() => { if (page === 'fw-interfaces' && !document.hidden) tick(); }, 5000);
    }
    if (name === 'fw-rules') {
      const tick = () => api('GET', '/api/sdn/counters').then(r => { if (r.ok) { counters = r.data || {}; if (page === 'fw-rules') renderPage(); } });
      tick();
      pollTimer = setInterval(() => { if (page === 'fw-rules' && !document.hidden) tick(); }, 15000);
      api('GET', '/api/sdn/interfaces/live').then(r => { if (r.ok) live = r.data || []; });
    }
  }

  // ── top bar ────────────────────────────────────────────────────────────
  function topbar(title) {
    const n = (draft && draft.pending_changes) || 0;
    const lc = status && status.last_change;
    const admin = isAdmin();
    return `
      ${status && status.enabled && (status.missing_packages || []).length && isAdmin() ? `<div class="fw-safemode" style="background:rgba(255,214,10,.10);border-color:rgba(255,214,10,.4)">${icon('info', 16)}<div>Some packages the Firewall uses are missing: <b>${E(status.missing_packages.join(', '))}</b>.</div><span class="fw-sp" style="flex:1"></span><button class="fw-btn" data-act="pkgs">Install</button></div>` : ''}
      ${status && status.safe_mode_reason ? `<div class="fw-safemode">${icon('shield-check', 18)}<div><b>Firewall in SAFE MODE</b> — the saved configuration could not be loaded at boot: ${E(status.safe_mode_reason)}. Only the management interface is reachable.</div><span class="fw-sp" style="flex:1"></span><button class="fw-btn" data-act="history">Restore a previous change</button></div>` : ''}
      <div class="fw-topbar">
        <h2>${E(title)}</h2><span class="fw-sp"></span>
        <div class="fw-dd" data-dd="history">
          <button class="fw-btn" data-act="history" title="Last 15 applied changes — click one to go back to it">${icon('clock', 14)}${lc ? 'Last Change ' + E(fmtTime(lc.at)) : 'No changes yet'} <span style="opacity:.6;display:inline-flex">${icon('chevron-down', 13)}</span></button>
        </div>
        ${admin ? `<button class="fw-btn fw-apply${n ? '' : ' fw-idle'}" data-act="apply" ${n ? '' : 'disabled'} title="${E((draft && draft.summary) || '')}">Apply${n ? ` <span class="fw-pill">${n}</span>` : ''}</button>
        <div class="fw-dd" data-dd="more"><button class="fw-btn" data-act="more" title="More">${icon('more-vertical', 14)}</button></div>` : ''}
      </div>`;
  }

  function wireTopbar(root) {
    root.querySelectorAll('[data-act="history"]').forEach(b => b.onclick = e => { e.stopPropagation(); openHistory(root); });
    const ap = root.querySelector('[data-act="apply"]');
    if (ap) ap.onclick = openApply;
    const pk = root.querySelector('[data-act="pkgs"]');
    if (pk) pk.onclick = async () => {
      pk.disabled = true; pk.textContent = 'Installing…';
      const r = await api('POST', '/api/prereqs/install', { package: 'sdn-firewall' });
      if (!r.ok) { pk.disabled = false; pk.textContent = 'Install'; toast((r.data && r.data.error) || 'Install failed', 'error'); return; }
      toast((r.data && r.data.message) || 'Installed', 'success');
      await loadStatus(); renderPage();
    };
    const more = root.querySelector('[data-act="more"]');
    if (more) more.onclick = e => {
      e.stopPropagation();
      // Every Firewall page keeps its own top bar: open in this one.
      const dd = more.closest('.fw-dd');
      if (dd.querySelector('.fw-menu')) { dd.querySelector('.fw-menu').remove(); return; }
      const m = document.createElement('div');
      m.className = 'fw-menu';
      const n = (draft && draft.pending_changes) || 0;
      // Once Router mode is applied, going back to Monitor only (nothing
      // filtered) lives here, away from the Interfaces page.
      const dm = (cfg().settings && cfg().settings.mode) || 'monitor';
      m.innerHTML = `<div class="fw-menu-item" data-m="export">${icon('download')}Export configuration…</div>
        <div class="fw-menu-item" data-m="import">${icon('upload')}Import configuration…</div>
        ${n ? `<div class="fw-menu-item" data-m="discard">${icon('undo')}Discard ${n} pending change${n > 1 ? 's' : ''}</div>` : ''}
        ${routerApplied() ? (dm === 'router'
          ? `<div class="fw-menu-sep"></div><div class="fw-menu-item fw-warn" data-m="monitor">${icon('alert-triangle')}Switch to Monitor only…</div>`
          : `<div class="fw-menu-sep"></div><div class="fw-menu-item" data-m="router">${icon('shield-check')}Stay in Router mode</div>`) : ''}`;
      dd.appendChild(m);
      m.querySelectorAll('[data-m]').forEach(it => it.onclick = () => {
        m.remove();
        ({ export: openExport, import: openImport, discard: discardDraft, monitor: toMonitor,
          router: () => saveDraft(d => { d.settings.mode = 'router'; }) })[it.dataset.m]();
      });
      setTimeout(() => document.addEventListener('click', function off() { m.remove(); document.removeEventListener('click', off); }), 0);
    };
  }

  const routerApplied = () => !!(status && status.mode === 'router');

  function toMonitor() {
    modal({ title: 'Switch to Monitor only?', body: `<p>When you apply, <b>the firewall stops filtering</b>: every rule is set aside and all traffic is let through, only observed. NAT, DHCP and DNS keep running.</p><p>On a server that protects a network, this opens that network to anything the rules blocked until you switch back to Router.</p>`,
      buttons: [{ label: 'Cancel' }, { label: 'Switch to Monitor only', cls: 'btn-warn', onClick: close => {
        close(); saveDraft(d => { d.settings.mode = 'monitor'; });
      } }] });
  }

  async function discardDraft() {
    modal({ title: 'Discard pending changes?', body: `<p>${E(draft.summary)}</p><p>The firewall keeps running its current configuration.</p>`,
      buttons: [{ label: 'Cancel' }, { label: 'Discard', cls: 'btn-danger', onClick: async close => {
        close();
        await api('DELETE', '/api/sdn/draft');
        await loadDraft(); renderPage();
      } }] });
  }

  // ── history ("Last Change …") ──────────────────────────────────────────
  async function openHistory(root) {
    // Every Firewall page keeps its own top bar (the safe-mode banner's button
    // too): open in the one on screen.
    const host = root || document.querySelector('#page-' + page + ' .fw-page');
    const dd = host && host.querySelector('.fw-dd[data-dd="history"]');
    if (!dd) return;
    if (dd.querySelector('.fw-menu')) { dd.querySelector('.fw-menu').remove(); return; }
    const r = await api('GET', '/api/sdn/history');
    const list = (r.ok && r.data) || [];
    const m = document.createElement('div');
    m.className = 'fw-menu fw-hist';
    const outcomeLabel = { pending: 'waiting for confirmation', confirmed: '', 'auto-reverted': 'auto-reverted', reverted: 'reverted' };
    const curIdx = list.findIndex(s => s.outcome === 'confirmed' || s.outcome === 'pending');
    m.innerHTML = list.length ? list.map((s, i) => `
      <div class="fw-hrow" data-id="${E(s.id)}" data-i="${i}">
        <span class="fw-dot ${s.outcome === 'auto-reverted' || s.outcome === 'reverted' ? 'amber' : (s.outcome === 'pending' ? 'grey' : '')}"></span>
        <div class="fw-s">${E(s.summary)}<div class="fw-t">${E(s.user || 'system')} · ${E(fmtTime(s.at))}${outcomeLabel[s.outcome] ? ' · ' + E(outcomeLabel[s.outcome]) : ''}</div></div>
        <span class="fw-t">${i === curIdx ? 'current' : (isAdmin() ? 'Restore' : '')}</span>
      </div>`).join('') : '<div class="fw-empty">No change applied yet.</div>';
    dd.appendChild(m);
    m.onclick = e => e.stopPropagation();
    m.querySelectorAll('.fw-hrow').forEach(row => row.onclick = () => {
      if (!isAdmin() || Number(row.dataset.i) === curIdx) return;
      m.remove();
      const s = list[Number(row.dataset.i)];
      confirmApply({
        title: 'Go back to this change?',
        summary: `${s.summary} — ${fmtTime(s.at)}`,
        go: autoRevert => api('POST', `/api/sdn/history/${encodeURIComponent(s.id)}/restore`, { auto_revert: autoRevert }),
      });
    });
    setTimeout(() => document.addEventListener('click', function off() { m.remove(); document.removeEventListener('click', off); }), 0);
  }

  // ── apply + countdown ──────────────────────────────────────────────────
  function openApply() {
    if (!draft || !draft.pending_changes) return;
    confirmApply({
      title: 'Apply changes to the router',
      summary: draft.summary,
      go: autoRevert => api('POST', '/api/sdn/apply', { auto_revert: autoRevert }),
    });
  }

  // Auto-revert checkbox: unchecked by default, remembers the last choice for
  // this browser session.
  const AR_KEY = 'znas-fw-autorevert';
  const arLoad = () => { try { return sessionStorage.getItem(AR_KEY) === '1'; } catch (e) { return false; } };
  const arSave = on => { try { sessionStorage.setItem(AR_KEY, on ? '1' : '0'); } catch (e) { /* storage blocked */ } };

  function confirmApply({ title, summary, go }) {
    const body = `
      <p style="margin:0 0 10px;color:var(--text-2)">These changes take effect on the router now:</p>
      <ul style="margin:0 0 14px 18px;padding:0;line-height:1.7">${summary.split(' · ').map(s => `<li>${E(s)}</li>`).join('')}</ul>
      <label style="display:flex;gap:9px;align-items:flex-start;cursor:pointer;font-size:13.5px">
        <input type="checkbox" id="fw-autorevert" ${arLoad() ? 'checked' : ''} style="margin-top:3px">
        <span><b>Auto-revert if not confirmed within ${COUNTDOWN} s</b><br><span style="color:var(--text-3);font-size:12.5px">If this change cuts you off, the router goes back to the previous configuration by itself.</span></span>
      </label>
      <div id="fw-apply-err" style="margin-top:12px"></div>`;
    modal({ title, body, width: 520, buttons: [
      { label: 'Cancel' },
      { label: 'Apply', cls: 'btn-primary', onClick: async (close, btn) => {
        const auto = document.getElementById('fw-autorevert').checked;
        arSave(auto);
        btn.disabled = true; btn.textContent = 'Applying…';
        const r = await go(auto);
        btn.disabled = false; btn.textContent = 'Apply';
        if (!r.ok) {
          const errs = (r.data && r.data.errors) || [];
          document.getElementById('fw-apply-err').innerHTML = `<div class="fw-safemode"><div><b>Not applied.</b> ${E((r.data && r.data.error) || 'The server refused the change.')}${errs.length ? '<ul style="margin:6px 0 0 16px;padding:0">' + errs.map(e => `<li>${E(e.message)}</li>`).join('') + '</ul>' : ''}</div></div>`;
          return;
        }
        close();
        await Promise.all([loadDraft(), loadStatus()]);
        renderPage();
        if (r.data && r.data.seconds > 0) openCountdown(r.data.seconds);
        else toast('Applied', 'success');
        (r.data && r.data.warnings || []).forEach(w => toast(w, 'info'));
      } },
    ] });
  }

  function openCountdown(seconds) {
    if (document.getElementById('fw-countdown')) return;
    const R = 58, C = 2 * Math.PI * R;
    const m = modal({ title: 'Is everything still working?', locked: true, width: 460, body: `
      <div class="fw-count" id="fw-countdown">
        <div class="fw-ring"><svg width="132" height="132"><circle cx="66" cy="66" r="${R}" stroke="var(--surface2)" stroke-width="8" fill="none"/>
          <circle id="fw-ring-arc" cx="66" cy="66" r="${R}" stroke="url(#fw-grad)" stroke-width="8" fill="none" stroke-linecap="round" stroke-dasharray="${C}" stroke-dashoffset="0"/>
          <defs><linearGradient id="fw-grad"><stop offset="0" stop-color="#bf5af2"/><stop offset="1" stop-color="#0a84ff"/></linearGradient></defs></svg>
          <div class="fw-ring-n" id="fw-ring-n">${Math.ceil(seconds)}</div></div>
        <p id="fw-count-msg">The change is live. Click <b>All good — keep it</b> to confirm you can still reach this page. Otherwise the previous configuration comes back automatically.</p>
      </div>`, buttons: [
      { label: 'Revert now', id: 'fw-revert-btn', onClick: async (close, btn) => {
        btn.disabled = true;
        const r = await api('POST', '/api/sdn/revert-now');
        if (!r.ok) { toast((r.data && r.data.error) || 'Revert failed', 'error'); btn.disabled = false; return; }
        stop(); close(); toast('Previous configuration restored', 'success');
        await Promise.all([loadDraft(), loadStatus()]); renderPage();
      } },
      { label: 'All good — keep it', cls: 'btn-primary', id: 'fw-keep-btn', onClick: async (close, btn) => {
        btn.disabled = true;
        const r = await api('POST', '/api/sdn/confirm');
        if (!r.ok) {
          toast((r.data && r.data.error) || 'Could not confirm — the change may already have been reverted', 'error');
          btn.disabled = false;
          if (r.status === 409) { stop(); close(); await Promise.all([loadDraft(), loadStatus()]); renderPage(); }
          return;
        }
        stop(); close(); toast('Change kept', 'success');
        await loadStatus(); renderPage();
      } },
    ] });
    const deadline = Date.now() + seconds * 1000;
    const stop = () => { clearInterval(countdownTimer); countdownTimer = null; };
    const tick = async () => {
      const left = Math.max(0, (deadline - Date.now()) / 1000);
      const n = document.getElementById('fw-ring-n'), arc = document.getElementById('fw-ring-arc');
      if (n) n.textContent = Math.ceil(left);
      if (arc) arc.setAttribute('stroke-dashoffset', String(C * (1 - left / COUNTDOWN)));
      if (left <= 0) {
        stop();
        document.getElementById('fw-count-msg').innerHTML = 'Not confirmed — the router is going back to the previous configuration…';
        m.foot.querySelectorAll('button').forEach(b => b.disabled = true);
        for (let i = 0; i < 20; i++) {
          await new Promise(r => setTimeout(r, 1500));
          const s = await api('GET', '/api/sdn/status');
          if (s.ok && !s.data.pending) { m.close(); toast('Not confirmed in time — previous configuration restored', 'info'); await Promise.all([loadDraft(), loadStatus()]); renderPage(); return; }
        }
        m.close();
      }
    };
    stop();
    countdownTimer = setInterval(tick, 250);
    tick();
  }

  // ── page rendering ─────────────────────────────────────────────────────
  function renderPage() {
    const host = document.querySelector('#page-' + page + ' .fw-page');
    if (!host) return;
    const def = PAGES[page] || { title: 'Firewall' };
    let body;
    const reg = registered[page];
    if (reg && reg.busy && reg.busy()) return; // the user is typing: redraw later
    if (host.querySelector('.fw-topbar .fw-menu')) return; // a top-bar menu is open: redraw at the next refresh
    if (document.querySelector('.fw-menu.fw-incus-menu')) return; // the Incus tag menu is open
    if (reg) body = reg.render();
    else if (def.soon) body = soon(def);
    else if (!draft) body = '<div class="fw-empty">Loading…</div>';
    else if (page === 'fw-interfaces') body = interfacesHTML();
    else if (page === 'fw-groups') body = groupsHTML();
    else if (page === 'fw-rules') body = rulesHTML();
    host.innerHTML = topbar(def.title) + body;
    wireTopbar(host);
    if (draft && page === 'fw-interfaces') wireInterfaces(host);
    if (draft && page === 'fw-groups') wireGroups(host);
    if (draft && page === 'fw-rules') wireRules(host);
    if (reg) reg.wire(host);
    sortTables(host);
  }

  // ── sortable tables ────────────────────────────────────────────────────
  // <table class="fw-table" data-sort="key">: a click on a column title sorts
  // the rows (again: reverse). Cells sort by data-v when set (bytes, times,
  // counts), else by their text: IPv4 (with :port) by address, plain
  // numbers as numbers, the rest alphabetically. The choice survives the
  // page's refreshes. Empty titles (action columns) and data-nosort stay put.
  const sortState = (() => { try { return JSON.parse(sessionStorage.getItem('znas-fw-sort') || '{}') || {}; } catch (_) { return {}; } })();
  function sortVal(td) {
    if (!td) return null;
    const v = td.dataset.v != null ? td.dataset.v : td.textContent.trim();
    if (v === '') return null;
    const ip = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::(\d+))?/.exec(v);
    if (ip) return ((((+ip[1] * 256 + +ip[2]) * 256 + +ip[3]) * 256 + +ip[4]) * 65536) + (+ip[5] || 0);
    if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
    return v.toLowerCase();
  }
  function sortTables(root) {
    root.querySelectorAll('table.fw-table[data-sort]').forEach(tb => {
      const key = tb.dataset.sort, head = tb.tHead && tb.tHead.rows[0], body = tb.tBodies[0];
      if (!head || !body) return;
      const ths = [...head.cells];
      const apply = () => {
        const st = sortState[key];
        ths.forEach((th, i) => {
          th.classList.toggle('fw-sorted', !!st && st.col === i);
          th.setAttribute('aria-sort', st && st.col === i ? (st.desc ? 'descending' : 'ascending') : 'none');
          const ind = th.querySelector('.fw-sort-ind');
          if (ind) ind.innerHTML = st && st.col === i ? icon(st.desc ? 'chevron-down' : 'chevron-up', 12) : icon('chevrons-up-down', 12);
        });
        if (!st || st.col >= ths.length) return;
        const rows = [...body.rows].filter(r => r.cells.length > 1); // one wide cell: "Nothing here"
        rows.sort((a, b) => {
          const x = sortVal(a.cells[st.col]), y = sortVal(b.cells[st.col]);
          if (x === y) return 0;
          if (x === null) return 1; // blanks last, both ways
          if (y === null) return -1;
          const c = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true });
          return st.desc ? -c : c;
        });
        rows.forEach(r => body.appendChild(r));
        tb.dispatchEvent(new Event('fw-sorted'));
      };
      ths.forEach((th, i) => {
        if (th.dataset.nosort != null || !th.textContent.trim()) return;
        th.classList.add('fw-sortable');
        th.title = 'Sort by ' + th.textContent.trim();
        if (!th.querySelector('.fw-sort-ind')) th.insertAdjacentHTML('beforeend', '<span class="fw-sort-ind"></span>');
        th.onclick = () => {
          const cur = sortState[key];
          // amounts start biggest first; words and addresses A→Z / low→high
          const cell = [...body.rows].map(r => r.cells[i]).find(c => sortVal(c) !== null);
          const amount = !!cell && typeof sortVal(cell) === 'number' && !/^\d{1,3}(\.\d{1,3}){3}/.test(cell.dataset.v != null ? cell.dataset.v : cell.textContent.trim());
          sortState[key] = cur && cur.col === i ? { col: i, desc: !cur.desc } : { col: i, desc: amount && th.dataset.asc == null };
          try { sessionStorage.setItem('znas-fw-sort', JSON.stringify(sortState)); } catch (_) {}
          apply();
        };
      });
      apply();
    });
  }

  function soon(def) {
    return `<div class="fw-soon">${icon('sparkles', 28)}<h3>${E(def.title)} — coming in a later update</h3><div>${E(def.soon)}</div></div>`;
  }

  // ── Interfaces ─────────────────────────────────────────────────────────
  const l3 = i => (i.kind === 'vlan' && i.allow_vms) ? (i.bridge_device || ('br-' + i.device).slice(0, 15)) : i.device;
  function liveOf(dev) { return live.find(l => l.device === dev); }
  // PPPoE links and WireGuard tunnels are listed for their live address only.
  const isPort = l => l.kind !== 'ppp' && l.kind !== 'wireguard';
  function usedBy(id) {
    const c = cfg();
    return c.rules.filter(r => r.interface === id || [r.source, r.destination].some(e => (e.type === 'iface_net' || e.type === 'iface_addr') && e.value === id)).length;
  }

  // The Incus network behind a Firewall interface (a managed bridge the
  // Firewall also manages): shown on its card, not as a second card.
  const incusOf = i => incusNets.find(n => n.name === l3(i) || n.name === i.device);
  const incusRuns = n => [n.dhcp && 'DHCP', n.dns && 'DNS', n.nat && 'NAT'].filter(Boolean);
  function incusBadge(n, i) {
    const runs = incusRuns(n);
    if (i && i.kind === 'incus' && !i.incus_keep) // migrated in the draft: the Firewall takes it over on Apply
      return `<span class="fw-badge none" style="color:#ff9f0a" title="The Firewall takes over ${E(n.name)} when you apply. Discard the change to keep it in Incus.">Incus → SDN on apply</span>`;
    const tip = `Also an Incus network: Incus ${runs.length ? 'runs its ' + runs.join(', ') : 'holds its address only (no DHCP, DNS or NAT)'}.`;
    return isAdmin()
      ? `<span class="fw-dd" style="display:inline-flex"><button type="button" class="fw-badge none fw-incus-link" data-incus-net="${E(n.name)}" data-incus-if="${E(i ? i.id : '')}" title="${E(tip)} Click for options.">Incus ▾</button></span>`
      : `<span class="fw-badge none" title="${E(tip)} It is changed under Infrastructure, Networking.">Incus</span>`;
  }

  // The Incus tag menu: edit the network in Incus, or hand it to the Firewall.
  function openIncusMenu(btn) {
    const old = document.querySelector('.fw-menu.fw-incus-menu');
    if (old) { const same = old.dataset.net === btn.dataset.incusNet; old.remove(); if (same) return; }
    const net = btn.dataset.incusNet;
    const it = cfg().interfaces.find(x => x.id === btn.dataset.incusIf);
    const canEdit = typeof window.openBridgeEditorFromFirewall === 'function';
    const canMigrate = it && it.kind === 'incus' && it.incus_keep;
    const m = document.createElement('div');
    m.className = 'fw-menu fw-incus-menu';
    m.dataset.net = net;
    const r = btn.getBoundingClientRect();
    Object.assign(m.style, { position: 'fixed', top: (r.bottom + 6) + 'px', left: Math.max(8, Math.min(r.left, window.innerWidth - 300)) + 'px', right: 'auto', minWidth: '280px', whiteSpace: 'nowrap' });
    m.innerHTML = `<div class="fw-menu-item${canEdit ? '' : ' fw-off'}" data-m="edit">${icon('pencil')}Edit from Incus</div>
      ${canMigrate ? `<div class="fw-menu-item" data-m="migrate" title="The Firewall takes over the address, DHCP and DNS of ${E(net)}, like a network it created">${icon('shield-check')}Migrate to SDN Networking…</div>` : ''}`;
    document.body.appendChild(m);
    m.onclick = ev => ev.stopPropagation();
    const close = () => { m.remove(); document.removeEventListener('click', close); window.removeEventListener('scroll', close, true); };
    m.querySelectorAll('[data-m]').forEach(el => el.onclick = () => {
      if (el.classList.contains('fw-off')) return;
      close();
      if (el.dataset.m === 'edit') window.openBridgeEditorFromFirewall(net);
      else migrateIncus(it, net);
    });
    setTimeout(() => { document.addEventListener('click', close); window.addEventListener('scroll', close, true); }, 0);
  }

  function migrateIncus(it, net) {
    const n = incusNets.find(x => x.name === net) || {};
    const blocking = [n.dhcp && 'DHCP', n.nat && 'NAT'].filter(Boolean);
    const canEdit = typeof window.openBridgeEditorFromFirewall === 'function';
    if (blocking.length) {
      modal({ title: `Turn off Incus ${blocking.join(' and ')} first`,
        body: `<p>Incus still runs <b>${E(blocking.join(' and '))}</b> on ${E(net)}. Migrating now would cut that service off for its instances without warning.</p>
          <p>Edit ${E(net)} with the Incus editor and turn off ${blocking.length > 1 ? 'both' : 'it'} (IPv4 DHCP${n.nat ? ', IPv4 NAT' : ''}). Then migrate again: the Firewall can then serve DHCP and NAT there itself.</p>`,
        buttons: [{ label: 'Close' }].concat(canEdit ? [{ label: 'Edit from Incus', cls: 'btn-primary', onClick: close => { close(); window.openBridgeEditorFromFirewall(net); } }] : []) });
      return;
    }
    modal({ title: `Migrate ${net} to SDN Networking?`,
      body: `<p>The Firewall takes over <b>${E(net)}</b>, like the networks it created. Its address stays <span class="fw-mono">${E(it.ipv4 || n.address || '')}</span> and its instances stay connected.</p>
        <ul style="margin:6px 0 0 18px;padding:0;line-height:1.6">
          <li>Its address is then changed here, on the Interfaces page.</li>
          <li>Incus' own DNS${n.dns ? ' (on now)' : ''}, IPv6 and firewall rules are turned off there. DHCP and DNS can be set up on the DHCP &amp; DNS page.</li>
          <li>If the Firewall is turned off later, ${E(net)} goes back to Incus without an address.</li>
        </ul>
        <p style="margin-top:10px">This is a draft change: nothing happens until you apply.</p>`,
      buttons: [{ label: 'Cancel' }, { label: 'Migrate', cls: 'btn-primary', onClick: async close => {
        const ok = await saveDraft(c => {
          const x = c.interfaces.find(y => y.id === it.id);
          if (!x) return false;
          x.incus_keep = false; x.incus_dhcp = false; x.incus_dns = false;
          x.ipv4_mode = 'static'; x.ipv4 = x.ipv4 || n.address;
        });
        if (ok === false) return;
        close();
        toast(`${net} moves to SDN Networking when you apply`, 'success');
        renderPage();
      } }] });
  }

  function interfacesHTML() {
    const c = cfg();
    const mode = (c.settings && c.settings.mode) || 'monitor';
    const cards = c.interfaces.map(i => {
      const L = liveOf(l3(i)) || {};
      const role = i.role || 'none';
      const mgmt = c.settings && c.settings.mgmt_interface === i.device;
      const vipSet = new Set((i.virtual_ips || []).map(v => v.address)); // listed below, not as the interface's own address
      const own = (L.ipv4 || []).filter(a => !vipSet.has(a.split('/')[0]));
      const ip = own.length ? own.join(', ') : (i.ipv4_mode === 'static' ? i.ipv4 + (i.disabled ? '' : ' (pending)') : ({ dhcp: 'DHCP', pppoe: 'from the provider (not connected)' }[i.ipv4_mode] || '—'));
      const kind = { physical: 'Network port', vlan: `VLAN ${i.vlan_tag} on ${i.parent}`, bridge: 'Bridge', incus: 'VM network (Incus)', pppoe: `PPPoE on ${i.parent}`, wireguard: `WireGuard tunnel · UDP ${i.wg_listen_port}` }[i.kind] || i.kind;
      const n = usedBy(i.id);
      const inc = incusOf(i), incRuns = inc ? incusRuns(inc) : [];
      return `<div class="fw-card${i.disabled ? ' fw-card-off' : ''}" data-id="${E(i.id)}">
        <div class="fw-stripe" style="background:${C(i.color)}"></div>
        <div class="fw-card-h"><span class="fw-state ${L.state === 'up' ? 'up' : 'down'}" title="${E(L.state || 'not created yet')}"></span>
          <span class="fw-name">${E(i.name)}</span>
          ${i.disabled ? '<span class="fw-badge none" title="Its settings are kept, but it is not in use. Edit it to enable it again.">Disabled</span>' : ''}
          ${mgmt ? `<span class="fw-badge lock" title="The anti-lockout rule protects portal and SSH access on this interface">${icon('lock', 11)}Mgmt</span>` : ''}
          ${inc ? incusBadge(inc, i) : ''}
          <span class="fw-badge ${role}">${role === 'none' ? 'unassigned' : role.toUpperCase()}</span></div>
        <div class="fw-kv"><span>Type</span><span>${E(kind)}${i.allow_vms ? ' · VMs allowed' : ''}${inc ? ` · ${i.kind === 'incus' ? '' : 'Incus network, '}${inc.instances} instance${inc.instances === 1 ? '' : 's'}` : ''}</span>
          ${incRuns.length ? `<span>Incus runs</span><span style="color:#ff9f0a" title="Incus serves this network itself, next to the Firewall. Turn it off in the bridge settings (Incus tag) unless you want it.">${E(incRuns.join(', '))}</span>` : ''}
          <span>Device</span><span class="fw-mono">${E(l3(i))}</span>
          <span>IPv4</span><span class="fw-mono">${E(ip)}</span>
          <span>Link</span><span>${L.speed_mbps ? E(L.speed_mbps + ' Mb/s') : (L.state ? E(L.state) : (i.disabled ? 'disabled' : 'not created yet'))}${L.mac ? ` · <span class="fw-mono">${E(L.mac)}</span>` : ''}</span>
          <span>Traffic</span><span>↓ ${fmtBps(L.rx_bps)} · ↑ ${fmtBps(L.tx_bps)}</span></div>
        ${vipListHTML(i)}
        ${isAdmin() && i.kind === 'wireguard' ? `<div class="fw-card-actions"><button class="fw-icon-btn" onclick="showPage('fw-wireguard')">${icon('lock', 12)}Manage on the WireGuard page</button></div>` : ''}
        ${isAdmin() && i.kind !== 'wireguard' ? `<div class="fw-card-actions">
          <button class="fw-icon-btn" data-edit="${E(i.id)}">${icon('pencil', 12)}Edit</button>
          ${vipCapable(i) ? `<button class="fw-icon-btn" data-addvip="${E(i.id)}" title="Add an address in this network that can move to another server">${icon('plus', 12)}Virtual IP</button>` : ''}
          <button class="fw-icon-btn danger" data-del="${E(i.id)}" ${mgmt ? 'disabled' : ''} title="${mgmt ? 'The management interface cannot be removed' : (n ? `Used by ${n} rule${n > 1 ? 's' : ''}: you are shown what goes with it` : 'Remove from the firewall')}">${icon('trash', 12)}Remove</button></div>` : ''}
      </div>`;
    }).join('');
    // Router applied and kept: no Mode card (going back is in the ⋮ menu).
    return `
      ${routerApplied() && mode === 'router' ? '' : `<div class="fw-card" style="flex-direction:row;align-items:center;gap:14px;flex-wrap:wrap">
        <div style="flex:1;min-width:240px"><b>Mode</b><div style="color:var(--text-3);font-size:12.5px;margin-top:3px">${mode === 'router'
          ? 'Router — rules are enforced; anything not allowed is blocked.'
          : (routerApplied()
            ? '<b style="color:#ff9f0a">Monitor only, when you apply</b> — the rules will stop being enforced. To stay in Router mode, use the ⋮ menu or discard the change.'
            : 'Monitor only — nothing is filtered; traffic is only observed. Switch to Router when your rules are ready.')}</div></div>
        ${routerApplied() ? '' : '<div id="fw-mode-seg"></div>'}
      </div>`}
      <div class="fw-cards">${cards}${incusCardsHTML()}${isAdmin() ? `<div class="fw-card fw-add-card" id="fw-add-iface">${icon('plus', 22)}<span>New interface</span><span style="font-size:11.5px">Adopt a network port, create a VLAN or add a virtual IP</span></div>` : ''}</div>`;
  }

  // Incus networks with their own address (host-nat): Incus gives them their
  // address, DHCP, DNS and NAT, so the Firewall leaves them alone and only
  // shows them.
  function incusCardsHTML() {
    const fwDevs = new Set(cfg().interfaces.flatMap(i => [l3(i), i.device]));
    return incusNets.filter(n => !fwDevs.has(n.name)).map(n => { // a Firewall interface: on its own card
      const L = liveOf(n.name) || {};
      const runs = [n.dhcp && 'DHCP', n.dns && 'DNS', n.nat && 'NAT'].filter(Boolean).join(', ');
      const open = isAdmin() && typeof window.openBridgeDetail === 'function';
      return `<div class="fw-card fw-incus-card" data-incus="${E(n.name)}">
        <div class="fw-stripe" style="background:var(--text-3)"></div>
        <div class="fw-card-h"><span class="fw-state ${L.state === 'up' ? 'up' : 'down'}" title="${E(L.state || 'down')}"></span>
          <span class="fw-name">${E(n.name)}</span>
          <span class="fw-badge none" title="Incus gives this network its address${runs ? ' and runs its ' + E(runs) : ''}. Change it under VMs &amp; Containers.">Managed by Incus</span></div>
        <div class="fw-kv"><span>Type</span><span>VM network (Incus) · ${n.instances} instance${n.instances === 1 ? '' : 's'}</span>
          <span>Device</span><span class="fw-mono">${E(n.name)}</span>
          <span>IPv4</span><span class="fw-mono">${E((L.ipv4 || []).join(', ') || n.address)}</span>
          <span>Incus runs</span><span>${E(runs || 'nothing')}</span>
          <span>Traffic</span><span>↓ ${fmtBps(L.rx_bps)} · ↑ ${fmtBps(L.tx_bps)}</span>
          ${routerApplied() ? '<span>Firewall</span><span>Traffic from its instances is not filtered by your rules</span>' : ''}</div>
        ${open ? `<div class="fw-card-actions"><button class="fw-icon-btn" data-incusopen="${E(n.name)}">${icon('external-link', 12)}Open in VMs &amp; Containers</button></div>` : ''}
      </div>`;
    }).join('');
  }

  function wireInterfaces(root) {
    const c = cfg();
    root.querySelectorAll('[data-incus-net]').forEach(b => b.onclick = e => { e.stopPropagation(); openIncusMenu(b); });
    root.querySelectorAll('[data-incusopen]').forEach(b => b.onclick = () => {
      if (typeof window.switchSidebarMode === 'function') window.switchSidebarMode('networking');
      window.openBridgeDetail(b.dataset.incusopen);
    });
    const segEl = root.querySelector('#fw-mode-seg');
    if (segEl) {
      if (isAdmin()) seg(segEl, [['monitor', 'Monitor only'], ['router', 'Router']], (c.settings && c.settings.mode) || 'monitor',
        v => saveDraft(n => { n.settings.mode = v; }));
      else segEl.innerHTML = `<span class="fw-badge none">${E((c.settings && c.settings.mode) || 'monitor')}</span>`;
    }
    root.querySelectorAll('[data-edit]').forEach(b => b.onclick = () => editInterface(c.interfaces.find(i => i.id === b.dataset.edit)));
    root.querySelectorAll('[data-del]').forEach(b => b.onclick = () => {
      const i = c.interfaces.find(x => x.id === b.dataset.del);
      const dep = removalOf(c, i);
      const rows = dep.lines;
      modal({ title: `Remove ${i.name}?`, width: 560, body: `<p>${i.owned ? 'It is deleted from the system when you apply.' : 'The port is left as it is; the firewall simply stops managing it.'}</p>
        ${rows.length ? `<p style="margin:0 0 6px"><b>These depend on it and go with it:</b></p><ul style="margin:0 0 10px 18px;padding:0;line-height:1.6">${rows.map(x => `<li>${E(x)}</li>`).join('')}</ul>` : ''}`,
        buttons: [{ label: 'Cancel' }, { label: rows.length ? 'Remove all of it' : 'Remove', cls: 'btn-danger', onClick: close => { close(); saveDraft(n => { dep.apply(n); }); } }] });
    });
    const add = root.querySelector('#fw-add-iface');
    if (add) add.onclick = () => editInterface(null);
    root.querySelectorAll('[data-addvip]').forEach(b => b.onclick = () => editVIP(b.dataset.addvip, -1));
    root.querySelectorAll('[data-editvip]').forEach(b => b.onclick = () => { const [id, k] = b.dataset.editvip.split('|'); editVIP(id, Number(k)); });
    root.querySelectorAll('[data-delvip]').forEach(b => b.onclick = () => {
      const [id, k] = b.dataset.delvip.split('|'), i = c.interfaces.find(x => x.id === id), v = i && (i.virtual_ips || [])[Number(k)];
      if (!v) return;
      modal({ title: `Release ${v.address}?`, body: `<p>When you apply, <span class="fw-mono">${E(v.address)}</span> leaves this server. Another server can then take it: add it there as a virtual IP of the same network.</p>${v.for_clients ? '<p>DHCP clients of this network get this server\'s own address as their gateway again (at their next renewal).</p>' : ''}`,
        buttons: [{ label: 'Cancel' }, { label: 'Release', cls: 'btn-danger', onClick: close => { close(); saveDraft(n => {
          const t = n.interfaces.find(x => x.id === id);
          t.virtual_ips = (t.virtual_ips || []).filter((_, j) => j !== Number(k));
        }); } }] });
    });
  }

  // ── Virtual IPs ────────────────────────────────────────────────────────
  // An extra address in an interface's network, kept on the device by the
  // portal (after a check that nobody else answers for it). Typical use: the
  // network's gateway address, which can later move to another ZNAS server
  // without changing either server's own address.
  const vipCapable = i => i.ipv4_mode === 'static' && i.kind !== 'pppoe' && i.kind !== 'wireguard' && !!i.ipv4;
  function vipListHTML(i) {
    const vips = i.virtual_ips || [];
    if (!vips.length) return '';
    const sts = (status && status.virtual_ips) || {};
    const bits = (i.ipv4 || '').split('/')[1] || '';
    return `<div class="fw-vips"><div class="fw-vips-h">Virtual IPs</div>${vips.map((v, k) => {
      const st = sts[v.address];
      const badge = !st ? '<span class="fw-badge none" title="Added when you apply">pending</span>'
        : st.state === 'active' ? '<span class="fw-vip-st up">active</span>'
        : st.state === 'conflict' ? `<span class="fw-vip-st bad" title="Another device answers for this address (${E(st.mac || '')}). ZNAS takes it as soon as it is free — release it on the other server.">in use elsewhere</span>`
        : `<span class="fw-vip-st bad" title="${E(st.error || '')}">error</span>`;
      return `<div class="fw-vip"><span class="fw-mono">${E(v.address)}${bits ? '/' + E(bits) : ''}</span>${badge}
        ${v.for_clients ? `<span class="fw-badge lan" title="DHCP hands it out as the gateway and DNS server of this network">${icon('user', 10)}clients' gateway</span>` : ''}
        <span class="fw-vip-d">${E(v.description || '')}</span>
        ${isAdmin() ? `<span class="fw-vip-a"><button class="fw-rbtn" data-editvip="${E(i.id)}|${k}" title="Edit">${icon('pencil', 12)}</button><button class="fw-rbtn" data-delvip="${E(i.id)}|${k}" title="Release">${icon('x', 12)}</button></span>` : ''}</div>`;
    }).join('')}</div>`;
  }
  function editVIP(ifaceId, k) {
    const c = cfg();
    const nets = c.interfaces.filter(vipCapable);
    if (!nets.length) { toast('Give an interface a static address first: a virtual IP lives in an existing network', 'error'); return; }
    let pid = ifaceId || nets[0].id;
    const cur = ifaceId && k >= 0 ? clone((c.interfaces.find(x => x.id === ifaceId).virtual_ips || [])[k]) : { address: '', description: '', for_clients: false };
    const dhcpOn = id => (c.dhcp || []).some(d => d.interface === id && d.enabled);
    const box = document.createElement('div');
    box.innerHTML = `<p style="margin-top:0;color:var(--text-2);font-size:13px">An extra address in one of your networks, separate from this server's own address. Use it as the network's gateway: it can later move to another ZNAS server and the clients keep working, without changing either server's address. Before taking it, ZNAS checks that no other device answers for it.</p>
      <div class="fw-field"><label>Network</label><div id="fwv-net"></div></div>
      <div class="fw-row2"><div class="fw-field"><label>Address</label><input type="text" id="fwv-ip" placeholder="" value="${E(cur.address)}"><div class="fw-err" id="fwv-ip-err"></div></div>
        <div class="fw-field"><label>Description (optional)</label><input type="text" id="fwv-desc" maxlength="80" value="${E(cur.description || '')}" placeholder="e.g. LAN gateway"></div></div>
      <label class="fw-cbx" style="margin-top:4px"><input type="checkbox" id="fwv-cl" ${cur.for_clients ? 'checked' : ''}><span><b style="color:var(--text)">Clients use it as their gateway and DNS server</b><br><small id="fwv-cl-h" style="color:var(--text-3)"></small></span></label>
      <div class="fw-err" id="fwv-err"></div>`;
    const hint = () => {
      const i = c.interfaces.find(x => x.id === pid);
      box.querySelector('#fwv-ip').placeholder = i ? 'in ' + i.ipv4.replace(/\.\d+\//, '.x/') : '';
      box.querySelector('#fwv-cl-h').textContent = dhcpOn(pid)
        ? 'DHCP on this network hands it out instead of this server\'s own address (at the clients\' next renewal).'
        : 'DHCP is off on this network: set the gateway on your clients by hand.';
    };
    picker(box.querySelector('#fwv-net'), nets.map(i => ({ value: i.id, label: i.name, hint: i.ipv4, color: i.color })), pid, v => { pid = v; hint(); }, { placeholder: 'Choose the network…' });
    if (ifaceId && k >= 0) box.querySelectorAll('#fwv-net button').forEach(b => b.disabled = true);
    hint();
    modal({ title: k >= 0 ? `Edit virtual IP ${cur.address}` : 'New virtual IP', body: box, width: 560, buttons: [
      { label: 'Cancel' },
      { label: k >= 0 ? 'Save' : 'Add', cls: 'btn-primary', onClick: async close => {
        const v = { address: box.querySelector('#fwv-ip').value.trim(), description: box.querySelector('#fwv-desc').value.trim(), for_clients: box.querySelector('#fwv-cl').checked };
        const next = clone(cfg());
        const idx = next.interfaces.findIndex(x => x.id === pid);
        const t = next.interfaces[idx];
        t.virtual_ips = t.virtual_ips || [];
        if (k >= 0) t.virtual_ips[k] = v; else t.virtual_ips.push(v);
        const at = k >= 0 ? k : t.virtual_ips.length - 1;
        box.querySelectorAll('.fw-err').forEach(e => e.textContent = '');
        const errs = (await validate(next)).filter(e => e.path.startsWith(`interfaces[${idx}].virtual_ips`));
        if (errs.length) {
          const mine = errs.find(e => e.path.startsWith(`interfaces[${idx}].virtual_ips[${at}]`)) || errs[0];
          box.querySelector(mine.path.endsWith('.address') ? '#fwv-ip-err' : '#fwv-err').textContent = mine.message;
          return;
        }
        close();
        saveDraft(n => { n.interfaces = next.interfaces; });
      } },
    ] });
  }

  // Everything that refers to an interface, for removing it: what to tell the
  // admin, and the edit that removes them from a draft.
  function removalOf(c, i) {
    const refs = e => e && (e.type === 'iface_net' || e.type === 'iface_addr') && e.value === i.id;
    const gws = (c.gateways || []).filter(g => g.interface === i.id), gwIds = new Set(gws.map(g => g.id));
    const ruleGone = r => r.interface === i.id || refs(r.source) || refs(r.destination);
    const snatGone = r => gwIds.has(r.gateway) || refs(r.source) || refs(r.destination);
    const label = (r, what) => `${what}: ${r.description || r.id}`;
    const lines = [
      ...(c.rules || []).filter(ruleGone).map(r => label(r, 'Firewall rule')),
      ...gws.map(g => `Gateway: ${g.name}`),
      ...(c.routes || []).filter(r => r.interface === i.id).map(r => `Local route to ${r.destination}`),
      ...(c.snat_rules || []).filter(snatGone).map(r => label(r, 'Outbound NAT rule')),
      ...(c.ddns || []).filter(e => gwIds.has(e.gateway)).map(e => `Dynamic DNS: ${(e.hostnames || []).join(', ')}`),
      ...(c.dhcp || []).filter(d => d.interface === i.id).map(() => 'Its DHCP server'),
      ...((c.dns && c.dns.interfaces) || []).filter(x => x === i.id).map(() => 'DNS on this network'),
    ];
    (c.rules || []).filter(r => !ruleGone(r) && gwIds.has(r.gateway)).forEach(r => lines.push(`${label(r, 'Firewall rule')} (kept, back on normal routing)`));
    (c.port_forwards || []).filter(f => (f.interfaces || []).includes(i.id)).forEach(f => lines.push(`Port forward ${f.description || f.pub_ports} (kept, no longer on this interface)`));
    return { lines, apply: n => {
      n.interfaces = n.interfaces.filter(x => x.id !== i.id);
      n.rules = (n.rules || []).filter(r => !ruleGone(r));
      n.rules.forEach(r => { if (gwIds.has(r.gateway)) r.gateway = ''; });
      n.gateways = (n.gateways || []).filter(g => !gwIds.has(g.id));
      n.routes = (n.routes || []).filter(r => r.interface !== i.id);
      n.snat_rules = (n.snat_rules || []).filter(r => !snatGone(r));
      n.ddns = (n.ddns || []).filter(e => !gwIds.has(e.gateway));
      n.dhcp = (n.dhcp || []).filter(d => d.interface !== i.id);
      if (n.dns) n.dns.interfaces = (n.dns.interfaces || []).filter(x => x !== i.id);
      if (n.ids) n.ids.interfaces = (n.ids.interfaces || []).filter(x => x !== i.id);
      (n.port_forwards || []).forEach(f => { f.interfaces = (f.interfaces || []).filter(x => x !== i.id); });
    } };
  }

  // A gateway takes the priority asked for; those in its way move down one.
  function setGwPriority(gateways, g, p) {
    g.priority = p;
    let want = p;
    gateways.filter(o => o.id !== g.id).sort((a, b) => a.priority - b.priority).forEach(o => {
      if (o.priority === want) { o.priority++; want++; }
    });
  }
  const nextGwPriority = c => (c.gateways || []).reduce((m, g) => Math.max(m, g.priority), 0) + 1;

  // What disabling an interface breaks: what validation refused, and the
  // gateway it leaves the router without.
  function disableWarnings(c, it, blocks) {
    if (!it.disabled) return [];
    const off = id => { const x = c.interfaces.find(i => i.id === id); return !x || x.disabled; };
    const gws = c.gateways || [];
    const warn = blocks.map(b => b.message);
    if (gws.some(g => g.interface === it.id) && gws.every(g => off(g.interface))) warn.push('It carries the last gateway: this router will have no Internet access.');
    return warn;
  }

  async function editInterface(existing, preset) {
    if (!live.length) { const r = await api('GET', '/api/sdn/interfaces/live'); if (r.ok) live = r.data || []; }
    const c = cfg();
    const used = new Set(c.interfaces.map(i => i.kind === 'vlan' ? null : i.device).filter(Boolean));
    const it = existing ? clone(existing) : { id: newId(), name: '', color: PALETTE[c.interfaces.length % PALETTE.length], kind: 'physical',
      device: '', role: 'lan', ipv4_mode: 'none', ipv4: '', gateway: '', mtu: 0, allow_vms: false, owned: false };
    let how = existing ? ({ vlan: 'vlan', pppoe: 'pppoe' }[existing.kind] || 'adopt') : (preset || 'adopt');
    if (how === 'pppoe') it.role = 'wan';
    const pppGw = (c.gateways || []).find(g => g.interface === it.id);
    const box = document.createElement('div');
    box.innerHTML = `
      ${existing ? '' : `<div class="fw-field"><label>What do you want to add?</label><div id="fwi-how"></div></div>`}
      <div class="fw-field" id="fwi-adopt-f"><label>Network port</label><div id="fwi-dev"></div><div class="fw-err" id="fwi-dev-err"></div></div>
      <div id="fwi-vlan-f" class="fw-row2">
        <div class="fw-field"><label>Parent port</label><div id="fwi-parent"></div></div>
        <div class="fw-field"><label>VLAN tag (1–4094)</label><input type="number" min="1" max="4094" id="fwi-tag" value="${E(it.vlan_tag || '')}"><div class="fw-err" id="fwi-tag-err"></div></div>
      </div>
      <div id="fwi-pppoe-f">
        ${status && !status.ppp_installed ? `<div class="fw-safemode" style="margin-bottom:10px">${icon('info', 16)}<div>PPPoE needs the <b>ppp</b> package on this server.</div><span style="flex:1"></span><button class="fw-btn" id="fwi-ppp-install" type="button">Install</button></div>` : ''}
        <div class="fw-field"><label>Runs on (port or VLAN towards the modem / ONT)</label><div id="fwi-pparent"></div><div class="fw-err" id="fwi-pparent-err"></div></div>
        <div class="fw-row2">
          <div class="fw-field"><label>User name</label><input type="text" id="fwi-puser" autocomplete="off" value="${E(it.pppoe_user || '')}" placeholder="b1234567@provider"><div class="fw-err" id="fwi-puser-err"></div></div>
          <div class="fw-field"><label>Password</label><input type="password" id="fwi-ppass" autocomplete="new-password" placeholder="${it.pppoe_password_set ? 'unchanged — type to replace' : ''}"><div class="fw-err" id="fwi-ppass-err"></div></div>
        </div>
        <div class="fw-field">${lab('Gateway priority', 'Gateway priority', '<p>Makes this link a gateway. Traffic to the Internet uses the online gateway with the lowest number; 1 is tried first. A gateway already at this number moves down one.</p><p>Leave it empty to add no gateway. You can change it later on the Routing page.</p>')}<input type="number" min="1" id="fwi-pprio" value="${pppGw ? pppGw.priority : (existing ? '' : nextGwPriority(c))}"><div class="fw-err" id="fwi-pprio-err"></div></div>
        <div style="font-size:12px;color:var(--text-3);margin:-4px 0 10px">The address comes from the provider. Other PPPoE links can run on the same port.</div>
      </div>
      ${existing ? `<div class="fw-field"><div class="fw-lab"><label style="display:flex;gap:8px;align-items:center;text-transform:none;letter-spacing:0;font-size:13px;color:var(--text)"><input type="checkbox" id="fwi-en" ${it.disabled ? '' : 'checked'}>Enable this interface</label>${info('Enable this interface', '<p>On by default. Turn it off to stop using this interface and keep all its settings for later.</p><p>When you apply, its link goes down, or a VLAN or PPPoE link is removed from the system, and its DHCP, DNS, virtual IPs, gateway and dynamic DNS stop. Its rules and port forwards stay saved. Turn it back on and apply to restore everything.</p><p>If it is the management interface, a port an enabled VLAN or PPPoE link runs on, or the last gateway, you are told what that breaks and can disable it anyway.</p>')}</div><div class="fw-err" id="fwi-en-err"></div></div>` : ''}
      <div class="fw-field"><label>Name</label><input type="text" id="fwi-name" value="${E(it.name)}" placeholder="e.g. VLAN800 — Servers"></div>
      <div class="fw-field"><label>Colour</label><div class="fw-chips" id="fwi-colors">${PALETTE.map(p => `<span data-c="${p}" style="width:22px;height:22px;border-radius:50%;cursor:pointer;background:${p};outline:${p === it.color ? '2px solid var(--text)' : 'none'};outline-offset:2px"></span>`).join('')}</div></div>
      <div class="fw-field"><label>Role</label><div id="fwi-role"></div></div>
      <div class="fw-field"><label>IPv4 address</label><div id="fwi-mode"></div>
        <div class="fw-row2" id="fwi-static" style="margin-top:8px">
          <input type="text" id="fwi-ip" placeholder="10.128.8.1/24" value="${E(it.ipv4 || '')}">
          <input type="text" id="fwi-gw" placeholder="Gateway (optional)" value="${E(it.gateway || '')}"></div>
        <div class="fw-err" id="fwi-ip-err"></div>
        <div id="fwi-keep" class="fw-safemode" style="margin-top:8px;display:none">${icon('info', 16)}<div></div></div></div>
      <div class="fw-row2"><div class="fw-field"><label>MTU (optional)</label><input type="number" id="fwi-mtu" value="${E(it.mtu || '')}" placeholder="1500"></div>
        <div class="fw-field" id="fwi-vms-f"><label>Virtual machines</label><label style="display:flex;gap:8px;align-items:center;text-transform:none;letter-spacing:0;font-size:13px;color:var(--text)"><input type="checkbox" id="fwi-vms" ${it.allow_vms ? 'checked' : ''}>Allow VMs/containers on this network</label></div></div>`;
    const sync = () => {
      box.querySelector('#fwi-adopt-f').style.display = how === 'adopt' ? '' : 'none';
      box.querySelector('#fwi-vlan-f').style.display = how === 'vlan' ? '' : 'none';
      box.querySelector('#fwi-vms-f').style.display = how === 'vlan' ? '' : 'none';
      box.querySelector('#fwi-static').style.display = it.ipv4_mode === 'static' && how !== 'pppoe' ? '' : 'none';
      box.querySelector('#fwi-pppoe-f').style.display = how === 'pppoe' ? '' : 'none';
      box.querySelector('#fwi-mode').parentElement.style.display = how === 'pppoe' ? 'none' : '';
      box.querySelector('#fwi-adopt-f').querySelectorAll('button').forEach(b => b.disabled = !!existing);
      // Incus keeps this network's address and DHCP: the Firewall only filters and translates.
      const keep = how === 'adopt' && it.incus_keep, L = liveOf(it.device) || {};
      box.querySelector('#fwi-mode').style.display = keep ? 'none' : '';
      box.querySelector('#fwi-gw').style.display = keep ? 'none' : '';
      box.querySelector('#fwi-ip').readOnly = !!keep;
      const note = box.querySelector('#fwi-keep');
      note.style.display = keep ? '' : 'none';
      note.lastElementChild.textContent = !keep ? '' : 'Incus keeps this address and its DHCP: change them in VMs & Containers. '
        + (cfg().settings.mode === 'router' ? 'In router mode, its VMs lose access to other networks and the Internet until you add allow rules. ' : '')
        + (L.incus_nat ? 'Incus also translates this network\'s outgoing traffic itself: turn that off there if you want Firewall outbound NAT rules to apply.' : '');
    };
    let dlg = null;
    if (!existing) seg(box.querySelector('#fwi-how'), [['adopt', 'Adopt a network port'], ['vlan', 'Create a VLAN'], ['pppoe', 'PPPoE Internet link'], ['vip', 'Virtual IP']], how, v => {
      if (v === 'vip') { if (dlg) dlg.close(); editVIP(null, -1); return; }
      how = v;
      if (v === 'pppoe') { it.role = 'wan'; seg(box.querySelector('#fwi-role'), roleItems, 'wan', x => { it.role = x; }); }
      sync();
    });
    const portName = d => { const x = c.interfaces.find(i => i.device === d); return x ? x.name : d; };
    const pppParents = [...live.filter(l => (l.kind === 'physical' || l.kind === 'bridge') && !l.master && l.reason !== 'managed by Incus').map(l => ({ value: l.device, label: portName(l.device), hint: l.device })),
      ...c.interfaces.filter(x => x.kind === 'vlan').map(x => ({ value: x.device, label: x.name, hint: x.device, color: x.color }))];
    picker(box.querySelector('#fwi-pparent'), pppParents, it.kind === 'pppoe' ? it.parent : '', v => { it.parent = v; }, { placeholder: 'Choose the port…' });
    const inst = box.querySelector('#fwi-ppp-install');
    if (inst) inst.onclick = async () => {
      inst.disabled = true; inst.textContent = 'Installing…';
      const r = await api('POST', '/api/prereqs/install', { package: 'ppp' });
      if (r.ok) { await loadStatus(); inst.closest('.fw-safemode').remove(); toast('ppp installed', 'success'); }
      else { inst.disabled = false; inst.textContent = 'Install'; toast((r.data && r.data.error) || 'Install failed', 'error'); }
    };
    const devOpts = live.filter(isPort).map(l => ({ value: l.device, label: l.device + (l.ipv4 && l.ipv4.length ? '  ' + l.ipv4[0] : ''),
      hint: !l.adoptable ? l.reason : (used.has(l.device) && l.device !== (existing && existing.device) ? 'already added' : l.kind),
      disabled: !l.adoptable || (used.has(l.device) && l.device !== (existing && existing.device)) }));
    picker(box.querySelector('#fwi-dev'), devOpts, it.kind !== 'vlan' ? it.device : '', v => {
      it.device = v;
      const L = liveOf(v) || {};
      it.kind = L.incus ? 'incus' : (L.kind === 'bridge' ? 'bridge' : 'physical');
      if (!it.name) box.querySelector('#fwi-name').value = v;
      it.incus_keep = !!L.incus_keep;
      if (L.incus_keep) { it.ipv4_mode = 'static'; box.querySelector('#fwi-ip').value = L.cfg_address || ''; modeSeg(); sync(); }
      else if (L.incus) { it.ipv4_mode = 'none'; modeSeg(); sync(); }
      else if (L.cfg_mode) {
        it.ipv4_mode = L.cfg_mode === 'manual' ? 'none' : L.cfg_mode;
        if (L.cfg_address) box.querySelector('#fwi-ip').value = L.cfg_address;
        if (L.cfg_gateway) box.querySelector('#fwi-gw').value = L.cfg_gateway;
        modeSeg();
      }
    }, { placeholder: 'Choose a port…' });
    // A VLAN goes on the device that carries the tagged frames to the
    // switch: a network port (even one that is also in a bridge such as
    // vmbr0, so the VLAN stays independent of that bridge) or a bond. Never
    // a bond's member port, and never a bridge: our bridges aren't
    // VLAN-aware, so a VLAN on one leaks its tagged traffic to every VM on
    // that bridge. An existing VLAN keeps its current parent in the list.
    const liveKind = d => (live.find(x => x.device === d) || {}).kind;
    const parentOk = l => (l.kind === 'physical' || l.kind === 'bond') && (!l.master || liveKind(l.master) === 'bridge');
    const parents = live.filter(parentOk).map(l => ({ value: l.device, label: l.device,
      hint: (l.kind === 'bond' ? 'bond' : 'network port') + (l.master ? ' · also in ' + l.master : '') }));
    if (it.parent && !parents.some(p => p.value === it.parent)) parents.push({ value: it.parent, label: it.parent, hint: 'current parent' });
    picker(box.querySelector('#fwi-parent'), parents, it.parent || '', v => { it.parent = v; }, { placeholder: 'Choose the trunk port…' });
    box.querySelectorAll('#fwi-colors span').forEach(s => s.onclick = () => {
      it.color = s.dataset.c;
      box.querySelectorAll('#fwi-colors span').forEach(x => x.style.outline = x === s ? '2px solid var(--text)' : 'none');
    });
    const roleItems = [['wan', 'WAN (Internet)'], ['lan', 'LAN'], ['', 'Unassigned']];
    seg(box.querySelector('#fwi-role'), roleItems, it.role || '', v => { it.role = v; });
    // Incus networks take their address through Incus: static or none.
    const modeSeg = () => seg(box.querySelector('#fwi-mode'), it.kind === 'incus'
      ? [['static', 'Static (gateway for its VMs)'], ['none', 'None']]
      : [['static', 'Static'], ['dhcp', 'DHCP client'], ['none', 'None']], it.ipv4_mode || 'none', v => { it.ipv4_mode = v; sync(); });
    modeSeg();
    sync();
    dlg = modal({ title: existing ? `Edit ${existing.name}` : 'New interface', body: box, width: 600, buttons: [
      { label: 'Cancel' },
      { label: existing ? 'Save' : 'Add', cls: 'btn-primary', onClick: async close => {
        let pppPrio = '';
        it.name = box.querySelector('#fwi-name').value.trim();
        const en = box.querySelector('#fwi-en');
        if (en && en.checked) { delete it.disabled; delete it.disable_forced; } else if (en) it.disabled = true;
        it.ipv4 = it.ipv4_mode === 'static' ? box.querySelector('#fwi-ip').value.trim() : '';
        it.gateway = it.ipv4_mode === 'static' ? box.querySelector('#fwi-gw').value.trim() : '';
        it.mtu = Number(box.querySelector('#fwi-mtu').value) || 0;
        if (how === 'pppoe') {
          it.kind = 'pppoe'; it.owned = true; it.ipv4_mode = 'pppoe'; it.allow_vms = false; it.ipv4 = ''; it.gateway = '';
          it.pppoe_user = box.querySelector('#fwi-puser').value.trim();
          const pw = box.querySelector('#fwi-ppass').value;
          it.pppoe_password = pw; // empty = keep the stored one (server side)
          if (!it.parent) { box.querySelector('#fwi-pparent-err').textContent = 'Choose the port the session runs on'; return; }
          if (!existing && !pw) { box.querySelector('#fwi-ppass-err').textContent = 'The password is required'; return; }
          if (!it.name) it.name = 'Internet (PPPoE)';
          pppPrio = box.querySelector('#fwi-pprio').value.trim();
          if (pppPrio && !(Number(pppPrio) >= 1)) { box.querySelector('#fwi-pprio-err').textContent = 'The priority is a number from 1'; return; }
        } else if (how === 'vlan') {
          it.kind = 'vlan'; it.owned = true;
          it.vlan_tag = Number(box.querySelector('#fwi-tag').value) || 0;
          it.allow_vms = box.querySelector('#fwi-vms').checked;
          if (!it.name) it.name = 'VLAN' + it.vlan_tag;
        } else {
          it.owned = false; it.allow_vms = false;
          if (!it.device) { box.querySelector('#fwi-dev-err').textContent = 'Choose a network port'; return; }
          if (!it.name) it.name = it.device;
        }
        const next = clone(cfg());
        const idx = next.interfaces.findIndex(x => x.id === it.id);
        if (idx >= 0) next.interfaces[idx] = it; else next.interfaces.push(it);
        if (pppPrio) {
          next.gateways = next.gateways || [];
          let g = next.gateways.find(x => x.interface === it.id);
          if (!g) { g = { id: newId(), name: it.name, interface: it.id, address: '', priority: 0, monitor: false }; next.gateways.push(g); }
          setGwPriority(next.gateways, g, Number(pppPrio));
        }
        const at = idx >= 0 ? idx : next.interfaces.length - 1;
        const errs = (await validate(next)).filter(e => e.path.startsWith(`interfaces[${at}]`));
        box.querySelectorAll('.fw-err').forEach(e => e.textContent = '');
        // Disabling what something depends on: say so, and let the admin go on.
        const blocks = it.disabled && !it.disable_forced && it.kind !== 'wireguard' ? errs.filter(e => e.path === `interfaces[${at}].disabled`) : [];
        const warn = disableWarnings(next, it, blocks);
        const others = errs.filter(e => !blocks.includes(e));
        if (!others.length && warn.length && !(existing && existing.disabled && !blocks.length)) {
          const mgmt = next.settings && next.settings.mgmt_interface === it.device;
          modal({ title: `Disable ${it.name}?`, width: 540, body: `<ul style="margin:0 0 10px 18px;padding:0;line-height:1.6">${warn.map(w => `<li>${E(w)}</li>`).join('')}</ul>
            <p style="margin:0;color:var(--text-2)">Nothing changes until you apply.${mgmt ? ' The apply dialog will have auto-revert ticked: keep it, so the router goes back by itself if you lose access.' : ''}</p>`,
            buttons: [{ label: 'Cancel' }, { label: 'Disable anyway', cls: 'btn-danger', onClick: async c2 => {
              c2();
              if (blocks.length) { it.disable_forced = true; next.interfaces[at] = it; }
              if (mgmt) arSave(true);
              close();
              saveDraft(n => { n.interfaces = next.interfaces; n.gateways = next.gateways; });
            } }] });
          return;
        }
        if (others.length) {
          errs.splice(0, errs.length, ...others);
          const f = errs[0].path.split('.').pop();
          const target = { disabled: '#fwi-en-err', vlan_tag: '#fwi-tag-err', ipv4: '#fwi-ip-err', gateway: '#fwi-ip-err', device: '#fwi-dev-err',
            parent: how === 'pppoe' ? '#fwi-pparent-err' : '#fwi-tag-err', pppoe_user: '#fwi-puser-err', pppoe_password: '#fwi-ppass-err' }[f] || (how === 'pppoe' ? '#fwi-puser-err' : '#fwi-ip-err');
          box.querySelector(target).textContent = errs[0].message;
          return;
        }
        close();
        saveDraft(n => { n.interfaces = next.interfaces; n.gateways = next.gateways; });
      } },
    ] });
  }

  // ── Groups ─────────────────────────────────────────────────────────────
  function groupUse(id) {
    return cfg().rules.filter(r => [r.source, r.destination].some(e => e.type === 'group' && e.value === id) || r.dst_ports === 'group:' + id).length;
  }
  let countryList = null;
  async function loadCountries() {
    if (countryList) return countryList;
    const r = await api('GET', '/api/sdn/countries');
    countryList = (r.ok && r.data) || [];
    return countryList;
  }
  const flagOf = cc => (cc && /^[A-Z]{2}$/.test(cc)) ? String.fromCodePoint(...[...cc].map(ch => 127397 + ch.charCodeAt(0))) : '';
  const ccName = cc => { const f = (countryList || []).find(x => x[0] === cc); return f ? f[1] : cc; };
  function countryOptions() { return (countryList || []).map(([code, name]) => ({ value: code, label: flagOf(code) + ' ' + name + ' (' + code + ')' })); }

  function groupsHTML() {
    const c = cfg();
    if (!countryList) loadCountries().then(() => { if (page === 'fw-groups') renderPage(); });
    const sec = (kind, title, hint) => {
      const gs = c.groups.filter(g => g.kind === kind);
      return `<div><h3 style="margin:4px 0 4px;font-size:15px">${E(title)}</h3><div style="color:var(--text-3);font-size:12.5px;margin-bottom:10px">${E(hint)}</div>
        <div class="fw-cards">${gs.map(g => {
          const n = groupUse(g.id);
          return `<div class="fw-card" data-gid="${E(g.id)}"><div class="fw-card-h">${icon(kind === 'hosts' ? 'network' : (kind === 'countries' ? 'globe' : 'plug'), 15)}<span class="fw-name">${E(g.name)}</span><span class="fw-t" style="color:var(--text-3);font-size:11.5px">${n ? `used by ${n} rule${n > 1 ? 's' : ''}` : 'unused'}</span></div>
            <div class="fw-chips">${g.members.map((m, k) => `<span class="fw-chip">${kind === 'countries' ? flagOf(m) + ' ' + E(ccName(m)) : E(m)}${isAdmin() ? `<button data-rm="${k}" title="Remove">${icon('x', 11)}</button>` : ''}</span>`).join('')}
              ${isAdmin() ? (kind === 'countries' ? `<span data-addcc style="min-width:220px;display:inline-block"></span>` : `<input class="fw-chip-input" placeholder="${kind === 'hosts' ? '+ IP, CIDR or range' : '+ port or range'}" data-add>`) : ''}</div>
            <div class="fw-err" style="color:var(--fw-blk);font-size:12px" data-err></div>
            ${isAdmin() ? `<div class="fw-card-actions"><button class="fw-icon-btn danger" data-gdel ${n ? 'disabled title="Remove it from the rules first"' : ''}>${icon('trash', 12)}Delete</button></div>` : ''}</div>`;
        }).join('')}${isAdmin() ? `<div class="fw-card fw-add-card" data-gnew="${kind}" style="min-height:110px">${icon('plus', 20)}<span>New ${kind === 'hosts' ? 'host/network' : (kind === 'countries' ? 'country' : 'port')} group</span></div>` : ''}</div></div>`;
    };
    return sec('hosts', 'Hosts & networks', 'Named lists of addresses to use in rules — e.g. ALXInternalSubnets = 10.0.0.0/8, 192.168.0.0/16.')
      + sec('ports', 'Ports', 'Named lists of ports — e.g. game = 16261-16263.')
      + sec('countries', 'Countries', 'Named lists of countries to allow or block — e.g. OKCOUNTRIES = Canada, United States, Singapore, Sweden. Uses the location database (Traffic page).');
  }

  function wireGroups(root) {
    const c = cfg();
    root.querySelectorAll('[data-gnew]').forEach(b => b.onclick = () => {
      const kind = b.dataset.gnew;
      const box = document.createElement('div');
      box.innerHTML = `<div class="fw-field"><label>Name</label><input type="text" id="fwg-name" placeholder="${kind === 'hosts' ? 'ALXInternalSubnets' : (kind === 'countries' ? 'OKCOUNTRIES' : 'game')}"><div class="fw-err" id="fwg-err"></div></div>`;
      modal({ title: kind === 'hosts' ? 'New host/network group' : (kind === 'countries' ? 'New country group' : 'New port group'), body: box, buttons: [{ label: 'Cancel' }, { label: 'Create', cls: 'btn-primary', onClick: async close => {
        const name = box.querySelector('#fwg-name').value.trim();
        const next = clone(cfg());
        next.groups.push({ id: newId(), name, kind, members: [] });
        const errs = (await validate(next)).filter(e => e.path.startsWith(`groups[${next.groups.length - 1}]`));
        if (errs.length) { box.querySelector('#fwg-err').textContent = errs[0].message; return; }
        close(); saveDraft(n => { n.groups = next.groups; });
      } }] });
    });
    root.querySelectorAll('[data-gid]').forEach(card => {
      const id = card.dataset.gid;
      card.querySelectorAll('[data-rm]').forEach(b => b.onclick = () => saveDraft(n => { n.groups.find(g => g.id === id).members.splice(Number(b.dataset.rm), 1); }));
      const ccSlot = card.querySelector('[data-addcc]');
      if (ccSlot) picker(ccSlot, countryOptions(), '', v => saveDraft(n => { const g = n.groups.find(x => x.id === id); if (!g.members.includes(v)) g.members.push(v); }), { placeholder: '+ Add a country…', search: true });
      const inp = card.querySelector('[data-add]');
      if (inp) inp.onkeydown = async e => {
        if (e.key !== 'Enter' && e.key !== ',') return;
        e.preventDefault();
        const vals = inp.value.split(/[\s,]+/).filter(Boolean);
        if (!vals.length) return;
        const next = clone(cfg());
        const gi = next.groups.findIndex(g => g.id === id);
        next.groups[gi].members.push(...vals);
        const errs = (await validate(next)).filter(x => x.path.startsWith(`groups[${gi}]`));
        if (errs.length) { card.querySelector('[data-err]').textContent = errs[0].message; return; }
        saveDraft(n => { n.groups = next.groups; });
      };
      const del = card.querySelector('[data-gdel]');
      if (del) del.onclick = () => saveDraft(n => { n.groups = n.groups.filter(g => g.id !== id); });
    });
  }

  // ── Rules ──────────────────────────────────────────────────────────────
  const PROTO = { any: 'Any', tcp: 'TCP', udp: 'UDP', tcpudp: 'TCP+UDP', icmp: 'ICMP' };
  function ifaceById(id) { return cfg().interfaces.find(i => i.id === id); }
  function epLabel(ep) {
    if (!ep) return 'Any';
    const not = ep.not ? 'not ' : '';
    switch (ep.type) {
      case 'any': return 'Any';
      case 'cidr': return not + ep.value;
      case 'group': { const g = cfg().groups.find(x => x.id === ep.value); return not + (g ? g.name : '(deleted group)'); }
      case 'countries': return not + (ep.value || '').split(',').filter(Boolean).map(cc => flagOf(cc) + ' ' + ccName(cc)).join(', ');
      case 'iface_net': { const i = ifaceById(ep.value); return not + (i ? i.name + ' net' : '(deleted interface)'); }
      case 'iface_addr': { const i = ifaceById(ep.value); return not + (i ? i.name + ' address' : '(deleted interface)'); }
      case 'this_znas': return not + 'This ZNAS';
      case 'internal': return not + 'Internal networks';
    }
    return '?';
  }
  function epColor(ep) {
    if (ep && (ep.type === 'iface_net' || ep.type === 'iface_addr')) { const i = ifaceById(ep.value); return i && i.color; }
    return null;
  }
  function portsLabel(p) {
    if (!p) return '';
    if (p.startsWith('group:')) { const g = cfg().groups.find(x => x.id === p.slice(6)); return g ? g.name : '(deleted group)'; }
    return p.replace(/,/g, ', ');
  }
  // The rule written as a sentence (drawer header and tooltips).
  function sentence(r) {
    const act = { allow: 'Allow', block: 'Block', reject: 'Reject' }[r.action] || r.action;
    const proto = { any: 'all traffic', tcp: 'TCP', udp: 'UDP', tcpudp: 'TCP+UDP', icmp: 'ICMP (ping)' }[r.protocol] || r.protocol;
    const i = r.interface ? ifaceById(r.interface) : null;
    const on = r.interface ? (i ? i.name : '(deleted interface)') : 'any interface';
    let port = '';
    if (r.dst_ports) {
      port = r.dst_ports.startsWith('group:') ? ` ports in <b>${E(portsLabel(r.dst_ports))}</b>`
        : (r.dst_ports.includes(',') || r.dst_ports.includes('-') ? ` ports <b>${E(portsLabel(r.dst_ports))}</b>` : ` port <b>${E(r.dst_ports)}</b>`);
    }
    const g = r.gateway ? cfg().gateways.find(x => x.id === r.gateway) : null;
    const via = r.gateway ? ` Leaves through <b>${E(g ? g.name : '(deleted gateway)')}</b>${r.only_gateway ? ' only' : ''}.` : '';
    return `${E(act)} <b>${E(proto)}</b> from <b>${E(epLabel(r.source))}</b> arriving on <b>${E(on)}</b> to <b>${E(epLabel(r.destination))}</b>${port}.${via}${r.log ? ' Matches are logged.' : ''}`;
  }

  function rulesHTML() {
    const c = cfg();
    if (!countryList) loadCountries().then(() => { if (page === 'fw-rules') renderPage(); });
    const tabs = [['all', 'All', null], ['', 'Any interface', null], ...c.interfaces.map(i => [i.id, i.name, i.color])];
    const count = id => id === 'all' ? c.rules.length : c.rules.filter(r => r.interface === id).length;
    const rows = c.rules.map((r, idx) => ({ r, idx })).filter(x => rulesTab === 'all' || x.r.interface === rulesTab);
    const mgmt = c.interfaces.find(i => i.device === (c.settings && c.settings.mgmt_interface));
    const showPinned = c.settings && c.settings.anti_lockout && mgmt && (rulesTab === 'all' || rulesTab === mgmt.id);
    const portalPorts = (status && status.portal_ports) || [22, 8443];
    const mode = (c.settings && c.settings.mode) || 'monitor';
    return `
      ${mode !== 'router' ? `<div class="fw-safemode" style="background:rgba(255,214,10,.10);border-color:rgba(255,214,10,.4)">${icon('info', 16)}<div><b style="color:var(--accent-warn)">Monitor only</b> — these rules are not enforced yet. Switch to Router on the Interfaces page when they are ready.</div></div>` : ''}
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <div class="fw-tabs">${tabs.map(t => `<button class="fw-tab${t[0] === rulesTab ? ' on' : ''}" data-tab="${E(t[0])}">${t[2] ? `<span class="fw-cdot" style="background:${C(t[2])}"></span>` : ''}${E(t[1])}<span class="fw-n">${count(t[0])}</span></button>`).join('')}</div>
        <span style="flex:1"></span>
        ${isAdmin() ? `<button class="fw-btn" id="fw-anti" title="Always allow portal and SSH access on the management interface">${icon(c.settings && c.settings.anti_lockout ? 'lock' : 'unlock', 13)}Anti-lockout: ${c.settings && c.settings.anti_lockout ? 'on' : 'OFF'}</button>
        <button class="fw-btn fw-apply" id="fw-new-rule" style="font-weight:600">${icon('plus', 13)}New rule</button>` : ''}
      </div>
      <div class="fw-rules">
        ${showPinned ? `<div class="fw-rule fw-pinned" title="Built-in: keeps the portal and SSH reachable whatever the rules say">
          <span class="fw-drag">${icon('lock', 12)}</span><span></span><span class="fw-act allow">Allow</span><span class="fw-proto">TCP</span>
          <span class="fw-flow"><span class="fw-pillx"><span class="fw-cdot" style="background:${C(mgmt.color)}"></span>${E(mgmt.name)}</span><span class="fw-arrow">→</span><span class="fw-pillx">This ZNAS</span><span class="fw-port">: ${E(portalPorts.join(', '))}</span></span>
          <span class="fw-desc">Anti-lockout (built-in)</span><span></span><span class="fw-hits"></span><span></span></div>` : ''}
        ${rows.length ? rows.map(({ r, idx }) => {
          const cnt = counters[r.id] || {};
          const sc = epColor(r.source), dc = epColor(r.destination);
          return `<div class="fw-rule${r.enabled ? '' : ' fw-off'}" data-idx="${idx}" ${isAdmin() && rulesTab !== 'all' ? 'draggable="true"' : ''} title="${E(sentence(r).replace(/<[^>]+>/g, ''))}">
            <span class="fw-drag">${isAdmin() && rulesTab !== 'all' ? icon('menu', 13) : ''}</span>
            <span class="fw-toggle${r.enabled ? ' on' : ''}" data-toggle="${idx}"></span>
            <span class="fw-act ${E(r.action)}">${E(r.action)}</span>
            <span class="fw-proto">${E(PROTO[r.protocol] || r.protocol)}</span>
            <span class="fw-flow">${rulesTab === 'all' ? (() => { const ri = c.interfaces.find(i => i.id === r.interface);
                return `<span class="fw-onif" title="Rule of ${E(ri ? ri.name : 'Any interface')}"><span class="fw-cdot" style="background:${C(ri && ri.color)}"></span>${E(ri ? ri.name : 'Any')}</span>`; })() : ''}<span class="fw-pillx${r.source.not ? ' not' : ''}">${sc ? `<span class="fw-cdot" style="background:${C(sc)}"></span>` : ''}${E(epLabel(r.source))}</span>
              <span class="fw-arrow">→</span>
              <span class="fw-pillx${r.destination.not ? ' not' : ''}">${dc ? `<span class="fw-cdot" style="background:${C(dc)}"></span>` : ''}${E(epLabel(r.destination))}</span>
              ${r.dst_ports ? `<span class="fw-port">: ${E(portsLabel(r.dst_ports))}</span>` : ''}</span>
            <span class="fw-desc">${E(r.description || (rulesTab === 'all' ? (r.interface ? (ifaceById(r.interface) || {}).name : 'Any interface') : ''))}</span>
            <span class="fw-logi" title="${r.log ? 'Logged' : ''}">${r.log ? icon('file', 13) : ''}</span>
            <span class="fw-hits" title="${cnt.last_hit && !cnt.last_hit.startsWith('0001') ? 'Last hit ' + E(fmtTime(cnt.last_hit)) : 'No hit recorded'}">${spark(cnt.spark, r.action === 'allow' ? 'var(--fw-allow)' : 'var(--fw-block)')}${fmtCount(cnt.packets)}</span>
            ${rowActs('r', idx)}
          </div>`;
        }).join('') : `<div class="fw-empty">No rules here yet.${mode === 'router' && rulesTab !== 'all' ? ' Everything arriving on this interface is blocked.' : ''}</div>`}
      </div>`;
  }

  function wireRules(root) {
    root.querySelectorAll('[data-tab]').forEach(b => b.onclick = () => { rulesTab = b.dataset.tab; renderPage(); });
    const nb = root.querySelector('#fw-new-rule');
    if (nb) nb.onclick = () => editRule(null);
    const anti = root.querySelector('#fw-anti');
    if (anti) anti.onclick = () => {
      const on = cfg().settings.anti_lockout;
      modal({ title: on ? 'Turn anti-lockout off?' : 'Turn anti-lockout on?', body: on
        ? '<p>Portal and SSH access on the management interface will then depend on your own rules only. A wrong rule can lock you out of this server.</p><p>Tick the auto-revert checkbox when you apply.</p>'
        : '<p>Portal and SSH access on the management interface will always be allowed, whatever the rules say.</p>',
        buttons: [{ label: 'Cancel' }, { label: on ? 'Turn off' : 'Turn on', cls: on ? 'btn-danger' : 'btn-primary', onClick: close => { close(); saveDraft(n => { n.settings.anti_lockout = !on; }); } }] });
    };
    root.querySelectorAll('[data-toggle]').forEach(t => t.onclick = e => {
      e.stopPropagation();
      if (!isAdmin()) return;
      const idx = Number(t.dataset.toggle);
      saveDraft(n => { n.rules[idx].enabled = !n.rules[idx].enabled; });
    });
    root.querySelectorAll('[data-redit]').forEach(b => b.onclick = e => { e.stopPropagation(); editRule(Number(b.dataset.redit)); });
    root.querySelectorAll('[data-rclone]').forEach(b => b.onclick = e => { e.stopPropagation(); editRule(null, Number(b.dataset.rclone)); });
    root.querySelectorAll('.fw-rule[data-idx]').forEach(row => {
      row.onclick = () => isAdmin() && editRule(Number(row.dataset.idx));
      row.addEventListener('dragstart', e => { e.dataTransfer.setData('text/plain', row.dataset.idx); });
      row.addEventListener('dragover', e => { e.preventDefault(); row.classList.add('fw-dragover'); });
      row.addEventListener('dragleave', () => row.classList.remove('fw-dragover'));
      row.addEventListener('drop', e => {
        e.preventDefault(); row.classList.remove('fw-dragover');
        const from = Number(e.dataTransfer.getData('text/plain')), to = Number(row.dataset.idx);
        if (from === to || isNaN(from)) return;
        saveDraft(n => { const [m] = n.rules.splice(from, 1); n.rules.splice(to > from ? to - 1 : to, 0, m); });
      });
    });
  }

  function endpointOptions(isDst) {
    const c = cfg();
    const o = [{ value: 'any:', label: 'Any', section: 'General' }];
    // Every non-WAN network with a static address — follows the interfaces (server: InternalNets).
    const inside = c.interfaces.filter(i => i.role !== 'wan' && i.ipv4_mode === 'static' && i.ipv4);
    o.push({ value: 'internal:', label: 'Internal networks', section: 'General',
      hint: inside.length ? inside.map(i => i.name).join(', ') : 'none yet' });
    if (isDst) o.push({ value: 'this_znas:', label: 'This ZNAS', section: 'General' });
    o.push({ value: 'cidr:', label: 'An address or network…', section: 'General' });
    c.interfaces.forEach(i => {
      if (i.ipv4_mode !== 'static') return;
      o.push({ value: 'iface_net:' + i.id, label: i.name + ' net', section: 'Interfaces', color: i.color, hint: i.ipv4 });
      o.push({ value: 'iface_addr:' + i.id, label: i.name + ' address', section: 'Interfaces', color: i.color });
    });
    c.groups.filter(g => g.kind === 'hosts').forEach(g => o.push({ value: 'group:' + g.id, label: g.name, section: 'Groups', hint: g.members.length + ' entries' }));
    o.push({ value: 'countries:', label: 'Countries…', section: 'Countries' });
    c.groups.filter(g => g.kind === 'countries').forEach(g => o.push({ value: 'group:' + g.id, label: g.name, section: 'Countries', hint: g.members.join(', ') }));
    return o;
  }

  // from: index of a rule to clone — the new rule is prefilled from it and lands right below it.
  function editRule(idx, from) {
    const c = cfg();
    const cloned = idx == null && from != null && c.rules[from];
    const r = cloned ? Object.assign(clone(c.rules[from]), { id: newId(), description: cloneDesc(c.rules[from].description) })
      : idx == null ? { id: newId(), enabled: true, interface: rulesTab !== 'all' ? rulesTab : '', action: 'allow', protocol: 'tcp',
      source: { type: 'any' }, destination: { type: 'any' }, dst_ports: '', log: false, description: '' } : clone(c.rules[idx]);
    const bg = document.createElement('div');
    bg.className = 'fw-drawer-bg';
    const dr = document.createElement('div');
    dr.className = 'fw-drawer';
    dr.innerHTML = `<div class="fw-drawer-h"><h3>${cloned ? 'New rule (clone)' : (idx == null ? 'New rule' : 'Edit rule')}</h3><div class="fw-sentence" id="fwr-sent"></div></div>
      <div class="fw-drawer-b">
        <div class="fw-field"><label>Applies to traffic arriving on</label><div id="fwr-if"></div></div>
        <div class="fw-field"><label>Action</label><div id="fwr-act"></div></div>
        <div class="fw-field"><label>Protocol</label><div id="fwr-proto"></div></div>
        <div class="fw-field" id="fwr-gw-f"><label>Leaves through</label><div id="fwr-gw"></div>
          <label style="display:flex;gap:7px;align-items:center;margin-top:6px;text-transform:none;letter-spacing:0;font-size:12.5px;color:var(--text-2)"><input type="checkbox" id="fwr-gw-only">Only this gateway — block instead of failing over when it is down</label></div>
        <div class="fw-field"><label>From (source)</label><div id="fwr-src"></div><input type="text" id="fwr-src-v" placeholder="203.0.113.0/24" style="margin-top:6px"><div class="fw-chips" id="fwr-src-cc" style="margin-top:6px"></div>
          <label style="display:flex;gap:7px;align-items:center;margin-top:6px;text-transform:none;letter-spacing:0;font-size:12.5px;color:var(--text-2)"><input type="checkbox" id="fwr-src-not">Everything except this</label><div class="fw-err" id="fwr-src-err"></div></div>
        <div class="fw-field"><label>To (destination)</label><div id="fwr-dst"></div><input type="text" id="fwr-dst-v" placeholder="10.128.8.4" style="margin-top:6px"><div class="fw-chips" id="fwr-dst-cc" style="margin-top:6px"></div>
          <label style="display:flex;gap:7px;align-items:center;margin-top:6px;text-transform:none;letter-spacing:0;font-size:12.5px;color:var(--text-2)"><input type="checkbox" id="fwr-dst-not">Everything except this</label><div class="fw-err" id="fwr-dst-err"></div></div>
        <div class="fw-field" id="fwr-ports-f"><label>Destination port(s)</label><div class="fw-row2"><input type="text" id="fwr-ports" placeholder="443, 80 or 16261-16263 — empty = all"><div id="fwr-pgroup"></div></div><div class="fw-err" id="fwr-ports-err"></div></div>
        <div class="fw-field"><label>Description</label><input type="text" id="fwr-desc" placeholder="e.g. Plex from the Internet" value="${E(r.description)}"></div>
        <label style="display:flex;gap:8px;align-items:center;font-size:13px;cursor:pointer"><input type="checkbox" id="fwr-log" ${r.log ? 'checked' : ''}>Log matching connections</label>
        <label style="display:flex;gap:8px;align-items:center;font-size:13px;cursor:pointer"><input type="checkbox" id="fwr-en" ${r.enabled ? 'checked' : ''}>Enabled</label>
        <div class="fw-err" id="fwr-err"></div>
      </div>
      <div class="fw-drawer-f">${idx != null ? `<button class="btn btn-ghost" id="fwr-del" style="margin-right:auto;color:var(--fw-blk)">Delete</button>` : ''}<button class="btn btn-ghost" id="fwr-cancel">Cancel</button><button class="btn btn-primary" id="fwr-save">${idx == null ? 'Add rule' : 'Save'}</button></div>`;
    document.body.appendChild(bg); document.body.appendChild(dr);
    const close = () => { bg.remove(); dr.remove(); };
    bg.onclick = close;
    dr.querySelector('#fwr-cancel').onclick = close;
    const q = s => dr.querySelector(s);
    const epVal = ep => ep.type === 'cidr' ? 'cidr:' : (ep.type === 'countries' ? 'countries:' : ep.type + ':' + (ep.value || ''));
    const cc = { src: r.source.type === 'countries' ? (r.source.value || '').split(',').filter(Boolean) : [],
                 dst: r.destination.type === 'countries' ? (r.destination.value || '').split(',').filter(Boolean) : [] };
    const drawCC = which => {
      const el = q(`#fwr-${which}-cc`), sel = which === 'src' ? srcSel : dstSel;
      el.style.display = sel === 'countries:' ? '' : 'none';
      if (sel !== 'countries:') return;
      el.innerHTML = cc[which].map((code, k) => `<span class="fw-chip">${flagOf(code)} ${E(ccName(code))}<button data-ccrm="${k}" title="Remove">${icon('x', 11)}</button></span>`).join('') + '<span data-ccadd style="min-width:200px;display:inline-block"></span>';
      el.querySelectorAll('[data-ccrm]').forEach(b => b.onclick = () => { cc[which].splice(Number(b.dataset.ccrm), 1); drawCC(which); update(); });
      picker(el.querySelector('[data-ccadd]'), countryOptions(), '', v => { if (!cc[which].includes(v)) cc[which].push(v); drawCC(which); update(); }, { placeholder: '+ Add a country…', search: true });
    };
    const readEp = (which) => {
      const sel = which === 'src' ? srcSel : dstSel;
      const [type, value] = sel.split(/:(.*)/s);
      const ep = { type, not: q(`#fwr-${which}-not`).checked };
      if (type === 'cidr') ep.value = q(`#fwr-${which}-v`).value.trim();
      else if (type === 'countries') ep.value = cc[which].join(',');
      else if (value) ep.value = value;
      if (type === 'any') delete ep.not;
      return ep;
    };
    let srcSel = epVal(r.source), dstSel = epVal(r.destination), portGroup = (r.dst_ports || '').startsWith('group:') ? r.dst_ports.slice(6) : '';
    if (r.source.type === 'cidr') q('#fwr-src-v').value = r.source.value || '';
    if (r.destination.type === 'cidr') q('#fwr-dst-v').value = r.destination.value || '';
    q('#fwr-src-not').checked = !!r.source.not; q('#fwr-dst-not').checked = !!r.destination.not;
    if (!portGroup) q('#fwr-ports').value = r.dst_ports || '';
    const update = () => {
      r.source = readEp('src'); r.destination = readEp('dst');
      r.dst_ports = portGroup ? 'group:' + portGroup : q('#fwr-ports').value.replace(/\s+/g, '');
      r.description = q('#fwr-desc').value; r.log = q('#fwr-log').checked; r.enabled = q('#fwr-en').checked;
      [['src', srcSel], ['dst', dstSel]].forEach(([w, sel]) => { // "except Any" means nothing
        const cb = q(`#fwr-${w}-not`), any = sel === 'any:';
        cb.disabled = any; cb.parentElement.style.opacity = any ? '.45' : '';
        cb.parentElement.title = any ? 'Choose something other than Any to invert it' : '';
      });
      q('#fwr-src-v').style.display = srcSel === 'cidr:' ? '' : 'none';
      q('#fwr-dst-v').style.display = dstSel === 'cidr:' ? '' : 'none';
      q('#fwr-ports-f').style.display = ['tcp', 'udp', 'tcpudp'].includes(r.protocol) ? '' : 'none';
      q('#fwr-ports').disabled = !!portGroup;
      r.only_gateway = !!r.gateway && q('#fwr-gw-only').checked;
      q('#fwr-gw-f').style.display = c.gateways.length && r.action === 'allow' ? '' : 'none';
      q('#fwr-gw-only').parentElement.style.display = r.gateway ? '' : 'none';
      q('#fwr-sent').innerHTML = sentence(r);
    };
    const ifOpts = [{ value: '', label: 'Any interface' }, ...c.interfaces.map(i => ({ value: i.id, label: i.name, color: i.color, hint: i.role ? i.role.toUpperCase() : '' }))];
    picker(q('#fwr-if'), ifOpts, r.interface, v => { r.interface = v; update(); });
    seg(q('#fwr-act'), [['allow', 'Allow'], ['block', 'Block (silent)'], ['reject', 'Reject']], r.action, v => { r.action = v; if (v !== 'allow') { r.gateway = ''; gwp.set(''); } update(); });
    q('#fwr-gw-only').checked = !!r.only_gateway;
    const gwp = picker(q('#fwr-gw'), [{ value: '', label: 'Normal routing (best gateway, with failover)' },
      ...c.gateways.slice().sort((a, b) => a.priority - b.priority).map(g => ({ value: g.id, label: g.name, hint: 'priority ' + g.priority }))],
      r.gateway || '', v => { r.gateway = v; update(); });
    seg(q('#fwr-proto'), [['tcp', 'TCP'], ['udp', 'UDP'], ['tcpudp', 'TCP+UDP'], ['icmp', 'ICMP'], ['any', 'Any']], r.protocol, v => {
      r.protocol = v; if (!['tcp', 'udp', 'tcpudp'].includes(v)) { q('#fwr-ports').value = ''; portGroup = ''; pg.set(''); } update();
    });
    picker(q('#fwr-src'), endpointOptions(false), srcSel, v => { srcSel = v; drawCC('src'); update(); }, { search: true });
    picker(q('#fwr-dst'), endpointOptions(true), dstSel, v => { dstSel = v; drawCC('dst'); update(); }, { search: true });
    loadCountries().then(() => { drawCC('src'); drawCC('dst'); });
    const pg = picker(q('#fwr-pgroup'), [{ value: '', label: 'or a port group…' }, ...c.groups.filter(g => g.kind === 'ports').map(g => ({ value: g.id, label: g.name, hint: g.members.join(', ') }))],
      portGroup, v => { portGroup = v; if (v) q('#fwr-ports').value = ''; update(); });
    dr.querySelectorAll('input').forEach(i => i.addEventListener('input', update));
    dr.querySelectorAll('input[type=checkbox]').forEach(i => i.addEventListener('change', update));
    update();
    if (idx != null) q('#fwr-del').onclick = () => { close(); saveDraft(n => { n.rules.splice(idx, 1); }); };
    q('#fwr-save').onclick = async () => {
      update();
      const next = clone(cfg());
      let at = idx;
      if (idx == null) { at = cloned ? from + 1 : next.rules.length; next.rules.splice(at, 0, r); } else next.rules[idx] = r;
      const errs = (await validate(next)).filter(e => e.path.startsWith(`rules[${at}]`));
      dr.querySelectorAll('.fw-err').forEach(e => e.textContent = '');
      if (errs.length) {
        const f = errs[0].path.split('.').pop();
        (q({ source: '#fwr-src-err', destination: '#fwr-dst-err', dst_ports: '#fwr-ports-err' }[f] || '#fwr-err')).textContent = errs[0].message;
        return;
      }
      close();
      saveDraft(n => { n.rules = next.rules; });
    };
  }

  // ── Optional Features row + enable wizard + disable ────────────────────
  function renderOptFeatRow() {
    const st = document.getElementById('sdnfeat-status');
    const btn = document.getElementById('sdnfeat-btn');
    if (!st || !btn) return;
    if (!status) { st.textContent = 'Unavailable'; btn.style.display = 'none'; return; }
    btn.style.display = isAdmin() ? '' : 'none';
    if (status.enabled) {
      st.textContent = status.safe_mode_reason ? 'Enabled — SAFE MODE' : 'Enabled'; st.style.color = status.safe_mode_reason ? 'var(--fw-blk)' : 'var(--accent-3)';
      btn.textContent = 'Disable'; btn.disabled = false; btn.onclick = openDisable; btn.title = '';
    } else {
      st.textContent = status.installed ? 'Not enabled' : 'Not installed'; st.style.color = 'var(--text-3)';
      const missing = status.missing_packages || [];
      btn.textContent = status.installed && !missing.length ? 'Enable' : 'Install & Enable';
      btn.title = missing.length ? 'Installs ' + missing.join(', ') : '';
      btn.disabled = !status.sudo_ok;
      if (!status.sudo_ok) btn.title = 'Requires running as root or sudo-all';
      btn.onclick = status.installed && !missing.length ? openEnable : installThenEnable;
    }
  }

  async function installThenEnable() {
    const btn = document.getElementById('sdnfeat-btn');
    btn.disabled = true; btn.textContent = 'Installing packages…';
    // Everything the Firewall can use, in one go — its services stay off until configured.
    const r = await api('POST', '/api/prereqs/install', { package: 'sdn-firewall' });
    btn.disabled = false;
    if (!r.ok) { toast((r.data && r.data.error) || 'Install failed', 'error'); renderOptFeatRow(); return; }
    await loadStatus();
    if (status && status.installed) openEnable();
    else modal({ title: 'ifupdown networking required', body: '<p>The Firewall manages interfaces through <code>/etc/network/interfaces</code> (ifupdown). This server is not using ifupdown yet.</p><p>Enable <b>VMs &amp; Containers</b> first — its setup switches the server to ifupdown networking — then enable the Firewall.</p>', buttons: [{ label: 'OK', cls: 'btn-primary' }] });
  }

  async function openEnable() {
    const r = await api('GET', '/api/sdn/interfaces/live');
    live = ((r.ok && r.data) || []).filter(isPort);
    const mgmt = live.find(l => l.mgmt) || {};
    const st = { step: 0, mgmt: mgmt.device || '', mode: 'monitor', rows: {}, restored: !!(status && status.restored), fresh: false, map: {} };
    const lastCfg = await api('GET', '/api/sdn/config');
    const saved = (lastCfg.ok && lastCfg.data) || {};
    // Ports of a restored config that have another name here (new hardware).
    const needed = st.restored ? [...new Set((saved.interfaces || []).filter(i => i.kind !== 'wireguard').map(i => i.kind === 'vlan' || i.kind === 'pppoe' ? i.parent : i.device))].filter(d => !live.some(l => l.device === d)) : [];
    const devOf = d => st.map[d] || d;
    const prefill = () => {
      const mgmtDev = st.mgmt;
      st.rows = {};
      live.forEach((l, k) => {
        st.rows[l.device] = { on: !!l.mgmt, role: l.mgmt ? 'lan' : '', name: l.device, color: PALETTE[k % PALETTE.length] };
      });
      st.mode = 'monitor';
      if (st.fresh) return;
      // Enabled before: start from the ports it had (same names, roles,
      // colours; the server keeps their rules, VLANs, DHCP… with them).
      (saved.interfaces || []).forEach(i => {
        const row = st.rows[devOf(i.device)];
        if (row && !i.owned && live.some(l => l.device === devOf(i.device) && l.adoptable)) Object.assign(row, { on: true, role: i.role || '', name: i.name, color: C(i.color) });
      });
      const sm = saved.settings || {};
      if (sm.mgmt_interface && st.rows[devOf(sm.mgmt_interface)]) st.mgmt = mgmtDev || devOf(sm.mgmt_interface);
      if (sm.mode) st.mode = sm.mode;
    };
    prefill();
    const box = document.createElement('div');
    const steps = ['Management', 'Interfaces', 'Starting mode', 'Review'];
    const m = modal({ title: 'Enable the Firewall', body: box, width: 640, buttons: [
      { label: 'Back', id: 'fwe-back', onClick: () => { if (st.step > 0) { st.step--; draw(); } } },
      { label: 'Next', cls: 'btn-primary', id: 'fwe-next', onClick: async (close, btn) => {
        if (st.step === 0 && !st.fresh) {
          const used = Object.values(st.map).filter(Boolean);
          if (new Set(used).size !== used.length) { box.querySelector('#fwe-map-err').textContent = 'Each port here can take the place of one port only'; return; }
        }
        if (st.step < 3) { st.step++; draw(); return; }
        btn.disabled = true; btn.textContent = 'Enabling…';
        const ifaces = Object.entries(st.rows).filter(([d, v]) => v.on || d === st.mgmt).map(([d, v]) => {
          const L = liveOf(d) || {};
          return { id: newId(), name: v.name || d, color: v.color, kind: L.incus ? 'incus' : (L.kind === 'bridge' ? 'bridge' : 'physical'), device: d, role: v.role, incus_keep: !!L.incus_keep,
            ipv4_mode: (!L.incus || L.incus_keep) && L.cfg_mode === 'static' ? 'static' : (!L.incus && L.cfg_mode === 'dhcp' ? 'dhcp' : 'none'), ipv4: (!L.incus || L.incus_keep) && L.cfg_mode === 'static' ? (L.cfg_address || '') : '',
            gateway: L.cfg_mode === 'static' && !L.incus ? (L.cfg_gateway || '') : '', owned: false, allow_vms: false };
        });
        const res = await api('POST', '/api/sdn/enable', { mgmt_interface: st.mgmt, mode: st.mode, interfaces: ifaces, fresh: st.fresh, mapping: st.fresh ? {} : st.map });
        btn.disabled = false; btn.textContent = 'Enable';
        if (!res.ok) {
          const errs = (res.data && res.data.errors) || [];
          box.querySelector('#fwe-err').innerHTML = `<div class="fw-safemode"><div><b>Not enabled.</b> ${E((res.data && res.data.error) || '')}${errs.map(e => `<div>${E(e.message)}</div>`).join('')}</div></div>`;
          return;
        }
        close();
        await Promise.all([loadStatus(), loadDraft()]);
        if (res.data && res.data.dropped) toast('Not restored, it does not fit this server: ' + res.data.dropped.join(', '), 'error');
        if (res.data && res.data.seconds) openCountdown(res.data.seconds);
      } },
    ] });
    const draw = () => {
      const bar = `<div class="fw-steps">${steps.map((s, k) => `<div class="${k <= st.step ? 'on' : ''}" title="${E(s)}"></div>`).join('')}</div>`;
      let html = '';
      if (st.step === 0) {
        html = (st.restored ? `<div class="fw-note" style="margin-bottom:12px"><b>A Firewall configuration was restored from a backup:</b> ${(saved.interfaces || []).length} interfaces, ${(saved.rules || []).length} rules, ${(saved.wg_peers || []).length} VPN peers, ${(saved.dhcp || []).length} DHCP networks.</div>
          <div id="fwe-restored" style="margin-bottom:12px"></div>
          ${needed.length && !st.fresh ? `<div class="fw-field" style="margin-bottom:12px"><label>Ports of the old server that are not here</label>
            ${needed.map(d => `<div style="display:flex;gap:10px;align-items:center;margin-top:6px"><span class="fw-mono" style="min-width:120px">${E(d)}</span><div data-map="${E(d)}" style="flex:1"></div></div>`).join('')}
            <div class="fw-err" id="fwe-map-err"></div></div>` : ''}` : '') + `<p style="margin-top:0">Which network port do you use to reach this portal? The <b>anti-lockout</b> rule will always keep the portal and SSH reachable on it.</p><div id="fwe-mgmt"></div>
          <p style="color:var(--text-3);font-size:12.5px">Detected from the address your browser used: <b>${E(mgmt.device || 'unknown')}</b>.</p>`;
      } else if (st.step === 1) {
        html = `<p style="margin-top:0">Choose the ports the firewall manages and their role. Nothing is changed on them — their addresses stay as they are. You can add VLANs after enabling.</p>
          <table class="fw-adopt"><tr><th></th><th>Port</th><th>Name</th><th>Role</th><th>Address</th></tr>${live.map(l => {
            const row = st.rows[l.device];
            const dis = !l.adoptable;
            return `<tr class="${dis ? 'dis' : ''}" data-d="${E(l.device)}"><td><input type="checkbox" ${row.on || l.device === st.mgmt ? 'checked' : ''} ${dis || l.device === st.mgmt ? 'disabled' : ''}></td>
              <td class="fw-mono">${E(l.device)}<div style="color:var(--text-3);font-size:11px">${E(dis ? l.reason : l.kind)}</div></td>
              <td><input type="text" value="${E(row.name)}" style="width:130px" ${dis ? 'disabled' : ''}></td><td><div class="fwe-role"></div></td>
              <td class="fw-mono" style="font-size:11.5px">${E((l.ipv4 || []).join(', ') || '—')}</td></tr>`;
          }).join('')}</table>`;
      } else if (st.step === 2) {
        html = `<div class="fw-choice ${st.mode === 'monitor' ? 'on' : ''}" data-mode="monitor"><b>Monitor only (recommended to start)</b><span>Nothing is filtered. Interfaces are managed and traffic is observed, so you can build your rules first and switch to Router when ready.</span></div>
          <div class="fw-choice ${st.mode === 'router' ? 'on' : ''}" data-mode="router"><b>Router</b><span>Rules are enforced immediately: whatever is not allowed is blocked (the anti-lockout rule still protects the portal).</span></div>`;
      } else {
        const sel = Object.entries(st.rows).filter(([d, v]) => v.on || d === st.mgmt);
        html = `<p style="margin-top:0">Ready to enable:</p><ul style="line-height:1.8">
          <li>Management: <b>${E(st.mgmt)}</b> (anti-lockout on)</li>
          <li>Interfaces: ${sel.map(([d, v]) => `<b>${E(v.name)}</b> (${E(v.role ? v.role.toUpperCase() : 'unassigned')})`).join(', ')}</li>
          <li>Mode: <b>${st.mode === 'router' ? 'Router' : 'Monitor only'}</b></li></ul>
          <p style="color:var(--text-3);font-size:12.5px">The change is applied with the ${COUNTDOWN}-second confirmation: if you lose this page, the server goes back to its current networking by itself.</p><div id="fwe-err"></div>`;
      }
      box.innerHTML = bar + html;
      m.foot.querySelector('#fwe-back').style.visibility = st.step ? '' : 'hidden';
      m.foot.querySelector('#fwe-next').textContent = st.step === 3 ? 'Enable' : 'Next';
      if (st.step === 0) picker(box.querySelector('#fwe-mgmt'), live.filter(l => l.adoptable).map(l => ({ value: l.device, label: l.device + ((l.ipv4 || [])[0] ? '  ' + l.ipv4[0] : ''), hint: l.mgmt ? 'this session' : l.kind })),
        st.mgmt, v => { st.mgmt = v; st.rows[v].on = true; if (!st.rows[v].role) st.rows[v].role = 'lan'; });
      if (st.step === 0 && st.restored) {
        seg(box.querySelector('#fwe-restored'), [['saved', 'Start from the restored configuration'], ['fresh', 'Start empty']], st.fresh ? 'fresh' : 'saved', v => { st.fresh = v === 'fresh'; if (st.fresh) st.map = {}; prefill(); draw(); });
        box.querySelectorAll('[data-map]').forEach(el => picker(el, [{ value: '', label: "Don't use this port" }, ...live.filter(l => l.adoptable).map(l => ({ value: l.device, label: l.device }))], st.map[el.dataset.map] || '', v => { if (v) st.map[el.dataset.map] = v; else delete st.map[el.dataset.map]; prefill(); }));
      }
      if (st.step === 1) box.querySelectorAll('tr[data-d]').forEach(tr => {
        const d = tr.dataset.d, row = st.rows[d];
        const cb = tr.querySelector('input[type=checkbox]');
        cb.onchange = () => { row.on = cb.checked; };
        tr.querySelector('input[type=text]').oninput = e => { row.name = e.target.value; };
        if (!tr.classList.contains('dis')) seg(tr.querySelector('.fwe-role'), [['wan', 'WAN'], ['lan', 'LAN'], ['', '—']], row.role, v => { row.role = v; });
      });
      if (st.step === 2) box.querySelectorAll('[data-mode]').forEach(c => c.onclick = () => { st.mode = c.dataset.mode; draw(); });
    };
    draw();
  }

  function openDisable() {
    const box = document.createElement('div');
    box.innerHTML = `<p style="margin-top:0">The server goes back to the networking it had before the Firewall was enabled: VLANs created by the Firewall are removed, rules stop, and the Firewall menu disappears.</p>
      <p>Your firewall configuration is kept — enabling again starts from it.</p>
      <label style="display:flex;gap:8px;align-items:center;font-size:13px"><input type="checkbox" id="fwd-traffic">Also delete the traffic history</label>`;
    modal({ title: 'Disable the Firewall?', body: box, buttons: [{ label: 'Cancel' }, { label: 'Disable', cls: 'btn-danger', onClick: async (close, btn) => {
      btn.disabled = true;
      const r = await api('POST', '/api/sdn/disable', { delete_traffic: box.querySelector('#fwd-traffic').checked });
      btn.disabled = false;
      if (!r.ok) { toast((r.data && r.data.error) || 'Could not disable', 'error'); return; }
      close(); toast('Firewall disabled', 'success');
      await loadStatus();
    } }] });
  }

  // ── Export / Import ────────────────────────────────────────────────────
  function openExport() {
    const box = document.createElement('div');
    box.innerHTML = `<p style="margin-top:0">One file with the whole firewall configuration: interfaces, groups, rules, gateways, NAT, DHCP & DNS, WireGuard tunnels and their keys, and settings. It is encrypted with the password you choose.</p>
      <div class="fw-field"><label>Password (12 characters minimum)</label><input type="password" id="fwx-p1" autocomplete="new-password"></div>
      <div class="fw-field"><label>Confirm password</label><input type="password" id="fwx-p2" autocomplete="new-password"><div class="fw-err" id="fwx-err"></div></div>`;
    modal({ title: 'Export the firewall configuration', body: box, buttons: [{ label: 'Cancel' }, { label: 'Download', cls: 'btn-primary', onClick: async (close, btn) => {
      const p1 = box.querySelector('#fwx-p1').value, p2 = box.querySelector('#fwx-p2').value;
      if (p1.length < 12) { box.querySelector('#fwx-err').textContent = 'At least 12 characters'; return; }
      if (p1 !== p2) { box.querySelector('#fwx-err').textContent = 'The passwords do not match'; return; }
      btn.disabled = true;
      const res = await fetch('/api/sdn/export', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: p1 }) });
      btn.disabled = false;
      if (!res.ok) { let e = {}; try { e = await res.json(); } catch (_) {} box.querySelector('#fwx-err').textContent = e.error || 'Export failed'; return; }
      const blob = await res.blob();
      const name = ((res.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/) || [])[1] || 'znas-firewall.znasfw';
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
      close();
    } }] });
  }

  function openImport() {
    const box = document.createElement('div');
    box.innerHTML = `<p style="margin-top:0">Load a <code>.znasfw</code> file into the draft. Nothing changes on the router until you press <b>Apply</b>.</p>
      <div class="fw-field"><label>File</label><input type="file" id="fwm-file" accept=".znasfw"></div>
      <div class="fw-field"><label>Password</label><input type="password" id="fwm-pw"></div>
      <div id="fwm-step2"></div><div class="fw-err" id="fwm-err"></div>`;
    let inspected = null;
    const mapping = {};
    const m = modal({ title: 'Import a firewall configuration', body: box, width: 600, buttons: [{ label: 'Cancel' }, { label: 'Check file', cls: 'btn-primary', id: 'fwm-go', onClick: async (close, btn) => {
      box.querySelector('#fwm-err').textContent = '';
      if (!inspected) {
        const f = box.querySelector('#fwm-file').files[0];
        if (!f) { box.querySelector('#fwm-err').textContent = 'Choose a file'; return; }
        const fd = new FormData(); fd.append('file', f); fd.append('password', box.querySelector('#fwm-pw').value);
        btn.disabled = true;
        const res = await fetch('/api/sdn/import/inspect', { method: 'POST', body: fd, credentials: 'same-origin' });
        btn.disabled = false;
        let d = {}; try { d = await res.json(); } catch (_) {}
        if (!res.ok) { box.querySelector('#fwm-err').textContent = d.error || 'This file cannot be read'; return; }
        inspected = d;
        const miss = d.devices_missing || [];
        box.querySelector('#fwm-step2').innerHTML = `<div class="fw-card" style="margin-top:6px"><b>${E(d.hostname)}</b><span style="color:var(--text-3);font-size:12.5px">exported ${E(fmtTime(d.created_at))} · ZNAS ${E(d.znas_version)}</span>
          <div style="font-size:13px">Changes compared with this server: ${E(d.summary)}</div></div>
          ${miss.length ? `<p style="margin:12px 0 6px"><b>These network ports do not exist here.</b> Choose which port takes their place:</p>
            <table class="fw-adopt">${miss.map(dev => `<tr><td class="fw-mono">${E(dev)}</td><td>→</td><td><div data-map="${E(dev)}"></div></td></tr>`).join('')}</table>` : '<p style="color:var(--accent-3)">All its network ports exist on this server.</p>'}`;
        box.querySelectorAll('[data-map]').forEach(el => picker(el, (d.live_devices || []).map(x => ({ value: x, label: x })), '', v => { mapping[el.dataset.map] = v; }, { placeholder: 'Choose a port…' }));
        btn.textContent = 'Load into draft';
        return;
      }
      const miss = inspected.devices_missing || [];
      if (miss.some(d => !mapping[d])) { box.querySelector('#fwm-err').textContent = 'Choose a port for every missing one'; return; }
      btn.disabled = true;
      const r = await api('POST', '/api/sdn/import/apply', { id: inspected.id, mapping });
      btn.disabled = false;
      if (!r.ok) { box.querySelector('#fwm-err').textContent = (r.data && r.data.error) || 'Import failed'; return; }
      draft = r.data;
      close(); renderPage();
      toast('Imported into the draft — review it, then press Apply', 'success');
    } }] });
    return m;
  }

  // ── boot ───────────────────────────────────────────────────────────────
  // Shared with the pages in other files (sdn-gw-nat.js).
  window.sdnFW = {
    E, C, icon, isAdmin, toast, api, cfg, clone, newId, PALETTE, modal, picker, seg, saveDraft, validate, rowActs, cloneDesc, info, lab,
    editInterface, setGwPriority, nextGwPriority, liveLinks: async () => { const r = await api('GET', '/api/sdn/interfaces/live'); if (r.ok) live = r.data || []; return live; },
    endpointOptions, epLabel, sortTables, loadCountries, countryOptions, flagOf, ccName, fmtTime, fmtCount,
    status: () => status, page: () => page, rerender: () => renderPage(), l3,
  };
  window.sdnLoadStatus = loadStatus;
  window.sdnModal = modal;
  window.sdnReloadTopbar = async () => { await loadDraft(); renderPage(); };
  window.sdnOnShowPage = onShowPage;
  window.sdnFirstPage = () => 'fw-interfaces';
  window.sdnIsPage = name => !!PAGES[name];

  // The script sits at the end of <body>: the page anchors exist already, so
  // create the containers now. The app's async startup can still beat us
  // (index.html is ~3 MB and still parsing when it restores #fw-* from the
  // URL): then it fell back to the dashboard — show the requested page now.
  ensurePages();
  (function reshowFromHash() {
    const h = (location.hash || '').slice(1);
    const el = PAGES[h] && document.getElementById('page-' + h);
    if (el && el.classList.contains('hidden') && me() && typeof window.showPage === 'function') window.showPage(h);
  })();
  function boot() {
    ensurePages();
    if (me()) loadStatus(); else setTimeout(boot, 400);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
