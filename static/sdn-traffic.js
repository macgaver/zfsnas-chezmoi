/*
 * Firewall → Traffic & GeoMap and Live connections (SDN phase 2).
 * Spec: PLANS/spec-sdn-firewall.md §12; approved mockup ~/Videos/mockups/01-traffic.html.
 *
 * Registers renderers with sdn.js through window.sdnRegisterPage(name, {render, wire, poll}).
 * The world map is drawn with a local Natural Earth projection and a tiny TopoJSON decoder
 * over static/vendor/world-110m.json (no CDN, portal CSP).
 */
(function () {
  'use strict';

  const E = s => (typeof window.esc === 'function' ? window.esc(s) : String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'));
  const me = () => (typeof currentUser !== 'undefined' ? currentUser : null);
  const isAdmin = () => !!me() && me().role === 'admin';
  const toast = (m, t) => (typeof window.showToast === 'function' ? window.showToast(m, t) : null);
  const icon = (n, size) => (typeof window.znasIcon === 'function' ? window.znasIcon(n, { size: size || 14 }) : '');
  const flag = cc => (cc && /^[A-Z]{2}$/.test(cc)) ? String.fromCodePoint(...[...cc].map(c => 127397 + c.charCodeAt(0))) : '';
  const fmtB = b => { b = Number(b || 0); if (b >= 1e12) return (b / 1e12).toFixed(1) + ' TB'; if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB'; if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'; if (b >= 1e3) return (b / 1e3).toFixed(0) + ' kB'; return b + ' B'; };
  const fmtN = n => Number(n || 0).toLocaleString();
  const ago = t => {
    if (!t || t.startsWith('0001')) return '';
    const s = (Date.now() - new Date(t).getTime()) / 1000;
    if (s < 60) return 'now'; if (s < 3600) return Math.round(s / 60) + ' min ago'; if (s < 86400) return Math.round(s / 3600) + ' h ago';
    return Math.round(s / 86400) + ' d ago';
  };
  // interfaces by the name they were given (index.html ifLabel), else Linux
  const ifName = d => (typeof window.ifLabel === 'function' ? window.ifLabel(d) : d) || '';
  async function api(url, opt) {
    try { const r = await fetch(url, Object.assign({ credentials: 'same-origin' }, opt || {})); let d = null; try { d = await r.json(); } catch (_) {} return { ok: r.ok, status: r.status, data: d }; }
    catch (e) { return { ok: false, status: 0, data: { error: 'The server is not reachable' } }; }
  }

  // ── projection + topojson ───────────────────────────────────────────────
  // Two base maps: the built-in outline (Natural Earth projection) and
  // OpenStreetMap tiles (Web Mercator, taller so the far north still fits).
  const W = 960, NE_H = 470, OSM_H = 620, SCALE = 175, TX = W / 2, TY = NE_H / 2 + 20;
  let H = NE_H;
  const isOSM = () => T.style === 'osm';
  function proj(lon, lat) {
    if (!isOSM()) return projNE(lon, lat);
    const p = Math.max(-85, Math.min(85, lat)) * Math.PI / 180;
    return [W / 2 + Math.max(-180, Math.min(180, lon)) / 360 * W, H / 2 - W / (2 * Math.PI) * Math.log(Math.tan(Math.PI / 4 + p / 2))];
  }
  function projNE(lon, lat) {
    const l = Math.max(-180, Math.min(180, lon)) * Math.PI / 180, p = Math.max(-89.9, Math.min(89.9, lat)) * Math.PI / 180;
    const p2 = p * p, p4 = p2 * p2;
    const x = l * (0.8707 - 0.131979 * p2 + p4 * (-0.013791 + p4 * (0.003971 * p2 - 0.001529 * p4)));
    const y = p * (1.007226 + p2 * (0.015085 + p4 * (-0.044475 + 0.028874 * p2 - 0.005916 * p4)));
    return [TX + SCALE * x, TY - SCALE * y];
  }
  let landPaths = null;
  async function loadLand() {
    if (landPaths) return landPaths;
    const r = await api('/static/vendor/world-110m.json');
    if (!r.ok || !r.data) return (landPaths = []);
    const topo = r.data, [sx, sy] = topo.transform.scale, [tx, ty] = topo.transform.translate;
    const arcs = topo.arcs.map(a => { let x = 0, y = 0; return a.map(([dx, dy]) => { x += dx; y += dy; return [x * sx + tx, y * sy + ty]; }); });
    const ring = idx => {
      let pts = [];
      idx.forEach(i => { const a = i < 0 ? arcs[~i].slice().reverse() : arcs[i]; pts = pts.concat(pts.length ? a.slice(1) : a); });
      // unwrap the antimeridian then clamp: no streaks across the map
      for (let k = 1; k < pts.length; k++) { while (pts[k][0] - pts[k - 1][0] > 180) pts[k] = [pts[k][0] - 360, pts[k][1]]; while (pts[k][0] - pts[k - 1][0] < -180) pts[k] = [pts[k][0] + 360, pts[k][1]]; }
      return 'M' + pts.map(p => projNE(p[0], p[1]).map(v => v.toFixed(1)).join(',')).join('L') + 'Z';
    };
    landPaths = topo.objects.countries.geometries.map(g => {
      const polys = g.type === 'Polygon' ? [g.arcs] : (g.type === 'MultiPolygon' ? g.arcs : []);
      return { name: (g.properties && g.properties.name) || '', d: polys.map(p => p.map(ring).join('')).join('') };
    });
    return landPaths;
  }
  function graticule() {
    let d = '';
    for (let lon = -180; lon <= 180; lon += 30) { d += 'M' + [...Array(37)].map((_, i) => projNE(lon, -90 + i * 5).map(v => v.toFixed(1)).join(',')).join('L'); }
    for (let lat = -60; lat <= 60; lat += 30) { d += 'M' + [...Array(73)].map((_, i) => projNE(-180 + i * 5, lat).map(v => v.toFixed(1)).join(',')).join('L'); }
    return d;
  }

  // ── state ───────────────────────────────────────────────────────────────
  // Until the server's location is known: the top half of the map, which is
  // the northern hemisphere in both projections.
  function northView() { return { k: 2, x: W / 4, y: 0 }; }
  // The starting view: three clicks of + from the whole world, around this
  // server. The zoom bar's globe shows the whole world.
  function homeView() {
    const k = 8, [hx, hy] = proj(home().lon, home().lat);
    return { k, x: Math.max(0, Math.min(W - W / k, hx - W / k / 2)), y: Math.max(0, Math.min(H - H / k, hy - H / k / 2)) };
  }
  const T = { range: '1h', page: { in: 0, out: 0, blk: 0 }, dir: 'all', group: 'ip', q: '', data: { in: null, out: null, blk: null }, status: null, sel: null, pools: null,
    zoom: northView(), // map view: scale + top-left corner (map units), kept across re-renders
    style: null }; // base map: '' (outline) | 'osm' — the user's preference, saved on the server
  function mapStyle() {
    if (T.style == null) { const u = me(); T.style = (u && u.preferences && u.preferences.fw_map_style) || ''; }
    H = isOSM() ? OSM_H : NE_H;
    return T.style;
  }
  function setMapStyle(v) {
    T.style = v; T.zoom = northView(); T.homed = false; // the projections differ: start over
    const u = me();
    if (u) u.preferences = Object.assign({}, u.preferences || {}, { fw_map_style: v });
    fetch('/api/prefs', { method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ fw_map_style: v }) }).catch(() => {});
    if (rerender) rerender();
  }
  const COL = { in: 'var(--fw-in)', out: 'var(--fw-out)', blk: 'var(--fw-blk)' };
  // Line colours by theme: the dark ones fade on a light map (the cyan was
  // close to the street map's water), so light themes get deeper hues.
  const HEX_DARK = { in: '#64d2ff', out: '#bf5af2', blk: '#ff453a' };
  const HEX_LIGHT = { in: '#0a5fd6', out: '#9b3fd1', blk: '#d92d20' };
  const lightTheme = () => document.body.classList.contains('light') || document.body.classList.contains('dawn');
  const HEX = new Proxy({}, { get: (_, k) => (lightTheme() ? HEX_LIGHT : HEX_DARK)[k] });

  const TABLE_MAX = 2000, PAGE_SIZE = 20;
  async function loadTraffic() {
    const qs = d => `/api/sdn/traffic?range=${T.range}&dir=${d}&group=${d === 'blk' && T.group !== 'ip' ? 'country' : T.group}&q=${encodeURIComponent(T.q)}&limit=${TABLE_MAX}`;
    const [a, b, c, s] = await Promise.all([api(qs('in')), api(qs('out')), api(qs('blk')), api('/api/sdn/traffic/status')]);
    T.data = { in: a.data, out: b.data, blk: c.data };
    T.status = s.data;
    await loadLand();
  }

  function kpi() {
    const k = (T.data.in && T.data.in.kpi) || {};
    const i = k.in || {}, o = k.out || {}, b = k.blk || {};
    const st = (T.status && T.status.status) || {};
    return `<div class="fw-kpis">
      <div class="fw-kpi"><div class="fw-kpi-bar" style="background:var(--fw-in)"></div><div class="fw-kpi-l"><span class="fw-sw" style="background:var(--fw-in)"></span>Incoming (they connected to us)</div><div class="fw-kpi-v">${fmtB(i.Bytes)}</div><div class="fw-kpi-d">${fmtN(i.Sessions)} sessions · ${fmtN(i.Remotes)} remote IPs · ${fmtN(i.Countries)} countries</div></div>
      <div class="fw-kpi"><div class="fw-kpi-bar" style="background:var(--fw-out)"></div><div class="fw-kpi-l"><span class="fw-sw" style="background:var(--fw-out)"></span>Outgoing (we connected out)</div><div class="fw-kpi-v">${fmtB(o.Bytes)}</div><div class="fw-kpi-d">${fmtN(o.Sessions)} sessions · ${fmtN(o.Remotes)} remote IPs · ${fmtN(o.Countries)} countries</div></div>
      <div class="fw-kpi"><div class="fw-kpi-bar" style="background:var(--fw-blk)"></div><div class="fw-kpi-l"><span class="fw-sw" style="background:var(--fw-blk)"></span>Blocked attempts</div><div class="fw-kpi-v">${fmtN(b.Pkts)}</div><div class="fw-kpi-d">${fmtN(b.Remotes)} IPs${(b.top_countries || []).length ? ' · top: ' + E(b.top_countries.join(', ')) : ''}</div></div>
      <div class="fw-kpi"><div class="fw-kpi-bar" style="background:var(--accent-3)"></div><div class="fw-kpi-l"><span class="fw-sw" style="background:var(--accent-3)"></span>Collector</div><div class="fw-kpi-v" style="font-size:15px;margin-top:8px">${st.running ? `<span style="color:var(--accent-3)">● running</span>` : `<span style="color:var(--fw-blk)">● stopped</span>`}</div><div class="fw-kpi-d">${st.error ? E(st.error) : (st.last_flush && !st.last_flush.startsWith('0001') ? 'saved ' + ago(st.last_flush) : 'first save within 10 min')}</div></div>
    </div>`;
  }

  function seg(name, items, val) {
    return `<div class="fw-seg" data-tseg="${name}">${items.map(([v, l, c]) => `<button type="button" data-v="${v}" class="${v === val ? 'on' : ''}">${c ? `<span class="fw-sw" style="background:${c}"></span>` : ''}${E(l)}</button>`).join('')}</div>`;
  }

  function banners() {
    const st = (T.status && T.status.status) || {};
    let h = '';
    if (st.ram_only) {
      h += `<div class="fw-safemode" style="background:rgba(255,214,10,.10);border-color:rgba(255,214,10,.4)">${icon('info', 16)}<div><b style="color:var(--accent-warn)">Statistics are kept in memory only</b> and are lost at reboot. Choose a pool to keep 5 years of history (a dataset <code>znas-netstats</code> is created on it).</div><span style="flex:1"></span>${isAdmin() ? '<button class="fw-btn" id="fwt-pool">Choose a pool…</button>' : ''}</div>`;
    }
    const geo = st.geo || [];
    if (geo.length && !geo.some(g => g.present)) {
      h += `<div class="fw-safemode" style="background:rgba(10,132,255,.08);border-color:rgba(10,132,255,.35)">${icon('globe', 16)}<div><b>Location database not downloaded yet</b>${st.geo_error ? ' — ' + E(st.geo_error) : ''}. Countries, cities and the map appear once it is in place.</div><span style="flex:1"></span>${isAdmin() ? '<button class="fw-btn" id="fwt-geo">Download now</button>' : ''}</div>`;
    }
    return h;
  }

  function mapHTML() {
    const lp = landPaths || [], osm = mapStyle() === 'osm';
    if (!T.homed && T.status) { T.zoom = homeView(); T.homed = true; }
    return `<div class="fw-mapcard${osm ? ' fw-osm' : ''}" id="fwt-mapcard">
      <svg id="fwt-map" viewBox="${viewBox()}" preserveAspectRatio="xMidYMid meet" style="touch-action:${T.zoom.k > 1 ? 'none' : 'pan-y'}">
        ${osm ? '<g id="fwt-tiles"></g>' : `<path class="fw-grat" d="${graticule()}"/>
        <g>${lp.map(c => `<path class="fw-land" d="${c.d}"><title>${E(c.name)}</title></path>`).join('')}</g>`}
        <g id="fwt-arcs"></g>
      </svg>
      <div class="fw-maplegend">
        <span><svg width="26" height="10"><path d="M1 5h24" stroke="${HEX.in}" stroke-width="2"/><path d="${ARROW}" transform="translate(13 5)" fill="${HEX.in}"/></svg>Incoming → us</span>
        <span><svg width="26" height="10"><path d="M1 5h24" stroke="${HEX.out}" stroke-width="2"/><path d="${ARROW}" transform="translate(13 5)" fill="${HEX.out}"/></svg>Outgoing us →</span>
        <span><svg width="26" height="10"><path d="M1 5h24" stroke="${HEX.blk}" stroke-width="2" stroke-dasharray="3 3"/><path d="${ARROW}" transform="translate(13 5)" fill="${HEX.blk}"/></svg>Blocked</span>
        <span style="color:var(--text-3)">line width = volume · arrow = who started it</span>
      </div>
      <div class="fw-zoombar">
        <button type="button" data-zoom="in" title="Zoom in">${icon('plus', 15)}</button>
        <button type="button" data-zoom="out" title="Zoom out">${icon('line-h', 15)}</button>
        <button type="button" data-zoom="reset" title="Whole world"${T.zoom.k > 1 ? '' : ' disabled'}>${icon('globe', 15)}</button>
        <button type="button" data-mapstyle title="Map mode">${icon('layers', 15)}</button>
      </div>
      ${osm ? '<div class="fw-osm-attr">© <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors</div>' : ''}
      <div class="fw-tip" id="fwt-tip"></div>
    </div>`;
  }

  // ── zoom & pan (viewBox; scroll wheel, drag, pinch, buttons) ─────────────
  const zmax = () => isOSM() ? 256 : 16; // street map: down to neighbourhood level
  // OpenStreetMap tiles for the visible area, at the zoom level whose tiles
  // are closest to their native 256 px on screen.
  function drawTiles() {
    const g = document.getElementById('fwt-tiles'), svg = document.getElementById('fwt-map');
    if (!g || !svg) return;
    const rc = svg.getBoundingClientRect(), z0 = T.zoom;
    // The map keeps its proportions inside a height-capped box: the side
    // margins show the map beyond the viewBox too — cover them with tiles.
    const s = Math.min((rc.width || W) / W, (rc.height || H) / H) || 1, px = W * s;
    const vw = (rc.width || W) / s / z0.k, vh = (rc.height || H) / s / z0.k; // visible map units
    const vx = z0.x - (vw - W / z0.k) / 2, vy = z0.y - (vh - H / z0.k) / 2;
    const z = Math.max(0, Math.min(19, Math.round(Math.log2(px * z0.k / 256))));
    const n = 2 ** z, ts = W / n, top = H / 2 - W / 2; // map units per tile; y of the world's top edge
    const x0 = Math.max(0, Math.floor(vx / ts)), x1 = Math.min(n - 1, Math.floor((vx + vw) / ts));
    const y0 = Math.max(0, Math.floor((vy - top) / ts)), y1 = Math.min(n - 1, Math.floor((vy + vh - top) / ts));
    const url = (x, y) => `https://tile.openstreetmap.org/${z}/${x}/${y}.png`;
    let html = '';
    for (let y = y0; y <= y1; y++) for (let x = x0; x <= x1; x++) {
      // a hair of overlap hides the seams between tiles
      html += `<image class="fw-tile" href="${url(x, y)}" x="${(x * ts).toFixed(3)}" y="${(top + y * ts).toFixed(3)}" width="${(ts * 1.004).toFixed(3)}" height="${(ts * 1.004).toFixed(3)}" preserveAspectRatio="none"/>`;
    }
    const key = [html.length, z, x0, y0].join(':');
    if (g.dataset.k !== key) { g.innerHTML = html; g.dataset.k = key; }
  }
  // Arrow drawn at the middle of each arc, pointing from who started the
  // connection (screen pixels; scaled down by the zoom when placed).
  const ARROW = 'M-4.5,-3.6L4,0L-4.5,3.6L-2.6,0Z';
  function viewBox() { const z = T.zoom; return `${z.x.toFixed(2)} ${z.y.toFixed(2)} ${(W / z.k).toFixed(2)} ${(H / z.k).toFixed(2)}`; }
  function zoomTo(k, fx, fy) { // fx, fy: map point that stays put
    const z = T.zoom, nk = Math.max(1, Math.min(zmax(), k));
    z.x = fx - (fx - z.x) * z.k / nk; z.y = fy - (fy - z.y) * z.k / nk; z.k = nk;
    clampView(); applyView();
  }
  function clampView() {
    const z = T.zoom;
    z.x = Math.max(0, Math.min(W - W / z.k, z.x)); z.y = Math.max(0, Math.min(H - H / z.k, z.y));
  }
  let viewRedraw = 0;
  function applyView() {
    const svg = document.getElementById('fwt-map');
    if (!svg) return;
    svg.setAttribute('viewBox', viewBox());
    svg.style.touchAction = T.zoom.k > 1 ? 'none' : 'pan-y';
    const rb = document.querySelector('[data-zoom="reset"]');
    if (rb) rb.disabled = T.zoom.k <= 1;
    // Arc widths, arrows and dots keep their on-screen size: redraw once per frame.
    if (!viewRedraw) viewRedraw = requestAnimationFrame(() => { viewRedraw = 0; drawTiles(); drawArcs(); if (T.sel) select(T.sel); });
  }
  let resizeHooked = false, paneObs = null;
  // The map takes ~37% of the scrolling pane's height (not the window's:
  // the top bar and the activity panel take part of it), so the tables
  // below always peek out. It keeps its proportions inside that box.
  function fitMapHeight() {
    const svg = document.getElementById('fwt-map');
    if (!svg) return;
    let pane = svg.parentElement;
    while (pane && pane !== document.body) {
      const oy = getComputedStyle(pane).overflowY;
      if ((oy === 'auto' || oy === 'scroll') && pane.clientHeight) break;
      pane = pane.parentElement;
    }
    const h = pane && pane !== document.body ? pane.clientHeight : window.innerHeight;
    svg.style.maxHeight = Math.max(180, Math.round(h * 0.375)) + 'px';
    // the activity panel can be dragged taller/shorter: follow the pane's size
    if (pane && pane !== document.body && window.ResizeObserver && (!paneObs || paneObs.pane !== pane)) {
      if (paneObs) paneObs.disconnect();
      paneObs = new ResizeObserver(() => { if (document.getElementById('fwt-map')) { fitMapHeight(); drawTiles(); } });
      paneObs.pane = pane; paneObs.observe(pane);
    }
  }
  function wireZoom(root) {
    const svg = root.querySelector('#fwt-map');
    if (!svg) return;
    fitMapHeight();
    if (!resizeHooked) {
      resizeHooked = true;
      window.addEventListener('resize', () => { if (document.getElementById('fwt-map')) { fitMapHeight(); drawTiles(); } });
    }
    const toMap = (cx, cy) => { // client px → map units
      const r = svg.getBoundingClientRect(), z = T.zoom, s = Math.min(r.width / W, r.height / H);
      const ox = (r.width - W * s) / 2, oy = (r.height - H * s) / 2;
      return [z.x + (cx - r.left - ox) / s / z.k, z.y + (cy - r.top - oy) / s / z.k];
    };
    const centre = () => [T.zoom.x + W / T.zoom.k / 2, T.zoom.y + H / T.zoom.k / 2];
    const ms = root.querySelector('[data-mapstyle]');
    if (ms) ms.onclick = ev => {
      ev.stopPropagation();
      const card = root.querySelector('#fwt-mapcard'), old = card.querySelector('.fw-mapmenu');
      if (old) { old.remove(); return; }
      const modes = [['', 'Simple map', 'Country outlines'], ['osm', 'Street map', 'OpenStreetMap — roads, cities, terrain']];
      const m = document.createElement('div');
      m.className = 'fw-mapmenu';
      m.innerHTML = '<div class="fw-mapmenu-h">Map mode</div>' + modes.map(([v, l, d]) => `<button type="button" data-v="${v}" class="${mapStyle() === v ? 'on' : ''}">
        <span class="fw-mm-chk">${mapStyle() === v ? icon('check', 14) : ''}</span><span><b>${E(l)}</b><small>${E(d)}</small></span></button>`).join('');
      card.appendChild(m);
      m.querySelectorAll('button').forEach(b => b.onclick = e => { e.stopPropagation(); m.remove(); if (b.dataset.v !== mapStyle()) setMapStyle(b.dataset.v); });
      setTimeout(() => document.addEventListener('click', function off() { m.remove(); document.removeEventListener('click', off); }), 0);
    };
    root.querySelectorAll('[data-zoom]').forEach(b => b.onclick = () => {
      const [cx, cy] = centre();
      if (b.dataset.zoom === 'reset') { T.zoom = { k: 1, x: 0, y: 0 }; applyView(); }
      else zoomTo(T.zoom.k * (b.dataset.zoom === 'in' ? 2 : 0.5), cx, cy);
    });
    // Wheel zooms around the pointer; zooming out at full world lets the page scroll.
    svg.addEventListener('wheel', ev => {
      if (ev.deltaY > 0 && T.zoom.k <= 1) return;
      ev.preventDefault();
      const [fx, fy] = toMap(ev.clientX, ev.clientY);
      zoomTo(T.zoom.k * Math.exp(-ev.deltaY * (ev.deltaMode === 1 ? 0.03 : 0.0011)), fx, fy);
    }, { passive: false });
    svg.addEventListener('dblclick', ev => { const [fx, fy] = toMap(ev.clientX, ev.clientY); zoomTo(T.zoom.k * 2, fx, fy); });
    // Drag to pan, two fingers to pinch.
    const ptrs = new Map();
    let last = null, pinch = null;
    svg.addEventListener('pointerdown', ev => {
      if (ev.pointerType === 'touch') return; // fingers: the touch handlers below
      ptrs.set(ev.pointerId, [ev.clientX, ev.clientY]);
      if (ptrs.size === 1) last = [ev.clientX, ev.clientY, 0];
      if (ptrs.size === 2) { const [a, b] = [...ptrs.values()]; pinch = { d: Math.hypot(a[0] - b[0], a[1] - b[1]), k: T.zoom.k }; }
    });
    svg.addEventListener('pointermove', ev => {
      if (!ptrs.has(ev.pointerId)) return;
      ptrs.set(ev.pointerId, [ev.clientX, ev.clientY]);
      if (ptrs.size === 2 && pinch) {
        const [a, b] = [...ptrs.values()];
        const [fx, fy] = toMap((a[0] + b[0]) / 2, (a[1] + b[1]) / 2);
        zoomTo(pinch.k * Math.hypot(a[0] - b[0], a[1] - b[1]) / (pinch.d || 1), fx, fy);
        return;
      }
      if (!last || T.zoom.k <= 1) return;
      const dx = ev.clientX - last[0], dy = ev.clientY - last[1];
      last[2] += Math.abs(dx) + Math.abs(dy);
      if (last[2] < 4) return; // a click, not a drag (yet)
      if (!svg.hasPointerCapture(ev.pointerId)) { svg.setPointerCapture(ev.pointerId); svg.classList.add('fw-panning'); }
      const r = svg.getBoundingClientRect(), s = Math.min(r.width / W, r.height / H) * T.zoom.k;
      T.zoom.x -= dx / s; T.zoom.y -= dy / s; last[0] = ev.clientX; last[1] = ev.clientY;
      clampView(); applyView();
    });
    const end = ev => {
      ptrs.delete(ev.pointerId);
      if (ptrs.size < 2) pinch = null;
      if (!ptrs.size) { svg.dragged = last && last[2] >= 4; last = null; svg.classList.remove('fw-panning'); }
    };
    svg.addEventListener('pointerup', end); svg.addEventListener('pointercancel', end);
    wireTouch(svg, toMap);
  }

  // iPad / phone: two fingers pinch and move the map, one finger pans once
  // zoomed in (at the whole world it scrolls the page), double-tap zooms in,
  // a tap on a line opens its card. Safari's own page zoom stays off the map.
  function wireTouch(svg, toMap) {
    let g = null; // gesture: { mode: 'pinch'|'pan'|'tap', ... }
    let lastTap = null;
    const mid = t => [(t[0].clientX + t[1].clientX) / 2, (t[0].clientY + t[1].clientY) / 2];
    const dist = t => Math.hypot(t[0].clientX - t[1].clientX, t[0].clientY - t[1].clientY) || 1;
    const scale = () => { const r = svg.getBoundingClientRect(); return Math.min(r.width / W, r.height / H) * T.zoom.k; };
    const panBy = (dx, dy) => { const s = scale(); T.zoom.x -= dx / s; T.zoom.y -= dy / s; clampView(); applyView(); };
    ['gesturestart', 'gesturechange', 'gestureend'].forEach(n => svg.addEventListener(n, ev => ev.preventDefault(), { passive: false }));
    svg.addEventListener('touchstart', ev => {
      const t = ev.touches;
      if (t.length >= 2) {
        ev.preventDefault();
        const m = mid(t);
        g = { mode: 'pinch', d: dist(t), k: T.zoom.k, m, f: toMap(m[0], m[1]) };
        hideTip();
      } else if (t.length === 1) {
        g = { mode: 'tap', x: t[0].clientX, y: t[0].clientY, moved: 0, target: ev.target, at: Date.now() };
        if (T.zoom.k > 1) ev.preventDefault(); // zoomed in: the finger moves the map, not the page
      }
    }, { passive: false });
    svg.addEventListener('touchmove', ev => {
      if (!g) return;
      const t = ev.touches;
      if (g.mode === 'pinch' && t.length >= 2) {
        ev.preventDefault();
        const m = mid(t);
        // zoom around the point that was under the fingers, then keep it under them
        zoomTo(g.k * dist(t) / g.d, g.f[0], g.f[1]);
        const now = toMap(m[0], m[1]);
        T.zoom.x += g.f[0] - now[0]; T.zoom.y += g.f[1] - now[1]; clampView(); applyView();
        svg.classList.add('fw-panning');
        return;
      }
      if (t.length !== 1 || g.mode === 'pinch') return;
      const dx = t[0].clientX - g.x, dy = t[0].clientY - g.y;
      g.moved += Math.abs(dx) + Math.abs(dy);
      if (T.zoom.k <= 1) return; // whole world: let the page scroll
      ev.preventDefault();
      if (g.moved < 6 && g.mode === 'tap') return;
      g.mode = 'pan'; svg.classList.add('fw-panning'); hideTip();
      panBy(dx, dy); g.x = t[0].clientX; g.y = t[0].clientY;
    }, { passive: false });
    svg.addEventListener('touchend', ev => {
      if (!g) return;
      if (g.mode === 'pinch') {
        if (ev.touches.length === 1) g = { mode: 'pan', x: ev.touches[0].clientX, y: ev.touches[0].clientY, moved: 99 }; // one finger left: keep panning
        else if (!ev.touches.length) { g = null; svg.classList.remove('fw-panning'); }
        return;
      }
      if (ev.touches.length) return;
      const was = g; g = null; svg.classList.remove('fw-panning');
      if (was.mode !== 'tap' || was.moved >= 10) return;
      ev.preventDefault(); // no emulated mouse events / Safari double-tap zoom
      const now = Date.now();
      if (lastTap && now - lastTap.at < 320 && Math.hypot(was.x - lastTap.x, was.y - lastTap.y) < 30) {
        lastTap = null;
        const [fx, fy] = toMap(was.x, was.y);
        zoomTo(T.zoom.k * 2, fx, fy);
        return;
      }
      lastTap = { at: now, x: was.x, y: was.y };
      const hit = was.target && was.target.closest && was.target.closest('.fw-hit');
      if (hit && typeof hit.fwShowTip === 'function') { hit.fwShowTip(was.x, was.y); if (T.sel !== hit.dataset.k) select(hit.dataset.k); }
      else { hideTip(); if (T.sel) select(T.sel); }
    }, { passive: false });
    svg.addEventListener('touchcancel', () => { g = null; svg.classList.remove('fw-panning'); });
  }
  function hideTip() {
    const tip = document.getElementById('fwt-tip');
    if (tip) tip.style.display = 'none';
    document.querySelectorAll('#fwt-arcs .fw-hover').forEach(a => a.classList.remove('fw-hover'));
  }

  function home() {
    const h = T.status && T.status.home;
    if (h && (h.lat || h.lon)) return { lat: h.lat, lon: h.lon, name: h.city ? 'ZNAS — ' + h.city : 'ZNAS' };
    // No public address on this box: centre of the outgoing traffic's own
    // country is unknown — place it at the most common local country.
    return { lat: 45.5, lon: -73.6, name: 'ZNAS (location unknown)' };
  }

  const coarse = () => !!(window.matchMedia && matchMedia('(pointer: coarse)').matches);
  function drawArcs() {
    const g = document.getElementById('fwt-arcs');
    if (!g) return;
    const k = T.zoom.k, hm = home(), hp = proj(hm.lon, hm.lat);
    const sets = [['blk', T.data.blk], ['out', T.data.out], ['in', T.data.in]].filter(([d]) => T.dir === 'all' || T.dir === d);
    let html = '', hits = '';
    sets.forEach(([dir, res]) => {
      const pts = (res && res.points) || [];
      const max = Math.max(1, ...pts.map(p => dir === 'blk' ? p.pkts : (p.bytes_in || 0) + (p.bytes_out || 0)));
      pts.slice(0, 60).forEach((p, i) => {
        const rp = proj(p.lon, p.lat);
        const [a, b] = dir === 'out' ? [hp, rp] : [rp, hp];
        const dist = Math.hypot(b[0] - a[0], b[1] - a[1]);
        const vol = dir === 'blk' ? p.pkts : (p.bytes_in || 0) + (p.bytes_out || 0);
        const w = 1.1 + (dir === 'blk' ? 3 : 5) * vol / max; // screen px (non-scaling stroke)
        const key = `${dir}:${p.remote || p.cc}:${p.city || ''}`;
        const attrs = `data-k="${E(key)}" data-d="${dir}" data-i="${i}"`;
        html += `<circle cx="${rp[0].toFixed(2)}" cy="${rp[1].toFixed(2)}" r="${(2.6 / k).toFixed(3)}" fill="${HEX[dir]}" opacity=".9"/>`;
        // Too close to draw a readable arc at this zoom (same city/region): the
        // dot alone, hoverable.
        if (dist * k < 18) { hits += `<circle class="fw-hit" ${attrs} cx="${rp[0].toFixed(2)}" cy="${rp[1].toFixed(2)}" r="${((coarse() ? 15 : 8) / k).toFixed(3)}"/>`; return; }
        const c = [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2 - Math.min(140, dist * .35) - 10 / k];
        const d = `M${a[0].toFixed(2)},${a[1].toFixed(2)}Q${c[0].toFixed(2)},${c[1].toFixed(2)} ${b[0].toFixed(2)},${b[1].toFixed(2)}`;
        // midpoint of the curve; its direction there is parallel to a→b
        const m = [(a[0] + 2 * c[0] + b[0]) / 4, (a[1] + 2 * c[1] + b[1]) / 4], ang = Math.atan2(b[1] - a[1], b[0] - a[0]) * 180 / Math.PI;
        const as = (1 + w * 0.14) / k;
        html += `<g class="fw-arcg" ${attrs} style="color:${HEX[dir]}"><path class="fw-arc${dir === 'blk' ? '' : ' fw-flow'}" d="${d}" stroke="${HEX[dir]}" stroke-width="${w.toFixed(2)}" vector-effect="non-scaling-stroke"${dir === 'blk' ? ' stroke-dasharray="2 5"' : ''}/>`
          + `<path class="fw-arrow-m" d="${ARROW}" fill="${HEX[dir]}" transform="translate(${m[0].toFixed(2)} ${m[1].toFixed(2)}) rotate(${ang.toFixed(1)}) scale(${as.toFixed(4)})"/></g>`;
        // wide invisible twin on top: easy to hover and click
        hits += `<path class="fw-hit" ${attrs} d="${d}" vector-effect="non-scaling-stroke"/>`;
      });
    });
    html += `<circle class="fw-home-pulse" cx="${hp[0]}" cy="${hp[1]}" r="${4 / k}" stroke-width="${2 / k}"/><circle cx="${hp[0]}" cy="${hp[1]}" r="${5 / k}" fill="#32d74b" stroke="#0d0d0f" stroke-width="${2 / k}"/><text x="${hp[0] + 9 / k}" y="${hp[1] + 4 / k}" class="fw-home-label" style="font-size:${10 / k}px">${E(hm.name)}</text>`;
    g.innerHTML = html + hits;
    const tip = document.getElementById('fwt-tip'), card = document.getElementById('fwt-mapcard'), svg = document.getElementById('fwt-map');
    const twin = el => g.querySelector(`.fw-arcg[data-k="${CSS.escape(el.dataset.k)}"]`);
    g.querySelectorAll('.fw-hit').forEach(el => {
      const dir = el.dataset.d, p = ((T.data[dir] && T.data[dir].points) || [])[Number(el.dataset.i)];
      el.addEventListener('mouseenter', () => { const t = twin(el); if (t) t.classList.add('fw-hover'); });
      el.addEventListener('mousemove', ev => {
        if (svg.classList.contains('fw-panning')) { tip.style.display = 'none'; return; }
        el.fwShowTip(ev.clientX, ev.clientY);
      });
      el.fwShowTip = (cx, cy) => {
        const bb = card.getBoundingClientRect();
        tip.style.display = 'block';
        const ipRow = p.remote ? `<div class="fw-r">Internet IP<b class="fw-mono">${E(p.remote)}</b></div>` : '';
        const place = [p.city, p.country || p.cc].filter(Boolean).join(', ');
        tip.innerHTML = dir === 'blk'
          ? `<div class="fw-tip-h">${flag(p.cc)} ${E(place || 'Unknown location')} — blocked</div>${ipRow}<div class="fw-r">Attempts<b>${fmtN(p.pkts)}</b></div>${p.remote ? '' : `<div class="fw-r">Unique IPs<b>${fmtN(p.ips)}</b></div>`}<div class="fw-r">Port${(p.ports || []).length > 1 ? 's' : ''}<b>${E((p.ports || []).join(', '))}</b></div>${p.rule ? `<div class="fw-r">Blocked by<b>${E(p.rule)}</b></div>` : ''}`
          : `<div class="fw-tip-h">${flag(p.cc)} ${E(place || 'Unknown location')}</div>${ipRow}${p.remote ? '' : `<div class="fw-r">IPs<b>${fmtN(p.ips)}</b></div>`}<div class="fw-r">Started by<b>${dir === 'in' ? 'remote → us' : 'us → remote'}</b></div>${dir === 'in' ? `<div class="fw-r">Inside host<b>${E(p.name || p.inside || '')} ${E(p.inside ? p.inside + ':' + p.port : '')}</b></div><div class="fw-r">Hit our public<b class="fw-mono">${E((p.pub_ip ? p.pub_ip + ':' : '') + (p.pub_port || ''))}</b></div>` : `<div class="fw-r">Port${(p.ports || []).length > 1 ? 's' : ''}<b>${E(portsLabel(p) || '—')}</b></div><div class="fw-r">Inside hosts<b>${E((p.hosts || []).join(', '))}</b></div><div class="fw-r">Interface<b>${E(ifName(p.iface))}</b></div>`}<div class="fw-r">Data<b>${fmtB((p.bytes_in || 0) + (p.bytes_out || 0))}</b></div><div class="fw-r">Sessions<b>${fmtN(p.sessions)}</b></div>${p.as_org ? `<div class="fw-r">Network<b>${E(p.as_org)}</b></div>` : ''}`;
        // keep the card inside the map
        const x = cx - bb.left + 14, y = cy - bb.top + 14;
        tip.style.left = Math.max(4, Math.min(x, bb.width - tip.offsetWidth - 8)) + 'px';
        tip.style.top = Math.max(4, y + tip.offsetHeight > bb.height - 8 ? y - tip.offsetHeight - 24 : y) + 'px';
        g.querySelectorAll('.fw-hover').forEach(a => a.classList.remove('fw-hover'));
        const t = twin(el); if (t) t.classList.add('fw-hover');
      };
      el.addEventListener('mouseleave', () => { tip.style.display = 'none'; const t = twin(el); if (t) t.classList.remove('fw-hover'); });
      el.addEventListener('click', () => { if (!svg.dragged) select(el.dataset.k); });
    });
  }

  function select(k) {
    T.sel = T.sel === k ? null : k;
    document.querySelectorAll('#fwt-arcs .fw-arcg').forEach(a => { a.classList.toggle('fw-sel', a.dataset.k === T.sel); a.classList.toggle('fw-dim', !!T.sel && a.dataset.k !== T.sel); });
    document.querySelectorAll('tr[data-k]').forEach(t => t.classList.toggle('fw-sel', t.dataset.k === T.sel));
    // chosen on the map: open the page of the table that holds its row
    const row = T.sel && [...document.querySelectorAll('tr[data-k]')].find(t => t.dataset.k === T.sel);
    if (row) {
      const tb = row.closest('table'), rows = pagedRows(tb);
      T.page[pageDir(tb)] = Math.floor(rows.indexOf(row) / PAGE_SIZE);
      paintPage(tb);
    }
  }

  // ── table pages ─────────────────────────────────────────────────────────
  // Every row stays in the table so sorting covers all of them; only the
  // current page's rows show. The pager appears when there is a second page.
  const pageDir = tb => tb.dataset.sort.split('-')[1];
  const pagedRows = tb => [...tb.tBodies[0].rows].filter(r => r.cells.length > 1); // one wide cell: "Nothing here"
  function paintPage(tb) {
    const dir = pageDir(tb), rows = pagedRows(tb), pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
    const pg = T.page[dir] = Math.max(0, Math.min(pages - 1, T.page[dir] || 0));
    rows.forEach((r, i) => { r.style.display = Math.floor(i / PAGE_SIZE) === pg ? '' : 'none'; });
    // a cell cut short by the dense tables shows its whole text on hover
    rows.slice(pg * PAGE_SIZE, (pg + 1) * PAGE_SIZE).forEach(r => [...r.cells].forEach(td => { if (td.scrollWidth > td.clientWidth) td.title = td.textContent.trim(); }));
    const box = tb.closest('.fw-tcard').querySelector('.fw-pager'), total = (T.data[dir] || {}).total || 0;
    box.style.display = pages > 1 ? '' : 'none';
    if (pages < 2) { box.innerHTML = ''; return; }
    box.innerHTML = `<span class="fw-sub">${fmtN(pg * PAGE_SIZE + 1)}–${fmtN(Math.min(rows.length, (pg + 1) * PAGE_SIZE))} of ${fmtN(rows.length)}${total > rows.length ? ` (the biggest ${fmtN(rows.length)} of ${fmtN(total)} lines)` : ''}</span>
      <button type="button" class="fw-icon-btn" data-pg="-1" title="Previous page" aria-label="Previous page"${pg ? '' : ' disabled'}>${icon('chevron-left', 14)}</button>
      <span class="fw-pager-n">Page ${pg + 1} of ${pages}</span>
      <button type="button" class="fw-icon-btn" data-pg="1" title="Next page" aria-label="Next page"${pg < pages - 1 ? '' : ' disabled'}>${icon('chevron-right', 14)}</button>`;
    box.querySelectorAll('[data-pg]').forEach(b => b.onclick = () => { T.page[dir] += Number(b.dataset.pg); paintPage(tb); });
  }
  function wirePages(root) {
    root.querySelectorAll('table.fw-dense').forEach(tb => {
      tb.addEventListener('fw-sorted', () => paintPage(tb));
      tb.tHead.addEventListener('click', ev => { if (ev.target.closest('.fw-sortable')) { T.page[pageDir(tb)] = 0; paintPage(tb); } });
      paintPage(tb);
    });
  }

  const arr = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M5 12h14M13 6l6 6-6 6"/></svg>';
  // Well-known ports → service, to read "443 HTTPS" instead of a bare number.
  const SVC = { 20: 'FTP data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 69: 'TFTP', 80: 'HTTP', 110: 'POP3', 123: 'NTP',
    143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 500: 'IKE', 514: 'Syslog', 587: 'SMTP submit', 636: 'LDAPS',
    853: 'DNS over TLS', 873: 'rsync', 993: 'IMAPS', 995: 'POP3S', 1194: 'OpenVPN', 1883: 'MQTT', 3074: 'Xbox Live', 3306: 'MySQL', 3389: 'RDP',
    3478: 'STUN', 4500: 'IPsec NAT-T', 5060: 'SIP', 5222: 'XMPP', 5223: 'Apple push', 5228: 'Google push', 5353: 'mDNS', 5432: 'PostgreSQL',
    5900: 'VNC', 6881: 'BitTorrent', 8080: 'HTTP alt', 8443: 'HTTPS alt', 8883: 'MQTT TLS', 9418: 'git', 19302: 'Google STUN', 51820: 'WireGuard' };
  const portLabel = p => SVC[p] ? `${p} ${SVC[p]}` : String(p);
  const portsLabel = r => (r.ports || []).map(portLabel).join(', ');

  const hn = (name, ip, cls) => (typeof window.fwHostName === 'function' ? window.fwHostName(name, ip, cls) : E(name || ip || ''));
  const tms = t => (t && !String(t).startsWith('0001') ? new Date(t).getTime() || 0 : 0);
  const locKey = r => [r.country || r.cc, r.city].filter(Boolean).join(' ');
  function rowKey(dir, r) { return `${dir}:${r.remote || r.cc}:${r.city || ''}`; }
  function loc(r) { return `<span class="fw-flag">${flag(r.cc)}</span>${E(r.city ? r.city : (r.country || r.cc || '—'))}`; }
  function bar(v, max, grad) { return `<div class="fw-bytes"><div class="fw-b" style="width:${Math.max(3, 70 * v / Math.max(1, max))}px;background:${grad}"></div>`; }

  function tableIn() {
    const res = T.data.in || {}, rows = res.rows || [];
    const max = Math.max(1, ...rows.map(r => (r.bytes_in || 0) + (r.bytes_out || 0)));
    const byIP = T.group === 'ip';
    return `<div class="fw-tcard"><div class="fw-tch"><span class="fw-dir in">${arr}Incoming</span><h3>Connections coming from the Internet</h3><span class="fw-sub">${E(T.range)} · ${fmtN(res.total)} lines · click a row to find it on the map</span><span style="flex:1"></span><button class="fw-icon-btn" data-csv="in">${icon('download', 12)}CSV</button></div>
      <div class="fw-tscroll"><table class="fw-table fw-dense" data-sort="traffic-in-${byIP ? 'ip' : 'geo'}"><thead><tr><th>${byIP ? 'Remote (initiator)' : 'Where'}</th>${byIP ? '<th>Location</th><th>Network</th><th></th><th>Hit our public</th><th>Forwarded to (inside)</th>' : '<th>IPs</th>'}<th>Sessions</th><th>Data ↓ / ↑</th><th>Last seen</th><th></th></tr></thead><tbody>
      ${rows.length ? rows.map(r => `<tr data-k="${E(rowKey('in', r))}">
        ${byIP ? `<td class="fw-mono">${E(r.remote || '(others)')}</td><td data-v="${E(locKey(r))}">${loc(r)}</td><td>${E(r.as_org || '')}</td><td><span class="fw-dir in">${arr}</span></td><td><span title="${E(r.iface && ifName(r.iface) !== r.iface ? 'Linux interface: ' + r.iface : '')}">${E(ifName(r.iface))}</span><span class="fw-mono">:${E(r.pub_port || '')}</span></td><td><span class="fw-host">${hn(r.name || '', r.inside)}<small>${E(r.inside ? r.inside + ':' + r.port : '')}</small></span></td>`
          : `<td data-v="${E(locKey(r))}">${loc(r)}</td><td data-v="${r.ips || 0}">${fmtN(r.ips)}</td>`}
        <td data-v="${r.sessions || 0}">${fmtN(r.sessions)}</td><td data-v="${(r.bytes_in || 0) + (r.bytes_out || 0)}">${bar((r.bytes_in || 0) + (r.bytes_out || 0), max, 'linear-gradient(90deg,var(--accent-2),var(--fw-in))')}${fmtB(r.bytes_in)} / ${fmtB(r.bytes_out)}</div></td><td data-v="${tms(r.last)}">${ago(r.last)}</td>
        <td>${isAdmin() ? `<span class="fw-act-h">${r.remote ? `<button data-block-ip="${E(r.remote)}">Block IP</button>` : ''}${r.cc ? `<button data-block-cc="${E(r.cc)}">Block ${E(r.country || r.cc)}</button>` : ''}</span>` : ''}</td></tr>`).join('')
        : `<tr><td colspan="10" class="fw-empty">Nothing connected to this server from the Internet in this period.</td></tr>`}
      </tbody></table></div><div class="fw-pager"></div></div>`;
  }

  function tableOut() {
    const res = T.data.out || {}, rows = res.rows || [];
    const max = Math.max(1, ...rows.map(r => (r.bytes_in || 0) + (r.bytes_out || 0)));
    const byIP = T.group === 'ip';
    return `<div class="fw-tcard"><div class="fw-tch"><span class="fw-dir out">${arr}Outgoing</span><h3>Connections we opened to the Internet</h3><span class="fw-sub">${E(T.range)} · ${fmtN(res.total)} lines</span><span style="flex:1"></span><button class="fw-icon-btn" data-csv="out">${icon('download', 12)}CSV</button></div>
      <div class="fw-tscroll"><table class="fw-table fw-dense" data-sort="traffic-out-${byIP ? 'ip' : 'geo'}"><thead><tr><th>${byIP ? 'Remote' : 'Where'}</th>${byIP ? '<th>Location</th><th>Network</th><th>Port / service</th><th>Top inside hosts</th><th>Interface</th>' : '<th>IPs</th><th>Top ports</th>'}<th>Sessions</th><th>Data ↑ / ↓</th><th>Last seen</th><th></th></tr></thead><tbody>
      ${rows.length ? rows.map(r => `<tr data-k="${E(rowKey('out', r))}">
        ${byIP ? `<td class="fw-mono">${E(r.remote || '(others)')}</td><td data-v="${E(locKey(r))}">${loc(r)}</td><td>${E(r.as_org || '')}</td><td>${E(portsLabel(r))}</td><td class="fw-hosts">${(r.hosts || []).map((h, i) => hn(h, (r.host_ips || [])[i])).join(', ')}</td><td title="${E(r.iface && ifName(r.iface) !== r.iface ? 'Linux interface: ' + r.iface : '')}">${E(ifName(r.iface))}</td>` : `<td data-v="${E(locKey(r))}">${loc(r)}</td><td data-v="${r.ips || 0}">${fmtN(r.ips)}</td><td>${E(portsLabel(r))}</td>`}
        <td data-v="${r.sessions || 0}">${fmtN(r.sessions)}</td><td data-v="${(r.bytes_in || 0) + (r.bytes_out || 0)}">${bar((r.bytes_in || 0) + (r.bytes_out || 0), max, 'linear-gradient(90deg,#8e44ad,var(--fw-out))')}${fmtB(r.bytes_out)} / ${fmtB(r.bytes_in)}</div></td><td data-v="${tms(r.last)}">${ago(r.last)}</td>
        <td>${isAdmin() && r.remote ? `<span class="fw-act-h"><button data-block-ip="${E(r.remote)}" data-out="1">Block</button></span>` : ''}</td></tr>`).join('')
        : `<tr><td colspan="10" class="fw-empty">No outgoing connections in this period.</td></tr>`}
      </tbody></table></div><div class="fw-pager"></div></div>`;
  }

  function tableBlk() {
    const res = T.data.blk || {}, rows = res.rows || [], byIP = T.group === 'ip';
    return `<div class="fw-tcard"><div class="fw-tch"><span class="fw-dir blk"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>Blocked</span><h3>Blocked attempts</h3><span class="fw-sub">${byIP ? 'by IP' : 'by country'} · ${E(T.range)}</span><span style="flex:1"></span><button class="fw-icon-btn" data-csv="blk">${icon('download', 12)}CSV</button></div>
      <div class="fw-tscroll"><table class="fw-table fw-dense" data-sort="traffic-blk-${byIP ? 'ip' : 'geo'}"><thead><tr>${byIP ? '<th>Remote</th><th>Location</th>' : '<th>Country</th>'}<th>Attempts</th>${byIP ? '' : '<th>Unique IPs</th>'}<th>Top targeted ports</th><th>Blocked by</th><th>Last seen</th><th data-nosort>Trend</th>${byIP ? '<th></th>' : ''}</tr></thead><tbody>
      ${rows.length ? rows.map(r => {
        const m = Math.max(1, ...(r.trend || [0]));
        const pts = (r.trend || []).map((v, j) => `${j * 3.4},${(20 - 18 * v / m).toFixed(1)}`).join(' ');
        const where = r.cc ? `<span class="fw-flag">${flag(r.cc)}</span>${E(r.country || r.cc)}` : '<span title="Blocked traffic from private addresses (between your own networks)">Your own networks</span>';
        return `<tr data-k="${E(rowKey('blk', r))}">${byIP ? `<td class="fw-mono">${E(r.remote || '(others)')}</td><td data-v="${E(locKey(r))}">${r.cc ? loc(r) : where}</td>` : `<td data-v="${E(locKey(r))}">${where}</td>`}<td data-v="${r.pkts || 0}">${fmtN(r.pkts)}</td>${byIP ? '' : `<td data-v="${r.ips || 0}">${fmtN(r.ips)}</td>`}<td class="fw-mono">${E((r.ports || []).join(', '))}</td><td>${E(r.rule || '')}</td><td data-v="${tms(r.last)}">${ago(r.last)}</td><td><svg width="80" height="22"><polyline points="${pts}" fill="none" stroke="#ff453a" stroke-width="1.5"/></svg></td>${byIP ? `<td>${isAdmin() && r.remote ? `<span class="fw-act-h"><button data-block-ip="${E(r.remote)}">Block IP</button></span>` : ''}</td>` : ''}</tr>`;
      }).join('') : `<tr><td colspan="8" class="fw-empty">Nothing was blocked in this period${(window._sdnMode === 'router') ? '' : ' (blocking happens in Router mode)'}.</td></tr>`}
      </tbody></table></div><div class="fw-pager"></div></div>`;
  }

  function tablesHTML() {
    return `${T.dir === 'all' || T.dir === 'in' ? tableIn() : ''}
      ${T.dir === 'all' || T.dir === 'out' ? tableOut() : ''}
      ${T.dir === 'all' || T.dir === 'blk' ? tableBlk() : ''}`;
  }

  function trafficHTML() {
    if (!T.data.in) return '<div class="fw-empty">Loading traffic…</div>';
    const att = (T.status && T.status.attribution) || '';
    return `${banners()}<div id="fwt-kpi" class="fw-contents">${kpi()}</div>
      <div class="fw-ttb">
        ${seg('dir', [['all', 'All'], ['in', 'Incoming', 'var(--fw-in)'], ['out', 'Outgoing', 'var(--fw-out)'], ['blk', 'Blocked', 'var(--fw-blk)']], T.dir)}
        ${seg('range', [['1h', '1h'], ['24h', '24h'], ['7d', '7d'], ['30d', '30d'], ['1y', '1y'], ['5y', '5y']], T.range)}
        ${seg('group', [['ip', 'By IP'], ['country', 'By country'], ['city', 'By city']], T.group)}
        <input class="fw-search" id="fwt-q" placeholder="Filter: IP, country, city, network, inside host, port…" value="${E(T.q)}">
        ${isAdmin() ? `<div class="fw-dd" id="fwt-geo-dd"><button class="fw-btn" id="fwt-geo-more" title="Location database">${icon('more-vertical', 14)}</button></div>` : ''}
      </div>
      ${mapHTML()}
      <div id="fwt-tables" class="fw-contents">${tablesHTML()}</div>
      <div class="fw-note">${E(att)} · data tier: ${E((T.data.in && T.data.in.tier) || '')}</div>`;
  }

  function csv(dir) {
    const rows = ((T.data[dir] || {}).rows) || [];
    const cols = ['remote', 'cc', 'country', 'city', 'as_org', 'inside', 'name', 'port', 'pub_port', 'ports', 'iface', 'rule', 'sessions', 'bytes_in', 'bytes_out', 'pkts', 'first', 'last'];
    const val = (r, c) => c === 'ports' ? (r.ports || []).join(' ') : (c === 'port' && r.ports && r.ports.length ? '' : r[c]); // out/blk: the list, not one arbitrary port
    const body = [cols.join(',')].concat(rows.map(r => cols.map(c => `"${String(val(r, c) == null ? '' : val(r, c)).replace(/"/g, '""')}"`).join(','))).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([body], { type: 'text/csv' }));
    a.download = `znas-traffic-${dir}-${T.range}.csv`; document.body.appendChild(a); a.click(); a.remove();
  }

  async function quickBlock(kind, value, outgoing) {
    const d = (await api('/api/sdn/draft')).data;
    if (!d) return;
    const c = d.config;
    const wan = (c.interfaces || []).find(i => i.role === 'wan');
    const r = { id: Array.from(crypto.getRandomValues(new Uint8Array(4))).map(b => b.toString(16).padStart(2, '0')).join(''), enabled: true,
      interface: outgoing ? '' : (wan ? wan.id : ''), action: 'block', protocol: 'any',
      source: outgoing ? { type: 'any' } : (kind === 'ip' ? { type: 'cidr', value } : { type: 'countries', value }),
      destination: outgoing ? { type: 'cidr', value } : { type: 'any' }, log: false,
      description: kind === 'ip' ? (outgoing ? 'Block going out to ' : 'Block ') + value : 'Block ' + value + ' (from the Traffic page)' };
    c.rules = [r].concat(c.rules || []);
    const res = await api('/api/sdn/draft', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ base_revision: d.revision, config: c }) });
    if (!res.ok) { toast((res.data && res.data.error) || 'Could not add the rule', 'error'); return; }
    toast('Rule added to the draft' + (wan || outgoing ? '' : ' (Any interface — no WAN interface yet)') + ' — review it in Rules, then Apply', 'success');
    if (typeof window.sdnReloadTopbar === 'function') window.sdnReloadTopbar();
  }

  async function choosePool(root) {
    const r = await api('/api/pools');
    const pools = (r.ok && Array.isArray(r.data) ? r.data : []).map(p => p.name).filter(Boolean);
    if (!pools.length) { toast('No ZFS pool on this server yet', 'error'); return; }
    const box = document.createElement('div');
    box.innerHTML = `<p style="margin-top:0">Traffic statistics and the location database go to a dataset <code>znas-netstats</code> on the pool you choose (about 1–2 GB for 5 years).</p><div class="fw-seg" id="fwp-seg">${pools.map((p, i) => `<button type="button" data-v="${E(p)}" class="${i ? '' : 'on'}">${E(p)}</button>`).join('')}</div><div class="fw-err" id="fwp-err" style="margin-top:8px"></div>`;
    let pick = pools[0];
    box.querySelectorAll('#fwp-seg button').forEach(b => b.onclick = () => { pick = b.dataset.v; box.querySelectorAll('#fwp-seg button').forEach(x => x.classList.toggle('on', x === b)); });
    window.sdnModal({ title: 'Keep the statistics on a pool', body: box, buttons: [{ label: 'Cancel' }, { label: 'Use this pool', cls: 'btn-primary', onClick: async (close, btn) => {
      btn.disabled = true;
      const res = await api('/api/sdn/traffic/location', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pool: pick }) });
      btn.disabled = false;
      if (!res.ok) { box.querySelector('#fwp-err').textContent = (res.data && res.data.error) || 'Failed'; return; }
      close(); toast('Statistics now kept on ' + pick, 'success');
      setTimeout(() => refresh(true), 1500);
    } }] });
  }

  // What the tables need after being drawn.
  function wireTables(root) {
    wirePages(root);
    root.querySelectorAll('tr[data-k]').forEach(tr => tr.onclick = ev => { if (ev.target.closest('button')) return; select(tr.dataset.k); });
    root.querySelectorAll('[data-csv]').forEach(b => b.onclick = () => csv(b.dataset.csv));
    root.querySelectorAll('[data-block-ip]').forEach(b => b.onclick = ev => { ev.stopPropagation(); quickBlock('ip', b.dataset.blockIp, !!b.dataset.out); });
    root.querySelectorAll('[data-block-cc]').forEach(b => b.onclick = ev => { ev.stopPropagation(); quickBlock('cc', b.dataset.blockCc, false); });
  }

  // A new filter redraws the results only: rebuilding the page would replace
  // the box being typed in, and take the keyboard away with it.
  const filterFocused = () => !!document.activeElement && document.activeElement.id === 'fwt-q';
  let filterRun = 0;
  async function applyFilter(q) {
    const run = ++filterRun;
    T.q = q; T.page = { in: 0, out: 0, blk: 0 };
    await loadTraffic();
    const tables = document.getElementById('fwt-tables'), kpis = document.getElementById('fwt-kpi');
    if (run !== filterRun || !tables) return; // typed on: a newer answer is coming
    kpis.innerHTML = kpi();
    tables.innerHTML = tablesHTML();
    wireTables(tables);
    window.sdnFW.sortTables(tables);
    drawArcs();
  }

  function wireTraffic(root) {
    wireTables(root);
    root.querySelectorAll('[data-tseg]').forEach(s => s.querySelectorAll('button').forEach(b => b.onclick = () => {
      T[s.dataset.tseg] = b.dataset.v;
      if (s.dataset.tseg !== 'dir') T.page = { in: 0, out: 0, blk: 0 };
      refresh(s.dataset.tseg !== 'dir');
    }));
    const q = root.querySelector('#fwt-q');
    if (q) { let t; q.oninput = () => { clearTimeout(t); t = setTimeout(() => applyFilter(q.value), 350); }; }
    const pool = root.querySelector('#fwt-pool');
    if (pool) pool.onclick = () => choosePool(root);
    const geo = root.querySelector('#fwt-geo');
    if (geo) geo.onclick = async () => {
      geo.disabled = true; geo.textContent = 'Downloading… (≈150 MB)';
      const r = await api('/api/sdn/geodb/update', { method: 'POST' });
      toast(r.ok ? 'Location database installed' : ((r.data && r.data.error) || 'Download failed'), r.ok ? 'success' : 'error');
      refresh(true);
    };
    wireGeoMenu(root);
    wireZoom(root);
    drawTiles();
    drawArcs();
    if (T.sel) select(T.sel);
  }

  // ── location database choice (⋮ at the end of the filter row) ──────────
  const geoMenuOpen = () => !!document.querySelector('#fwt-geo-dd .fw-menu');
  const jsonPut = (url, body, method) => api(url, { method: method || 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  function wireGeoMenu(root) {
    const btn = root.querySelector('#fwt-geo-more');
    if (!btn) return;
    btn.onclick = async e => {
      e.stopPropagation();
      const dd = btn.closest('.fw-dd');
      if (dd.querySelector('.fw-menu')) { dd.querySelector('.fw-menu').remove(); return; }
      const r = await api('/api/sdn/geodb/provider');
      if (!r.ok) { toast((r.data && r.data.error) || 'Not available', 'error'); return; }
      const g = r.data, mm = g.provider === 'maxmind';
      const f = (g.files || []).find(x => x.present);
      const chk = on => `<span style="width:16px;display:inline-flex;justify-content:center;color:var(--accent-3)">${on ? icon('check', 14) : ''}</span>`;
      const src = g.in_use === 'maxmind' ? 'MaxMind GeoLite2' : 'DB-IP Lite';
      let info = g.job && g.job.running ? `Downloading ${mm ? 'MaxMind GeoLite2' : 'DB-IP Lite'}…`
        : `In use: ${src}${f && f.updated ? ' · updated ' + ago(f.updated) : ' · not downloaded yet'}`;
      if (mm && g.in_use !== 'maxmind' && !(g.job && g.job.running)) info = 'MaxMind GeoLite2 not downloaded yet: DB-IP Lite answers meanwhile';
      const m = document.createElement('div');
      m.className = 'fw-menu';
      m.style.minWidth = '330px'; m.style.whiteSpace = 'nowrap';
      m.innerHTML = `<div class="fw-menu-item" data-m="dbip">${chk(!mm)}Use Free DB-IP Lite Country Database</div>
        <div class="fw-menu-item" data-m="maxmind" title="${g.configured ? 'Change the MaxMind account or license key' : 'Use your MaxMind license key for the GeoLite2 databases'}">${chk(mm)}MaxMind GeoLite2${g.configured && !mm ? ' <span style="color:var(--text-3);font-size:11.5px">(configured)</span>' : ''}…</div>
        <div class="fw-menu-sep"></div>
        <div style="padding:4px 10px 6px 35px;font-size:11.5px;color:${g.job && g.job.error ? 'var(--fw-blk)' : 'var(--text-3)'};white-space:normal;max-width:330px">${E(g.job && g.job.error ? 'Last download failed: ' + g.job.error : info)}</div>`;
      dd.appendChild(m);
      m.onclick = ev => ev.stopPropagation();
      const close = () => { m.remove(); document.removeEventListener('click', close); };
      m.querySelectorAll('[data-m]').forEach(it => it.onclick = async () => {
        close();
        if (it.dataset.m === 'maxmind') { maxmindDialog(g); return; }
        if (!mm) return;
        const res = await jsonPut('/api/sdn/geodb/provider', { provider: 'dbip' });
        if (!res.ok) { toast((res.data && res.data.error) || 'Not saved', 'error'); return; }
        toast('Now using the free DB-IP Lite databases', 'success');
        watchGeoJob();
      });
      setTimeout(() => document.addEventListener('click', close), 0);
    };
  }

  function maxmindDialog(g) {
    const box = document.createElement('div');
    box.innerHTML = `<p style="margin-top:0">GeoLite2 is MaxMind's free database, updated twice a week. It needs a free MaxMind account: <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank" rel="noopener noreferrer">sign up</a>, then create a license key under <a href="https://www.maxmind.com/en/accounts/current/license-key" target="_blank" rel="noopener noreferrer">Manage license keys</a>.</p>
      <div class="fw-field" style="margin-top:12px"><label>Account ID</label><input type="text" id="fwm-acc" autocomplete="off" inputmode="numeric" value="${E(g.account_id || '')}" placeholder="e.g. 1234567"></div>
      <div class="fw-field" style="margin-top:12px"><label>License key</label><input type="password" id="fwm-key" autocomplete="new-password" placeholder="${g.key_set ? 'Saved: leave empty to keep it' : 'The 40-character key MaxMind shows once'}"></div>
      <div id="fwm-res" style="min-height:18px;font-size:12.5px;margin-top:4px"></div>
      <p style="color:var(--text-3);font-size:12px;margin-bottom:0">About 70 MB is downloaded to the statistics pool. DB-IP Lite keeps answering until GeoLite2 is in place.</p>`;
    const res = box.querySelector('#fwm-res');
    const body = () => ({ provider: 'maxmind', account_id: box.querySelector('#fwm-acc').value.trim(), license_key: box.querySelector('#fwm-key').value.trim() });
    const show = (ok, msg) => { res.style.color = ok ? 'var(--accent-3)' : 'var(--fw-blk)'; res.textContent = msg; };
    const missing = b => !b.account_id ? 'Enter the account ID' : (!b.license_key && !g.key_set ? 'Enter the license key' : '');
    window.sdnModal({ title: 'MaxMind GeoLite2', body: box, buttons: [
      { label: 'Cancel' },
      { label: 'Test', onClick: async (close, b) => {
        const v = body(), miss = missing(v);
        if (miss) { show(false, miss); return; }
        b.disabled = true; show(true, 'Asking MaxMind…'); res.style.color = 'var(--text-3)';
        const r = await jsonPut('/api/sdn/geodb/maxmind/test', v, 'POST');
        b.disabled = false;
        show(r.ok, r.ok ? '✓ MaxMind accepted this account ID and license key' : ((r.data && r.data.error) || 'Test failed'));
      } },
      { label: 'Save', cls: 'btn-primary', onClick: async (close, b) => {
        const v = body(), miss = missing(v);
        if (miss) { show(false, miss); return; }
        b.disabled = true; res.style.color = 'var(--text-3)'; res.textContent = 'Checking with MaxMind…';
        const r = await jsonPut('/api/sdn/geodb/provider', v);
        b.disabled = false;
        if (!r.ok) { show(false, (r.data && r.data.error) || 'Not saved'); return; }
        close();
        toast(r.data && r.data.in_use === 'maxmind' ? 'Now using MaxMind GeoLite2' : 'MaxMind GeoLite2 saved: downloading the databases', 'success');
        watchGeoJob();
      } }] });
    setTimeout(() => box.querySelector(g.account_id ? '#fwm-key' : '#fwm-acc').focus(), 50);
  }

  // Follows the background download, then reloads the page's locations.
  let geoWatch = null;
  function watchGeoJob() {
    clearInterval(geoWatch);
    let n = 0;
    geoWatch = setInterval(async () => {
      const r = await api('/api/sdn/geodb/provider');
      if (++n > 120 || (r.ok && r.data && !(r.data.job && r.data.job.running))) {
        clearInterval(geoWatch);
        const g = r.data || {}, err = g.job && g.job.error;
        if (err) toast('Location database: ' + err, 'error');
        else if (g.provider === 'maxmind' && g.in_use === 'maxmind') toast('MaxMind GeoLite2 is in use', 'success');
        refresh(true);
      }
    }, 3000);
  }

  let rerender = null;
  // A theme change recolours the map lines at once, not at the next poll.
  let wasLight = null;
  new MutationObserver(() => {
    const l = lightTheme();
    if (l === wasLight) return;
    wasLight = l;
    if (rerender && document.getElementById('fwt-map') && !geoMenuOpen() && !filterFocused()) rerender();
  }).observe(document.body, { attributes: true, attributeFilter: ['class'] });
  async function refresh(reload) {
    if (reload) await loadTraffic();
    if (rerender) rerender();
  }

  // ── Live connections ─────────────────────────────────────────────────────
  const L = { list: null, q: '', qf: '' }; // qf: quick filter ('' | from-inet | to-inet | from:<iface id> | to:<iface id>)
  async function loadLive() { const r = await api('/api/sdn/connections?limit=500'); L.list = r.ok ? (r.data || []) : []; liveNames(); }
  // DNS names of the addresses shown (internal and external), fetched in the
  // background — 16 per request, 4 requests at a time — and kept for the page.
  const LN = {}; // ip → fqdn ('' = none) | null while asked
  let lnBusy = false;
  async function liveNames() {
    if (lnBusy) return;
    const want = [...new Set((L.list || []).flatMap(c => [c.src, c.dst, c.inside]).filter(ip => ip && !(ip in LN)))].slice(0, 400);
    if (!want.length) return;
    lnBusy = true;
    want.forEach(ip => { LN[ip] = null; });
    const chunks = [];
    for (let i = 0; i < want.length; i += 16) chunks.push(want.slice(i, i + 16));
    let found = false;
    const worker = async () => {
      for (let ch = chunks.shift(); ch; ch = chunks.shift()) {
        const r = await api('/api/sdn/ids/names?' + ch.map(ip => 'ip=' + encodeURIComponent(ip)).join('&'));
        ch.forEach(ip => { const f = (r.ok && r.data && r.data[ip] && r.data[ip].fqdn) || ''; LN[ip] = f; if (f) found = true; });
      }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
    lnBusy = false;
    // show them now unless the user is typing in the search box or a menu is open
    const busy = (document.activeElement && document.activeElement.id === 'fwl-q') || document.querySelector('#fwl-quick .fw-picker-pop');
    if (found && rerenderLive && document.getElementById('fwl-q') && !busy) rerenderLive();
  }
  const fq = ip => (ip && LN[ip]) ? `<small class="fw-fqdn" title="${E(LN[ip])}">${hn(LN[ip], ip)}</small>` : '';
  // Quick filters: direction to/from the Internet, or to/from one of our
  // inside networks (every non-WAN interface with its own address).
  const ip2n = a => (a || '').split('.').reduce((n, o) => n * 256 + (Number(o) || 0), 0);
  const inNet = (ip, cidr) => {
    const [base, bits] = cidr.split('/'), b = Number(bits);
    if (!ip || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return false;
    const size = 2 ** (32 - b);
    return Math.floor(ip2n(ip) / size) === Math.floor(ip2n(base) / size);
  };
  const netOf = cidr => { // 10.97.9.1/24 → 10.97.9.0/24
    const [base, bits] = cidr.split('/'), size = 2 ** (32 - Number(bits)), n = Math.floor(ip2n(base) / size) * size;
    return [24, 16, 8, 0].map(sh => Math.floor(n / 2 ** sh) % 256).join('.') + '/' + bits;
  };
  function insideNets() {
    const F = window.sdnFW, c = F && F.cfg && F.cfg();
    return ((c && c.interfaces) || []).filter(i => i.role !== 'wan' && i.ipv4_mode === 'static' && i.ipv4)
      .map(i => ({ id: i.id, name: i.name, color: i.color, cidr: netOf(i.ipv4) }));
  }
  function quickOptions() {
    const o = [{ value: '', label: 'All connections', section: 'Show' },
      { value: 'from-inet', label: 'From Internet', section: 'Internet', hint: 'started outside' },
      { value: 'to-inet', label: 'To Internet', section: 'Internet', hint: 'started inside' }];
    insideNets().forEach(n => {
      o.push({ value: 'from:' + n.id, label: 'From ' + n.name, section: 'Networks', color: n.color, hint: n.cidr });
      o.push({ value: 'to:' + n.id, label: 'To ' + n.name, section: 'Networks', color: n.color, hint: n.cidr });
    });
    return o;
  }
  function quickMatch(c) {
    const f = L.qf;
    if (!f) return true;
    if (f === 'from-inet') return c.initiator === 'remote';
    if (f === 'to-inet') return c.initiator === 'inside';
    const [side, id] = f.split(':'), n = insideNets().find(x => x.id === id);
    if (!n) return true; // its interface is gone: show everything
    // a forwarded incoming connection is addressed to our public IP: its inside host counts as the target
    return side === 'from' ? inNet(c.src, n.cidr) : (inNet(c.dst, n.cidr) || (c.initiator === 'remote' && inNet(c.inside, n.cidr)));
  }

  function liveHTML() {
    if (!L.list) return '<div class="fw-empty">Loading connections…</div>';
    const q = L.q.toLowerCase();
    const rows = L.list.filter(c => quickMatch(c) && (!q || (JSON.stringify(c) + ' ' + [c.src, c.dst, c.inside].map(ip => LN[ip] || '').join(' ')).toLowerCase().includes(q)));
    const ini = c => c.initiator === 'remote' ? `<span class="fw-dir in" title="Started by the remote side">${arr}in</span>` : (c.initiator === 'inside' ? `<span class="fw-dir out" title="Started from inside">${arr}out</span>` : '<span class="fw-dir" style="background:var(--surface2);color:var(--text-3)" title="Between your own networks">internal</span>');
    return `<div class="fw-ttb"><div id="fwl-quick" class="fw-quick"></div><input class="fw-search fw-search-sm" id="fwl-q" placeholder="Filter: IP, country, host, port…" value="${E(L.q)}"><span class="fw-sub" style="color:var(--text-3);font-size:12px">${fmtN(rows.length)} of ${fmtN(L.list.length)} · refreshes every 5 s</span></div>
      <div class="fw-tcard"><div class="fw-tscroll"><table class="fw-table" data-sort="live"><thead><tr><th></th><th>Proto</th><th>From</th><th>To</th><th>Location</th><th>Inside host</th><th>Data</th>${isAdmin() ? '<th></th>' : ''}</tr></thead><tbody>
      ${rows.map(c => `<tr><td>${ini(c)}</td><td>${E(c.proto || '')}</td><td class="fw-mono">${E(c.src)}${c.sport ? ':' + c.sport : ''}${fq(c.src)}</td><td class="fw-mono">${E(c.dst)}${c.dport ? ':' + c.dport : ''}${fq(c.dst)}</td>
        <td data-v="${E([c.country, c.city].filter(Boolean).join(' '))}">${c.cc ? `<span class="fw-flag">${flag(c.cc)}</span>${E(c.city || c.country || '')}` : ''}${c.as_org ? `<div style="color:var(--text-3);font-size:11px">${E(c.as_org)}</div>` : ''}</td>
        <td>${hn(c.name || '', c.inside)}${c.inside && c.inside !== c.src && c.inside !== c.dst ? fq(c.inside) : ''}</td><td data-v="${(c.bytes_in || 0) + (c.bytes_out || 0)}">${fmtB((c.bytes_in || 0) + (c.bytes_out || 0))}</td>
        ${isAdmin() ? `<td><span class="fw-act-h"><button data-kill='${E(JSON.stringify({ proto: c.proto, src: c.src, dst: c.dst, sport: c.sport, dport: c.dport }))}' title="Drop this connection from the tracking table">Kill</button></span></td>` : ''}</tr>`).join('') || '<tr><td colspan="8" class="fw-empty">No connection.</td></tr>'}
      </tbody></table></div></div>`;
  }
  function wireLive(root) {
    const qb = root.querySelector('#fwl-quick'), F = window.sdnFW;
    if (qb && F && F.picker) {
      F.picker(qb, quickOptions(), L.qf, v => { L.qf = v; if (rerenderLive) rerenderLive(); }, { width: 300 });
      const btn = qb.querySelector('.fw-picker-btn');
      if (btn) btn.insertAdjacentHTML('afterbegin', icon('filter', 13)), btn.classList.toggle('fw-quick-on', !!L.qf);
    }
    const q = root.querySelector('#fwl-q');
    if (q) { q.oninput = () => { L.q = q.value; const pos = q.selectionStart; if (rerenderLive) rerenderLive(); const n = document.getElementById('fwl-q'); if (n) { n.focus(); n.setSelectionRange(pos, pos); } }; }
    root.querySelectorAll('[data-kill]').forEach(b => b.onclick = async () => {
      const r = await api('/api/sdn/connections/kill', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: b.dataset.kill });
      toast(r.ok ? 'Connection dropped' : ((r.data && r.data.error) || 'Failed'), r.ok ? 'success' : 'error');
      await loadLive(); if (rerenderLive) rerenderLive();
    });
  }
  let rerenderLive = null;

  function register() {
    if (typeof window.sdnRegisterPage !== 'function') { setTimeout(register, 200); return; }
    window.sdnRegisterPage('fw-traffic', {
      load: async rr => { rerender = rr; await loadTraffic(); },
      render: trafficHTML, wire: wireTraffic, busy: () => filterFocused() || geoMenuOpen(), pollMs: 60000, poll: async () => { if (filterFocused()) return false; await loadTraffic(); },
    });
    window.sdnRegisterPage('fw-live', {
      load: async rr => { rerenderLive = rr; await loadLive(); },
      render: liveHTML, wire: wireLive, pollMs: 5000, poll: async () => {
        if (document.querySelector('#fwl-quick .fw-picker-pop')) return false; // quick-filter menu open: don't redraw under it
        if (!document.activeElement || document.activeElement.id !== 'fwl-q') await loadLive();
      },
    });
  }
  register();
})();
