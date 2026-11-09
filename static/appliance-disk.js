// USB appliance: "Where ZNAS runs" card + "Move to an internal disk" wizard
// (PLANS/plan-appliance-internal-disk.md). Web page only: the erase needs the
// typed disk name and the admin password again; the server refuses it through
// InterLink.
(function () {
  'use strict';
  const E = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const GB = n => n >= 1e12 ? (n / 1e12).toFixed(1) + ' TB' : Math.round(n / 1e9) + ' GB';
  const STEPS = [
    ['preflight', 'Checks'], ['image', 'Image source'], ['nvme-format', 'NVMe sector format'], ['wipe', 'Erase the disk'],
    ['write-image', 'Write the image'], ['partitions', 'Partitions'], ['boot-entry', 'Boot entry'], ['pool', 'Create the pool'],
    ['settings', 'Copy the settings'], ['retire-stick', 'Retire the stick’s settings'], ['restart', 'Restart services']];
  let where = null, poll = null, wiz = null;

  async function getJSON(url, opts) {
    const r = await fetch(url, Object.assign({ headers: { Accept: 'application/json', 'Content-Type': 'application/json' } }, opts || {}));
    let d = {};
    try { d = await r.json(); } catch (e) { /* portal restarting */ }
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    return d;
  }

  function card() { return document.getElementById('appliance-where-card'); }

  function mediumLine(m) {
    if (!m || !m.kind) return '';
    const parts = [m.kind === 'disk' ? 'Internal disk' : 'USB stick', m.disk, m.model, m.size_bytes ? GB(m.size_bytes) : ''];
    if (m.kind === 'disk' && m.pool_name) parts.push('pool ' + m.pool_name);
    return parts.filter(Boolean).map(E).join(' · ');
  }

  function stepsHTML(st) {
    const reached = st.steps || [];
    const last = reached[reached.length - 1];
    return STEPS.filter(([k]) => reached.includes(k) || !['nvme-format', 'pool'].includes(k)).map(([k, label]) => {
      const done = reached.includes(k) && (k !== last || st.phase === 'done');
      const cur = k === last && st.phase === 'running';
      const bad = k === last && st.phase === 'failed';
      const dot = bad ? '#ff453a' : done ? 'var(--accent-3,#30d158)' : cur ? 'var(--accent-1)' : 'var(--surface2)';
      return `<div style="display:flex;align-items:center;gap:8px;font-size:13px;color:${done || cur || bad ? 'var(--text-1)' : 'var(--text-3)'};">
        <span style="width:9px;height:9px;border-radius:50%;background:${dot};flex:none;${cur ? 'box-shadow:0 0 0 3px rgba(10,132,255,.25);' : ''}"></span>${E(label)}</div>`;
    }).join('');
  }

  function render() {
    const c = card();
    if (!c || !where || !where.appliance) return;
    const m = where.medium || {}, st = where.install || { phase: 'idle' };
    let body = '';
    if (st.phase === 'running' || st.phase === 'done' || st.phase === 'failed') {
      const head = st.phase === 'running' ? 'Moving ZNAS to ' + E(st.disk || 'the internal disk') + '…'
        : st.phase === 'done' ? 'ZNAS is on ' + E(st.disk) + '. Remove the USB stick, then restart.'
          : 'The move failed: ' + E(st.error || 'unknown error');
      body += `<div class="alert ${st.phase === 'failed' ? 'alert-error' : st.phase === 'done' ? 'alert-success' : 'alert-info'}" style="margin-bottom:12px;">${head}</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:6px 14px;margin-bottom:12px;">${stepsHTML(st)}</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          ${st.phase === 'done' ? '<button class="btn btn-primary btn-sm" id="awd-reboot">Restart now</button>' : ''}
          ${st.phase === 'failed' && m.kind === 'stick' ? '<button class="btn btn-ghost btn-sm" id="awd-open">Try again…</button>' : ''}
          <button class="btn btn-ghost btn-sm" id="awd-log-t">Show the log</button></div>
        <pre id="awd-log" style="display:none;margin-top:10px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 12px;font-size:12px;max-height:240px;overflow:auto;white-space:pre-wrap;">${E((st.log || []).join('\n'))}</pre>`;
      if (st.phase === 'done') body += '<div style="font-size:12px;color:var(--text-3);margin-top:8px;">Changes made before the restart are not kept: the settings were copied when the move ran.</div>';
    } else if (m.kind === 'stick') {
      body += `<div style="font-size:13px;color:var(--text-2);line-height:1.55;margin-bottom:12px;">ZNAS runs from its USB stick. You can move it to an internal disk: it then works exactly like the stick (it runs from memory and is upgraded by us), and the rest of that disk becomes a ZFS pool.</div>
        ${where.relayed ? '<div class="alert alert-info">Moving to an internal disk erases a disk, so it can only be started when logged in to this server directly, not through InterLink.</div>'
          : '<button class="btn btn-primary btn-sm" id="awd-open">Move to an internal disk…</button>'}`;
    } else if (m.kind === 'disk') {
      body += '<div style="font-size:13px;color:var(--text-2);line-height:1.55;">ZNAS runs from this internal disk, from memory, like the USB stick. Upgrades (above) write the new image to this disk.</div>';
      if (m.booted_from_other) body += `<div class="alert alert-error" style="margin-top:10px;">This machine started from ${E(m.other_image_disk || 'another disk')}, not from ${E(m.disk)}: the firmware boot order puts it first. Everything works, but an upgrade written to ${E(m.disk)} won't take effect. Remove the old USB stick, or choose ${E(m.disk)} first in the firmware boot order.</div>`;
      else if (m.other_image_disk) body += `<div class="alert alert-info" style="margin-top:10px;">The old USB stick (${E(m.other_image_disk)}) is still plugged in. ZNAS doesn't use it any more: you can remove it.</div>`;
    } else if (m.persist_status === 'moved') {
      body += `<div class="alert alert-error">This USB stick's settings were moved to an internal disk${m.moved_to ? ' (' + E(m.moved_to) + ')' : ''}. Remove the stick and start the server from that disk.</div>`;
    } else {
      body += '<div style="font-size:13px;color:var(--text-3);">No settings partition is in use, so ZNAS can’t be moved right now.</div>';
    }
    c.innerHTML = `<div style="margin-bottom:12px;"><h3 style="margin-bottom:2px;">Where ZNAS runs</h3>
      <div style="font-size:13px;color:var(--text-3);">${mediumLine(m) || '—'}</div></div>${body}`;
    const o = c.querySelector('#awd-open'); if (o) o.onclick = openWizard;
    const lt = c.querySelector('#awd-log-t'); if (lt) lt.onclick = () => { const p = c.querySelector('#awd-log'); p.style.display = p.style.display === 'none' ? '' : 'none'; };
    const rb = c.querySelector('#awd-reboot'); if (rb) rb.onclick = () => {
      rb.disabled = true;
      getJSON('/api/system/reboot', { method: 'POST' }).then(() => { rb.textContent = 'Restarting…'; }).catch(e => { rb.disabled = false; window.showToast && showToast(e.message); });
    };
    if (st.phase === 'running' && !poll) poll = setInterval(load, 2000);
    if (st.phase !== 'running' && poll) { clearInterval(poll); poll = null; }
  }

  function load() {
    getJSON('/api/appliance/where').then(d => { where = d; render(); }).catch(() => { /* portal restarting during the copy: keep polling */ });
  }

  // ---- wizard -----------------------------------------------------------------
  function modal() {
    let m = document.getElementById('modal-appliance-disk');
    if (m) return m;
    m = document.createElement('div');
    m.className = 'modal-backdrop hidden';
    m.id = 'modal-appliance-disk';
    m.innerHTML = `<div class="modal" style="max-width:640px;">
      <div class="modal-header"><h3 style="margin:0;">Move ZNAS to an internal disk</h3>
        <button class="modal-close" data-close>✕</button></div>
      <div class="modal-body" id="awd-body" style="padding-top:4px;"></div>
      <div class="modal-footer" style="display:flex;gap:8px;justify-content:flex-end;">
        <button class="btn btn-ghost" data-close>Cancel</button>
        <button class="btn btn-ghost" id="awd-back">Back</button>
        <button class="btn btn-primary" id="awd-next">Next</button></div></div>`;
    document.body.appendChild(m);
    m.querySelectorAll('[data-close]').forEach(b => b.onclick = () => m.classList.add('hidden'));
    m.querySelector('#awd-back').onclick = () => { if (wiz.step > 0) { wiz.step--; draw(); } };
    m.querySelector('#awd-next').onclick = next;
    return m;
  }

  function openWizard() {
    wiz = { step: 0, targets: null, disk: '', pool: true, poolName: 'zpool-1', confirm: '', password: '', totp: '', needTotp: false, err: '', busy: false };
    modal().classList.remove('hidden');
    draw();
    getJSON('/api/appliance/install-targets').then(d => { wiz.targets = d; draw(); }).catch(e => { wiz.err = e.message; draw(); });
  }

  const layoutBar = `<div style="display:flex;height:34px;border-radius:6px;overflow:hidden;font-size:11px;font-weight:600;color:#fff;margin:10px 0 4px;">
      <div style="flex:0 0 14%;background:var(--accent-2);display:flex;align-items:center;justify-content:center;">ZNAS OS</div>
      <div style="flex:0 0 8%;background:var(--surface2);"></div>
      <div style="flex:0 0 16%;background:var(--accent-1);display:flex;align-items:center;justify-content:center;">Settings</div>
      <div style="flex:1;background:#30a46c;display:flex;align-items:center;justify-content:center;">zpool-1 (the rest of the disk)</div></div>
    <div style="display:flex;font-size:11px;color:var(--text-3);"><span style="flex:0 0 22%;">0 – 8 GB</span><span style="flex:0 0 16%;">8 – 16 GB</span><span>16 GB – end</span></div>`;

  function selected() { return ((wiz.targets || {}).targets || []).find(t => t.name === wiz.disk); }

  function draw() {
    const m = modal(), b = m.querySelector('#awd-body'), nx = m.querySelector('#awd-next'), bk = m.querySelector('#awd-back');
    bk.style.display = wiz.step > 0 ? '' : 'none';
    nx.className = 'btn ' + (wiz.step === 3 ? 'btn-danger' : 'btn-primary');
    nx.textContent = wiz.step === 3 ? (wiz.busy ? 'Starting…' : 'Erase and move') : 'Next';
    nx.disabled = wiz.busy;
    const err = wiz.err ? `<div class="alert alert-error" style="margin-top:12px;">${E(wiz.err)}</div>` : '';
    if (wiz.step === 0) {
      b.innerHTML = `<div style="font-size:13px;color:var(--text-2);line-height:1.6;">
        The disk you pick gets the same ZNAS system as the USB stick, and works the same way: ZNAS runs from memory, changes outside its settings are lost at restart, and upgrades come from us as signed images.
        ${layoutBar}
        <div class="alert alert-error" style="margin-top:14px;"><strong>Everything on the disk you pick is erased.</strong></div>
        <p style="margin:10px 0 0;">ZNAS and the new pool then share one disk: if that disk fails, both are lost. Your settings can come back from a backup file; the data on the pool can't.</p>
        <p style="margin:10px 0 0;">Export a backup of the settings first. <a href="#" id="awd-export">Export a backup now</a></p>
        <p style="margin:10px 0 0;">During the copy, running VMs and containers are stopped and the portal restarts. Afterwards, remove the USB stick and restart.</p></div>${err}`;
      const ex = b.querySelector('#awd-export');
      if (ex) ex.onclick = ev => { ev.preventDefault(); if (window.ZnasBak) window.ZnasBak.openExport(); };
    } else if (wiz.step === 1) {
      const T = wiz.targets;
      if (!T) { b.innerHTML = '<div style="color:var(--text-3);font-size:13px;">Looking for disks…</div>' + err; return; }
      const rows = (T.targets || []).map(t => {
        const sel = t.name === wiz.disk;
        const what = [t.model, t.tran ? t.tran.toUpperCase() : '', t.rotational ? 'HDD' : 'SSD', t.serial ? 'S/N ' + t.serial : ''].filter(Boolean).join(' · ');
        return `<div data-disk="${E(t.name)}" style="border:1px solid ${sel ? 'var(--accent-1)' : 'var(--border)'};background:${sel ? 'rgba(10,132,255,.08)' : 'var(--surface)'};border-radius:8px;padding:10px 12px;margin-bottom:8px;cursor:${t.eligible ? 'pointer' : 'not-allowed'};opacity:${t.eligible ? 1 : .5};">
          <div style="display:flex;justify-content:space-between;gap:10px;"><strong>${E(t.name)}</strong><span style="color:var(--text-2);">${GB(t.size)}</span></div>
          <div style="font-size:12px;color:var(--text-3);">${E(what)}</div>
          ${t.eligible ? '' : `<div style="font-size:12px;color:#ff9f0a;margin-top:3px;">${E(t.reason)}</div>`}
          ${(t.notes || []).map(n => `<div style="font-size:12px;color:var(--text-2);margin-top:3px;">${E(n)}</div>`).join('')}
          ${(t.contents || []).length ? `<div style="font-size:11px;color:var(--text-3);margin-top:3px;">Now on it: ${E(t.contents.join(', '))}</div>` : ''}</div>`;
      }).join('') || '<div style="color:var(--text-3);font-size:13px;">No disks found.</div>';
      b.innerHTML = `<div style="font-size:13px;color:var(--text-2);margin-bottom:10px;">Pick the disk ZNAS moves to.</div>${rows}${err}`;
      b.querySelectorAll('[data-disk]').forEach(el => el.onclick = () => {
        const t = (T.targets || []).find(x => x.name === el.dataset.disk);
        if (t && t.eligible) { wiz.disk = t.name; wiz.err = ''; draw(); }
      });
    } else if (wiz.step === 2) {
      b.innerHTML = `<label style="display:flex;gap:8px;align-items:flex-start;font-size:13px;color:var(--text-1);cursor:pointer;">
          <input type="checkbox" id="awd-pool" ${wiz.pool ? 'checked' : ''} style="margin-top:2px;"> <span>Create a ZFS pool on the rest of the disk (from 16 GB to the end)</span></label>
        <div style="margin:10px 0 0 24px;${wiz.pool ? '' : 'opacity:.5;'}"><div style="font-size:12px;color:var(--text-3);margin-bottom:4px;">Pool name</div>
          <input type="text" class="input" id="awd-pname" value="${E(wiz.poolName)}" style="max-width:240px;" ${wiz.pool ? '' : 'disabled'}></div>
        <div style="font-size:12px;color:var(--text-3);margin-top:12px;">Without a pool, the settings partition takes the whole rest of the disk.</div>${err}`;
      b.querySelector('#awd-pool').onchange = e => { wiz.pool = e.target.checked; draw(); };
      b.querySelector('#awd-pname').oninput = e => { wiz.poolName = e.target.value.trim(); };
    } else {
      const t = selected() || {};
      b.innerHTML = `<div style="font-size:13px;color:var(--text-2);line-height:1.6;">
          <div><strong>${E(t.name)}</strong> · ${E(t.model || '')} · ${GB(t.size || 0)} will be <strong>erased</strong>.</div>
          ${(t.contents || []).length ? `<div>Erased with it: ${E(t.contents.join(', '))}</div>` : ''}
          ${(t.notes || []).map(n => `<div>${E(n)}</div>`).join('')}
          <div>${wiz.pool ? 'Pool <strong>' + E(wiz.poolName) + '</strong> is created on the rest of the disk.' : 'No pool is created.'}</div>
          <div>Running VMs and containers are stopped during the copy.</div></div>
        <div style="margin-top:14px;font-size:12px;color:var(--text-3);">Type <strong style="color:var(--text-1);">${E(t.name)}</strong> to confirm</div>
        <input type="text" class="input" id="awd-confirm" autocomplete="off" spellcheck="false" value="${E(wiz.confirm)}" style="max-width:240px;">
        <div style="margin-top:10px;font-size:12px;color:var(--text-3);">Your password</div>
        <input type="password" class="input" id="awd-pw" autocomplete="current-password" value="${E(wiz.password)}" style="max-width:240px;">
        ${wiz.needTotp ? `<div style="margin-top:10px;font-size:12px;color:var(--text-3);">2FA code</div>
        <input type="text" class="input" id="awd-totp" inputmode="numeric" autocomplete="one-time-code" value="${E(wiz.totp)}" style="max-width:140px;">` : ''}${err}`;
      b.querySelector('#awd-confirm').oninput = e => { wiz.confirm = e.target.value.trim(); };
      b.querySelector('#awd-pw').oninput = e => { wiz.password = e.target.value; };
      const tt = b.querySelector('#awd-totp'); if (tt) tt.oninput = e => { wiz.totp = e.target.value.trim(); };
    }
  }

  function next() {
    wiz.err = '';
    if (wiz.step === 1 && !wiz.disk) { wiz.err = 'Pick a disk'; return draw(); }
    if (wiz.step === 2 && wiz.pool && !/^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/.test(wiz.poolName)) { wiz.err = 'Pool names start with a letter and use letters, digits, _ . : -'; return draw(); }
    if (wiz.step < 3) { wiz.step++; return draw(); }
    if (wiz.confirm !== wiz.disk) { wiz.err = 'Type ' + wiz.disk + ' exactly to confirm'; return draw(); }
    if (!wiz.password) { wiz.err = 'Enter your password'; return draw(); }
    wiz.busy = true; draw();
    getJSON('/api/appliance/install-disk', { method: 'POST', body: JSON.stringify({ disk: wiz.disk, confirm: wiz.confirm, password: wiz.password, totp: wiz.totp, pool: wiz.pool ? wiz.poolName : '' }) })
      .then(d => {
        wiz.busy = false;
        if (d.totp_needed) { wiz.needTotp = true; wiz.err = 'Enter your 2FA code'; return draw(); }
        modal().classList.add('hidden');
        wiz.password = '';
        load();
      })
      .catch(e => { wiz.busy = false; wiz.err = e.message; draw(); });
  }

  window._applWhereLoad = load;
  window._applOpenMoveWizard = openWizard;
})();
