// ZNAS configuration backup (.znasbak) — export, import wizard and rollback.
// Shared by the portal (Settings → General → Backup & Migration) and the
// first-run page (/setup → "Restore from a ZNAS backup"), so it depends on
// nothing but style.css.
(function () {
  'use strict';

  const MIN_PW = 12;
  const ICON_X = '<svg width="1em" height="1em" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>';
  const ICON_CHEV = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>';

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // ── Modal shell ───────────────────────────────────────────────────────────
  let busy = false; // an import is running: the modal cannot be closed

  function modal(title, width) {
    close(true);
    const bd = document.createElement('div');
    bd.className = 'modal-backdrop';
    bd.id = 'zb-modal';
    bd.innerHTML =
      '<div class="modal" role="dialog" aria-labelledby="zb-title" style="max-width:' + (width || 560) + 'px;">' +
      '<div class="modal-header"><h3 id="zb-title" style="margin:0;">' + esc(title) + '</h3>' +
      '<button class="modal-close" id="zb-close" aria-label="Close">' + ICON_X + '</button></div>' +
      '<div class="modal-body" id="zb-body"></div>' +
      '<div class="modal-footer" id="zb-foot"></div></div>';
    document.body.appendChild(bd);
    bd.addEventListener('click', e => { if (e.target === bd) close(); });
    bd.querySelector('#zb-close').onclick = () => close();
    return { body: bd.querySelector('#zb-body'), foot: bd.querySelector('#zb-foot'), title: bd.querySelector('#zb-title') };
  }

  function close(force) {
    if (busy && !force) return;
    const el = document.getElementById('zb-modal');
    if (el) el.remove();
  }

  document.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });

  function alertBox(kind, html) {
    // style.css has no .alert-warning: draw it inline in the same shape.
    if (kind === 'warning') {
      return '<div class="alert" style="margin-bottom:14px;background:rgba(255,214,10,.1);border:1px solid rgba(255,214,10,.45);border-left:3px solid var(--accent-warn);color:var(--text);">' + html + '</div>';
    }
    return '<div class="alert alert-' + kind + '" style="margin-bottom:14px;">' + html + '</div>';
  }

  function check(id, label, hint, on) {
    return '<label style="display:flex;gap:9px;align-items:flex-start;margin:0 0 12px;font-weight:400;cursor:pointer;">' +
      '<input type="checkbox" id="' + id + '"' + (on ? ' checked' : '') + ' style="width:auto;margin-top:3px;flex:0 0 auto;">' +
      '<span style="line-height:1.45;">' + label +
      (hint ? '<span style="display:block;font-size:12px;color:var(--text-3);">' + hint + '</span>' : '') +
      '</span></label>';
  }

  async function errText(resp) {
    try { const d = await resp.json(); return d.error || resp.statusText; } catch (_) { return resp.statusText || 'request failed'; }
  }

  // ── Export ────────────────────────────────────────────────────────────────
  function openExport() {
    const m = modal('Export configuration');
    m.body.innerHTML =
      '<p style="color:var(--text-3);font-size:13px;margin-bottom:16px;">Downloads one encrypted <b>.znasbak</b> file with everything needed to rebuild this server ' +
      'on new hardware or on the USB appliance: settings, users and their passwords, shares, schedules, alerts, encryption keys, ' +
      'pool list and the VM / container inventory. Your data stays on the pools — it is not in the file.</p>' +
      '<div id="zb-msg"></div>' +
      '<div class="form-group"><label for="zb-pw">Backup password</label>' +
      '<input type="password" id="zb-pw" autocomplete="new-password" placeholder="At least ' + MIN_PW + ' characters"></div>' +
      '<div class="form-group"><label for="zb-pw2">Confirm password</label>' +
      '<input type="password" id="zb-pw2" autocomplete="new-password" placeholder="Repeat the password"></div>' +
      check('zb-charts', 'Include performance charts history', 'Keeps your CPU, network, disk and capacity graphs.', true) +
      check('zb-certs', 'Include HTTPS certificates', 'Leave on to keep the same certificate on the new server.', true) +
      check('zb-audit', 'Include the audit log', 'The activity history. Can be large.', false) +
      alertBox('warning', 'Keep the password safe: <b>without it the file cannot be opened</b>, and nobody can recover it. ' +
        'The file holds password hashes and the keys of your encrypted datasets — store it like a password.');
    m.foot.innerHTML = '<button class="btn btn-ghost" id="zb-cancel">Cancel</button>' +
      '<button class="btn btn-primary" id="zb-go">Export</button>';
    m.foot.querySelector('#zb-cancel').onclick = () => close();
    m.foot.querySelector('#zb-go').onclick = doExport;
    setTimeout(() => document.getElementById('zb-pw').focus(), 50);
  }

  async function doExport() {
    const pw = document.getElementById('zb-pw').value;
    const msg = document.getElementById('zb-msg');
    msg.innerHTML = '';
    if (pw.length < MIN_PW) { msg.innerHTML = alertBox('error', 'The password must be at least ' + MIN_PW + ' characters.'); return; }
    if (pw !== document.getElementById('zb-pw2').value) { msg.innerHTML = alertBox('error', 'The passwords do not match.'); return; }
    const btn = document.getElementById('zb-go');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Building…';
    try {
      const resp = await fetch('/api/backup/export', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          password: pw,
          include_charts: document.getElementById('zb-charts').checked,
          include_certs: document.getElementById('zb-certs').checked,
          include_audit: document.getElementById('zb-audit').checked,
        }),
      });
      if (!resp.ok) throw new Error(await errText(resp));
      const blob = await resp.blob();
      const cd = resp.headers.get('Content-Disposition') || '';
      const name = (cd.match(/filename="([^"]+)"/) || [])[1] || 'znas-backup.znasbak';
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 10000);
      const m = modal('Export configuration');
      m.body.innerHTML = alertBox('success', 'Backup downloaded: <b>' + esc(name) + '</b> (' + Math.max(1, Math.round(blob.size / 1024)) + ' KB).') +
        '<p style="font-size:13px;color:var(--text-2);line-height:1.6;">To move to new hardware or to the USB appliance: shut this server down, ' +
        'move the pool disks, start the new server and choose <b>Restore from a ZNAS backup</b> on its first-start page ' +
        '(or Settings → General → Backup &amp; Migration → Import).</p>';
      m.foot.innerHTML = '<button class="btn btn-primary" id="zb-ok">Done</button>';
      m.foot.querySelector('#zb-ok').onclick = () => close();
    } catch (e) {
      msg.innerHTML = alertBox('error', esc(e.message));
      btn.disabled = false;
      btn.textContent = 'Export';
    }
  }

  // ── Import ────────────────────────────────────────────────────────────────
  let imp = null; // { setup, file, password, plan }

  function openImport(opts) {
    imp = { setup: !!(opts && opts.setup), file: null, password: '', plan: null };
    stepUpload();
  }

  function stepUpload(error) {
    const m = modal('Import a configuration backup', 560);
    m.body.innerHTML =
      (imp.setup
        ? '<p style="color:var(--text-3);font-size:13px;margin-bottom:16px;">Moving from another ZNAS server? Restore its backup instead of creating a new account: ' +
          'your users, shares, settings, pools and VMs come back as they were. Connect the pool disks to this machine first.</p>'
        : '<p style="color:var(--text-3);font-size:13px;margin-bottom:16px;">Restore a <b>.znasbak</b> file. Nothing changes until you review the plan and confirm.</p>') +
      '<div id="zb-msg">' + (error ? alertBox('error', esc(error)) : '') + '</div>' +
      '<div class="form-group"><label>Backup file</label>' +
      '<label id="zb-drop" style="display:flex;align-items:center;gap:10px;padding:14px;border:1px dashed var(--border);border-radius:8px;cursor:pointer;font-weight:400;background:var(--surface2);">' +
      '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/></svg>' +
      '<span id="zb-fname" style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;">' +
      (imp.file ? esc(imp.file.name) : 'Choose or drop a .znasbak file') + '</span>' +
      '<input type="file" id="zb-file" accept=".znasbak" style="display:none;"></label></div>' +
      '<div class="form-group"><label for="zb-ipw">Backup password</label>' +
      '<input type="password" id="zb-ipw" autocomplete="off"></div>';
    m.foot.innerHTML = '<button class="btn btn-ghost" id="zb-cancel">Cancel</button>' +
      '<button class="btn btn-primary" id="zb-go">Open backup</button>';
    const fileIn = m.body.querySelector('#zb-file');
    const setFile = f => { if (f) { imp.file = f; m.body.querySelector('#zb-fname').textContent = f.name; } };
    fileIn.onchange = () => setFile(fileIn.files[0]);
    const drop = m.body.querySelector('#zb-drop');
    drop.addEventListener('dragover', e => { e.preventDefault(); drop.style.borderColor = 'var(--accent-2)'; });
    drop.addEventListener('dragleave', () => { drop.style.borderColor = ''; });
    drop.addEventListener('drop', e => { e.preventDefault(); drop.style.borderColor = ''; setFile(e.dataTransfer.files[0]); });
    m.body.querySelector('#zb-ipw').addEventListener('keydown', e => { if (e.key === 'Enter') inspect(); });
    m.foot.querySelector('#zb-cancel').onclick = () => close();
    m.foot.querySelector('#zb-go').onclick = inspect;
  }

  async function inspect() {
    const pwEl = document.getElementById('zb-ipw');
    if (pwEl) imp.password = pwEl.value;
    const msg = document.getElementById('zb-msg');
    if (!imp.file) { msg.innerHTML = alertBox('error', 'Choose the backup file.'); return; }
    if (!imp.password) { msg.innerHTML = alertBox('error', 'Enter the backup password.'); return; }
    const btn = document.getElementById('zb-go');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Decrypting…';
    const fd = new FormData();
    fd.append('file', imp.file);
    fd.append('password', imp.password);
    try {
      const resp = await fetch('/api/backup/inspect', { method: 'POST', body: fd });
      if (!resp.ok) throw new Error(await errText(resp));
      imp.plan = await resp.json();
      stepPlan();
    } catch (e) {
      stepUpload(e.message);
    }
  }

  function chip(text, kind) {
    const c = { ok: 'var(--accent-4)', warn: 'var(--accent-warn)', bad: 'var(--accent-danger)', info: 'var(--text-3)' }[kind];
    return '<span style="display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;border:1px solid ' + c +
      ';color:' + c + ';white-space:nowrap;">' + esc(text) + '</span>';
  }

  function section(title, inner) {
    return '<div style="margin:0 0 16px;"><div style="font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--text-3);margin-bottom:6px;">' +
      esc(title) + '</div>' + inner + '</div>';
  }

  function rows(list) {
    return '<div style="border:1px solid var(--border);border-radius:8px;overflow:hidden;">' + list.map((r, i) =>
      '<div style="display:flex;align-items:center;gap:10px;padding:8px 12px;font-size:13px;' + (i ? 'border-top:1px solid var(--border);' : '') + '">' +
      r + '</div>').join('') + '</div>';
  }

  const FEATURE_NAMES = { iscsi: 'iSCSI', ups: 'UPS (NUT)', mergerfs: 'MergerFS', s3: 'S3 storage', virtualization: 'Virtualization' };

  function stepPlan() {
    const p = imp.plan, mf = p.manifest || {}, inv = mf.inventory || {};
    const m = modal('Import plan', 680);
    const created = mf.created_at ? new Date(mf.created_at).toLocaleString() : '';
    let h = '<div style="display:flex;gap:14px;align-items:center;padding:12px 14px;border:1px solid var(--border);border-radius:8px;margin-bottom:16px;background:var(--surface2);">' +
      '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="flex:0 0 auto;color:var(--accent-2);"><rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6 6h.01"/><path d="M6 18h.01"/></svg>' +
      '<div style="min-width:0;"><div style="font-weight:600;">' + esc(mf.hostname) + ' <span style="font-weight:400;color:var(--text-3);">→ ' + esc(p.hostname) + '</span></div>' +
      '<div style="font-size:12px;color:var(--text-3);">ZNAS ' + esc(mf.znas_version) + ' · ' + (mf.source_type === 'appliance' ? 'USB appliance' : 'installed on a host') +
      (created ? ' · ' + esc(created) : '') + '</div></div></div>';

    // What comes back
    const parts = [];
    const n = (x, one, many) => x ? x + ' ' + (x === 1 ? one : many) : '';
    [n((inv.users || []).length, 'user', 'users'), n((inv.smb_shares || []).length, 'SMB share', 'SMB shares'),
      n((inv.nfs_exports || []).length, 'NFS export', 'NFS exports'), n(inv.iscsi_targets, 'iSCSI target', 'iSCSI targets'),
      n((inv.instances || []).length, 'VM / container', 'VMs / containers')].forEach(s => { if (s) parts.push(s); });
    h += section('Restores', '<div style="font-size:13px;color:var(--text-2);line-height:1.6;">' +
      (parts.length ? esc(parts.join(' · ')) + ', and all settings, schedules and alerts.' : 'Settings, schedules and alerts.') + '</div>');

    if (!p.setup) {
      h += alertBox('warning', 'This <b>replaces</b> the settings and users of this server. A copy of the current settings is kept so the import can be rolled back.');
    }

    // Pools
    if ((p.pools || []).length) {
      h += section('ZFS pools', rows(p.pools.map(pl =>
        '<span style="font-family:\'SF Mono\',monospace;flex:1;">' + esc(pl.name) + '</span>' +
        '<span style="font-size:12px;color:var(--text-3);">' + esc(pl.note) + '</span>' +
        chip(pl.state === 'imported' ? 'present' : pl.state === 'importable' ? 'will import' : 'not found',
          pl.state === 'missing' ? 'bad' : pl.state === 'importable' ? 'warn' : 'ok'))));
      if (p.pools.some(pl => pl.state === 'missing')) {
        h += '<div style="margin:-8px 0 16px;font-size:12px;color:var(--text-3);">Pools not found are skipped: their shares and VMs stay configured and come back once the disks are connected and the pool is imported. ' +
          '<a href="#" id="zb-recheck">Check the disks again</a></div>';
      }
    }

    // Accounts
    const conflicts = (p.accounts || []).filter(a => a.conflict);
    if (conflicts.length) {
      h += section('Account conflicts', rows(conflicts.map(a =>
        '<span style="font-family:\'SF Mono\',monospace;">' + esc(a.name) + '</span>' +
        '<span style="font-size:12px;color:var(--text-3);flex:1;">' + esc(a.conflict) + '</span>' + chip('skipped', 'warn'))));
    }

    // Missing optional features
    if ((p.missing_features || []).length) {
      h += alertBox('warning', 'Not installed here: <b>' + p.missing_features.map(f => esc(FEATURE_NAMES[f] || f)).join(', ') +
        '</b>. Their settings are restored and start working once you install them from Optional Features.');
    }

    // VMs & networks
    const insts = inv.instances || [];
    if (insts.length && !p.virt_here) {
      h += alertBox('warning', 'Virtualization is not installed here, so the ' + insts.length + ' VM(s) / container(s) cannot be recovered now. ' +
        'Install it, then import the backup again — the rest of the import is not affected.');
    }
    const nets = (p.networks || []);
    if (insts.length && p.virt_here && nets.length) {
      h += section('VM & container networks', rows(nets.map(nw => {
        let right;
        if (nw.exists) right = chip('present', 'ok');
        else if (nw.managed) right = chip('will be created', 'info');
        else right = '<span style="font-size:12px;color:var(--text-3);">connect to</span>' + picker('zb-net-' + nw.name, nw.suggest, p.bridges || []);
        return '<span style="font-family:\'SF Mono\',monospace;flex:1;">' + esc(nw.name) + '</span>' + right;
      })) + '<div style="font-size:12px;color:var(--text-3);margin-top:6px;">VMs and containers are recovered stopped, so you can check them before starting them.</div>');
    }

    // Options
    let o = '';
    if (p.force_needed) {
      o += check('zb-force', 'Import pools last used by the old server', 'Needed when the disks were moved without exporting the pools first (zpool import -f). Make sure the old server is off.', true);
    }
    if (mf.hostname && mf.hostname !== p.hostname) {
      o += check('zb-host', 'Rename this server to <b>' + esc(mf.hostname) + '</b>', 'Keeps network shares and bookmarks working with the old name. Your router may then give this server a different IP address.', true);
    }
    if (o) h += section('Options', o);

    m.body.innerHTML = h;
    m.foot.innerHTML = '<button class="btn btn-ghost" id="zb-back">Back</button>' +
      '<button class="btn btn-primary" id="zb-go">Import</button>';
    m.foot.querySelector('#zb-back').onclick = () => stepUpload();
    m.foot.querySelector('#zb-go').onclick = apply;
    const rc = m.body.querySelector('#zb-recheck');
    if (rc) rc.onclick = e => { e.preventDefault(); recheck(); };
    wirePickers(m.body);
  }

  async function recheck() {
    const fd = new FormData();
    fd.append('file', imp.file);
    fd.append('password', imp.password);
    const resp = await fetch('/api/backup/inspect', { method: 'POST', body: fd });
    if (resp.ok) { imp.plan = await resp.json(); stepPlan(); } else stepUpload(await errText(resp));
  }

  // Small button + popover picker (the house style forbids native <select> menus).
  function picker(id, value, options) {
    const opts = [''].concat(options);
    return '<span class="zb-pick" style="position:relative;display:inline-block;">' +
      '<button type="button" id="' + esc(id) + '" data-value="' + esc(value || '') + '" data-options="' + esc(JSON.stringify(opts)) + '" ' +
      'style="display:inline-flex;align-items:center;gap:6px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:4px 10px;font-size:13px;cursor:pointer;font-family:\'SF Mono\',monospace;">' +
      '<span>' + esc(value || 'leave unconnected') + '</span>' + ICON_CHEV + '</button></span>';
  }

  function wirePickers(root) {
    root.querySelectorAll('.zb-pick > button').forEach(btn => {
      btn.onclick = e => {
        e.stopPropagation();
        document.querySelectorAll('.zb-pop').forEach(x => x.remove());
        const pop = document.createElement('div');
        pop.className = 'zb-pop';
        pop.style.cssText = 'position:absolute;right:0;top:calc(100% + 4px);z-index:5;min-width:180px;background:var(--surface);border:1px solid var(--border);border-radius:8px;box-shadow:var(--shadow-lg);padding:4px;';
        JSON.parse(btn.dataset.options).forEach(v => {
          const it = document.createElement('button');
          it.type = 'button';
          it.style.cssText = 'display:flex;width:100%;gap:8px;align-items:center;text-align:left;background:none;border:0;border-radius:6px;color:var(--text);padding:6px 10px;font-size:13px;cursor:pointer;' +
            (v ? "font-family:'SF Mono',monospace;" : 'color:var(--text-3);');
          it.innerHTML = '<span style="width:12px;">' + (v === btn.dataset.value ? '✓' : '') + '</span>' + esc(v || 'leave unconnected');
          it.onmouseenter = () => { it.style.background = 'var(--surface2)'; };
          it.onmouseleave = () => { it.style.background = 'none'; };
          it.onclick = ev => {
            ev.stopPropagation();
            btn.dataset.value = v;
            btn.querySelector('span').textContent = v || 'leave unconnected';
            pop.remove();
          };
          pop.appendChild(it);
        });
        btn.parentNode.appendChild(pop);
      };
    });
  }
  document.addEventListener('click', () => document.querySelectorAll('.zb-pop').forEach(x => x.remove()));

  async function apply() {
    const p = imp.plan;
    const netMap = {};
    document.querySelectorAll('.zb-pick > button').forEach(b => {
      if (b.dataset.value) netMap[b.id.replace(/^zb-net-/, '')] = b.dataset.value;
    });
    const force = document.getElementById('zb-force');
    const host = document.getElementById('zb-host');
    const btn = document.getElementById('zb-go');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Starting…';
    try {
      const resp = await fetch('/api/backup/apply', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          import_id: p.import_id,
          force_import: force ? force.checked : false,
          restore_hostname: host ? host.checked : false,
          network_map: netMap,
        }),
      });
      if (!resp.ok) throw new Error(await errText(resp));
      const { job_id } = await resp.json();
      stepProgress(job_id);
    } catch (e) {
      stepUpload(e.message); // the import id is single-use: start over
    }
  }

  function stepProgress(jobId) {
    busy = true;
    const m = modal('Importing…', 680);
    m.body.innerHTML = '<pre id="zb-log" style="margin:0;max-height:46vh;overflow:auto;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px;font-size:12px;line-height:1.6;white-space:pre-wrap;"></pre>' +
      '<div id="zb-sum"></div>';
    m.foot.innerHTML = '<span id="zb-state" style="margin-right:auto;font-size:13px;color:var(--text-3);"><span class="spinner"></span> Working — do not close this page</span>';
    let misses = 0;
    const tick = async () => {
      let j;
      try {
        const resp = await fetch('/api/backup/jobs/' + encodeURIComponent(jobId), { cache: 'no-store' });
        if (!resp.ok) throw new Error();
        j = await resp.json();
        misses = 0;
      } catch (_) {
        if (++misses > 5) { finished(m, null); return; } // portal already restarting
        setTimeout(tick, 1000);
        return;
      }
      const log = document.getElementById('zb-log');
      log.textContent = (j.lines || []).join('\n');
      log.scrollTop = log.scrollHeight;
      if (!j.done) { setTimeout(tick, 1000); return; }
      finished(m, j);
    };
    tick();
  }

  function finished(m, j) {
    busy = false;
    const sum = document.getElementById('zb-sum');
    if (j && j.failed) {
      m.title.textContent = 'Import stopped';
      sum.innerHTML = '<div style="margin-top:14px;">' + alertBox('error', esc(j.error)) +
        '<p style="font-size:13px;color:var(--text-2);">Steps already done are listed above. ' +
        (imp.setup ? 'You can try again, or create a new account instead.' : 'Use <b>Roll back</b> in Backup &amp; Migration to return to the previous settings.') + '</p></div>';
      m.foot.innerHTML = '<button class="btn btn-primary" id="zb-ok">Close</button>';
      m.foot.querySelector('#zb-ok').onclick = () => close();
      return;
    }
    m.title.textContent = 'Import complete';
    const notes = (j && j.summary) || [];
    sum.innerHTML = '<div style="margin-top:14px;">' +
      (notes.length ? section('To check', '<ul style="margin:0;padding-left:18px;font-size:13px;line-height:1.6;color:var(--text-2);">' +
        notes.map(s => '<li>' + esc(s) + '</li>').join('') + '</ul>') : '') +
      alertBox('success', 'The portal is restarting with the imported configuration. Sign in with your migrated account.') + '</div>';
    m.foot.innerHTML = '<span id="zb-state" style="margin-right:auto;font-size:13px;color:var(--text-3);"><span class="spinner"></span> Waiting for the portal…</span>' +
      '<button class="btn btn-primary" id="zb-ok" disabled>Go to sign-in</button>';
    const ok = m.foot.querySelector('#zb-ok');
    ok.onclick = () => { window.location.href = '/login'; };
    waitForPortal(() => {
      ok.disabled = false;
      const st = document.getElementById('zb-state');
      if (st) st.textContent = 'The portal is back.';
    });
  }

  // Wait until the portal has gone down and come back (restart after import).
  function waitForPortal(done) {
    let wentDown = false, tries = 0;
    const poll = async () => {
      tries++;
      try {
        const r = await fetch('/login', { cache: 'no-store' });
        if (r.ok && (wentDown || tries > 15)) { done(); return; }
      } catch (_) { wentDown = true; }
      setTimeout(poll, 1500);
    };
    setTimeout(poll, 3000);
  }

  // ── Settings card ─────────────────────────────────────────────────────────
  async function loadStatus() {
    const el = document.getElementById('zb-rollback-row');
    if (!el) return;
    try {
      const r = await fetch('/api/backup/status', { cache: 'no-store' });
      if (!r.ok) throw new Error();
      const s = await r.json();
      if (!s.rollback_available) { el.innerHTML = ''; return; }
      const ts = s.rollback_from.replace(/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})$/, '$1-$2-$3 $4:$5');
      el.innerHTML = '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:16px;padding-top:14px;border-top:1px solid var(--border);font-size:13px;color:var(--text-3);">' +
        '<span style="flex:1;min-width:200px;">Settings from before the last import (' + esc(ts) + ') are kept.</span>' +
        '<button class="btn btn-ghost btn-sm" id="zb-rollback">Roll back</button></div>';
      el.querySelector('#zb-rollback').onclick = () => confirmRollback(ts);
    } catch (_) { el.innerHTML = ''; }
  }

  function confirmRollback(ts) {
    const m = modal('Roll back the import?');
    m.body.innerHTML = '<p style="font-size:13px;color:var(--text-2);line-height:1.6;">Puts back the portal settings and users as they were on <b>' + esc(ts) +
      '</b>, before the import, and restarts the portal.</p>' +
      alertBox('warning', 'Pools that were imported stay imported, and system accounts and VMs created by the import are kept — only the portal settings go back.') +
      '<div id="zb-msg"></div>';
    m.foot.innerHTML = '<button class="btn btn-ghost" id="zb-cancel">Cancel</button><button class="btn btn-danger" id="zb-go">Roll back</button>';
    m.foot.querySelector('#zb-cancel').onclick = () => close();
    m.foot.querySelector('#zb-go').onclick = async () => {
      const btn = document.getElementById('zb-go');
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> Rolling back…';
      const r = await fetch('/api/backup/rollback', { method: 'POST' });
      if (!r.ok) {
        document.getElementById('zb-msg').innerHTML = alertBox('error', esc(await errText(r)));
        btn.disabled = false;
        btn.textContent = 'Roll back';
        return;
      }
      m.body.innerHTML = alertBox('success', 'Settings restored. The portal is restarting…');
      m.foot.innerHTML = '<button class="btn btn-primary" id="zb-ok" disabled>Go to sign-in</button>';
      const ok = m.foot.querySelector('#zb-ok');
      ok.onclick = () => { window.location.href = '/login'; };
      waitForPortal(() => { ok.disabled = false; });
    };
  }

  window.ZnasBak = { openExport, openImport, loadStatus };
})();
