/*
 * Manage InterLink → health. GET /api/interlink/health tries every link with
 * real signed requests; each problem it finds gets its repair next to it.
 */
(function () {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const api = (u, o) => window._apiFetch(u, o);
  const toast = (m, t) => window._showToast(m, t);
  const post = (u, b) => api(u, { method: 'POST', body: JSON.stringify(b || {}) });
  let last = null, seq = 0;

  const REASON = {
    secret_mismatch: 'the two servers hold different link keys',
    clock: 'their clocks differ too much',
    cert_changed: 'its certificate changed',
    unreachable: 'it cannot be reached',
    needs_update: 'it runs an older version',
    error: 'it returned an error',
  };
  const STATUS = { ok: 'OK', secret_mismatch: 'Key mismatch', clock: 'Clock', cert_changed: 'Certificate', unreachable: 'No route', needs_update: 'Update', error: 'Error' };

  const chip = (state, label, title, action) =>
    `<span class="il-chip ${state}"${title ? ` title="${E(title)}"` : ''}>${E(label)}</span>${action || ''}`;
  const btn = (label, fn, args) =>
    `<button class="btn btn-ghost btn-sm il-fix" data-fn="${fn}" data-args="${E(JSON.stringify(args))}">${E(label)}</button>`;

  function checks(s) {
    const c = [];
    if (s.reach !== 'ok') {
      c.push(chip('bad', 'Not reachable', s.reach_detail));
      return c;
    }
    if (s.cert === 'changed') {
      c.push(chip('bad', 'Certificate changed', `Pinned ${s.pinned}\nNow ${s.live}`, btn('Review certificate', 'cert', [s.id, s.hostname, s.pinned, s.live])));
      return c;
    }
    if (s.secret === 'mismatch') c.push(chip('bad', 'Link keys differ', 'Each side signs with a different key, so every request is refused', btn('Repair link', 'repair', [s.id, s.hostname])));
    else if (s.secret === 'ok') c.push(chip('ok', 'Link key'));
    else c.push(chip('warn', 'Link key not checked'));
    if (s.ids_match === false) c.push(chip('warn', 'Link IDs differ', 'Unlinking from one side will not remove the other', s.secret === 'ok' ? btn('Repair link', 'repair', [s.id, s.hostname]) : ''));
    if (s.reach_back === 'ok') c.push(chip('ok', 'Reaches us'));
    else if (s.reach_back === 'unreachable') c.push(chip('bad', 'Cannot reach us', (s.back_detail || '') + '\nThis server cannot be reached from there. Check that it has a route back, for example for the VPN addresses.'));
    else if (s.reach_back !== 'unknown') c.push(chip('bad', 'Refuses us: ' + (STATUS[s.reach_back] || s.reach_back), s.back_detail));
    if (s.cert === 'ok') c.push(chip('ok', 'Certificate'));
    else if (s.cert === 'missing') c.push(chip('warn', 'Certificate not pinned', 'Any certificate is accepted from this server', btn('Pin certificate', 'pin', [s.id, s.hostname, s.live])));
    if (s.clock_skew != null) c.push(s.clock_ok ? chip('ok', 'Clock') : chip('bad', `Clock off by ${Math.abs(s.clock_skew)} s`, 'Signed requests are refused when the clocks differ too much. Fix the time on one of the servers.'));
    if (s.account === 'exists') c.push(chip('ok', 'Your account: ' + s.account_role));
    else if (s.account === 'missing') c.push(chip('bad', 'No account for you', '', last ? btn('Create account', 'account', [s.id, s.hostname, last.username]) : ''));
    if (s.zfs_access === false) c.push(chip('warn', 'No ZFS access', 'Pushes to this server may fail', btn('Repair', 'access', [s.id, s.hostname])));
    else if (s.zfs_access) c.push(chip('ok', 'ZFS access'));
    if (s.incus_trust === false) c.push(chip('warn', 'Incus not trusted', '', btn('Sync trust', 'trust', [s.id, s.hostname])));
    else if (s.incus_trust) c.push(chip('ok', 'Incus trust'));
    if (s.needs_update) c.push(chip('warn', 'Older version ' + (s.version || ''), 'Update it for the full check and repairs'));
    return c;
  }

  // ── cluster grid ──
  function clusterHTML(d) {
    const names = [d.hostname];
    const urls = {};
    const add = (n, u) => { if (!n) return; if (!names.includes(n)) names.push(n); if (u && !urls[n]) urls[n] = u; };
    d.servers.forEach(s => add(s.hostname, s.url));
    d.servers.forEach(s => (s.links || []).forEach(l => add(l.hostname, l.url)));
    const byName = Object.fromEntries(d.servers.map(s => [s.hostname, s]));
    const cell = (from, to) => {
      if (from === to) return '<td class="il-self"></td>';
      let st = null, fix = '';
      if (from === d.hostname) {
        const s = byName[to];
        if (s) {
          st = s.reach !== 'ok' ? 'unreachable' : s.cert === 'changed' ? 'cert_changed' : s.secret === 'mismatch' ? 'secret_mismatch' : 'ok';
          fix = btn('Repair', 'repair', [s.id, to]);
        }
      } else {
        const s = byName[from];
        // Keys differ: it can't answer us, but this cell is that same link.
        if (s && to === d.hostname && s.secret === 'mismatch') { st = 'secret_mismatch'; fix = btn('Repair', 'repair', [s.id, from]); }
        else if (!s || !s.links) return '<td class="il-na" title="This server cannot tell">?</td>';
        else {
          const l = s.links.find(x => x.hostname === to);
          if (l) {
            st = l.status;
            fix = to === d.hostname ? btn('Repair', 'repair', [s.id, from]) : btn('Repair', 'repairPeer', [s.id, l.id, from, to]);
          }
        }
      }
      if (st) return `<td class="${st === 'ok' ? 'il-good' : 'il-badc'}" title="${E(REASON[st] || '')}">${E(STATUS[st] || st)}${st === 'secret_mismatch' ? fix : ''}</td>`;
      if (!urls[to]) return '<td class="il-na">Not linked</td>';
      return `<td class="il-na">${btn('Link', 'link', [from === d.hostname ? '' : byName[from].id, from, to, urls[to]])}</td>`;
    };
    return `<table class="il-grid"><thead><tr><th>From ↓ to →</th>${names.map(n => `<th>${E(n)}</th>`).join('')}</tr></thead><tbody>` +
      names.map(f => `<tr><th>${E(f)}</th>${names.map(t => cell(f, t)).join('')}</tr>`).join('') + '</tbody></table>';
  }

  // ── accounts grid ──
  function accountsHTML(d) {
    const cols = [{ name: d.hostname, users: d.users, here: true }].concat(d.servers.filter(s => s.users).map(s => ({ name: s.hostname, users: s.users, s })));
    const names = [...new Set(cols.flatMap(c => c.users.map(u => u.username)))].sort();
    const roleHere = n => (d.users.find(u => u.username === n) || {}).role;
    return `<table class="il-grid"><thead><tr><th>Account</th>${cols.map(c => `<th>${E(c.name)}</th>`).join('')}</tr></thead><tbody>` +
      names.map(n => `<tr><th>${E(n)}</th>${cols.map(c => {
        const u = c.users.find(x => x.username === n);
        if (u) {
          const differs = roleHere(n) && roleHere(n) !== u.role;
          return `<td class="${differs ? 'il-warnc' : 'il-good'}"${differs ? ' title="A different role than on this server"' : ''}>${E(u.role)}</td>`;
        }
        return `<td class="il-na">${roleHere(n) && c.s ? btn('Create', 'account', [c.s.id, c.name, n]) : '—'}</td>`;
      }).join('')}</tr>`).join('') + '</tbody></table>';
  }

  function render(d) {
    const wrap = document.getElementById('interlink-health-wrap');
    if (!wrap) return;
    if (!d.servers.length) { wrap.innerHTML = ''; return; }
    const tip = t => `<i class="info-tip" data-tip="${E(t)}"></i>`;
    wrap.innerHTML = `<div class="il-head"><span>Health</span>${tip('Each link is tried with real signed requests, from this server and from the other side.')}
        <span style="flex:1"></span><button class="btn btn-ghost btn-sm" data-il-recheck>Check again</button></div>` +
      d.servers.map(s => `<div class="il-row"><div class="il-name">${E(s.hostname)}</div><div class="il-chips">${checks(s).join('')}</div></div>`).join('') +
      `<div class="il-head" style="margin-top:14px"><span>All links</span>${tip('How each server reaches the others. A question mark means this server could not ask it.')}</div><div class="il-scroll">${clusterHTML(d)}</div>` +
      `<div class="il-head" style="margin-top:14px"><span>Accounts</span>${tip('Accounts differ between servers on purpose or by accident, so nothing changes here unless you create one. An account created here is a portal login only: no SSH or file sharing.')}</div><div class="il-scroll">${accountsHTML(d)}</div>`;
  }

  async function load() {
    const wrap = document.getElementById('interlink-health-wrap');
    if (!wrap) return;
    const mine = ++seq;
    wrap.innerHTML = '<div class="il-head"><span>Health</span></div><div style="color:var(--text-3);padding:6px 0;font-size:12px">Checking every link…</div>';
    try {
      const d = await api('/api/interlink/health');
      if (mine === seq) { last = d; render(d); }
    } catch (e) {
      if (mine === seq) wrap.innerHTML = `<div class="alert alert-error">${E(e.message)}</div>`;
    }
  }
  function refresh() { if (window.loadInterlinkList) window.loadInterlinkList(); if (window.loadHostnameDropdown) window.loadHostnameDropdown(); }

  // ── credentials modal ──
  function credModal({ title, intro, extra, confirm, run }) {
    const el = document.createElement('div');
    el.className = 'modal-backdrop';
    el.style.zIndex = 10050;
    el.innerHTML = `<div class="modal" style="max-width:440px"><div class="modal-header"><h3>${E(title)}</h3></div>
      <div class="modal-body"><p style="font-size:13px;color:var(--text-2);margin:0 0 12px">${intro}</p>${extra || ''}
        <div class="form-group"><label>Admin username there</label><input class="il-u" autocomplete="off" value="${E(window._currentUsername || (last && last.username) || '')}"></div>
        <div class="form-group"><label>Password</label><input class="il-p" type="password" autocomplete="off"></div>
        <div class="form-group il-t" style="display:none"><label>2FA code</label><input class="il-c" inputmode="numeric" autocomplete="off"></div>
        <div class="alert alert-error hidden il-err"></div></div>
      <div class="modal-footer"><button class="btn btn-ghost il-x">Cancel</button><button class="btn btn-primary il-ok">${E(confirm)}</button></div></div>`;
    document.body.appendChild(el);
    const q = s => el.querySelector(s);
    const close = () => el.remove();
    q('.il-x').onclick = close;
    q('.il-p').focus();
    q('.il-ok').onclick = async () => {
      const ok = q('.il-ok');
      q('.il-err').classList.add('hidden');
      ok.disabled = true;
      try {
        const res = await run({ username: q('.il-u').value.trim(), password: q('.il-p').value, totp: q('.il-c').value.trim() }, q);
        if (res && res.totp_needed) { q('.il-t').style.display = ''; q('.il-c').focus(); return; }
        close();
        refresh();
        load();
      } catch (e) {
        q('.il-err').textContent = e.message;
        q('.il-err').classList.remove('hidden');
      } finally { ok.disabled = false; }
    };
  }

  const FIX = {
    repair(id, host) {
      credModal({ title: 'Repair link', confirm: 'Repair',
        intro: `Gives <strong>${E(host)}</strong> and this server a new link key. The link keeps its settings. A wrong key can't prove who is asking, so this needs an admin login on ${E(host)}.`,
        run: async c => { const r = await post(`/api/interlink/${encodeURIComponent(id)}/repair-link`, c); if (!r.totp_needed) toast(`Link to ${host} repaired`, 'success'); return r; } });
    },
    repairPeer(rowId, linkId, from, to) {
      credModal({ title: 'Repair link', confirm: 'Repair',
        intro: `Gives <strong>${E(from)}</strong> and <strong>${E(to)}</strong> a new link key. The link keeps its settings. Runs on ${E(from)} under your account, and needs an admin login on ${E(to)}.`,
        run: async c => {
          const r = await post(`/api/interlink/${encodeURIComponent(rowId)}/repair-peer`, { ...c, link_id: linkId });
          if (!r.totp_needed) toast(`Link from ${from} to ${to} repaired`, 'success');
          return r;
        } });
    },
    link(rowId, from, to, url) {
      credModal({ title: 'Link servers', confirm: 'Link',
        intro: `Links <strong>${E(from)}</strong> to <strong>${E(to)}</strong> at ${E(url)}. Enter an admin login on ${E(to)}.`,
        run: async c => {
          const r = await post(rowId ? `/api/interlink/${encodeURIComponent(rowId)}/link-peer` : '/api/interlink/link', { ...c, url });
          if (!r.totp_needed) toast(`${from} linked to ${to}`, 'success');
          return r;
        } });
    },
    account(id, host, account) {
      credModal({ title: `Create ${account} on ${host}`, confirm: 'Create',
        intro: `Creates a portal login with the role it has here. No SSH or file sharing account is made, and 2FA isn't copied.`,
        extra: `<div class="form-group"><label style="display:flex;gap:8px;align-items:center;font-weight:400"><input type="radio" name="il-pw" class="il-copy" checked style="width:auto">Same password as here</label>
          <label style="display:flex;gap:8px;align-items:center;font-weight:400"><input type="radio" name="il-pw" class="il-new" style="width:auto">A new password</label>
          <input class="il-np" type="password" placeholder="New password, at least 8 characters" autocomplete="new-password" style="margin-top:6px"></div>
          <p style="font-size:12px;color:var(--text-3);margin:0 0 12px">Only a password hash is sent, over the pinned connection. Below: an admin login on ${E(host)}.</p>`,
        run: async (c, q) => {
          const r = await post(`/api/interlink/${encodeURIComponent(id)}/create-account`, { ...c, account, copy_password: q('.il-copy').checked, new_password: q('.il-np').value });
          if (!r.totp_needed) toast(`${account} created on ${host}`, 'success');
          return r;
        } });
    },
    cert(id, host, pinned, live) {
      showConfirm({ title: 'Certificate changed', danger: true, confirmText: 'Accept new certificate',
        body: `<strong>${E(host)}</strong> presents a different certificate than when it was linked. Expected after a reinstall or a renewed certificate. If you did neither, someone may be intercepting the connection, so don't accept it.<br><br>
          Pinned: <code style="word-break:break-all">${E(pinned)}</code><br>Now: <code style="word-break:break-all">${E(live)}</code>`,
        onConfirm: () => accept(id, host, live) });
    },
    pin(id, host, live) {
      showConfirm({ title: 'Pin certificate', confirmText: 'Pin',
        body: `From now on, only this certificate will be accepted from <strong>${E(host)}</strong>:<br><br><code style="word-break:break-all">${E(live)}</code>`,
        onConfirm: () => accept(id, host, live) });
    },
    async access(id, host) {
      try { await post(`/api/interlink/${encodeURIComponent(id)}/repair-access`); toast(`Access to ${host} repaired`, 'success'); } catch (e) { toast(e.message, 'error'); }
      load();
    },
    async trust(id, host) {
      try { await post('/api/incus/interlink-sync-trust/' + encodeURIComponent(id)); toast(`Incus trust with ${host} synced`, 'success'); } catch (e) { toast(e.message, 'error'); }
      load();
    },
  };
  async function accept(id, host, fp) {
    try { await post(`/api/interlink/${encodeURIComponent(id)}/accept-cert`, { fingerprint: fp }); toast(`Certificate of ${host} accepted`, 'success'); } catch (e) { toast(e.message, 'error'); }
    load();
  }

  document.addEventListener('click', ev => {
    const b = ev.target.closest('#interlink-health-wrap .il-fix');
    if (b) { FIX[b.dataset.fn](...JSON.parse(b.dataset.args)); return; }
    if (ev.target.closest('[data-il-recheck]')) load();
  });

  window.interlinkHealthLoad = load;

  // A failed switch: says why, and leads to the repair when it's not the account.
  window.interlinkSwitchFailed = function (res) {
    const reason = res && res.reason;
    if (!reason || reason === 'no_account') {
      toast('Your account does not exist on that server.', 'warning');
      return;
    }
    showConfirm({ title: 'Could not switch', confirmText: 'Open Manage InterLink',
      body: `Your account isn't the problem: ${E(REASON[reason] || 'the link failed')}.` + (res.detail ? `<br><br><code style="word-break:break-word;font-size:12px">${E(res.detail)}</code>` : ''),
      onConfirm: () => window.openInterlinkModal() });
  };
})();
