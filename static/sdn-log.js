/*
 * Firewall → Monitor → Firewall log (6.11.27).
 *
 * The packets matched by rules with "Log matching connections", read from the
 * kernel log (GET /api/sdn/log, last 24 h). A rule's hit count on the Rules
 * page opens this page filtered to that rule (window.fwLogFocus). Addresses
 * are plain text: sdn-hostcard.js turns them into hover cards.
 */
(function () {
  'use strict';

  let F = null;
  let entries = [], rate = 10, loadedFor = null, err = '';
  // Filters. The rule filter survives a reload of this tab (sessionStorage).
  const ss = { get: k => { try { return sessionStorage.getItem('znas-fw-log-' + k) || ''; } catch (e) { return ''; } },
               set: (k, v) => { try { sessionStorage.setItem('znas-fw-log-' + k, v); } catch (e) { /* storage blocked */ } } };
  let ruleF = ss.get('rule'), actF = 'all', q = '';

  // Opens the log filtered to one rule (the Rules page's hit counts).
  window.fwLogFocus = id => {
    ruleF = id || ''; ss.set('rule', ruleF); actF = 'all'; q = '';
    if (typeof switchSidebarMode === 'function') switchSidebarMode('firewall');
    window.showPage('fw-log');
  };

  const ruleById = id => F.cfg().rules.find(r => r.id === id);
  const ruleName = r => r ? (r.description || F.epLabel(r.source) + ' → ' + F.epLabel(r.destination)) : '(deleted rule)';
  const ifName = d => (typeof window.ifLabelHTML === 'function' ? window.ifLabelHTML(d) : F.E(d || ''));

  async function load() {
    const want = ruleF;
    const r = await F.api('GET', '/api/sdn/log?limit=1000' + (want ? '&rule=' + encodeURIComponent(want) : ''));
    if (want !== ruleF) return; // the filter changed meanwhile
    if (r.ok) { entries = (r.data && r.data.entries) || []; rate = (r.data && r.data.rate_per_sec) || rate; err = ''; }
    else err = (r.data && r.data.error) || 'The kernel log could not be read';
    loadedFor = want;
  }

  function visible() {
    const s = q.trim().toLowerCase();
    return entries.filter(e => {
      const r = ruleById(e.rule);
      if (actF !== 'all' && (!r || r.action !== actF)) return false;
      if (!s) return true;
      return [e.src, e.dst, e.sport, e.dport, e.proto, e.in, e.out, ruleName(r)].join(' ').toLowerCase().includes(s);
    });
  }

  function render() {
    const c = F.cfg();
    const logged = c.rules.filter(r => r.log);
    const list = visible();
    const fr = ruleF ? ruleById(ruleF) : null;
    const actBadge = r => r ? `<span class="fw-act ${F.E(r.action)}">${F.E(r.action)}</span>` : '<span class="fw-act">?</span>';
    const rows = list.map(e => {
      const r = ruleById(e.rule);
      const t = new Date(e.time);
      return `<tr>
        <td data-v="${t.getTime() || 0}" class="fw-mono" style="white-space:nowrap">${F.E(F.fmtTime(e.time, true))}</td>
        <td style="min-width:200px"><span class="fw-log-rule">${actBadge(r)}<button type="button" class="fw-log-rlink" data-lrule="${F.E(e.rule)}" title="Only this rule">${F.E(ruleName(r))}</button></span></td>
        <td style="white-space:nowrap">${ifName(e.in)}${e.out ? ' <span style="color:var(--text-3)">→</span> ' + ifName(e.out) : ''}</td>
        <td class="fw-mono" data-v="${F.E(e.src)}">${F.E(e.src)}${e.sport ? '<span class="fw-log-port">:' + F.E(e.sport) + '</span>' : ''}</td>
        <td class="fw-mono" data-v="${F.E(e.dst)}">${F.E(e.dst)}${e.dport ? '<span class="fw-log-port">:' + F.E(e.dport) + '</span>' : ''}</td>
        <td>${F.E(e.proto || '')}</td>
        <td class="fw-mono" data-v="${e.len || 0}" style="color:var(--text-3)">${e.len ? F.E(e.len) + ' B' : ''}</td></tr>`;
    }).join('');
    const empty = err ? F.E(err)
      : !logged.length && !ruleF ? 'No rule logs its matches yet. Open a rule and tick <b>Log matching connections</b>, then Apply.'
      : fr && !fr.log ? 'Logging is off for this rule: nothing new is recorded. Turn it on in the rule, then Apply.'
      : entries.length ? 'Nothing matches the filters.'
      : (ruleF ? 'This rule has not matched anything in the last 24 hours.' : 'No logged connection in the last 24 hours.');
    return `
      <div class="fw-filterbar"><span class="fw-filterbar-l">${F.icon('filter', 13)}Filtering</span>
        ${ruleF ? `<span class="fw-ipchip">Rule <b>${F.E(ruleName(fr))}</b><button type="button" id="fw-log-rx" title="Show every logged rule" aria-label="Show every logged rule">${F.icon('x', 12)}</button></span>` : ''}
        <div id="fw-log-rulef" class="fw-quick"></div><div id="fw-log-actf"></div>
        <span class="fw-sub">At most ${F.E(rate)} lines per second are logged for each rule; its hit count on the Rules page counts every packet.</span></div>
      <div class="fw-tcard"><div class="fw-tch"><h3>Logged connections</h3><span class="fw-sub">${list.length === entries.length ? F.E(F.fmtCount(entries.length)) : F.E(list.length) + ' of ' + F.E(entries.length)} · last 24 hours${entries.length >= 1000 ? ' (newest 1,000)' : ''}</span><span style="flex:1"></span>
        <input class="fw-search" id="fw-log-q" placeholder="Search address, port…" value="${F.E(q)}" style="max-width:220px"></div>
        <div class="fw-tscroll"><table class="fw-table" data-sort="fwlog"><thead><tr><th>Time</th><th>Rule</th><th>Interface</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Size</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="7" style="color:var(--text-3);white-space:normal">${empty}</td></tr>`}</tbody></table></div></div>`;
  }

  function wire(root) {
    const c = F.cfg();
    const rx = root.querySelector('#fw-log-rx');
    if (rx) rx.onclick = () => { ruleF = ''; ss.set('rule', ''); entries = []; F.rerender(); load().then(F.rerender); };
    const rb = root.querySelector('#fw-log-rulef');
    if (rb) {
      const opts = [{ value: '', label: 'Every logged rule', section: 'Rules' }];
      c.rules.filter(r => r.log || r.id === ruleF).forEach(r => {
        const i = r.interface ? c.interfaces.find(x => x.id === r.interface) : null;
        opts.push({ value: r.id, label: ruleName(r), section: 'Rules', color: i && i.color, hint: r.action + ' · ' + (i ? i.name : 'Any interface') + (r.log ? '' : ' · logging off') });
      });
      F.picker(rb, opts, ruleF, v => { ruleF = v; ss.set('rule', v); entries = []; F.rerender(); load().then(F.rerender); }, { width: 360, placeholder: 'Every logged rule' });
    }
    F.seg(root.querySelector('#fw-log-actf'), [['all', 'All'], ['allow', 'Allowed'], ['block', 'Blocked'], ['reject', 'Rejected']], actF, v => { actF = v; F.rerender(); });
    const qi = root.querySelector('#fw-log-q');
    qi.oninput = () => { q = qi.value; const pos = qi.selectionStart; F.rerender(); const n = document.getElementById('fw-log-q'); if (n) { n.focus(); n.setSelectionRange(pos, pos); } };
    root.querySelectorAll('[data-lrule]').forEach(b => b.onclick = () => { ruleF = b.dataset.lrule; ss.set('rule', ruleF); entries = []; F.rerender(); load().then(F.rerender); });
  }

  function register() {
    if (typeof window.sdnRegisterPage !== 'function' || !window.sdnFW || !window.sdnFW.epLabel) { setTimeout(register, 200); return; }
    F = window.sdnFW;
    window.sdnRegisterPage('fw-log', { load, render, wire, pollMs: 5000,
      // no refresh under an open menu or while typing in the search box
      poll: async () => { const a = document.activeElement; if (document.querySelector('#fw-log-rulef .fw-picker-pop') || (a && a.id === 'fw-log-q')) return false; await load(); } });
  }
  register();
})();
