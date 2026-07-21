package handlers

// Shared SVG icon helper for the two standalone terminal/console pages
// (terminal_multi.go and lxd_vga.go). Those pages are served on their own and
// do not load the SPA's /static/icons.js, so the glyphs they need are vendored
// here — one copy, referenced by both templates, so the two codebases can't
// drift apart. Keep the paths identical to static/icons.js.
const znasIconsJS = `
var _ICONS = {
    'settings': '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>',
    'chevron-down': '<path d="m6 9 6 6 6-6"/>',
    'chevron-right': '<path d="m9 18 6-6-6-6"/>',
    'check': '<path d="M20 6 9 17l-5-5"/>',
    'x': '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    'laptop': '<rect width="18" height="12" x="3" y="4" rx="2"/><path d="M2 20h20"/>',
    'box': '<path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/>',
    'whale': '<path d="M3 12a5 5 0 0 0 5 5h6a5 5 0 0 0 5-5v-1H3z"/><path d="M4 9h2v2H4zM7 9h2v2H7zM10 9h2v2h-2zM10 6h2v2h-2z"/><path d="M19 12c1.5 0 3-1 3-3-1 0-2 .5-2.5 1"/>',
    'monitor': '<rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/>',
    'image': '<rect width="18" height="18" x="3" y="3" rx="2" ry="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/>',
    'upload': '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" x2="12" y1="3" y2="15"/>',
    'keyboard': '<path d="M10 8h.01"/><path d="M12 12h.01"/><path d="M14 8h.01"/><path d="M16 12h.01"/><path d="M18 8h.01"/><path d="M6 8h.01"/><path d="M7 16h10"/><path d="M8 12h.01"/><rect width="20" height="16" x="2" y="4" rx="2"/>',
    'clipboard': '<rect width="8" height="4" x="8" y="2" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>',
    'menu': '<line x1="4" x2="20" y1="12" y2="12"/><line x1="4" x2="20" y1="6" y2="6"/><line x1="4" x2="20" y1="18" y2="18"/>',
    'copy': '<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
    'link': '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    'play': '<polygon points="6 3 20 12 6 21 6 3"/>',
    'zap': '<path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/>',
    'square': '<rect width="18" height="18" x="3" y="3" rx="2"/>',
    'disc': '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="2"/>',
    'circle-fill': '<circle cx="12" cy="12" r="8" fill="currentColor" stroke="none"/>',
    'terminal': '<polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/>',
    'eject': '<path d="M5 17h14a1 1 0 0 1 0 2H5a1 1 0 0 1 0-2z"/><path d="M12.53 3.4a.7.7 0 0 0-1.06 0l-6.28 7A.7.7 0 0 0 5.72 12h12.56a.7.7 0 0 0 .53-1.6z"/>',
    'mouse': '<rect x="5" y="2" width="14" height="20" rx="7"/><path d="M12 6v4"/>'
};
// Mirror of window.znasIcon() in static/icons.js.
function ico(n, o) {
  o = o || {};
  var b = _ICONS[n];
  if (!b) return '';
  var s = o.size || 16;
  return '<svg class="znas-icon" width="' + s + '" height="' + s +
    '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"' +
    ' stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"' +
    ' style="vertical-align:-0.14em' + (o.color ? ';color:' + o.color : '') + '">' + b + '</svg>';
}
// Sets a label that may start with an inline <svg>: the icon is rendered as
// markup, the rest is appended as a TEXT node. Never let caller-supplied text
// (instance names, ISO filenames) reach innerHTML.
function icoLabel(el, label) {
  el.textContent = '';
  var m = /^(<svg[\s\S]*?<\/svg>)\s*([\s\S]*)$/.exec(String(label));
  if (!m) { el.textContent = label; return; }
  var w = document.createElement('span');
  w.innerHTML = m[1];
  el.appendChild(w);
  if (m[2]) el.appendChild(document.createTextNode(' ' + m[2]));
}
`
