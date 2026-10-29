'use strict';
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const store = {
    get(k, d) { try { const v = localStorage.getItem('osis-mockup:' + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem('osis-mockup:' + k, JSON.stringify(v)); } catch { /* private mode */ } },
  };


  const things = DATA.things;
  const byId = new Map(things.map(t => [t.id, t]));
  const get = id => byId.get(id);
  let favs = store.get('favs', DATA.favorites).filter(id => byId.has(id));
  // themes: the built-ins plus one custom theme made by editing any of them (themes.js)
  // a custom theme saved before a parameter existed takes that parameter from the first built-in
  let custom = store.get('custom', null);
  if (custom) custom = { ...THEMES[0], ...custom, id: 'custom' };
  // ...and an enum value that no longer exists falls back the same way
  if (custom) for (const p of THEME_PARAMS) if (p.opts && !p.opts.includes(custom[p.k])) custom[p.k] = THEMES[0][p.k];
  const themes = () => custom ? [...THEMES, custom] : THEMES;
  let themeId = store.get('theme', 'frost');
  if (!themes().some(x => x.id === themeId)) themeId = 'frost';
  const theme = () => themes().find(x => x.id === themeId);
  let editOpen = store.get('editOpen', false);
  let looksOpen = store.get('looksOpen', true);
  let mode = store.get('mode', 'auto');
  if (!['auto', 'light', 'dark'].includes(mode)) mode = 'auto';
  let q = '';
  let focusTitle = false;

  const app = $('#app');
  const spotEl = $('#spot');
  const spotQ = $('#spot-q');
  const looksEl = $('#looks');

  // ---------- icons
  const ICON = {
    note: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 16h4"/>',
    event: '<rect x="4" y="5" width="16" height="15" rx="2.5"/><path d="M4 10h16M9 3v4M15 3v4"/>',
    calendar: '<rect x="4" y="5" width="16" height="15" rx="2.5"/><path d="M4 10h16M9 3v4M15 3v4"/><path d="M8 14h.01M12 14h.01M16 14h.01M8 17h.01M12 17h.01"/>',
    contact: '<circle cx="12" cy="9" r="3.6"/><path d="M5 20c.9-3.6 3.6-5.4 7-5.4s6.1 1.8 7 5.4"/>',
    people: '<circle cx="9" cy="9" r="3.2"/><circle cx="17" cy="10" r="2.4"/><path d="M3 20c.7-3.3 3-5 6-5s5.3 1.7 6 5M15.5 15.2c2.6-.2 4.6 1.2 5.5 4.3"/>',
    tag: '<path d="M3.5 12.5V4.5h8l9 9-8 8z"/><circle cx="8" cy="9" r="1.4"/>',
    tags: '<path d="M2.5 13V6h7l8 8-6.5 6.5z"/><path d="M12 6h1.5l8 8L15 20.5"/><circle cx="6.5" cy="10" r="1.2"/>',
    recent: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
    search: '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4.2-4.2"/>',
    star: '<path d="M12 3.5l2.6 5.3 5.9.9-4.3 4.1 1 5.8L12 16.8l-5.2 2.8 1-5.8-4.3-4.1 5.9-.9z"/>',
    back: '<path d="M15 5l-7 7 7 7"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.8"/>',
    clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
    pin: '<path d="M12 21s-6.5-6.2-6.5-11a6.5 6.5 0 0 1 13 0c0 4.8-6.5 11-6.5 11z"/><circle cx="12" cy="10" r="2.3"/>',
  };
  const icon = n => `<svg class="i" viewBox="0 0 24 24" aria-hidden="true">${ICON[n]}</svg>`;

  // ---------- model helpers
  const fmtDay = new Intl.DateTimeFormat(undefined, { weekday: 'short', day: 'numeric', month: 'short' });
  const fmtWd = new Intl.DateTimeFormat(undefined, { weekday: 'short' });
  const fmtTime = new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' });
  const sameDay = (a, b) => a.toDateString() === b.toDateString();
  function ago(d) {
    if (!d) return 'a while ago';
    const m = Math.round((Date.now() - d) / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return m + ' min ago';
    const h = Math.round(m / 60);
    return h < 24 ? h + ' h ago' : Math.round(h / 24) + ' d ago';
  }
  const tagsOf = t => (t.tags || []).map(get).filter(Boolean);
  const itemsIn = g => things.filter(t => (t.tags || []).includes(g.id));
  const subTags = g => things.filter(t => t.kind === 'tag' && t.parent === g.id);
  const ofKind = k => things.filter(t => t.kind === k);
  const events = () => ofKind('event').sort((a, b) => a.start - b.start);
  const inWeek = e => e.start >= DATA.monday && e.start < +DATA.monday + 7 * 86400000;
  const linkedTo = t => things.filter(x => (x.with || []).includes(t.id));
  function tintOf(t) {
    if (!t) return null;
    if (t.color) return t.color;
    const g = tagsOf(t)[0];
    return g ? g.color : null;
  }
  const tintStyle = t => { const c = tintOf(t); return c ? ` style="--tint:${c}"` : ''; };
  const iconFor = t => t.kind === 'view' ? t.view : t.kind;
  function kindLabel(t) {
    if (t.kind === 'event') return t.body ? 'Event · Note' : 'Event';
    return { note: 'Note', contact: 'Person', tag: 'Tag', view: 'View' }[t.kind];
  }
  const when = e => `${fmtDay.format(e.start)} · ${fmtTime.format(e.start)}–${fmtTime.format(e.end)}`;
  const firstLine = s => (s || '').split('\n').find(l => l.trim()) || '';
  function subtitle(t) {
    switch (t.kind) {
      case 'note': return firstLine(t.body) || 'Empty note';
      case 'event': return when(t);
      case 'contact': return t.role || t.email || '';
      case 'tag': { const n = itemsIn(t).length + subTags(t).length; return n + (n === 1 ? ' item' : ' items') + (t.shared ? ' · shared' : ''); }
      case 'view':
        switch (t.view) {
          case 'calendar': return events().filter(inWeek).length + ' events this week';
          case 'people': return ofKind('contact').length + ' people';
          case 'tags': return ofKind('tag').length + ' tags';
          case 'recent': return 'Last touched first';
        }
    }
    return '';
  }
  function visibleTo(t) {
    const via = [t, ...tagsOf(t)].filter(g => g.kind === 'tag' && g.shared);
    if (!via.length) return { who: 'Only you', via: '' };
    const names = [...new Set(via.flatMap(g => g.shared))];
    return { who: 'You, ' + names.join(', '), via: 'via ' + via.map(g => g.name).join(', ') };
  }

  // ---------- search
  function search(query) {
    const s = query.trim().toLowerCase();
    const scopes = [], named = [], content = [];
    for (const t of things) {
      const hay = (t.name || '').toLowerCase();
      if (t.kind === 'tag' || t.kind === 'view') { if (hay.includes(s)) scopes.push(t); continue; }
      if (hay.includes(s)) { named.push(t); continue; }
      const text = [t.body, t.place, t.role, t.email].filter(Boolean).join('\n');
      const i = text.toLowerCase().indexOf(s);
      if (i >= 0) {
        const a = Math.max(0, i - 10), b = Math.min(text.length, i + s.length + 40);
        const snip = (a ? '…' : '') + esc(text.slice(a, i)) + '<mark>' + esc(text.slice(i, i + s.length)) + '</mark>' + esc(text.slice(i + s.length, b)) + (b < text.length ? '…' : '');
        content.push({ t, snip: snip.replace(/\n/g, ' · ') });
      }
    }
    const seen = new Set([...named, ...content.map(c => c.t)]);
    const inScopes = things.filter(t => !seen.has(t) && t.kind !== 'tag' && t.kind !== 'view' && tagsOf(t).some(g => scopes.includes(g)));
    return { scopes, named, content, inScopes, total: scopes.length + named.length + content.length };
  }
  const section = (label, inner, cls = 'grid') => `<div class="section-label"><span>${label}</span></div><div class="${cls}">${inner}</div>`;
  function results(query) {
    const r = search(query);
    if (!r.total) return `<p class="empty">Nothing matches “${esc(query.trim())}”.</p>`;
    let h = '';
    if (r.scopes.length) h += section('Scopes', r.scopes.map(t => tile(t)).join(''));
    if (r.named.length) h += section('Things', r.named.map(t => tile(t)).join(''));
    if (r.content.length) h += section('Mentions', r.content.map(c => tile(c.t, { sub: c.snip })).join(''));
    if (r.inScopes.length) h += section('In those scopes', r.inScopes.map(t => tile(t)).join(''));
    return h;
  }

  // ---------- pieces
  function tile(t, o = {}) {
    const cls = ['tile', 'k-' + t.kind];
    if (o.row) cls.push('row');
    if (t.kind === 'tag' || t.kind === 'view') cls.push('scope');
    return `<a class="${cls.join(' ')}" href="#/t/${t.id}"${tintStyle(t)}${o.current ? ' aria-current="page"' : ''} draggable="false">
      <span class="tile-ic">${t.kind === 'contact' ? `<b>${initials(t)}</b>` : icon(iconFor(t))}</span>
      <span class="tile-text"><span class="tile-name">${esc(t.name || 'Untitled')}</span><span class="tile-sub">${o.sub ?? esc(subtitle(t))}</span></span>
    </a>`;
  }
  const initials = t => esc((t.name || '?').split(/\s+/).map(w => w[0]).slice(0, 2).join(''));
  const chip = x => `<a class="chip" href="#/t/${x.id}"${tintStyle(x)}><i class="dot"></i>${esc(x.name)}</a>`;

  function home() {
    return `<main class="home"><div class="home-inner">
      <header class="home-head"><a class="brand" href="#/">osis</a></header>
      <label class="search-field">${icon('search')}<input id="home-q" type="text" placeholder="Search notes, people, tags, views…" value="${esc(q)}" autocomplete="off" spellcheck="false"></label>
      <div id="home-body">${homeBody()}</div>
    </div></main>`;
  }
  function homeBody() {
    if (q.trim()) return results(q);
    return `<div class="section-label"><span>Favorites</span><span class="hint">drag to reorder</span></div>
      <ol class="grid fav-grid">${favs.map(id => `<li draggable="true" data-fav="${id}">${tile(get(id))}</li>`).join('')}
        <li><button class="tile tile-new" data-act="new"><span class="tile-ic">${icon('plus')}</span><span class="tile-text"><span class="tile-name">New note</span><span class="tile-sub">or event, person, tag…</span></span></button></li>
      </ol>`;
  }
  const favRail = cur => favs.map(id => `<li draggable="true" data-fav="${id}">${tile(get(id), { row: true, current: id === cur })}</li>`).join('');

  function shell(t) {
    const fav = favs.includes(t.id);
    return `<div class="shell">
      <nav class="rail panel">
        <a class="brand rail-brand" href="#/">osis</a>
        <button class="rail-search" data-act="search">${icon('search')}<span>Search</span><kbd>/</kbd></button>
        <div class="section-label"><span>Favorites</span></div>
        <ol class="fav-list">${favRail(t.id)}</ol>
        <button class="rail-new" data-act="new">${icon('plus')}<span>New note</span></button>
      </nav>
      <section class="pane">
        <header class="pane-bar">
          <a class="icon-btn back" href="#/" aria-label="Back">${icon('back')}</a>
          <span class="pane-kind"${tintStyle(t)}>${icon(iconFor(t))}${kindLabel(t)}</span>
          <span class="spacer"></span>
          <button class="icon-btn star${fav ? ' on' : ''}" data-act="fav" aria-pressed="${fav}" aria-label="Favorite" title="Favorite">${icon('star')}</button>
          <button class="icon-btn narrow-only" data-act="search" aria-label="Search">${icon('search')}</button>
        </header>
        <div class="pane-body panel">${body(t)}</div>
      </section>
    </div>`;
  }

  function body(t) {
    switch (t.kind) {
      case 'note': case 'event': return thingView(t);
      case 'contact': return contactView(t);
      case 'tag': return tagView(t);
      case 'view': return ({ calendar: calendarView, people: peopleView, tags: tagsView, recent: recentView })[t.view](t);
    }
  }

  function meta(t) {
    const v = visibleTo(t);
    const linked = linkedTo(t);
    const withs = (t.with || []).map(get).filter(Boolean);
    return `<aside class="meta">
      <div class="meta-sec"><div class="meta-h">${icon('eye')}Visible to</div><div>${esc(v.who)}</div>${v.via ? `<div class="muted small">${esc(v.via)}</div>` : ''}</div>
      ${withs.length ? `<div class="meta-sec"><div class="meta-h">With</div>${withs.map(x => tile(x, { row: true })).join('')}</div>` : ''}
      ${linked.length ? `<div class="meta-sec"><div class="meta-h">Linked from</div>${linked.map(x => tile(x, { row: true })).join('')}</div>` : ''}
      <div class="meta-sec"><div class="meta-h">${icon('clock')}History</div><div>Edited ${ago(t.edited)}</div><button class="link-btn" data-act="noop">Undo last change</button></div>
    </aside>`;
  }

  function thingView(t) {
    return `<article class="thing"><div class="thing-main">
      <input class="title-input" data-field="name" value="${esc(t.name)}" placeholder="Untitled" spellcheck="false">
      ${t.kind === 'event' ? `<div class="inset facet-event">${icon('event')}<div><div class="when">${esc(when(t))}</div>${t.place ? `<div class="muted small">${esc(t.place)}</div>` : ''}</div></div>` : ''}
      <div class="chips">${tagsOf(t).map(chip).join('')}<button class="chip chip-add" data-act="noop">${icon('plus')}Tag</button></div>
      <textarea class="body-input" data-field="body" placeholder="Write something…">${esc(t.body || '')}</textarea>
    </div>${meta(t)}</article>`;
  }

  function contactView(t) {
    const first = (t.name || '').split(' ')[0] || 'them';
    return `<article class="thing"><div class="thing-main">
      <div class="person-head"><span class="avatar"${tintStyle(t)}>${initials(t)}</span>
        <div class="grow"><input class="title-input" data-field="name" value="${esc(t.name)}" placeholder="Name"><div class="muted">${esc(t.role || '')}</div></div></div>
      <dl class="fields inset">
        ${t.email ? `<dt>Email</dt><dd>${esc(t.email)}</dd>` : ''}
        ${t.phone ? `<dt>Phone</dt><dd>${esc(t.phone)}</dd>` : ''}
        ${t.place ? `<dt>Where</dt><dd>${esc(t.place)}</dd>` : ''}
      </dl>
      <textarea class="body-input short" data-field="body" placeholder="Notes about ${esc(first)}…">${esc(t.body || '')}</textarea>
    </div>${meta(t)}</article>`;
  }

  function tagView(t) {
    const subs = subTags(t), items = itemsIn(t), parent = get(t.parent), v = visibleTo(t);
    return `<div class="scope-head"><span class="swatch"${tintStyle(t)}></span>
        <div class="grow"><input class="title-input" data-field="name" value="${esc(t.name)}">
        <div class="muted small">${parent ? `in ${chip(parent)} · ` : ''}${esc(v.who)}${t.shared ? ' · <button class="link-btn" data-act="noop">Share settings</button>' : ''}</div></div></div>
      ${subs.length ? section('Tags inside', subs.map(x => tile(x)).join('')) : ''}
      ${section('Items', items.map(x => tile(x)).join('') || '<p class="empty">Nothing tagged yet.</p>')}`;
  }

  function viewHead(t) {
    return `<div class="scope-head"><span class="swatch"${tintStyle(t)}>${icon(iconFor(t))}</span><h1 class="view-title">${esc(t.name)}</h1></div>`;
  }
  function calendarView(t) {
    const today = new Date();
    const days = [...Array(7)].map((_, i) => new Date(+DATA.monday + i * 86400000));
    return viewHead(t) + `<div class="cal">${days.map(d => {
      const evs = events().filter(e => sameDay(e.start, d));
      return `<section class="cal-day inset${sameDay(d, today) ? ' today' : ''}">
        <h3><span>${fmtWd.format(d)}</span><span class="dnum">${d.getDate()}</span></h3>
        ${evs.length ? evs.map(e => tile(e, { row: true, sub: esc(fmtTime.format(e.start) + (e.place ? ' · ' + e.place : '')) })).join('') : '<p class="muted small free">Free</p>'}
      </section>`;
    }).join('')}</div>`;
  }
  const peopleView = t => viewHead(t) + `<div class="grid">${ofKind('contact').map(x => tile(x)).join('')}</div>`;
  const tagsView = t => viewHead(t) + `<div class="grid">${ofKind('tag').map(x => tile(x)).join('')}</div>`;
  const recentView = t => viewHead(t) + `<div class="grid">${things.filter(x => x.edited).sort((a, b) => b.edited - a.edited).map(x => tile(x, { sub: esc(ago(x.edited)) })).join('')}</div>`;

  // ---------- main colour and background seed, both from the open thing
  // main: the thing's own colour, else the first colour among what it holds or links, else a soft grey
  function mainColor(t) {
    let near = [t, ...tagsOf(t), ...(t.with || []).map(get).filter(Boolean)];
    if (t.kind === 'tag') near = [t, ...subTags(t), ...itemsIn(t)];
    else if (t.kind === 'view') near = [t, ...({
      calendar: () => events().filter(inWeek), people: () => ofKind('contact'), tags: () => ofKind('tag'),
      recent: () => things.filter(x => x.edited).sort((a, b) => b.edited - a.edited),
    })[t.view]()];
    return near.map(tintOf).find(Boolean) || null;
  }
  const kindKey = t => !t ? 'home' : t.kind === 'view' ? t.view : t.kind;
  function applyBg(t) {
    const st = document.body.style;
    st.setProperty('--main', (t && mainColor(t)) || NEUTRAL_MAIN);
    // four seeds in [0, 1) hashed from the id: each thing keeps its own arrangement of the theme's background
    let h = [...(t ? t.id : 'home')].reduce((a, ch) => (a * 31 + ch.charCodeAt(0)) >>> 0, 7);
    for (let i = 1; i <= 4; i++) { h = (h * 1103515245 + 12345) >>> 0; st.setProperty('--s' + i, ((h >>> 8) % 1000) / 1000); }
    document.body.dataset.kind = kindKey(t);
  }

  // ---------- render
  const routeId = () => { const m = location.hash.match(/^#\/t\/(.+)$/); return m ? decodeURIComponent(m[1]) : null; };
  const current = () => get(routeId());
  function render() {
    const t = current();
    app.innerHTML = t ? shell(t) : home();
    applyBg(t);
    document.title = t ? `${t.name || 'Untitled'} · osis mockup` : 'osis mockup';
    if (focusTitle) { focusTitle = false; $('.title-input')?.focus(); }
  }
  function refreshRail() { const l = $('.fav-list'); if (l) l.innerHTML = favRail(routeId()); }

  function openSpot() {
    spotEl.hidden = false;
    spotQ.value = '';
    $('#spot-results').innerHTML = spotIdle();
    spotQ.focus();
  }
  function closeSpot() { spotEl.hidden = true; }
  const spotIdle = () => section('Jump to', favs.map(id => tile(get(id), { row: true })).join(''), 'rows');

  function newNote() {
    const t = { id: 'n-' + Date.now().toString(36), kind: 'note', name: '', body: '', tags: [], edited: new Date() };
    things.push(t); byId.set(t.id, t);
    focusTitle = true;
    location.hash = '#/t/' + t.id;
  }
  function toggleFav() {
    const t = current(); if (!t) return;
    favs = favs.includes(t.id) ? favs.filter(x => x !== t.id) : [...favs, t.id];
    store.set('favs', favs);
    const b = $('.star'); b.classList.toggle('on'); b.setAttribute('aria-pressed', favs.includes(t.id));
    refreshRail();
  }

  // ---------- events
  document.addEventListener('click', e => {
    const b = e.target.closest('[data-act]');
    if (!b) { if (e.target === spotEl) closeSpot(); return; }
    ({ search: openSpot, new: newNote, fav: toggleFav, noop() {} })[b.dataset.act]?.();
  });
  document.addEventListener('input', e => {
    const el = e.target;
    if (el.id === 'home-q') { q = el.value; $('#home-body').innerHTML = homeBody(); return; }
    if (el.id === 'spot-q') { $('#spot-results').innerHTML = el.value.trim() ? results(el.value) : spotIdle(); return; }
    const f = el.dataset.field, t = current();
    if (f && t) { t[f] = el.value; t.edited = new Date(); if (f === 'name') refreshRail(); }
  });
  document.addEventListener('keydown', e => {
    const typing = /^(INPUT|TEXTAREA)$/.test(document.activeElement?.tagName);
    if (e.key === 'Escape') {
      if (!spotEl.hidden) closeSpot();
      else if (document.activeElement?.id === 'home-q' && q) { q = ''; render(); $('#home-q').focus(); }
      else if (typing) document.activeElement.blur();
      return;
    }
    if (e.key === 'Enter' && (e.target.id === 'home-q' || e.target.id === 'spot-q')) {
      const a = (e.target.id === 'home-q' ? $('#home-body') : $('#spot-results')).querySelector('a.tile');
      if (a) location.hash = a.getAttribute('href');
      return;
    }
    if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === '/') { e.preventDefault(); if (routeId()) openSpot(); else $('#home-q').focus(); }
    else if (e.key === ']' || e.key === '[') { const l = themes(); setTheme(l[(l.indexOf(theme()) + (e.key === ']' ? 1 : l.length - 1)) % l.length].id); }
    else if (/^[1-9]$/.test(e.key) && themes()[e.key - 1]) setTheme(themes()[e.key - 1].id);
    else if (e.key === 'd') setMode(resolvedMode() === 'dark' ? 'light' : 'dark');
  });
  window.addEventListener('hashchange', () => { closeSpot(); render(); window.scrollTo(0, 0); });

  // drag to reorder favorites (home grid and rail)
  let dragEl = null;
  document.addEventListener('dragstart', e => {
    const li = e.target.closest?.('[data-fav]'); if (!li) return;
    dragEl = li; li.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', li.dataset.fav);
  });
  document.addEventListener('dragover', e => {
    if (!dragEl) return;
    const li = e.target.closest?.('[data-fav]');
    if (!li || li.parentNode !== dragEl.parentNode) return;
    e.preventDefault();
    if (li === dragEl) return;
    const r = li.getBoundingClientRect();
    const after = li.parentNode.classList.contains('fav-list') ? e.clientY > r.top + r.height / 2 : e.clientX > r.left + r.width / 2;
    li.parentNode.insertBefore(dragEl, after ? li.nextSibling : li);
  });
  document.addEventListener('drop', e => { if (dragEl) e.preventDefault(); });
  document.addEventListener('dragend', () => {
    if (!dragEl) return;
    const list = dragEl.parentNode;
    dragEl.classList.remove('dragging'); dragEl = null;
    favs = [...list.querySelectorAll('[data-fav]')].map(li => li.dataset.fav);
    store.set('favs', favs);
  });

  // ---------- theme: enums go on body[data-*], numbers and colours on --p-*; engine.css does the rest
  function applyTheme() {
    const th = theme(), b = document.body;
    for (const p of THEME_PARAMS) {
      if (p.opts) b.dataset[p.k] = th[p.k];
      else for (const k of p.keys || [p.k]) b.style.setProperty('--p-' + k.replace(/[A-Z]/g, c => '-' + c.toLowerCase()), th[k]);
    }
    applyBg(current());
  }
  function setTheme(id) { themeId = id; store.set('theme', id); applyTheme(); renderLooks(); }
  // editing a built-in theme forks it into the custom theme
  function setParam(k, v) {
    const fork = theme() !== custom;
    if (fork) { custom = { ...theme(), id: 'custom', name: 'Custom', desc: 'Your edit of ' + theme().name + '.' }; themeId = 'custom'; store.set('theme', 'custom'); }
    custom[k] = v; store.set('custom', custom);
    applyTheme();
    if (fork) renderLooks();
  }

  // ---------- switcher
  // mode: 'auto' follows the system; the resolved light/dark goes on body[data-mode]
  const darkMq = matchMedia('(prefers-color-scheme: dark)');
  const resolvedMode = () => mode === 'auto' ? (darkMq.matches ? 'dark' : 'light') : mode;
  function setMode(m) { mode = m; store.set('mode', m); renderLooks(); }
  darkMq.addEventListener('change', () => { if (mode === 'auto') renderLooks(); });
  // colours come in light and dark pairs; a swatch opens a hue/saturation/lightness picker below its row
  let pickOpen = null;
  function hexToHsl(hex) {
    const n = parseInt(hex.slice(1), 16), [r, g, b] = [n >> 16, n >> 8 & 255, n & 255].map(v => v / 255);
    const mx = Math.max(r, g, b), mn = Math.min(r, g, b), d = mx - mn, l = (mx + mn) / 2;
    const sat = d ? d / (1 - Math.abs(2 * l - 1)) : 0;
    const h = !d ? 0 : mx === r ? ((g - b) / d + 6) % 6 : mx === g ? (b - r) / d + 2 : (r - g) / d + 4;
    return [Math.round(h * 60), Math.round(sat * 100), Math.round(l * 100)];
  }
  function hslToHex(h, sat, l) {
    sat /= 100; l /= 100;
    const f = n => { const k = (n + h / 30) % 12, a = sat * Math.min(l, 1 - l); return Math.round(255 * (l - a * Math.max(-1, Math.min(k - 3, 9 - k, 1)))); };
    return '#' + [f(0), f(8), f(4)].map(v => v.toString(16).padStart(2, '0')).join('');
  }
  const isHex = v => /^#[0-9a-f]{6}$/i.test(v);
  function pickerTracks(h, sat, l) {
    return [`linear-gradient(90deg, ${[0, 60, 120, 180, 240, 300, 360].map(x => `hsl(${x} ${sat}% ${l}%)`).join(', ')})`,
      `linear-gradient(90deg, hsl(${h} 0% ${l}%), hsl(${h} 100% ${l}%))`,
      `linear-gradient(90deg, #000, hsl(${h} ${sat}% 50%), #fff)`];
  }
  function picker(k, v) {
    const hsl = hexToHsl(v), tr = pickerTracks(...hsl);
    return `<div class="lk-picker" data-for="${k}">${['H', 'S', 'L'].map((n, i) => `<label><span>${n}</span><input type="range" class="lk-hsl" data-hsl="${k}" min="0" max="${i ? 100 : 360}" value="${hsl[i]}" style="background:${tr[i]}"></label>`).join('')}
      <input class="lk-hex" data-hex="${k}" value="${v}" spellcheck="false" maxlength="7"></div>`;
  }
  function control(p, v) {
    if (p.opts) return `<select data-p="${p.k}">${p.opts.map(o => `<option${o === v ? ' selected' : ''}>${o}</option>`).join('')}</select>`;
    if (p.type === 'color2') return `<span class="lk-color">${p.keys.map((k, i) => `<span class="lk-sw-l">${i ? 'dark' : 'light'}</span><button class="lk-sw${pickOpen === k ? ' on' : ''}" data-lk="pick-${k}" style="background:${v[i]}" aria-label="Pick ${esc(p.label)} (${i ? 'dark' : 'light'})"></button>`).join('')}</span>`;
    return `<span class="lk-range"><input type="range" data-p="${p.k}" min="${p.min}" max="${p.max}" step="${p.step}" value="${v}"><output>${v}</output></span>`;
  }
  function renderLooks() {
    const th = theme(), rm = resolvedMode(), scroll = looksEl.querySelector('.lk-params')?.scrollTop;
    document.body.dataset.mode = rm;
    looksEl.classList.toggle('open', looksOpen);
    looksEl.innerHTML = `<button class="lk-toggle" data-lk="toggle" aria-expanded="${looksOpen}">Theme: <b>${esc(th.name)}</b><span class="lk-mode">${rm}</span><span class="lk-caret">${looksOpen ? '▾' : '▴'}</span></button>
      <div class="lk-body">
        <div class="lk-modes" role="group" aria-label="Light or dark">${['light', 'dark', 'auto'].map(m => `<button class="lk-m${m === mode ? ' on' : ''}" data-lk="mode-${m}">${m[0].toUpperCase() + m.slice(1)}</button>`).join('')}</div>
        <div class="lk-list">${themes().map((x, i) => `<button class="lk-opt${x === th ? ' on' : ''}" data-lk="theme-${x.id}"><span class="lk-n">${i + 1}</span><span>${esc(x.name)}</span></button>`).join('')}</div>
        <p class="lk-desc">${esc(th.desc)}</p>
        <button class="lk-edit" data-lk="edit" aria-expanded="${editOpen}">${editOpen ? '▾' : '▸'} Edit parameters${th === custom ? '' : ' (makes a custom copy)'}</button>
        ${editOpen ? `<div class="lk-params">${THEME_PARAMS.map(p => `<div class="lk-row"><span>${p.label}</span>${control(p, p.keys ? p.keys.map(k => th[k]) : th[p.k])}</div>${p.keys?.includes(pickOpen) && isHex(th[pickOpen]) ? picker(pickOpen, th[pickOpen]) : ''}`).join('')}</div>
          <button class="lk-copy" data-lk="copy">Copy theme as JSON</button>` : ''}
        <p class="lk-keys">Keys: 1–7 or [ ] themes · d light/dark · / search</p>
      </div>`;
    if (scroll) looksEl.querySelector('.lk-params').scrollTop = scroll;
  }
  looksEl.addEventListener('click', e => {
    const b = e.target.closest('[data-lk]'); if (!b) return;
    const k = b.dataset.lk;
    if (k === 'toggle') { looksOpen = !looksOpen; store.set('looksOpen', looksOpen); renderLooks(); }
    else if (k === 'edit') { editOpen = !editOpen; store.set('editOpen', editOpen); renderLooks(); }
    else if (k === 'copy') { const { id, desc, ...params } = theme(); navigator.clipboard?.writeText(JSON.stringify(params, null, 1)).then(() => { b.textContent = 'Copied'; }, () => {}); }
    else if (k.startsWith('pick-')) { pickOpen = pickOpen === k.slice(5) ? null : k.slice(5); renderLooks(); }
    else if (k.startsWith('mode-')) setMode(k.slice(5));
    else if (k.startsWith('theme-')) setTheme(k.slice(6));
  });
  // apply while dragging, without rebuilding the switcher (a fork into the custom theme rebuilds it once)
  looksEl.addEventListener('input', e => {
    const el = e.target, d = el.dataset;
    if (d.hsl) {
      const box = el.closest('.lk-picker'), [h, sat, l] = [...box.querySelectorAll('.lk-hsl')].map(x => +x.value), hex = hslToHex(h, sat, l);
      pickerTracks(h, sat, l).forEach((t, i) => { box.querySelectorAll('.lk-hsl')[i].style.background = t; });
      box.querySelector('.lk-hex').value = hex;
      looksEl.querySelector(`[data-lk="pick-${d.hsl}"]`).style.background = hex;
      return setParam(d.hsl, hex);
    }
    if (d.hex) { if (isHex(el.value)) setParam(d.hex, el.value.toLowerCase()); return; }
    const p = THEME_PARAMS.find(x => x.k === d.p); if (!p) return;
    const v = p.type === 'range' ? Number(el.value) : el.value;
    if (el.nextElementSibling?.tagName === 'OUTPUT') el.nextElementSibling.textContent = v;
    setParam(p.k, v);
  });
  // a typed hex moves the picker's sliders
  looksEl.addEventListener('change', e => { if (e.target.dataset.hex && isHex(e.target.value)) renderLooks(); });

  applyTheme();
  renderLooks();
  render();
})();
