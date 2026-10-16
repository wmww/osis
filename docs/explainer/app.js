// Router and presentation engine. Routes: "#/" (topic grid) and "#/<deck-id>/<slide 1-based>".
import decks from './decks/index.js';
import { arrowheads, cropToContent } from './lib/svg.js';

const $ = s => document.querySelector(s);
const view = $('#view'), pager = $('#pager'), crumb = $('#crumb'), replayBtn = $('#replay');
const prev = $('#prev'), next = $('#next'), dots = $('#dots');

let current = null;      // { deckIdx, index }
let rendered = null;     // "<mode>:<deck id>" in the view; page mode scrolls within it instead of re-rendering
let cleanups = [];       // teardowns returned by slides' enter()
let observers = [];
const seen = new Set();  // "deck/index" visited this session, for progress dots

// ---------- Theme: follows the browser until toggled; the choice is remembered. ----------
const systemDark = matchMedia('(prefers-color-scheme: dark)');
const isDark = () => (document.documentElement.dataset.theme ?? (systemDark.matches ? 'dark' : 'light')) === 'dark';
$('#theme').addEventListener('click', () => {
  const t = isDark() ? 'light' : 'dark';
  // Back to "follow the system" when the choice matches it.
  if ((t === 'dark') === systemDark.matches) delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = t;
  try {
    if (document.documentElement.dataset.theme) localStorage.setItem('osis-theme', t);
    else localStorage.removeItem('osis-theme');
  } catch {}
});

// ---------- View mode: slides (one at a time) or page (whole deck, scrolling). Remembered. ----------
const modeBtn = $('#mode');
let mode = 'slides';
try { if (localStorage.getItem('osis-view') === 'page') mode = 'page'; } catch {}
function syncModeBtn() {
  const label = mode === 'page' ? 'Switch to slides' : 'Switch to one scrolling page';
  modeBtn.title = modeBtn.ariaLabel = label;
  modeBtn.dataset.mode = mode;
}
syncModeBtn();
modeBtn.addEventListener('click', () => {
  mode = mode === 'page' ? 'slides' : 'page';
  try { localStorage.setItem('osis-view', mode); } catch {}
  syncModeBtn();
  rendered = null;
  route();
});

// ---------- Rendering ----------
const href = (deck, i) => `#/${deck.id}/${i + 1}`;
const call = v => (typeof v === 'function' ? v() : v ?? '');

function teardown() {
  for (const c of cleanups) { try { c(); } catch (e) { console.error(e); } }
  cleanups = [];
  observers.forEach(o => o.disconnect());
  observers = [];
  removeEventListener('resize', fit);
}

function renderHome() {
  teardown();
  current = rendered = null;
  document.title = 'osis explained';
  crumb.textContent = '';
  pager.hidden = replayBtn.hidden = modeBtn.hidden = true;
  view.innerHTML = `
    <section class="home">
      <div class="hero">
        <h1>A local-first data layer that many apps share.</h1>
        <p>osis stores small-to-large interconnected data (notes, calendars, spreadsheets) on your devices, syncs it between people with no central server, and lets any app, version or agent work on the same data, the way files work today.</p>
        <p class="note">osis is at the design stage. These slides describe the design, not shipped code.</p>
      </div>
      <div class="grid">
        ${decks.map((d, i) => `
          <a class="card ap" style="--d:${(i * 0.05).toFixed(2)}s" href="${href(d, 0)}">
            <span class="num">${String(i + 1).padStart(2, '0')}</span>
            <div class="ico">${call(d.icon)}</div>
            <h2>${d.title}</h2>
            <p>${d.blurb}</p>
          </a>`).join('')}
      </div>
    </section>`;
  window.scrollTo(0, 0);
}

/** One slide's markup, shared by both modes. */
function slideHtml(s, i, cls = '') {
  const more = s.more ? `<button class="more-btn" popovertarget="more-${i}" title="Details" aria-label="Details">?</button>
    <div class="more" id="more-${i}" popover>${s.more}</div>` : '';
  return `<article class="slide ${cls}" id="s${i + 1}">
      <h1>${s.title}</h1>
      <div class="stage">${call(s.stage)}</div>
      <div class="caption">${call(s.text)}${more}</div>
    </article>`;
}

/** Finish a rendered slide: tidy diagrams, then run its enter() hook. */
function mount(el, s) {
  // Demos re-render their diagrams, so they crop (or not) themselves.
  el.querySelectorAll('.stage .dia').forEach(d => d.closest('.demo') || cropToContent(d));
  arrowheads(el);
  if (s.enter) { const c = s.enter(el); if (c) cleanups.push(c); }
}

const deckLinks = deckIdx => {
  const prevDeck = decks[deckIdx - 1], nextDeck = decks[deckIdx + 1];
  return {
    prev: prevDeck ? [href(prevDeck, 0), prevDeck.title] : ['#/', 'All topics'],
    next: nextDeck ? [href(nextDeck, 0), `Next: ${nextDeck.title}`] : ['#/', 'All topics'],
  };
};

function renderSlide(deckIdx, index, dir) {
  teardown();
  const deck = decks[deckIdx];
  const s = deck.slides[index];
  current = { deckIdx, index };
  rendered = `slides:${deck.id}`;
  seen.add(`${deck.id}/${index}`);
  document.title = `${s.title} · ${deck.title} · osis`;
  crumb.textContent = deck.title;
  view.innerHTML = `<section class="deck slides">${slideHtml(s, index, dir < 0 ? 'back' : '')}</section>`;
  const root = view.querySelector('.slide');
  mount(root, s);
  fit();
  addEventListener('resize', fit);

  // Pager: back/next cross deck boundaries so the whole site reads as one path.
  const prevDeck = decks[deckIdx - 1], links = deckLinks(deckIdx);
  setLink(prev, index > 0 ? href(deck, index - 1) : prevDeck ? href(prevDeck, prevDeck.slides.length - 1) : '#/',
    index > 0 ? 'Back' : links.prev[1]);
  const last = index === deck.slides.length - 1;
  setLink(next, ...(!last ? [href(deck, index + 1), 'Next'] : links.next));
  dots.innerHTML = deck.slides.map((sl, i) =>
    `<a href="${href(deck, i)}" class="${i === index ? 'on' : seen.has(`${deck.id}/${i}`) ? 'seen' : ''}" title="${sl.title}" aria-label="Slide ${i + 1}"></a>`).join('');
  pager.hidden = modeBtn.hidden = false;
  replayBtn.hidden = !root.querySelector('.ap, .draw, animateMotion') && !s.enter;
  window.scrollTo(0, 0);
}

/** Slides mode: shrink the diagram so title, diagram and caption fit above the pager without scrolling. */
function fit() {
  const stage = view.querySelector('.slides .stage'), dia = stage?.querySelector('.dia');
  if (!dia) return;
  stage.style.removeProperty('--fit');
  if (innerWidth <= 560) return; // phones scroll diagrams sideways instead
  const room = innerHeight - (document.documentElement.scrollHeight - dia.getBoundingClientRect().height);
  // Set on the stage so it also applies to diagrams a demo re-renders.
  stage.style.setProperty('--fit', `${Math.max(240, room)}px`);
}

function renderPage(deckIdx, index) {
  const deck = decks[deckIdx];
  const go = () => document.getElementById(`s${index + 1}`)?.scrollIntoView({ block: 'start' });
  if (rendered === `page:${deck.id}`) return index === 0 ? window.scrollTo({ top: 0, behavior: 'smooth' }) : go();
  teardown();
  current = { deckIdx, index };
  rendered = `page:${deck.id}`;
  document.title = `${deck.title} · osis`;
  crumb.textContent = deck.title;
  pager.hidden = replayBtn.hidden = true;
  modeBtn.hidden = false;
  const { prev: p, next: n } = deckLinks(deckIdx);
  view.innerHTML = `<section class="deck page">
      <header class="page-head"><h1>${deck.title}</h1><p>${deck.blurb}</p></header>
      ${deck.slides.map((s, i) => slideHtml(s, i, 'idle')).join('')}
      <nav class="page-nav"><a class="pg" href="${p[0]}"><span class="arr">←</span><span class="lbl">${p[1]}</span></a>
        <a class="pg next" href="${n[0]}"><span class="lbl">${n[1]}</span><span class="arr">→</span></a></nav>
    </section>`;
  const els = [...view.querySelectorAll('.page .slide')];
  els.forEach((el, i) => {
    mount(el, deck.slides[i]);
    el.querySelectorAll('svg.dia').forEach(svg => { svg.pauseAnimations(); svg.setCurrentTime(0); });
  });

  // Animations start when a slide scrolls into view.
  const play = new IntersectionObserver(es => es.forEach(e => {
    if (!e.isIntersecting) return;
    e.target.classList.remove('idle');
    e.target.querySelectorAll('svg.dia').forEach(svg => svg.unpauseAnimations());
    play.unobserve(e.target);
  }), { threshold: 0.3 });
  // Keep the URL on the slide being read, without triggering a route.
  const spy = new IntersectionObserver(es => es.forEach(e => {
    if (!e.isIntersecting) return;
    const i = els.indexOf(e.target);
    current.index = i;
    seen.add(`${deck.id}/${i}`);
    history.replaceState(null, '', href(deck, i));
  }), { rootMargin: '-35% 0px -60% 0px' });
  els.forEach(el => { play.observe(el); spy.observe(el); });
  observers.push(play, spy);
  if (index > 0) go(); else window.scrollTo(0, 0);
}

function setLink(a, url, label) {
  a.href = url;
  a.querySelector('.lbl').textContent = label;
  a.setAttribute('aria-label', label);
}

// ---------- Routing ----------
function route() {
  const [, id, n] = location.hash.match(/^#\/([\w-]+)(?:\/(\d+))?/) ?? [];
  const deckIdx = decks.findIndex(d => d.id === id);
  if (deckIdx < 0) return renderHome();
  const deck = decks[deckIdx];
  const index = Math.min(Math.max((parseInt(n, 10) || 1) - 1, 0), deck.slides.length - 1);
  if (mode === 'page') return renderPage(deckIdx, index);
  const dir = current && (current.deckIdx > deckIdx || (current.deckIdx === deckIdx && current.index > index)) ? -1 : 1;
  renderSlide(deckIdx, index, dir);
}
addEventListener('hashchange', route);
route();

function replay() {
  if (current && mode === 'slides') renderSlide(current.deckIdx, current.index, 0);
}
replayBtn.addEventListener('click', replay);

// ---------- Keyboard and swipe ----------
addEventListener('keydown', e => {
  if (e.metaKey || e.ctrlKey || e.altKey || e.target.closest('input, textarea, select')) return;
  if (document.querySelector('.more:popover-open')) return;
  if (!current || mode === 'page') { if (e.key === 'Escape' && current) location.hash = '#/'; return; }
  if (['ArrowRight', 'PageDown'].includes(e.key) || (e.key === ' ' && !e.target.closest('button'))) { e.preventDefault(); location.hash = next.getAttribute('href'); }
  else if (['ArrowLeft', 'PageUp'].includes(e.key)) { e.preventDefault(); location.hash = prev.getAttribute('href'); }
  else if (e.key === 'Escape') location.hash = '#/';
  else if (e.key === 'r' || e.key === 'R') replay();
});
let touch = null;
addEventListener('touchstart', e => { touch = e.touches.length === 1 && !e.target.closest('.stage') ? [e.touches[0].clientX, e.touches[0].clientY] : null; }, { passive: true });
addEventListener('touchend', e => {
  if (!touch || !current || mode === 'page') return;
  const dx = e.changedTouches[0].clientX - touch[0], dy = e.changedTouches[0].clientY - touch[1];
  if (Math.abs(dx) > 70 && Math.abs(dx) > Math.abs(dy) * 1.5) location.hash = (dx < 0 ? next : prev).getAttribute('href');
  touch = null;
}, { passive: true });
