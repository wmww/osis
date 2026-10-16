// Router and presentation engine. Routes: "#/" (topic grid) and "#/<deck-id>/<slide 1-based>".
import decks from './decks/index.js';

const $ = s => document.querySelector(s);
const view = $('#view'), pager = $('#pager'), crumb = $('#crumb'), replayBtn = $('#replay');
const prev = $('#prev'), next = $('#next'), dots = $('#dots');

let cleanup = null;      // teardown returned by the current slide's enter()
let current = null;      // { deck, index }
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

// ---------- Rendering ----------
const href = (deck, i) => `#/${deck.id}/${i + 1}`;
const call = v => (typeof v === 'function' ? v() : v ?? '');

function teardown() {
  if (cleanup) { try { cleanup(); } catch (e) { console.error(e); } }
  cleanup = null;
}

function renderHome() {
  teardown();
  current = null;
  document.title = 'osis explained';
  crumb.textContent = '';
  pager.hidden = true;
  replayBtn.hidden = true;
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

function renderSlide(deckIdx, index, dir) {
  teardown();
  const deck = decks[deckIdx];
  const s = deck.slides[index];
  current = { deckIdx, index };
  seen.add(`${deck.id}/${index}`);
  document.title = `${s.title} · ${deck.title} · osis`;
  crumb.textContent = deck.title;

  const more = s.more ? `<button class="more-btn" popovertarget="more">${s.moreLabel ?? 'Details'}</button>
    <div class="more" id="more" popover>${s.more}</div>` : '';
  view.innerHTML = `
    <section class="deck">
      <article class="slide${dir < 0 ? ' back' : ''}">
        <h1>${s.title}</h1>
        <div class="stage">${call(s.stage)}</div>
        <div class="caption"><div class="txt">${call(s.text)}</div>${more}</div>
      </article>
    </section>`;
  const root = view.querySelector('.slide');
  if (s.enter) cleanup = s.enter(root) ?? null;

  // Pager: back/next cross deck boundaries so the whole site reads as one path.
  const prevDeck = decks[deckIdx - 1], nextDeck = decks[deckIdx + 1];
  setLink(prev, index > 0 ? href(deck, index - 1) : prevDeck ? href(prevDeck, prevDeck.slides.length - 1) : '#/',
    index > 0 ? 'Back' : prevDeck ? prevDeck.title : 'All topics');
  const last = index === deck.slides.length - 1;
  setLink(next, !last ? href(deck, index + 1) : nextDeck ? href(nextDeck, 0) : '#/',
    !last ? 'Next' : nextDeck ? `Next: ${nextDeck.title}` : 'All topics');
  dots.innerHTML = deck.slides.map((sl, i) =>
    `<a href="${href(deck, i)}" class="${i === index ? 'on' : seen.has(`${deck.id}/${i}`) ? 'seen' : ''}" title="${sl.title}" aria-label="Slide ${i + 1}"></a>`).join('');
  pager.hidden = false;
  replayBtn.hidden = !root.querySelector('.ap, .draw, animateMotion') && !s.enter;
  window.scrollTo(0, 0);
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
  const dir = current && (current.deckIdx > deckIdx || (current.deckIdx === deckIdx && current.index > index)) ? -1 : 1;
  renderSlide(deckIdx, index, dir);
}
addEventListener('hashchange', route);
route();

function replay() {
  if (current) renderSlide(current.deckIdx, current.index, 0);
}
replayBtn.addEventListener('click', replay);

// ---------- Keyboard and swipe ----------
addEventListener('keydown', e => {
  if (e.metaKey || e.ctrlKey || e.altKey || e.target.closest('input, textarea, select')) return;
  if (document.querySelector('.more:popover-open')) return;
  if (!current) return;
  if (['ArrowRight', 'PageDown'].includes(e.key) || (e.key === ' ' && !e.target.closest('button'))) { e.preventDefault(); location.hash = next.getAttribute('href'); }
  else if (['ArrowLeft', 'PageUp'].includes(e.key)) { e.preventDefault(); location.hash = prev.getAttribute('href'); }
  else if (e.key === 'Escape') location.hash = '#/';
  else if (e.key === 'r' || e.key === 'R') replay();
});
let touch = null;
addEventListener('touchstart', e => { touch = e.touches.length === 1 && !e.target.closest('.stage') ? [e.touches[0].clientX, e.touches[0].clientY] : null; }, { passive: true });
addEventListener('touchend', e => {
  if (!touch || !current) return;
  const dx = e.changedTouches[0].clientX - touch[0], dy = e.changedTouches[0].clientY - touch[1];
  if (Math.abs(dx) > 70 && Math.abs(dx) > Math.abs(dy) * 1.5) location.hash = (dx < 0 ? next : prev).getAttribute('href');
  touch = null;
}, { passive: true });
