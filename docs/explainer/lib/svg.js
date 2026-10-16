// Diagram helpers. Each returns an SVG markup string. Shared conventions:
//   c: color role class ('c1'..'c4', 'bad', 'blind', 'acc', 'fgc')
//   d: entrance delay in seconds; when set the element fades in (.ap) or strokes in (.draw)
//   cls: extra classes
// Colors and fonts come from CSS tokens, so diagrams follow the light/dark theme.

const delay = d => (d == null ? '' : ` style="--d:${d}s"`);
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const cx = (...c) => c.filter(Boolean).join(' ');

/** Root diagram element. w/h set the coordinate system; the SVG scales to its container. */
export const svg = (w, h, body, { cls = '', label = '' } = {}) =>
  `<svg class="${cx('dia', cls)}" viewBox="0 0 ${w} ${h}" role="img"${label ? ` aria-label="${esc(label)}"` : ''}>${body}</svg>`;

/** Group, optionally delayed, colored or transformed. */
export const g = (body, { d, c, cls, x = 0, y = 0, attrs = '' } = {}) => {
  // The entrance animation sets CSS transform, which would override a transform attribute, so translate on an outer group.
  const inner = `<g class="${cx(c, d != null && 'ap', cls)}"${delay(d)} ${attrs}>${body}</g>`;
  return x || y ? `<g transform="translate(${x} ${y})">${inner}</g>` : inner;
};

/** Text. Default centered; `anchor: 'start'|'end'` to align. Supports `<tspan>` markup when raw=true. */
export const text = (x, y, s, { c, cls, anchor = 'middle', d, raw = false, attrs = '' } = {}) =>
  `<text x="${x}" y="${y}" text-anchor="${anchor}" class="${cx(c && 'tc', c, cls, d != null && 'ap')}"${delay(d)} ${attrs}>${raw ? s : esc(s)}</text>`;

/** Rounded box with a centered label and optional sub-label. `solid` fills with the role color; `ghost` is dashed outline. */
export const box = (x, y, w, h, { label = '', sub = '', c = 'fgc', d, r = 12, cls, solid, ghost, plain, mono, anchor = 'middle', attrs = '' } = {}) => {
  const tx = anchor === 'start' ? x + 14 : x + w / 2;
  const ty = y + h / 2;
  const tcls = cx(mono && 'mono', 'b');
  const label1 = label ? text(tx, sub ? ty - 9 : ty, label, { cls: tcls, anchor }) : '';
  const label2 = sub ? text(tx, ty + 11, sub, { cls: cx('sub', mono && 'mono'), anchor }) : '';
  return `<g class="${cx('box', c, solid && 'solid', ghost && 'ghost', plain && 'plain', d != null && 'ap', cls)}"${delay(d)} ${attrs}>` +
    `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${r}"/>${label1}${label2}</g>`;
};

/** Straight or curved connector. `curve` bends it sideways by that many units. `head`: 'end'|'both'|false. */
export const arrow = (x1, y1, x2, y2, { c = 'fgc', d, cls, dash, head = 'end', curve = 0, thin, id } = {}) => {
  let p = `M${x1},${y1} L${x2},${y2}`;
  if (curve) {
    const mx = (x1 + x2) / 2, my = (y1 + y2) / 2, dx = x2 - x1, dy = y2 - y1, len = Math.hypot(dx, dy) || 1;
    p = `M${x1},${y1} Q${mx - (dy / len) * curve},${my + (dx / len) * curve} ${x2},${y2}`;
  }
  return path(p, { c, d, cls: cx(cls, head === 'end' && 'arrow', head === 'both' && 'arrow2', dash && 'dash', thin && 'thin'), id });
};

/** Arbitrary stroked path. With `d` it draws itself in. */
export const path = (p, { c = 'fgc', d, cls, id } = {}) => {
  // Drawing in relies on stroke-dasharray, which a dashed line needs for its dashes, so dashed lines fade in instead.
  const dashed = /\bdash\b/.test(cls ?? '');
  return `<path${id ? ` id="${id}"` : ''} d="${p}"${dashed ? '' : ' pathLength="1"'} class="${cx('ln', c, cls, d != null && (dashed ? 'ap' : 'draw'))}"${delay(d)}/>`;
};

/** A dot travelling along path `p` forever (or `repeat` times). Use for data in flight. */
export const packet = (p, { c = 'acc', dur = 2.4, begin = 0, repeat = 'indefinite', r = 5, shape = 'dot', fill = 'freeze', vanish = true } = {}) => {
  const motion = `<animateMotion path="${p}" dur="${dur}s" begin="${begin}s" repeatCount="${repeat}" fill="${fill}" rotate="0"/>`;
  // A finite packet disappears on arrival unless vanish is false.
  const end = repeat !== 'indefinite' && vanish ? `<set attributeName="opacity" to="0" begin="${begin + dur * repeat}s"/>` : '';
  const vis = `<set attributeName="opacity" to="1" begin="${begin}s"/>${end}`;
  const body = shape === 'blob'
    ? `<rect x="-9" y="-7" width="18" height="14" rx="3.5" class="fills"/><path d="M-3,-1 v-2 a3,3 0 0 1 6,0 v2 M-4.5,-1 h9 v5 h-9 z" fill="none" stroke="var(--surface)" stroke-width="1.4"/>`
    : `<circle r="${r}" class="fills"/>`;
  return `<g class="${c}" opacity="0">${body}${vis}${motion}</g>`;
};

/** Device glyph with a label underneath. kind: 'laptop' | 'phone' | 'server'. blind servers get a closed-eye mark. */
export const device = (x, y, { kind = 'laptop', label = '', sub = '', c = 'c1', d, blind } = {}) => {
  let gl;
  if (kind === 'phone') gl = `<rect x="-13" y="-22" width="26" height="44" rx="5" class="fillt glyph"/><path class="glyph" d="M-4,16 h8"/>`;
  else if (kind === 'server') gl = `<rect x="-26" y="-22" width="52" height="19" rx="4" class="fillt glyph"/><rect x="-26" y="3" width="52" height="19" rx="4" class="fillt glyph"/><circle cx="-16" cy="-12.5" r="2" class="tc"/><circle cx="-16" cy="12.5" r="2" class="tc"/>`;
  else gl = `<rect x="-28" y="-20" width="56" height="34" rx="4" class="fillt glyph"/><path class="glyph" d="M-36,19 h72"/>`;
  if (blind) gl += `<g transform="translate(15 -1)"><path class="glyph" style="stroke-width:1.6" d="M-7,0 q7,6 14,0 M-5,3 l-1.5,2.4 M0,4.4 v2.6 M5,3 l1.5,2.4"/></g>`;
  const lbl = label ? text(0, 40, label, { cls: 'b small' }) : '';
  const s = sub ? text(0, 57, sub, { cls: 'sub' }) : '';
  return g(gl + lbl + s, { c, d, x, y });
};

/** Encrypted blob: a small rounded square with a lock. */
export const blob = (x, y, { c = 'blind', d, label = '', size = 26, cls } = {}) => {
  const s = size, h = s / 2;
  const body = `<rect x="${-h}" y="${-h}" width="${s}" height="${s}" rx="${s / 5}" class="fills"/>` +
    `<path d="M${-s * .13},${-s * .02} v${-s * .1} a${s * .13},${s * .13} 0 0 1 ${s * .26},0 v${s * .1} M${-s * .2},${-s * .02} h${s * .4} v${s * .25} h${-s * .4} z" fill="none" stroke="var(--surface)" stroke-width="${Math.max(1.3, s / 16)}"/>` +
    (label ? text(0, h + 13, label, { cls: 'sub' }) : '');
  return g(body, { c, d, x, y, cls });
};

/** Key glyph. */
export const key = (x, y, { c = 'c4', d, scale = 1, label = '' } = {}) =>
  g(`<g transform="scale(${scale})"><circle cx="-7" cy="0" r="6" class="glyph"/><path class="glyph" d="M-1,0 h14 M9,0 v5 M13,0 v4"/></g>` +
    (label ? text(3, 16 * scale + 4, label, { cls: 'sub' }) : ''), { c, d, x, y });

/** Person glyph (an actor) with label. */
export const person = (x, y, { c = 'c1', d, label = '', r = 20 } = {}) =>
  g(`<circle r="${r}" class="fillt"/><circle cy="${-r * .28}" r="${r * .28}" class="tc"/><path class="tc" d="M${-r * .52},${r * .55} a${r * .52},${r * .5} 0 0 1 ${r * 1.04},0 z"/>` +
    (label ? text(0, r + 15, label, { cls: 'b small' }) : ''), { c, d, x, y });

/** Check / cross marks. */
export const check = (x, y, { c = 'c3', d, s = 1 } = {}) =>
  g(`<circle r="${11 * s}" class="fills"/><path d="M${-5 * s},0 l${3.5 * s},${3.5 * s} l${6.5 * s},${-7 * s}" fill="none" stroke="var(--surface)" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>`, { c, d, x, y });
export const cross = (x, y, { c = 'bad', d, s = 1 } = {}) =>
  g(`<circle r="${11 * s}" class="fills"/><path d="M${-4 * s},${-4 * s} l${8 * s},${8 * s} M${4 * s},${-4 * s} l${-8 * s},${8 * s}" fill="none" stroke="var(--surface)" stroke-width="2.4" stroke-linecap="round"/>`, { c, d, x, y });

/** Small pill label (e.g. a timestamp or tag). */
export const pill = (x, y, s, { c = 'fgc', d, solid, mono = true, w } = {}) => {
  const width = w ?? Math.max(28, s.length * (mono ? 8 : 7.4) + 18);
  return box(x - width / 2, y - 12, width, 24, { label: s, c, d, solid, r: 12, mono, cls: 'pill' });
};

// ---------- HTML helpers ----------

/** Lightweight code block. Mark tokens with {k:..} keyword, {t:..} type, {s:..} string, {n:..} number, {cm:..} comment. */
export const code = src => `<pre class="codeblk">${esc(src).replace(/\{(k|t|s|n|cm):([^}]*)\}/g, '<span class="$1">$2</span>')}</pre>`;

/** Grid of colored tiles: [{title, text, c, href}] */
export const tiles = items => `<div class="tiles">${items.map((t, i) => {
  const tag = t.href ? 'a' : 'div';
  return `<${tag} class="tile ${t.c ?? ''} ap"${t.href ? ` href="${t.href}"` : ''} style="--d:${(t.d ?? i * 0.12).toFixed(2)}s"><h3>${t.title}</h3><p>${t.text}</p></${tag}>`;
}).join('')}</div>`;

// ---------- DOM finishing (run after diagrams are inserted) ----------

/** Swap marker arrowheads on drawn-in paths for separate heads that appear as the line arrives. */
export function arrowheads(root) {
  for (const p of root.querySelectorAll('path.draw.arrow, path.draw.arrow2')) {
    const len = p.getTotalLength();
    if (!len) continue;
    const k = 0.7 * (parseFloat(getComputedStyle(p).strokeWidth) || 2);
    const d = parseFloat(p.style.getPropertyValue('--d')) || 0;
    const roles = [...p.classList].filter(c => /^(c\d|bad|blind|acc|fgc)$/.test(c)).join(' ');
    const head = (at, back) => {
      const a = p.getPointAtLength(at), b = p.getPointAtLength(at + (back ? 1 : -1) * Math.min(1, len));
      const deg = Math.atan2(a.y - b.y, a.x - b.x) * 180 / Math.PI;
      return `<g transform="translate(${a.x} ${a.y}) rotate(${deg}) scale(${k})"><path class="ahd ap ${roles}" style="--d:${(d + 0.4).toFixed(2)}s" d="M-7.5,-3.5 L0.5,0 L-7.5,3.5 Z"/></g>`;
    };
    let html = head(len, false);
    if (p.classList.contains('arrow2')) html += head(0, true);
    p.classList.remove('arrow', 'arrow2');
    p.insertAdjacentHTML('afterend', html);
  }
}

/** Trim a diagram's viewBox to its content vertically (keeps full width so text scale stays uniform). */
export function cropToContent(el, pad = 14) {
  const { x, width: w } = el.viewBox.baseVal;
  // Moving dots wait at the origin until they start, so leave them out of the measurement.
  const pk = [...el.querySelectorAll('animateMotion')].map(m => m.parentElement);
  pk.forEach(p => p.style.display = 'none');
  const bb = el.getBBox();
  pk.forEach(p => p.style.display = '');
  if (!bb.height) return;
  const x1 = Math.min(x, bb.x - pad), x2 = Math.max(x + w, bb.x + bb.width + pad);
  el.setAttribute('viewBox', `${x1} ${bb.y - pad} ${x2 - x1} ${bb.height + 2 * pad}`);
}
