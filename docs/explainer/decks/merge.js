import { svg, g, box, text, arrow, path, packet, device, pill, check, cross, code } from '../lib/svg.js';

const icon = () => svg(300, 92, [
  box(10, 8, 110, 30, { label: 'title: A', c: 'c1', r: 8, mono: true }),
  box(10, 54, 110, 30, { label: 'title: B', c: 'c2', r: 8, mono: true }),
  arrow(124, 23, 176, 42, { c: 'c1' }),
  arrow(124, 69, 176, 50, { c: 'c2' }),
  box(180, 30, 110, 32, { label: 'title: B', c: 'c3', solid: true, r: 8, mono: true }),
].join(''));

// A struct-like card: title bar plus rows of [field, value, time, color|null, extraClass].
const card = (x, y, w, title, rows, { c, d } = {}) => {
  const h = 40 + rows.length * 34;
  return g(box(x, y, w, h, c ? { c } : { plain: true }) +
    text(x + 16, y + 20, title, { anchor: 'start', cls: 'b small' }) +
    rows.map(([f, v, t, rc, cls], i) => {
      const ry = y + 52 + i * 34;
      return g(
        (rc ? box(x + 8, ry - 14, w - 16, 28, { c: rc, solid: false, r: 7 }) : '') +
        text(x + 18, ry, `${f}:`, { anchor: 'start', cls: 'mono muted' }) +
        text(x + 78, ry, v, { anchor: 'start', cls: 'mono' }) +
        text(x + w - 18, ry, t, { anchor: 'end', cls: 'mono muted' }), { cls });
    }).join(''), { d });
};

// A row of character cells. chars: [[ch, color|null]]
const CW = 50;
const cells = (x, y, chars, { d } = {}) => g(chars.map(([ch, c], i) =>
  box(x + i * CW, y, CW - 6, 44, { label: ch, c: c ?? 'fgc', solid: !!c, r: 8 })).join(''), { d });

// ---------- Interactive LWW demo ----------
const demoHtml = `
<div class="dk-merge demo">
<style>
  .dk-merge .mg-row { display: grid; grid-template-columns: 1fr minmax(120px, .8fr) 1fr; gap: 14px; align-items: stretch; }
  .dk-merge .mg-dev { border-radius: 16px; padding: 16px 18px; background: color-mix(in oklab, var(--c) var(--tint), var(--surface)); }
  .dk-merge .mg-h { font-weight: 650; font-size: .95rem; color: var(--c); }
  .dk-merge .mg-val { font: 600 1.35rem var(--mono); margin: 6px 0 2px; word-break: break-word; }
  .dk-merge .mg-meta, .dk-merge .mg-out { font: .82rem var(--mono); color: var(--muted); }
  .dk-merge .mg-out { margin-top: 8px; }
  .dk-merge .mg-mid { display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; gap: 6px; font-size: .9rem; color: var(--muted); }
  .dk-merge .mg-st { font-weight: 650; font-size: 1rem; color: var(--fg); }
  .dk-merge .mg-st.ok { color: var(--c3); } .dk-merge .mg-st.no { color: var(--bad); }
  .dk-merge .mg-log { min-height: 2.6em; font: .82rem var(--mono); }
  .dk-merge .flash { animation: mgflash .6s var(--ease); }
  @keyframes mgflash { from { box-shadow: 0 0 0 4px color-mix(in oklab, var(--c3) 60%, transparent); } }
  @media (max-width: 640px) { .dk-merge .mg-row { grid-template-columns: 1fr 1fr; } .dk-merge .mg-mid { grid-column: 1 / -1; order: 3; } }
</style>
<div class="mg-row">
  <div class="mg-dev c1" data-dev="L"><div class="mg-h">Laptop (offline)</div><div class="mg-val"></div><div class="mg-meta"></div><div class="mg-out"></div></div>
  <div class="mg-mid"><div class="mg-st"></div><div class="mg-log"></div></div>
  <div class="mg-dev c2" data-dev="P"><div class="mg-h">Phone (offline)</div><div class="mg-val"></div><div class="mg-meta"></div><div class="mg-out"></div></div>
</div>
<div class="ctl">
  <button class="c1" data-act="eL">Edit on laptop</button>
  <button class="c2" data-act="eP">Edit on phone</button>
  <button class="c3" data-act="sLP">Deliver laptop → phone</button>
  <button class="c3" data-act="sPL">Deliver phone → laptop</button>
  <button data-act="reset">Reset</button>
</div>
</div>`;

function lwwDemo(root) {
  const el = root.querySelector('.dk-merge');
  const words = { L: ['Groceries', 'Weekend shop', 'Errands', 'Market'], P: ['Shopping', 'Food run', 'Supplies', 'To buy'] };
  const name = { L: 'laptop', P: 'phone' };
  let now, dev, log;
  const fmt = t => `10:${String(t).padStart(2, '0')}`;
  const wins = (a, b) => a.t > b.t || (a.t === b.t && a.node > b.node); // timestamp, then node id breaks ties
  function reset() {
    now = 1;
    const init = { v: 'Untitled', t: 1, node: 'L', n: 1 };
    dev = { L: { reg: { ...init }, out: [], n: 1, ed: 0 }, P: { reg: { ...init }, out: [], n: 0, ed: 0 } };
    log = 'Edit each side, then deliver.';
    draw();
  }
  function edit(k) {
    const d = dev[k];
    now += 1 + Math.floor(Math.random() * 3);
    d.n++;
    d.reg = { v: words[k][d.ed++ % words[k].length], t: now, node: k, n: d.n };
    d.out.push({ ...d.reg });
    log = `${name[k]} wrote "${d.reg.v}" at ${fmt(now)}`;
    draw();
  }
  function deliver(from, to) {
    const src = dev[from], dst = dev[to];
    if (!src.out.length) { log = `nothing new from the ${name[from]}`; return draw(); }
    const msgs = src.out.map(dl => {
      const kept = wins(dl, dst.reg);
      if (kept) dst.reg = { ...dl };
      return `"${dl.v}" ${fmt(dl.t)}: ${kept ? 'newer, kept' : 'older, ignored'}`;
    });
    src.out = [];
    now = Math.max(now, dst.reg.t); // HLC: receiving advances the local clock
    log = msgs.join('<br>');
    draw(to);
  }
  function draw(flash) {
    for (const k of ['L', 'P']) {
      const box = el.querySelector(`[data-dev="${k}"]`), d = dev[k];
      box.querySelector('.mg-val').textContent = d.reg.v;
      box.querySelector('.mg-meta').textContent = `written ${fmt(d.reg.t)} by ${name[d.reg.node]}·${d.reg.n}`;
      box.querySelector('.mg-out').textContent = d.out.length ? `${d.out.length} unsent change${d.out.length > 1 ? 's' : ''}` : 'nothing unsent';
      box.classList.remove('flash');
      if (flash === k) { void box.offsetWidth; box.classList.add('flash'); }
    }
    const same = dev.L.reg.v === dev.P.reg.v && dev.L.reg.t === dev.P.reg.t;
    const pending = dev.L.out.length + dev.P.out.length;
    const st = el.querySelector('.mg-st');
    st.className = 'mg-st ' + (same && !pending ? 'ok' : same ? '' : 'no');
    st.textContent = same && !pending ? '✓ Converged' : same ? 'Same, for now' : 'Diverged';
    el.querySelector('.mg-log').innerHTML = log;
  }
  const onClick = e => {
    const a = e.target.closest('button')?.dataset.act;
    if (a === 'eL') edit('L'); else if (a === 'eP') edit('P');
    else if (a === 'sLP') deliver('L', 'P'); else if (a === 'sPL') deliver('P', 'L');
    else if (a === 'reset') reset();
  };
  el.addEventListener('click', onClick);
  reset();
  return () => el.removeEventListener('click', onClick);
}

// ---------- Slides ----------
export default {
  id: 'merge',
  title: 'Merging without a referee',
  blurb: 'One conflict rule, applied recursively, makes every copy converge without a server.',
  icon,
  slides: [
    {
      title: 'Two devices edit offline. Nobody referees.',
      stage: () => svg(960, 280, [
        device(150, 70, { kind: 'laptop', label: 'laptop', c: 'c1', d: 0 }),
        device(810, 70, { kind: 'phone', label: 'phone', c: 'c2', d: 0.1 }),
        box(60, 150, 180, 44, { label: '"Groceries"', c: 'c1', mono: true, d: 0.4 }),
        box(720, 150, 180, 44, { label: '"Shopping"', c: 'c2', mono: true, d: 0.6 }),
        device(480, 60, { kind: 'server', label: 'no server decides', c: 'blind', d: 0.8 }),
        cross(508, 40, { d: 0.9 }),
        path('M250,172 Q480,250 710,172', { c: 'acc', cls: 'dash arrow2', d: 1.3 }),
        packet('M250,172 Q480,250 710,172', { c: 'c1', begin: 1.6, dur: 1.4, repeat: 1 }),
        packet('M710,172 Q480,250 250,172', { c: 'c2', begin: 1.9, dur: 1.4, repeat: 1 }),
        box(60, 150, 180, 44, { label: '"Shopping"', c: 'c3', solid: true, mono: true, d: 3.4 }),
        box(720, 150, 180, 44, { label: '"Shopping"', c: 'c3', solid: true, mono: true, d: 3.4 }),
        text(480, 250, 'they meet days later', { cls: 'sub', d: 1.4 }),
      ].join('')),
      text: `<p>Each device edits its own copy. When copies meet, possibly through a server that can't read them, all must end up identical: no lock, no leader, no merge dialog.</p>
        <p>osis gets this from <strong>CRDTs</strong> (conflict-free replicated data types): state where merging is a pure function that gives the same answer in any order, any number of times.</p>`,
      more: `<h3>Delta-state CRDTs</h3>
        <p>Every aspect's state is a join-semilattice: merging (<em>join</em>) is commutative, associative and idempotent. A change travels as a <em>delta</em>, a tiny state of the same type, and applying it is just a join. No operation log, ordered delivery or commit DAG is needed.</p>
        <p>Causality is only tracked inside one aspect. References between things may dangle, so nothing waits for another thing to arrive.</p>`,
    },
    {
      title: 'One rule everywhere: the later write wins',
      stage: demoHtml,
      enter: lwwDemo,
      text: `<p>Every write carries a <strong>timestamp</strong> and a <strong>dot</strong>: a unique ID (node plus counter) that later operations can point at. On merge, the later timestamp wins and the node ID breaks ties. Edit both sides and deliver in either order: the result is the same.</p>`,
      more: `<h3>Clocks and dots</h3>
        <p>Timestamps come from a <em>hybrid logical clock</em>: wall-clock milliseconds plus a counter, advanced whenever a node receives something newer, with drift capped. So causally later writes always have later timestamps even if a device's clock is a bit off.</p>
        <p>A dot is (node, per-aspect counter). Dots let removals, undo and revocation name exactly which writes they affect.</p>
        <p>A writer who games their clock to always win is out of scope.</p>`,
    },
    {
      title: 'Merging goes all the way down to the leaves',
      stage: () => svg(960, 380, [
        text(190, 16, 'laptop', { cls: 'b', c: 'c1', d: 0 }),
        card(40, 34, 300, 'task', [['title', '"Buy oat milk"', '10:05', 'c1'], ['done', 'false', '10:01']], { d: 0.1 }),
        text(770, 16, 'phone', { cls: 'b', c: 'c2', d: 0.3 }),
        card(620, 34, 300, 'task', [['title', '"Buy milk"', '10:01'], ['done', 'true', '10:06', 'c2']], { d: 0.4 }),
        arrow(190, 152, 400, 236, { c: 'c1', d: 1, curve: -20 }),
        arrow(770, 152, 560, 236, { c: 'c2', d: 1, curve: 20 }),
        card(330, 240, 300, 'task, merged on both', [['title', '"Buy oat milk"', '10:05', 'c1'], ['done', 'true', '10:06', 'c2']], { c: 'c3', d: 1.5 }),
      ].join('')),
      text: `<p>Struct fields, map entries, list elements and enum payloads each merge on their own, down to single values. Edits to different fields don't conflict; only two writes to the <em>same</em> leaf are decided by timestamp.</p>`,
      more: `<h3>Per type</h3>
        <ul>
          <li><strong>Scalars</strong>: last writer wins. Numbers can opt into a counter (concurrent increments add up), max or min.</li>
          <li><strong>Struct</strong>: per field. <strong>Map</strong>: per entry. <strong>Set</strong>: per element.</li>
          <li><strong>Enum</strong>: the case is a last-writer-wins register; payloads merge while both sides are in the same case.</li>
          <li><strong>List and text</strong>: a sequence CRDT whose elements can themselves be edited in place.</li>
        </ul>`,
    },
    {
      title: 'Deleting is a timestamped reset, and newer writes survive it',
      stage: () => {
        const X = t => 90 + (t - 1) * 100; // 10:01 .. 10:09
        const ax = 200;
        return svg(960, 400, [
          path(`M60,${ax} H900`, { c: 'blind', cls: 'arrow', d: 0 }),
          ...[1, 2, 4, 6, 8].map(t => text(X(t), ax + 18, `10:0${t}`, { cls: 'sub mono', d: 0 })),
          text(40, 110, 'laptop', { anchor: 'start', cls: 'b small', c: 'c1', d: 0.1 }),
          text(40, 290, 'phone', { anchor: 'start', cls: 'b small', c: 'c2', d: 0.1 }),
          `<rect x="${X(5) - 3}" y="80" width="6" height="${ax - 80}" rx="3" class="fills bad ap" style="--d:.4s"/>`,
          box(X(5) - 90, 40, 180, 40, { label: 'delete task', sub: 'reset @ 10:05', c: 'bad', d: 0.4 }),
          g(`<rect x="60" y="${ax - 8}" width="${X(5) - 60}" height="16" rx="8" class="fills bad" opacity=".18"/>`, { d: 0.9 }),
          box(X(3) - 85, 250, 170, 40, { label: 'title = "Milk"', sub: '10:03', c: 'c2', mono: true, d: 1.2 }),
          path(`M${X(3)},250 V${ax + 6}`, { c: 'c2', cls: 'thin', d: 1.2 }),
          box(X(7) - 85, 250, 170, 40, { label: 'done = true', sub: '10:07', c: 'c2', mono: true, d: 1.6 }),
          path(`M${X(7)},250 V${ax + 6}`, { c: 'c2', cls: 'thin', d: 1.6 }),
          cross(X(3) + 92, 260, { d: 2.4 }),
          check(X(7) + 92, 260, { d: 2.6 }),
          box(280, 330, 400, 50, { label: 'merged: task = { done: true }', sub: 'everything older than 10:05 is gone', c: 'c3', mono: true, d: 3 }),
        ].join(''));
      },
      text: `<p>Deleting a thing or an aspect writes a <strong>reset</strong>: a timestamp that drops everything older there. A concurrent edit made <em>after</em> the reset survives; an older one loses like any older write.</p>
        <p>Map keys, set elements and text are removed the same way, aimed at specific elements (next slide). Either way, a newer write never loses to an older removal.</p>`,
      more: `<h3>Why resets</h3>
        <p>Concurrent resets need no tiebreak (the later dominates), and after one, the dropped content is gone from state, which is what real deletion needs.</p>
        <p>Tombstones are never garbage-collected by a timeout in v1, so no edit is silently discarded after long separation.</p>`,
    },
    {
      title: 'Elements are named by their birth, not their value',
      stage: () => svg(960, 400, [
        text(200, 18, 'laptop sees, then removes "urgent"', { cls: 'b small', c: 'c1', d: 0 }),
        pill(140, 60, 'urgent · L1', { c: 'c1', d: 0.2 }),
        pill(275, 60, 'home · L2', { c: 'c1', d: 0.3 }),
        g(`<path d="M80,60 H200" class="ln bad" style="stroke-width:3"/>`, { d: 1 }),
        text(200, 100, 'reset dot L1 (only what it saw)', { cls: 'sub', d: 1.1 }),

        text(760, 18, 'phone, concurrently, adds "urgent"', { cls: 'b small', c: 'c2', d: 0.4 }),
        pill(760, 60, 'urgent · P4', { c: 'c2', d: 0.6 }),
        text(760, 100, 'a new element with its own dot', { cls: 'sub', d: 0.7 }),

        arrow(200, 120, 420, 210, { c: 'c1', d: 1.6, curve: -20 }),
        arrow(760, 120, 540, 210, { c: 'c2', d: 1.6, curve: 20 }),
        box(300, 214, 360, 76, { c: 'c3', d: 2.1 }),
        text(480, 234, 'merged set', { cls: 'b small', d: 2.1 }),
        pill(410, 266, 'urgent · P4', { c: 'c2', d: 2.3 }),
        pill(550, 266, 'home · L2', { c: 'c1', d: 2.3 }),
        box(330, 320, 300, 44, { label: 'L1 removed', sub: 'nothing kept names "urgent"', c: 'blind', d: 2.8 }),
      ].join('')),
      text: `<p>Each set element, map entry and list item is identified by the <strong>dot it was created with</strong>. "Remove urgent" resets the dots the remover can see. An add it never saw has a different dot, so it survives.</p>
        <p>Removals never record the removed value or key, so nothing left behind can confirm what was there.</p>`,
      more: `<h3>Trade-off</h3>
        <p>Removing by value ("urgent is gone, whenever it was added") would beat unseen adds, but the tombstone would have to name the value: a fingerprint that lets anyone confirm a guess, even after a purge.</p>
        <p>The accepted worst case: one admin removes Bob's membership while another, offline admin who never saw it grants Bob again. Bob stays a member until removed again.</p>`,
    },
    {
      title: 'Text is a tree of anchors, so moves merge cleanly',
      stage: () => {
        const start = [['F'], ['O'], ['O'], ['B'], ['A'], ['R']];
        const sx = 480 - 3 * CW, my = 280, mx = 480 - 3.5 * CW;
        // Merged row: B A R F O O x. Each glyph slides from its position in "FOOBAR".
        const fin = [['B', null, 3], ['A', null, 4], ['R', null, 5], ['F', 'c2', 0], ['O', 'c2', 1], ['O', 'c2', 2], ['x', 'c1', null]];
        const merged = fin.map(([ch, c, from], i) => {
          const fx = mx + i * CW;
          const dx = from == null ? 0 : (sx + from * CW) - fx;
          const anim = from == null ? '' : `<animateTransform attributeName="transform" type="translate" from="${dx} 0" to="0 0" begin="3.2s" dur="1.1s" fill="freeze" calcMode="spline" keySplines=".3 0 .2 1" keyTimes="0;1"/>`;
          const cell = box(fx, my, CW - 6, 44, { label: ch, c: c ?? 'fgc', solid: !!c, r: 8 });
          const extra = from == null ? g(cell, { d: 4.3 }) : `<g transform="translate(${dx} 0)">${anim}${cell}</g>`;
          return extra;
        }).join('');
        return svg(960, 380, [
          text(480, 14, 'start', { cls: 'sub', d: 0 }),
          cells(sx, 30, start, { d: 0 }),
          text(240, 104, 'laptop: type "x" after FOO', { cls: 'b small', c: 'c1', d: 0.5 }),
          cells(240 - 3.5 * CW, 124, [['F'], ['O'], ['O'], ['x', 'c1'], ['B'], ['A'], ['R']], { d: 0.6 }),
          text(720, 104, 'phone: move FOO to the end', { cls: 'b small', c: 'c2', d: 1 }),
          cells(720 - 3 * CW, 124, [['B'], ['A'], ['R'], ['F', 'c2'], ['O', 'c2'], ['O', 'c2']], { d: 1.1 }),
          text(480, 254, 'merged on both', { cls: 'b small', c: 'c3', d: 2.2 }),
          g(merged, { d: 2.3 }),
          text(480, 356, '"x" is anchored to the last O, so it travels with FOO', { cls: 'sub', d: 4.6 }),
        ].join(''));
      },
      text: `<p>Each character (or list item) has a permanent ID and two small registers: <strong>pos</strong>, the element it sits after, and <strong>deleted</strong>. Typing, moving, deleting and pasting are register writes, merged by the same timestamp rule.</p>
        <p>The move changed where F sits, not the O that "x" hangs from, so "x" follows the moved text.</p>`,
      more: `<h3>The sequence CRDT</h3>
        <ul>
          <li>Elements whose <code>pos</code> is X are X's children, newest <code>pos</code> write first; a depth-first walk gives the order (RGA-style).</li>
          <li>A move writes <code>pos</code> only for the moved range's roots, so concurrent inserts inside it travel along. Concurrent moves of one element resolve by timestamp and never duplicate it. Cycles are broken at the oldest edge.</li>
          <li>Delete is a flag: the content is dropped from state immediately, the ID stays as an anchor for others' inserts.</li>
          <li>Cut and paste keep the original IDs, so others' concurrent edits inside the cut text move with it.</li>
          <li>IDs are mostly implicit in runs; target state size is 1.5–3x the plain text.</li>
        </ul>`,
    },
    {
      title: 'Commits are atomic, and undo is just another commit',
      stage: () => svg(960, 400, [
        device(90, 90, { kind: 'laptop', label: 'laptop', c: 'c1', d: 0 }),
        device(870, 90, { kind: 'phone', label: 'phone', c: 'c2', d: 0 }),
        box(220, 30, 520, 120, { c: 'c4', d: 0.3 }),
        text(240, 54, 'commit C7 · Alice via laptop · 10:05 · signed', { anchor: 'start', cls: 'b small', d: 0.3 }),
        box(240, 72, 480, 30, { label: '/note/body: paste paragraph (dots L40–L52)', c: 'fgc', plain: true, mono: true, r: 7, d: 0.4 }),
        box(240, 108, 480, 30, { label: '/note/tasks: add "Call Sam" (dot L7)', c: 'fgc', plain: true, mono: true, r: 7, d: 0.5 }),
        arrow(130, 90, 214, 90, { c: 'c1', d: 0.6 }),
        arrow(746, 90, 832, 90, { c: 'c1', d: 0.8 }),
        packet('M746,90 H832', { c: 'c1', begin: 1, dur: 1.4, shape: 'blob' }),
        text(480, 180, 'both changes appear together, or not at all', { cls: 'sub', d: 1.2 }),

        device(870, 290, { kind: 'phone', label: 'phone', c: 'c2', d: 2 }),
        box(220, 250, 520, 90, { c: 'c4', d: 2.3 }),
        text(240, 274, 'commit C9 · Alice via phone · undoes C7', { anchor: 'start', cls: 'b small', d: 2.3 }),
        box(240, 292, 480, 32, { label: 'reset body L40–L52, tasks L7', c: 'fgc', plain: true, mono: true, r: 7, d: 2.4 }),
        arrow(832, 290, 746, 290, { c: 'c2', d: 2.6 }),
        arrow(214, 290, 130, 290, { c: 'c2', d: 2.8 }),
        device(90, 290, { kind: 'laptop', label: 'laptop', c: 'c1', d: 2.8 }),
        packet('M214,290 H130', { c: 'c2', begin: 3, dur: 1.4, shape: 'blob' }),
      ].join('')),
      text: `<p>A <strong>commit</strong> may touch several aspects and things; every node applies it in one step, then fires listeners.</p>
        <p><strong>Undo</strong> is a new commit that cancels specific dots of an earlier one. It syncs like any edit, so you can undo on your phone what you typed on your laptop.</p>`,
      more: `<h3>Undo details</h3>
        <ul>
          <li>Undoing an insert resets its dot; undoing a delete restores the original IDs, with the content from the local undo buffer.</li>
          <li>Undoing a plain value restores the old one only if your write is still the winner, so you never clobber someone's later edit.</li>
          <li>Undo is per actor by default, scoped by the app. Admins can also undo others' changes.</li>
          <li>Purged content cannot be undone.</li>
        </ul>`,
    },
    {
      title: 'Apps see plain values. The price: no isolation.',
      stage: () => `<div class="split">
        ${code(`{k:let} {k:mut} task = db.get_aspect(t, {s:"/task"}).{k:await}?;
task.title = {s:"Buy oat milk"};
{k:let} {k:mut} m = db.mutate();
m.set_aspect(t, {s:"/task"}, task); {cm:// diffed: only title}
m.commit().{k:await}?;`)}
        ${svg(420, 300, [
          text(210, 14, 'invariant: at most 3 tasks', { cls: 'b small', d: 0.3 }),
          ...['a', 'b'].map((n, i) => box(150, 36 + i * 40, 120, 32, { label: `task ${n}`, c: 'fgc', mono: true, r: 8, d: 0.4 })),
          box(20, 116, 150, 32, { label: 'laptop adds c', c: 'c1', mono: true, r: 8, d: 0.8 }),
          box(250, 116, 150, 32, { label: 'phone adds d', c: 'c2', mono: true, r: 8, d: 0.9 }),
          arrow(95, 152, 180, 196, { c: 'c1', d: 1.2 }),
          arrow(325, 152, 240, 196, { c: 'c2', d: 1.2 }),
          box(110, 200, 200, 50, { label: '4 tasks: a b c d', c: 'bad', mono: true, d: 1.6 }),
          text(210, 278, 'both commits were valid alone', { cls: 'sub', d: 1.8 }),
        ].join(''))}
      </div>`,
      text: `<p>Writing a whole value back is diffed, so only changed fields are written and concurrent edits to other fields survive. No CRDT machinery reaches the app.</p>
        <p>The price: merges are not transactions. Two commits that are each valid can combine into a state that breaks an app rule. App invariants must tolerate merging, and any repair must be a deterministic function of state, or two devices will fight.</p>`,
    },
  ],
};
