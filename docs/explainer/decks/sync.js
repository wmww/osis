import { svg, g, box, text, arrow, path, device, blob, key, check, cross, pill, tiles } from '../lib/svg.js';

// One-shot travelling blob: fades in, moves along `p`, fades out on arrival.
// Dashed path that fades in. Written raw: path() sets pathLength=1, which turns dashes solid.
const dpath = (p, { c = 'fgc', cls = '' } = {}, d) => g(`<path d="${p}" class="ln ${c} ${cls}"/>`, { d });

const shot = (p, { c = 'blind', begin = 0, dur = 1.2, shape = 'blob' } = {}) => {
  const body = shape === 'blob'
    ? `<rect x="-9" y="-7" width="18" height="14" rx="3.5" class="fills"/>`
    : `<circle r="5" class="fills"/>`;
  return `<g class="${c}" opacity="0">${body}` +
    `<animate attributeName="opacity" values="0;1;1;0" keyTimes="0;.12;.88;1" dur="${dur}s" begin="${begin}s" fill="freeze"/>` +
    `<animateMotion path="${p}" dur="${dur}s" begin="${begin}s" fill="freeze"/></g>`;
};

const icon = () => svg(300, 92, [
  blob(30, 46, { size: 24 }), blob(70, 46, { size: 24 }), blob(110, 46, { size: 24, c: 'acc' }),
  arrow(136, 46, 200, 46, { c: 'blind' }),
  device(250, 46, { kind: 'server', c: 'blind', blind: true }),
].join(''));

// ---------- Spreadsheet demo: which blobs a device downloads when it syncs a row, a column, or both ----------
const COLS = 'ABCD';
function sheet(sel) {
  const wantRow = sel !== 'col', wantCol = sel !== 'row';
  const gx = 60, gy = 70, cw = 76, ch = 50, gap = 6;
  const picked = [];
  let s = '';
  [...COLS].forEach((L, c) => { s += text(gx + c * (cw + gap) + cw / 2, gy - 18, L, { cls: 'sub' }); });
  for (let r = 0; r < 4; r++) {
    s += text(gx - 18, gy + r * (ch + gap) + ch / 2, String(r + 1), { cls: 'sub' });
    for (let c = 0; c < 4; c++) {
      const inRow = wantRow && r === 2, inCol = wantCol && c === 1;
      const col = inRow && inCol ? 'acc' : inRow ? 'c1' : inCol ? 'c2' : 'fgc';
      if (inRow || inCol) picked.push([COLS[c] + (r + 1), col]);
      s += box(gx + c * (cw + gap), gy + r * (ch + gap), cw, ch, { label: COLS[c] + (r + 1), c: col, solid: inRow && inCol, r: 8 });
    }
  }
  s += text(gx + 2 * (cw + gap) - gap / 2, gy + 4 * (ch + gap) + 12, "the spreadsheet on Alice's laptop", { cls: 'sub' });
  if (wantRow) s += pill(gx + 4 * (cw + gap) + 30, gy + 2 * (ch + gap) + ch / 2, 'row 3', { c: 'c1', mono: false });
  if (wantCol) s += pill(gx + 1 * (cw + gap) + cw / 2, gy - 44, 'column B', { c: 'c2', mono: false });

  const sx = 610, px = 850, cy = 170;
  s += device(sx, cy, { kind: 'server', label: 'server', sub: 'one label per synced group', c: 'blind', blind: true });
  s += device(px, cy, { kind: 'phone', label: 'phone', sub: `syncs ${sel === 'row' ? 'row 3' : sel === 'col' ? 'column B' : 'both'}`, c: 'c1' });
  s += arrow(gx + 4 * (cw + gap) + 62, cy, sx - 36, cy, { c: 'blind', dash: true });
  s += arrow(sx + 36, cy, px - 24, cy, { c: 'blind' });
  // Received blobs pile up under the phone, one per distinct cell.
  picked.forEach(([name, col], i) => {
    const t = 0.4 + i * 0.32;
    s += shot(`M${sx + 30},${cy} L${px - 20},${cy}`, { c: col, begin: t, dur: 0.9 });
    const bx = 720 + (i % 4) * 50, by = 278 + Math.floor(i / 4) * 50;
    s += blob(bx, by, { c: col, d: t + 0.8, label: name, size: 24 });
  });
  const n = picked.length;
  s += text(795, 388, sel === 'both' ? `${n} blobs: B3 arrives once, not twice` : `${n} blobs, not 16`, { cls: 'b small', d: 0.4 + n * 0.32 + 0.6 });
  return svg(960, 400, s);
}


export default {
  id: 'sync',
  title: 'Sync',
  blurb: 'Encrypted blobs, overlapping groups, one-round-trip sync, and servers that store what they cannot read.',
  icon,
  slides: [
    {
      title: 'Every commit becomes one opaque blob',
      stage: () => svg(960, 320, [
        box(30, 30, 270, 260, { c: 'c1', d: 0 }),
        text(165, 56, 'commit', { cls: 'b', d: 0 }),
        box(50, 78, 230, 56, { label: 'header', sub: 'author · time · signature', c: 'c4', d: 0.15, r: 9 }),
        box(50, 144, 230, 56, { label: 'delta', sub: '/note/title', c: 'c3', d: 0.25, r: 9 }),
        box(50, 210, 230, 56, { label: 'delta', sub: '/note/done', c: 'c3', d: 0.35, r: 9 }),
        arrow(314, 160, 452, 160, { c: 'c4', d: 0.7 }),
        key(383, 128, { c: 'c4', d: 0.8, scale: 1.3 }),
        text(383, 196, 'fresh random key', { cls: 'sub', d: 0.85 }),
        blob(530, 160, { c: 'blind', d: 1.2, size: 84 }),
        text(530, 228, '7f3a 91c0 … e2d4', { cls: 'mono', d: 1.5 }),
        text(530, 250, 'ID = hash of the ciphertext', { cls: 'sub', d: 1.6 }),
        ...[
          ['one ID everywhere,', 'whichever groups hold it', 'c3'],
          ['reveals only padded size', 'and which labels hold it', 'blind'],
          ['applies whole', 'or not at all', 'c4'],
        ].map(([t, t2, c], i) => g(`<circle cx="0" cy="-9" r="5" class="fills"/>` + text(16, -9, t, { anchor: 'start', cls: 'small' }) + text(16, 9, t2, { anchor: 'start', cls: 'sub' }), { c, x: 650, y: 100 + i * 60, d: 1.9 + i * 0.2 })),
      ].join('')),
      text: `<p>A <strong>commit</strong> (one save: a signed header plus a small delta per changed value) is encrypted under its own random key into a single <strong>blob</strong>. Its ID is the hash of the ciphertext, so every node names it the same way.</p>
        <p>Sync never looks inside. It only moves sets of blobs between nodes; a node with the right keys decrypts and merges them locally.</p>`,
      more: `<h3>Why one blob per commit</h3>
        <p>A commit may touch several things, and it must apply atomically on every node. Keeping it as one blob guarantees that, at the cost of a node that syncs only some of those things downloading the whole commit. Such partial syncs are rare; atomicity was judged more important.</p>
        <p>Large values (multi-GB files, million-key maps) are split into content-defined chunks that travel as separate blobs, each under its own random key stored in its parent's link. Editing the middle of a big file uploads only the chunks that changed.</p>`,
    },
    {
      title: 'Groups are the unit of sync, and they overlap',
      stage: `<div style="width:100%"><div class="demo"></div><div class="ctl">
        <button data-sel="row" class="c1">Sync row 3</button>
        <button data-sel="col" class="c2">Sync column B</button>
        <button data-sel="both" class="acc">Sync both</button></div></div>`,
      enter(root) {
        const demo = root.querySelector('.demo');
        const show = sel => {
          demo.innerHTML = sheet(sel);
          root.querySelectorAll('.ctl button').forEach(b => b.disabled = b.dataset.sel === sel);
        };
        root.querySelectorAll('.ctl button').forEach(b => b.addEventListener('click', () => show(b.dataset.sel)));
        show('row');
      },
      text: `<p>Recall: a <strong>group</strong> is a thing that lists other things, and groups may overlap and nest, like the rows and columns of a spreadsheet. Each synced group gets a <strong>label</strong>: a random ID a server can file blobs under, which says nothing about what is in it.</p>
        <p>A device asks for the labels it wants: just row 3, just column B, or both. A cell in both is still stored and sent only once.</p>`,
      more: `<h3>Which blobs belong to a group</h3>
        <p>"Blobs of G" are the commits touching anything in G's transitive closure, plus the chunks they reference. Each node computes this from its own data, tagging commits with their things' groups on arrival and retagging when membership changes. Cycles need nothing special.</p>
        <p>There is no "repository" that has to be synced whole. That is the test case behind the design: syncing one row or one column must each be efficient, without duplicating the table at rest or in transit.</p>`,
    },
    {
      title: 'A 48-byte wrap puts a blob under another label',
      stage: () => svg(960, 360, [
        blob(480, 50, { c: 'blind', size: 56, d: 0 }),
        text(530, 50, 'one blob, stored once', { anchor: 'start', cls: 'sub', d: 0.1 }),
        key(480, 130, { c: 'c4', d: 0.4, scale: 1.4 }),
        text(510, 130, 'its key', { anchor: 'start', cls: 'sub', d: 0.45 }),
        path('M480,82 V112', { c: 'blind', cls: 'dash', d: 0.3 }),
        ...[
          [180, 'c1', 'row 3', 0.9],
          [480, 'c2', 'column B', 1.3],
          [780, 'c3', 'Bob', 2.3],
        ].map(([x, c, lbl, d]) =>
          arrow(480, 152, x, 236, { c: 'c4', d, curve: x === 480 ? 0 : (x < 480 ? 18 : -18) }) +
          key(x - 112, 270, { c, d: d + 0.2 }) +
          box(x - 80, 240, 160, 60, { label: `wrap · ${lbl}`, sub: '≈ 48 bytes', c, d: d + 0.3 }) +
          text(x, 318, `blob key sealed with the label's secret`, { cls: 'sub', d: d + 0.4 })),
        text(780, 345, 'shared later: no re-encryption', { cls: 'b small', d: 2.8, c: 'c3' }),
      ].join('')),
      text: `<p>A <strong>wrap</strong> is the blob's key, encrypted with a label's read secret (each synced group has secrets held by its members; see Permissions). Anyone who holds that label's secret can open the blob; a server stores the wraps next to the blob ID without being able to use them.</p>
        <p>One blob under three labels costs one copy and three wraps. Sharing old history with someone new means adding wraps, never re-encrypting data.</p>`,
      more: `<h3>Who adds wraps</h3>
        <p>An uploader puts a blob under the label of every group its things are in, for which it holds the read secret and whose actor may read the thing. When a thing moves between groups, its live blobs gain a wrap under the new label and are retired under the old one; the blob itself stays put.</p>
        <p>The wrap's nonce is derived from the blob ID, so a wrap is about 48 bytes: around 20% overhead on a minimal 200-byte commit, under 5% on typical edits, and nothing per chunk of a large value.</p>`,
    },
    {
      title: 'Catching up takes one round trip',
      stage: () => {
        const lx = 170, rx = 790, ex = 196, ew = 46, eg = 6;
        const ent = i => ex + i * (ew + eg); // left edge of log entry i (0-based)
        return svg(960, 420, [
          device(lx, 50, { kind: 'laptop', label: 'your laptop', sub: 'keeps a cursor per peer and label', c: 'c1', d: 0 }),
          device(rx, 50, { kind: 'server', label: 'peer', sub: 'blind server or another device', c: 'blind', blind: true, d: 0 }),
          path(`M${lx},120 V290`, { c: 'blind', cls: 'thin dash', d: 0.2 }),
          path(`M${rx},120 V290`, { c: 'blind', cls: 'thin dash', d: 0.2 }),
          text(480, 142, 'since #6 · I gained x, y', { cls: 'mono', d: 0.6 }),
          arrow(lx + 6, 166, rx - 6, 166, { c: 'c1', d: 0.6 }),
          shot(`M${lx + 10},166 H${rx - 10}`, { c: 'c1', begin: 0.9, dur: 1.1 }),
          shot(`M${lx + 10},166 H${rx - 10}`, { c: 'c1', begin: 1.15, dur: 1.1 }),
          text(480, 226, 'entries #7–#9, minus x, y', { cls: 'mono', d: 2.3 }),
          arrow(rx - 6, 250, lx + 6, 250, { c: 'blind', d: 2.3 }),
          ...[0, 1, 2].map(i => shot(`M${rx - 10},250 H${lx + 10}`, { c: 'acc', begin: 2.6 + i * 0.25, dur: 1.1 })),
          text(30, 340, 'label log', { anchor: 'start', cls: 'b small', d: 0.1 }),
          text(30, 358, 'at the peer', { anchor: 'start', cls: 'sub', d: 0.1 }),
          ...Array.from({ length: 11 }, (_, i) => {
            const c = i >= 9 ? 'c1' : (i >= 6 ? 'acc' : 'blind');
            const d = i >= 9 ? 2.0 + (i - 9) * 0.15 : 0.1 + i * 0.04;
            return box(ent(i), 330, ew, 36, { label: `#${i + 1}`, c, d, r: 8, mono: true });
          }),
          `<g class="fadeout" style="--d:3.6s">${pill(ent(5) + ew / 2, 392, 'cursor', { c: 'c1', mono: false, d: 0.3 })}</g>`,
          pill(ent(10) + ew / 2, 392, 'cursor', { c: 'c1', mono: false, d: 3.7 }),
        ].join(''));
      },
      text: `<p>Each node keeps an append-only log per label of the entries it received. You send "since entry #6, and here is what I gained elsewhere". The peer replies with everything after #6 you don't already have, and keeps your new blobs. Blobs travel inline: one round trip each way.</p>
        <p>If there is no usable cursor (first contact, or the peer reset), the nodes fall back to range-based set reconciliation over blob IDs, which takes about log(n) rounds.</p>`,
      more: `<h3>Range-based set reconciliation</h3>
        <p>Both sides sort their blob IDs, split the ID space into ranges and exchange a fingerprint per range. Matching ranges are done; differing ranges are split again until the differences are small enough to list. The number of rounds grows with log(n) of the set size, and the bytes with the size of the difference (Negentropy and Willow use the same idea).</p>
        <p>A connection can also subscribe to labels; the peer then pushes new entries as they arrive, which is what makes live collaboration low-latency.</p>`,
    },
    {
      title: 'Blind servers run the same protocol without keys',
      stage: () => {
        const cols = [['label', 40], ['blob ID', 140], ['wrap', 250], ['gen', 360], ['token #', 420], ['expires', 520]];
        const rows = [
          ['9xq…', '7f3a…', 'Ux7…Qe', '4', 'c3…9b', '—'],
          ['9xq…', 'e21b…', 'kP0…sa', '4', '0f…a2', '—'],
          ['k2w…', '7f3a…', 'Zr9…3m', '2', 'c3…9b', '—'],
          ['k2w…', '50cc…', 'a4L…vb', '2', '81…7d', 'Oct 20'],
        ];
        const never = ['values, text, files', 'aspect names, thing IDs', 'who wrote what', 'who is a member', 'how groups nest', 'how many things exist'];
        return svg(960, 380, [
          text(30, 30, 'What the server stores', { anchor: 'start', cls: 'b', d: 0 }),
          ...cols.map(([h, x]) => text(x, 70, h, { anchor: 'start', cls: 'sub', d: 0.1 })),
          ...rows.map((r, i) => {
            const y = 108 + i * 46;
            return box(28, y - 19, 570, 38, { c: 'blind', r: 8, d: 0.2 + i * 0.12 }) +
              r.map((v, j) => text(cols[j][1], y, v, { anchor: 'start', cls: 'mono', d: 0.2 + i * 0.12, c: j === 1 && v === '7f3a…' ? 'c2' : undefined })).join('');
          }),
          path('M126,112 Q96,154 126,196', { c: 'c2', cls: 'arrow', d: 1.0 }),
          text(30, 300, 'Also visible: which labels share blobs, blob counts,', { anchor: 'start', cls: 'sub', d: 1.1 }),
          text(30, 320, 'padded sizes, arrival times, retires, client addresses.', { anchor: 'start', cls: 'sub', d: 1.15 }),
          text(660, 30, 'Never visible', { anchor: 'start', cls: 'b', d: 1.3 }),
          ...never.map((t, i) => cross(672, 80 + i * 46, { d: 1.4 + i * 0.12, s: 0.85 }) + text(694, 80 + i * 46, t, { anchor: 'start', d: 1.4 + i * 0.12 })),
        ].join(''));
      },
      text: `<p>A server without keys holds, per label, a flat list of entries: blob ID, wraps it cannot open, a generation number, a delete-token hash and an optional expiry time. That is enough to store, reconcile, push and garbage-collect.</p>
        <p>It never sees content, names, authors, membership or how groups nest. It does see which labels share a blob (the orange IDs above), entry counts, padded sizes and timing: selective sync from a blind server can't avoid that.</p>`,
      more: `<h3>Sizes</h3>
        <p>Every blob is padded up to the next step of one eighth of a power of two (the Padmé scheme): at most 12% and about 6% on average. That hides exact sizes but not overall volume; heavier padding would cost bandwidth on every edit, and content-defined chunking of large values already exposes chunk sizes. Volume is an accepted leak.</p>
        <p>Trusted peers and blind servers speak one protocol and differ only in which keys they hold. A blind server may be the only backup of rarely used data, so deleting there is guarded separately (see Deletion).</p>`,
    },
    {
      title: 'Devices that are never online together still sync',
      stage: () => {
        const x = h => 110 + (h - 8) * 64;
        const lanes = [['phone', 100, 'c1'], ['server', 200, 'blind'], ['laptop', 300, 'c2']];
        return svg(960, 380, [
          ...lanes.map(([n, y, c]) => text(24, y, n, { anchor: 'start', cls: 'b small', c, d: 0 }) +
            (n === 'server'
              ? box(x(8), y - 7, x(20) + 22 - x(8), 14, { c, r: 7, d: 0 })
              : dpath(`M${x(8)},${y} H${x(20) + 22}`, { c, cls: 'thin dash' }, 0))),
          ...[8, 10, 12, 14, 16, 18, 20].map(h => text(x(h), 352, `${h}:00`, { cls: 'sub', d: 0 })),
          box(x(9), 88, 44, 24, { c: 'c1', solid: true, r: 6, d: 0.3 }),
          text(x(9) + 22, 62, 'online 9:00, uploads', { cls: 'sub', d: 0.3 }),
          shot(`M${x(9) + 22},112 V196`, { c: 'c1', begin: 0.7, dur: 0.8 }),
          blob(x(9) + 22, 200, { c: 'c1', size: 20, d: 1.4 }),
          path(`M${x(9) + 40},200 H${x(18) + 4}`, { c: 'c1', d: 1.6 }),
          text((x(9) + x(18)) / 2, 178, 'waits on the server, encrypted', { cls: 'sub', d: 1.8 }),
          box(x(18), 288, 44, 24, { c: 'c2', solid: true, r: 6, d: 2.3 }),
          text(x(18) + 22, 328, 'online 18:00', { cls: 'sub', d: 2.3 }),
          shot(`M${x(18) + 14},204 V284`, { c: 'c1', begin: 2.6, dur: 0.8 }),
          shot(`M${x(18) + 32},284 V204`, { c: 'c2', begin: 3.5, dur: 0.8 }),
          blob(x(18) + 32, 200, { c: 'c2', size: 20, d: 4.2 }),
          path(`M${x(18) + 50},200 H${x(20) + 22}`, { c: 'c2', cls: 'arrow', d: 4.4 }),
          text(x(20) + 22, 230, 'phone gets it tomorrow', { anchor: 'end', cls: 'sub', d: 4.6 }),
        ].join(''));
      },
      text: `<p>Your phone is online at 9:00, your laptop only at 18:00. The phone drops its new commits at a blind server; the laptop picks them up hours later and leaves its own for the phone's next sync.</p>
        <p>This "briefly online" pattern is a primary use case: everything must still work when the only always-on machine is a blind server.</p>`,
    },
    {
      title: 'Compaction without tombstones: generations',
      stage: () => {
        const bx = i => 110 + i * 86;
        const retired = [0, 1, 2, 4];
        return svg(960, 400, [
          box(40, 50, 880, 120, { c: 'blind', d: 0 }),
          text(60, 72, 'label at the server', { anchor: 'start', cls: 'sub', d: 0 }),
          ...Array.from({ length: 7 }, (_, i) => {
            const b = blob(bx(i), 115, { c: 'blind', size: 30, d: 0.1 + i * 0.06, label: `b${i + 1}` });
            return retired.includes(i) ? `<g class="fadeout" style="--d:2.6s">${b}</g>` : b;
          }),
          `<g class="fadeout" style="--d:1.3s">${pill(855, 115, 'gen 4', { c: 'blind' })}</g>`,
          pill(855, 115, 'gen 5', { c: 'c3', solid: true, d: 1.4 }),
          device(150, 310, { kind: 'laptop', label: 'a writer', sub: 'compacts', c: 'c1', d: 0.4 }),
          shot('M170,285 Q500,240 712,128', { c: 'c3', begin: 0.8, dur: 1.2 }),
          blob(730, 115, { c: 'c3', size: 30, d: 1.9, label: 'snapshot' }),
          pill(480, 300, 'signed: retire b1 b2 b3 b5', { c: 'c4', mono: false, d: 2.2 }),
          device(800, 310, { kind: 'laptop', label: 'stale peer', sub: 'back after 3 months', c: 'c2', d: 3.0 }),
          shot('M780,285 Q520,250 205,150', { c: 'c2', begin: 3.4, dur: 1.2 }),
          cross(205, 200, { d: 4.5 }),
          text(228, 200, 're-upload of b2 (gen 4) refused', { anchor: 'start', cls: 'small b', c: 'bad', d: 4.6 }),
        ].join(''));
      },
      text: `<p>Old commits pile up. Any writer can compact a label: upload snapshot commits of the current state into a new <strong>generation</strong>, then sign a retire list naming the blobs they replace. The cost tracks how much changed, not the size of the group.</p>
        <p>Peers reconcile only within the live generation and refuse uploads tagged with an older one, so a device returning after months cannot resurrect retired blobs, and no tombstone list is needed.</p>`,
      more: `<h3>Details</h3>
        <ul>
          <li>Blobs not named in the retire list carry over implicitly. Concurrent compactions are harmless: snapshots merge like any other deltas.</li>
          <li>A returning member re-tags into the live generation only those of its old commits that still change state, so a snapshot that missed something gets repaired rather than lost.</li>
          <li>Blind servers keep soft-retired blobs in a recycle bin for a grace period (default 30 days), so a bad compaction loses history only after that.</li>
        </ul>`,
    },
    {
      title: 'Bytes on the wire track the size of the change',
      stage: () => `<div style="display:grid;gap:22px;width:100%">${svg(960, 250, [
        text(40, 24, 'A minimal commit', { anchor: 'start', cls: 'b', d: 0 }),
        box(40, 44, 400, 48, { label: 'header + signature ≈ 200 B', c: 'blind', r: 8, d: 0.1 }),
        box(446, 44, 110, 48, { label: 'wrap 48 B', sub: 'per label', c: 'c4', r: 8, d: 0.3 }),
        box(562, 44, 76, 48, { label: '16 B', sub: 'token', c: 'c4', r: 8, d: 0.4 }),
        box(644, 44, 150, 48, { label: 'your change', c: 'c3', solid: true, r: 8, d: 0.5 }),
        text(40, 150, 'Editing a 1 GB file', { anchor: 'start', cls: 'b', d: 0.8 }),
        ...Array.from({ length: 16 }, (_, i) => box(40 + i * 48, 172, 42, 34, { c: i === 9 ? 'c3' : 'blind', solid: i === 9, r: 6, d: 0.9 + i * 0.03 })),
        arrow(40 + 9 * 48 + 21, 216, 40 + 9 * 48 + 21, 236, { c: 'c3', d: 1.6, head: false }),
        text(40 + 9 * 48 + 34, 238, 'only the changed chunk and its path in the tree travel', { anchor: 'start', cls: 'sub', d: 1.6 }),
      ].join(''))}${tiles([
        { title: '1 round trip', text: 'for the usual incremental sync, with blobs inline.', c: 'c1', d: 1.8 },
        { title: 'log(n) rounds', text: 'worst case, when a peer has no cursor and must reconcile sets.', c: 'c2', d: 1.95 },
        { title: 'Never twice', text: 'a blob a node already holds is never sent again, whatever groups it is in.', c: 'c3', d: 2.1 },
        { title: '≤ 12% padding', text: 'to blur exact sizes; about 6% on average.', c: 'blind', d: 2.25 },
      ])}</div>`,
      text: `<p>The targets: large changes cost about 1.2× their size on the wire, small ones carry a fixed overhead of roughly 200 bytes per commit plus 48 per label. Compaction, deletion and membership changes cost in proportion to what changed, never to the size of the group or its history.</p>`,
    },
  ],
};
