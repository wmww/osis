import { svg, g, box, text, arrow, path, packet, device, check, cross, pill, code } from '../lib/svg.js';

const icon = () => svg(300, 92, [
  box(70, 4, 160, 84, { c: 'fgc', plain: true, r: 10 }),
  box(80, 12, 140, 20, { label: '/note/title', c: 'c1', r: 6, mono: true }),
  box(80, 36, 140, 20, { label: '/event/start', c: 'c2', r: 6, mono: true }),
  box(80, 60, 140, 20, { label: '/group', c: 'c3', r: 6, mono: true }),
].join(''));

// Spreadsheet grid helpers for the groups slide.
const COLS = ['A', 'B', 'C', 'D'];
const cell = (r, c) => ({ x: 70 + c * 82, y: 90 + r * 54 });

// Chunk tree helpers for the large-values slide.
const chunkRow = (x0, widths, gap = 8) => {
  let x = x0;
  return widths.map(w => { const r = { x, w, mid: x + w / 2 }; x += w + gap; return r; });
};

export default {
  id: 'data',
  title: 'Things and aspects',
  blurb: 'The data model: things, aspects, schemas, canonical bytes, self-certifying IDs and groups.',
  icon,
  slides: [
    {
      title: 'Everything is an aspect of a thing',
      stage: () => {
        const rows = [
          ['/note/title', '"Team offsite"', 'c1'],
          ['/note/body', '"Agenda: …"', 'c1'],
          ['/event/start', '2026-11-03 09:00', 'c2'],
          ['/event/place', '"Lisbon"', 'c2'],
          ['/aspects', 'synthetic: the keys above', 'blind'],
        ];
        const y0 = 92, step = 54;
        const ry = i => y0 + i * step + 21;
        return svg(960, 380, [
          box(300, 20, 360, 350, { c: 'fgc', plain: true, r: 18, d: 0 }),
          text(480, 50, 'one thing', { cls: 'b', d: 0 }),
          text(480, 72, 'osis://zqf7FN-YvhtF_Dy-nqdi', { cls: 'sub mono', d: 0.1 }),
          ...rows.map(([k, v, c], i) => box(318, y0 + i * step, 324, 42, { label: k, sub: v, c, mono: true, anchor: 'start', d: 0.25 + i * 0.12 })),
          box(30, 110, 180, 60, { label: 'Notes app', sub: 'reads /note/*', c: 'c1', d: 1 }),
          arrow(212, 140, 314, ry(0), { c: 'c1', d: 1.2 }),
          arrow(212, 140, 314, ry(1), { c: 'c1', d: 1.3 }),
          box(750, 220, 180, 60, { label: 'Calendar app', sub: 'reads /event/*', c: 'c2', d: 1.5 }),
          arrow(748, 250, 646, ry(2), { c: 'c2', d: 1.7 }),
          arrow(748, 250, 646, ry(3), { c: 'c2', d: 1.8 }),
          box(30, 270, 180, 60, { label: 'AI agent', sub: 'reads anything', c: 'c4', d: 2 }),
          arrow(212, 300, 314, ry(4) - 10, { c: 'c4', d: 2.2, dash: true }),
        ].join(''));
      },
      text: `<p>A <strong>thing</strong> is an ID plus a bag of <strong>aspects</strong>. Each aspect is a typed value under an aspect key (AK) such as <code>/note/title</code>. A thing holds nothing else.</p>
        <p>Apps pick the aspects they understand and ignore the rest, so a meeting can be a note to one app and an event to another, with no copying and no format conversion.</p>`,
      more: `<h3>Aspect flags</h3><p>The schema can mark an aspect <code>indexed</code> (full-text search), <code>synthetic</code> (computed, such as <code>/aspects</code> or <code>/groups</code>), <code>ro</code>, or <code>guaranteed</code> (present on every thing). It also sets a retention class and an optional expiry; those are covered in the Deletion and Live data topics.</p>`,
    },
    {
      title: 'Schemas declare types; only small integer IDs go on the wire',
      stage: () => `<div class="split">${code(`{cm:/// Notes app schema.}
{k:type} {t:task} = {k:struct} {
    {n:1} title: {t:string},
    {n:2} done: {t:bool},
    {n:3} tags: {t:set}<{t:string}>,
};

{k:aspect} /note/title: {t:string} [indexed];
{k:aspect} /note/body: {t:markdown} [indexed, preserve];
{k:aspect} /note/tasks: {t:list}<{t:task}>;`)}${svg(440, 380, [
        box(40, 10, 360, 100, { c: 'c1', d: 0.2 }),
        text(60, 36, 'what the app sees', { anchor: 'start', cls: 'sub', d: 0.2 }),
        text(60, 64, 'title: "Buy milk"', { anchor: 'start', cls: 'mono', d: 0.3 }),
        text(60, 88, 'done:  false', { anchor: 'start', cls: 'mono', d: 0.35 }),
        arrow(220, 116, 220, 190, { c: 'c4', d: 0.7 }),
        text(236, 140, 'schema: title → 1', { anchor: 'start', cls: 'sub', d: 0.8 }),
        text(236, 162, 'done → 2', { anchor: 'start', cls: 'sub', d: 0.85 }),
        box(40, 196, 360, 100, { c: 'blind', d: 1.1 }),
        text(60, 222, 'what is stored and synced', { anchor: 'start', cls: 'sub', d: 1.1 }),
        text(60, 258, '{1: "Buy milk", 2: false}', { anchor: 'start', cls: 'mono', d: 1.2 }),
        text(220, 340, 'names never leave the schema', { cls: 'sub', d: 1.5 }),
      ].join(''))}</div>`,
      text: `<p>Types are declared in <code>.osis</code> schema files with a small Rust-like syntax: strings, ints, floats, bools, blobs, tids, structs, enums, lists, maps and sets. Writes are type-checked against the writer's schema.</p>
        <p>Struct fields and enum cases carry explicit integer IDs. Field names stay in the schema, which is what lets a field be renamed freely and lets versions evolve (see <a href="#/versioning/1">Versioning</a>).</p>`,
      more: `<h3>Schema files</h3><ul><li>Loaded at runtime, or at compile time with <code>load_schema!()</code>; one hand-written parser for both.</li><li><code>///</code> doc comments are kept in the parsed schema, so generic tools and agents can read the invariants a value is meant to keep.</li><li>Every AK belongs to exactly one schema, the only place allowed to extend it. Someone else who needs more data adds their own aspects.</li><li>The exact ID syntax is still a sketch.</li></ul>`,
    },
    {
      title: 'One value, one byte string, on every platform',
      stage: () => {
        const bytes = [
          ['A2', 'c4', 'map(2)'], ['01', 'c2', 'key 1'], ['68', 'c1', 'text(8)'],
          ['42', 'c1'], ['75', 'c1'], ['79', 'c1'], ['20', 'c1'], ['6D', 'c1'], ['69', 'c1'], ['6C', 'c1'], ['6B', 'c1'],
          ['02', 'c2', 'key 2'], ['F4', 'c3', 'false'],
        ];
        const w = 52, gap = 6, x0 = (960 - bytes.length * (w + gap) + gap) / 2, y = 70;
        const bx = i => x0 + i * (w + gap);
        return svg(960, 360, [
          text(480, 24, '{1: "Buy milk", 2: false}', { cls: 'mono', d: 0 }),
          ...bytes.map(([b, c], i) => box(bx(i), y, w, 44, { label: b, c, mono: true, d: 0.3 + i * 0.06, r: 8 })),
          ...bytes.map(([, c, note], i) => note ? text(bx(i) + w / 2, 142, note, { cls: 'sub', d: 1.2 }) : '').join(''),
          text((bx(3) + bx(10) + w) / 2, 142, '"Buy milk"', { cls: 'sub', d: 1.2 }),
          path(`M${bx(3)},126 H${bx(10) + w}`, { c: 'c1', cls: 'thin', d: 1.1 }),
          device(250, 220, { kind: 'laptop', label: 'laptop, x86', c: 'c1', d: 1.6 }),
          device(250, 312, { kind: 'phone', label: 'phone, ARM', c: 'c2', d: 1.7 }),
          arrow(300, 220, 470, 260, { c: 'c1', d: 1.9 }),
          arrow(290, 306, 470, 270, { c: 'c2', d: 2 }),
          box(480, 232, 210, 66, { label: 'identical bytes', sub: 'hash and store as received', c: 'c3', d: 2.2 }),
          arrow(694, 265, 760, 265, { c: 'c3', d: 2.4 }),
          check(790, 265, { d: 2.6 }),
          text(810, 265, 'same hash, signature holds', { anchor: 'start', cls: 'small', d: 2.6 }),
        ].join(''));
      },
      text: `<p>Values are encoded as <strong>canonical CBOR</strong>: a binary JSON-like standard, restricted so each value has exactly one valid encoding (shortest integers, sorted map keys, always 8-byte floats).</p>
        <p>The decoder rejects anything non-canonical, so bytes are hashed and stored exactly as received and never re-encoded. Hashes and signatures stay valid across platforms and versions, so large values are never re-encoded to check them.</p>`,
      more: `<h3>Why CBOR, and why not serde</h3><ul><li>CBOR is an IETF standard with a deterministic profile, tags for osis's extra types (tid, enum, set, link), and a text notation so any tool can print a value without the schema.</li><li>Not the dCBOR profile: it encodes <code>1.0</code> as <code>1</code>, losing int vs float.</li><li>osis owns its encoder and strict decoder (a few hundred lines). Generic serde backends do not sort keys or reject non-canonical input. BLAKE3 is the only hash.</li></ul>`,
    },
    {
      title: 'Thing IDs are minted offline and prove their owner',
      stage: () => svg(960, 410, [
        text(20, 22, 'Creating a thing, on any device, offline', { anchor: 'start', cls: 'sub', d: 0 }),
        box(20, 40, 260, 76, { label: 'creation record', sub: 'owner: Alice · nonce: 9f3c…', c: 'c1', d: 0.1 }),
        arrow(284, 78, 344, 78, { d: 0.4 }),
        box(348, 50, 120, 56, { label: 'BLAKE3', c: 'c4', solid: true, d: 0.5 }),
        arrow(472, 78, 532, 78, { d: 0.8 }),
        box(536, 40, 400, 76, { label: 'tid = first 120 bits', sub: 'osis://zqf7FN-YvhtF_Dy-nqdi', c: 'c3', d: 0.9 }),
        g(path('M20,170 H940', { c: 'blind', cls: 'thin dash' }), { d: 1.3 }),
        text(20, 200, 'Any node receiving the thing later re-hashes the record', { anchor: 'start', cls: 'sub', d: 1.4 }),
        box(20, 220, 260, 64, { label: 'record says: Alice', c: 'c1', d: 1.6 }),
        arrow(284, 252, 344, 252, { d: 1.8 }),
        box(348, 226, 120, 52, { label: 'BLAKE3', c: 'c4', solid: true, d: 1.8 }),
        arrow(472, 252, 532, 252, { d: 2 }),
        text(548, 252, 'matches the tid', { anchor: 'start', cls: 'b', d: 2.1 }),
        check(700, 252, { d: 2.2 }),
        box(20, 310, 260, 64, { label: 'record says: Mallory', c: 'bad', d: 2.6 }),
        arrow(284, 342, 344, 342, { d: 2.8, c: 'bad' }),
        box(348, 316, 120, 52, { label: 'BLAKE3', c: 'c4', solid: true, d: 2.8 }),
        arrow(472, 342, 532, 342, { d: 3, c: 'bad' }),
        text(548, 342, 'different hash', { anchor: 'start', cls: 'b', d: 3.1 }),
        cross(686, 342, { d: 3.2 }),
        text(712, 342, 'rejected', { anchor: 'start', cls: 'small', d: 3.2 }),
      ].join('')),
      text: `<p>A thing's ID (<strong>tid</strong>) is a hash of its creation record: the owning actor plus a random nonce. Anyone can mint one offline with no registry, and nobody can later publish a different owner for it, since that record would hash to a different tid.</p>
        <p>Every check of who may write a thing starts here (see <a href="#/permissions/1">Permissions</a>).</p>`,
      more: `<h3>Numbers</h3><ul><li>120 bits, shown as 20 base64url characters. Forging a record for one given tid costs about 2<sup>120</sup> hashes.</li><li>The nonce keeps a bare tid from revealing its owner, and seeds the thing's secret for keyed hashes.</li><li>A key actor (a device, a recovery key) owns itself: its record is (public key, nonce).</li><li>The record is checked when the thing's data arrives. A bare reference to an unknown tid is never checked; it simply dangles.</li></ul>`,
    },
    {
      title: 'Things reference each other by tid, and references may dangle',
      stage: () => svg(960, 380, [
        box(340, 140, 240, 84, { label: 'Note "Offsite plan"', sub: 'body: "see osis://Qx9…"', c: 'c1', d: 0 }),
        arrow(336, 165, 236, 92, { c: 'c1', d: 0.4 }),
        box(30, 40, 200, 60, { label: 'Event "Offsite"', c: 'c2', d: 0.5 }),
        arrow(336, 200, 236, 280, { c: 'c1', d: 0.6 }),
        box(30, 270, 200, 60, { label: 'Person "Bob"', c: 'c4', d: 0.7 }),
        arrow(584, 165, 720, 90, { c: 'c1', d: 0.8 }),
        box(730, 40, 200, 60, { label: 'Task "Book flights"', c: 'c3', d: 0.9 }),
        arrow(584, 200, 720, 280, { c: 'c1', d: 1, dash: true }),
        box(730, 254, 200, 84, { label: 'osis://Qx9…', sub: 'not here (yet)', c: 'blind', ghost: true, mono: true, d: 1.1 }),
        arrow(130, 104, 130, 264, { c: 'c2', d: 1.3, curve: -20 }),
        text(110, 184, 'attendee', { anchor: 'end', cls: 'sub', d: 1.4 }),
      ].join('')),
      text: `<p>A <code>tid</code> is an ordinary value type, so references appear in typed fields or as <code>osis://</code> links in markdown. Values nest but never recurse; trees and graphs are built from things pointing at things.</p>
        <p>There are no foreign-key guarantees. The target may not have synced yet, may be shared with someone else, or may lack the aspects you expect. Apps treat a missing target like a missing file.</p>`,
    },
    {
      title: 'Groups are overlapping sets of things',
      stage: () => {
        const out = [];
        COLS.forEach((c, j) => out.push(text(cell(0, j).x + 37, 70, c, { cls: 'sub b', d: 0 })));
        for (let r = 0; r < 4; r++) {
          out.push(text(48, cell(r, 0).y + 22, String(r + 1), { cls: 'sub b', d: 0 }));
          for (let j = 0; j < 4; j++) out.push(box(cell(r, j).x, cell(r, j).y, 74, 44, { c: 'blind', r: 8, d: 0.05 * (r + j) }));
        }
        for (let j = 0; j < 4; j++) if (j !== 1) out.push(box(cell(2, j).x, cell(2, j).y, 74, 44, { c: 'c1', solid: true, r: 8, d: 0.8 + j * 0.05 }));
        for (let r = 0; r < 4; r++) if (r !== 2) out.push(box(cell(r, 1).x, cell(r, 1).y, 74, 44, { c: 'c2', solid: true, r: 8, d: 1.5 + r * 0.05 }));
        out.push(box(cell(2, 1).x, cell(2, 1).y, 74, 44, { label: 'B3', c: 'acc', solid: true, r: 8, d: 2.1 }));
        out.push(text(220, 340, 'row 3', { c: 'c1', cls: 'b', d: 0.9, anchor: 'end' }), text(240, 340, '+', { cls: 'sub', d: 1.6 }),
          text(260, 340, 'column B', { c: 'c2', cls: 'b', d: 1.6, anchor: 'start' }));
        // group tree
        out.push(
          box(640, 20, 160, 46, { label: 'Sheet', c: 'c4', d: 2.4 }),
          arrow(690, 70, 600, 130, { c: 'c4', d: 2.6 }), arrow(750, 70, 840, 130, { c: 'c4', d: 2.6 }),
          box(520, 134, 160, 46, { label: 'Rows', c: 'c1', d: 2.7 }),
          box(760, 134, 160, 46, { label: 'Columns', c: 'c2', d: 2.7 }),
          arrow(600, 184, 600, 236, { c: 'c1', d: 2.9 }), arrow(840, 184, 840, 236, { c: 'c2', d: 2.9 }),
          box(530, 240, 140, 46, { label: 'row 3', c: 'c1', solid: true, d: 3 }),
          box(770, 240, 140, 46, { label: 'column B', c: 'c2', solid: true, d: 3 }),
          arrow(620, 290, 700, 326, { c: 'c1', d: 3.2 }), arrow(820, 290, 740, 326, { c: 'c2', d: 3.2 }),
          box(680, 330, 80, 40, { label: 'B3', c: 'acc', solid: true, d: 3.3 }),
        );
        return svg(960, 380, out.join(''));
      },
      text: `<p>A <strong>group</strong> is just a thing with a <code>/group</code> aspect listing items and subgroups. A thing can sit in many groups; groups nest, overlap, and may even contain each other.</p>
        <p>Groups are what you sync. A spreadsheet can be a group of row groups and column groups, so a device can sync row 3 or column B alone, and cell B3 is still stored and sent only once. How is in <a href="#/sync/1">Sync</a>.</p>`,
      more: `<h3>Groups are not permissions</h3><p>Putting a thing in a group grants nobody any rights to it. Access comes from ownership and explicit membership edges (see <a href="#/permissions/1">Permissions</a>). A group meant to be shared as a unit is made a read member of its contents. Blind servers see a synced group as one flat, opaque set; nesting is only known to nodes with keys.</p>`,
    },
    {
      title: 'Big values are split into content-defined chunks',
      stage: () => {
        const widths = [56, 40, 70, 44, 62, 48];
        const tree = (x0, label, newIdx, d0) => {
          const ch = chunkRow(x0, widths.map((w, i) => (i === newIdx ? w + 22 : w)));
          const lMid = (ch[0].x + ch[2].x + ch[2].w) / 2, rMid = (ch[3].x + ch[5].x + ch[5].w) / 2, root = (lMid + rMid) / 2;
          const isNew = which => newIdx != null && which;
          const out = [
            text(root, 22, label, { cls: 'b', d: d0 }),
            box(root - 45, 44, 90, 40, { label: 'root', c: isNew(true) ? 'c3' : 'blind', solid: isNew(true), d: d0 + 0.1 }),
            arrow(root - 20, 86, lMid, 160, { c: isNew(true) ? 'c3' : 'blind', d: d0 + 0.3 }),
            arrow(root + 20, 86, rMid, 160, { c: 'blind', d: d0 + 0.3 }),
            box(lMid - 40, 164, 80, 40, { label: 'node', c: isNew(true) ? 'c3' : 'blind', solid: isNew(true), d: d0 + 0.4 }),
            box(rMid - 40, 164, 80, 40, { label: 'node', c: 'blind', d: d0 + 0.4 }),
          ];
          ch.forEach((c, i) => {
            const parent = i < 3 ? lMid : rMid;
            const n = newIdx === i;
            out.push(arrow(parent, 206, c.mid, 276, { c: n ? 'c3' : 'blind', d: d0 + 0.6, thin: true }));
            out.push(box(c.x, 280, c.w, 46, { label: n ? 'new' : '', c: n ? 'c3' : 'blind', solid: n, r: 6, d: d0 + 0.7 + i * 0.05 }));
          });
          return { out: out.join(''), ch };
        };
        const v1 = tree(40, 'version 1', null, 0);
        const v2 = tree(520, 'after inserting a paragraph', 2, 1.4);
        const mark = v1.ch[2];
        return svg(960, 400, [
          v1.out,
          path(`M${mark.mid},348 V332`, { c: 'c3', cls: 'arrow', d: 1 }),
          text(mark.mid, 364, 'insert here', { cls: 'sub', d: 1 }),
          v2.out,
          text(700, 370, 'upload 1 chunk + 2 tree nodes; the rest is reused', { cls: 'small', c: 'c3', d: 2.5 }),
        ].join(''));
      },
      text: `<p>Values can be many GB, and maps can hold millions of keys. Large values are cut into chunks at boundaries chosen by the content itself (a rolling hash), and the chunks form a tree.</p>
        <p>An insert only changes the chunk it lands in and the path to the root; every other chunk keeps its ID and is reused. Uploads and storage track the size of the edit, not the size of the value.</p>`,
      more: `<h3>Details</h3><ul><li>Large blobs use content-defined chunking (FastCDC-style); large maps and sets use prolly trees, where equal contents give equal trees regardless of edit history.</li><li>Each chunk is its own encrypted blob under a random key stored in its parent's link, so chunks are fetched, deduplicated and deleted piecewise.</li><li>Apps can read a large value whole, or stream and edit it without loading it all. The exact API is open, as is the size threshold for chunking.</li></ul>`,
    },
  ],
};
