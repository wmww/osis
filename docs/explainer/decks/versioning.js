import { svg, g, box, text, arrow, path, packet, device, check, cross, pill, code } from '../lib/svg.js';

const icon = () => svg(300, 92, [
  pill(50, 18, 'v1', { c: 'c2' }), pill(150, 18, 'v2', { c: 'c1' }), pill(250, 18, 'v3', { c: 'c4' }),
  arrow(50, 32, 120, 58, { c: 'c2', thin: true }), arrow(150, 32, 150, 56, { c: 'c1', thin: true }), arrow(250, 32, 180, 58, { c: 'c4', thin: true }),
  box(20, 60, 260, 28, { label: 'same data', c: 'acc', solid: true, r: 8 }),
].join(''));

// One row of the "who writes what" policy slide.
const phase = (x, title, sub, write, oldOn, newOn, d) => [
  text(x + 140, 24, title, { cls: 'b', d }),
  text(x + 140, 46, sub, { cls: 'sub', d }),
  box(x + 20, 70, 240, 50, { label: write, c: 'fgc', mono: true, d: d + 0.2 }),
  arrow(x + 90, 124, x + 75, 190, { c: oldOn ? 'c2' : 'blind', d: d + 0.4, dash: !oldOn }),
  arrow(x + 190, 124, x + 205, 190, { c: newOn ? 'c1' : 'blind', d: d + 0.4, dash: !newOn }),
  box(x + 15, 194, 120, 50, { label: 'old form', sub: oldOn || '', c: oldOn ? 'c2' : 'blind', solid: !!oldOn, ghost: !oldOn, d: d + 0.5 }),
  box(x + 145, 194, 120, 50, { label: 'new form', sub: newOn || '', c: newOn ? 'c1' : 'blind', solid: !!newOn, ghost: !newOn, d: d + 0.5 }),
].join('');

export default {
  id: 'versioning',
  title: 'Many apps, many versions',
  blurb: 'How old and new apps keep sharing the same data while schemas and formats evolve.',
  icon,
  slides: [
    {
      title: 'Apps update on their own schedule; the data is shared for years',
      stage: () => {
        const lanes = [
          [70, "Notes v1 · Alice's phone", 'c2', [[300, 'v1']], [420, 700]],
          [150, "Notes · Alice's laptop", 'c1', [[300, 'v1'], [560, 'v2']], [360, 620, 860]],
          [230, 'Tasks tool · Bob', 'c4', [[300, 'v3'], [760, 'v4']], [480, 820]],
        ];
        const writes = lanes.flatMap(([y, , c, , ws]) => ws.map(x => [x, y, c])).sort((a, b) => a[0] - b[0]);
        return svg(960, 400, [
          ...lanes.map(([y, label, c, vs], i) =>
            text(20, y, label, { anchor: 'start', cls: 'small b', d: i * 0.1 }) +
            g(path(`M260,${y} H930`, { c: 'blind', cls: 'thin' }), { d: i * 0.1 }) +
            vs.map(([x, v], j) => pill(x, y, v, { c, solid: j > 0, d: 0.3 + i * 0.1 + j * 0.8 })).join('')),
          ...writes.map(([x, y, c], i) => {
            const d = 1 + i * 0.25;
            return g(`<circle cx="${x}" cy="${y}" r="6" class="fills"/>`, { c, d }) +
              arrow(x, y + 10, x, 304, { c, dash: true, thin: true, d });
          }),
          box(260, 308, 670, 50, { label: 'one shared group: the same things and aspects', c: 'acc', solid: true, d: 0.6 }),
          arrow(260, 386, 930, 386, { c: 'blind', thin: true, d: 0.2 }),
          text(940, 386, 'time', { anchor: 'start', cls: 'sub', d: 0.2 }),
        ].join(''));
      },
      text: `<p>Data in osis behaves like a file format: many apps, each in several versions, read and write the same things. Nobody controls when apps update, users skip updates, and two devices may sit on different versions for years.</p>
        <p>So a schema change can never assume every reader has upgraded, and an old app can never be allowed to break newer data.</p>`,
    },
    {
      title: 'Never drop what you do not understand',
      stage: () => svg(960, 400, [
        device(90, 180, { kind: 'laptop', label: 'newer app', c: 'c1', d: 0 }),
        box(290, 30, 380, 300, { c: 'fgc', plain: true, r: 18, d: 0.2 }),
        text(480, 58, 'older node', { cls: 'b', d: 0.2 }),
        text(480, 80, 'its schema has no field 7', { cls: 'sub', d: 0.2 }),
        box(310, 100, 340, 46, { label: '1 title: "Buy milk"', c: 'c3', mono: true, anchor: 'start', d: 1.2 }),
        box(310, 154, 340, 46, { label: '2 done: false', c: 'c3', mono: true, anchor: 'start', d: 1.3 }),
        box(310, 208, 340, 46, { label: '7 ??? : 8A 03 1F …', c: 'blind', ghost: true, mono: true, anchor: 'start', d: 1.5 }),
        text(480, 282, 'kept, merged, relayed', { cls: 'sub', d: 1.7 }),
        text(480, 304, 'read again after the next upgrade', { cls: 'sub', d: 1.8 }),
        path('M130,180 H284', { c: 'c1', cls: 'arrow', d: 0.4 }),
        packet('M130,180 H284', { c: 'c1', shape: 'blob', begin: 0.6, dur: 0.8, repeat: 1 }),
        device(870, 180, { kind: 'phone', label: 'another newer app', c: 'c1', d: 2 }),
        path('M676,180 H836', { c: 'c1', cls: 'arrow', d: 2.1 }),
        packet('M676,180 H836', { c: 'c1', shape: 'blob', begin: 2.4, dur: 1, repeat: 'indefinite' }),
        text(756, 160, 'field 7 intact', { cls: 'sub', d: 2.2 }),
        cross(380, 372, { d: 2.6, s: 0.8 }),
        text(398, 372, 'never: reject, discard, panic', { anchor: 'start', cls: 'small', d: 2.6 }),
      ].join('')),
      text: `<p>The <strong>parking rule</strong>: a node never rejects, discards or crashes on data it cannot interpret, whether that is an unknown field, aspect, merge encoding or format version. It stores it, merges what it can, relays it to others, and looks again after it upgrades.</p>
        <p>"Not understood" is treated like "not received yet". That keeps an old device from silently destroying a newer app's data on its way through.</p>`,
      more: `<h3>Three layers of compatibility</h3><ul><li><strong>Store, relay, merge</strong>: universal. Merge needs no schema, so any node can combine any aspect's state.</li><li><strong>Typing</strong>: per app. If an app's schema cannot type a value, the typed read fails with the path; the untyped value API always works, and an app can skip one bad element of a large list.</li><li><strong>Meaning</strong>: invariants in doc comments, which no tool can check.</li></ul>`,
    },
    {
      title: 'The wire schema only grows',
      stage: () => `<div class="split">${code(`{k:type} {t:task} = {k:struct} {
    {n:1} title: {t:string},
    {n:2} done: {t:bool},
    {n:3} tags: {t:set}<{t:string}>,
    {n:4} status: {t:option}<{t:status}>,  {cm:// new: reads as none}
    {k:reserved} {n:5};                 {cm:// removed, never reused}
};
{k:revision} {n:7};`)}${svg(440, 380, [
        box(10, 10, 200, 56, { label: 'lock file', sub: 'last published, rev 6', c: 'blind', d: 0.2 }),
        box(230, 10, 200, 56, { label: 'schema file', sub: 'rev 7', c: 'c1', d: 0.3 }),
        arrow(110, 70, 200, 110, { d: 0.5 }), arrow(330, 70, 240, 110, { d: 0.5 }),
        box(140, 114, 160, 44, { label: 'checker', c: 'c4', solid: true, d: 0.7 }),
        ...[
          ['add a field with a default', true], ['add an aspect', true], ['reuse a removed ID', false],
          ["change a field's type", false], ['add a required field', false],
        ].map(([s, ok], i) => (ok ? check : cross)(40, 196 + i * 40, { d: 1 + i * 0.15, s: 0.9 }) +
          text(62, 196 + i * 40, s, { anchor: 'start', cls: 'small', d: 1 + i * 0.15 })),
      ].join(''))}</div>`,
      text: `<p>Names never go on the wire, only integer IDs, and an ID is never reused. Structs are <strong>open</strong>: readers ignore field IDs they do not know, and writes only touch the fields the writer knows, so unknown fields survive a round trip through an old app.</p>
        <p>A new field gets a <strong>reader-side default</strong> instead of a migration. A checker built into the schema loader compares each revision against the last published one and refuses anything that is not purely additive.</p>`,
      more: `<h3>Notes</h3><ul><li>The syntax for IDs, <code>reserved</code> and <code>revision</code> is still a sketch.</li><li>Commit headers carry the writer's schema revision and a hash of the aspect's type. Seeing a higher revision of your own schema is the "update required" signal.</li><li>The one change no checker can catch is giving an existing ID a new meaning (feet become meters). The rule is simply: new meaning, new ID.</li></ul>`,
    },
    {
      title: 'A breaking change is a new form that succeeds the old one',
      stage: () => svg(960, 385, [
        box(30, 30, 270, 76, { label: 'old form', sub: '2 done: bool', c: 'c2', d: 0 }),
        box(660, 30, 270, 76, { label: 'new form', sub: '4 status: todo | doing | blocked | done', c: 'c1', d: 0.2 }),
        arrow(306, 52, 652, 52, { c: 'c1', d: 0.5 }),
        text(480, 36, 'f: read old as new', { cls: 'small b', d: 0.6 }),
        arrow(652, 88, 306, 88, { c: 'c2', d: 0.9 }),
        text(480, 106, 'g: write new into old', { cls: 'small b', d: 1 }),
        text(480, 140, 'done ↔ true · todo, doing → false', { cls: 'sub mono', d: 1.1 }),
        text(480, 162, 'blocked → cannot be expressed', { cls: 'small mono', c: 'bad', d: 1.2 }),
        path('M30,186 H930', { c: 'blind', cls: 'thin', d: 1.4 }),
        text(30, 212, 'Both forms stay in the data. Which one does a new app show? The newer one.', { anchor: 'start', cls: 'small b', d: 1.5 }),
        arrow(30, 300, 920, 300, { c: 'blind', thin: true, d: 1.6 }),
        pill(240, 256, 'new app: status = blocked', { c: 'c1', d: 1.9, mono: false }),
        g(`<circle cx="240" cy="300" r="6" class="fills"/>`, { c: 'c1', d: 1.9 }),
        pill(540, 256, 'old app: done = true', { c: 'c2', d: 2.4, mono: false }),
        g(`<circle cx="540" cy="300" r="6" class="fills"/>`, { c: 'c2', d: 2.4 }),
        box(660, 322, 270, 56, { label: 'new app shows: done', sub: 'old form is newer, so f(true)', c: 'c3', d: 2.9 }),
        arrow(560, 308, 656, 344, { c: 'c3', d: 2.9, thin: true }),
      ].join('')),
      text: `<p>When the old shape cannot hold every new value, the schema adds fields with new IDs and declares that they <strong>succeed</strong> the old ones. The app supplies two conversions: <strong>f</strong> reads old data as new, <strong>g</strong> writes new data in the old shape where it can.</p>
        <p>Readers show whichever form was written last, so an old app's later edit still wins, read through f. Only values g cannot express (here, "blocked") look stale to old apps.</p>`,
      more: `<h3>Why this lives in app code, not the core</h3><p>The core never interprets a transition. Merge is schema-free, so a maintainer who ignores the convention still converges; the convention can change without touching stored data. Timestamps are already the system's one conflict rule, so the tie-break needs no extra laws relating f and g. Renaming an aspect, splitting one field into two, or merging two into one all use the same mechanism.</p>`,
    },
    {
      title: 'Installing an update never changes stored data by itself',
      stage: () => svg(960, 330, [
        phase(0, 'Old apps still write here', 'g is exact for this value', 'status = done', 'done = true', '', 0),
        phase(330, 'Value g cannot express', 'old apps see it as stale', 'status = blocked', '', 'blocked', 0.9),
        phase(660, 'Every node reads v2', 'from published node info', 'status = doing', '', 'doing', 1.8),
        path('M318,10 V250', { c: 'blind', cls: 'thin', d: 0.8 }),
        path('M648,10 V250', { c: 'blind', cls: 'thin', d: 1.7 }),
        arrow(20, 300, 930, 300, { c: 'blind', thin: true, d: 0.1 }),
        text(480, 318, 'time in one shared group', { cls: 'sub', d: 0.1 }),
      ].join('')),
      text: `<p>An upgraded app gains the <em>ability</em> to write the new form; it decides per write which form to use. By default it writes the old form whenever that loses nothing, so older apps in the group keep working fully. Only a value the old form cannot hold forces the new form, and only for that value.</p>
        <p>Once every active device can read the new form, apps start writing it. Devices may decide at different times; the result still merges correctly.</p>`,
      more: `<h3>Policy inputs (all local)</h3><p>"Active" means every recent writer in the group's commit headers and every node syncing it. No step needs global agreement: nodes that decide differently produce a mix of forms, which the timestamp rule reads correctly.</p><ul><li>Whether g is exact, or approximate but declared acceptable (unit conversions).</li><li>Schema revisions seen in this group's recent commit headers.</li><li>Each node's published <code>/node</code> info: which revisions and forms it reads. This catches read-only old apps, which never appear in headers. An age cutoff keeps a dead phone from blocking forever.</li><li>An explicit per-group or per-app compatibility setting, which overrides the rest.</li></ul><p>A whole redesign is an ordinary import (read old forms, write new ones) once the group has moved on. The core has no migration concept.</p>`,
    },
    {
      title: 'Merge encodings upgrade without breaking anyone',
      stage: () => svg(960, 300, [
        box(30, 30, 270, 70, { label: 'plain string, last write wins', sub: '"Hello", from an old app', c: 'c2', d: 0 }),
        arrow(304, 65, 386, 65, { c: 'c4', d: 0.4 }),
        text(345, 46, 'embed', { cls: 'sub', d: 0.4 }),
        box(390, 30, 270, 70, { label: 'text CRDT', sub: 'reset, then insert "Hello"', c: 'c4', d: 0.6 }),
        box(30, 170, 270, 70, { label: 'text CRDT', sub: '"Hello world", from a new app', c: 'c1', d: 0.2 }),
        arrow(600, 104, 716, 126, { c: 'c4', d: 1 }),
        arrow(304, 205, 716, 160, { c: 'c1', d: 1 }),
        box(720, 100, 210, 76, { label: 'join', sub: 'stored as the richer one', c: 'c3', solid: true, d: 1.3 }),
        g(text(30, 280, 'Other upgrade edges:', { anchor: 'start', cls: 'sub' }) +
          pill(310, 280, 'int (last write wins) → counter', { c: 'c4', mono: false }) +
          pill(610, 280, 'no edge → later write resets', { c: 'blind', mono: false }), { d: 1.7 }),
      ].join('')),
      text: `<p>Below the schema, each aspect's state uses a <strong>merge encoding</strong>: a plain last-write-wins register, a counter, a text CRDT, and so on. The core defines how each simpler encoding embeds into a richer one, so when two nodes disagree, the join converts the simpler encoding to the richer one.</p>
        <p>So turning a title into collaboratively edited text is an additive change. Until old apps are gone, their saves overwrite concurrent text edits, since old code has no notion of merging characters.</p>`,
    },
    {
      title: 'Read everything older; write the oldest format that fits',
      stage: () => {
        const cols = ['format v1 node', 'format v2 node', 'format v3 node'];
        const rows = [
          ['title edit', 'v1', [1, 1, 1]],
          ['task list edit', 'v1', [1, 1, 1]],
          ['edit using a v3 feature', 'v3', [0, 0, 1]],
        ];
        const cx = i => 480 + i * 170, ry = i => 150 + i * 70;
        return svg(960, 380, [
          device(80, 70, { kind: 'laptop', label: 'writer runs v3', c: 'c1', d: 0 }),
          ...cols.map((c, i) => text(cx(i), 70, c, { cls: 'small b', d: 0.2 + i * 0.1 })),
          ...rows.map(([n, v, res], r) =>
            box(20, ry(r) - 26, 280, 52, { label: n, c: 'fgc', anchor: 'start', d: 0.6 + r * 0.5 }) +
            pill(340, ry(r), `as ${v}`, { c: v === 'v1' ? 'c3' : 'c4', solid: true, d: 0.7 + r * 0.5 }) +
            res.map((ok, i) => ok ? check(cx(i), ry(r), { d: 0.9 + r * 0.5 + i * 0.08 })
              : pill(cx(i), ry(r), 'parked', { c: 'blind', d: 0.9 + r * 0.5 + i * 0.08, mono: false })).join('')),
          text(480, 360, 'Old nodes lag only on the one aspect that used the new feature, and catch up after upgrading.', { cls: 'sub', d: 2.5 }),
        ].join(''));
      },
      text: `<p>The bytes on the wire (commit headers, delta encodings, chunks, values) carry one format version. Readers accept every older version forever. Writers emit the <strong>oldest</strong> version that can express each change, so upgrading one device strands nobody until a new feature is actually used, and then only on that aspect.</p>
        <p>Everything that is local to a node (storage layout, indexes, the sync protocol, the API) can change freely, because none of it is shared data.</p>`,
      more: `<h3>Prior art</h3><p>Protobuf (integer IDs, reserved numbers, additive discipline), Avro (reader and writer schemas, defaults), SQLite's file-format promise (read everything older, forever). Cambria-style lenses were considered and rejected: no conversion language in the schema and no core-managed mirroring between forms.</p>`,
    },
  ],
};
