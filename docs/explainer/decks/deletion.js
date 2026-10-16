import { svg, g, box, text, arrow, path, blob, person, check, cross, pill } from '../lib/svg.js';

// Wrap markup so it fades to near-invisible at `d` seconds (after its own entrance, if any).
const fade = (body, d) => `<g class="fadeout" style="--d:${d}s">${body}</g>`;
// Like fade, but disappears entirely (for content replaced in place). GONE_CSS must be in the same slide.
const gone = (body, d) => `<g class="dk-gone" style="--d:${d}s">${body}</g>`;
const GONE_CSS = '<style>.dk-gone{animation:dk-gone .5s var(--ease) var(--d,0s) forwards}@keyframes dk-gone{to{opacity:0}}</style>';
// Dashed path that fades in. Written raw: path() sets pathLength=1, which turns dashes solid.
const dpath = (p, { c = 'fgc', cls = '' } = {}, d) => g(`<path d="${p}" class="ln ${c} ${cls}"/>`, { d });
// One-shot dot that travels along `p` and vanishes on arrival.
const shot = (p, { c = 'c3', begin = 0, dur = 1.2, r = 5 } = {}) =>
  `<g class="${c}" opacity="0"><circle r="${r}" class="fills"/>` +
  `<animate attributeName="opacity" values="0;1;1;0" keyTimes="0;.12;.88;1" dur="${dur}s" begin="${begin}s" fill="freeze"/>` +
  `<animateMotion path="${p}" dur="${dur}s" begin="${begin}s" fill="freeze"/></g>`;

const icon = () => svg(300, 92, [
  box(14, 26, 80, 40, { label: 'v1', c: 'bad', ghost: true, r: 8 }),
  box(110, 26, 80, 40, { label: 'v2', c: 'bad', ghost: true, r: 8 }),
  box(206, 26, 80, 40, { label: 'live', c: 'c3', solid: true, r: 8 }),
].join(''));

export default {
  id: 'deletion',
  title: 'Deletion',
  blurb: 'Retention classes, purge without fingerprints, crypto-shredding, and backups readers cannot wipe.',
  icon,
  slides: [
    {
      title: 'Deleted data hides in many places',
      stage: () => {
        const cx = 480, cy = 200;
        const sats = [
          [130, 70, 'your laptop', 'live copy', 'c1'],
          [480, 50, 'your phone', 'live copy', 'c1'],
          [830, 70, "a friend's laptop", 'live copy', 'c2'],
          [860, 200, 'edit history', 'old versions', 'fgc'],
          [830, 330, 'undo buffer', 'kept for ctrl-z', 'fgc'],
          [480, 355, 'server backup', 'encrypted, but kept', 'blind'],
          [130, 330, 'search index', 'words of the text', 'fgc'],
          [100, 200, 'SSD pages', 'freed is not erased', 'bad'],
        ];
        return svg(960, 400, [
          ...sats.map(([x, y], i) => path(`M${cx},${cy} L${x},${y}`, { c: 'blind', cls: 'thin', d: 0.3 + i * 0.12 })),
          ...sats.map(([x, y], i) => shot(`M${cx},${cy} L${x},${y}`, { c: 'c2', begin: 0.3 + i * 0.12, dur: 0.8, r: 4 })),
          ...sats.map(([x, y, l, s, c], i) => box(x - 85, y - 26, 170, 52, { label: l, sub: s, c, d: 0.6 + i * 0.12 })),
          box(cx - 105, cy - 36, 210, 72, { label: 'bank details', sub: 'pasted into a shared doc', c: 'c2', solid: true, d: 0 }),
        ].join(''));
      },
      text: `<p>One paste of the wrong text lands on every device that syncs the doc, in its edit history, undo buffers, search indexes and server backups. Storage engines don't reliably erase either: SSDs, journals and copy-on-write filesystems keep old pages around.</p>
        <p>Goal: once an honest node applies a deletion, the content is unrecoverable there, even from a later-stolen device, and nothing left behind confirms what it was. Offline copies and dishonest nodes are out of scope.</p>`,
    },
    {
      title: 'Each aspect chooses how long old versions live',
      stage: () => {
        const xs = [370, 530, 690], lanes = [
          ['preserve', 'kept and synced until explicitly purged', 'c3', 70, []],
          ['undefined (default)', 'dropped later, by each node’s policy', 'fgc', 165, [[0, 3.4]]],
          ['purge', 'dropped everywhere as soon as replaced', 'bad', 260, [[0, 1.15], [1, 1.85]]],
        ];
        const appear = [0.3, 1.0, 1.7];
        return svg(960, 340, [
          GONE_CSS,
          ...lanes.map(([n, s, c, y, drops]) =>
            text(30, y - 10, n, { anchor: 'start', cls: 'b', c: c === 'fgc' ? undefined : c, d: 0 }) +
            text(30, y + 12, s, { anchor: 'start', cls: 'sub', d: 0 }) +
            xs.map((x, i) => {
              const drop = drops.find(([j]) => j === i);
              const live = i === 2;
              const b = box(x, y - 23, 140, 46, { label: `v${i + 1}`, c: live ? 'c3' : c === 'fgc' ? 'blind' : c, solid: live, d: appear[i], r: 10 });
              return drop ? gone(b, drop[1]) + box(x, y - 23, 140, 46, { label: 'header only', c: 'blind', ghost: true, d: drop[1] + 0.3, r: 10 }) : b;
            }).join('')),
          arrow(370, 318, 860, 318, { c: 'blind', d: 0.2 }),
          text(870, 318, 'time', { anchor: 'start', cls: 'sub', d: 0.2 }),
        ].join(''));
      },
      text: `<p>A schema gives each aspect (each kind of value) a <strong>retention class</strong>, and a single write can override it. <strong>preserve</strong> keeps full history, <strong>purge</strong> drops superseded content on every node the moment it applies the change, and the default leaves old versions to each node's cleanup policy.</p>
        <p>Purge is not free: every edit to a purge-class value uploads a fresh snapshot and retires the old bodies at servers. It is meant for values where that is worth it.</p>`,
      more: `<h3>Explicit purge of preserved history</h3>
        <p>"I pasted my bank details into a versioned shared doc" is the case for purging preserved history on demand. A delta's own author or an admin may purge it. Letting any writer do it would turn recoverable vandalism into permanent loss.</p>
        <p>Granularity is one delta, i.e. one (commit, aspect) pair. A commit touching several aspects can lose just one of its deltas; its blob is rewritten without it under the same commit ID.</p>`,
    },
    {
      title: 'Purge drops the body and keeps the signed header',
      stage: () => svg(960, 300, [
        GONE_CSS,
        box(150, 30, 520, 240, { c: 'c1', d: 0 }),
        text(170, 52, 'a commit', { anchor: 'start', cls: 'sub', d: 0 }),
        box(170, 70, 480, 78, { label: 'header (signed)', sub: 'laptop · 14:02 · /account/pin · hash(delta)', c: 'c4', d: 0.2 }),
        gone(box(170, 166, 480, 78, { label: 'delta body', sub: 'PIN = 4831 · random nonce 9f2c…', c: 'c2', d: 0.4 }), 1.5),
        box(170, 166, 480, 78, { label: 'body purged', c: 'bad', ghost: true, d: 1.9 }),
        check(710, 109, { d: 2.4 }),
        text(732, 100, 'still verifies:', { anchor: 'start', cls: 'b small', d: 2.4 }),
        text(732, 120, 'who, when, which aspect', { anchor: 'start', cls: 'sub', d: 2.45 }),
        cross(710, 205, { d: 2.7 }),
        text(732, 196, 'content gone', { anchor: 'start', cls: 'b small', d: 2.7 }),
        text(732, 216, 'no copy, no undo', { anchor: 'start', cls: 'sub', d: 2.75 }),
      ].join('')),
      text: `<p>The signature covers the header, and the header holds only a hash of the delta. So bodies can be destroyed while the commit stays valid: any reader can still check that an edit happened, when, by whom and to which aspect, and the purge itself stays on record.</p>
        <p>Nothing in osis depends on keeping full history, so purged history never breaks sync or merging.</p>`,
    },
    {
      title: 'Removing part of a value: snapshot, then retire',
      stage: () => svg(960, 360, [
        box(30, 40, 300, 250, { c: 'fgc', d: 0 }),
        text(50, 62, 'the doc', { anchor: 'start', cls: 'sub', d: 0 }),
        box(50, 82, 260, 50, { label: 'Shopping list', c: 'blind', r: 8, d: 0.1 }),
        fade(box(50, 144, 260, 50, { label: 'IBAN DE89 3704 …', c: 'bad', r: 8, d: 0.2 }), 1.2),
        box(50, 206, 260, 50, { label: 'Call Sam', c: 'blind', r: 8, d: 0.3 }),
        box(400, 40, 530, 150, { c: 'blind', d: 0.1 }),
        text(420, 62, 'history at the server', { anchor: 'start', cls: 'sub', d: 0.1 }),
        ...[1, 2, 3, 4].map(i => fade(blob(400 + i * 80, 118, { c: i === 2 || i === 3 ? 'c2' : 'blind', size: 34, label: `edit ${i}`, d: 0.2 + i * 0.08 }), 3.0)),
        shot('M330,170 Q560,280 840,135', { c: 'c3', begin: 1.6, dur: 1.2, r: 6 }),
        blob(850, 118, { c: 'c3', size: 34, label: 'snapshot', d: 2.6 }),
        pill(540, 245, '① upload a snapshot of what is still live', { c: 'c3', mono: false, d: 2.0 }),
        pill(540, 290, '② retire every body that carried it', { c: 'bad', mono: false, d: 3.0 }),
        text(540, 330, 'in the same sync, no batching', { cls: 'sub', d: 3.3 }),
      ].join('')),
      text: `<p>Deleting one paragraph of a purge-class doc can't just delete one commit: earlier edits may carry the same text. The node purges every delta that carries it and replaces the aspect's history with a snapshot of what is still live, in the same sync.</p>
        <p>A signed delta is never rewritten. History becomes "snapshot plus newer edits", and every node that applies it drops the old bodies.</p>`,
    },
    {
      title: 'Purge must not leave a fingerprint',
      stage: () => {
        const guesses = ['0000', '0001', '0002', '…', '1233', '1234'];
        return svg(960, 400, [
          GONE_CSS,
          text(240, 24, 'A plain hash left behind', { cls: 'b', d: 0 }),
          box(40, 46, 400, 50, { label: 'kept: hash("1234") = 03ac…', c: 'bad', mono: true, d: 0.1 }),
          text(240, 122, 'an attacker hashes every guess', { cls: 'sub', d: 0.4 }),
          ...guesses.map((s, i) => {
            const y = 150 + i * 34, d = 0.6 + i * 0.3, hit = s === '1234';
            return pill(200, y, s, { c: hit ? 'c3' : 'blind', d, w: 70 }) +
              (s === '…' ? '' : hit ? check(260, y, { d: d + 0.1, s: 0.8, c: 'bad' }) : cross(260, y, { d: d + 0.1, s: 0.7, c: 'blind' }));
          }),
          text(285, 320, 'match: the PIN was 1234', { anchor: 'start', cls: 'b small', c: 'bad', d: 2.4 }),
          path('M480,30 V380', { c: 'blind', cls: 'thin dash', d: 0 }),
          text(720, 24, 'What osis keeps', { cls: 'b', d: 0.2 }),
          gone(box(520, 46, 400, 50, { label: 'body: "1234" + random nonce', c: 'c2', mono: true, d: 0.3 }), 1.4),
          box(520, 46, 400, 50, { label: 'body purged', c: 'bad', ghost: true, d: 1.8 }),
          text(720, 112, 'nonce destroyed with the body', { cls: 'sub', d: 1.6 }),
          box(520, 140, 400, 56, { label: 'tombstone: (laptop, dot 41) @ 14:02', sub: 'names the edit, not the value', c: 'c3', mono: true, d: 1.9 }),
          box(520, 214, 400, 56, { label: 'other hashes: keyed', sub: 'with a secret only readers of the thing hold', c: 'c4', d: 2.2 }),
          pill(620, 320, '1234', { c: 'blind', d: 2.6, w: 70 }),
          cross(675, 320, { d: 2.9, s: 0.8 }),
          text(700, 320, 'nothing to compare with', { anchor: 'start', cls: 'b small', d: 2.9 }),
        ].join(''));
      },
      text: `<p>If anything derived from the deleted value survives, such as a hash in an index, a link or a tombstone, anyone can test guesses against it. For a 4-digit PIN or a yes/no field that takes moments.</p>
        <p>So every delta body carries a random nonce that dies with it, every outward hash is keyed with a per-thing secret, and removals name the edit by its <strong>dot</strong> (author node plus counter), never the value or key. Purge also drops every local index entry and link to the content.</p>`,
      more: `<h3>Why this holds even against members</h3>
        <p>The guarantee is meant to hold even against someone who holds the read key. Keyed hashes stop outsiders; the destroyed nonce stops insiders, since a hash over (nonce, value) can't be recomputed without the nonce.</p>
        <p>Removing a set element or map key by its creation dot has a side effect on merging: a concurrent add of the same value elsewhere has a different dot and survives. That trade (add wins over unseen adds) was accepted to keep tombstones content-free.</p>`,
    },
    {
      title: 'Deleting locally means forgetting a key',
      stage: () => {
        const nodes = [170, 480, 790], leafDx = [-92, 0, 92];
        const names = [['notes', 'tasks', 'photos'], ['calendar', 'bank doc', 'people'], ['chat', 'sheet', 'drafts']];
        return svg(960, 400, [
          GONE_CSS,
          ...nodes.map((x, i) => path(`M480,72 L${x},128`, { c: 'c4', cls: 'thin', d: 0.2 + i * 0.05 })),
          ...nodes.flatMap((x, i) => leafDx.map((dx, j) => path(`M${x},168 L${x + dx},222`, { c: 'c4', cls: 'thin', d: 0.4 + i * 0.05 + j * 0.03 }))),
          box(400, 20, 160, 52, { label: 'root key', sub: 'secure hardware', c: 'c4', solid: true, d: 0 }),
          ...nodes.map((x, i) => box(x - 60, 128, 120, 40, { label: 'branch key', c: 'c4', d: 0.25 + i * 0.05 })),
          ...nodes.flatMap((x, i) => leafDx.map((dx, j) => {
            const target = i === 1 && j === 1;
            const b = box(x + dx - 42, 222, 84, 40, { label: names[i][j], c: target ? 'c2' : 'fgc', d: 0.5 + i * 0.05 + j * 0.03, r: 8 });
            return target ? gone(b, 1.6) + box(x + dx - 42, 222, 84, 40, { c: 'bad', ghost: true, d: 1.7, r: 8 }) + cross(x + dx, 242, { d: 1.6 }) : b;
          })),
          box(400, 20, 160, 52, { label: 'new root', sub: 'old one erased', c: 'c3', solid: true, d: 2.4 }),
          box(420, 128, 120, 40, { label: 'new key', c: 'c3', solid: true, d: 2.1 }),
          box(40, 310, 880, 64, { label: 'disk: ciphertext only (SQLite, files, …)', sub: 'old pages of "bank doc" may linger, but nothing can decrypt them', c: 'blind', d: 0.8 }),
        ].join(''));
      },
      text: `<p>No storage engine erases reliably, so osis never relies on erasing data. Every piece of local plaintext lives in a unit encrypted under its own key; those keys hang off a tree whose root sits in the one place the platform can truly erase, such as a hardware keystore.</p>
        <p>Deleting a unit drops its key, and every key above it in the tree gets replaced. Leftover pages on disk become noise. This is what makes deletion hold even if the device is stolen later.</p>`,
      more: `<h3>Large values too</h3>
        <p>Chunks of large values are encrypted under random keys stored in their parent links, and a commit's blob key is reachable only through wraps. Dropping a version's wraps makes its deltas, links and every chunk only that version reached unreadable, at a cost independent of the value's size.</p>
        <p>The tree is 256-ary, so three levels cover 16 million units. A deletion rewrites about three small nodes and one root write, batched per sync; the new root is written last, so a crash leaves either the old or the new tree, never a half-deleted one.</p>`,
    },
    {
      title: 'Readers cannot wipe a backup',
      stage: () => {
        const cols = [['upload', 400], ['soft retire', 590], ['hard delete', 790]];
        const rows = [
          ['reader', 'c1', ['y', 'n', 'n']],
          ['writer', 'c2', ['y', 'y', 'token']],
          ['admin', 'c4', ['y', 'y', 'y']],
        ];
        return svg(960, 380, [
          ...cols.map(([h, x]) => text(x, 40, h, { cls: 'b', d: 0 })),
          text(590, 62, 'to a 30-day recycle bin', { cls: 'sub', d: 0 }),
          text(790, 62, 'gone immediately', { cls: 'sub', d: 0 }),
          ...rows.map(([n, c, cells], i) => {
            const y = 120 + i * 80, d = 0.3 + i * 0.4;
            return box(30, y - 32, 900, 64, { c, d, r: 14 }) +
              person(80, y, { c, r: 18, d }) +
              text(112, y, n, { anchor: 'start', cls: 'b', d }) +
              cells.map((v, j) => {
                const x = cols[j][1];
                return v === 'y' ? check(x, y, { d: d + 0.1 + j * 0.08 })
                  : v === 'n' ? cross(x, y, { d: d + 0.1 + j * 0.08 })
                  : pill(x, y, 'one entry, with its token', { c: 'c4', mono: false, d: d + 0.25 });
              }).join('');
          }),
          text(480, 360, 'A blind server checks only signatures under each label’s per-role keys; it never learns why.', { cls: 'sub', d: 1.6 }),
        ].join(''));
      },
      text: `<p>A blind server may be someone's only backup, so its delete rights are split by role. Readers can only upload (to relay what they received). Writers can retire blobs into a recycle bin, recoverable for a grace period. Only admins can hard-delete any entry outright.</p>
        <p>For one entry, a <strong>delete token</strong> from the delta's author plus a signature under the label's current writer (soft-retire) key deletes it immediately. That is how a purge finishes at servers without waiting 30 days.</p>`,
      more: `<h3>Delete tokens</h3>
        <p>When a delta introduces a blob, its author derives a token from a secret and the blob ID and puts the token's hash in the commit header; servers store the 16-byte hash per entry. Presenting the preimage plus a signature under the label's current writer key deletes that entry. The token alone does nothing, so a removed writer loses the power as soon as the label's keys are re-registered.</p>
        <p>For purge-class content the token derives from the writers' shared secret, so any current writer can finish another writer's purge on its next sync. Servers learn nothing from tokens: not the author, not the retention class.</p>`,
    },
    {
      title: 'Expiry: gone at time T, even with nobody online',
      stage: () => {
        const T = 640;
        const lanes = [['phone', 90, 'c1'], ['laptop', 180, 'c2'], ['server', 270, 'blind']];
        return svg(960, 360, [
          ...lanes.map(([n, y, c]) => text(30, y, n, { anchor: 'start', cls: 'b small', c, d: 0 })),
          pill(200, 36, 'sent 12:00 · expires 18:00', { c: 'c4', mono: false, d: 0 }),
          path(`M${T},50 V320`, { c: 'bad', cls: 'dash', d: 0.2 }),
          text(T, 340, 'T = 18:00', { cls: 'b small', c: 'bad', d: 0.2 }),
          ...lanes.map(([, y, c], i) => blob(200, y, { c, size: 24, d: 0.4 + i * 0.1 })),
          path(`M216,90 H${T - 16}`, { c: 'c1', d: 0.7 }),
          path('M216,180 H500', { c: 'c2', d: 0.8 }),
          dpath('M500,180 H760', { c: 'blind', cls: 'thin dash' }, 1.0),
          text(580, 162, 'offline', { cls: 'sub', d: 1.0 }),
          path(`M216,270 H${T - 16}`, { c: 'blind', d: 0.9 }),
          cross(T, 90, { d: 1.8 }),
          cross(T, 270, { d: 2.0 }),
          text(T + 22, 270, 'server deletes the entry by itself', { anchor: 'start', cls: 'small', d: 2.1 }),
          cross(760, 180, { d: 2.7 }),
          text(782, 180, 'back at 19:00: drops it', { anchor: 'start', cls: 'small', d: 2.8 }),
          text(T + 22, 304, 'late re-uploads are refused', { anchor: 'start', cls: 'sub', d: 3.1 }),
        ].join(''));
      },
      text: `<p>A commit can carry an expiry time. At that time every node treats its content as purged, including blind servers, which see the time in plain metadata and delete the entry with no one online. A device that was offline drops it the moment it wakes up.</p>
        <p>That makes disappearing messages and short-lived buffers cheap: nothing has to be retired by hand. The cost is that servers learn which entries expire, and when.</p>`,
      more: `<h3>What osis does not promise</h3>
        <ul>
          <li>Copies made outside osis (screenshots, exports, a device that never syncs again) are out of reach.</li>
          <li>Dishonest nodes can keep anything they received; deletion binds honest nodes only.</li>
          <li>Expiry is a hard upper bound, not a minimum: there is no server-enforced legal hold.</li>
          <li>Clock skew moves the moment of expiry slightly, not the outcome: the expiry is part of the commit, so every node agrees on it.</li>
        </ul>`,
    },
  ],
};
