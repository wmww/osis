import { svg, g, box, text, tiles } from '../lib/svg.js';

// A balance scale: two goals that can't both hold, tipped toward the one that wins.
// win: 'left' | 'right' | 'even'. Width w, left edge x0. The beam rotates and the pans sink/rise to match.
const SCALE_CSS = `<style>
  .dk-scale .beam { transform-box: view-box; animation: dk-tilt 1.1s var(--ease) .7s forwards; }
  .dk-scale .pan { animation: dk-sink 1.1s var(--ease) .7s forwards; }
  .dk-scale .beam.even { animation: dk-wobble 2.2s ease-in-out .7s; }
  @keyframes dk-tilt { to { transform: rotate(var(--a)); } }
  @keyframes dk-sink { to { transform: translateY(var(--dy)); } }
  @keyframes dk-wobble { 25% { transform: rotate(3deg); } 75% { transform: rotate(-3deg); } }
  @media (prefers-reduced-motion: reduce) { .dk-scale .beam, .dk-scale .pan { animation-duration: .01s; animation-delay: 0s; } }
</style>`;

function scale(x0, w, left, right, win) {
  const cx = x0 + w / 2, py = 40, L = w * 0.28, pw = Math.min(w * 0.4, 300), ph = 70, hang = 46;
  const deg = win === 'left' ? -9 : win === 'right' ? 9 : 0;
  const dy = L * Math.sin(deg * Math.PI / 180);
  const wins = side => win === (side < 0 ? 'left' : 'right');
  const pan = (side, [label, sub], sdy) => {
    const px = cx + side * L;
    return `<g class="pan" style="--dy:${sdy.toFixed(1)}px">` +
      `<path class="ln thin fgc" d="M${px},${py} V${py + hang}"/>` +
      box(px - pw / 2, py + hang, pw, ph, { label, sub, c: wins(side) ? 'acc' : 'fgc', solid: wins(side) }) + `</g>`;
  };
  return [
    `<path class="ln fgc" d="M${cx},${py} L${cx - 16},${py + 210} H${cx + 16} Z" style="fill:var(--faint);stroke:none"/>`,
    `<path class="ln fgc" d="M${cx - 40},${py + 210} H${cx + 40}" style="stroke-width:4"/>`,
    pan(-1, left, -dy),
    pan(1, right, dy),
    `<g class="beam${win === 'even' ? ' even' : ''}" style="--a:${deg}deg; transform-origin:${cx}px ${py}px">` +
      `<path class="ln fgc" d="M${cx - L - 8},${py} H${cx + L + 8}" style="stroke-width:5"/></g>`,
    `<circle cx="${cx}" cy="${py}" r="7" class="tc acc"/>`,
  ].join('');
}

// One tension: scale plus the call made, as a highlighted box below.
const tension = (left, right, win, call) => SCALE_CSS + svg(960, 390, [
  scale(130, 700, left, right, win),
  box(130, 300, 700, 76, { c: 'acc', d: 1.6, label: call[0], sub: call[1] }),
].join(''), { cls: 'dk-scale' });

// Tiles in at most three columns, so six items form two even rows.
const tiles3 = items => `<div class="dk-3" style="width:100%"><style>.dk-3 .tiles { grid-template-columns: repeat(auto-fit, minmax(min(100%, 290px), 1fr)); }</style>${tiles(items)}</div>`;

// Two tensions side by side, each with its own call.
const tension2 = (a, b) => SCALE_CSS + svg(960, 400, [a, b].map((t, i) => {
  const x0 = i * 490, w = 470;
  return scale(x0, w, t[0], t[1], t[2]) +
    box(x0 + 10, 300, w - 20, 84, { c: 'acc', d: 1.6 + i * 0.3, label: t[3][0], sub: t[3][1] });
}).join(''), { cls: 'dk-scale' });

const icon = () => SCALE_CSS + svg(300, 92, [
  `<path d="M150,22 L140,84 H160 Z" style="fill:var(--faint)"/>`,
  `<g class="beam" style="--a:9deg; transform-origin:150px 22px"><path class="ln fgc" d="M60,22 H240" style="stroke-width:4"/></g>`,
  `<g class="pan" style="--dy:-13px">${box(20, 42, 90, 30, { c: 'fgc', r: 8, label: 'goal A' })}</g>`,
  `<g class="pan" style="--dy:13px">${box(190, 42, 90, 30, { c: 'acc', solid: true, r: 8, label: 'goal B' })}</g>`,
  `<circle cx="150" cy="22" r="5" class="tc acc"/>`,
].join(''), { cls: 'dk-scale' });

export default {
  id: 'tradeoffs',
  title: 'Trade-offs',
  blurb: 'The goals that collide, which one wins each time, and what is out of scope.',
  icon,
  slides: [
    {
      title: 'Some goals can\'t all hold at once',
      stage: () => tiles3([
        { title: 'Ownership vs no consensus', text: 'Ownership can\'t be transferred, only handed over to a new id.', c: 'c1', href: '#/permissions/7' },
        { title: 'Selective sync vs a blind server', text: 'Blind servers learn some shape: which labels a blob is under, and rough sizes.', c: 'blind', href: '#/tradeoffs/2' },
        { title: 'Deletion vs history', text: 'Each aspect picks: purge now, keep history, or compact later.', c: 'bad', href: '#/tradeoffs/3' },
        { title: 'Revocation vs no coordinator', text: 'Precise only up to what writers received, and clock skew.', c: 'c2', href: '#/tradeoffs/4' },
        { title: 'Cheap removal vs old keys', text: 'Keys rotate lazily; history isn\'t re-encrypted.', c: 'c4', href: '#/tradeoffs/5' },
        { title: 'Atomic commits vs partial fetch', text: 'A multi-thing commit is one blob, fetched whole.', c: 'c3', href: '#/tradeoffs/5' },
      ]),
      text: `<p>Some requirements collide, and each collision needs an explicit call. The next slides weigh the main ones; the heavier side wins.</p>`,
    },
    {
      title: 'A blind server learns some shape, never content',
      stage: () => tension2(
        [['Fetch one row', 'from a blind server'], ['Hide structure', 'from that server'], 'left',
          ['Server sees opaque labels per blob', 'and which labels overlap; not names, ids, authors']],
        [['Cheap edits', 'to multi-GB values'], ['Hide sizes', 'of values and edits'], 'left',
          ['Chunk by content, pad coarsely', 'at most 12% padding; data volume may leak']]),
      text: `<p>To hand you just one row of a table, a blind server must be able to tell rows apart, so it learns which opaque label each blob is under.</p>
        <p>Likewise, editing a huge file cheaply means re-sending only the changed chunks, so chunk sizes are visible. Padding hides fine detail, not volume.</p>`,
    },
    {
      title: 'Prompt deletion and keeping history pull in opposite directions',
      stage: () => tension(
        ['Delete right away', 'everywhere, irrevocably'],
        ['History, undo, backups', 'bodies kept to serve and restore'], 'even',
        ['Call: each aspect picks a retention class', 'purge (no undo, snapshot per edit) · preserve (until explicitly purged) · default (compacted later)']),
      text: `<p>Old versions are useful: other devices need them, undo needs them, and a server's recycle bin lets you recover from mistakes. A password pasted into a shared doc needs the opposite.</p>
        <p>So the schema sets a class per aspect, and any commit can override it. Servers keep retired data 30 days by default, except purge-class content, which never waits.</p>`,
    },
    {
      title: 'Revocation is exactly as precise as writers\' receipts',
      stage: () => tension2(
        [["Server's word counts", 'as proof of timing'], ['No coordinator', 'blind servers decide nothing'], 'right',
          ['Only a writer\'s receipt counts', 'honest edits only a blind server saw before the revoke are dropped']],
        [['Exact revoke instant', 'everywhere'], ['No clock sync', 'clocks are only bounded'], 'right',
          ['Window of at most the clock skew', 'between members, against a node that hasn\'t heard yet']]),
      text: `<p>If two devices only ever meet through a blind server, an honest edit uploaded before a revoke still doesn't count unless a writer downloaded it in time. Trusting the server's arrival order would make it a coordinator.</p>
        <p>Member clocks are close, not identical, so the cut-off is fuzzy by at most their skew.</p>`,
    },
    {
      title: 'Removing people stays cheap; old content stays as it was',
      stage: () => tension2(
        [['Re-encrypt history', 'on every member removal'], ['Cheap removal', 'old data left as is'], 'right',
          ['Lazy rotation: new keys for new content', 'an ex-member plus a dishonest blind server could read old data']],
        [['Atomic commits', 'across several things'], ['Fetch or purge', 'one thing alone'], 'left',
          ['One commit, one blob', 'partial syncers over-fetch; purging one part rewrites the blob']]),
      text: `<p>A removed member could already read and copy old content, so re-encrypting it buys little and costs a lot. New content gets new keys.</p>
        <p>A commit that touches several things is one blob, so it applies all-or-nothing. Atomicity wins over the rare case of syncing only some of those things.</p>`,
    },
    {
      title: 'Out of scope, on purpose',
      stage: () => tiles3([
        { title: 'Hostile admins', text: 'An admin can add, remove and re-key. The owner is the recourse, not the protocol.', c: 'bad' },
        { title: 'Malicious writers', text: 'An authorized writer gaming clocks to win merges or uploading junk. Junk is rejected, not prevented.', c: 'bad' },
        { title: 'Copies made elsewhere', text: 'Screenshots, exports, offline copies. Deletion binds honest nodes only.', c: 'blind' },
        { title: 'Dishonest nodes', text: 'A node that ignores deletes, or a blind server that keeps what it was told to drop.', c: 'blind' },
        { title: 'Memory and swap', text: 'Plaintext in RAM, swap and core dumps: best effort only.', c: 'blind' },
        { title: 'Lost owning key', text: 'Recovering an actor whose owning key is lost. Can be added later.', c: 'c4' },
      ]),
      text: `<p>Limits no protocol can enforce, or deliberate calls. "Deleted" means every honest node that saw the deletion dropped it, not that no copy can exist.</p>`,
    },
    {
      title: 'Where osis stands',
      stage: () => tiles3([
        { title: 'Decided', text: 'Things and aspects with self-certifying ids; the one conflict rule; group-based blob sync with blind servers; sharing by membership edges; the revocation rule; hand-over; retention classes; local store design (implementation deferred); versioning; signals and expiry.', c: 'c3' },
        { title: 'Proposal', text: 'The app API\'s shape, record and commit header layouts, most merge mechanics beyond the conflict rule (such as text CRDT details), purge mechanics, CBOR tag numbers, chunking parameters, schema syntax.', c: 'c2' },
        { title: 'Open', text: 'Transport and peer discovery, crypto primitives, model-checking the membership fixpoint, lazy fetch of huge values, partial restore from blind servers.', c: 'c4' },
      ]),
      text: `<p>osis is at the design stage, with no code yet. Decisions are recorded with dates and reasons in the project's notes, and the API will be shaped by building real apps on it.</p>`,
    },
  ],
};
