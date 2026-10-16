import { svg, g, box, text, arrow, path, packet, device, blob, key, person, check, cross, pill } from '../lib/svg.js';

const icon = () => svg(300, 92, [
  device(40, 40, { kind: 'phone', c: 'c1' }),
  arrow(62, 40, 104, 40, { c: 'c1' }),
  person(130, 40, { c: 'c1', r: 22 }),
  arrow(156, 40, 198, 40, { c: 'c1' }),
  box(204, 18, 82, 44, { label: 'team', c: 'acc', r: 10 }),
  check(270, 18, { s: 0.8 }),
].join(''));

// ---------- Revocation timeline (interactive) ----------
const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const dx = i => 170 + i * 120;
const ROW = { alice: 90, bob: 190, carol: 290 };

function timeline(carol) {
  const yb = carol ? 380 : 270;
  const res = (i, ok, name, why, d) => (ok ? check : cross)(dx(i) + 40, ROW.bob - 20, { d, s: 0.8 }) +
    (ok ? check : cross)(i === 2 ? 290 : 590, yb, { d, s: 0.8 }) +
    text(i === 2 ? 306 : 606, yb, `${name}: ${why}`, { anchor: 'start', d });
  return svg(960, carol ? 400 : 290, [
    ...DAYS.map((n, i) => text(dx(i), 24, n, { cls: 'sub' })),
    text(20, ROW.alice, 'Alice', { anchor: 'start', cls: 'b', c: 'c1' }),
    text(20, ROW.bob, 'Bob', { anchor: 'start', cls: 'b', c: 'c2' }),
    path(`M110,${ROW.alice} H930`, { c: 'blind', cls: 'thin' }),
    path(`M110,${ROW.bob} H930`, { c: 'blind', cls: 'thin' }),
    // Bob offline from Tue to Sun
    `<rect x="${dx(1) - 20}" y="${ROW.bob - 16}" width="${dx(6) - dx(1)}" height="32" rx="16" class="fillt blind ap" style="--d:.2s"/>`,
    text(dx(1) + 26, ROW.bob, 'offline', { cls: 'sub', d: 0.2 }),
    // Mon share
    arrow(dx(0), ROW.alice + 14, dx(0), ROW.bob - 14, { c: 'c3', d: 0.1 }),
    pill(dx(0), ROW.alice, 'shares', { c: 'c3', solid: true, mono: false, d: 0 }),
    // Wed X, Fri Y
    pill(dx(2), ROW.bob, 'edit X', { c: 'c2', solid: true, mono: false, d: 0.4 }),
    pill(dx(4), ROW.bob, 'edit Y', { c: 'c2', solid: true, mono: false, d: 0.8 }),
    // Thu revoke
    path(`M${dx(3)},40 V${carol ? 345 : 235}`, { c: 'bad', cls: 'dash', d: 0.6 }),
    pill(dx(3), ROW.alice, 'revokes Bob', { c: 'bad', solid: true, mono: false, d: 0.6 }),
    // Sun sync
    arrow(dx(6), ROW.bob - 14, dx(6), ROW.alice + 14, { c: 'acc', d: 1.1 }),
    pill(dx(6), (ROW.alice + ROW.bob) / 2, 'sync', { c: 'acc', mono: false, d: 1.1 }),
    ...(carol ? [
      text(20, ROW.carol + 30, 'Carol', { anchor: 'start', cls: 'b', c: 'c4' }),
      path(`M110,${ROW.carol + 30} H930`, { c: 'blind', cls: 'thin' }),
      `<rect x="${dx(1) - 20}" y="${ROW.carol + 14}" width="${dx(6) - dx(1)}" height="32" rx="16" class="fillt blind ap" style="--d:.2s"/>`,
      text(dx(1) + 26, ROW.carol + 30, 'offline, with Bob', { cls: 'sub', anchor: 'start', d: 0.2 }),
      arrow(dx(2) + 30, ROW.bob + 12, dx(2) + 60, ROW.carol + 16, { c: 'c4', d: 0.5, curve: -10 }),
      pill(dx(2) + 60, ROW.carol + 30, 'gets X', { c: 'c4', mono: false, d: 0.5 }),
      arrow(dx(4) + 30, ROW.bob + 12, dx(4) + 60, ROW.carol + 16, { c: 'c4', d: 0.9, curve: -10 }),
      pill(dx(4) + 60, ROW.carol + 30, 'gets Y', { c: 'c4', mono: false, d: 0.9 }),
    ] : []),
    res(2, carol, 'X', carol ? 'Carol got it before Thu' : 'no writer got it before Thu', 1.5),
    res(4, false, 'Y', 'after the revoke', 1.7),
  ].join(''));
}

const tlStage = () => `<div class="demo dk-perm">
  <style>.dk-perm .ctl button[aria-pressed="true"] { background: var(--accent); color: var(--bg); }</style>
  <div class="tl">${timeline(false)}</div>
  <div class="ctl"><button aria-pressed="true" data-carol="0">Bob alone</button><button aria-pressed="false" data-carol="1">Carol offline with Bob</button></div>
</div>`;

function tlEnter(root) {
  const tl = root.querySelector('.tl');
  const btns = [...root.querySelectorAll('.ctl button')];
  const onClick = e => {
    const carol = e.currentTarget.dataset.carol === '1';
    btns.forEach(b => b.setAttribute('aria-pressed', String(b === e.currentTarget)));
    tl.innerHTML = timeline(carol);
  };
  btns.forEach(b => b.addEventListener('click', onClick));
  return () => btns.forEach(b => b.removeEventListener('click', onClick));
}

export default {
  id: 'permissions',
  title: 'Permissions',
  blurb: 'Who may read and write, checked on each device with no server to ask.',
  icon,
  slides: [
    {
      title: 'Three concepts cover every permission',
      stage: () => svg(960, 400, [
        device(100, 100, { kind: 'laptop', label: "Alice's laptop", sub: 'node', c: 'c1', d: 0 }),
        device(100, 270, { kind: 'phone', label: "Alice's phone", sub: 'node', c: 'c1', d: 0.1 }),
        person(360, 190, { c: 'c1', label: 'Alice', r: 24, d: 0.3 }),
        arrow(140, 108, 330, 180, { c: 'c1', d: 0.5 }),
        arrow(124, 262, 330, 200, { c: 'c1', d: 0.6 }),
        pill(235, 144, 'admin', { c: 'c1', d: 0.7 }),
        pill(227, 231, 'admin', { c: 'c1', d: 0.7 }),
        box(530, 160, 170, 64, { label: 'Design team', sub: 'actor', c: 'acc', d: 0.9 }),
        arrow(390, 192, 524, 192, { c: 'c1', d: 1.1 }),
        pill(457, 192, 'write', { c: 'c1', d: 1.2 }),
        ...['note', 'sheet', 'chat'].map((n, i) =>
          box(800, 60 + i * 100, 140, 56, { label: n, sub: 'thing', d: 1.4 + i * 0.1 }) +
          g(arrow(704, 192, 794, 88 + i * 100, { c: 'acc', dash: true }), { d: 1.5 + i * 0.1 })),
        text(748, 360, 'owns (fixed by tid)', { cls: 'sub', d: 1.8 }),
        text(300, 360, 'membership edges, each with a role', { cls: 'sub', d: 1.8 }),
      ].join('')),
      text: `<p>An <strong>actor</strong> is something others can be members of: a person, a team, a shared document. Devices are actors too, at the leaves. A <strong>membership</strong> edge gives a role (read &lt; write &lt; admin) on an actor or a single thing. <strong>Ownership</strong> says which actor a thing belongs to; it's baked into the thing's id and never changes.</p>
        <p>"This phone acts for Alice" and "Alice is in the team" are the same kind of edge.</p>`,
      more: `<h3>Details</h3><ul>
        <li>An edge on an actor grants rights on everything it owns; an edge on a plain thing grants rights on that thing only.</li>
        <li>Effective role through a chain is the minimum along it.</li>
        <li>An actor's owner is implicitly an admin that other admins can't remove. A sensible setup: a person owned by an offline recovery key, with devices as admins.</li>
      </ul>`,
    },
    {
      title: 'Joining is one edge plus wrapped secrets',
      stage: () => svg(960, 400, [
        text(230, 20, 'Add your phone', { cls: 'b', d: 0 }),
        device(90, 110, { kind: 'laptop', label: 'laptop', sub: 'existing admin', c: 'c1', d: 0.1 }),
        device(90, 290, { kind: 'phone', label: 'new phone', sub: 'makes its own key pair', c: 'c1', d: 0.3 }),
        person(360, 200, { c: 'c1', label: 'you', r: 24, d: 0.2 }),
        arrow(126, 112, 332, 188, { c: 'c1', d: 0.2 }),
        arrow(118, 280, 332, 212, { c: 'c3', d: 0.8 }),
        pill(225, 246, 'admin', { c: 'c3', solid: true, d: 0.9 }),
        text(262, 122, 'writes the new edge', { cls: 'sub', d: 0.6 }),
        packet('M340,222 Q260,330 118,300', { c: 'c4', begin: 1.4, dur: 1.6, repeat: 1 }),
        text(290, 350, 'your secrets, wrapped to the phone', { cls: 'sub', c: 'c4', d: 1.6 }),

        path('M480,30 V380', { c: 'blind', cls: 'thin dash', d: 1.8 }),

        text(720, 20, 'Add Bob to a doc', { cls: 'b', d: 2 }),
        person(570, 110, { c: 'c1', label: 'you (doc admin)', d: 2.1 }),
        box(790, 168, 150, 64, { label: 'Doc', sub: 'actor', c: 'acc', d: 2.1 }),
        arrow(596, 118, 784, 186, { c: 'c1', d: 2.2 }),
        person(570, 290, { c: 'c2', label: 'Bob', d: 2.3 }),
        arrow(596, 280, 784, 214, { c: 'c3', d: 2.6 }),
        pill(690, 247, 'write', { c: 'c3', solid: true, d: 2.7 }),
        packet('M800,236 Q760,330 600,300', { c: 'c4', begin: 3.1, dur: 1.6, repeat: 1 }),
        text(740, 350, "doc's secrets, wrapped to Bob", { cls: 'sub', c: 'c4', d: 3.3 }),
      ].join('')),
      text: `<p><strong>A new device</strong> makes its own key pair. An existing admin device writes one membership edge (phone → you, admin) and wraps your secrets to the phone. From then on the phone signs its own writes and reads what you can.</p>
        <p><strong>A new person</strong> is the same move: an edge (Bob → doc, write) and the doc's secrets wrapped to Bob, which all of Bob's devices can open.</p>`,
    },
    {
      title: 'A write is checked by walking a chain, not by asking a server',
      stage: () => {
        const steps = [
          ['Signature', "valid for the laptop's key", 'c4'],
          ['laptop → Alice', 'edge, role admin', 'c1'],
          ['Alice → team', 'edge, role write', 'c1'],
          ['team owns note', 'checked by hashing its tid', 'acc'],
        ];
        const w = 196, gap = 30, x0 = 12, y = 90;
        return svg(960, 360, [
          blob(x0 + 20, 30, { c: 'c2', size: 30, d: 0 }),
          text(x0 + 46, 30, 'incoming commit: an edit to the note, from Alice\'s laptop', { anchor: 'start', cls: 'sub', d: 0 }),
          ...steps.map(([n, s, c], i) => {
            const x = x0 + i * (w + gap), t = 0.4 + i * 0.6;
            return box(x, y, w, 64, { label: n, sub: s, c, d: t - 0.3 }) +
              check(x + w - 6, y + 4, { d: t + 0.2 }) +
              (i < 3 ? arrow(x + w + 4, y + 32, x + w + gap - 4, y + 32, { d: t }) : '');
          }),
          packet(`M${x0 + 20},${y + 32} H${x0 + 3 * (w + gap) + w / 2} L480,${y + 154}`, { c: 'c4', begin: 0.3, dur: 3, repeat: 1 }),
          path(`M480,${y + 70} V${y + 116}`, { cls: 'arrow', c: 'c3', d: 2.8 }),
          box(310, y + 122, 340, 64, { label: 'Allowed to write', sub: 'min(admin, write) = write', c: 'c3', solid: true, d: 3 }),
        ].join(''));
      },
      text: `<p>Every node that can read the data checks every write itself. The commit's signature names the device, signed membership commits link the device to Alice and Alice to the team, and the note's id commits to its owner.</p>
        <p>The uploader sends the membership commits proving its chain along with its data, so even a reader who can't see the team's member list can check it.</p>`,
      more: `<h3>Details</h3><p>The checks need no secrets: signatures, plus hashing creation records to confirm they match tids.</p>
        <p>A commit whose chain hasn't arrived yet waits, unverified. A reader learns the chain of each author it sees, never the full member list.</p>`,
    },
    {
      title: 'Reading is key wrapping: share history by adding a wrap',
      stage: () => svg(960, 400, [
        blob(90, 200, { c: 'blind', size: 70, d: 0 }),
        text(90, 262, 'encrypted once', { cls: 'sub', d: 0 }),
        key(250, 200, { c: 'c4', scale: 1.6, d: 0.3 }),
        text(250, 236, 'its own random key', { cls: 'sub', d: 0.3 }),
        g(arrow(140, 200, 210, 200, { c: 'c4', head: false, dash: true }), { d: 0.2 }),
        arrow(290, 190, 416, 130, { c: 'c4', d: 0.6 }),
        box(420, 98, 190, 60, { label: 'wrap for label A', sub: '≈ 48 bytes', c: 'c4', d: 0.7 }),
        box(650, 98, 150, 60, { label: 'label A', sub: 'read secret', c: 'acc', d: 1 }),
        arrow(614, 128, 646, 128, { c: 'c4', d: 0.9 }),
        person(890, 70, { c: 'c1', label: 'Alice', d: 1.3 }),
        person(890, 175, { c: 'c2', label: 'Bob', d: 1.4 }),
        arrow(804, 120, 862, 78, { c: 'acc', d: 1.3 }),
        arrow(804, 136, 862, 168, { c: 'acc', d: 1.4 }),
        // added later: share old content with Carol
        g([
          arrow(290, 212, 416, 278, { c: 'c3' }),
          box(420, 250, 190, 60, { label: 'wrap for label B', sub: 'added later', c: 'c3' }),
          arrow(614, 280, 646, 280, { c: 'c3' }),
          box(650, 250, 150, 60, { label: 'label B', sub: 'read secret', c: 'acc' }),
          arrow(804, 280, 862, 296, { c: 'acc' }),
          person(890, 300, { c: 'c4', label: 'Carol' }),
        ].join(''), { d: 2.2 }),
        text(480, 370, 'the blob is never re-encrypted', { cls: 'sub', d: 2.6 }),
      ].join('')),
      text: `<p>Each commit's key is <strong>wrapped</strong> under the read secret of every label (synced group) it belongs to, and each label's secret is wrapped to that group's members.</p>
        <p>Giving Carol old content means adding one wrap. Removing someone rotates secrets for <em>new</em> content only; what they could read, they could have copied.</p>
        <p>A blind server holds none of these secrets. It checks signatures under per-label role keys, so a reader can relay data through it but not delete (see <a href="#/deletion/7">Deletion</a>).</p>`,
      more: `<h3>Details</h3><ul>
        <li>Proposed: an actor has one secret per role (read, write, admin), each wrapped to members at that role or higher.</li>
        <li>Writes are always authorized by the device's own signature plus the membership chain. A shared signing key would erase who wrote what.</li>
        <li>A blind server checks signatures under a label's shared role keys, so it learns the role, not the member.</li>
      </ul>`,
    },
    {
      title: 'Sharing patterns all use the same three parts',
      stage: () => svg(960, 400, [
        // (a) one note
        text(150, 20, 'Share one note', { cls: 'b', d: 0 }),
        box(30, 60, 120, 50, { label: 'Alice', sub: 'owner', c: 'c1', d: 0.1 }),
        box(150, 190, 130, 56, { label: 'note N', sub: 'same tid', d: 0.2 }),
        g(arrow(110, 114, 175, 186, { c: 'c1', dash: true }), { d: 0.3 }),
        person(60, 300, { c: 'c2', label: 'Bob', d: 0.4 }),
        arrow(86, 290, 170, 250, { c: 'c2', d: 0.5 }),
        pill(128, 270, 'write', { c: 'c2', d: 0.6 }),
        text(150, 370, 'an edge written on N itself', { cls: 'sub', d: 0.7 }),

        path('M320,30 V380', { c: 'blind', cls: 'thin dash', d: 0.8 }),

        // (b) shared spreadsheet
        text(480, 20, 'Shared spreadsheet', { cls: 'b', d: 0.9 }),
        person(400, 75, { c: 'c1', label: 'Alice', d: 1 }),
        person(560, 75, { c: 'c2', label: 'Bob', d: 1 }),
        box(400, 150, 160, 50, { label: 'Sheet', sub: 'actor', c: 'acc', d: 1.1 }),
        arrow(416, 100, 446, 146, { c: 'c1', d: 1.2 }),
        arrow(544, 100, 514, 146, { c: 'c2', d: 1.2 }),
        ...[0, 1, 2].flatMap(cI => [0, 1].map(r =>
          `<rect x="${417 + cI * 44}" y="${250 + r * 34}" width="38" height="28" rx="5" class="fillt fgc ap" style="--d:${1.4 + (cI + r) * 0.05}s"/>`)),
        g(arrow(480, 204, 480, 244, { c: 'acc', dash: true }), { d: 1.3 }),
        text(480, 345, 'one actor owns every cell:', { cls: 'sub', d: 1.6 }),
        text(480, 365, 'access changes in one place', { cls: 'sub', d: 1.6 }),

        path('M640,30 V380', { c: 'blind', cls: 'thin dash', d: 1.7 }),

        // (c) group chat
        text(800, 20, 'Group chat', { cls: 'b', d: 1.8 }),
        box(730, 55, 140, 50, { label: 'Chat', sub: 'actor', c: 'acc', d: 1.9 }),
        box(668, 180, 124, 50, { label: "Alice's msgs", c: 'c1', d: 2 }),
        box(808, 180, 124, 50, { label: "Bob's msgs", c: 'c2', d: 2 }),
        arrow(770, 109, 735, 174, { c: 'acc', d: 2.1 }),
        arrow(830, 109, 865, 174, { c: 'acc', d: 2.1 }),
        pill(800, 145, 'read', { c: 'acc', d: 2.2 }),
        person(730, 300, { c: 'c1', d: 2.3 }),
        person(870, 300, { c: 'c2', d: 2.3 }),
        arrow(730, 276, 730, 236, { c: 'c1', d: 2.4 }),
        arrow(870, 276, 870, 236, { c: 'c2', d: 2.4 }),
        text(800, 345, 'each author owns their messages;', { cls: 'sub', d: 2.5 }),
        text(800, 365, 'admins can\'t edit them', { cls: 'sub', d: 2.5 }),
      ].join('')),
      text: `<p><strong>One note:</strong> an admin writes "Bob: write" on the note itself; its id doesn't change.</p>
        <p><strong>Spreadsheet:</strong> one actor owns every cell, so access changes in one place.</p>
        <p><strong>Group chat:</strong> each author has a participant actor that owns their messages, and the chat is a read member of each, so members read everything but only authors edit.</p>`,
      more: `<h3>Groups grant nothing</h3><p>A group (a folder, say) is for organizing and syncing; it carries no rights. A shared folder is made a read member of each thing in it. Dropping a thing in without that edge doesn't share it, which is the safe failure. An "add to shared folder" helper writes both.</p>`,
    },
    {
      title: 'Revocation vs offline edits: only a writer\'s receipt counts',
      stage: tlStage,
      enter: tlEnter,
      text: `<p>Alice shares a doc with Bob on Monday and revokes him on Thursday, while Bob is offline editing. Which edits count? Bob's own timestamps can be forged, so they can't decide. The rule: <strong>a revoked actor's write counts only if a node of a member with write access received it before the revoke</strong>, by that member's clock.</p>
        <p>Alone, both edits are dropped. If Carol, a writer, synced with Bob while offline, X counts.</p>`,
      more: `<h3>How the others find out</h3><ul>
        <li>A node that learns of a revoke publishes a signed <em>attestation</em>: "as of the revoke time, I held this author's writes up to here".</li>
        <li>Blind servers never count as witnesses.</li>
        <li>A write can become valid late, when a witness comes back online. A node that merged a now-invalid write un-merges it.</li>
        <li>Clock skew between members leaves a window of at most the skew. Re-granting the actor makes their writes valid again.</li>
      </ul>`,
    },
    {
      title: 'Ownership never changes; a hand-over creates a new id',
      stage: () => svg(960, 400, [
        box(30, 170, 180, 64, { label: 'thing T', sub: 'owned by A', c: 'c1', d: 0 }),
        arrow(214, 190, 640, 100, { c: 'c3', d: 0.4, curve: -30 }),
        pill(400, 112, 'A signs: hand to X', { c: 'c3', mono: false, d: 0.6 }),
        box(644, 60, 290, 70, { label: 'hash(T, record₁)', sub: 'owned by X, forever', c: 'c3', mono: true, d: 0.9 }),
        g([
          arrow(214, 214, 640, 310, { c: 'c2', dash: true, curve: 30 }),
          pill(400, 300, 'A signs again: hand to Y', { c: 'c2', mono: false }),
          box(644, 270, 290, 70, { label: 'hash(T, record₂)', sub: 'a separate thing, owned by Y', c: 'c2', mono: true }),
        ].join(''), { d: 1.8 }),
        text(788, 205, 'neither can touch the other', { cls: 'sub', d: 2.4 }),
        text(120, 262, 'T stays as an alias', { cls: 'sub', d: 2.6 }),
      ].join('')),
      text: `<p>Without a central ledger, nothing stops a former owner from signing a second, competing transfer. So ownership is immutable: a hand-over creates a new thing, whose id hashes the old id and the signed hand-over record, owned by the receiver forever. A competing hand-over just creates another, separate thing.</p>
        <p>Hand-overs are rare: sharing never needs one.</p>`,
      more: `<h3>Aliases and forks</h3><ul>
        <li>The old id resolves to its successor while there is exactly one; listeners on the old id keep firing.</li>
        <li>On a fork, a reference resolves to the branch where the referring thing's owner has rights, else to the branch the reader chose to follow (first seen by default). Stored bytes are never rewritten.</li>
        <li>A hand-over also revokes the rights that came through the old owner. Handing over an actor strips its explicit admin edges (readers and writers carry over), and the new owner rotates all keys.</li>
      </ul>`,
    },
  ],
};
