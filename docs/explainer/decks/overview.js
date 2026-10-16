import { svg, g, box, text, arrow, path, packet, device, blob, person, code, tiles } from '../lib/svg.js';

const icon = () => svg(300, 92, [
  box(18, 6, 80, 26, { label: 'notes', c: 'c1', r: 8 }),
  box(110, 6, 80, 26, { label: 'calendar', c: 'c2', r: 8 }),
  box(202, 6, 80, 26, { label: 'agent', c: 'c4', r: 8 }),
  box(18, 50, 264, 34, { label: 'osis', c: 'acc', solid: true, r: 10 }),
].join(''));

export default {
  id: 'overview',
  title: 'What osis is',
  blurb: 'The problem, the main pieces, the hard requirements, and how one edit travels.',
  icon,
  slides: [
    {
      title: 'Today, every app keeps its own copy of your data',
      stage: () => svg(960, 420, [
        text(230, 18, 'Today', { cls: 'big', d: 0 }),
        ...['Notes', 'Calendar', 'AI agent'].map((n, i) => {
          const x = 40 + i * 130, c = ['c1', 'c2', 'c4'][i];
          return box(x, 50, 110, 46, { label: n, c, d: 0.1 + i * 0.1 }) +
            arrow(x + 55, 100, x + 55, 186, { c, d: 0.4 + i * 0.1 }) +
            box(x, 190, 110, 60, { label: 'its cloud', sub: 'its format', c, d: 0.5 + i * 0.1, solid: true });
        }),
        arrow(152, 220, 168, 220, { c: 'bad', head: 'both', dash: true, d: 1 }),
        arrow(282, 220, 298, 220, { c: 'bad', head: 'both', dash: true, d: 1 }),
        text(230, 290, 'export, import, sync APIs', { cls: 'sub', d: 1.1 }),
        text(230, 312, 'every provider reads everything', { cls: 'sub', d: 1.2 }),

        path('M480,30 V400', { c: 'blind', cls: 'thin dash', d: 1.3 }),

        text(730, 18, 'With osis', { cls: 'big', d: 1.5 }),
        ...['Notes', 'Calendar', 'AI agent'].map((n, i) => {
          const x = 560 + i * 115, c = ['c1', 'c2', 'c4'][i];
          return box(x, 50, 100, 46, { label: n, c, d: 1.6 + i * 0.1 }) + arrow(x + 50, 100, x + 50, 150, { c, d: 1.9 + i * 0.05 });
        }),
        box(550, 154, 360, 56, { label: 'osis on your laptop', sub: 'one shared store of things', c: 'acc', solid: true, d: 2.1 }),
        device(620, 330, { kind: 'phone', label: 'your phone', c: 'c1', d: 2.4 }),
        device(840, 330, { kind: 'laptop', label: "a friend's laptop", c: 'c2', d: 2.5 }),
        path('M640,214 L620,296', { c: 'acc', cls: 'arrow2 dash', d: 2.6 }),
        path('M820,214 L840,300', { c: 'acc', cls: 'arrow2 dash', d: 2.6 }),
        packet('M640,214 L620,296', { c: 'acc', begin: 3, dur: 1.6 }),
        packet('M840,300 L820,214', { c: 'acc', begin: 3.6, dur: 1.6 }),
      ].join('')),
      text: `<p>Apps keep data on their own servers, in their own formats. Moving it between apps, devices or people takes exports and vendor APIs, and every provider can read it.</p>
        <p><strong>osis</strong> is a database on each of your devices. Many apps share the same data, the way they share files, and osis keeps every copy in sync.</p>`,
    },
    {
      title: 'Somewhere between Git, Google Drive, Syncthing and Obsidian',
      stage: () => {
        const sats = [
          [150, 70, 'Git', 'offline, no server, history', 'c2'],
          [810, 70, 'Google Drive', 'sharing, live collaboration', 'c1'],
          [150, 330, 'Syncthing', 'device sync, no cloud account', 'c3'],
          [810, 330, 'Obsidian', 'many tools on local data', 'c4'],
        ];
        return svg(960, 400, [
          ...sats.map(([x, y, n, s, c], i) =>
            arrow(x + (x < 480 ? 120 : -120), y, 480 + (x < 480 ? -110 : 110), 200 + (y < 200 ? -36 : 36), { c, d: 0.6 + i * 0.1, curve: (x < 480) === (y < 200) ? 30 : -30 }) +
            box(x - 120, y - 34, 240, 68, { label: n, sub: s, c, d: 0.2 + i * 0.1 })),
          box(370, 160, 220, 80, { label: 'osis', sub: 'all of it, plus structure', c: 'acc', solid: true, d: 0 }),
        ].join(''));
      },
      text: `<p>On top, osis adds <strong>typed, structured data</strong> that merges automatically, and end-to-end encryption, so a server you rent can store your data without reading it.</p>`,
    },
    {
      title: 'The cast: nodes, actors and blind nodes',
      stage: () => svg(960, 430, [
        box(30, 170, 260, 230, { c: 'c1', ghost: true, d: 0.3 }),
        person(160, 210, { c: 'c1', label: 'Alice (actor)', d: 0 }),
        device(95, 320, { kind: 'laptop', label: 'laptop', sub: 'node', c: 'c1', d: 0.2 }),
        device(225, 320, { kind: 'phone', label: 'phone', sub: 'node', c: 'c1', d: 0.25 }),
        box(670, 170, 260, 230, { c: 'c2', ghost: true, d: 0.4 }),
        person(800, 210, { c: 'c2', label: 'Bob (actor)', d: 0.1 }),
        device(800, 320, { kind: 'laptop', label: 'laptop', sub: 'node', c: 'c2', d: 0.3 }),
        device(480, 60, { kind: 'server', label: 'rented server', sub: 'blind node: no keys', c: 'blind', blind: true, d: 0.7 }),
        path('M250,295 Q330,80 440,62', { c: 'blind', cls: 'dash', d: 1 }),
        path('M520,62 Q650,80 760,298', { c: 'blind', cls: 'dash', d: 1 }),
        path('M296,280 Q480,330 664,280', { c: 'acc', cls: 'dash arrow2', d: 1.2 }),
        text(480, 330, 'direct, when both are online', { cls: 'sub', d: 1.3 }),
        packet('M250,295 Q330,80 440,62', { c: 'blind', shape: 'blob', begin: 1.6, dur: 2.2 }),
        packet('M520,62 Q650,80 760,298', { c: 'blind', shape: 'blob', begin: 2.4, dur: 2.2 }),
      ].join('')),
      text: `<p>A <strong>node</strong> is osis on one device, with a private key that never leaves it. An <strong>actor</strong> is anything that can hold rights: a person, a team, an agent, a shared document. Nodes act for the actors they belong to.</p>
        <p>Nodes sync directly when they can. A <strong>blind node</strong> stores and relays a group's encrypted data without holding its keys. A rented server is the typical example: through it, your devices sync even if they are never online at the same time.</p>`,
      more: `<p>How nodes find and connect to each other isn't designed yet. iroh (QUIC with hole punching and relays) is a candidate.</p>`,
    },
    {
      title: 'The requirements that make this hard',
      stage: () => tiles([
        { title: 'No coordinator', text: 'No central server or consensus. Any node may be offline for months and come back.', c: 'c1', href: '#/permissions/1' },
        { title: 'Always converges', text: 'Concurrent edits merge to the same result everywhere, with no conflict dialogs.', c: 'c3', href: '#/merge/1' },
        { title: "Servers can't read", text: 'Servers without keys sync as efficiently as trusted peers, but see only ciphertext and some metadata.', c: 'blind', href: '#/sync/1' },
        { title: 'Delete means deleted', text: 'Purged content is gone from every honest node that sees the purge, backups included, and leaves no fingerprint.', c: 'bad', href: '#/deletion/1' },
        { title: 'Many apps, many versions', text: 'Old and new apps share data forever. Nothing is dropped because it is not understood.', c: 'c4', href: '#/versioning/1' },
        { title: 'Big and fine-grained', text: 'Multi-GB values, million-key maps, overlapping groups. Cost tracks the change, not the data.', c: 'c2', href: '#/sync/1' },
      ]),
      text: `<p>Each is solved somewhere on its own. osis needs all of them at once, and most of the design is about where they collide.</p>`,
    },
    {
      title: 'Life of one edit',
      stage: () => {
        const top = [['App', 'title = "Groceries"', 'c1'], ['Delta', 'just the change', 'c3'], ['Commit', 'signed by this node', 'c4'], ['Blob', 'encrypted, random key', 'blind']];
        const bot = [['Listener fires', 'phone app updates', 'c1'], ['Join', 'merge into local state', 'c3'], ['Decrypt, verify', 'signature + membership', 'c4']];
        const w = 170, gap = 34, y1 = 40, y2 = 300;
        const route = `M${w / 2},${y1 + 30} H${3 * (w + gap) + w} Q880,${y1 + 30} 880,140 V232 Q880,${y2 + 30} ${2 * (w + gap) + w},${y2 + 30} H${w / 2}`;
        return svg(940, 380, [
          ...top.map(([n, s, c], i) => box(i * (w + gap), y1, w, 60, { label: n, sub: s, c, d: i * 0.35 }) +
            (i < 3 ? arrow(i * (w + gap) + w + 4, y1 + 30, (i + 1) * (w + gap) - 4, y1 + 30, { d: i * 0.35 + 0.2 }) : '')),
          device(880, 170, { kind: 'server', label: 'peer or server', c: 'blind', blind: true, d: 1.4 }),
          path(`M${3 * (w + gap) + w + 4},${y1 + 30} Q880,${y1 + 30} 880,140`, { c: 'blind', cls: 'arrow', d: 1.5 }),
          path(`M880,232 Q880,${y2 + 30} ${2 * (w + gap) + w + 4},${y2 + 30}`, { c: 'blind', cls: 'arrow', d: 1.8 }),
          ...bot.map(([n, s, c], i) => box(i * (w + gap), y2, w, 60, { label: n, sub: s, c, d: 2.6 - i * 0.35 }) +
            (i < 2 ? arrow((i + 1) * (w + gap) - 4, y2 + 30, i * (w + gap) + w + 4, y2 + 30, { d: 2.7 - i * 0.35 }) : '')),
          packet(route, { c: 'acc', begin: 3.2, dur: 4.5 }),
        ].join(''));
      },
      text: `<p>An app changes a value. osis records just the change (a <strong>delta</strong>), bundles one save's deltas into a <strong>commit</strong> signed by the device, and encrypts it into an opaque <strong>blob</strong>.</p>
        <p>The blob travels directly or through blind nodes. The receiver decrypts it, checks the signer's permissions, merges it in, and the app's listener fires.</p>`,
    },
    {
      title: 'What an app actually sees',
      stage: () => code(`{k:let} {k:mut} m = db.mutate();
{k:let} note = m.create_thing();
m.set_aspect(note, {s:"/note/title"}, {s:"Groceries"});
m.set_aspect(note, {s:"/note/tasks"}, tasks);
m.commit().{k:await}?;                      {cm:// atomic, signed, synced}

db.listen_aspect(note, {s:"/note/title"}, |title| {
    render(title);                        {cm:// local or remote change}
}).{k:await}?;`),
      text: `<p>Plain values and listeners: no merge API, conflict state, networking or crypto. Edits from other devices and people arrive as listener calls. (The API is a sketch.)</p>`,
    },
  ],
};
