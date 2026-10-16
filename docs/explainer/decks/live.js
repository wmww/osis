import { svg, g, box, text, arrow, path, packet, device, pill, check, cross } from '../lib/svg.js';

const icon = () => svg(300, 92, [
  device(40, 40, { kind: 'laptop', c: 'c1' }),
  device(260, 40, { kind: 'phone', c: 'c2' }),
  path('M80,40 H230', { c: 'acc', cls: 'dash' }),
  packet('M80,40 H230', { c: 'acc', dur: 1.4 }),
  packet('M80,40 H230', { c: 'acc', dur: 1.4, begin: 0.7 }),
  text(150, 80, 'never stored', { cls: 'sub' }),
].join(''));

export default {
  id: 'live',
  title: 'Live and ephemeral data',
  blurb: 'Cursors and typing indicators that are never stored, and why nothing waits until everyone has seen it.',
  icon,
  slides: [
    {
      title: 'Signals are writes that nobody stores',
      stage: () => {
        const relay = [480, 200];
        const outs = [[820, 80], [820, 220]];
        return svg(960, 420, [
          device(120, 200, { kind: 'laptop', label: 'Alice', sub: 'moves her cursor', c: 'c1', d: 0 }),
          device(relay[0], relay[1], { kind: 'server', label: 'relay (blind)', sub: 'forwards, keeps nothing', c: 'blind', blind: true, d: 0.2 }),
          device(outs[0][0], outs[0][1], { kind: 'laptop', label: "Bob's laptop", sub: 'subscribed', c: 'c2', d: 0.4 }),
          device(outs[1][0], outs[1][1], { kind: 'phone', label: "Bob's phone", sub: 'subscribed', c: 'c2', d: 0.5 }),
          g(device(820, 350, { kind: 'phone', label: 'offline device', sub: 'sees nothing; next signal will do', c: 'blind' }), { d: 0.6 }),
          path('M165,200 H430', { c: 'c1', cls: 'arrow', d: 0.7 }),
          path('M530,190 Q680,100 776,84', { c: 'c2', cls: 'arrow', d: 0.9 }),
          path('M530,210 Q680,220 790,220', { c: 'c2', cls: 'arrow', d: 0.9 }),
          path('M530,222 Q680,330 790,348', { c: 'blind', cls: 'dash', d: 0.9 }),
          cross(690, 300, { d: 1.1, s: 0.8 }),
          pill(300, 172, 'cursor: line 12', { c: 'c1', d: 0.8 }),
          packet('M165,200 H430', { c: 'c1', begin: 1.4, dur: 1.1 }),
          packet('M530,190 Q680,100 776,84', { c: 'c1', begin: 2.5, dur: 1.1 }),
          packet('M530,210 Q680,220 790,220', { c: 'c1', begin: 2.5, dur: 1.1 }),
        ].join(''));
      },
      text: `<p>Cursor positions, typing indicators and presence change constantly and are worthless a second later. In osis they are <strong>signals</strong>: encrypted and signed like any commit, sent to the peers connected right now, then forgotten. A blind server relaying it forwards it to its other subscribers and stores nothing.</p>
        <p>Delivery is best effort, at most once. Anything that must survive a device being offline is state, not a signal.</p>`,
      more: `<h3>Signal details</h3>
        <ul>
          <li>Separate API: <code>send_signal(thing, kind, value)</code> and <code>listen_signals(...)</code>. Signal kinds are typed in the schema like aspects, but never appear in state or history.</li>
          <li>Sending needs write access to the thing, listening needs read. Receivers verify the signature and the sender's membership chain, exactly as for commits.</li>
          <li>Encrypted under the thing's sync labels, so a blind server learns only label, size and arrival time.</li>
          <li>Targeting one device is a field in the envelope; others drop it. Busy channels get their own group so they don't wake every subscriber of a big one.</li>
        </ul>`,
    },
    {
      title: 'One connection pushes both new state and signals',
      stage: () => {
        const logX = 400, logY = 70;
        const entry = (i, d, c = 'blind') => box(logX, logY + i * 38, 160, 30, { label: `#${41 + i}  blob`, c, mono: true, r: 7, d });
        return svg(960, 380, [
          device(110, 110, { kind: 'laptop', label: 'writer', c: 'c1', d: 0 }),
          device(850, 180, { kind: 'phone', label: 'subscriber', c: 'c2', d: 0.1 }),
          text(480, 40, 'label log at the peer', { cls: 'b small', d: 0.2 }),
          entry(0, 0.2), entry(1, 0.25), entry(2, 0.3),
          // commit lane
          text(260, 82, 'commit', { cls: 'sub', d: 0.5 }),
          path('M150,104 Q300,104 392,184', { c: 'c1', cls: 'arrow', d: 0.5 }),
          packet('M150,104 Q300,104 392,184', { c: 'c1', shape: 'blob', begin: 0.9, dur: 1, repeat: 1 }),
          entry(3, 1.9, 'c3'),
          text(580, 184, 'stored', { anchor: 'start', cls: 'sub', c: 'c3', d: 2 }),
          path('M565,200 Q700,190 808,170', { c: 'c3', cls: 'arrow', d: 2.1 }),
          packet('M565,200 Q700,190 808,170', { c: 'c3', shape: 'blob', begin: 2.3, dur: 1, repeat: 1 }),
          // signal lane
          path('M150,130 Q300,320 480,320 Q700,320 808,198', { c: 'c4', cls: 'arrow dash', d: 3 }),
          packet('M150,130 Q300,320 480,320 Q700,320 808,198', { c: 'c4', begin: 3.3, dur: 2, repeat: 'indefinite' }),
          text(480, 345, 'signal: passes through, no log entry', { cls: 'sub', c: 'c4', d: 3.2 }),
        ].join(''));
      },
      text: `<p>A connection can <strong>subscribe</strong> to sync labels. The peer then pushes every new entry the moment it arrives, so edits show up on other devices about one server hop later, not on the next poll. Signals ride the same subscription but skip the log.</p>`,
      more: `<h3>How this relates to sync</h3>
        <p>A push is the same message a client would get by asking "what's new since my cursor?". If a connection drops, the next sync simply resumes from the cursor, so nothing depends on pushes arriving. See the Sync topic for the log and cursors.</p>`,
    },
    {
      title: 'Nothing waits until "everyone has seen it"',
      stage: () => svg(960, 400, [
        text(230, 20, 'keep until all receivers saw it?', { cls: 'b small', d: 0 }),
        device(110, 90, { kind: 'laptop', label: 'laptop', c: 'c2', d: 0.2 }),
        check(150, 66, { d: 0.5, s: 0.8 }),
        device(250, 90, { kind: 'phone', label: 'phone', c: 'c2', d: 0.3 }),
        check(275, 66, { d: 0.6, s: 0.8 }),
        device(370, 90, { kind: 'phone', label: 'lost in a taxi', c: 'blind', d: 0.4 }),
        text(400, 66, '?', { cls: 'big', c: 'bad', d: 0.7 }),
        box(70, 180, 140, 60, { label: '+ next year\'s', sub: 'device', c: 'c2', ghost: true, d: 0.8 }),
        device(330, 210, { kind: 'server', label: 'blind server', sub: 'knows no members', c: 'blind', blind: true, d: 1 }),
        box(70, 300, 330, 56, { label: 'no answer: the set is open', sub: 'and devices die', c: 'bad', d: 1.5 }),

        path('M480,20 V380', { c: 'blind', cls: 'thin dash', d: 1.6 }),

        text(730, 20, 'instead: an inbox, plus expiry', { cls: 'b small', d: 1.8 }),
        box(600, 50, 260, 180, { c: 'c2', d: 2 }),
        text(620, 72, "Bob's inbox (Bob owns it)", { anchor: 'start', cls: 'b small', d: 2 }),
        box(616, 92, 228, 30, { label: 'msg from Alice', c: 'fgc', plain: true, r: 7, d: 2.4 }),
        box(616, 130, 228, 30, { label: 'msg from Carol', c: 'fgc', plain: true, r: 7, d: 2.5 }),
        g(box(616, 168, 228, 30, { label: 'read, deleted by Bob', c: 'bad', r: 7 }), { d: 3.2 }),
        device(540, 300, { kind: 'laptop', label: 'Alice appends', c: 'c1', d: 2.2 }),
        arrow(570, 268, 594, 112, { c: 'c1', d: 2.3, curve: 20 }),
        pill(760, 290, 'expires in 30 days', { c: 'bad', mono: false, d: 3.6 }),
        text(760, 320, 'backstop if Bob never returns', { cls: 'sub', d: 3.7 }),
      ].join('')),
      text: `<p>"Buffer until every recipient has it" sounds simple but is not decidable: a person can add a device next year, a lost phone never returns, and a blind server cannot even tell who the recipients are. Every approximation turns into guesswork.</p>
        <p>So osis offers two precise tools instead: state that the receiver owns and deletes (an <strong>inbox</strong>), and <strong>expiry</strong> as the backstop: a time at which every node, blind servers included, drops the data (<a href="#/deletion/8">see Deletion</a>).</p>`,
    },
    {
      title: '"All my devices" is a question you ask of state',
      stage: () => {
        const rows = [
          ['laptop', '1.4', 'yes', '2 min ago', 'c3', 'c1'],
          ['phone', '1.4', 'yes', '1 h ago', 'c3', 'c1'],
          ['old tablet', '1.1', 'no', '8 months ago', 'blind', 'blind'],
        ];
        const cols = [60, 270, 440, 610];
        return svg(960, 380, [
          ...['node', 'software', 'reads tasks v2', 'last sync'].map((h, i) => text(cols[i], 30, h, { anchor: 'start', cls: 'sub', d: 0 })),
          ...rows.map(([n, rev, v2, seen, c, dc], i) => {
            const y = 74 + i * 58, d = 0.3 + i * 0.25;
            return box(40, y - 24, 860, 48, { c: c === 'blind' ? 'blind' : 'fgc', plain: c !== 'blind', d }) +
              text(cols[0], y, `/node of ${n}`, { anchor: 'start', cls: 'mono', d }) +
              text(cols[1], y, rev, { anchor: 'start', cls: 'mono', d }) +
              text(cols[2], y, v2, { anchor: 'start', cls: 'mono', c: v2 === 'yes' ? 'c3' : 'bad', d }) +
              text(cols[3], y, seen, { anchor: 'start', cls: 'mono', d });
          }),
          g(`<path d="M50,${74 + 2 * 58} H890" class="ln bad" style="stroke-width:2.5"/>`, { d: 1.8 }),
          text(880, 74 + 2 * 58 + 38, 'excluded: no sync for over 90 days', { anchor: 'end', cls: 'sub', c: 'bad', d: 1.9 }),
          box(180, 300, 600, 60, { label: 'policy: start writing tasks v2 now?', sub: 'every live node reads it → yes', c: 'c3', d: 2.4 }),
          check(760, 330, { d: 2.8 }),
        ].join(''));
      },
      text: `<p>Each node publishes a small <code>/node</code> record: its software revision, which schema forms it can read, and when it last synced. Policies read these records like any other data: "switch to the new format once every device reads it", "clear the inbox once all my devices have acknowledged".</p>
        <p>Because a lost device would block "all" forever, every such policy pairs it with an age cutoff or an explicit device removal. It is never a protocol condition, and it never gates deletion at blind servers.</p>`,
    },
  ],
};
