# Full-size sync differential: open failure classes
> Summary: `OSIS_FULL=1 differential::histories_hold_their_closure` over seeds 0..199 fails 6 (114, 131, 138, 169, 180, 189). Understood: a connection whose sources never catch up while idle (114). A reader lacking a keying commit its holder logs (189) has a shrunk script; chain reads (138, 169), a keyless read (180) and 131 are unstudied.
> Priority: normal
> Tags: sync, engine, tests

Seed numbers move whenever commit bytes change (worlds are seeded by ID): work from scripts, and turn each class into a hand test (notes/principles.md, Never pin a seed). Replay: `OSIS_FULL=1 OSIS_SYNC_SEED=<n> OSIS_SYNC_SEEDS=1`. Run the 200 seeds as four `tools/heavy` holds of 50 (about 4 minutes each on an idle box).

## A reader lacking a keying commit its holder logs (189)
- Shrunk script on world 189 (debugging aid, 8 steps): `New(3), NewIn(3, 0), Give(3, 1, Holder::Node(1), Syncs), Strong(1, None, 1), Strong(1, None, 0), Give(3, 0, Holder::Node(1), Reads), Run, Unstrong(0, Some(0), 1)`. Node 1 holds, as must-hold under T0's sync ID, a role commit (`keys.0`, `sync.0`, `secrets.0`) on T1 by node 3, with `kept: true`; node 0, caught up, has no entry of it at all. Not studied further.
- Ruled out: the history path. A grant with history writes the history entry of each epoch it boxes (`osis_keys::box_holder`), a plain thing's derived epochs from before its keying included, and boxes the holder up to the grant's own role (spec/crypto.md §4 Key access). No keyless grant or raise is in this script.

## A connection idle and never caught up (114)
- Script on world 114 (debugging aid): `New(2), Give(2, 0, Holder::Node(1), Reads), Strong(1, None, 0)`. Node 1 reads T as None. At quiet the session between nodes 1 and 2 is idle (no request out, none waiting, nothing unanswered), yet every sync ID on it shows that source not caught up at both ends, so node 1 never pulls T's entries. Not a closure bug: a streams or opens stall. No seed-0 reproducer yet.

## Reads the model rejects
- 138, 169: the node reads by its role commits through a chain path (a grant to a thing, then record edges) that held-model's closure does not count.
- 180: the node reads a value while holding no secret of the thing, through a keyless grant chain (`None with key access`).
- 131: a node reads a thing unlike the reference.
- None studied: first decide whether the model or the engine is right in each. Shrinks of these stop at the 150-candidate cap at 20 to 50 steps.

## Stale status sources after a power cycle
- Not reached by seeds 0..199. `Node::closed` returns early only when it holds no session for the connection; a session goes only in `closed` itself, which then closes it in streams and opens and hands its members on, and opens learns of a connection only through its session's messages. So that early return skips nothing, and the stale path is elsewhere; no reproducer, so no hand test.
