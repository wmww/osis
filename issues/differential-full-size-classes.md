# Full-size sync differential: open failure classes
> Summary: `OSIS_FULL=1 differential::histories_hold_their_closure` over seeds 0..199 fails 6 (131, 138, 146, 169, 180, 189 at the commit closing this text's last edit): a device paired just after its account, holding T at sync, was given read judges a loss from partial role commits and keeps T unread for good (must-hold class); reads the model rejects through chains and a keyless grant; one read unlike the reference. The stale status sources class (a node's status counting sources on a connection that is no member at quiet, after a power cycle) is not reached.
> Priority: normal
> Tags: sync, engine, tests

Seed numbers move whenever commit bytes change (worlds are seeded by ID): work from scripts, and turn each class into a hand test (notes/principles.md, Never pin a seed). Replay: `OSIS_FULL=1 OSIS_SYNC_SEED=<n> OSIS_SYNC_SEEDS=1`.

## A loss judged from partial role commits (`must-hold bodies a caught-up reader lacks`)
- Script (debugging aid, `differential::holds(seed, &script, ..)` at full size; fails on worlds 6, 22, 23, 41, 61 of 0..79): `New(2), Give(2, 0, Holder::Node(0), Syncs), Strong(0, None, 0), Strong(3, None, 0), Run, Give(2, 0, Holder::Node(0), Reads), Pair(3)`. Seeds 146 and 189 fail the same check.
- World 22: new node 4 takes T's read secret by D's read ticket while it holds no role commit reaching its account (the read word counts, spec/sync-set.md §2). D's certificates then bring the sync grant with its `roles.0` but only the read grant's `secrets.0` (its `roles.0` and `keys.0` not held). The sync grant's edge reaches the account, so the read word stops counting and the role commits give sync; the loss is judged in that same delivery, the read secrets drop, and T's sync ID, which would bring the read grant's `roles.0`, is never read again. Node 4 keeps T unread for good, and judges the read grant's entry under D `MustNot(OutsideRequired)` and deletes it, while nodes 0 and 3 hold it `Must`.
- Design question: "once the role commits it holds reach the holder they alone decide" assumes a node holds a role commit's role parts whenever it holds the commit; a certificate copy carrying some parts only breaks that. Candidates: the read word counts while a held role commit on T lacks a role part (a missing part is no decision), or certificate copies under the holder's sync ID carry a grant's `roles.0` with its boxes.

## Reads the model rejects
- 138, 169: the node reads by its role commits through a chain path (a grant to a thing, then record edges) that held-model's closure does not count.
- 180: the node reads a value while holding no secret of the thing, through a keyless grant chain (`None with key access`).
- 131: a node reads a thing unlike the reference.
- None studied: first decide whether the model or the engine is right in each.

## Stale status sources after a power cycle
- Not reached by seeds 0..199. `Node::closed` returns early only when it holds no session for the connection; a session goes only in `closed` itself, which then closes it in streams and opens and hands its members on, and opens learns of a connection only through its session's messages. So that early return skips nothing, and the stale path is elsewhere; no reproducer, so no hand test.
