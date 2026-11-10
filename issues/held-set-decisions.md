# held_set_decides: what is left needs two decisions
> Summary: Every remaining plain-size failure of `order::held_set_decides` is one of two open rules. (1) A purged write a node never got shows the value it had replaced; a node that got it first shows nothing (seeds 743309, 452234901986). (2) When a creator's write turns invalid, which other writes inside its entries a snapshot keeps; engine and held-model read the spec differently (seeds 1524893203, 758421392937).
> Priority: normal
> Tags: engine, crdt, held-model, tests, tess-call

Replay: `OSIS_ORDER_SEED=<seed> OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain`. `OSIS_ORDER_DUMP=1` prints where the failing node's index differs from the keep-everything node's.

## 1. A purge reaching a write before the write itself (needs Tess)
What users see: Bob writes "b" over Alice's "a". An admin purges Bob's write. A node that had Bob's write before the purge shows nothing (the purged write still counts as the newer write, just without its value). A node that learned of Bob's commit but not its content before the purge (it was not following that item yet, or had thrown the write out while it seemed invalid) shows "a" again, for good: the purge marks the write as never received, so it is never fetched, and the purger deletes it at hosts.

Two routes in, same state ("a part missing when purged", spec/commits.md §5 Never received):
- seed 743309 (PartsAway): the node starts following the thing after Bob's commit arrived and after the purge.
- seed 452234901986 (`repro_purge_author_order_452234901986`): the write was dropped as invalid, then turned valid and purged in one step.

This breaks "a part on a thing it starts holding later joins then" (spec/requirements.md). Options:
1. Treat the purged-but-never-received write as missing: fetch it, keep only its value-less remains. Converges wherever a host still has it; after the purger's hosts delete it, nodes that missed it still show "a".
2. A purge takes the write out of every node's state entirely (no value-less remains). Every node shows "a" unless the purger also resets; spec/crdt.md §4.7 changes for purges.
3. Accept it, and the harness spares such aspects (computed from the history). Users can see a replaced value come back on some nodes.

Option 2 is the only one that is the same everywhere without hosts keeping anything; it makes a purge without a reset show the older value, which the API's purge by author does today (it writes `purge.0` only), so that API would reset too.

## 2. Which writes an invalid creator's entry keeps (spec reading; held-model rewrite)
spec/crdt.md §4.6: an invalid delta's records go with others' writes nested in them, but a record a valid snapshot holds stays "with the valid writes nested in it, whichever body carries them". The engine and held-model differ on which positions that covers. Both cases agree on validity and on every applied commit; only the read differs.
- 1524893203 (shrunk to 25 steps, below): key `k2` of a map has two records; a valid write by another author went into the first record's nested map, at entries whose creation is in the second record, whose creator is invalid here. The engine keeps the write (reads `{0: "v2", 1: 2}`); held-model drops it (`{0: "v1", 1: 7}`). The spec's "a copy under another key keeps only its own record" suggests the model.
- 758421392937 (Keeps, `later`): an invalid creator's map entry `k0` is held by a valid snapshot; a later valid write into it expired, so its writes sit value-less in the dot's key-erased record. The engine keeps them, so they beat the snapshot's older values and `k0` reads absent; held-model drops them and reads the snapshot's `{0: "whole", 1: 1}`. The spec says a snapshot holding the key-erased record keeps every record of the dot, not the converse.

Decide the rule (one candidate: the records of a dot are one entry here too, spec/crdt.md §5.6, so a snapshot holding any record of a dot keeps valid writes in all of them; that covers 758421392937 and not 1524893203), state it in §4.6, then make the engine or held-model follow it.

Shrunk 1524893203 (`check(1524893203, &h, cfg)` with RecordOnly's cfg): `vec![RecordOnly { by: 0, under: None }, GrantFlow { by: 0, t: 1, holder: 2, role: Admin }, RemoveFlow { by: 0, t: 1, holder: 0, lower: false }, Mixed { by: 2, t: 0, op: 19, k: 1, v: 8 }, Forged { by: 0, a: 1, b: 1, how: 1, op: 21, k: 0, v: 2 }, Aim(New { by: 0, parent: 6, write: false }), Aim(Edge { by: 0, t: 5, holder: 2, role: Some(Admin) }), Aim(Require { by: 0, t: 0, op: 31, rule: 1 }), RecordOnly { by: 1, under: None }, Aim(RecordOnly { by: 0, under: Some(0) }), Aim(Require { by: 0, t: 2, op: 16, rule: 3 }), Aim(Typed { by: 0, t: 4, op: 30, k: 2, v: 1 }), Aim(Typed { by: 0, t: 2, op: 11, k: 1, v: 3 }), Aim(NestedItem { by: 0, other: 1, t: 3, k: 2, compact: true, also: false }), Aim(Nested { by: 2, other: 1, t: 0, k: 2, text: false, compact: true, also: true }), Aim(Typed { by: 2, t: 1, op: 9, k: 1, v: 0 }), Aim(RemoveFlow { by: 1, t: 6, holder: 3, lower: false }), Aim(Nested { by: 0, other: 1, t: 2, k: 1, text: true, compact: true, also: false }), Aim(Message { by: 0, t: 2, v: 5 }), Aim(Write { by: 1, t: 2, op: 3, k: 2, v: 2 }), Aim(Nested { by: 2, other: 1, t: 2, k: 0, text: false, compact: false, also: false }), Aim(Undo { by: 1, back: 2 }), Aim(Compact { by: 2, t: 0, op: 10 }), Aim(Write { by: 2, t: 1, op: 0, k: 1, v: 4 }), Aim(Demote { by: 0, t: 3, holder: 2, at: 0, to_read: true })]` (as printed: `Aim(x)` is `Aim(Box::new(x))`).

## Also open
- A commit pending because its linked header list waits for pages (`WaitBlobs`) that turns out unjudgeable once resolved stays pending: node-sync holds its entry as a commit, so nothing would fetch it again if the engine threw it out. Unjudgeability is otherwise decided before any pending reason.
