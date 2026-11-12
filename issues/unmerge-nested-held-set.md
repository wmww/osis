# Un-merge of an invalid record's nested writes depends on holding the invalid delta
> Summary: spec/crdt.md §4.6 (Removed) drops others' valid writes nested in a record an invalid delta created, but invalid bodies never travel, so a node that saw the invalid delta and one that never did read the aspect differently forever (an empty map vs absent). Invalid data affects a value. Found by `sim-sweep:revocation_carol` seed 723062969599 on main f9101135d.
> Priority: normal
> Tags: crdt, engine

## What happens
Replay: `cargo run --bin sim-sweep -- --seeds 1 --from 723062969599 --only revocation_carol --jobs 1` (1 s, fails on main f9101135d). Nodes: 0 Alice (admin), 1 Bob, 2 Carol (writers).
1. Bob and Carol are offline; Alice removes Bob. Bob, offline and not knowing, writes commit E (`e16109e0`) creating map record "ash" in `s:map.0` of some item (the sim's random workload).
2. Carol syncs with Bob directly (`sim.direct`): she gets E and, not knowing of the removal either, judges it valid.
3. Back online, Carol writes commit C (`ec80b627`): a register write nested in Bob's record "ash", no creation of its own. Then she learns of the removal: E is invalid at her.
4. Carol uploads C (valid) but not E (invalid bodies are dropped and never uploaded; Bob forgets the doc). No host and no other node ever holds E.

At quiescence:
- Carol holds E (invalid, dropped) and C. §4.6 removes E's writes with "others' writes nested in them": C's write goes, the aspect's state is empty, `s:map.0` reads **absent**.
- Alice holds only C. She cannot know the record's creation is invalid; the state is C's nested write in a record with no creation held: `s:map.0` reads **`Map({})`**.

The sim's agreement invariant (connected holders read alike) fails: `holders 0 and 2 ... read differently at quiescence: ... s:map.0 Ok(Some(Map({}))) vs ... s:reg.0 ...`, with the three Bob commits Carol got directly listed as held only by node 2 (they are not pending: `pending there None` means node 0 does not hold them pending either). Nothing in node sync is involved: every node holds what it should.

## Why it is a design problem
§4.6 says un-merge is "a function of the held set", and the held sets differ for good: an invalid body never travels, so whether a node holds it depends on who it met before learning of the removal. The "others' nested writes go" clause makes an invalid delta change the reading of a valid write. notes/engine-validity.md states the rule as making that write go "on every node alike", which holds only among nodes that hold the invalid delta.

## Direction
Make an invalid delta affect nothing but its own writes: others' writes nested in its records stay (the record, with no creation held, is not live and reads as at a node that never held the delta). This is the rule §4.6 already gives sequence elements ("others' position and flag writes on them stay"), so maps and sequences would share one rule. Touches spec/crdt.md §4.6, `atomic::Unmerge` / `remove_dots` (notes/crdt.md, Un-merge), crdt-model and held-model, and the compaction trigger issue issues/hidden-writes-not-swept.md (valid writes nested in an un-merged record). Check first why the clause was added (git log -S'others\' writes nested in them' spec/crdt.md).

Minimal reproducer to write with the fix: three writers on `Net`, B and C cut off, A removes B, B creates a map record, C gets it from B directly and writes into it, C reconnects and learns the removal; A and C read the aspect alike.
