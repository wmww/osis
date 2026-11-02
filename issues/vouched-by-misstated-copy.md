# A misstated snapshot copy still vouches for an entry's nested writes
> Summary: `Unmerge::strip` keeps others' writes nested in an invalid delta's entry when any held valid snapshot indexes a write under the entry's dot (`validity::vouched`), even where `rebuilt` strips that snapshot's copy as misstated (`strip_forged`); the entry then keeps nested writes with no creation, which spec/crdt.md §4.6 ("a record whose creation a valid snapshot's copy so keeps") does not allow. Found by reading; not reproduced.
> Tags: security, engine, crdt

- Shape: writer A (later invalid) creates entry k at dot dA; B (valid) writes into k; V (valid) writes a snapshot whose copy of dA's creation differs from A's delta (another `ts` or value: misstated, item 218 rules). `rebuilt` strips V's copy under dA (`strip_own`) but `vouched` still holds dA, so B's nested write stays in a record whose creation nothing keeps; it may read live under k.
- Fix direction: build `vouched` from copies that survive (leave out a snapshot's misstated dots), in `rebuilt`, `replay_all` and `join_into_state` alike, so the rule stays one function of the held set. Hostile-only (a forging valid writer); B's own content only, k is A's.
- Needs a hand-built repro first (`Forged` steps in order.rs make misstated copies).
