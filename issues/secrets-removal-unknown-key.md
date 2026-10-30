# A `/secrets` removal of an entry whose key a node never learns is judged admin there
> Summary: a removal names only the entry's dot; a node that never held the entry's creation (dropped by compaction) and holds it dead in a snapshot judges the removal as needing admin forever, while nodes that held the creation judge it by the entry's role; a writer's rotation removing an entry a concurrent rotation already removed can then be valid at one node and invalid at another.
> Tags: engine, perm

Where: core/engine/src/apply/validity.rs `secrets_role`, `resolve_rotation` (keys from `box_keys` or the entry live in the state; tombstones carry no key, spec/crdt.md §5.6).

Scenario: writers W1 and W2 concurrently rotate read on A, both removing old read box X. An admin compacts `/secrets` covering W1's rotation, not W2's; X's creating delta is dropped. A new node C holds the snapshot (X tombstoned, no key) and W2's rotation: W2's removal of X needs admin at C, so W2's delta (its new boxes) is invalid at C and valid elsewhere. Narrow (needs both the concurrency and the compaction before C joins); healed by a re-seal or the next rotation for C's boxes, not for the state divergence.

Fix directions: count a removal of an entry the receiver holds dead (tombstone in a valid snapshot or state) as touching nothing; or let `/secrets` snapshots keep the keys of tombstoned entries; or carry the key in a `/secrets` removal record (a CRDT format change).
