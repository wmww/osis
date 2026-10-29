# Forged map keys join in arrival order after a prune
> Summary: Copies of one map entry with differing keys (a forged copy a valid snapshot vouches for) join by the copy order of spec/crdt.md §4.1, but the key belongs to whichever records carry it, not to one write: when one copy's record loses all its content to a reset before it meets the other, that key is gone on one path and kept on another, so holders can read different keys. Needs per-entry key provenance or keying entries by (dot, key).
> Tags: security, crdt

## Problem
- A map entry's key is repeated in every record of the entry (resurrection, spec/crdt.md §5.6), so it is carried by the creation and by nested writes of any author. §5.6 joins it as: the key of the creation with the greater stamp; between equal creation stamps the greater key.
- Repro (osis-crdt, `forged_states` in `tests_laws.rs` with the kitchen-sink type: writers 0 and 1 share source and clock, writer 2 resets): A carries entry d with key 0 and later nested writes; B carries d's creation (same stamp) with key 1 and nothing newer; C resets above B's writes. `(A ⊔ B) ⊔ C` reads key 1 (taken while B's record lived), `A ⊔ (B ⊔ C)` key 0 (B's record pruned first). Two-way joins also differ when one side prunes the other's record before the merge. The forged-copy proptests therefore leave maps out (`sink_no_map`).
- Honest copies always carry one key, so only a writer forging a copy (snapshot) or a key in its own nested write can cause it; readers write nothing.

## Direction
- Key entries by (dot, key): records with another key are another entry (a forged key shows as an extra map key, a pure union). Wire and state change.
- Or engine-level: one designated carrier per dot (least snapshot ID); `copies_outside` detects the conflict between held snapshots and a rebuild resolves it (`strip_forged`).
