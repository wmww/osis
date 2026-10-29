# Same-stamp substitution makes holders diverge
> Summary: Two copies of one write (same stamp: `ts`, source, counter) with different values join in arrival order (`osis-crdt` `join_write` keeps the first valued copy), so two valid snapshots (or ephemeral covers) carrying one write with different values, where its own delta was never received, make holders that saw them in different orders read different values forever. Needs a deterministic tie-break at the CRDT level (spec/crdt.md, crdt-model, oracles). Found by the ephemeral security review (M3); repro `tests_review::same_stamp_substitution_diverges` (ignored).
> Tags: security, crdt, ephemeral

## Problem
- A snapshot (durable compaction snapshot, ephemeral commit) carries others' writes under their stamps. Nothing binds a carried write's value to its stamp where the receiver never held the original (for ephemeral session writes it never existed as its own commit). A writer of the aspect can put Alice's stamp on another value. Since snapshots vouch (spec/permissions.md §5.2) such a copy counts as the writer's word; where the original delta was received (held or dropped) copies under its dots count for nothing, so only never-received dots remain.
- `join_write` (core/crdt/src/state.rs): equal stamps keep the copy already held (the valued one over a value-less one). Holders with Alice's copy keep hers; a node joining later, or one restarted (ephemeral), keeps whichever arrives first. That breaks "Deterministic" and "Convergence" (spec/requirements.md), for durable snapshots as well as ephemeral commits (a valid snapshot vouches for what it carries, whatever the value).
- Scope beyond registers: the same holds wherever a dot identifies content: reset writes (no value, harmless), map entry and set/bag element creations (key, value), sequence element creations (chars, anchors), enum case writes. A tie-break must cover each, and keep join commutative, associative and idempotent with pruning and un-merge (`strip_copies`).

## Repro
`cargo test -p osis-crdt --lib -- --ignored same_stamp_substitution_diverges`: two writes under one stamp, joined in both orders, read `alice` and `forged`.

## Direction
- Deterministic tie-break: of two copies under one stamp, the one with the greater canonical encoding wins (valued over value-less first, as now). Spec text first (spec/crdt.md §4.1 join, §8 snapshot copies), then crdt-model from the spec, then the implementation; the crdt differentials and the arrival-order oracles must agree.
- The attacker still chooses the outcome (a forged copy may compare greater), but every holder agrees, which is all a writer could get by writing a new value anyway. Readers write nothing, so this needs write access.
- Not done in the ephemeral security fix (branch `ephemeral-sync`): it changes the join of every write kind, durable included, and the model and oracles with it.

## Also (from issues/snapshot-copy-residue.md, closed)
- The same tie in `join_entry` (keys: a forged key in a held delta's entry ties with the delta's, first seen; where the snapshot also copies the creation, `copies_outside` sees it and `refill` strips the key) and seq `merge_elem` (creation, char). Alternative to an osis-crdt total order: one designated carrier per dot (least snapshot ID) with `copies_outside` detecting the conflict and a rebuild resolving it.
