# Same-stamp substitution makes holders diverge
> Summary: Two copies of one write (same stamp: `ts`, source, counter) with different values join in arrival order (`osis-crdt` `join_write` keeps the first valued copy), so a writer that re-sends another's write with another value inside a snapshot makes holders that saw the copies in different orders read different values forever. Needs a deterministic tie-break at the CRDT level (spec/crdt.md, crdt-model, oracles). Found by the ephemeral security review (M3); repro `tests_review::same_stamp_substitution_diverges` (ignored).
> Tags: security, crdt, ephemeral

## Problem
- A snapshot (durable compaction snapshot, ephemeral commit) carries others' writes under their stamps. Nothing binds a carried write's value to its stamp: the original commit may be dropped (covered) or, for ephemeral session writes, never existed as its own commit. A writer of the aspect can put Alice's stamp on another value.
- `join_write` (core/crdt/src/state.rs): equal stamps keep the copy already held (the valued one over a value-less one). Holders with Alice's copy keep hers; a node joining later, or one restarted (ephemeral), keeps whichever arrives first. That breaks "Deterministic" and "Convergence" (spec/requirements.md), for durable snapshots as well as ephemeral commits (spec/permissions.md §5.2 judges a carried write by its claimed author, not its value).
- Scope beyond registers: the same holds wherever a dot identifies content: reset writes (no value, harmless), map entry and set/bag element creations (key, value), sequence element creations (chars, anchors), enum case writes. A tie-break must cover each, and keep join commutative, associative and idempotent with pruning and un-merge (`strip_copies`).

## Repro
`cargo test -p osis-crdt --lib -- --ignored same_stamp_substitution_diverges`: two writes under one stamp, joined in both orders, read `alice` and `forged`.

## Direction
- Deterministic tie-break: of two copies under one stamp, the one with the greater canonical encoding wins (valued over value-less first, as now). Spec text first (spec/crdt.md §4.1 join, §8 snapshot copies), then crdt-model from the spec, then the implementation; the crdt differentials and the arrival-order oracles must agree.
- The attacker still chooses the outcome (a forged copy may compare greater), but every holder agrees, which is all a writer could get by writing a new value anyway. Readers write nothing, so this needs write access.
- Not done in the ephemeral security fix (branch `ephemeral-sync`): it changes the join of every write kind, durable included, and the model and oracles with it.
