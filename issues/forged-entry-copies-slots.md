# Forged copies of one map entry written as two encodings break the join laws
> Summary: copies of one map dot's records under different keys whose content at one position is two encodings (§7 `Slots`: a register beside an enum, text or map) join differently by order, differ from crdt-model, and expiry stops commuting with join; `tests_laws::entry_copies::repro_forged_entry_copies_across_encodings`.
> Priority: normal
> Tags: crdt, security

Only forged copies reach it (a valid snapshot's copy of a write beside its delta's, spec/permissions.md §5.2: equal stamps, differing keys and encodings), so nodes holding the same bodies can still read apart: class F in notes/convergence-study.md, but not "no divergence". Present on main before the copy-order rework too (more often there).

Smallest seen (two copies, flat): record `a` holds an enum case and record `b` a register write `w`, joined with a copy holding `w` under `a`. Record `a` then holds a `Slots` whose enum slot carries `w`'s embedded reset (§7 `embed`) while `w` itself sits under `b`. `state::prune_dot` filters slot by slot (`Fragment::filter_by` against the embedding of the other's register slot) and crdt-model splits writes leaving out the embedding (`writes::writes`); the two disagree on whether an embedded reset is the register write's (and goes with it) or the slot's.

Replay: `cargo test -p osis-crdt --lib -- --ignored entry_copies::repro_` (fails within the first 30 seeds). Likely fix: say in spec/crdt.md §5.6 which record a slot's embedding sits in (the register write's), and make `filter_by` treat embedded writes as the register's, as the model does.
