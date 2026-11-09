# held-model judges values with crdt-model (test-design step 5b)
> Summary: held-model has its own CRDT (`src/crdt.rs`: registers, maps of registers, texts), so `held_set_decides` judges sets, counters, lists, structs, enums and nested maps only by the same-engine keep-everything node. Make crdt-model the one model of values: held-model's deltas become crdt-model fragments, and every encoding is judged by an engine-independent oracle. Moderate: about 1-1.5k lines across held-model and the adapter.
> Priority: normal
> Tags: tests, held-model

Why: the keep-everything node shares the engine, so it is blind to a wrong rule both nodes apply alike, and to an order-dependent bug both reach alike. A sabotaged list/text flag join (`seq.rs` `join_flag`: a held delete beats a later undelete) passed `held_set_decides` at quick; at `OSIS_FULL=1` plain from 5000 it failed 2 seeds only, both on `t:text.0` (the debug index rebuild and held-model's text), never on a list aspect and never through the keep-everything node. osis-crdt's differential caught it at once (10 tests).

What changes:
- held-model depends on crdt-model (both are independent readings of spec/; tools/policy.py allows held-model's one workspace dependency on crdt-model and nothing else). `Delta::Writes(Vec<Write>)` becomes a crdt-model `Frag`; `crdt.rs`, `Op` and `Write` go.
- crdt-model has join, prune, read, value-less writes, `strip` (expiry and purge by dot), `unmerge` (invalid copies), `writes()` (each write alone, by name) and the wire decoder. Missing, to add there: supersedes (spec/crdt.md §4.8, generic over `writes()` and prune), covered (join equality, spec/commits.md §5), holds (by name), and a dot-to-commit map (sessions' ranges, as the adapter's `hist.ranges` gives) so purge and expiry strip one commit's values.
- model.rs uses the CRDT at about a dozen places (state and read per aspect, replaced and replaced_at, covers, forbidden values, the leftover and key-erased rules). undo.rs (§4.6 undo commits, used by held-model's own generator) and gen.rs write fragments through crdt-model's `ops`. held-model's tests port with them.
- The adapter (osis-node `tests/it/held.rs`) converts the engine's fragments by their wire bytes (crdt-model `wire::decode_delta`), dropping `Fragment::flat`, the `IN` list and the "another shape" skip: every aspect is in scope.
- ASSUMPTIONS.md's CRDT section shrinks to what crdt-model leaves out; README and notes/testing.md say held-model covers every encoding.

Done: a wrong join, supersede or strip per encoding (set, counter, list, struct, nested map) fails `held_set_decides` through held-model at plain size.
