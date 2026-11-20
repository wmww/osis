# A forged copy can die with no superseder found: Corrupt at the node
> Summary: `Killed::note` dates each dying write by a superseding write held at the join's reach (before, after, or in the delta); for some forged copies (repeated counters: a writer's twins or a hostile writer) no superseder is found and the apply fails `Corrupt("a dead write nothing in its join supersedes")`, which wedges the node (issues/engine-invariant-wedges-sync.md). Two shapes seen in the crdt model's Twins/Hostile modes: equal-stamp copies of a set element's register where one holds a reference (`Place::Ref`) and the other not (`Place::In`), so copy order moves the write to another path; and a sequence position write variant (seed 1043). The law `tests_model::reach_holds_the_change` checks superseders for honest histories only until this is fixed (Interim).
> Priority: normal
> Tags: crdt, engine, security

Replays (osis-crdt, with the honest-only gate in `reach_holds_the_change` removed): `OSIS_CRDT_START=352928056188 OSIS_CRDT_SEEDS=1 OSIS_CRDT_SEED=352928056187 cargo test -p osis-crdt --lib -- --ignored --exact tests_model::crdt_equals_model_large` (Ref/In), `OSIS_CRDT_START=352928056478 OSIS_CRDT_SEED=352928056187 ...` (same), `OSIS_CRDT_START=1043 OSIS_CRDT_SEEDS=1 ...` (Pos). About 1 in 150 large seeds.

Fixed shapes (hand cases in tests_seq): a move stamped with its element's dot above the creation; the same in a delta without the creation.

Direction: a copy that loses by copy order (§4.1 Copy order) is the same write, never a death: compare writes by kind and stamp across the In/Ref split, or put a set element's register at one path whatever its value. Then drop the honest-only gate.
