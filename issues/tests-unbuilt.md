# Test strategy items not built
> Summary: What the MVP test strategy planned but did not build: two simulator adversaries, a state-size invariant, a green 10^4-seed sweep, model refactors and additions for differential tests, a decoder differential, the optional TLA+ membership-walk model, and the minor open TLA+ readings.
> Tags: tests, sim

Repro: not built, no failing test. Left from plans/sim.md, plans/testing.md and plans/tla-models.md (deleted; what is built is in notes/testing.md).

- **Sim adversaries**: an equivocating writer (two commits of one node with overlapping counter ranges on one aspect: both invalid, spec/commits.md §4); a server lying about tombstones (re-serves or re-announces deleted entries).
- **Sim invariant**: state size bounded per spec/requirements.md, Scale.
- **Sweep**: "every headline scenario green over 10^4 seeds" was never run; the largest runs are in notes/testing.md (Simulator; latest sweep numbers there). Nightly runs `sim-sweep --seeds 10000 --budget-secs 6000`, which covers far fewer seeds per scenario.
- **Models**: crdt model: own-counter checks and strict rule 7 rejection (notes/crdt.md, unmodeled); membership model: rule code mirroring spec/permissions.md section by section, shrinking counterexample traces, quiescence checks, the walk as a pure library function. Differential tests exist for crdt (osis-crdt `tests_seq`, `tests_join`) and perm (osis-perm `tests/differential.rs`); a decoder differential (model vs implementation accept/reject on mutated input) does not.
- **TLA+**: target 3 (membership walk, spec/permissions.md §5–§6) dropped for the MVP; worth doing when that text next changes. Open minor readings without counterexample: sync S17, rotation R10–R15 (models/tla/*/AMBIGUITIES.md). Not modeled: notes/testing.md (Models).
- **GUI**: no GUI apps yet, so no gui-testing smoke tests.
