# Test strategy items not built
> Summary: Testing still missing: a long simulator run (10^4 seeds per scenario) and cleaner membership-model code for differential tests; plus small open TLA+ readings.
> Tags: tests, sim

Repro: not built, no failing test. What is built is in notes/testing.md.

- **Sweep**: "every headline scenario green over 10^4 seeds" was never run; the largest runs are in notes/testing.md (Simulator; latest sweep numbers there). Nightly runs `sim-sweep --seeds 10000 --budget-secs 6000`, which covers far fewer seeds per scenario.
- **Membership model**: rule code mirroring spec/permissions.md section by section, shrinking counterexample traces, quiescence checks, the walk as a pure library function (differential tests exist for crdt and perm: osis-crdt `tests_seq`, `tests_join`, `tests_decoder`; osis-perm `tests/differential.rs`).
- **TLA+**: open minor readings without counterexample: sync S17, rotation R10–R15, membership M4–M10 (models/tla/*/AMBIGUITIES.md). Not modeled: notes/testing.md (Models).
- **GUI**: no GUI apps yet, so no gui-testing smoke tests.
