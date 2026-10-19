# Testing strategy
> Summary: How osis is tested from the start of the Rust implementation: models as oracles, conformance vectors, differential tests against the models, property tests and fuzzing per crate, a deterministic multi-node simulator with fault injection and adversaries, security and size regression tests, and a spec-to-test map. Built infrastructure (principles, tiers, vectors, fuzzing, budgets, benches, coverage, policy, spec map) lives in notes/testing.md; this plan keeps the strategy items not yet built.
> Tags: tests

## 1. Models (existing, refactored)
- **crdt model**: stays the reference for merge semantics. Add what notes/crdt.md lists as unmodeled where cheap (own-counter checks, strict rule 7 rejection) so differential tests cover them. Expose a library API (apply ops, join, read, encode) for the differential harness.
- **membership model**: refactor so the rule code mirrors spec/permissions.md section by section and can be audited against the prose; add counterexample traces with shrinking (minimal failing history printed as a scenario); add quiescence checks ("after all deliveries, every node agrees" as the standard property); expose the walk as a pure library function over a history for differential tests.
- **TLA+ / stateright**: plans/tla-models.md.
- Model findings flow to spec first, then to the implementation; a model is never patched to match the implementation.

## 3. Differential tests (implementation vs model)
- CRDT: random op sequences from the model's generator applied to both; equal reads, equal canonical bytes, equal results under random delivery orders, duplication, snapshots and expiry stripping. Run on every commit at modest size, nightly at large size.
- Membership: random histories from the membership model applied to the implementation's timeline; equal rosters, equal validity per write, equal effect of roster snapshots and projections.
- Decoders: model decoder and implementation decoder agree on accept/reject for random and mutated inputs.

## 4. Per-crate property tests (fuzzing: notes/testing.md)
- proptest in every crate for its algebra: join laws, encode/decode round trips, canonical form, diff/read identities, HLC monotonicity under skew, retention arithmetic, paging (every page within the chunker bounds, pages re-join to the state).
- Crypto: known-answer tests from the primitive crates' vectors plus ours; test that each domain string is distinct and used once; a test that every signature verifies only under its own domain.

## 5. Deterministic simulation (the main tool once nodes exist)
Built (notes/testing.md, Simulator): harness, faults, crashes, disk and server loss, the invariants, the scenario library, adversaries, version skew, seed replay, the nightly sweep. Left (plans/sim.md tracks the blocked scenarios):
- Invariant: state size bounded per spec/requirements.md, Scale.
- Adversaries: an equivocating writer (two commits of one node with overlapping counter ranges on one aspect: both invalid, spec/commits.md §4), a server that lies about tombstones (re-serves or re-announces deleted entries).

## 6. Security tests beyond the simulator
- Negative tests per permission rule: every "MUST NOT be able to" in spec/permissions.md and spec/sync.md as a test where an actor tries it and fails.
- Metadata tests: blind-node view checks (a server sees only what spec/sync.md says it sees; blob sizes padded; no author linkage across labels without the read key).
- A review pass per subsystem by a fresh agent with the attack list in notes as a checklist, before each milestone.

## 8. API and app level
- The Rust API tested through small example apps in the repo (notes, chat per notes/chat.md, folder): end-to-end tests in the simulator, driving two or more app instances.
- GUI apps, when they exist, via the gui-testing skill for smoke tests only; logic stays testable below the GUI.

## Done when
Each item above exists and runs in CI or nightly, and notes/testing.md describes what it covers and how to run it. Then delete this plan.
