# Test design (proposal)
> Summary: PROPOSAL, Tess decides. A test system with one property test per stated property per component, examples and minimal reproducers beside it, sizes as a knob rather than separate tests, and selection by component instead of hand lists. Consolidation groups with what to delete, TLA verdicts, why runs are slow, the gate lock, migration order.

Nothing here is decided or built. notes/testing.md and notes/build.md describe what runs today; this note says what it should become. It folds in issues/tests-slow.md, issues/pinned-seeds-go.md and issues/oracles-observable.md.

## Principle
Each component's note states its few properties at the top (crdt: join is a lattice and equals the model; engine: what a node reads is a function of the commits it holds; perm: the incremental walk equals the walk from scratch; rotation: no departed holder reads later content, every holder ends reading everything; sync: everything settles and must-hold bodies reach the host). Each property has exactly one randomized test with an oracle (a model, or the from-scratch path). Rules that need a picture get a small hand-written example. Nothing else enters the suite. A test that names no property or rule goes.

## Organization: component x kind
Five kinds, each run in every component that has it:

| kind | what | size | runs |
|---|---|---|---|
| example | one spec rule or one minimal reproducer, hand-readable steps, no generator seed | ms, under 1 s | every gate |
| property | one generator + one oracle per property | one function; `quick` (seconds) in the gate, `plain` for a reviewer, `full` before a release | gate quick; reviewer plain for touched components; release full |
| model | crdt-model, roles-model, held-model, TLA: oracles the properties use, plus their own self-checks | small | when the model or the spec sections it models change |
| system | the sim: many engines, hosts, faults; checks only what no single engine can (sync liveness, host contents, state bound) | every scenario x 5 seeds in the gate; breadth before a release | gate; release |
| timing, fuzz | release-build scale and budget checks, libFuzzer | by hand | by hand |

A component's reviewer set is "every property test of the crates the branch touched and their dependents", computed from paths and the Cargo graph by a tool, not a hand list in notes. Three of the last periodic run's six bugs were per-branch-list gaps: a plain-size test nobody's list named. Derived selection removes that class.

What today's words become:
- **tier 1** = examples + properties at `quick`. **tier 2** = properties at `plain`/`full` + real-socket networking tests. **tier 3** = models, system breadth, timing, fuzz.
- **oracles / per-branch oracles / per-branch list** = properties at `plain` for the touched components (derived, above).
- **periodic checks** = properties and sim at `full`, before a release only.
- **sim sweep** = the system kind. **order harness** = the engine's held-set property (G1). **walks** = the engine's rebuild property (G2).
- **held-model, roles-model, crdt-model** = models: the oracle inside G1, G4, G3.
- **TLA** = models of designs; run only by the branch that edits one (below).
- `_small` / `_large` twins and `OSIS_FULL` = one function with a size knob; an override env var still prints its range.

## Measured (main 8f3cd8d0, osis-node `it` tier 1, each test alone on one thread, box load about 85)
- 1147 tests, 1404 CPU-s. The 556 cheapest (under 0.3 CPU-s each) cost 62 CPU-s together; the 252 at 1 CPU-s or more cost 1144 (81%).
- `order::` 92 tests, 604 CPU-s (43%): the 23 `arrival_order_*` configs 292, the 69 pinned or scripted others 312. `arrival_order_found_histories` alone 160 CPU-s.
- Tests named alike/any-order/every-order across modules: 114, 461 CPU-s (33%), all checking G1's one property.
- Seed-named tests: 76 in the workspace (30 node `order::`, 26 sim `library`, 14 sim `net`, 6 sim `work_sets`), plus 37 `check(<seed>, ..)` pinned histories in order.rs and the `found()` lists.
- Last periodic run (e3cdd005f): tier-2 set 54,474 CPU-s, of which osis-node `it` ran 4,547 s wall of 10,371; order alike + exhaustive 19,650 CPU-s; sweep 35,350; TLC `small` 8,800.

## Consolidation groups
**G1 Engine: reads are a function of the held set.** Today: 23 `order::arrival_order_*` tests over 14 generators (`history`, `record_only`, `required`, `focused`, `kept`, `seq_compact`, `purge`, `purge_author`, `purge_rows`, `list_expiry`, `carrierless`, `node_history`, `settled(..)` twice), `carrierless_part_alike_*`, `new_node_alike_*`, `reopen_after_each_commit_*`, `parts::parts_differential`, `part_away_differential`, `rosters_alike_across_sync_sets`, `keep::any_order_*`, `retention::purge_rights_any_arrival_order`, `waits::gap_snapshots_converge`, `sessions::gap_cover`, engine `apply::tests_order::validity_alike_*_random`, held-model's compare, and about 60 scripted `*_alike*` tests. One test instead: `held_set_decides`. One generator with every feature on its own draws; the seed picks an emphasis (seed mod k: purges, keeps, required, record-only, lists, parts away, settled), as `with_syncs` already picks by seed. Orders from one Cfg (as made, reversed, fill, a few shuffles, late parts, early clock); an `exhaustive` size runs every order of histories of at most 5-6 commits. Oracle per judged node: held-model where in scope, else the keep-everything node holding the same commits (oracles-observable P1-P4); orders then agree because each node equals its oracle. Delete the 23 configs and their generators, the `_small` twins, `held_model_retention_modes_survey`, and the scripted alike tests that a minimal reproducer does not justify. A generator that steers around a known difference (`purge_author_history`'s comment) is a carve-out: the unified generator does not steer, and a failure is a design question.

**G2 Engine and perm: incremental equals from scratch.** Today: `check_rebuilt` (debug, every transaction), `walks::` (3 random harnesses, 9 scripted), order's reopen-against-rebuild compare, `reopen_after_each_commit_*`, `flows::persisted_index_equals_rebuild`, `sessions::pruned_sessions_converge`, `retention::register_rebuild_*`, engine `paged_apply_matches_whole` (streamed vs whole), perm `incremental::` (8 `_large` shapes). Engine: extend the always-on debug check to compare the persisted index with a rebuild at the same sampled points; every test then is a walks test, so delete the walks harnesses and `reopen_after_each_commit`; keep streamed-vs-whole as one property. Perm: one `incremental_equals_from_scratch` whose generator mixes the 8 shapes.

**G3 CRDT: implementation equals the model.** Today: crdt-model `props` (laws and convergence on the model, 28 tests), osis-crdt `*_matches_model` split by type (join, kitchen sink, list join, list read order, map of text, slots, nested slots, hostile list/text/text slots, seq wire, long runs), `seq_differential`, `model_order_independent`, `tests_laws` join laws x3, node-level order. One differential on the kitchen-sink generator over every encoding, with a hostile mode and the wire round trip; the model keeps its own law tests. Delete the per-type variants and the implementation-side honest join laws (they follow from equality with a lawful model); keep the forged-copy laws where the model has no answer.

**G4 Perm: walk equals roles-model.** `differential::` (walk, trust, addenda) stays, one test per model layer. Roles.tla duplicates roles-model (below).

**G5 Engine rotation.** Seven `_large` harnesses (`forked_reseals_settle`, `forks_with_departures_settle`, `regrants_after_invalid_rotation`, `withheld_departures_leak_nothing`, `forged_departs_leak_nothing`, `cycle_removals_leak_nothing_random`, `rotator_lacking_write_rotates`) check two properties. One generator mixing forks, departures, forgeries, cycles, withholding and missing write; both properties checked on every seed. Pinned `withheld_*` seeds become examples or go.

**G6 Ephemeral.** `random_window_{converges,inflight,one_capped_host}`, `random_churn_converges`, `ephemeral_reverts_{within_rights,with_restarts}`, `memory_random_*` x3, `many_authors_under_host_rates` and sim `ephemeral`/`ephemeral_capped` test convergence within caps at two layers. With the queued ephemeral redesign: one node-level property (holders sharing non-lossy hosts read alike, caps respected) and the sim scenario for liveness only. Delete `many_authors_under_host_rates` (12 min in dev; rates are a counted-work check).

**G7 Sim.** About 40 library and net tests replay one scenario at seed 1 (26 + 15, most `#[ignore]`); the gate's sweep already runs every scenario at 5 seeds: delete those that assert nothing beyond the scenario's own checks. The 46 seed-named sim tests (16 `link_race_seed_*` alone) reproduce nothing once dice or code move: delete, keeping only bugs that have no example yet (issues/seed-pinned-bugs-without-test.md). The sim's read-alike invariant stays as a cheap sanity check; G1 owns the property.

**Pinned seeds everywhere.** Each of the 76 seed-named tests, the 37 pinned `check(<seed>, ..)` histories and `found()`/`found_histories` (160 CPU-s, 11% of node tier 1): delete when a scripted test already cites the same rule; otherwise rewrite as an example with named orders (no shuffle rng). Expect most to go.

## TLA
Why `small` went from about 6 min to 3.3 h: its list grew from 31 to 69 instances between Nov 1 and Nov 7, nearly all from the keys design steps, and Depth0 instances were tagged small. Depth0 is 9,320 s of 11,758 (79%); roles `MC_core` 1,526 s. The cost is per state, not state count (`D0_rm_possess0`: 3,596 states, 5,047 s). Measured: `D0_nc` (716 states) 23 CPU-s safety-only against 203 with its four temporal properties, same states: the fairness conditions (one `WF` per learner and actor, five families) re-evaluate Depth0's recursive operators (`Fix`, `AncV`, `KeyedTo`) on every transition.
- **sync** (4 small, 163 s): keep.
- **rotation/Rotation** (8 small, 79 s): keep; one negative control, not three.
- **rotation/Depth0** (21 small, 9,320 s): shrink. The live keys model, but 27 constants, many selecting rejected candidates (`Rule` = box/remover/ahead, `Merge`, `Alone`, `LeftOut`, `Fresh`, `Taint`, `DMerge`), with 13 expected-failure instances that record rejected rules. Strip the rejected-rule knobs (one line each in AMBIGUITIES.md says what failed), check safety on every instance, liveness on one, keep one or two negative controls. Target under 3 min.
- **rotation/Lockout, Finalize, Cover**: decided-rule studies; keep one passing instance and one negative control each, delete the other candidate instances.
- **roles/Roles**: delete. roles-model covers the same walk, has exhaustive tiers and is checked against osis-perm; `MC_sticky` is a stated limit already in notes/permissions.md.
- **sides** (17 instances, 10 expected failures): a design exploration not written from spec; keep the chosen mode's passing instances, delete the candidate modes' failures.
- When: never periodic, never in the gate. `run.sh <module>` runs that module's instances; the branch that edits a module or the spec sections it models runs it. Each module's set stays under 3 min at one worker; anything bigger is a by-hand instance.

## Why slow, why so many binaries
- Binaries: cargo builds one test executable per crate target (17 lib unit-test, 15 `it`, 3 single-file, plus doctests; 35 in the tier-2 run). That is normal and not the cost: osis-node `it` alone is about half of tier-1 CPU and 44% of the tier-2 wall.
- Slow: every test is a multi-node signed, encrypted sync in a debug build (50-200 ms floor); harnesses multiply seeds x held sets x orders x late parts x clock modes (exhaustive: up to 720 orders per held set); a dozen harnesses re-test G1's one property on their own histories; pinned tests run whole LARGE configs inside tier 1.
- Running binaries in parallel: not worth building. Tier 1 is CPU-bound (gate logs: 8-11 busy threads of 16 even under load), and `every binary at once` was measured not to help (testing.md). The periodic tail (osis-cli `localhost::` waiting on sockets, osis-crdt's single-threaded `_large` tests) costs minutes, not the hours that 54,000 CPU-s do. Cutting the CPU through G1-G7 removes the need.

## The gate lock
Five recent gate logs: `cargo test --workspace` (build plus tests) is 75-90% of the wall at 8-11 CPU-s per second, the sim sweep 8-14 per second; clippy, unification, deny, schema check and the kit `cargo check` take 30-100 s at 1-3 cores. Overlapping all-core steps gain nothing (two gates each took twice as long), so locking those costs nothing. CPU sampling was not done: load was 85-96 throughout this study. Recommendation: keep a lock, but only around the all-core steps (`cargo test --workspace` and the sim sweep). Docs-only and GUI-only gates take no lock: today a 5-second docs gate waits behind a 10-minute core gate.

## Migration order
1. Gate lock narrowed (small, tools only).
2. TLA: delete Roles.tla, shrink Depth0 and the studies, `run.sh <module>`.
3. Sim: delete seed-1 duplicates and seed-named tests.
4. Pinned seeds in osis-node and osis-engine: example or delete (pinned-seeds-go).
5. G1 with oracles-observable P1-P4 and the retention steps; delete the 23 configs and the scripted alike tests it covers. The biggest win: about 40% of node tier 1 and most of the periodic order CPU.
6. G2, G3, G5 (each a single-crate task); G6 inside the ephemeral redesign.
7. Derived reviewer selection replaces testing.md's per-branch list; testing.md and coordination.md rewritten to this organization.
