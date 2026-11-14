# Test design
> Summary: Decided (Tess): one property test per stated property per component, examples and minimal reproducers beside it, sizes as a knob, selection derived from what a branch touched. The kinds of test, the rules every test change follows, and the open test-system work (ephemeral property, the default-test slow tail, small items). What runs today: notes/testing.md.

## Principle
Each component states its few properties (crdt: the join equals the model's lawful join; engine: what a node reads is a function of the commits it holds; perm: the incremental walk equals the walk from scratch and the walk equals roles-model; rotation: no departed holder reads later content, every holder ends reading everything; sync: everything settles and must-hold bodies reach a peer that keeps them). Each property has exactly one randomized test with an oracle (a model or the from-scratch path) that compares what users observe: osis-crdt `tests_model::crdt_equals_model` (notes/crdt.md Tests), osis-engine `order::held_set_decides` (notes/test-properties.md Held-set property), `Engine::check_index` and osis-perm `incremental::incremental_equals_from_scratch` (incremental equals from scratch), osis-engine `rotation::tests_property` (Rotation property), the sim sweeps (sync). A rule that needs a picture gets a small hand-written example. A test that names no property or rule goes.

| kind | what | size | runs |
|---|---|---|---|
| example | one spec rule or one minimal reproducer; steps in the body, no generator seed | under 1 s | every gate |
| property | one generator, one oracle, one function with a size knob | small in the gate, large in release checks | gate (selected); release |
| model | crdt-model, roles-model, held-model, TLA, with their own self-checks | small | when the model or its spec sections change |
| system | the sim: what no single engine can show (sync liveness, what peers keep, state bound) | every scenario at small size in the gate; large before a release | gate; release |
| timing, fuzz | release timing, libFuzzer | by hand | by hand |

Rules for every test change:
- Sizes are one function with a knob, never `_small`/`_large` twins of separate code; only the ignored sizes read `OSIS_*` ranges, and an override prints its range.
- Oracles compare observables: reads, rosters, promised history (`history()` within kept history), errors. Best-effort APIs (undo availability, `commits()`, `changed()`, `Change.origin`) are never compared across nodes. An excuse comes from the generated history, never from the node under test; exchanges between nodes run through real sync.
- A generator does not steer around a known difference; a failure is a design question.
- Before deleting a harness, every open issue whose replay uses it gets a minimal example (`#[ignore] repro_*` naming the issue) or a replay that survives the change.
- A change that removes or adds tests updates notes/testing.md and measures the default-test CPU-s of the touched binaries before and after (instruction counts, notes/testing.md Default-test cost).
- Only less work shortens the default tests: running binaries in parallel was measured not to help (notes/testing.md Default-test cost).

## Open work
**Ephemeral property**, inside the ephemeral redesign, not before: one node-level property (holders sharing peers that are not lossy read alike, caps respected); the sim scenarios for liveness only. It replaces `random_window_{converges,inflight,one_capped_host}`, `random_churn_converges`, `ephemeral_reverts_{within_rights,with_restarts}`, the three `memory_random_*` and `many_authors_under_a_peers_rates_by_hand` (12 min in dev; rates become a counted-work check), and the pinned seed lists inside their default-test runs.

**Default-test slow tail.** Measure each binary's tests alone (notes/testing.md Default-test cost) and shrink, merge, move or delete every test over about 1 s. Known: osis `port_clients::client_session_differential_against_grants`, node `shred_sync::purged_synced_body_crash_safe` (forensic attack per crash point), `wrap_poison::useless_*`, proto `slow_link::bulk_over_slow_link`, chat `flows::new_node_of_a_participant_sees_history`, `encodings::big_list_insert_fits_blobs` (8 MiB), host `ephemeral_churn_keeps_durable_cursors`, base `decode_peak_within_the_bound`, `write_ops::commit_equals_single_op_commits`, `tied::*`, `inbox_life::burst_of_grants_is_not_cleared_spec_sync_5`. Levers that worked: fewer, larger elements where a size threshold is the point; a config knob for a batch size; one clock jump past a lifetime; cpuprof before guessing; a shared starting network copied per test (notes/test-harnesses.md Copied worlds); rules tested at the engine or perm layer, a full `Net` only where sync is the point. The largest share is node-sync pass cost, not test size (issues/derived-state-recomputed.md).

**Paged property cost**: `paged_apply_matches_whole` seeds take 90-200 CPU-s each (ingest with its purge-on-replace snapshots about 30%, stored-state reloads after every step about 20%, judging about 4%); the goal is the slowest large seed under a minute.

**Small items**:
- A deterministic test of `close` on `Runtime::Tokio` (notes/api.md Handle and lifecycle: after `close` returns no driver poll touches a timer of a shut-down runtime). The one race test catches a removed `net::wait_ended` about a third of runs; `num_alive_tasks() == 0` after `close` is wrong (the task is released after the guard drops). Needs a seam: a hook holding the driver inside an engine call while `close` runs, released after shutdown began.
- Judgment vectors still missing: linked header lists (an aspect list past `CHUNK_THRESHOLD`, about 300 KB of hex) and the secrets-side rotation scenarios (core/test/vectors/README.md).
- The `expired_by_now` excuse spares every read on an aspect a commit expired by the history's end lists, in every order, though most such commits join alike (value-less) wherever they arrive. Tighter needs the node's judgment (which parts were missing when the commit arrived past its expiry or was purged) or a model of validity and judgeability per arrival; a history-only readiness rule misses the routes through validity (a part dropped while invalid, valid again, then past its expiry or purged before its refetch). The value-less join itself is checked by held-model on each node's own held set and by `expired_late_part_joins_valueless_spec_crdt_4_7`.
- held-model's comparison leaves out every aspect when a role commit carries parts outside the model (notes/test-properties.md, held-model comparison): a carve-out to close by modelling those role commits.
