# Test design
> Summary: Decided (Tess): one property test per stated property per component, examples and minimal reproducers beside it, sizes as a knob, selection derived from what a branch touched. The kinds of test, the rules every test change follows, what has found bugs, and the open test-system work. What runs when: notes/testing.md.

## Principle
Each component states its few properties (crdt: the join equals the model's lawful join; engine: what a node reads is a function of the commits it holds; perm: the incremental walk equals the walk from scratch and the walk equals roles-model; rotation: no departed holder reads later content, every holder ends reading everything; sync: everything settles and must-hold bodies reach a peer that keeps them). A rule that needs a picture gets a small hand-written example. A test that names no property or rule goes.

| kind | what | size | runs |
|---|---|---|---|
| example | one spec rule or one minimal reproducer; steps in the body, no generator seed | under 1 s | every gate |
| property | one generator, one oracle, one function with a size knob | small in the gate, large in release checks | gate (selected); release |
| model | crdt-model, roles-model, held-model, TLA, with their own self-checks | small | when the model or its spec sections change |
| system | the sim: what no single engine can show (sync liveness, what peers keep, state bound) | small in the gate; large before a release | gate; release |
| timing, fuzz | release timing, libFuzzer | by hand | by hand |

Rules for every test change:
- Sizes are one function with a knob, never `_small`/`_large` twins of separate code; only the ignored sizes read `OSIS_*` ranges, and an override prints its range.
- Oracles compare observables: reads, rosters, promised history (`history()` within kept history), errors. Best-effort APIs (undo availability, `commits()`, `changed()`, `Change.origin`) are never compared across nodes. An excuse comes from the generated history, never from the node under test; exchanges between nodes run through real sync.
- A generator does not steer around a known difference; a failure is a design question.
- A test asserting an absence (nothing reaches a node, nothing is read) first asserts the presence that makes it meaningful (the node entered, read before): absence tests passed vacuously when entry broke.
- A test comment citing the spec (a spec file, section and `;` pieces) must use text of that section for each `;` piece: policy's spec-anchor check refuses it otherwise.
- A disabled oracle answers "no model", never panics: a panic in a shared check breaks every test that plays.
- Before deleting a harness, every open issue whose replay uses it gets a minimal example (`#[ignore] repro_*` naming the issue) or a replay that survives the change.
- A change that removes or adds tests updates notes/testing.md where it describes them and compares the touched binaries' instruction counts before and after (notes/test-harnesses.md, Default-test cost). Only less work shortens the default tests.

## What finds bugs
Over about 200 merged tasks: reading in review, audits and simplification passes found about 180 product bugs; a new targeted test or differential for the change about 45; small-size properties about 25; larger ranges, release checks and wide sweeps 15-19; dogfooding about 10; the default tests 2; TLA one (a model extended in review by the action the code met and the model lacked); re-running already-run ranges about 4 (all regressions). Of about 38 classified seed-found bugs, about 14 were slips against a clear rule and about 24 had no rule yet (the fix wrote a new spec sentence, a weaker stated property or a redesign); they clustered (arrival order × retention × validity, epochs and rotation, ephemeral), and each chase ended with a study that found one root shape, never with more seeds. Hence (notes/coordination.md, Test budget): a job's sizes small, breadth only in release checks, never rerun old ranges, a study after the second seed fix in an area, and time spent on reviews that read, audits, dogfooding and targeted differentials.

osis-sync's module reviews (about 50 product bugs) split the same way. Reading against the spec and asking what a hostile peer or removed party controls found most, in four shapes: state a peer or time grows without bound, authority or information from unproven input, clock, restart and ordering, plain spec mismatch; seams between modules (a wrong key passed in, two logs' cursors mixed) the rest. Mutation found no product bug but about 8 tests passing with their rule removed.

- A check of one property never rides on a test ignored for another: an ignore takes every assertion in the test with it (`growth::flat_work` went unrun for days under a storage-leak ignore while work per round grew). Split the guard out first.

## Open work
**Ephemeral property**, inside the ephemeral redesign, not before: one node-level property (holders sharing peers that are not lossy read alike, caps respected); the sim scenarios for liveness only; rates as a counted-work check, never timed.

**Default-test slow tail.** Measure each binary's tests alone (notes/test-harnesses.md, Default-test cost) and shrink, merge, move or delete every test over about 1 s (about 4 G on ostrich). Over 15 G now: about 65 tests. Most of what is left is product cost, not test size: osis `commits::changes_on_as_many_things_*` (98 G, over half following certificates at minting: `follow_certificates`, `minting_evidence`); osis-sync growth's n-against-10n checks (`rotations_keep_keysets_flat_*` 40 G, `card_rewrites_grow_nothing_*` 27 G, each rotation or move a full sync round: issues/read-rejudges-per-delivery.md); `read::a_start_after_a_session_*` and `idle::` (mostly `history::shared(10)`, a fixture a gate pays once per process); hand-built six-node rotation scenarios (engine lib `rotation::tests::raise_name_over_older_raise_resealed_*`, 25 G). Base `decode_peak_within_the_bound` (16 G) keeps its 2 MiB input per shape, so a 64 MiB malloc arena step stays at 32 B per byte. The opening tests (`opens::`, the differential's sync-opens scripts) wait for the opening rewrite. Levers that worked: a size just past the threshold the test is about (a stored state pages past `PAGE_BYTES`, 3 KiB: notes/test-harnesses.md, Harness footguns), or small test pages (`PageParams::set_test`) where wire pages are the point; n of 1 and 10 where the check is exact equality; fewer, larger elements where a size threshold is the point; a config knob for a batch size; one clock jump past a lifetime; cpuprof before guessing; a shared starting world copied per test (notes/test-harnesses.md, Copied worlds); rules tested at the engine or perm layer or through a sync module's plain-value functions, a full world only where crossing modules is the point (notes/sync-test-harness.md).

**Paged property cost**: `paged_apply_matches_whole_plain` seeds take 90-200 CPU-s each (ingest with its purge-on-replace snapshots about 30%, stored-state reloads after every step about 20%); the goal is the slowest large seed under a minute.

**Small items**:
- A memo probe showing, per followed key, which containers its held reads come from (finding what a commit keeps in memory took a hand-written dump).
- A note on `growth::one_and_ten`/`round_work`: its counters reset per round (`costs::take`), so a `take` around `grant_rounds` reads only the last round and the settle tail.
- A `LocalPeer` helper that follows held grant signals as the sync layer does, so a cli or sync failure that needs a followed signal moves to an engine test cheaply. Built on the entries design (spec/sync-ids.md §3): a followed signal's holder gets into S by its entry, so a helper on notices would follow what that design deletes.
- A deterministic test of `close` on `Runtime::Tokio` (notes/api.md Handle and lifecycle: after `close` returns no driver poll touches a timer of a shut-down runtime). The one test, osis `runtime::close_then_runtime_shutdown_polls_no_dead_timer`, is a by-hand race caught about a third of runs; `num_alive_tasks() == 0` after `close` is wrong (the task is released after the guard drops). Needs a seam: a hook holding the driver inside an engine call while `close` runs, released after shutdown began.
- Judgment vectors still missing: linked header lists (an aspect list past `CHUNK_THRESHOLD`) and the secrets-side rotation scenarios (core/test/vectors/README.md).
- held-model's comparison leaves out every aspect when a role commit carries parts outside the model (notes/test-properties.md, held-model comparison): a carve-out to close by modelling those role commits.
