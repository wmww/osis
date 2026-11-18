# Test and gate time
> Summary: Targets (Tess): default tests 4x faster without losing coverage that matters (a test should cost milliseconds), and the whole gate in 5 minutes on ostrich, reached by fixing perf, not shrinking sizes. Both are about 2-3x over. Most of the cost is the engine's per-change work under every test and osis-sync's per-delivery settles; this lists where it goes, the levers left and the patterns behind them.
> Priority: normal
> Tags: tests, performance, sync, engine

The reference graph rebuild required fewer and faster default tests than its baseline (5b4faadfa: 3,493 default tests, 7,030 G instructions, 2,372 CPU-s; `~/osis-refgraph-baseline/pertest`). Now 3,131 tests, about 7,965 G (the last full profile, 8,233 G and 2,648 CPU-s, less 268 G of `deletes` tests moved to cheaper worlds; notes/test-harnesses.md, Default-test cost): 13% over it in instructions. Of the 904 G over the reference graph's end profile, 582 G is 74 new tests (`holding::a_section_of_a_thing_not_held_stays_sealed_spec_sync_judgement_1` alone 348 G; `growth::record_blobs_at_a_store_stay_flat` 55, `deletes::strips_of_two_parts_by_nodes_apart_meet_at_a_node_reading_neither` 43) and 372 G growth of existing ones (5%: the differential 175 to 198 G, `order::held_set_decides` 257 to 275, every 4-node `deletes`/`growth` world 4-5 G each). Each new default test needs a cut beside it. The figures below predate the rebuild where they name the old differential.

## Where it goes now (pertest, per test process)
- Engine `it` 2,010 G: `order::held_set_decides` 261 G (its default covering set: each emphasis once), `tree_ends_are_fresh_deliveries` 36, `judgment_vectors` 61, the paged write tests 38-44 each (a restart per step, each an engine drop's index check over a 20,000-char history). Order tests grew 3-5x since the baseline (`reopens_alike` about 40% of a small one: a reload after every ingest).
- osis-sync `it` 1,810 G: the differential 161 G (6 seeds), the sims 32-68 G each, the forensic purge test 118 G (an attack per device is most of it), `deletes` 314 G over 13 tests: the forensic test 88 G (two attacks), the two tests needing a second writer about 42 G each (the 4-node `world_of`: `introduce`'s 12 redeems over real sync, about 35 G per process), the rest 8-17 G on the shared 3-node `history::three`.
- Engine lib 1,710 G: rotation tests 2-4 G each, mostly their cached `synced`/`granted` fixtures; custody 73 G, `rotation_holds` 61 G (its coverage floor needs 8 seeds).
- The engine drop's index check (`Engine::check_index`, issues/index-check-rebuild-cost.md): about 12% of the engine tests.

## Budget
- Gate: 5 minutes wall but its lock wait (notes/time-limits.md, Limits, `gate`), about 4000 CPU-s on ostrich at its usual 85%; each stage's limit is its share (the hold 105 u: 241 s, 3795 CPU-s). Measured: the whole gate about 15 min (8000 CPU-s), the hold 11 min, every stage about 2x its share, builds after a rebase 7x. Other agents' unlocked builds take 25-35% of the box during the hold and count against its wall.
- Ostrich spends about 1.6x the CPU-s per u that fastbox-0 does (notes/time-limits.md, Investigations), so its u limits are tight by that factor until u is timed on real work.
- Default tests alone exceed the hold's budget even with properties and sim at zero.

## Where it goes
- Per binary (`tools/icount`): osis-sync `it` largest (1,541 G against notes/sync-test-harness.md's 1,200 G budget), osis-engine `it` 1,252 G, engine lib 588 G, osis `it` 321 G. Tests over 20 G were 59% of the total.
- osis-sync `it` (cpuprof): read's settle about a third (`judge::body`: `read_facts`, `may_log`), building differential worlds 17% (`introduce`: 620-760 deliveries, about 4,600 judgements per 3-node world), `Engine::follow` 12%, `follow_certificates` 8%, memo bookkeeping about a sixth.
- Costliest tests: the sync differential and sims (replaced by the rebuild), `order::held_set_decides` (218 G), the forensic attack in `shred::past_expiry_and_purge_alike` (brute force by design).
- Properties (engine, seeds from 0): the custody differential `engine_agrees_with_custody_model_large` 2,120 G instructions (about 730 CPU-s: deliveries' apply, validity re-judging, dating replaced parts; the engines' signing), `held_set_decides_exhaustive` 1,090 G, `_plain` 875 G (its clocked orders, held-model after every ingest, a quarter), `rotation_holds_large` 640 G; perm's `incremental_equals_from_scratch_large` 293 CPU-s, `epochs_model_agrees_large` about 50. The engine selection is about 1,920 CPU-s against the properties share of 1,219.
- Builds after a rebase: main moving under a low crate rebuilds every dependent's test binaries (5-17x the `build` share); even a warm comment-only change in osis-base costs 330-390 CPU-s. `gate.gui-tests` compiles kit, app and masonry test binaries inside its stage; prebuilding them in `build` would put the cost where its share counts it.

## Levers left, biggest first
1. **A body's facts derived again per write on its aspect**: a part's date reads the aspect's state row, own covers read the author's newest own replace: O(n) per write. Narrow by stamping dates by the positions read (issues/derived-state-recomputed.md step 4) and checking own covers against the first two covering own replaces after the body.
2. **osis-sync per-delivery work**: a settle of every module per delivery; `may_log`'s `held_blobs` reads the store per judgement; `follow_certificates` at every follow.
3. **Memos re-run on unchanged answers**: `Core::horizon` and `may_rotate` read a component's whole timeline (`Read::Whole`) though their answers rarely change; read the edges walked instead. `body_facts` tries every snapshot ever held of an aspect against each body. Absent rows at a bucket stamp: issues/absent-stamp-fanout.md.
4. **`check_index` has no incremental form** (22% of osis-engine `it`, 10-14% of the engine properties, a quarter of `covered_drops_move_nothing_large`): cheaper loads are the lever, and they are the product's open (issues/long-aspect-cost.md). Its sampling is a Tess call.
5. `rotation_holds`, `deep_departure_holds`: `LocalPeer::sync_all` builds every package of a sender again whenever its engine moved (`packages_hashed`; with each package's encode and body walk, 35-45% of each): a package kept per commit while its record, blobs and lists stand is the lever. `incremental_equals_from_scratch_large` and perm `incremental::late_writes_across_kept_states`: oracles that replay from scratch per query.
6. Allocation: `Value` trees for epochs and schema reads, fragment clones where a join could consume its side, `kdf_key` formatting its purpose per call.

Rejected: `opt-level` 2 for the workspace (3-10%); fake or memoized crypto in tests (debug and release differ, every forgery test must opt out).

## Patterns
- **A flip-prone input read before the answer needs it**: read it last, on the paths whose answer depends on it; a small map read whole where one key is asked: index it by what is asked.
- **Derived values whose inputs move far more often than their answers**: keep them as `Cutoff` rows or narrow their reads (n readers of an aggregate over n inputs record O(n²) reads per change).
- **Work done twice in one judgement**: one facade value asked from several calls.
- **Worlds built from nothing per case**: copy them (notes/test-harnesses.md, Copied worlds); left: tests that close and reopen a node.
- **Width**: a covering set by default, full width through `testenv::large_n` and `_large` twins.
- **Real time waited out** in osis real-runtime tests (300 ms to 2 s timeouts in `runtime.rs`, `port.rs`); quadratic helpers (`apply::keys::tests::spread`).

## Method
Per test: `tools/pertest.py` (`top`, `compare`). Whole binaries: `tools/icount <bin> -q`, under `tools/heavy`. Profile: `tools/cpuprof OUT <bin> -q`, or callgrind. Why a judgement re-ran: `osis_base::costs::take()` around the step, read the `"<effects> <- <cause>"` counts (notes/engine.md, Why a key went due). CPU seconds move 20-40% between identical runs: compare instructions.
