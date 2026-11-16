# Test and gate time
> Summary: Targets (Tess): default tests 4x faster without losing coverage that matters (a test should cost milliseconds), and the whole gate in 5 minutes on ostrich, reached by fixing perf, not shrinking sizes. Both are about 2-3x over. Most of the cost is the engine's per-change work under every test and osis-sync's per-delivery settles; this lists where it goes, the levers left and the patterns behind them.
> Priority: normal
> Tags: tests, performance, sync, engine

The reference graph rebuild (issues/reference-graph.md) replaces the sync differential and sim set and requires fewer and faster default tests than its baseline (5b4faadfa: 3,493 default tests, 7,030 G instructions, 2,372 CPU-s; `~/osis-refgraph-baseline/pertest`). Measure again after it before acting on the figures below, which predate it.

## Budget
- Gate: 5 minutes wall but its lock wait (notes/time-limits.md, Limits, `gate`), about 4000 CPU-s on ostrich at its usual 85%; each stage's limit is its share (the hold 105 u: 241 s, 3795 CPU-s). Measured: the whole gate about 15 min (8000 CPU-s), the hold 11 min, every stage about 2x its share, builds after a rebase 7x. Other agents' unlocked builds take 25-35% of the box during the hold and count against its wall.
- Ostrich spends about 1.6x the CPU-s per u that fastbox-0 does (notes/time-limits.md, Investigations), so its u limits are tight by that factor until u is timed on real work.
- Default tests alone exceed the hold's budget even with properties and sim at zero.

## Where it goes
- Per binary (`tools/icount`): osis-sync `it` largest (1,541 G against notes/sync-test-harness.md's 1,200 G budget), osis-engine `it` 1,252 G, engine lib 588 G, osis `it` 321 G. Tests over 20 G were 59% of the total.
- osis-sync `it` (cpuprof): read's settle about a third (`judge::body`: `read_facts`, `may_log`), building differential worlds 17% (`introduce`: 620-760 deliveries, about 4,600 judgements per 3-node world), `Engine::follow` 12%, `follow_certificates` 8%, memo bookkeeping about a sixth.
- Costliest tests: the sync differential and sims (replaced by the rebuild), `order::held_set_decides` (218 G), the forensic attack in `shred::past_expiry_and_purge_alike` (brute force by design).
- Properties: `held_set_decides_exhaustive` 705 CPU-s, `_plain` 408, `incremental_equals_from_scratch_large` 293, `rotation_holds_large` 228, `epochs_model_agrees_large` 194; the custody differential `engine_agrees_with_custody_model_large` about 75 s wall at small size (a candidate to split or slim).
- Builds after a rebase: main moving under a low crate rebuilds every dependent's test binaries (5-17x the `build` share); even a warm comment-only change in osis-base costs 330-390 CPU-s. `gate.gui-tests` compiles kit, app and masonry test binaries inside its stage; prebuilding them in `build` would put the cost where its share counts it.

## Levers left, biggest first
1. **A body's facts derived again per write on its aspect**: a part's date reads the aspect's state row, own covers read the author's newest own replace: O(n) per write. Narrow by stamping dates by the positions read (issues/derived-state-recomputed.md step 4) and checking own covers against the first two covering own replaces after the body.
2. **osis-sync per-delivery work**: a settle of every module per delivery; `may_log`'s `held_blobs` reads the store per judgement; `follow_certificates` at every follow.
3. **Memos re-run on unchanged answers**: `Core::horizon` and `may_rotate` read a component's whole timeline (`Read::Whole`) though their answers rarely change; read the edges walked instead. `body_facts` tries every snapshot ever held of an aspect against each body. Absent rows at a bucket stamp: issues/absent-stamp-fanout.md.
4. **`check_index` has no incremental form** (22% of osis-engine `it`): cheaper loads are the lever, and they are the product's open (issues/node-core-gaps.md). Its sampling in `held_set_decides_exhaustive` (about 120 CPU-s) is a Tess call.
5. `rotation_holds`: 95% of ingests re-deliver known commits, each fully decoded before `late_parts` finds nothing new. `incremental_equals_from_scratch_large` and perm `incremental::late_writes_across_kept_states`: oracles that replay from scratch per query.
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
