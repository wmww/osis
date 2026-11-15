# Tests cost about a hundred times what they should
> Summary: Target (Tess): default tests 4x faster without losing coverage that matters; a test should cost milliseconds. On the rebuilt sync the default tests run about 9,400 G instructions alone (each test its own process); osis-sync's `it` is the largest binary (1,683 G in one process against notes/sync-test-harness.md's 1,200 G budget). Left, biggest first: a body's facts derived again per write on its aspect, osis-sync's differential worlds and per-delivery settles, memos without early cutoff over whole-timeline reads, the costliest engine tests; the patterns behind them.
> Priority: normal
> Tags: tests, performance, sync, engine

## Where the cost is
- Per test (`tools/pertest.py`, 3,251 tests, 9,379 G, before the body-facts rows and later rounds): osis-sync `it` 4,996, osis-engine `it` 1,414, engine lib 1,042, osis `it` 1,004, held-model 241, crdt lib 231, perm 179, the rest 272. Tests over 20 G were 59% of it (66 tests), under 1 G 5% (2,399).
- Whole binaries now (`tools/icount BIN -q`): osis-sync `it` 1,683 G, osis-engine `it` 1,252 G, engine lib 588 G, osis `it` 321 G. Default-tests stage about 2,420 CPU-s against its 1,610 limit (notes/time-limits.md).
- Costliest single tests: `convergence::histories_converge` and `clean_histories_converge` (20 seeds each), `order::held_set_decides`, `sims::lost_and_repeated_messages` (178 G, six seeds), osis `tracking::dispatch_counts_matched_listeners_at_n_and_10n`.
- osis-sync `it` (cpuprof, inclusive): read's settle about a third to a half (`judge::body`: `read_facts`, `may_log`), the differential worlds' builds 16% (`introduce` 13%), `Engine::follow` 12%, `follow_certificates` 8%, memo bookkeeping (stamp reads, frames, `Effects` index) about a sixth, restarts in place a tenth. A 40-step faulted history plays for about 11 G; a 3-node differential world costs about as much to build.
- `introduce` (the 3-node world): about 800 deliveries (6 directional pairs, about 130 frames each: streams, fetches, Shared) and 4,630 judgements, twice a clean 40-step history's. A cheaper world needs fewer deliveries or cheaper settles, not sharing: each seed's world must draw its own IDs. A no-op `Engine::follow` is cheap (skipping it when nothing was written saved 1.6%); follow's cost is refreshes that do work and per-query refreshes (`sync_held`, `certified`: about 28 `follow_rows` per delivery).
- In a lossy play what still moves with connections (cause counts, seed 2 faulted): `read: toward` and `inbox: held` keys new per connection (612 and 708 of 1,260 and 752), `life: lost access` and `role duty owed` moved by `timelines: whole` (190 each in a clean 337-delivery history), `status: stranded` and `life: heard out` per connection stamp.
- Memo debug comparisons (total minus a run with `Checks::hit` false): engine lib 0.9%, osis `it` 6.3%.

## Left, by size
1. **A body's facts are derived again per body whose reads moved.** The judgement moves only with its facts (`Engine::read_facts`, a row), but every write on an aspect re-derives the facts of each body on it: a part's date reads the aspect's state row (`deaths` at its positions), and own covers read the author's newest own replace (`part_covered` checks the newest two, a new `covered` key per body per write). O(1) reads per body, O(n) per write. Narrowing: dates stamped by the positions read (issues/derived-state-recomputed.md step 4); own covers checked against the first two covering own replaces after the body (spec/commits.md §5 Own replaces says any two), stable as writes land.
2. **osis-sync's differential and simulations**: a fresh world per seed, then per delivery a settle of every module. `may_log`'s `held_blobs` reads the sync store per judgement; `Effects::due`'s log reads 10%; `follow_certificates` at every follow.
3. **Memos re-run on answers that did not change** (engine, `core/base/src/memo`). Of 6,070 judgements in a world build (clean seed 9), 1,844 were moved by `Core::horizon` (reached from `Engine::wrap_blocked`) and 1,066 by `may_rotate` (`rotation/departures.rs`): both read a thing's whole timeline component (`Timelines::get`, `Read::Whole`), which any held role input in the component moves, though their answers (a time bound, a set of roles) rarely change.
   - `Memo` has no early cutoff: a memo recomputed to the same answer still moves every key that read it (`memo::depend` passes the memo's reads on). `Cutoff` rows stop it where used (`wrap_blocked`, body facts and fates; notes/engine.md, General early cutoff).
   - `Core::horizon` reads `Whole` of the actor's and the writer's components to find the next `until`; reading the edges it walks (`Into` per target, as `roles_on` does) would move it only with them.
   - Absent rows read at a bucket stamp (`store: local rows`, `catalog kind`) move a further fifth of a play's judgements: issues/absent-stamp-fanout.md.
   - `body_facts_now` tries every snapshot ever held of each aspect (`sync/bodies.rs`, `ix.snapshots`) against the body: one write synced after 3 earlier writes joins 20 snapshot pairs, after 30 writes 200.
   - An inbox blob no key here opens (another actor's inbox this node reads, as `introduce`'s profiles give) is tried again at each move of that actor's timeline.
4. **`order::held_set_decides`** (399 G alone, the costliest engine test): ingest about half, held-model compares a fifth, `check_index` a sixth; every order is ingested from the setup (Properties, below).
5. **`check_index` has no exact incremental form** (22% of osis-engine `it` inclusive): its halves are two loads from scratch; cheaper loads are the lever, and they are the product's open.
6. **The forensic attack's tries**: candidates (130-185K per attack) times each unopened section and blob; each candidate prepared again per attack.
7. `rotation_holds_spec_crypto_4` (46 G, 8 seeds; `tally` needs 8): ingest 50%, 95% of its ingests re-deliveries of known commits, each fully decoded before `late_parts` finds nothing new.
8. Engine lib, alone (G): `rotation_holds` 38, `seq_placement_differential_after_reset` 31 (its oracles `vis_whole` and `place_whole_pass` 40%), `arrival_order_holds_alike` 19, `seq_cold_edits_keep_placement` 19, `per_entry_secrets_ingestion_equals_whole_state` 14, `every_box_is_recorded_beside_it` 13. osis-perm `incremental::late_writes_across_kept_states` 37 G: 98% its oracle `check`, which asks every role, `roles_on` and three `delta_valid` before each of about 200 applied writes for six nodes of both timelines, ten times; each such past query is a checkpoint replay and a graph walk.
9. Allocation (glibc's allocator, the production one): `Value` trees for epochs, histories and schema reads; B-tree nodes of fragments; fragment clones where a join consumes its side; `kdf_key` formats `"osis v1 " + purpose` per call.

Options on the test side, each a coverage trade (not taken): fewer default seeds (each faulted seed about 11 G plus its world); fewer distinct differential worlds (a history on world `seed % k`: fewer drawn IDs and tie-breaks, the fixture guard in notes/sync-test-harness.md); a cheaper `introduce` (contacts by cards).

Rejected levers: `opt-level` 2 for the workspace (3-10% for a full rebuild). Fake crypto in tests: a debug-only switch (every forgery and wrong-key test must opt out), a verification memo in osis-crypto (debug and release differ), dependencies without debug assertions (loses their assertions), precomputed keys (keygen under 1%).

## Patterns
- **A flip-prone input read before the answer needs it.** A key that reads something moving often (a source of S up now, S's source map) on every path moves with it even where its answer cannot: read such an input last, on the paths whose answer depends on it (sync read's `pullable`, status's sources). A small map read whole where one key is asked is the same pattern (`followed_links` before `FollowedLinks`): index it by what is asked.
- **Derived values whose inputs move far more often than their answers.** A memo copies its inner reads into its readers (notes/engine.md, Derived values), so an `Effects` follower re-runs whenever anything a memo it asked read moved. Where a value is read by many followers and its inputs are coarse (a component's whole timeline, an aspect's whole commit set), keep it as a `Cutoff` row or narrow its reads. The copy costs more than the rerun: n readers of an aggregate over n inputs record O(n²) reads per change. Next candidates by count: `life`'s lost-access and role-duty keys (moved by `timelines: whole`).
- **Work done twice in one judgement**: the same facade value asked from several calls (`sync_body_now`, `sync_bodies`, `covered` are memos for it); `held_blobs` per judgement.
- **Every test builds its world from nothing, and many build it once per case.** Exact in-memory copies exist for `LocalPeer`, the sim `World` and osis-sync's fixtures and differential worlds (notes/test-harnesses.md, notes/sync-test-harness.md). Left: tests that close and reopen a node from a store the setup kept; the order tree walk past the setup.
- **Width**: a covering set by default (named regressions, each item first and last, the smallest sizes where the counted quantity is not trivial, just past the threshold); the full width through `testenv::large_n` and `_large` twins. Left: `order::held_set_decides`' quick size, crdt variant loops other than `part_judges`, engine scale tests at 20/200 and 30/300, osis tests writing past `COMMIT_PAGE` (256) commits on one aspect.
- **Real time waited out** (osis real-runtime tests): must-expire timeouts of 300 ms to 2 s (`runtime.rs`, `port.rs`).
- **Quadratic helpers**: `apply::keys::tests::spread` sends every commit to every peer again.

## Properties and the sweep
- `order::held_set_decides` runs quick and quick-exhaustive in the default tests, plain and exhaustive as properties. Every order of a held set ingests the setup again in a fresh account; left, without losing an order: walk the permutation tree depth first, copying the node at each prefix past the setup (`Peer::copy`), so a prefix is ingested once.
- Fixed-seed properties run in every gate (forged_parts, tombstone, unmerge_paged, crdt stream and paging, base proptests): the same run each time; only worth it when the branch touches what they reach.
- Seed counts stay; the time is to come from the work each seed does.

## Order of work
1. osis-sync's per-delivery work (Left 2) and the memo re-runs (Left 3).
2. The facts' reads narrowed (Left 1).
3. The order tree walk (Properties).
4. Width, file by file.

## Method
Per-test instructions: `tools/pertest.py` (every default test alone under `tools/icount`; `top`, `compare`). Whole binaries: `tools/icount <bin> -q` from its package dir, every binary through `tools/heavy`. Where a binary's time goes: `tools/cpuprof OUT <bin> -q`. Why a judgement re-ran: take `costs` in a test (`osis_base::costs::take()` before, again after) and read the `"<effects> <- <cause>"` counts (notes/engine.md, Why a key went due). CPU seconds move 20-40% between identical runs (load, SMT): compare by `tools/icount`.
