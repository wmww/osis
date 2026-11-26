# Scale, budgets and performance
> Summary: How scaling is checked (work counted at n and 10n in default tests, never timed) and the table of scale checks per property; size budgets and benches (core/bench); by-hand memory checks; the performance targets (Tess delegated).

## Scale checks
Default tests against spec/requirements.md (Scale): each runs one operation at a size n and at 10n and counts its work, never time (notes/principles.md). `flat` (at 10n at most 2x + 2 the count at n) is O(change); `linear` (at most 15x + 15) allows O(n) or O(n log n), never quadratic. A failing count names the phase and both counts; a known violation is an ignored `repro_*` naming its issue.
- Store reads include debug-only checks, so tests count reads by spans and use the store for rows and bytes written; rows are the sharper count (each write's 20-40 KB of fixed bytes hides a per-commit term under 100 B).
- A collection of two or more elements pages above 3 KB of its own (notes/engine-paged.md): a check keeps n and 10n on one side of that (or both paged), or a count that is zero unpaged fails `linear` at 10n.
- Engine checks (core/engine/tests/it/scale.rs) run on `osis_engine::local_peer`: a few peers, packages delivered by hand, a peer's `restart` for a new session. Their wall time is mostly debug checks (O(state) each, uncounted); cut a check's cost by its n, never by its 10x.

Engine checks live in core/engine/tests/it/scale.rs (`scale::*`), one per property, named for its shape (`_is_flat`, `_is_linear`, `_spec_*` for the rule): map and set edits, text by index, roster removal (a rotation commit about 2.9 KB per remaining holder, budget 3000 B), purge on replace, late deltas and deaths, validity flips, snapshots, addenda, the path wait, purge requests, grants and open, long aspects, role history, history settings, expiry, chunk drops, an account's pairing, node removal and per-unit evidence (`account_nodes`: n and 10n nodes; notes/thing-cost.md, Accounts at n and 10n nodes). Elsewhere:

| property | test |
|---|---|
| `covered` per body | engine `decoded::tests::cover_judgments_read_the_bodys_pages_spec_commits_5` |
| large value edits | engine `write::large_edit_reuses_chunks_spec_sync_1` |
| the walk | perm `paths::counts` (notes/perm-paths.md, Cost shapes; left: issues/perm-eval-cost.md) |
| map edit in store tables | store `paged::table_edit_is_flat` |
| paged snapshot rewrite | bench `scale::big_map_snapshot_rewrite` |
| held-writes edit below a deep path | crdt `row_pages::tests::deep_edit_is_flat` |
| text joins at the crdt | crdt `small_joins_follow_cached_placement_spec_6` |
| large value read | osis `scale::large_value_read_work_is_linear` |
| one commit on many things | osis `commits::changes_on_as_many_things_spec_requirements_decentralization` |

`scale::text_edits_are_flat` is by hand (minutes in a debug build).

## Sync scale checks
osis-sync's checks (core/sync/tests/it) count module work (`Work` counters, store rows) at n and 10n: `driver::dial_work_follows_change_spec_sync_opens_1`; `opens::a_credential_change_costs_the_same_at_n_and_10n_spec_sync_opens_6`, `a_credential_change_costs_per_connection_not_per_sync_id_spec_sync_opens_6`, `a_reconnect_costs_the_same_at_n_and_10n_spec_sync_opens_3`; `read::work_follows_change`, `work_follows_sources`; `status::work_follows_change`; `store::log_reads_cost_what_they_return_spec_sync_streams_3`, `removal_and_expiry_cost_alike_at_any_size_spec_sync_ids_5`; `streams::push_work_follows_the_events_not_the_log_spec_sync_streams_4`, `a_reconnect_after_a_restart_costs_the_same_at_10n_spec_sync_streams_4`.

**Checks to restore**: sync-shaped counts with no test yet (issues/sync-tests-owed.md; drop an item when its test lands):
- a write's judgement flat in history at writer and reader, whatever the sources;
- a role change judging only the sync IDs it touches;
- a first sync by a node keeping S unread linear, nothing examined again;
- a walk past missed rotations and filter arrivals flat in steps; one Behind item per rotation crossed;
- role entries growing with churn, not with the members each change boxes;
- cover work per write flat;
- many sync IDs, idle ones costing nothing; a timed wait judging its sync ID alone;
- a chat post's cost flat in history and members; a joiner reading each pending commit a few times;
- a node keeping S unread writing a 64-entry log or delete batch in a few durable writes at any size.

## Size budgets and benches (core/bench)
- Budgets: `core/bench/tests/it/budgets.rs`, each `#[test] fn budget_<name>` (`#[ignore = "by hand: ..."]` when slow) calling `assert_budget(name, actual, budget)` with its source's number plus about 10%, citing the source; public APIs only. Live: `budget_creation_record`, `budget_minimal_commit`, `budget_text_snapshot_ratio` (notes/crdt.md, Text size). Pending: role boxes about 1.2 KB per holder and role (notes/crypto.md); revoke frontier after a long-held role.
- Benches: `core/bench/benches/<crate>.rs` with `harness = false`, calling `osis_bench::bench(name, bytes, f)` (median ns/iter and MB/s; `OSIS_BENCH_MS` sets the sample time). `cargo bench`, by hand, release, not gated. No criterion: a 40-line harness keeps the tree small.

## Memory checks
By hand, release, each alone (they read the resident set): run with `GLIBC_TUNABLES=glibc.malloc.trim_threshold=0:glibc.malloc.mmap_threshold=65536`, or one child process per step as `big_map_apply_memory` and crdt `stream_memory_big_map` do.
- engine `memory::eph_decoded_memory` (`OSIS_EPH_SHAPE` tiny/large/aspects): RSS per encoded byte held against the charge (`Engine::memory_charge`; issues/eph-node-cost-bounds.md); with `OSIS_EPH_ROOM=16777216` a 3.8 MB commit of 200k tiny entries is refused with nothing decoded (`Engine::ingest_memory`). `memory::eph_leftover_memory`: expired ephemeral deltas held as leftovers until the writer's snapshot covers them.
- engine `memory::big_map_apply_memory` (`OSIS_SCALE_N`, default 10^6 in release): peaks of writing an N-key map commit, applying it, applying the snapshot alone, judging it covered and dropping it, each in a child process (the writer fails Scale: issues/durable-decode-bound.md).
- osis `scale::multi_gb_value_streams` (`OSIS_LARGE_MIB`): peak RSS growth reading a value as a `ValueStream` (bound 64 MB); the write holds the value whole (issues/api-deferred.md).

## Performance budgets
Coordinator-owned targets (Tess delegated; prefer simple, verifiable code that meets them over faster intricate code). At 10^4 commits per aspect and 10^4 things per closure, release, a quiet box: a single local write, read or received commit under 50 ms; node open under 1 s; one sync step after one new write under 100 ms; a late or out-of-order commit under 500 ms (a whole replay of one aspect is acceptable here); rare events (revocation) under a few seconds. Work beyond these is not pursued without a realistic scenario missing them; issues that only chase speed below them are closed as within budget.
- A node keeping a sync ID unread (its own `Store`, redb and a file root, release, a laptop disk): 1 KiB entries at least 1000/s logged and 1000/s deleted in 64-entry batches; a single-entry log batch plus a single-entry delete batch under 20 ms (about 4 fsyncs).
