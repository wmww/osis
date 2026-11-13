# Scale, budgets and performance
> Summary: How scaling is checked (work counted at n and 10n in default tests, never timed) and the table of scale checks per property; size budgets and benches (core/bench); by-hand memory checks; the performance targets (Tess delegated).

## Scale checks
Default tests, against spec/requirements.md (Scale): each runs one operation at a size n and at 10n and counts its work, never time (notes/coordination.md, Design principles). `flat` (at 10n at most 2x + 2 the count at n) is O(change); `linear` (at most 15x + 15) allows O(n) or O(n log n), never quadratic. A failing count names the phase and both counts. A known violation is an ignored `repro_*` naming its issue.
- **What is counted**: engine cost spans (`osis_node::costs`: pages and placement blocks loaded and written, commits ingested, examined, re-judged, bodies rebuilt; paused inside debug-only checks), engine counters (`death_walks`, `replaced_reads`, `examined`), `osis_perm::commits_walked` and `entries_moved` (debug builds only: they panic in release), node-sync `PassStats`, store rows and bytes (`MemoryBackend::io`), byte sizes. Store reads include debug-only checks, so tests count reads by spans and use the store for rows and bytes written; rows are the sharper count (each write's 20-40 KB of fixed bytes hides a per-commit term under 100 B).
- A paged state needs 64 KiB (`PAGE_TARGET`), so paged checks use long values to stay small.

| property | test | counted |
|---|---|---|
| map entry edit, at the root and in a map entry | node `scale::map_edit_is_flat` (500 / 5000 entries of 200 B) | store bytes 30 / 40 KB; a new session's read of one key 2 pages, its first edit 3 loaded and 1 written |
| set ops by value | `scale::set_by_value_is_flat` (10^3 / 10^4) | each op in a new session: 1-3 pages loaded, 0-1 written |
| group membership change | `scale::group_change_is_flat` (4·10^3 / 4·10^4 items) | remove, add back, add new, each in a new session: 2-3 pages loaded, 1 written (the group index refreshed from the tids touched) |
| text by index | `scale::text_edits_are_flat` (by hand: 80k / 800k chars) | read of 100 chars 2-3 pages; insert, delete, edit, undo 3 loaded, 4-5 written; a move loads every placement block (issues/text-move-loads-placement.md, `repro_text_move_loads_placement`) |
| removal from a roster | `scale::roster_removal_is_linear` (20 / 200 writers) | rotation commit 2.76 KB per remaining holder (budget 3000 B past 4 KiB); one more `secrets.0` entry flat |
| purge on replace pays its state | `scale::purge_on_replace_pays_its_state` (200 / 2000 entries of 100 B) | store bytes per replacing edit linear (713 KB at 2000: 465 KB rows, 246 KB the snapshot's body blob); no history 43 / 32 KB |
| sync pass per write | `scale::sync_pass_is_flat` (20 / 200 commits) | writer 1-2 passes, bodies, entries; reader 1; no full pass |
| sync pass per body | `scale::aspect_pass_is_flat` (10 / 100 keys) | flat; a body killed judges every entry of its label (issues/kill-judges-label-entries.md, `repro_kill_judges_label_entries`) |
| role change across labels | `scale::role_change_judges_its_labels_only` | an unrelated edge judges nothing; a label's group edge re-judges that label alone |
| first sync by a peer that cannot read L | `scale::first_sync_is_linear` (30 / 300) | commits ingested, bodies and entries judged linear; nothing examined again |
| late deltas and deaths | `scale::late_delta_deaths_are_flat_spec_crdt_4_8` (30 / 300) | every span, death walks and replaced reads flat |
| judging every body of an aspect | `scale::judging_every_body_reads_each_once_spec_commits_5` | bodies read for deaths and replaced reads per judgment 1 / 1 (`HeldWrites`) |
| validity flip | `scale::validity_flip_is_linear_spec_permissions_5_2`, `invalid_arrival_is_flat_spec_crdt_4_6` | a flip rebuilds the aspect once, commits re-judged flat; an invalid arrival reads no other body |
| snapshots | `scale::snapshot_join_is_flat_spec_permissions_5_2`, `commits_after_their_snapshot_are_linear_spec_permissions_5_2`, `kept_snapshots_stay_within_their_window_spec_commits_5`, `dropped_snapshot_frontier_is_linear_spec_commits_5` | a snapshot join linear (O(state)), the next delta flat; snapshots held stay at the D window; a dropped snapshot costs about 35 B of frontier |
| addenda | `scale::addenda_rejudge_spec_permissions_5_2` | a member joining a holder re-judges nothing per commit; with an addendum held the thing is judged whole (linear) |
| purge requests | `scale::purge_rejudge_is_linear_in_requests_spec_permissions_6` | a join flat; a requester's fall and rise rebuild the aspect once |
| grant and open | `scale::grant_is_flat_in_content_commits` | a grant flat in content commits; open rebuilds nothing |
| one aspect, many kept writes (chat) | `scale::long_aspect_writes_are_flat` (40 / 400) | a write and its arrival flat; removing a writer linear |
| role history at a joiner | `scale::role_history_join_is_linear` | ingesting 30 / 300 edge writes linear; a grant, a removal and their arrival flat |
| `covered` per body | engine `decoded::tests::cover_judgments_read_the_bodys_pages_spec_commits_5` | past the first judgment each streams 2 pieces (skeleton and the body's page) at both sizes |
| perm evaluation | perm `scale::` (10^2 / 10^3 edge writes) | evaluate walks each commit once; saved walks restored walk nothing; late grants, demotion scopes, record leaves bounded; late writes re-judging their readers and evaluation with drops left: issues/perm-eval-cost.md (`repro_late_write_rejudges_flat`, `repro_evaluate_with_drops_linear`) |
| many labels, chat members | sim `scale::label_costs_do_not_grow_with_labels`, `idle_labels_pass_only_when_due`, `an_edge_ending_passes_its_quiet_label`, `a_timed_wait_passes_its_label_alone`, `a_burst_of_shares_costs_each_about_once`, `post_reads_nothing_per_member`, `add_judges_nothing_per_message`, `joiner_reads_each_pending_commit_few_times`; chat `flows::post_cost_flat_in_history` | 762 B uploaded per post after 10 and 100 messages |
| map edit in store tables | store `paged::table_edit_is_flat` (3000 / 30,000 keys) | 4 unit rows at both; one more B-tree level |
| paged snapshot rewrite | bench `scale::big_map_snapshot_rewrite` (10^4 / 10^5 keys) | one change writes 1 new page at both |
| text joins at the crdt | crdt `small_joins_follow_cached_placement_spec_6` (30 / 300 runs) | no whole pass; placement work about the square root (the block walk) |
| large value read | osis `scale::large_value_read_work_is_linear` (1 / 10 MiB) | each chunk fetched once, at most 320 KiB held |
| one commit on many things | osis `commits::commit_work_linear_in_things_spec_requirements_decentralization` (50 / 500 things) | every engine span and count plus perm's things reached by role walks (`osis_perm::roles_reached`, debug checks' walks included), for creating the things in one commit, a commit changing each, and its apply elsewhere: linear (`meta: parts indexed` 100 / 1000 per side, write's roles reached 106 / 1006) |
| host batches | host `file::host_batch_writes_do_not_grow_with_entries` (100 / 1000 entries) | 64-upload and 64-delete batches, a single upload and delete: 3, 3, 4 durable writes at both |
| large value edits | `write::large_edit_reuses_chunks_spec_sync_1`; sim `large_edits` | an edit of a 4 MiB value writes the changed chunks plus the root node |

## Size budgets and benches (core/bench)
- Budgets: `core/bench/tests/it/budgets.rs`, each `#[test] #[ignore] fn budget_<name>()` calling `assert_budget(name, actual, budget)` with its source's number plus about 10%, citing the source; public APIs only. Live: `budget_creation_record`, `budget_minimal_commit` (commit blob plaintext of a header plus one register delta: 288 B against about 300), `budget_text_snapshot_ratio` (a synthetic typist's text snapshot: 2.89x at 100 edits per commit, 6.73x at 10, against 3.5x and 7x; notes/crdt.md, Text size). Pending: role boxes about 1.2 KB per holder and role (notes/crypto.md); revoke frontier after a long-held role.
- Benches: `core/bench/benches/<crate>.rs` with `harness = false`, calling `osis_bench::bench(name, bytes, f)` (median ns/iter and MB/s; `OSIS_BENCH_MS` sets the sample time). `cargo bench`, by hand, release, not gated; record notable numbers in notes. No criterion: a 40-line harness keeps the tree small. A new external dependency needs its line in notes/architecture.md §5.

## Memory checks
By hand, release, each alone (they read the resident set): run with `GLIBC_TUNABLES=glibc.malloc.trim_threshold=0:glibc.malloc.mmap_threshold=65536`, or one child process per step as `big_map_apply_memory` and crdt `stream_memory_big_map` do.
- node `memory::eph_decoded_memory` (`OSIS_EPH_SHAPE` tiny/large/aspects): RSS per encoded byte held: tiny map entries 218x, 8 KB strings 1.6x, one small write per aspect 22x; the node cap's charge 0.95-1.6x of that RSS (issues/eph-node-cost-bounds.md); with `OSIS_EPH_ROOM=16777216` a 3.8 MB commit of 200k tiny entries is refused with nothing decoded. `memory::eph_leftover_memory`: expired ephemeral deltas held until a snapshot covers them.
- node `memory::big_map_apply_memory` (`OSIS_SCALE_N`, default 10^6): writing the commit 3.1 GB, a node holding the thing applying it 0.24 GB, a node applying the snapshot alone 0.35 GB (the writer fails Scale: issues/durable-decode-bound.md).
- osis `scale::multi_gb_value_streams` (`OSIS_LARGE_MIB`, store in a directory): peak RSS growth reading a value as a `ValueStream` (bound 64 MB); the write holds the value whole (issues/api-deferred.md).

## Performance budgets
Coordinator-owned targets (Tess delegated; prefer simple, verifiable code that meets them over faster intricate code). At 10^4 commits per aspect and 10^4 things per group, release, a quiet box: a single local write, read or received commit under 50 ms; node open under 1 s; one sync pass after one new write under 100 ms; a late or out-of-order commit under 500 ms (a whole replay of one aspect is acceptable here); rare events (revocation) under a few seconds. Work beyond these is not pursued without a realistic scenario missing them; issues that only chase speed below them are closed as within budget.
- Host (osis-host on its own `Store`, redb and a file root, release, a laptop disk): 1 KiB entries at least 1000/s uploaded and 1000/s deleted in 64-entry batches; a single-entry upload batch plus a single-entry delete batch under 20 ms (about 4 fsyncs). Counted in the default tests by the host batches row above.
