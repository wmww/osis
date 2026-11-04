# eph-lane: finish the review, then merge or discard
> Summary: branch `eph-lane` on origin (pushed as an exception, only for this handover): eph-unify step C, the ephemeral lane moved onto the durable sync path, +1851/-2304. Built and reviewed in part, no verdict, stopped for Tess's wind-down. Finish the review on any box, merge or discard, then delete the branch. Whole-commits 2b waits on this.
> Tags: ephemeral, node-sync, tests

## To do
1. `git fetch && wt claim` a worktree of `eph-lane`; rebase on main (read the result; main has moved; re-check spec/sync.md §6, §9).
2. A fresh reviewer (spawn per notes/coordination.md): the fixes in c0321fd1 were written by the last reviewer and include one new rule, so they have had no independent review. Then everything under Open and Unchecked below. Drop the WIP probe commit before merge, keeping `notes/eph-lane-probe.patch` out of main.
3. Decide: merge (progress line in notes/mvp-progress.md, gate as usual) or discard, recording why in issues/eph-unify.md. Churn seed 9130190 should be traced first: a real storm if users can hit it.
4. **Either way: `git push origin --delete eph-lane`, delete the local branch, delete this issue.** Tell whoever holds whole-commits 2b.

What the branch is meant to do: issues/eph-unify.md "Step C plan" and "Step C as built". Worries the review was asked to attack: nothing memory-class on disk; typing and presence stay fast (write to delivery is unchanged in rounds, writer cost about 5-7x, see below; judge if acceptable, or if a measured budget says no); durable not harmed by the capped-upload retry.

## Handover from the last reviewer, unedited
Tip f0bede39 (notes and the probe only, WIP) on c0321fd1 (review fixes, gated). Base: origin/main at 9a2db7e8 when last rebased; main may have moved.
My fixes are all in c0321fd1, about 80 lines plus tests, and include one new rule, so coordination.md asks for a fresh reviewer of them.

## Checked
- Gate: passed on c0321fd1 (189 s; 2839 tests, 0 failed; 5-seed sweep of 53 scenarios). 1286e568 changes notes only and was not gated.
- Oracles, 200 seeds from 9120000, branch as handed over: random_window x3, churn, both reverts: all green. That range missed the bug below.
- Oracles, 300 seeds from 9130000, build with fixes but before the rebase and before the last amend: random_window x3 and both reverts green; churn: 1 hung (9130190).
- That last amend restored the memory-only filter in `note_memory_synced`, so durable things out of every closure may now compact. Oracles were NOT rerun after it; only the gate covers it.
- Sim `ephemeral,ephemeral_capped` 30 seeds from 9130: 0 failed, same pre-amend build. Brief says "all ephemeral scenarios": I ran only these two names.
- `--ignored order::` default, same build: 16 passed, 1 failed (settled seed 7026, see Open).
- Main vs branch probe, one run each, low load, Net harness, 200 writes (0 and 400 durable items; measured before the last fixes):
  - Write to delivery: same, 2 rounds and 4 messages.
  - Messages per write 4.00 vs 6.85; bytes 927 vs 1060 (uploads plus a delete for almost every write).
  - Burst: 2.01 vs 5.01 messages per write; 476 vs 591-829 bytes.
  - Writer sync time per write 0.19-0.25 ms vs 1.2-1.4 ms; holder 0.72-0.96 vs 1.6-1.9 ms. About 5-7x at the writer. Slightly up with closure size, up to 400 items only. 2000 was not measured: that run exceeded 10 min on the branch and was stopped, cause unknown.
  - Disk: no store rows gained in the typing probe. Backend writes per write 1.0 (main) vs about 1.5, burst 0.5 vs 1.0: a flush trace on the branch showed nearly all are the `y/c` cursor row. Main's were not traced.
- Durable cap probe (cap_bytes 100 KB, 30 items of 30 KB): identical on main and branch: bytes, messages, delivery once room appears. One scenario only.

## Found and fixed (in c0321fd1)
1. Storm, destructive: a restarted node with an incomplete closure judged window bodies Outside and deleted them at the host while another writer re-uploaded them. random_window seed 9130016 hung; main passes it. Fix: `State::memory_in_closure`, only a node that judged or placed an entry in the closure deletes it as Outside. Seed pinned in `random_window_converges_spec_sync_6`. New rule, also in spec/sync.md §9. Residual: bodies of an unplaced thing may stay at a host if only such a node remains.
2. Disk: a coalesced body with no entry wrote a `y/s` carrier row kept 30 days. Carriers of forgotten commits now come from `Forgotten::why`.
3. Growth: `deleted` rows and forgotten headers stayed 30 days, not `MAX_DRIFT` (132 headers after 200 writes, seen with the fix disabled). `deleted` now holds its end time.
4. Growth: a class mark outlived an entry dropped without a tombstone.
5. Cost: `drop_entry` scanned every entry; `sweep_forgotten` scanned `deleted` per step, now per Tick.
6. Growth: local-only aspects never compacted (501 bodies per 500 writes, main 3). Now only a memory thing that was a label entry and left every closure skips compaction. Spec updated.
- Added `sweep_forgotten` skipping commits held again: by reading, no test.
- New tests: `typing_leaves_nothing_stored_or_kept_spec_sync_9` (seen failing without 2 and 3), `local_only_bodies_do_not_pile_up_spec_sync_9`, `memory_entry_dropped_leaves_no_mark`, `batch_part_on_private_thing_stays_out_of_label_spec_sync_3`. The last three were NOT run with a fix disabled; the privacy one guards existing behaviour.
- Rebase conflict: I rewrote spec/sync.md §6 and §9 by hand onto main's new structure. Worth reading.

## Open
- Churn seed 9130190 never settles on the branch; issues/eph-churn-delete-upload-loop.md. Main and pre-review builds were also marked hung at a 15-30 CPU-s limit, but main's loop was not traced, so "same bug" is unproven. On the branch one node alternates Upload and label-key Delete. Cause unknown. A real storm if it happens to users.
- Order settled seed 7026 fails on main and in the branch's run. Branch replay was stopped; failures not compared, cause not looked at. Its issue link is unknown (my grep matched fallen-snapshot-at-its-writer.md possibly only on another seed).
- Seed 7362042: from its end state only, likely a demoted reader holding the last copy, minor. Steps not traced.

## Unchecked from the brief
- `cargo test-net -- --ignored driver:: runtime:: quic` (presence and relay on the real network): NOT run.
- Oracles and the ephemeral sweep on the final code; `scale::eph_*` release (planned as a risk check in the issue).
- Hostile peers: only existing hostile_host tests via the gate. By reading, unverified: stamped junk that does not open stays in the overlay uncharged, bounded by an honest host's cap, not with a colluding host.
- Caps: only through the capped oracles and existing tests. Growth per delete until restart: not measured.
- Past `MAX_GAINED` (4096) entries, a forgotten commit's entry may never be told apart after a reconnect: by reading, unverified.
- Privacy: one new test and reading `commit_bodies_under`; no differential.
- Whole-commits 2b: read the plan, no conflict seen (one commit per expiry class fits; 2b has one path to rework). notes/whole-commits.md line 51 still says "memory lane".

## Repro (from a worktree of the branch)
- OSIS_SEED_TIMEOUT_SECS=15 OSIS_EPH_START=9130190 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large
- OSIS_ORDER_SEED=7026 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_settled_large_spec_commits_5 (147 s on main)
- OSIS_EPH_START=7362042 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6
- Add OSIS_SYNC_TRACE=1 and --nocapture to see messages. Next fresh offset: 9140000.
- The probe: `notes/eph-lane-probe.patch` on the branch (apply with tools/bin-at main OUT --patch).
