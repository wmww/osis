# Past bugs pinned only by a sim seed
> Summary: since the sim's dice changed (oracle-dice) `_seed_N` tests are plain runs, and these past bugs have no handmade test: only the sweep's breadth would find them again.
> Tags: tests, node-sync

Worst first (bug as the test's comment tells it; `core/test/sim/tests/it/net.rs`, `library.rs`):
- two_devices_host 23: entries never fetched freeze the writer's must-hold set; the other device waits for good.
- stranded_reseal 23: a relayer whose upload was lost re-uploads its own copy, and the tiebreak deletes the author's after quiescence.
- compaction 2887, 3914: two writers drop by each other's carrier snapshots and delete each other's bodies (churn).
- ephemeral 21054, 83, ephemeral_capped 2400045: a commit's ephemeral part lost at a holder; a commit stuck out of a full host.
- stranded_reseal 0: an admin's `label.0` record merges two rotations' steps, so a stale device claims through.
- link_race 46: chain completion after a fix (comment too short to say more).

Weak pins, the fix's mechanism only: disk_loss 3, link_race 91/119/164/191 and 41/107/120/144/197/50, host_loses_data 41 (`wiped_host_gets_bodies_back_from_restarted_node_spec_sync_6`).

Each needs a hand-built net test; the near ones are named in the same area (`duplicate_encryptions_higher_goes_spec_sync_7`, `compaction_across_skew_no_churn_spec_sync_7`, `one_step_per_rotation_without_host_spec_sync_5`). A bug sabotaged back in is found by the sweep at about the old rate, so this is depth, not an open hole.
