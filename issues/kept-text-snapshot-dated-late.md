# A kept text snapshot dated later than held-model
> Summary: In 2 of about 150k keep-for-D judgments a text snapshot's `replaced_at` is later than held-model's date (the engine keeps it longer); cause not found. Not unsafe (never early), but the rule is exact.
> Priority: low
> Tags: engine, retention, tests

Repro: `cargo test -p osis-node --test it -- --ignored order::repro_kept_text_snapshot_dated_late_spec_commits_5` (held-model's `keep-for-D dated later` tally, as made, reversed and as fetched).
C's text snapshot (B's insert, C's delete; B re-deleted it concurrently) is dated by the engine at A's later insert (wall 1220), by held-model at B's re-delete. Suspect: a sequence join reporting a death of a carried write the inserted element does not supersede, or the model's delete-supersedes-delete. A spurious report there would date a delta early.
- The latest-uncarried-death rule (spec/commits.md §5) leaves it: the aspect holds one snapshot, so no later one carries anything.
