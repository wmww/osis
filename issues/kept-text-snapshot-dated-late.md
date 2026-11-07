# A kept text snapshot dated later than held-model
> Summary: In 2 of about 150k keep-for-D judgments a text snapshot's `replaced_at` is later than held-model's date (the engine keeps it longer); cause not found. Not unsafe (never early), but the rule is exact.
> Priority: low
> Tags: engine, retention, tests

Repro (the order harness's `keep-for-D dated later` tally; turn it into a diff to see it): `OSIS_ORDER_SEED=5059 OSIS_ORDER_LEN=40 cargo test -p osis-node --test it -- --include-ignored order::arrival_order_kept_small_spec_commits_5`, shrunk:
`[Aim(Typed { by: 2, t: 0, op: 35, k: 0, v: 1 }), Aim(Typed { by: 1, t: 0, op: 24, k: 1, v: 1 }), Sync { from: 1, to: 2 }, Aim(Compact { by: 0, t: 0, op: 35 }), Aim(Typed { by: 2, t: 0, op: 24, k: 1, v: 0 }), Aim(Typed { by: 1, t: 1, op: 22, k: 1, v: 1 }), Aim(Typed { by: 1, t: 0, op: 24, k: 1, v: 7 }), Aim(Typed { by: 2, t: 0, op: 22, k: 0, v: 5 }), Advance { who: Some(0), ms: 1220 }, Aim(Typed { by: 0, t: 0, op: 24, k: 1, v: 1 }), Aim(Compact { by: 2, t: 0, op: 24 })]`
C's text snapshot (B's insert, C's delete; B re-deleted it concurrently) is dated by the engine at A's later insert (wall 1220), by held-model at B's re-delete. Suspect: a sequence join reporting a death of a carried write the inserted element does not supersede, or the model's delete-supersedes-delete. A spurious report there would date a delta early.
- The latest-uncarried-death rule (spec/commits.md §5) leaves it: the aspect holds one snapshot, so no later one carries anything.
