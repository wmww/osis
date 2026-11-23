# The engine reads no snapshot's carries: a list naming a snapshot keeps nothing it carries
> Summary: spec/permissions.md §5.2 Copies: a list naming a snapshot names the commits it carries copies of. The engine's `validity::reading` fills no carries, so a removal whose list names a snapshot keeps none of the writes the snapshot carries; held-model (reading roles-model `paths`) does. Engine `order::held_set_decides_plain` fails at seed 486492445194 (rate line in tools/known_failures.txt).
> Priority: normal
> Tags: engine, perm

Shrunk script: /tmp/claude-1003/-home-ai-osis/d0a4da80-f202-4b81-802b-94bfee39d934/scratchpad/review-a1-switch-7713/shrunk-script.txt (admin 0 writes #7 on 13; 0's snapshot #56 carries it; 20 removes 0 listing #56). A hand test fit for any correct fix is on branch `mizzen-a1-switch-carries-wip`.

What the fix needs (from the attempt on that branch, not for landing):
1. Carries are the commits the body holds copies of (§5.2), not the snapshot's frontier/absorbed tables (claims, spec/crdt.md §8: `validity::inflated_snapshot_claims_count_nothing` fails on tables). The engine keeps only a per-source counter hull (`retention::snapshot::Carried`); an exact form (an interval set per source) derives carried commits from `ix.ranges` with no body reads.
2. Bounded rejudging: the walk reports every carried commit as `named` when a snapshot comes or goes; `Changed` should separate "carried by an unlisted snapshot" from `named` so the engine skips those (the table attempt failed `scale::commits_after_their_snapshot_are_linear` and `scale::expiry_is_flat`).
3. A rollback bug found on the way: the rollback path in `engine/mod.rs` takes every pending `touch_commit`, including touches before the savepoint, runs `tl.update` and discards the `Changed`, so what they reach is never rejudged. Probably: flush pending touches before a mark is taken, so a rollback's update is pure undo.
