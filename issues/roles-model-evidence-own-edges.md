# roles-model's evidence leaves out the edges a commit's own edge writes set
> Summary: roles-model `paths::evidence` takes every edge write on an edge of a held commit's path but not those on the edges its own edge writes set, which spec/permissions.md §4 (Evidence of a commit) includes; adding them flips a control of `each_fix_is_needed_plain`, so the fix needs that control re-read.
> Priority: normal
> Tags: tests, perm

- spec/permissions.md §4 Evidence of a commit: every edge write on the key hop, on each edge of the path it states, and on each edge its own edge writes set. roles-model `paths::evidence` (paths.rs) collects `w.rests(i)` alone. `paths::proofs::closure` has its own closure with both (`rests` and `sets`), and the proofs searches use it.
- Callers of `evidence`: `paths::purge` (`purge_worlds_hold_plain`), `paths::story`, hand tests in `paths/tests.rs`.
- The one-line fix (`edges.extend(w.rests(i).iter().copied().chain(w.sets(i)))`) keeps `small_worlds_hold_plain`, `purge_worlds_hold_plain`, `the_notes_rules_fail_liveness_and_alike_plain` and the default tests passing, but `each_fix_is_needed_plain` then fails its `lowered` assertion: the variant `Sides::Lowered` (rejected, "fails the story") no longer fails in random worlds 0..1000. To settle: whether that variant's failure needed the missing evidence (then it is no reason to reject it, and the story's finding needs re-reading) or only got rarer (then reach it by a hand world, notes/principles.md Never pin a seed). Then make `proofs::closure` the shared `evidence`.
