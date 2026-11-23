# A removal is logged in commit order, not before everything else of its sync
> Summary: spec/permissions.md §3 (removal logged first): a node removing a holder logs the removal and the new `keys.0` before anything else that sync logs. Read logs one settle's own commits in commit-ID order (`Read::settle_on` reacts over a map keyed by sync ID and commit ID), so a write made just before the removal, logged in the same step, goes first whenever its ID sorts first.
> Priority: low
> Tags: sync

## Reproducer
osis-sync `flows::repro_a_removal_is_logged_before_what_was_written_before_it_spec_permissions_3` (ignored): node 0 writes t and removes node 2's account from t before its sync steps, then checks the removal's entry under S comes first. It passes on main: in its world the removal's commit ID sorts first, so it shows nothing until its world (or the write's value) is changed so the write's ID sorts first.

## Notes
What follows the removal is encrypted under the new epoch and comes after it in the feed anyway, so the harm is small: a source pulling the step's entries in log order meets the old-epoch write before the removal. Fix in read's logging: within one settle, log own role commits (a removal, its rotation, `keys.0`) before own content; or rewrite the rule to "before anything written after it" if that is all it is for (spec decision).
