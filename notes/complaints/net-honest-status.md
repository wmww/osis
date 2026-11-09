# net-honest-status
> Summary: Mishaps building honest status: a probe revert took unsaved tests; a rebase turned a leaving test red with no conflict nearby.
- review: the rebase onto net-role-sync turned the branch's leaving test red with no conflict near it; a `tools/bin-at` of the pre-rebase tip (1 min) told it from a branch bug.
- A blanket `git checkout <file>` while reverting probes took my uncommitted tests in the same file: wip-commit first (notes/coordination.md says so; I skipped it once).
