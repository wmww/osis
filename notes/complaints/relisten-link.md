# relisten-link
- The brief's base (small-3) merged into sync-rebuild mid-task under new commit IDs and the branch was deleted: rebasing needs the old tip ID (1dd740ce8) noted before starting.
- tools/policy.py reported a violation in a file this branch never touched (small-3's siblings.rs citation), fixed only in the merge commit: run policy on the base first to know what is yours.
- Review: the branch's first driver-test rewrite matched a comment by its old line wrapping; a scripted multi-replace that asserts each match catches that before half the edits land.
