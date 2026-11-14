# sync-commit-sets
- The brief said node 2 read v5 wrongly while holding the removal and its addendum. Bob's tid sorts below Alice's, so v5 orders before the removal and node 2's addendum vouches for it: v5 is right, and node 0 lacked v5's body. Check the tie order (`Tid` Ord) and each node's `body_valid`/`held_bodies` before naming an engine cause.
- `commit_ids` counts headers: a node holding a commit's header with its part dropped looks like it holds the commit. Compare bodies (`commit_bytes`, `held_bodies`) when comparing what nodes hold.
- Trying `git merge origin/main` into sync-rebuild to test main's engine conflicts in engine/secrets.rs, testing.rs and rotation/tests.rs; not worth it for a probe.
