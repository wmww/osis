# valueless-gaps
> Summary: Footguns met fixing the value-less residue gaps.

- `git checkout main -- core/engine/src` to check "fails without the fix" broke the build once main moved past the branch base (another merge in between): use `git checkout $(git merge-base HEAD main) -- ...` (wip-commit first, `git checkout HEAD -- ...` after).
- A pipe `cargo test ... | grep "^test "` printed nothing when the build failed: grep for `^error` too.
- The order oracle's failure line ends with the shrunk history; the actual diff is only in the `check(...)` error, so a pinned `check(seed, &h, LARGE).unwrap()` test is the quickest way to read it.
