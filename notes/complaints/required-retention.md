# required-retention
- `wt claim`'s worktree on a nearly full disk (90%): cold first build a few minutes, fine.
- `LocalPeer::sync_all` re-delivers every package: a body dropped for its bound or rule joins again as a late part, so a drop test must not sync between the drop and its assertions. Cost me one wrong diagnosis.
- `cargo test --workspace` stops at the first failing binary: use `--no-fail-fast` when you need the whole picture. `Seen::floors` returns early under 20 seeds, so a reach assertion placed after that return never runs in a short tier-1 run.
- Changing a generator without rerunning the short harness left a reach assertion failing and made a whole fix-disabled pass read as caught by that test: check the baseline passes before and after such a pass.
- A `timeout` around an order replay of one seed kills the shrink, not only the check: a failing seed can run minutes.
- `whole_part` means more than decoded whole: it takes a part out of atomic apply's units. Adding a content aspect to it broke arrival order (seed 83048), caught only by the large oracle.
- A single-thing commit never applies with a part missing (atomic apply holds it), so a late-part test needs a commit on two things; the order harness's split delivery did not reach the path in 4 seeds.
