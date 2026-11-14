# sync-inbox complaints
- The worktree `wt claim` handed out (wt11) was "free" but had branch `sync-read` checked out at the sync-rebuild tip: unclear whether another agent was about to use it.
- The facade (sync-facade) is mid-change: `take_inbox` returns `InboxOpened` on sync-rebuild but `Option<InboxOpened>` on the branch, `inbox_blob` a `Sealed` vs bytes, `removal_notices` whole vs per S. Coding against a moving facade meant a `Ground` trait of its own.
- Opens and streams are stubs here, so `Net::member`, `present` and `filter_generation` have no stamped source in the product yet; only the fakes exercise the change-driven paths.
- Review: the rebase onto the moved sync-rebuild conflicted only in tools/dead_pub_allow.txt; a union of both sides left duplicate lines that policy.py does not flag (dedupe by hand).
- Review: the worker's numbered readings were not in the branch or the brief's scratch notes; the reviewer had to reconstruct them from code comments. Put readings in the commit message or the boundary note.
