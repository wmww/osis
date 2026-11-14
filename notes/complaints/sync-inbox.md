# sync-inbox complaints
- The worktree `wt claim` handed out (wt11) was "free" but had branch `sync-read` checked out at the sync-rebuild tip: unclear whether another agent was about to use it.
- The facade (sync-facade) is mid-change: `take_inbox` returns `InboxOpened` on sync-rebuild but `Option<InboxOpened>` on the branch, `inbox_blob` a `Sealed` vs bytes, `removal_notices` whole vs per S. Coding against a moving facade meant a `Ground` trait of its own.
- Opens and streams are stubs here, so `Net::member`, `present` and `filter_generation` have no stamped source in the product yet; only the fakes exercise the change-driven paths.
