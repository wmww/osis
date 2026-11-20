# Inbox held: two of judge's rules have no test
> Summary: in `inbox::held::judge`, the clearing exemption of a deposit read would promote (`Act::Promote`) and the "own deposit offered only while S is held" condition survive mutation: replacing Promote with Waiting, promoting on any promotion verdict, or offering an own deposit of an unheld S fails no osis-sync test.
> Priority: low
> Tags: sync, inbox, tests

- **Promote exemption** (spec/sync-inbox.md §4 Clearing: "except one it opened as a commit it would promote"): held only marks it so `clear` skips it. Read runs before inbox in a round and stamps a promotable deposit in place, so the exemption matters only where held judges Promote before read stamped it (an engine change mid-round), past the bound. A node-level test needs that window. Fresh encryptions of a commit held stamped do not reach it: read drops them as duplicates of its own entry before clearing counts them.
- **Offer only while S is held**: an own deposit of S whose holding is gone (sync set moved, shred not yet run) waits. A test needs a store source still connected in that window.
- The `Holding::Read` and stamp-key checks in front of `deposit_commit` only skip opening a deposit `promotion` would answer No for: work, not outcome; a count of deposits opened would pin them.
