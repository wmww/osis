# keel-review-c
- Lane (c)'s two engine tests drive tickets through `LocalPeer` alone, which delivers every commit whatever the sync set says, so "accept a stranger's grant" passed while real sync would fetch nothing (issues/ticket-sync-ids.md). A check of `sync_set()` after an accept would have caught it.
- Forging a ticket in a test needs crate-private `flows::recipient` and an epoch marked established by hand: hostile-ticket tests live in the engine lib (`sync::tests_tickets`), not `tests/it`.
