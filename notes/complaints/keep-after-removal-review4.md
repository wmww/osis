# keep-after-removal review 4
> Summary: footguns met reviewing kept copies.

- Rebase conflicts again on issues/order-seeds-found-on-main.md (every branch appends seeds there).
- A write unsent at a renewal reaches the other side only a re-sync later (`w.advance(hour)`): an assert right after `w.run()` read as a product bug.
- Filling 10^3 labels through `Net::group_seeded` in a debug build takes over five minutes: a cost probe should start at 100.
