# A writer may promote a deposit holding only covered parts
> Summary: `would_promote` (core/node/src/sync/pass/promote.rs) judges what a label needs by closure only, not by snapshot cover (matching spec/sync-inbox.md §4 promotion as written), so a writer could stamp and keep a reader's deposit whose parts a snapshot already carries: a wasted blob at hosts until it is dropped as covered, and a possible place/delete pair. Unreproduced; seen by reading in the evil-host review.
> Priority: low
> Tags: sync, node-sync

- Check: whether a promoted covered-only deposit is then deleted as covered by another writer (a loop) or only costs one upload; if it can loop, judge need in `would_promote` with the same cover rule the deleter uses (spec §7 Carriers), one function both read.
