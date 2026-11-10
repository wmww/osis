# order-roles-seed
- `OSIS_ORDER_DUMP` shows only index differences; a node missing a whole thing printed "node absent" on every commit with no pending entry, and nothing says a commit was thrown out and never fetched again. Finding that took ad-hoc prints of `Peer::receive` results and the `discarded` list.
- `engine.tick()`/`engine.reexamine()` on a `Peer` skip its wake: anything the call woke stays thrown out. `Peer::tick`/`Peer::reexamine` now exist; other scripted tests still call the engine directly (fine while nothing waits discarded).
- The worktree's first build took 13 min at load 50, then the two-offset sibling run waited 20+ min on the heavy lock.
