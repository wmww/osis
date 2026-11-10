# order-roles-seed
- `OSIS_ORDER_DUMP` shows only index differences; a node missing a whole thing printed "node absent" on every commit with no pending entry, and nothing says a commit was thrown out and never fetched again. Finding that took ad-hoc prints of `Peer::receive` results and the `discarded` list.
- `engine.tick()`/`engine.reexamine()` on a `Peer` skip its wake: anything the call woke stays thrown out. `Peer::tick`/`Peer::reexamine` now exist; other scripted tests still call the engine directly (fine while nothing waits discarded).
- The worktree's first build took 13 min at load 50, then the two-offset sibling run waited 20+ min on the heavy lock.
- Review: the footgun was at about 150 call sites (`lp.peers[i].engine.tick()` and `let e = &mut lp.peers[i].engine; e.tick()`); a probe run found only the new test relied on the wake. `tools/policy.py` now flags `<peer>.engine.tick()`/`reexamine()`; an `&mut Engine` alias still slips past it.
