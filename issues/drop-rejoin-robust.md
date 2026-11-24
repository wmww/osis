# Dropped bodies coming back: make it simple and robust
> Summary: Tess's rule: a drop a later validity flip undoes counts as never received; the body rejoins from any copy; none left means gone alike. Built: items 1-5 (code and notes cite them). Left: the revoker snapshot and the reference model.
> Priority: normal
> Tags: engine, tests

Why bugs keep coming (notes/engine-validity.md, Flips against dropped data): peers keeping a body unread may delete it in the same sync; the revoker may not hold it; a node without the revocation deletes a body logged again; drops stack (expiry, covers turning invalid); "nobody has it" looks like "not yet", so repair backstops can loop.

Rejected (Tess): deletions final against later revocation (a removed or stolen node keeps delete power forever); history kept so drops roll back (no prompt permanent deletion); a writer's compaction vouching for a deletion (still diverges when every writer saw the revocation first).

Built (notes/engine-validity.md, notes/engine-retention-purge.md Leftovers, notes/sync-read.md Fetching again, Role entries first, notes/test-harnesses.md Rebuild check): 1 one path (`apply::rebuild`), 2 leftovers are held bodies, 3 the holder logs it (a snapshot leftover through its purge's fall counts missing while short; a logging again waits for every role commit held, so a node lacking the revocation fetches it before deleting the body logged again), 4 asked by ID (a Want per connection from every reader peer, answered from whatever the peer holds), 5 the rebuild check.

Not covered by end-to-end world tests: the multi-account sync worlds are ignored while the accounts work lands; the pieces are tested at their boundaries (read's fake ground, streams' pair, the engine's fallen-snapshot rig). Once worlds run, a world per class (unread peers deleting in the same sync; the revoker not holding it; a node without the revocation deleting a body logged again; stacked drops) belongs in osis-sync.

Left, each its own task, in the order 7, with 6 alongside:
7. **Revoker snapshot** (notes/revocation.md, Frontiers; not built): the revoker compacts the aspects the demoted node wrote before stamping, so its snapshot carries content a node wrongly dropped. Shrinks the frontier only for data whose history may be dropped.
6. **Reference model** (notes/test-design.md, What finds bugs): from spec/ alone, what a node holding body set H reads; oracles compare each node with it after exchange.

Tess floated (not important, not built): edits dated before a re-grant stay invalid even when their author is re-added, which would remove refetch on re-grant entirely.

Small leftover: a body dropped as covered whose covering snapshot turns invalid and then valid again stays marked missing when no node will log it. Reads are fine; only the mark lingers.
