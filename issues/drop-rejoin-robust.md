# Dropped bodies coming back: make it simple and robust
> Summary: Tess's rule stands (a drop a later validity flip undoes counts as never received; the body rejoins from any copy; none left means gone alike). Built: one rebuild path, leftovers as held bodies, the debug rebuild check. Left, none built: holders log a purged body again (3), brute-force refetch by ID (4), a reference model (6), revoker snapshots (7).
> Priority: normal
> Tags: engine, tests

Most arrival-order bugs (notes/test-design.md, What finds bugs, notes/engine-validity.md, Flips against dropped data) come from the implementation, not the rule: finding a copy is unreliable (peers keeping it unread may delete it in the same sync; the revoker may not hold it; a node without the revocation deletes a body logged again); drops stack (expiry, covers turning invalid); "nobody has it" looks like "not yet", so repair backstops can loop (seed 5288: a re-snapshot every 6 h).

Rejected (Tess): deletions final against later revocation (a removed or stolen device keeps delete power forever); history kept so drops roll back (no prompt permanent deletion); a writer's compaction vouching for a deletion (still diverges when every writer saw the revocation first).

Built (notes/engine-validity.md, notes/engine-retention-purge.md Leftovers, notes/test-harnesses.md Rebuild check): 1 one path (`apply::rebuild`), 2 leftovers are held bodies, 5 the rebuild check.

Left, each its own task, cost no object; order 3, 4, 7, with 6 alongside:
3. **The holder logs it.** A node that receives a purge request (or a replacing write under purge on replace) it judges invalid makes sure the targeted body is held at the sync ID's sources. Closes a stated gap: after a purge's fall where no writer holds a whole copy (the fallen value's delta gone everywhere, whole carriers only at readers), a node reads the write absent while those readers read it. Refetching carrier leftovers does not close it: a writer that stripped the carrier deletes its blob at its sources once its own re-snapshot is held there.
4. **Brute-force refetch.** A body counting as never received is asked for by ID on every sync, from every peer, until it arrives (rate-limited, idempotent). No reliance on others' must-hold rules.
6. **Reference model** (notes/test-design.md, What finds bugs): from spec/ alone, what a node holding body set H reads; oracles compare each node with it after exchange.
7. **Revoker snapshot** (Tess: not built, notes/revocation.md Frontiers): the revoker compacts the aspects the demoted node wrote before stamping; its snapshot carries the content it never saw deleted, so a node that wrongly dropped it gets the copy with the revocation. Shrinks the frontier only for data whose history may be dropped.

Tess floated (not important, not built): edits dated before a re-grant stay invalid even when their author is re-added, so a re-grant never revives old edits. That would remove refetch on re-grant entirely (a body dropped while invalid could never turn valid again from a re-grant).

Small leftover: a body dropped as covered whose covering snapshot turns invalid and then valid again (after a re-grant) stays marked missing when no node will log it. Reads are fine; only the mark lingers.
