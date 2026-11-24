# Dropped bodies coming back: make it simple and robust
> Summary: Tess's rule: a drop a later validity flip undoes counts as never received; the body rejoins from any copy; none left means gone alike. Built: items 1, 2, 5 (code cites them). Left: finding a copy is unreliable, so arrival-order bugs keep coming from the implementation; the four pieces below make it robust.
> Priority: normal
> Tags: engine, tests

Why bugs keep coming (notes/engine-validity.md, Flips against dropped data): peers keeping a body unread may delete it in the same sync; the revoker may not hold it; a node without the revocation deletes a body logged again; drops stack (expiry, covers turning invalid); "nobody has it" looks like "not yet", so repair backstops can loop.

Rejected (Tess): deletions final against later revocation (a removed or stolen device keeps delete power forever); history kept so drops roll back (no prompt permanent deletion); a writer's compaction vouching for a deletion (still diverges when every writer saw the revocation first).

Built (notes/engine-validity.md, notes/engine-retention-purge.md Leftovers, notes/test-harnesses.md Rebuild check): 1 one path (`apply::rebuild`), 2 leftovers are held bodies, 5 the rebuild check.

Left, each its own task, in the order 3, 4, 7, with 6 alongside:
3. **The holder logs it.** A node receiving a purge request (or a replacing write under purge on replace) it judges invalid makes sure the targeted body is held at the sync ID's sources. Closes a stated gap: after a purge's fall where no writer holds a whole copy, a node reads the write absent while readers holding whole carriers read it.
4. **Brute-force refetch.** A body counting as never received is asked for by ID on every sync, from every peer, until it arrives (rate-limited, idempotent), relying on no one's must-hold rules.
7. **Revoker snapshot** (notes/revocation.md, Frontiers; not built): the revoker compacts the aspects the demoted node wrote before stamping, so its snapshot carries content a node wrongly dropped. Shrinks the frontier only for data whose history may be dropped.
6. **Reference model** (notes/test-design.md, What finds bugs): from spec/ alone, what a node holding body set H reads; oracles compare each node with it after exchange.

Tess floated (not important, not built): edits dated before a re-grant stay invalid even when their author is re-added, which would remove refetch on re-grant entirely.

Small leftover: a body dropped as covered whose covering snapshot turns invalid and then valid again stays marked missing when no node will log it. Reads are fine; only the mark lingers.
