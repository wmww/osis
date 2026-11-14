# Dropped bodies coming back: make it simple and robust
> Summary: Tess's rule stands (a drop a later validity flip undoes counts as never received; the body rejoins from any copy; none left means gone alike); build it robustly, spending download and CPU freely in this rare case. Built: one rebuild path, leftovers as held bodies, the debug rebuild check. Left: holders re-upload (3), brute-force refetch (4), a reference model (6), revoker snapshots (7).
> Priority: normal
> Tags: engine, tests

Most arrival-order bugs (notes/testing.md What finds bugs, notes/convergence-study.md) come from the implementation, not the rule: finding a copy is unreliable (hosts may delete in the same sync; the revoker may not hold it; a node without the revocation deletes a re-upload again); drops stack (expiry, covers turning invalid); "nobody has it" looks like "not yet", so repair backstops can loop (seed 5288: a re-snapshot every 6 h).

Rejected (Tess): deletions final against later revocation (a removed or stolen device keeps delete power forever); history kept so drops roll back (no prompt permanent deletion); a writer's compaction vouching for a deletion (still diverges when every writer saw the revocation first).

Built (notes/engine-validity-rebuild.md, notes/engine-retention-purge.md Leftovers, notes/test-harnesses.md Rebuild check): 1 one path (`apply::rebuild`), 2 leftovers are held bodies, 5 the rebuild check.

Left, each its own task, cost no object; order 3, 4, 7, with 6 alongside:
3. **The holder uploads.** A node that receives a purge request (or a replacing write under purge on replace) it judges invalid makes sure the targeted body is at the label's hosts. Closes a stated gap: after a purge's fall where no writer holds a whole copy (the fallen value's delta gone everywhere, whole carriers only at readers), a node reads the write absent while those readers read it. Refetching carrier leftovers does not close it: a writer that stripped the carrier deletes its host blob once its own re-snapshot is up.
4. **Brute-force refetch.** A body counting as never received is asked for by ID on every sync, from every host and peer, until it arrives (rate-limited, idempotent). No reliance on others' must-hold rules.
6. **Reference model** (notes/testing.md What finds bugs): from spec/ alone, what a node holding body set H reads; oracles compare each node with it after exchange.
7. **Revoker snapshot** (issues/session-sources.md): the revoker compacts the aspects the demoted node wrote before stamping; its snapshot carries the content it never saw deleted, so a node that wrongly dropped it gets the copy with the revocation. Shrinks the frontier only for data whose history may be dropped.
