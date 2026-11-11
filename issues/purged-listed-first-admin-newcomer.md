# A newcomer does not read a dependent of a purged first admin in the closure
> Summary: t in g's closure (listed), first admin of x (in g), b granted admin on t; a purges t. a, b, c read x; a node granted g afterwards never holds x's record (nothing pending, x unread). Fails on main too (seen with `tools/bin-at main`); the same world with t outside the closure, or ended by expiry, reads.
> Priority: normal
> Tags: engine, node-sync, retention

- Repro: as `ending::a_purge_ending_stays_under_a_dependents_label_for_a_newcomer_spec_commits_5` with t's creation commit listing t in g (`items.items.insert(t)` on `ct::GROUP`), asserting `net.read(d, x)`.
- Not diagnosed: whether x's body leaves the host with the ending or d cannot open it.
