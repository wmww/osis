# A destroyed thing comes back past its request's window
> Summary: Past `ROLE_KEEP` after the request, a node keeps nothing of a thing destroyed by purge (`destroy::in_force`), so where the purger's right came from a grant on the thing itself, any minting arriving (a stale copy, or a new one by any reader holding the record from a record blob) brings the thing back at every such node, writable by its first admin's side. Conflicts with spec/requirements.md ("ignores later writes to it"). Fix before merging destroyed-leftovers.
> Priority: critical
> Tags: engine, security, tess-call

- Reproducer: `setup()`, a makes t (first admin g), grants b admin on t; b purges t's creation; advance past the window (every node keeps nothing); then ingest the creation's package at c, or have c `m.create(record)` via `commit_hostile`. Every node then knows t, and a write by a lands everywhere. With a (g's admin) purging, both are destroyed again.
- Any former reader can do it: record blobs stay under the label for good (notes/growth.md row 5b), and a minting needs no authority.
- A tombstone of the creation's ID is not enough: a new minting has a new ID. What stops both is keeping the verdict, not the evidence: past the window the destruction cannot fall here (the Limit), so a node can hold "t destroyed for good" (its Tid, or a bit on the request's header, which every node keeps) and drop any minting of t on arrival without reading the right. Costs one small row per destroyed thing per node for good; a newcomer past the request's floor still cannot judge it, as for any purge.
- Or keep main's rule for purges (`in_force` for good) and drop only the release/expiry/dependent leftovers.
- held-model still models `Purge` as kept for good (issues/thing-lifetimes.md, its tests line): update it with the chosen rule.
