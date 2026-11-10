# Deletion: what each kind promises
> Summary: Tess's split of deletion into two purposes. Erasure (purge, expiry) promises the data is gone for good, a tombstone allowed; storage reclaim (history limits, no history, releasing a thing) promises nothing builds up, and leaving no trace is part of its contract, so what it removed may come back. Every deletion mechanism belongs to exactly one side.

## Erasure: the data is gone for good
- **Purge** and **expiry**. After them the data is gone at every node and stays gone; a stale copy never brings it back.
- A tombstone is allowed where the guarantee needs one. A purge is a separate request, so the request is kept to purge late copies. Expiry needs none: the `expires` field travels in the commit's own header, so a late copy is already expired when it arrives.
- Erasing a thing is purging or expiring its creation (`created.0`). After that the thing never comes back, not even by a new creation: the kept request covers every creation of the thing. Expiry is purge on a timer and promises the same for the commits it covers.

## Storage reclaim: nothing builds up, no trace
- **History limits** (keep for D, keep until T), **no history** (purge on replace, convenient), and **releasing a thing** (thing lifetimes, issues/thing-lifetimes.md).
- Their purpose is that nothing accumulates over time, so they leave no trace: no tombstone, no request kept, nothing that grows with what was removed.
- In exchange they promise nothing about the data never returning: a new write, or a node that still holds a copy, may bring it back. A history setting is self-describing (a copy arriving later is judged out of history again); a released thing is not, so a stale copy may revive it.
- They never stand in for erasure: an app that needs data gone for good purges or expires it.

## Consequences
- A mechanism that reclaims storage must not write a lasting record of what it removed; if it needs a request to reach other nodes, that request must be forgettable.
- A mechanism that erases may keep a tombstone, and a purge must.
- Naming: the reclaim verb for a thing is `release` (Tess preferred it to "drop", which the engine uses for bodies, and "free"). The erasure of a thing is a purge of its creation.
