# A reference from a thing that holds only sync on its target
> Summary: Tess wants a strong reference from G to T, where G holds only sync on T, to bring T, kept unread, to whoever syncs G. The built rules give it only to readers of G and only for an independent target: G's keys do not open T, so T is not in G's unit, a node keeping G unread stops at G, and a dependent target is not followed at all. To design under the built unit.
> Priority: low
> Tags: sync, engine, spec

## Wanted (Tess)
G holds sync on T (no read), G -> T strongly. Whoever syncs G should hold T kept unread: a reader of G, and a node keeping G unread.

## What the built rules give (checked: spec/sync-set.md §2)
- T is not in G's sync unit: G's keys open T only at read or above (T's keys open). So T is not carried under G's sync ID.
- A reader of G meeting the strong enters T's own sync unit kept unread when it holds a sync secret of T: G's unit carries T's stub (§2 Stub: the edge piece of G's grant on T, T's boxes to G and T's `sync.0`, as sync copies; Node closure, kept unread). So for an independent T a reader of G gets it.
- A node keeping G unread reads none of G's strongs and stops at G: it never holds T.
- A dependent target (X, a dependent of T): "a strong in a sync unit to a dependent thing the sync unit's keys do not open is not followed", so not even a reader of G holds X.
- spec/requirements.md Data model asks only that a reference from something that cannot read its target does not keep the target; it promises nothing here, so this is a wish beyond the requirement.

## In the way (argued)
- A node keeping G unread can follow nothing it cannot read; carrying T under G's sync ID would make G's unit hold what G cannot read, which breaks "a sync unit is what its thing can read" and puts a stamp of G's writers on T's blobs (G's writers cannot write T: they deposit or need a rule of their own).
- A dependent target has no sync ID of its own; it would come only with T's whole unit (kept unread), which no rule names from G's strong.
Each needs a design step: a sync unit's own data telling a node keeping it unread which sync IDs to keep beside it, judged by its readers from the grants it carries.
