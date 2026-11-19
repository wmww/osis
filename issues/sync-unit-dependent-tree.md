# Sync unit: one independent thing and its dependents
> Summary: Decided by Tess (notes/sync-unit-scope.md): a sync unit stops being a root's readable closure and becomes one independent thing with its dependents; a closure is synced unit by unit, by readers and by nodes keeping it unread alike. To study and plan before building, claiming every win and keeping what a node keeping units unread learns as small as practical.
> Priority: normal
> Tags: sync, engine, spec

Fixed (Tess): sharing a root gives its closure; promoting a thing to independent has no behavioural cost; the old model, its trade-offs and the reason for the change stay recorded (notes/sync-unit-scope.md).

To design, then model or check by differential before building:
- **The unit's list of direct independent members**: where it lives, how it opens for holders of sync and nobody else, what an entry holds (the sync ID and what keeping it unread needs), how it is written with the reference and removed with it, how a node keeping the unit unread follows it, drops a unit nothing it keeps points at, and finds a cycle nothing outside references.
- **Promotion**: a dependent thing becoming independent moves from its independent's unit to its own. What becomes of its blobs under the old sync ID, how the list entry is written in the same commit, and that no reader or node keeping it unread misses a write across the change.
- **What goes**, each named with the spec sections and code it removes: retag, deposits into enclosing units and their promotion, per-sync-ID copies, the keys-open walk, certificate placement by sync ID. Which open sync issues close with them.
- **Commits across units**: one blob under each unit it touches, as now; what a node holding only one of them holds.
- **Removal** from a root: what it costs across the units below it, each with its own access list, and when a removed reader stops fetching each.
- **Status and "caught up"** over a closure of many units; first sync of a closure with many units (round trips, opens); issues/many-sync-ids-cost.md measured first, since every closure now is many sync IDs.
- **With the account redesign** (issues/actors-one-mechanism.md): evidence per unit, removals to every unit a node could read, a public thing as a unit anyone may enter. Design the two together where they meet.
- **Privacy**: the list in notes/sync-unit-scope.md (Keeping the privacy story tight); say exactly what a node keeping a closure unread learns, at rest and over time, and update spec/requirements.md (Data a node cannot read) to it.
- A staged plan in which each stage leaves the tree working.
