# Group source hand-off
> Summary: A group sourced at another node (`group_source`) still syncs here: the engine's sync set does not leave it, so the move away waits for nothing and the move home reads its copy at once; build the hand-off in the engine's sync set.
> Priority: normal
> Tags: sync, api

spec/sync-set.md §5 and notes/api.md say a group sourced elsewhere is held here but not synced here ("at a node, this node holds what it had but does not sync it, and back home it syncs again"), and notes/client-port.md §8 (Sources) says a move away first waits until the group is synced here (`wait_synced`), then hands it off.

Built (`core/osis/src/sources.rs`): the source table (persisted as the app record `sources`, mirrored into `Core::sourced_elsewhere`, which `readable_by` uses so a client actor of this node reads nothing of a sourced group), calls on its things going to the source node, writes refused while split (`split`: a group carrying the thing whose sync ID is in `Engine::sync_set`, or a group sourced at another node), reads this port does not carry `Unsupported`.

Not built, all in the engine's sync set (`core/engine/src/sync/set.rs`, followed by `osis_sync::set::SetFollow`):
- `sync_things_now` leaves out a group in `sourced_elsewhere` and what the closure reaches only through it. `sourced_elsewhere` is a plain field today: it needs a stamp the closure's memo reads, so a move makes `SetFollow`'s closure key due; and the walk must keep spec/sync-set.md §2 Cost (a change costs work in proportion to what it adds or removes), so not a fresh closure walk per change.
- Leaving then follows spec/sync-set.md §3 (stop once own commits are held elsewhere), which is the "wait until synced" of a move away: `group_source(g, Node)` itself need not wait.
- Moving home: `group_source(g, Local)` keeps `g` in `sourced_elsewhere` (client actors read nothing of it) until the group has caught up (its sync IDs synced, as `wait_synced` judges), then drops it. Today the move home makes the copy answer at once, however far behind.

Until then a sourced group keeps syncing here: its copy is fed and never answers.
