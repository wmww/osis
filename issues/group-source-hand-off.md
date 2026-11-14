# Group source hand-off
> Summary: A group sourced at another node (`group_source`) still syncs here: the sync set does not leave it, so the move away waits for nothing and hands nothing off; build the hand-off once the engine's sync set is built.
> Priority: normal
> Tags: sync, api

spec/sync-set.md §5 and notes/api.md say a group sourced elsewhere is held here but not synced here ("at a node, this node holds what it had but does not sync it, and back home it syncs again"), and notes/client-port.md §8 (Sources) says a move away first waits until the group is synced here (`wait_synced`), then hands it off.

Built (`core/osis/src/sources.rs`): the source table (persisted as the app record `sources`), calls on its things going to the source node, writes refused while split, reads this port does not carry `Unsupported`.

Not built: the hand-off. The engine's `sync_set` (facade, not built on this branch) must leave out a group sourced elsewhere and its closure reached only through it; then `group_source(g, Node)` waits for `wait_synced` of `g` before recording the source (no local write stranded), and `group_source(g, Local)` reads nothing of `g` until it has caught up (notes/client-port.md §8 Catching up: `Engine::core.sourced_elsewhere`, which nothing sets yet). Until then a sourced group keeps syncing here: its copy is fed and never answers, and `split` counts it as sourced (not "syncing here"), as it will once the hand-off is built.
