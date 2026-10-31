# inbox-accept
- core/osis/tests uses two `World`s: `common/world.rs` (sync, sharing) and `osis_sim::world::World` (notes, tags, commits, event). Patching one left half the tests failing for a confusing reason; they duplicate run/pump logic.
- The sim's node faults mark a store crashed mid-write, but the engine stays callable until `after_node` takes the node down: any extra call after `handle` (here, listing invite requests) reads a broken store and trips an unrelated debug assertion (`labels_of cached`). Cost a debugging round.
