# cleanup-osis
> Summary: Footguns met cleaning the osis crate and the crdt pinned seeds.

- `making::making_an_independent_thing_costs_what_it_changed_spec_sync_set_2` failed once in a full `cargo test -p osis` run (`certified: follows` 45 -> 71, `sync set: follows` 55 -> 86) and passed alone three times and in the next full run: the count looks load-dependent.
- `deprecated_probe.py --dead osis` lists most of the crate's unused public API as dead (chains of private helpers under unused `pub` items): the dead list is only useful after filtering out what hangs off public items.
- A pinned script (`move_beside_broken_cycle_replays`) came with a harness change, not a crate fix, so there was no fix to undo: its replacement can only be checked by its own precondition asserts.
