# Derived epoch establishment is order-dependent
> Summary: Whether a thing's derived epoch is marked established (`Core::adopt_derived`) depends on whether its first admin's epoch was established when the thing's `secrets.0` ingested, so an incremental index and a rebuilt one can differ.
> Priority: normal
> Tags: engine, tests

`adopt_derived` runs only at ingest of the thing's own secrets. A node that gets the first admin's establishment later leaves the thing's epoch unestablished while a rebuild from the commits marks it `Derived` (`Engine` debug check "rebuilt from the commit records, the index Table(\"secrets\")").

Repro: `sync::repro_derived_adoption_order_item_granted_to_its_groups_reader` (ignored): an item in a synced group granted directly to a reader of that group. Its own sync ID (spec/sync.md §2) brings its secrets to the reader before the group's epoch is established there, so the plainest first share fires this; the index debug check samples (powers of four), so tier 1 misses it most runs. Re-adopting at the first admin's secrets ingest did not fix it: establishment also comes from applied commits (`Core::names_held`), so the fix needs a hook there or computing the adoption at read (`own_epochs`).
