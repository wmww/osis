# A dead tied grant is never removed by an admin of its thing
> Summary: spec/permissions.md §2 (tied edge removed): an admin of T holding a tied grant (G, T) dead removes it as an explicit demotion after a complete pass of the demotion's scope; the facade wants and gets that pass, but nothing then calls `Engine::untie`, so the edge stands for good (osis's `untie_now` covers only the self-removal case).
> Priority: normal
> Tags: sync, engine

## Reproducer
osis-sync `flows::repro_a_dead_tie_is_removed_after_a_pass_spec_permissions_2` (ignored): node 0, admin of g and t, grants g a write edge on t tied to t's place in g, then takes t out of g; after a run and a minute, `may_remove(t, g)` is `Explicit`, no pass is wanted, and g's edge on t stands at node 0 and node 2.

## Fix
Where a complete pass is noted (status, `note_complete_pass`), or in the driver after it, untie each dead tie whose scope's passes are done (`tied_unplaced` with the touched things; `may_remove == Explicit`), writing the demotion as pre-synced.
