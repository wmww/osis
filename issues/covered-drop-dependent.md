# A covered drop on a dependent thing writes with the data
> Summary: Dropping a body as covered on a paged map of a dependent thing writes store bytes that grow with the map (16,433 B at 500 entries, 32,997 B at 5,000), where on an independent thing they are flat. Every thing a node makes is dependent until shared, so this is the common case: find what the drop rewrites whole for a dependent thing (sections sealed under its derived epoch?) and make it O(change).
> Priority: normal
> Tags: engine

`scale::covered_drop_on_a_dependent_thing_is_flat` (osis-engine `it`, ignored on this issue) reproduces it; `covered_drop_is_flat` is the same on an independent thing.
