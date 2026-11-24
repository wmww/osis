# Evaluating the role timeline: what an update costs
> Summary: The walk along stated paths replays a component's role history from the earliest key an update touches (a backdated or forgotten edge write, a lowering applying with drops); k lowerings each dropping an early write cost about k times the history between; an open rebuilds the whole walk from every held commit's header.
> Priority: normal
> Tags: permissions, performance

Cost shapes and their count tests: notes/perm-paths.md (Cost shapes, Counts, The switch: cost shapes of the layer).

- A backdated or forgotten edge-class part, or a lowering applying with drops, replays its component from the earliest key touched; a walk by reach (only the parts whose step reads something that changed) is not built (Tess: simplest correct wins; a very large number of role changes being fast is no priority).
- k void lowerings at the end of a chain of k grants cost k² setters read.
- An open gives the walk every held commit again (`index::update_timelines_loaded`), decoding each header, until the walk's delta facts live in the engine's index.
- The query layer's `edges_at(point)` reads every applied write at or after the point; `standing_since_all` and `roles_ever` read the whole log.
