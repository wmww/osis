# Evaluating the role timeline: what an update costs
> Summary: The walk along stated paths replays a component's role history from the earliest key an update touches (a backdated or forgotten grant write, a lowering applying with drops); k lowerings each dropping an early write cost about k times the history between; an open rebuilds the whole walk from every held commit's header.
> Priority: normal
> Tags: perm, performance

Cost shapes and their count tests: notes/perm-paths.md (Cost shapes, Counts, The switch: cost shapes of the layer).

- A backdated or forgotten grant-class part, or a lowering applying with drops, replays its component from the earliest key touched; a walk by reach (only the parts whose step reads something that changed) is not built (Tess: simplest correct wins; a very large number of role changes being fast is no priority).
- k void lowerings at the end of a chain of k grants cost k² setters read.
- An open gives the walk every held commit again (`index::update_timelines_loaded`), from each header (decoded at open for its view).
- The query layer's `edges_at(point)` reads every applied write at or after the point; `standing_since_all` and `roles_ever` read the whole log.
- So a component of k role commits taken one by one costs O(k²): a node paired into an account of 3 and 21 nodes, on its first sync (engine `scale::pairing_a_node_spec_permissions_8`), judges 13 and 310 grants for key access (`keyless_in` per update), walks 49 and 886 roles, writes 18 and 250 held-writes pages (each grant a death on A's `secrets.0`). Each count is linear in A's holders per role commit; a sibling taking one grant walks 18 and 72 roles.
