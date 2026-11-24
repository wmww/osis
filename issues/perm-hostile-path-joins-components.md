# A held role commit's path joins the walk's components for good
> Summary: osis-perm's `paths` walk joins the components of every edge a held edge-class part names that a held part sets, whether or not the part can ever apply, so any signer whose role commits a node holds can merge unrelated things into one component by a path through their set edges, and every later out-of-order role change on one replays the others' later history.
> Priority: low
> Tags: perm, security

The walk is one walk per component of the edges, an update replaying its component from the earliest key it touches (notes/perm-paths.md, One definition; Scale, Components). A part joins the edges it touches that a held part sets: its own and its path's (an edge nobody sets joins nothing). A part whose path cannot give it its role (an edge set to none, a hop on an unrelated thing's set edge) never applies, yet joins all the same; components never split. Cost only, no reading changes (`Paths::single`, everything in one component, reads alike: `single::paths_components_agree_*`): a merge moves the smaller side's entries, and afterwards a backdated or forgotten part, or a lowering with drops, replays the joined history after its key.

Who can: any party whose role commit a node holds (a role commit is kept whatever its validity: spec/permissions.md §6 Invalid deltas), with one write per join.

To fix, if it ever measures: split a component when the part joining it is forgotten, or join a part only through the edges its step can read as giving its need.
