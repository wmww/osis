# A held role commit naming made-up path things joins the walk's components for good
> Summary: osis-perm's `paths` walk joins the components of every edge a held edge-class part names, whether or not the part can ever apply, so any signer whose role commits a node holds can merge unrelated things into one component, and every later out-of-order role change on one replays the others' later history.
> Priority: low
> Tags: perm, security

The walk is one walk per component of the edges, an update replaying its component from the earliest key it touches (notes/perm-paths.md, One definition; Scale, Components). A part joins the edges it touches: its own and its path's. A part whose path names an edge nobody set never applies, yet joins all the same; components never split. Cost only, no reading changes (`Paths::single`, everything in one component, reads alike: `single::paths_components_agree_*`): a merge moves the smaller side's entries, and afterwards a backdated or forgotten part, or a lowering with drops, replays the joined history after its key.

Who can: any party whose role commit a node holds (a role commit is kept whatever its validity: spec/permissions.md §6 Invalid deltas), with one write per join.

To fix, if it ever measures: a part joins only through edges a held write sets or a record gives (a part with a hop nobody set walks in no component, dropped or not decided by the lowerings after it, and joins when a setter of that hop arrives); or split a component when the part joining it is forgotten.
