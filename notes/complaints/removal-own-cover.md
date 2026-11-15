# removal-own-cover
- The heavy lock was held by others' gates for 15+ min twice before the roles-model search could start; a model run is cheap but queues behind full gates.
- Forcing a covered drop in an engine test needs `drop_body`/`forget_commits` by hand: `tick` and sync do not drop a body under another writer's snapshot, which cost a round of guessing.
- Several engine tests silently relied on removals listing every held commit; the list-what-you-hold variant restored them unchanged.
- The heavy lock queue ran past 35 min for one 7-min model run; worth a shorter by-hand slot or a queue view.
- Review: `LocalPeer::sync(a, b)` sends one way only; a test syncing pairs one way silently left a peer without the commit.
- Review: roles-model `forget` delivers a remover's own role write to itself only at its receipt event, after a same-tick arrival, so a node can act on a removal it already voided; worth a fix if another study leans on same-tick orders.
