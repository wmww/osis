# Purge-author indexes and waits along stated paths
> Summary: The engine indexes a commit's purge author (where not its signer) as the one extra thing written as, and a commit waits for its signer's and purge author's records alone; spec/permissions.md §4 wants every listed thing of each stated path (its record needed and in the evidence). Left from stage A1.
> Priority: normal
> Tags: engine, perm

What stands in, each site marked `Interim (issues/stated-path-certificates.md)`:
- `Indexes::by_actor`, filled in `apply::atomic::index_acting`, emptied in `apply::unindex`; `retention::needed` keeps by it each thing a held commit acts as.
- `apply::header_wait`: a commit waits for its signer's and purge author's records; a part's other listed things are awaited only where one of `thing_wait`'s hops reads its record (a hop's target always: a record edge or an edge write needs it), never the records further up their chains.
- `write::check_acts`: the writer's check that it holds write on the thing it writes as.
- osis-commit `Header::path_allowed`: a role commit's purge index is held to 0, a bad input spec/wire.md does not list.

Suspect, untested: a part whose hop to a listed thing A is neither a record edge known here nor reached by a held edge write waits as `MissingChain(signer)`, which wakes on held role inputs moving, not on A's record arriving: a record blob carrying A's record alone keeps it loose and wakes nothing. Waiting by `UnknownCreated` for every listed thing (and up its chain) closes it, and `Need::Acting` then becomes the spec's "every listed thing".

What else the engine reads short of the spec (snapshot carries, `addenda.0` entries, by-commit purge items, the list's frontier, epoch addenda, sides): notes/perm-paths.md, Read short of the spec.
