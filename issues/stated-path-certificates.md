# Purge-author indexes and waits along stated paths
> Summary: The engine indexes a commit's purge author (where not its signer) as the one extra thing written as, and a commit waits for its signer's and purge author's records alone; spec/permissions.md §4 wants every listed thing of each stated path (its record needed and in the evidence). Stage A1's second branch.
> Priority: normal
> Tags: engine, permissions

What stands in, each site marked `Interim (issues/stated-path-certificates.md)`:
- `Indexes::by_actor`, filled in `apply::atomic::index_acting`, emptied in `apply::unindex`; `retention::needed` keeps by it each thing a held commit acts as.
- `apply::header_wait`: a commit waits for its purge author's record, not for every listed thing's.
- `write::check_acts`: the writer's check that it holds write on the thing it writes as.
- osis-commit `Header::path_allowed`: a role commit's purge index is held to 0, a bad input spec/wire.md does not list.

What else the engine reads short of the spec (snapshot carries, `addenda.0` entries, by-commit purge items, the list's frontier, epoch addenda, sides): notes/perm-paths.md, Read short of the spec.
