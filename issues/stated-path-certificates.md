# Certificates and purge-author indexes along stated paths
> Summary: The engine still indexes a commit's purge author (where not its signer) as the one extra thing whose record and chain go with the commit, and builds chain certificates over any path of chained writes; spec/permissions.md §4 wants every listed thing of each stated path (its record needed, the chain along that path certified). Stage A1's second branch after the switch.
> Priority: normal
> Tags: engine, permissions

What stands in, each site marked `Interim (issues/stated-path-certificates.md)`:
- `Indexes::by_actor` and `acting_on` (with `chains_on`'s (author, purge author) pairs): the things written as, kept needed (`retention::needed`) and certified (`sync_ids/certs`); filled in `apply::atomic::index_acting`, emptied in `apply::unindex`.
- `apply::header_wait`: a commit waits for its purge author's record, not for every listed thing's.
- `write::check_acts`: the writer's check that it holds write on the thing it writes as.
- osis-commit `Header::path_allowed`: a role commit's purge index is held to 0, a bad input spec/wire.md does not list.

What else the engine reads short of the spec (snapshot carries, `addenda.0` entries, by-commit purge items, the list's frontier, epoch addenda, sides): notes/perm-paths.md, Read short of the spec.
