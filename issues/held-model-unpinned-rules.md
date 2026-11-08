# Engine rules the held-model ambiguities settled with no engine test
> Summary: Rules core/test/held-model/AMBIGUITIES.md resolved by reading the engine code, with no test pinning them.
> Priority: low
> Tags: tests, engine

Each was found by reading code only. Add a node test per line (core/node/tests/it/retention.rs unless said):

1. **A remover's reset is a live write of its own body** (spec/commits.md §5): a purge-on-replace `remove_aspect` body is not replaced (`retention::replace::replaced`) until a later reset prunes its reset.
2. **A bare leftover is never judged for purge on replace** (spec/commits.md §5 Dropping a body): an expired purge-on-replace body stays as its leftover past T (`Core::none_parts` leaves bare parts out of `ix.none_held`); a copy-stripped (valued) leftover is judged like a whole body.
3. **Covered against a value-less copy** (spec/commits.md §5 Covered): a valued body whose write a valid snapshot carries value-less is not covered (`covered` join test, snapshot.rs).
4. **Possible admins exclude pending role commits** (spec/commits.md §4): a drift-parked grant gives its holder no purge right by any role ever held (`counts_as_purged`, `Held::ever_holders`).
5. **Covered drop needs the node's own right** (spec/commits.md §5 Between the bounds): a node demoted below the right keeps a body a rightful snapshot covers (`drop_from` None).
6. **An aspect-wide purge names compaction snapshots** (spec/commits.md §5 Purge): `PurgeItem::Aspect` drops a snapshot of the aspect it may purge.
7. **An own-grant lowering by an edge admin is a self-removal** (spec/permissions.md §2, held-model AMBIGUITIES 25): `walk.rs` `judge` checks it before the author's class; no test pins it for an author with edge-admin authority.
