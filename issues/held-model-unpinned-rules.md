# Engine rules the held-model ambiguities settled with no engine test
> Summary: Rules core/test/held-model/AMBIGUITIES.md resolved by reading the engine code, with no test pinning them; one (an invalid insert's hidden anchors are live writes) guards against losing others' valid inserts.
> Priority: low
> Tags: tests, engine

Each was found by reading code only. Add a node test per line (core/node/tests/it/retention.rs unless said):

1. **Hidden anchors are live writes** (spec/commits.md §5 live write, spec/crdt.md §4.6), data-loss guard. Writer W inserts "a" in text under keep at most 0 after replaced; first admin O inserts "b" anchored on it; O demotes W with an empty frontier. W's body falls and must not drop before a carrier: `body_live` true, `body_keeps()` gives `at_most` = the fall, `due_live_drops` lists it; after the drop (and on a fresh node fed only the carrier) the text reads "b". Code: `Fragment::holds_owned_write` counts every `Rec::Seq` (core/crdt/src/remap.rs).
2. **A remover's reset is a live write of its own body** (spec/commits.md §5): a `remove_aspect` body under 0 after replaced stays live (dropped only after a carrier) until a later reset prunes its reset.
3. **A bare leftover never drops at keep at most** (spec/commits.md §5 Dropping a body): an expired body purged on replace stays as its leftover past T and past its first death (`judge_at_most` returns on `Meta::bare`); a copy-stripped (valued) leftover drops at its bound.
4. **Covered against a value-less copy** (spec/commits.md §5 Covered): a valued body whose write a valid snapshot carries value-less is not covered (`covered` join test, snapshot.rs).
5. **Possible admins exclude pending role commits** (spec/commits.md §4): a drift-parked grant gives its holder no purge right by any role ever held (`counts_as_purged`, `Held::ever_holders`).
6. **Covered drop needs the node's own right** (spec/commits.md §5 Between the bounds): a node demoted below the right keeps a body a rightful snapshot covers (`drop_from` None).
7. **An aspect-wide purge names compaction snapshots** (spec/commits.md §5 Purge): `PurgeItem::Aspect` drops a snapshot of the aspect it may purge.
8. **An own-grant lowering by an edge admin is a self-removal** (spec/permissions.md §2, held-model AMBIGUITIES 25): `walk.rs` `judge` checks it before the author's class; no test pins it for an author with edge-admin authority.
