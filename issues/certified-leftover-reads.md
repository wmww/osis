# Certified and published: reads still coarse or unstamped
> Summary: what `sync::certified` and `labeling::published` still read whole or outside the stamps: the read things from the whole sync set, `destroyed_kept` (a hand cache), and chain pieces untested by the oracle test.
> Priority: low
> Tags: engine, sync, performance

- `Engine::read_things` derives the read things from `sync_set()` whole: one O(things) set diff per change of the sync set (every thing made). Per sync ID entries would make it per change.
- `Engine::own_piece` → `certificates` → `destroyed_needed` reads `Core::destroyed_kept`, an unstamped `Option<BTreeSet>` filled once from `Held::things()` (a whole read): a destroyed thing coming to be needed moves no piece until another read does. It wants a stamped index of the destroyed things held.
- `sync::certified::tests::pieces_keep_what_the_whole_derivation_gives_spec_permissions_4` has no author that is no node, so no `Piece::Chain` is ever placed there: a mutation dropping chain removals passes it. A step with a link key's write (a non-node author) would cover it.
- `body_things` finds the actor a `sync.0`/`created.0` part goes under by `owned_sync_ids` up the standing chain, while `publisher` maps an account to its devices actor: a labeled thing whose first admin is an account is published under D (`published_under`) but its `sync.0` commit is no body of D's sync IDs unless D's closure holds it. One of the two readings is off (spec/sync-ids.md §2, §4).
