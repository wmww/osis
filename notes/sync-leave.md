# Sync: leave
> Summary: osis-sync's `leave` module (core/sync/src/leave.rs) and the engine's `forget_local`: a read sync ID leaving the sync set stops once this node's own commits under it are held elsewhere; an unsynced thing's local copy is forgotten then; what it keeps, its costs, and what is not built.

Spec: spec/sync-set.md §3. Overview: notes/sync.md. Kept unread leaving is `unread`'s (notes/sync-unread.md).

## The module
One settle a round, after status (`Node::settle`), so the held-elsewhere marks of the round are in.
- Follows `Engine::sync_set` (one `Effects` key) and diffs the read sync IDs. One that left (not lowered to kept unread, not followed by `unread`): if the node still reads its thing under it (`thing_sync`: a read secret held, so the thing left the synced group's closure) it waits; else (secrets lost) it is shredded at once.
- Waiting S: one `Effects` key per S judges each own commit with an entry under S (`Engine::own_commits`) held elsewhere by status's durable mark on one of its entries (`Store::elsewhere`). Then `Engine::forget_local(thing)`, then `Store::shred` (that order: a crash between leaves rows, so the next start redoes both).
- Synced again before it stops: the wait ends, nothing goes.
- At a start (first settle): every sync ID with rows (`Store::held_ids`) outside the sync set, not kept unread, whose owner (`sync_owner`) is still read under it, left while the node was down: it waits as above.
- State: the read sync IDs, the waiting ones, `Effects` keys; nothing durable (the store's rows are the truth after a restart).

## forget_local (engine, core/engine/src/sync/mod.rs, retention/forget.rs `Scope::Local`)
- Forgets `t` and each thing whose secret actor is `t`, but those the synced group's closure holds (a plain thing listed elsewhere still syncs under that group). Same machinery as lost access (`retention::forget::forget`), fate `Local`: everything an erased thing loses but `secrets.0`, so the thing stays read and syncs again when listed; commits left with no part are deleted and fetched again, others keep their other parts (late parts join). Event cause `Unsynced` (`DerivedFrom::Unsynced`).
- Cost: decodes every commit header and reloads the engine, like lost access. Unsyncing is rare; per thing.

## Reasons
- Any thing, admin or not, goes when unsynced: unsyncing means "not on this node" (Tess). Unsyncing everywhere the last copy loses it; stated in the spec as the behaviour, like deleting a local file.
- The wait guards only this node's own writes: a peer that never got them would lose them. Everyone else's are someone else's to keep.
- Status's durable mark, not stream presence: a reader source shows what it holds by reported positions, which status already folds into the mark; once S leaves, opens drops it from records and no source is followed, so the mark is what the node knew.

## Not built
- S does not stay a member of its shared sets while it waits (spec/sync-set.md §3): opens closes it as soon as the engine's sync set drops it. A commit not held elsewhere when S left keeps S waiting (its copy kept) until it is synced again. Same gap for kept unread leaving (issues/sync-unbuilt.md).
