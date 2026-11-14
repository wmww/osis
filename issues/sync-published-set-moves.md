# A thing published under an actor re-judges every body under it
> Summary: `BodyCtx::published` (`Engine::published_under`, a `memo::Spread` entry per actor) is read whole by every body judgement under the actor's sync IDs, so a labeled thing coming to be published under an actor re-judges every (S, commit) there; per-thing membership (as `groups::Closure` reads its closure) would move only the commits on that thing.
> Priority: low
> Tags: engine, sync

- Measured (osis-sync differential, seed 5 of `history(5, 3, 40, true)`, `read: judged <- ...` causes under `costs`): the published entry is the largest engine cause left, about 190 of 875 judgements; the rest are first judgements, a commit's blobs changing, store rows.
- Shape of a fix: `BodyCtx::published` as a view read per tid (`Row`-style stamps on the `Spread`'s entries), its `iter` (label_bodies_meta) read whole.
- The derivation side of each read thing's certificates (`sync_certificates`, whole per thing, followed by `sync::certified` so its readers move per commit) is still recomputed whole at every move of its component.
