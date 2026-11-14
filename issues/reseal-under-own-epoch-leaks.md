# Content another wrote, encrypted again under the sealer's epoch
> Summary: Built (spec/crypto.md §5 Passing on, `labeling::opened`, Reseal.tla; sync's one caller `Engine::seal_body`): a node encrypts another's part under an epoch it chooses only while an epoch it opened that part (or, for the header, unwrapped an entry of the commit) under is established there. Left: content read in no section still passes on (snapshots of it included).
> Priority: normal
> Tags: security, keys, engine

The leak (reproduced: `rotation::tests_reseal`): a2 removes reader M (W); R, holding W, rotates read (e_R, boxing V and not M) and writes under it. V holds e_R's secret but not W (a peer withholds it, or V holds A's demotion of a2 that voids W: the withdrawn-epoch shape), so e_R is not established at V and V's newest epoch is one M holds. A fresh encryption of R's write by V, a wrap of a blob of it, or V's compaction snapshot of the aspect, put R's content under V's epoch: M read it. Breaks spec/requirements.md Permissions ("removing a holder never re-encrypts existing content"; "stops reading new content once a writer has written after the removal").

The rule and where it lives: notes/crypto.md (Passing on content), notes/sync-facade.md (Sealing). Facade tests: `rotation::tests_reseal::facade_*`.

## Open
- **Content read in no section passes on** (`labeling::opened::passes_on`): a part whose openings are empty passes as the node's own. Every blob still needs a wrap, and the wrap's epoch is recorded as a header opening (`note_unwrapped`), so content read from a per-sync-ID copy is never wrapped under an unestablished-reader's epoch; but a snapshot (`retention::snapshot::may_snapshot`) reads only part openings, so V can compact an aspect holding R's write it read only from a copy (or an inbox payload) under its own epoch. Fixes: count header openings for a part with no section opening (a copy's content came under its wrap's epoch), or fail closed (safe and live in the model, `RS_closed`; LocalPeer's plain delivery, the engine tests' main harness, carries every commit in no section, 13 engine tests compact aspects so).
- Reseal.tla models section openings only: the header opening by a wrap's epoch (`note_unwrapped`) is not in it.

## Limits
- An aspect holding a write this node read only under an epoch not established here (withheld removal, or a withdrawn epoch: never established) is not compacted by this node while so. Not a new growth: other writers' valid snapshots still drop its bodies here (spec/sync-compaction.md §1), and its size is that of the writes, as with no compaction.
- A wrap whose epoch is not among the thing's own or first-admin-derived epochs held (a thing whose `created.0` is not here, opened by a key actor's derived secret) records no header opening.
