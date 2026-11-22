# A container wrongly marked undoable is caught by no world test
> Summary: `memo::Undoable` keeps a frame's reads across a rolled-back `Engine::run` for containers marked undoable; marking one a rollback does not restore exactly (every container, or the sync store) fails no sync test, the effects checker included.
> Priority: normal
> Tags: tests, engine, memo

`Stamps::undoable` is a claim that a rollback restores the container exactly; a false claim is a stale memo (a silent wrong read). Mutation probes (`tools/mutate.py`) over osis-sync `holding::`, `inbox::` and `differential::histories_hold_their_closure_plain`: `!table.undoable` -> `false` in `memo::undo_note` (every container undoable, followers' outputs and caches included) and the sync store's rows undoable each fail nothing; only `memo::effects::tests::a_settle_undoing_its_own_writes_moves_only_with_what_it_read` catches the first. The sync store's memory part was such a false claim (the engine's memory holds commit there at once).

Wanted: a check that fails when an undoable container is written in a stretch and left differing after the rollback, e.g. debug builds comparing each undoable container written in an undone stretch with its contents at the stretch's start (the journaled ones expose `contents` in tests), or a hand-made world where a frame runs a refused trial over each undoable container and the effects checker compares.
