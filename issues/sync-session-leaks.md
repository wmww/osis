# Two in-memory leaks in streams and suspect lists
> Summary: `Streams::pull_anew` loads a `Place` for every record holding a row of S (told rows, or any row of S) and nothing drops it unless a pulling connection of that record closes, so places of records never connected again, and of evicted records, stay for the session (grows with record churn times head moves and anew marks). `Suspects` keeps S followed in `synced` and in `first` when a list waiting for this node's first sync of S leaves (`left`/`closed`) before that sync ends: the idle unwant only sees S in `moved`.
> Priority: normal
> Tags: sync

- Places (core/sync/src/streams/pull.rs `pull_anew`, `place`; remover only `Streams::closed`, streams/mod.rs): at the end of `pull_anew`, drop the place of each record source no connection pulls from (its rows are already written), or write the record rows without caching a place. Test: n records each told a refusal under head h, none connected; move the head k times; `places` stays at the connected count (n vs 10n).
- Suspects (core/sync/src/inbox/suspect.rs, `synced`/`first`, idle unwant after the settle loop): put S in `moved` (or judge idleness) whenever `waiting` loses its last entry for S. Low on its own: one followed key per such S.
