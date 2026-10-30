# undo-creation
- `Tx::scan(prefix, f)` hands `f` the key with the prefix stripped (not documented at `scan`); reading the tid again gave `Storage("short record")`.
- review: `not_undoable_past_history_cap` set its cap (2000 B) just above one entry's charged size; growing `Entry` by 48 bytes emptied the log and failed it with an opaque `0`. Cap raised to 8000.
- re-review: the restart hole (a synced draft's ephemeral placement returns from the server with no `drafts` entry) only showed in a node-level `Net` test; osis-level tests cannot restart with synced ephemeral state.
