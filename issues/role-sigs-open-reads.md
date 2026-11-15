# An open reads every account role commit's record for its signatures
> Summary: `index::load` rebuilds `Indexes::role_sigs` by reading the record of every held role commit at an epoch, against the engine's rule that an open reads no commit record; keep the signatures with a row already written per commit instead.
> Priority: low
> Tags: engine

`role_sigs` (inner and merge signatures of each role commit at an epoch, read by `Core::devices_read` and merge verification) is not persisted: `index::load` scans `ix.commits` for role commits at an epoch and calls `get_commit` on each. Every grant, demotion and rotation an account makes is one, so a node holding large groups reads and decodes thousands of records at each open. Every other derived index is persisted or rebuilt from rows, so an open reads no commit record (notes/engine-store.md `c/`).

A separate `node/role sigs` table was dropped because it cost one store page per role commit applied (`scale::role_history_join_is_linear` went past linear). Keep the signatures in a row each role commit writes anyway (its `node/metas` row, or its `node/edges` row, written with the commit record), so neither apply nor open pays an extra read or page. Count record reads at an open with n and 10n role commits held.
