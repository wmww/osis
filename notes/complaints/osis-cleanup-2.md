# osis-cleanup-2
> Summary: footguns met while trimming the osis crate (second pass).

- `tools/loc.py` moves little for a dedup that names a concept (`ReadAs` cost 10 lines to replace a dozen hand-built readers): the line count undersells merges of knowledge, as it oversells deletions of doc comments.
- A local listener's callback is handed the node's own handle (`Osis::internal`, acting `None`), not the subscriber's: `on_grants_change` re-reads `db.grants` there, so on an `act_as` handle it would re-read as the node. Unreachable today (the port's Sub reads through `serve::watch` as the session's actor), but easy to miss when adding a listener: capture `read_as()` instead.
