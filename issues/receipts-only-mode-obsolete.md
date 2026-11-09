# Receipts-only sync mode has no reader left
> Summary: `SyncMode::LogOnly` (node-sync's receipts-only reads, `sync/receipts.rs`, `Engine::record_header`, the `r/` receipt records and `Core::header_receipts`) existed for `set_role`'s pre-sync, which is gone (addenda, spec/permissions.md §5.2). Nothing starts a read now; a `LogOnly` group just syncs nothing. Cut the mode, its API surface, the sim scenario `demotion_receipts` and the receipt records, or give the mode a purpose (activity views over unheld groups were the other idea).
> Priority: normal
> Tags: sync, node, api

Frontiers still list header-only receipts (`Engine::frontier` reads the `r/` records), so cutting the records changes nothing observable once no read writes them.

The sim scenario `demotion_receipts` fails every seed since accounts author everything (`Core::me` has no node fallback): after `sim.pair(a, phone)` the phone holds H's item (`knows(u)`), which it holds for receipts only. Cause not found; cutting the mode and the scenario ends it too.
