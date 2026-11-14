# Stranded reports and inbox chains use keysets the node does not follow
> Summary: Three rules assume the node reads a thing it may hold only sync (or chain projections) on: `own_holder` (core/node/src/sync/reports.rs:101) picks a team the account holds any role on, sync included, as the holder it reads through; `holder_keys` sends that holder's `Engine::current_keys` (labeling/certs.rs:317), the greatest keyset held, a frozen snapshot at a keeper; `send_inbox` (sync/local.rs:410-421) carries the chain and the thing's `keys.0` to every holder below read ("a grant's recipient reads the thing", false for a sync grant), and `accept_inbox` (flows/edges.rs:664) ingests it all. This is where issues/sync-only-chain.md's stale keeper `keys.0` and the failed re-seal come from.
> Priority: normal
> Tags: node, engine, sync

Fix shape: `own_holder` takes only a holder the node reads (`readable`), else its account; a sync grant's inbox blob carries the box and label IDs only (no chain, no `keys.0`), or, per notes/cannot-read-audit.md (Proposal), a keeper keeps a sync record and no engine state of the thing. Check against the five osis tests issues/sync-only-chain.md lists.
