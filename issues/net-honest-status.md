# Honest status and waits
> Summary: Status, `wait_synced` and history `complete` judge every sync ID over one set, the nodes connected now with it open whoever dialed, and the served side judges too (a pass of its own over the same connection). Synced needs at least one such node. Step 1 is built (the one set of sources, states, scopes, waits, `complete`); step 2, the served side judging by its own pull, remains with issues/net-reconnect.md. Part of issues/net-rework.md.
> Priority: normal
> Tags: api, node, sync

## Built (notes/api.md Sync configuration and status)
Step 1: `sources(L)` in `SyncEngine::label_status`, the states, the `All`/`Thing`/`Deliveries` scopes, waits that wait, `complete`, the pending delivery with nowhere to go.
- A served session is its own source, not caught up, unless it proved by a co-reader proof that it is a node this node has a connection to with the sync ID open (`name_sessions`); a dialer names itself only to a known co-reader.
- `Thing(t)` waits on every sync ID carrying `t` with at least one source; with none it waits; it ends once this node forgot a `t` it held.
- `Deliveries` is this node's pending deliveries alone, direct commits to a node included: grant-style CLI commands wait on it.

## Remaining (step 2, jobs 5-6 of issues/net-rework.md)
- **Both sides judge**: with issues/net-reconnect.md each side of a connection pulls from the other's node log, so every source is judged by this node's own pass and a pair needs one connection, not two. Until then a connection only the other side dialed reads `Syncing` at the served side (a NAT'd node's partner is never `Synced`) and `complete` stays false there.
- With it served sessions need no name: one record per peer (issues/net-sync-structure.md (a)).
- `Refused` names saved peers answering 14 (the current mechanism's "a node I hold to serve it"); issues/net-shared-set.md's judged holder replaces it.
- A delivery with nowhere to go (`SentInbox::nowhere`) is retried at `INBOX_LIFETIME`, not when the recipient's inbox gets a node: issues/net-first-contact.md replaces it with offers.

## Gaps in step 1
- `Command::Name`, `Pending::Name` and `named` are interim: proof 3 and a re-Open on an open label are not in spec/wire.md; issues/net-shared-set.md replaces them.
