# Honest status and waits
> Summary: Status, `wait_synced` and history `complete` judge every sync ID over one set, the nodes connected now with it open whoever dialed, and the served side judges too (a pass of its own over the same connection). Synced needs at least one such node. Step 1 is built (the one set of sources, states, scopes, waits, `complete`); step 2, the served side judging by its own pull, remains with issues/net-reconnect.md. Part of issues/net-rework.md.
> Priority: normal
> Tags: api, node, sync

## Built (notes/api.md Sync configuration and status)
Step 1: `sources(L)` in `SyncEngine::label_status`, the states, the `All`/`Thing` scopes, waits that wait, `complete`, the pending delivery with nowhere to go.

## Remaining (step 2, jobs 5-6 of issues/net-rework.md)
- **Both sides judge**: with issues/net-reconnect.md each side of a connection pulls from the other's node log, so every source is judged by this node's own pass and a pair needs one connection, not two. Until then a connection only the other side dialed reads `Syncing` at the served side (a NAT'd node's partner is never `Synced`) and `complete` stays false there.
- With it the arithmetic in `label_status` goes (served sessions beyond the co-readers dialed count as sources, because a session names no node: right when each pair both dialed or neither did, one short for a co-reader that dialed us alone beside one we dialed that did not dial back): one record per peer (issues/net-sync-structure.md (a)).
- `Refused` names saved peers answering 14 (the current mechanism's "a node I hold to serve it"); issues/net-shared-set.md's judged holder replaces it.
- A co-reader dialed one way plus a co-reader only they dialed: the arithmetic pairs them, so `Synced` can read true while the served-only one holds more (`repro_synced_while_a_served_only_source_holds_more`). Step 2 ends it; a session naming its node would too.
- `Thing(t)` judges every group holding `t`, so a group listed in a home group nobody else is connected on never ends the wait, though the group's own sync ID is caught up. (design) Scope to the nearest sync ID carrying `t`?
- `leaving` on a hostless group: a link joiner that left while apart gets code 1 reopening the group at Alice, so the removal never goes and `leaving` stays (`repro_leaving_stays_until_a_source_has_the_removal`, passed before net-role-sync merged). Find why the open is refused.
- CLI delivering commands with no shared thing wait on `All`, so an unrelated group with nobody connected ends them with exit 6 at `--timeout`: they want only their own deliveries.
- A delivery with nowhere to go (`SentInbox::nowhere`) is retried at `INBOX_LIFETIME`, not when the recipient's inbox gets a node: issues/net-first-contact.md replaces it with offers.
