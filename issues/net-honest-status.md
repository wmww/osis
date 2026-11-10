# Honest status and waits
> Summary: Status, `wait_synced` and history `complete` judge every sync ID over one set, the nodes connected now with it open whoever dialed, each judged by this node's own pass or pull. Synced needs at least one such node. Built, with one open question: a reader source is caught up by this node's pull alone, so this node's own writes the reader has not pulled yet do not hold `Synced` back. Part of issues/net-rework.md.
> Priority: normal
> Tags: api, node, sync

## Built (notes/api.md Sync configuration and status)
Step 1: `sources(L)` in `SyncEngine::label_status`, the states, the `All`/`Thing`/`Deliveries` scopes, waits that wait, `complete`, the pending delivery with nowhere to go.
- Step 2: both sides of a reader connection pull (issues/net-reconnect.md Built): a reader is a source while the sync ID is in the connection's shared set, caught up once this node's stream from it is read to its end with no body asked; readers count once per proven node, and two connections to one peer close down to one.
- `Thing(t)` waits on every sync ID carrying `t` with at least one source; with none it waits; it ends once this node forgot a `t` it held (nothing carries it and it holds no role).
- `Deliveries` is this node's pending deliveries alone: grant-style CLI commands wait on it. A direct commit to a node has no route outside pairing and counts in no scope.

## Remaining
- **Own writes at a reader source** (design question): a host source is not caught up while this node's pass has something to place (the label is dirty); a reader source has no such term, so a local write reads `Synced` before the reader pulled it. A rule: a reader is caught up only when this node also served it its log's end (the connection's follow position at the log's end, no local placement pending). Tests waiting on it: osis-sim `no_server::a_local_write_leaves_synced_and_last_sync_says_when`; `a_served_only_connection_is_synced_at_the_dialer_and_syncing_at_the_served_side`, `synced_is_never_true_while_a_served_only_source_holds_more`, `a_thing_wait_covers_a_source_further_up` and `a_thing_wait_does_not_end_when_only_its_carrier_went` assume a served-only connection is never caught up and need new premises (both sides now pull).
- `Refused` names saved peers answering 14 (the current mechanism's "a node I hold to serve it"); issues/net-shared-set.md's judged holder replaces it.
- A delivery with nowhere to go (`SentInbox::nowhere`) is retried at `INBOX_LIFETIME`, not when the recipient's inbox gets a node: issues/net-first-contact.md replaces it with offers.

## Gaps in step 1
- A `leave` that lands and forgets before the `Thing` wait begins reads as never carried, so the wait runs to its timeout (a spurious exit 6). Nothing tells a forgotten thing from one never held; a rule ending the wait when nothing carries `t` and no role is held, whether or not it was carried, would close it, but ends a wait on a thing that is not here yet.
