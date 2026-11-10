# Honest status and waits
> Summary: Status, `wait_synced` and history `complete` judge every sync ID over one set, the nodes connected now with it open whoever dialed: a host by this node's pass, a reader by this node's pull and the reader's reports of this node's log. Synced needs at least one such node and no connection still finding what it shares. Built; what remains is `Refused` by the judged holder and deliveries with nowhere to go. Part of issues/net-rework.md.
> Priority: normal
> Tags: api, node, sync

## Built (notes/api.md Sync configuration and status)
Step 1: `sources(L)` in `SyncEngine::label_status`, the states, the `All`/`Thing`/`Deliveries` scopes, waits that wait, `complete`, the pending delivery with nowhere to go.
- Step 2: both sides of a reader connection pull (issues/net-reconnect.md Built): a reader is a source while the sync ID is in the connection's shared set, caught up once this node's stream from it is read to its end with no body asked and the reader reported applying this node's log of it to the end (Applied; notes/peers.md The stream), so a fresh own write reads `Syncing` until a reader has it; readers count once per proven node, and two connections to one peer close down to one. A reader connection still finding its shared set (dialed, or served with its set begun) is `opening`, and a label with an opening connection is not `Synced`.
- `Thing(t)` waits on every sync ID carrying `t` with at least one source; with none it waits; it ends once this node forgot a `t` it held (nothing carries it and it holds no role).
- `Deliveries` is this node's pending deliveries alone: grant-style CLI commands wait on it. A direct commit to a node has no route outside pairing and counts in no scope.

## Remaining
- An Error answering a Beacons generation is ignored (`shared_message` handles only Shared for it), so that generation stays in flight for good: the connection never settles, counts as opening, and every label it does not share reads `Syncing` (waits on them hang). Its known cause (Beacons sent before the Resumed answer) is fixed; any other Error there would show the same. The fix that follows the rule: an Error ends the generation like a refusal, and the next goes after `resync_ms`.
- `Refused` names saved peers answering 14 (the current mechanism's "a node I hold to serve it"); issues/net-shared-set.md's judged holder replaces it.
- A delivery with nowhere to go (`SentInbox::nowhere`) is retried at `INBOX_LIFETIME`, not when the recipient's inbox gets a node: issues/net-first-contact.md replaces it with offers.

## Gaps in step 1
- A `leave` that lands and forgets before the `Thing` wait begins reads as never carried, so the wait runs to its timeout (a spurious exit 6). Nothing tells a forgotten thing from one never held; a rule ending the wait when nothing carries `t` and no role is held, whether or not it was carried, would close it, but ends a wait on a thing that is not here yet.
