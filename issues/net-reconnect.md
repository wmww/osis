# Cheap reconnects
> Summary: Design: a node keeps, per peer node it shares something with, a durable record keyed by the peer's proven node key: the shared set with what each side proved, the peer's beacons, and a cursor into the peer's node log. After the identity exchange a reconnect sends only beacons whose credentials changed and pulls once from one node-wide durable log; an idle reconnect is a few small messages with no per-sync-ID round. First contact is the same exchange from an empty record (issues/net-shared-set.md). Part of issues/net-rework.md (Tess: important).
> Priority: normal
> Tags: sync, node, proto, spec, tess-call

## Today
Each connection opens every wanted label (one Open each) and resumes each from its own cursor at that peer. Co-reader serving keeps its log in memory (`Feed`, a fresh log ID per start, notes/peers.md), so after a restart peers replay. A reconnect costs at least one round per shared sync ID, idle or not.

## Peer record
The identity exchange (issues/net-connect.md, Rules) proves the peer's node key, so records need no ticket or secret of their own. Per peer node, durably:
- the shared set S: each open sync ID with what each side proved (a shared epoch, a holder judgment, or at a peer that cannot read a sync-key or claim proof at head h);
- the peer's filter as last received, with its generation, and the generation of its own filter the peer last acknowledged;
- its cursor into the peer's node log.

## What a reconnect sends
- **Beacons**: beacons are stable for the pair (issues/net-shared-set.md), so each side sends a `Beacons` diff from the generation the peer last acknowledged: beacons of credentials added since (sync IDs gained, current epochs added) and removed ones. A peer that lacks that base (its record was evicted, its store restored) answers it as unknown and gets the whole set. A side may always send its whole set as a new generation; it does when it no longer holds what a removed beacon needs.
- **Testing**: the peer's added beacons against own beacons; own added beacons against the stored peer filter. So a match caused on either side is found without resending anything else.
- **The shared set**: each side judges S again locally, sends `Lost` for what no longer holds, and offers again (by sync ID) where a credential changed; new role offers go where it has since learned the peer's actor holds something. At a peer that cannot read, an open proved at head h is restored while that peer's head is still h and proved again only where the head moved.
- **Data**: one `Pull` from the cursor (below).

An idle reconnect: the identity exchange, empty `Beacons` both ways, one empty `Pull` reply: under 1 KB and a few round trips, whatever N.

## One node log, one cursor per peer
- Every node keeps one durable log over all sync IDs it holds: events (entry added or stamped, deleted, timed deletion, new head), each with its sync ID, under one sequence and one log ID kept for the store's life. This is the host log of spec/sync.md §4 made node-wide; it replaces `Feed`.
```
Pull   [id, cursor, max_reply, follow]  -> PullReply [id, [[sync_id, event]*], cursor, more]
```
- `Pull` returns the events after the cursor for the sync IDs in S, blobs inline as Sync does. With `follow`, the peer then pushes the same stream live (the existing Push, carrying the node-wide cursor) until the connection ends, so after a drop the next Pull carries only what changed while apart.
- Each side pulls from the other; uploads remain for peers that cannot read (stamped entries they lack).
- A sync ID that joins S is listed from no cursor (spec/sync.md §6 First sync), then follows the stream.
- A cursor the log no longer reaches (trimmed past, or another log ID: the peer's store was rebuilt) is no cursor: each S member is synced as a first sync, deletions inferred as after Error 15. That is the path every newly shared sync ID takes, not a second mechanism.
- **Retention**: as spec/sync.md §4: live entries' add events, deletions for `TOMBSTONE_LIFETIME`. The log is bounded by what the node holds plus recent deletions (notes/growth.md).
- **Restart**: log, records and cursors are durable, so a restart resumes. Ephemeral events are memory-only as at hosts; the sequence never hands out a number twice (a high-water mark). A store restored from a backup takes a fresh log ID.

## Costs
Per reconnect: O(credential changes) beacon bytes and lookups, O(events since the cursor) data, no per-sync-ID message. Per peer stored: about 1.2 B per peer beacon plus 50-100 B per S member.

## Hard cases
- A rotation while apart: the server judges again; offer again or `Lost`, as on a live connection.
- Two connections to one peer at once: one record, one session; the newer takes it and the older closes, as a LAN switch does (issues/net-connect.md, Preferring the LAN).
- A record on one side only: the base is unknown, whole sets both ways.
- Subscriptions and push (spec/sync.md §8): `follow` is the one subscription; per-label Subscribe goes for peer connections.

## Replaces
`Feed` and per-start log IDs; per-(peer, label) cursors and per-label Open, Sync and Subscribe on peer connections; with them the per-connection caps on open labels (4096) and `MAX_SUBS` for peers (spec/wire.md §11.2). Per-label logs at hosts become this log (issues/net-one-peer.md, one serving path).

## Rejected
- **Reconciling per-sync-ID digests**: two readers in sync legitimately hold different entry sets (keep bounds, dropped and covered bodies), so idle sync IDs' digests differ. Comparing the peer's set with one's record of it works, but each changed sync ID then costs its whole standing difference in range reconciliation. The log is exact.
- **Per-sync-ID cursors reconciled over (sync ID, head position) pairs**: works, but two structures where one log and one cursor do.
- **Resumption tickets**: needed only to recognise an unproven peer; the identity exchange proves it.
- **Running first contact on every connection**: one entry per sync ID each time.

## Picked values
Record budget (records and stored filters): resource bound. 0: every connection is a first contact (correct, more bytes); infinite: memory. Past it, evict the least recently used record.

## Mechanisms, counted
One message kind (`Pull`, with its reply; Push reused), one durable log, one record per peer. `Beacons`, `Offer` and `Lost` are issues/net-shared-set.md's, reused with a base generation.

## Unsure
- (design) The record is keyed by the peer's proven node key, but a connection proves the account (issues/account-signing.md): key it by a pair identity that shows no node to another account.
- (design) Bodies in a mesh: on a LAN every pair connects and `Pull`/Push carry bodies inline, so a body may arrive once per connected peer. Check against "nothing a node already holds is sent again" (spec/requirements.md, Cost) before fixing the message shape.
- (design) Counts of added and removed beacons show a peer roughly how many of the node's credentials changed, shared or not. Accept (the peer is a known actor) or pad to a power of two.
- (implementor) Serving `Pull`: scan the log after the cursor, or each S member's events after it, whichever is less (a busy node with a small S).
- (implementor) Joining a newly shared sync ID's first listing to the stream without gaps.
