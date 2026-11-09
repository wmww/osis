# Cheap reconnects
> Summary: Settled design, one mechanism with issues/net-shared-set.md: a durable per-peer record found by a pair key both nodes hold (no node identity), one node-wide durable log with opaque cursors, one Pull/Push stream per peer gated by the shared set; a member joins the stream through the same Pull, from a position or from the start. A reconnect costs what changed; a cursor the log no longer reaches restarts the one stream from the start, never a message per sync ID. Everything recorded is a cache: losing it is a first contact. A peer may recognise the same device reconnecting (Tess; spec/requirements.md). Model first. Part of issues/net-rework.md (Tess: important).
> Priority: normal
> Tags: sync, node, proto, spec

## The rule
issues/net-shared-set.md's: what is shared is judged on what a node holds now; a record says only what need not be sent again. So a reconnect is a first contact that skips what the record proves was already sent, and losing the record is a first contact.

## The record
A node keeps, per peer node it has shared something with or whose known actor it has met, a durable record **found by the pair key r**, never by a node key:
- `r`, 32 random bytes known only to the two nodes (issues/net-shared-set.md, The pair key);
- `actors`: the proven actors last seen;
- the peer's filter and its generation;
- `sent_gen`, `acked_gen`, and `acked_pos`: the position of the node log up to which the peer has acknowledged this node's filter and every Offer from testing it has been answered (a position below which nothing is pending, issues/net-shared-set.md Testing);
- `judged_pos`: the node log position up to which S was re-judged;
- the set S: each open sync ID with what each side proved, an optional `lag` (a cursor) when it is out of the stream, an optional `until` (a position) when it is being ended;
- `cursor`: its opaque position in the peer's node log.

A session finds its record by r; r is honoured only for a session whose proven actors meet the record's `actors` (a revoked node cannot prove the account, so cannot use a record).

## Resume
After the identity exchange (issues/net-connect.md), with a peer that proved a known actor:
```
Resume   [id, nonce, [tag*]]       -> Resumed [id, nonce, Opt(tag)]
```
- The dialer sends a fresh nonce and `tag = BLAKE3(key = r, "resume" || dialer challenge || listener challenge)` of every record whose `actors` include a proven actor of this session, most recent first, as many as fit one message. The listener compares each against its records with a matching actor and answers the tag of the one it holds, or none (itself a proof it holds r). `r` = that value, else `kdf("pair key", dialer nonce, listener nonce)` and a new record on each side.
- r itself never crosses again: a list shows other nodes of that account only tags keyed by r values they do not hold, and the peer's lookup is O(its records of that account).
- Two connections to one peer: one record, one session; the newer takes it and the older closes, as on a LAN switch (issues/net-connect.md).
- A connection that proved no known actor gets no record and no Resume; `r` for the filter a node serving sync IDs unread sends on it (issues/net-shared-set.md, Peers that cannot read) is `kdf("pair key", dialer challenge, listener challenge)` of the connection, sent nowhere and kept nowhere.

## What a reconnect sends
After Resume, in this order, none of it per sync ID that is unchanged:
1. **Beacons**: `changed_at` (below) entries after `acked_pos`, as additions at `gen = sent_gen + 1`, `base = acked_gen`; on code 13 or a doubling (issues/net-shared-set.md), a whole filter.
2. **Testing**: the pending set (issues/net-shared-set.md Testing), on every arrival of the peer's filter.
3. **The shared set**: each side re-judges S members whose L has `changed_at > judged_pos` (issues/net-shared-set.md rule), advancing `judged_pos` only once its Offers and Lost are answered. If the session's proven actors differ from the record's, it re-judges every held L (admissible credentials, S, ByRole) and sends a whole filter (rare, brute force). New opens go by Offer.
4. **Data**: one `Pull`. `Lost` for a member stopped while apart, or still marked ending, goes after the Pull arrives, its cursor = the Pull's own (the position this requester holds): the member is out of the reply, and nothing before that cursor is lost. A stop with a set `until` keeps its position.

An idle reconnect, unchanged credentials, roster and stream: identity exchange; `Resume`; empty `Beacons` both ways; one empty `PullReply`. Under 1 KB and a few round trips, whatever the number of sync IDs.

## Changes: `changed_at`
Each held sync ID has `changed_at`, a position of the node log, advanced on: a new sync ID, a new current credential, a role change on its thing or an actor reaching it. One index (changed_at, sync ID), one entry per sync ID: bounded by what the node holds, nothing to trim. A diff recomputes the current beacons of each changed sync ID for this pair; duplicates are harmless (multiset, additions only).

## One node log, one cursor
- One durable log over every sync ID the node holds: events (entry added or stamped, deleted, timed deletion, new head), each with its sync ID, one sequence, one log ID for the store's life. This is spec/sync.md §4's log made node-wide; it replaces `Feed`.
- A **cursor** is an opaque AEAD seal of `(log ID, incarnation, sequence)` under a durable per-log key: a peer learns neither node-wide activity nor sequence gaps. Every store start draws a new **incarnation** and records the end position of the one before (issues/net-restored-store-cursor.md). A cursor that does not open, a position past the log's end, one on no incarnation of this store's own history, or one below the **horizon** (the position of the newest deletion event the log has dropped, kept durably, 0 if none: below it deletions are gone, so a diff from there would miss them, issues/net-horizon-floor.md) is no cursor.
- **Retention** (spec/sync.md §4 made node-wide): the log keeps each held entry's latest add or stamp event (an entry's earlier events drop when a later one is logged) and deletion events for `TOMBSTONE_LIFETIME`; it is compacted, never trimmed by position. So it is bounded by what the node holds plus recent deletions (notes/growth.md), and a listing from its start is the node's live set of every sync ID.
```
Pull      [id, Opt(cursor), [join*], inline_limit, max_reply, follow, ephemeral] -> PullReply [id, [[sync_id, event]*], cursor, whole, more]
  join = [sync_id, Opt(cursor)]
```
- `Pull` returns, in log order, the events after `cursor` for the members of S with no `lag`, and for each `join` (a member entering the stream: newly open, or rejoining from its `lag`) that member's events after its own cursor, from the start when it has none. With no `cursor`, or one that is no cursor, the reply is the stream from the start for all of S, `whole` set. A reply from the start for a member (a `join` without a cursor, or `whole`) is a **listing**: it proves what is present and deletes nothing (issues/net-listing-inference.md). One form for a first contact, a reconnect, a sync ID that joins or rejoins, and a node back after `TOMBSTONE_LIFETIME`; no message per sync ID in any of them. Which to scan, the log after a position or a member's entries, is the implementor's per request (Unsure). With `follow`, the peer then pushes the same stream live (the existing Push, carrying this cursor).
- Both sides pull. Readers no longer upload to readers; own writes reach readers by the stream. Uploads stay at peers that cannot read (stamped entries they lack, spec/sync.md §5).
- **Bodies** (spec/requirements.md, "Nothing a node already holds is sent again"): `inline_limit` is the requester's. A requester with more than one source open on any sync ID of the stream sets it to 0: events carry IDs only (an announcement of about the fixed overhead per connected peer), and it fetches what it lacks, one source at a time per blob ID, the next only when that source fails. A requester with one source sets it to its inline preference. So in a mesh of m peers a body crosses once; the announcement crosses m-1 times.
- **Ephemeral**: entries are memory-only, in the log's memory part (no restart ever reuses a sequence; high-water mark). `ephemeral` true on a node's first Pull after its start: the reply also carries the serving node's live ephemeral entries for S. O(live ephemeral), one message; replaces the per-sync-ID `gained` listing and first-pass reconciliation. A connection that was merely down resumes by cursor; an ephemeral log lost at a restart gives live entries as spec/sync.md §5.

## Joining and rejoining
- **Joining** S (a sync ID newly open): the server adds L to the stream, and the requester's next `Pull` names it in `join` with no cursor: its listing arrives in the stream's order with everything after. Events the listing also shows are deduped by blob ID. Gap-free by order. A join in pages keeps its own position (its `lag`) until the last page; only then is it in the stream. A join of a member the server does not share is answered, never treated as an empty success. Opens from one Offer batch join in one Pull: a first contact sharing 10^4 sync IDs is one Pull with 10^4 joins and one paged reply.
- **Lost and rejoin**: `Lost [L, c]`: the cursor where L stopped for this receiver: the server's `until` position, or for an immediate `Lost` the end of what this connection's stream has delivered (the last cursor returned), `Lost` written in order after it. The receiver stores `lag = c`, or keeps an older one. When L rejoins: `join = [L, lag]` in the next Pull, L's events after that position. Cost: the events L missed, no listing. The server's `until` for a member ends the stream at the rotation event inclusive (issues/net-shared-set.md, Opens).
- **Back after a long absence**: a node whose cursor is below the peer's horizon (away past `TOMBSTONE_LIFETIME`, 30 days; or the peer's log has another ID or a rebuilt store) gets the stream from the start, `whole`: one paged listing of the peer's live set over S, bodies by `inline_limit`. O(live entries of S) IDs, no round trip per sync ID. A deletion older than the horizon is not carried; retention judges a stale entry the node still holds. What is spent is the cost of the diff that could not be kept, nothing the stream form adds.

## Restart and loss
- Log, records and cursors are durable: a restart resumes. A store restored from a backup is detected by nothing, and needs nothing detected: its next start ends the old incarnation at the restored position, so cursors past it are no cursor and every peer gets a stream from the start (issues/net-restored-store-cursor.md).
- A cursor is stored only with what it covers applied, and a position is issued only for durable events: a cursor never runs ahead of the data it names.
- Lost record on one side: the Resume list finds nothing, new r, whole filters, S rediscovered, one listing. On the other side the orphan record is unused, evicted by LRU.
- Partial loss: atomic per record, so either whole or none.

## Adversaries
- **A peer flooding `Resume`, `Beacons`, `Pull`**: the list is one message; lookup per entry. Filter pages linear (issues/net-shared-set.md). `Pull` bounded by `max_reply` and the flow control of spec/sync.md §6.
- **Restart losing the record**: first contact; no incorrect state, no leak beyond a first contact. A peer holding a stale copy of a whole-filter `gen` or `cursor` gets a base-unknown or no-cursor: it cannot influence opens, whose judgment is local.
- **Clock-skewed peer**: nothing in this design reads a clock. Filters, generations and cursors are sequences; judgment reads roles with `until` disregarded (spec/crypto.md §4). A skewed clock affects only the node's own writes (issues/clock-peer-offset.md).
- **Revoked node of a known actor**: Resume needs the session to prove an actor in the record's `actors`; it cannot at a closed epoch where the removal is held (issues/account-signing.md). Fork window: account signing's limit. Its r is then just a random value.

## Costs
With N held sync IDs, P peers, C changes since the last connection:
- **Per reconnect**: O(C) beacon bytes and hashes; O(events since the cursor) data, or O(live entries of S) listed when the cursor is below the horizon; no per-sync-ID message in either; local re-judging O(C) (O(S) only when the proven actors changed).
- **Per peer stored**: about 1.2 B per peer credential (filter) plus 50-100 B per S member.
- **Idle reconnect**: under 1 KB, a few round trips, whatever N.

## Hard cases
- A rotation while apart: the server's `until` stops L at the rotation (issues/net-shared-set.md, Opens); a holder rejoins by an added beacon.
- A record on one side only: base unknown, whole filters both ways.
- Subscriptions and push: `follow` is the one subscription; per-label Subscribe and Open are gone between readers.

## Replaces
`Feed` and per-start log IDs; per-(peer, label) cursors, per-label Open, Subscribe and Sync between readers (spec/sync.md §6 First sync and Cursor sync, spec/wire.md §11.2 Sync; the listing is a `join`); the per-connection caps on open labels (4096) and `MAX_SUBS` between readers (spec/wire.md §11.2); Error 15 and the trim position (the horizon is read from the log). Per-label logs at hosts become this log (issues/net-one-peer.md).

## Rejected
- **Reconciling per-sync-ID digests**: two readers in sync legitimately differ in entry sets (keep bounds, dropped and covered bodies): idle sync IDs would differ. The log is exact.
- **Per-sync-ID cursors reconciled over (sync ID, position) pairs**: works, but two structures.
- **A per-member first sync (`Sync(L, no cursor)`) for a join or a cursor below the horizon**: one round trip per sync ID, 10^4 of them for a phone back after a month or a first contact sharing 10^4, the cost this design exists to remove; the stream from the start lists the same entries in one paged reply.
- **A log trimmed by position with Error 15**: the log's retention already keeps every live entry's event, so "retained events plus trimmed below T" and "the stream from the start" are one reply; a trim position is one more value to keep and send.
- **Keying a record by a node key or dialable key**: a connection proves accounts (issues/account-signing.md), and a LAN listener has a fresh key per join; keying by r needs neither. **Tickets minted by one side**: same lookup, but one side must trust the other's minting; a pair value is symmetric.
- **Running first contact on every connection**: one entry per sync ID each time.
- **Storing a table of the peer's beacons, or own beacons per peer**: each side tests only its additions.

## Picked values
- **`RECORD_BUDGET`** 256 MiB total per node of durable records, resource bound: 0 is every connection a first contact (correct, more bytes), infinity is disk. Past it, evict the least recently used record not in use. A filter that would not fit is tested as it arrives and not stored: that peer is a first contact next time; no connection closes for it.

## Model
core/test/tla/net (TLC), both halves of this design with issues/net-shared-set.md; its README lists scenarios and state counts. Over restarts, record loss, deletion expiry, restored and copied stores, drops, role changes on one side and one-way dialing, each checked over all interleavings at small size:
- No node drops a write nobody deleted; a source judged caught up holds nothing this node lacks; nothing is served after the right is lost; a reconnect sends what changed; the connection settles; S is exactly the rule on what each side holds.
- It forced four changes: a listing proves presence only (issues/net-listing-inference.md), the horizon is the newest dropped deletion (issues/net-horizon-floor.md), a cursor is honoured only on the store's own history (issues/net-restored-store-cursor.md), and each Pull carries a digest of S (issues/net-shared-set-divergence.md).
- Rules the design relies on, each failing the properties when removed: pending set, ack after Offers, arrival test before later messages, the tag, ByRole, Lost's older lag, a join's own position, a join answered, the cursor applied before stored, a change announced during a Pull denying that Pull's caught-up, the server's S read per reply, both sides pull.
- Not modelled: more than one peer, key actors and covers, deposits, peers that cannot read, account proofs, filter pages and false positives, inline bodies, ephemeral entries, record eviction.

## Steps
issues/net-shared-set.md, Steps: this issue is 4, 6, 7.

## Tests (tier 1, over issues/net-tests.md)
An idle reconnect sends no per-sync-ID message (counted); a restarted node resumes; a lost record is a first contact and converges; a rotation while apart rejoins from its lag and refetches only the missed events (counted); a node back after the peer compacted deletions past its cursor converges with the messages of one stream (counted at n and 10n sync IDs: no term in n beyond pages) and holds no deleted entry; a first contact sharing n sync IDs joins them in O(1) Pulls (counted); a mesh body crosses once with announcements per peer (counted); a skewed clock changes nothing.

## Unsure
- (implementor) Serving `Pull`: scan the log after the cursor, or each member's events after its position (a join from the start: the member's entries), whichever is less (a busy node with a small S; one join among a large stream).
