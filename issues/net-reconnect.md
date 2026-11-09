# Cheap reconnects
> Summary: Settled design, one mechanism with issues/net-shared-set.md: a durable per-peer record found by a pair key both nodes hold (no node identity), one node-wide durable log with opaque cursors, one Pull/Push stream per peer gated by the shared set; a member joins the stream through the same Pull, from a position or from the start. Principle: a record says only what need not be sent again, so a connection first proves the two records agree (a digest of S, first in each direction), then sends what changed; nothing is inferred from absence. A reconnect costs what changed, however long a node was away. Everything recorded is a cache: losing it is a first contact. A peer may recognise the same device reconnecting (Tess; spec/requirements.md). Model first. Part of issues/net-rework.md (Tess: important).
> Priority: normal
> Tags: sync, node, proto, spec

## The rule
issues/net-shared-set.md's: what is shared is judged on what a node holds now; a record says only what need not be sent again. So a reconnect is a first contact that skips what the record proves was already sent, and losing the record is a first contact.

## The record
A node keeps, per peer node it has shared something with or whose known actor it has met, a durable record **found by the pair key r**, never by a node key:
- `r`, 32 random bytes known only to the two nodes (issues/net-shared-set.md, The pair key);
- `actors`: the proven actors last seen;
- the peer's filter and its generation;
- `sent_gen`, `acked_gen`, and `acked_pos`: the node log position below which nothing is pending: the peer has acknowledged it, this node has tested it, and no Offer from that test is unanswered (issues/net-shared-set.md Testing);
- `judged_pos`: the node log position up to which S was re-judged;
- the set S: each open sync ID with what each side proved, an optional `until` (a position) while it is being ended, and its `lag` (a cursor) while a join of it is in pages;
- beside S, the `lag` of each sync ID a `Lost` stopped, kept for its rejoin: not a member of S, not in the digest;
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
0. **Digest**: the first message each way (Agreement, below), then `Members` on a difference.
1. **Beacons**: `changed_at` (below) entries after `acked_pos`, as additions at `gen = sent_gen + 1`, `base = acked_gen`, one generation in flight per direction (the next waits for its Status, so `base` is what the peer holds; the sender remembers the log position each generation reached); on code 13 or a doubling (issues/net-shared-set.md), a whole filter.
2. **Testing**: the pending set (issues/net-shared-set.md Testing), on every arrival of the peer's filter.
3. **The shared set**: each side re-judges S members whose L has `changed_at > judged_pos` (issues/net-shared-set.md rule), advancing `judged_pos` only once its Offers are answered and its `Lost` sent. If the session's proven actors differ from the record's, it re-judges every held L (admissible credentials, S, ByRole) and sends a whole filter (rare, brute force). New opens go by Offer.
4. **Data**: one `Pull`, sent only once the peer's Digest has arrived. `Lost` for a member stopped while apart goes after the Pull arrives, its cursor = the Pull's own (the position this requester holds): the member is out of the reply, and nothing before that cursor is lost. A stop with a set `until` keeps its position, and its `Lost` goes only after a Pull's cursor has passed `until`.

An idle reconnect, unchanged credentials, roster and stream: identity exchange; `Resume`; a digest and empty `Beacons` both ways; one empty `PullReply`. Under 1 KB and a few round trips, whatever the number of sync IDs.

## Agreement
A connection's first message each way after `Resume` is `Digest [d]`, unanswered, `d` the xor over S's open members of `BLAKE3(key = r, sync_id)`, 32 bytes, computed from the record before anything else on the connection (Rejected, per-Pull digest). Only the sync IDs count: what each side proved differs between the two records and a stopped member's `lag` is not in S. A side compares the peer's `d` with the `d` it sent, not with S as it is by then. It is the only comparison of the two records and it runs once per connection: inside a connection S changes only by that connection's messages, in order, so the two copies differ only across a connection's end (a store restored or copied, a reply or `Lost` lost with its connection). A digest that matches ends it. On a difference each side sends its member list (`Members [[sync_id*], more]`, unanswered, paged, brute force and rare) in full as it reads the peer's `Digest`, before it acts on any later message, and for every member the peer's list lacks: closes it, no `lag`, and marks its credentials pending, on both sides. So a dropped `Lost` needs no resending, a member only one side holds is out on both and found again by the shared set's own rule (a Hit, a ByRole, or nothing if the rule no longer holds), and rejoining is a listing, which is exact where the cursor would not be. Each direction's digest precedes that direction's every other message, its list precedes every Offer or Status it answers with, no Offer (Hit or ByRole) is sent before the peer's `Digest` is read, and no open happens before the peer's digest (on a difference, its last `Members` page) is read, so an open made on this connection never crosses a digest or a list. The digest repair runs once a connection and only ever closes members or marks credentials pending: it ends.

## Changes: `changed_at`
Each held sync ID has `changed_at`, a position of the node log, advanced on: a new sync ID, a new current credential, a role change on its thing or an actor reaching it. One index (changed_at, sync ID), one entry per sync ID: bounded by what the node holds, nothing to trim. A diff recomputes the current beacons of each changed sync ID for this pair; duplicates are harmless (multiset, additions only).

## One node log, one cursor
- One durable log over every sync ID the node holds: events (entry added or stamped, deleted, timed deletion, new head), each with its sync ID, one sequence, one log ID for the store's life. This is spec/sync.md §4's log made node-wide; it replaces `Feed`.
- A **cursor** is an opaque AEAD seal of `(log ID, incarnation, sequence)` under a durable per-log key: a peer learns neither node-wide activity nor sequence gaps. A cursor that does not open, a position past the log's end, or one on no incarnation of this store's own history is **no cursor**.
- An **incarnation**: the first log append after a store start draws a new one and records the end position of the one before; a start that appends nothing costs nothing, and a cursor it issues names the incarnation still current. A store restored from a backup, or a copy running beside the original, needs no detection: its next append ends the old incarnation at the restored position, so a cursor from the lost store is past it and one from a sibling copy names an unknown incarnation. A cursor at a position the store's own history holds names what it covers.
- **Retention** (spec/sync.md §4 made node-wide, trimmed by compaction alone): the log keeps each held entry's latest add or stamp event (an entry's earlier events drop when a later one is logged) and deletion events for `TOMBSTONE_LIFETIME`; it is compacted, never trimmed by position. So it is bounded by what the node holds plus recent deletions (notes/growth.md), and a listing from its start is the node's live set of every sync ID.
```
Pull      [id, Opt(cursor), [join*], inline_limit, max_reply, follow, ephemeral] -> PullReply [id, [[sync_id, event]*], cursor, whole, more]
  join = [sync_id, Opt(cursor)]
```
- `Pull` returns, in log order, the events after `cursor` for the members of S with no `lag`, and for each `join` (a member entering the stream: newly open, or rejoining from its `lag`) that member's events after its own cursor, from the start when it has none. With no `cursor`, or one that is no cursor, the reply is the stream from the start for all of S, `whole` set. A reply from the start for a member (a `join` without a cursor, or `whole`) is a **listing**: the log's events for it from the start, so what is present plus the deletions the log still holds, and it never treats an absent entry as deleted: a node's entries are not all at any peer (a write of its own that has not reached this peer, anything this peer never received or lost in a restore). One form for a first contact, a reconnect, and a sync ID that joins or rejoins; no message per sync ID in any of them. Which to scan, the log after a position or a member's entries, is the implementor's per request (Unsure). With `follow`, the peer then pushes the same stream live (the existing Push, carrying this cursor).
- Both sides pull. Readers do not upload to readers; own writes reach readers by the stream. Uploads stay at peers that cannot read (stamped entries they lack, spec/sync.md §5).
- **Bodies** (spec/requirements.md, "Nothing a node already holds is sent again"): `inline_limit` is the requester's. A requester with more than one source open on any sync ID of the stream sets it to 0: events carry IDs only (an announcement of about the fixed overhead per connected peer), and it fetches what it lacks, one source at a time per blob ID, the next only when that source fails. A requester with one source sets it to its inline preference. So in a mesh of m peers a body crosses once; the announcement crosses m-1 times.
- **Ephemeral**: entries are memory-only, in the log's memory part (no restart ever reuses a sequence; high-water mark). `ephemeral` true on a node's first Pull after its start: the reply also carries the serving node's live ephemeral entries for S. O(live ephemeral), one message; replaces the per-sync-ID `gained` listing and first-pass reconciliation. A connection that was merely down resumes by cursor; an ephemeral log lost at a restart gives live entries as spec/sync.md §5.

## Joining and rejoining
- **Joining** S (a sync ID newly open): the server adds L to the stream, and the requester's next `Pull` names it in `join` with no cursor: its listing arrives in the stream's order with everything after. Events the listing also shows are deduped by blob ID. Gap-free by order. A join in pages keeps its own position (its `lag`) until the last page; only then is it in the stream. A join of a member the server does not share is answered, never treated as an empty success. Opens from one Offer batch join in one Pull: a first contact sharing 10^4 sync IDs is one Pull with 10^4 joins and one paged reply.
- **Lost and rejoin**: `Lost [L, c]`: the cursor where L stopped for this receiver: the server's `until` position, or for an immediate `Lost` the end of what this connection's stream has delivered (the last cursor returned), `Lost` written in order after it. The receiver stores `lag = c`, or keeps an older one. When L rejoins: `join = [L, lag]` in the next Pull, L's events after that position. Cost: the events L missed, no listing. The server's `until` for a member ends the stream at the rotation event inclusive (issues/net-shared-set.md, Opens).
- **Back after a long absence**: a cursor is honoured however old it is. The log holds each live entry's latest event and deletions for `TOMBSTONE_LIFETIME`, so the diff from the cursor carries everything a listing could, and a deletion older than the log is not carried by either; retention judges a stale entry the node still holds (a covering snapshot, expiry, purge; `Deletions`, below). Only a peer with a different store (restored, copied, rebuilt, another log ID) gives the whole stream from the start.

## Restart and loss
- Log, records and cursors are durable: a restart resumes. A store restored from a backup is detected by nothing and needs nothing detected (One node log, one cursor): every peer's next cursor past the restore point is no cursor, and it gets a stream from the start.
- A cursor is stored only with what it covers applied, and a position is issued only for durable events: a cursor never runs ahead of the data it names.
- Lost record on one side: the Resume list finds nothing, new r, whole filters, S rediscovered, one listing. On the other side the orphan record is unused, evicted by LRU.
- Partial loss: atomic per record, so either whole or none.

## Deletions
A deletion reaches a node as a log event, within the log's retention of it. No event carries it after that and none is needed: a stale entry is only bytes, retention's covering snapshot, expiry or purge removes it, and a listing or diff naming a covered entry leaves it for that judgment. A listing never deletes.

## Peers that cannot read
A reader's connection to a peer that cannot read L is one-sided: the reader tests (a Hit on the sync key, issues/net-shared-set.md), the peer tests nothing, keeps no record without a known actor (so the open is per connection, one Hit each), and never pulls.
- **Reading and known**: the reader pulls the peer's log like any stream, keeping in its record `known`, the entries a Pull has shown at the peer, one row per entry, counted in `RECORD_BUDGET`. A from-the-start reply replaces it. With no record on both sides (no known actor either way, Resume) there is no `r` to find a record by: `known` lasts the connection and each connection starts from the start (Unsure).
- **Uploads**: a reader uploads each entry it must place there that `known` lacks (spec/sync.md §5), once a connection. An upload's ack adds nothing to `known`: only a Pull does, because a store restored from a backup has lost what it acked. Uploads and deletes wait for the connection's first Pull, through its last page.
- **Deletes**: retention's rule, nothing new: a reader holding a delete key sends the ordinary signed Delete (spec/sync.md §5, §7) for every entry `known` lists that it covers (a held snapshot covers it, spec/commits.md §5), once `known` shows the covering snapshot (the carrier stays at the peer). The peer judges nothing and infers nothing; it removes the entry and logs the deletion, which other readers receive by the same Pull. Because the rule reads `known`, a peer that was away, a restored peer and a reader back from a lost record are all served by the same pass, with no tombstone channel and no memory of past deletes. A reader without a delete key sends none: an entry stays until a right holder connects or it expires at the peer (spec/sync.md §5 Expiry). Whether only own boxes or also others' run this way is issues/net-one-peer.md's consent.

## Adversaries
- **A peer flooding `Resume`, `Beacons`, `Pull`**: the list is one message; lookup per entry. Filter pages linear (issues/net-shared-set.md). `Pull` bounded by `max_reply` and the flow control of spec/sync.md §6.
- **Restart losing the record**: first contact; no incorrect state, no leak beyond a first contact. A peer holding a stale copy of a whole-filter `gen` or `cursor` gets a base-unknown or no-cursor: it cannot influence opens, whose judgment is local.
- **Clock-skewed peer**: nothing in this design reads a clock. Filters, generations and cursors are sequences; judgment reads roles with `until` disregarded (spec/crypto.md §4). A skewed clock affects only the node's own writes (issues/clock-peer-offset.md).
- **Revoked node of a known actor**: Resume needs the session to prove an actor in the record's `actors`; it cannot at a closed epoch where the removal is held (issues/account-signing.md). Fork window: account signing's limit. Its r is then just a random value.

## Costs
With N held sync IDs, P peers, C changes since the last connection:
- **Per reconnect**: O(C) beacon bytes and hashes; O(events since the cursor) data, or O(live entries of S) listed for a peer with a different store; no per-sync-ID message in either; local re-judging O(C) (O(S) only when the proven actors changed).
- **Per peer stored**: about 1.2 B per peer credential (filter) plus 50-100 B per S member; for a peer that cannot read, also a row of `known` per entry it shows.
- **Idle reconnect**: under 1 KB, a few round trips, whatever N.

## Hard cases
- A rotation while apart: the server's `until` stops L at the rotation (issues/net-shared-set.md, Opens); a holder rejoins by an added beacon.
- A record on one side only: base unknown, whole filters both ways.
- Subscriptions and push: `follow` is the one subscription; per-label Subscribe and Open are gone between readers.

## Replaces
`Feed` and per-start log IDs; per-(peer, label) cursors, per-label Open, Subscribe and Sync between readers (spec/sync.md §6 First sync and Cursor sync, spec/wire.md §11.2 Sync; the listing is a `join`); the per-connection caps on open labels (4096) and `MAX_SUBS` between readers (spec/wire.md §11.2); Error 15 and the trim position. Per-label logs at hosts become this log (issues/net-one-peer.md).

## Rejected
- **Reconciling per-sync-ID digests**: two readers in sync legitimately differ in entry sets (keep bounds, dropped and covered bodies): idle sync IDs would differ. The log is exact.
- **Per-sync-ID cursors reconciled over (sync ID, position) pairs**: works, but two structures.
- **A per-member first sync (`Sync(L, no cursor)`) for a join**: one round trip per sync ID, 10^4 of them for a phone back after a month or a first contact sharing 10^4, the cost this design exists to remove; the stream from the start lists the same entries in one paged reply.
- **A log trimmed by position with Error 15**: the log's retention already keeps every live entry's event, so "retained events plus trimmed below T" and "the stream from the start" are one reply; a trim position is one more value to keep and send.
- **A digest per Pull**: a digest crossing a reply in flight reads a just-opened member as a difference and the repair re-fires. At a connection's start nothing is in flight.
- **Resending `Lost` across connections**: the digest finds it, with no record state for ending members.
- **A horizon below which a cursor is refused**: a listing would teach no deletion the diff from the cursor does not; it spends a listing for nothing.
- **Keying a record by a node key or dialable key**: a connection proves accounts (issues/account-signing.md), and a LAN listener has a fresh key per join; keying by r needs neither. **Tickets minted by one side**: same lookup, but one side must trust the other's minting; a pair value is symmetric.
- **Running first contact on every connection**: one entry per sync ID each time.
- **Storing a table of the peer's beacons, or own beacons per peer**: each side tests only its additions.

## Picked values
- **`INCARNATIONS_KEPT`** 4096 (resource bound): the list of incarnations a store keeps, oldest evicted. 0 makes every cursor from before a start with an append no cursor (correct, a listing per peer), infinity is disk growing with appending restarts. Each entry is 24 bytes (ID and end position), one per start that appends: a start that does not append adds none; at 50 appending starts a day the list reaches its cap at about 82 days and 98 KB, and a peer absent longer than that is given one listing.
- **`RECORD_BUDGET`** 256 MiB total per node of durable records, resource bound: 0 is every connection a first contact (correct, more bytes), infinity is disk. Past it, evict the least recently used record not in use. A filter that would not fit is tested as it arrives and not stored: that peer is a first contact next time; no connection closes for it.

## Model
core/test/tla/net (TLC), both halves of this design with issues/net-shared-set.md; its README lists scenarios and state counts. Over restarts, record loss, deletion expiry, restored and copied stores, drops, role changes on one side and one-way dialing, each checked over all interleavings at small size:
- No node drops a write nobody deleted; a source judged caught up holds nothing this node lacks; nothing is served after the right is lost; a reconnect sends what changed; the connection settles; S is exactly the rule on what each side holds.
- Rules the design relies on, each failing the properties when removed: pending set; `acked_pos` only past what is acknowledged and tested; arrival test before later messages; the tag; ByRole; a declining tester's `Lost`; the rotation's `until`; the digest; `Lost` and digest re-marking pending; Lost's older lag; a join's own position; a join answered; the cursor applied before stored; a change announced during a Pull denying that Pull's caught-up; the server's S read per reply; both sides pull; a listing carrying retained deletions; at a peer that cannot read, `known` only from Pulls, replaced by a from-the-start reply, deletes from `known`, the carrier shown first.
- Not modelled: more than one peer, key actors and covers, deposits, account proofs, filter pages and false positives, inline bodies, ephemeral entries, record eviction, the generation base check's bug (a single credential makes additions equal the whole filter; the argument is ASSUMPTIONS.md's), the digest's list as messages of its own, `follow`'s pushes, a peer that cannot read with no record, two live copies each redialing.

## Steps
issues/net-shared-set.md, Steps: this issue is 4, 6, 7.

## Tests (tier 1, over issues/net-tests.md)
An idle reconnect sends no per-sync-ID message (counted); the digest of two equal records matches at any size (counted: 32 bytes each way); a store restored so that S differs finds the difference, closes members only one side holds and reopens by the shared set, and a stopped member's `lag` does not make the digests differ; a rotation that ends a member while the peer follows sends `Lost` after the rotation's event; a restarted node resumes; a lost record is a first contact and converges; a rotation while apart rejoins from its lag and refetches only the missed events (counted); a node back after the peer compacted deletions past its cursor converges with the messages of one stream (counted at n and 10n sync IDs: no term in n beyond pages); a first contact sharing n sync IDs joins them in O(1) Pulls (counted); a mesh body crosses once with announcements per peer (counted); a skewed clock changes nothing.

## Unsure
- (design) `Lost` after a `until` waits for a Pull's cursor to pass it: that wait is what keeps the member open across a drop until the rotation's event has been applied (model: `Lost` right after the event, with a drop, loses `EpochReached`). But with `follow` the requester sends one Pull and then receives Pushes, whose positions the server never hears, so the wait never ends. Settle before building step 7: the requester sends a Pull (its applied cursor) after a Push that carries an `until` event, or Push is answered with its cursor while an `until` is set; the test above then fails without it.
- (design) "Marks its credentials pending" is not a `changed_at` advance: `changed_at` is node-wide and would re-offer L to every peer on one peer's `Lost` or digest difference (any peer sharing L could cost every other peer additions). State a per-record mechanism: e.g. `acked_pos` lowered below L's `changed_at` with tested and acked state reset.
- (design) A reader with a peer that cannot read and has no record pays a listing and a Hit per sync ID each connection: is an opt-in box with no known actor accepted as outside "a reconnect costs what changed" (Tess), or does a reader keep `known` and the cursor keyed by the box's listening key?
- (design) A cursor issued for an ephemeral event (memory-only, not durable) and the rule "a position is issued only for durable events": state which positions a cursor may name and how "past the log's end" reads the high-water mark after a restart.
- (design) A sync ID a node stops holding has no `changed_at` entry: re-judging must still close it in S.
- (implementor) Serving `Pull`: scan the log after the cursor, or each member's events after its position (a join from the start: the member's entries), whichever is less (a busy node with a small S; one join among a large stream).
