# Ephemeral data: signals, expiry, the all-nodes predicate
> Summary: Decided with owner 2026-10-15. Three separate concepts: signals are never stored and reach only connected nodes (dedicated API, write to send, read to listen); state may carry an expiry at which every node, blind ones included, drops it without anyone online; "all nodes of a thing" is a predicate over node-published state used by policies, never a protocol condition. Nothing is kept "until everyone has seen it".

## Why three, not one
Owner's goal (2026-10-12): event-stream-like apps on the same infra, first-class if it helps, no cruft. "Keep until every receiver has seen it" is not decidable: the receiver set is open (a member adds a device later), nodes die, and blind nodes know no members. Every approximation (caps on a label, TTL guesses by the writer) was the cruft. So: a signal is never stored; anything that must outlive the moment is state, and state can expire at a time known to everyone.

## Signals (decided 2026-10-15)
A signal is a write that nobody stores.
- API: dedicated, not `set_aspect`. `send_signal(tid, kind, value)` and `listen_signals(tid, kind, callback)`. Signal kinds are declared in the schema like AKs (typed, so generic tools understand them) but are not aspects: reading one returns nothing, they never appear in state or history.
- Rights: send needs write on the thing, listen needs read. Receivers verify the sender's signature and membership chain like a commit; a sender whose chain has not arrived yet is dropped.
- Envelope: encrypted under the thing's group labels exactly like a blob (wrap per label), signed by the sender node. Inside: sender node, actor, HLC timestamp, tid, kind, optional target node, value. No dots, no retention class, no delete token, not a commit, never in the label log.
- Delivery: push on subscribed connections. A node subscribes to the labels it tracks on each connection; this is the same subscription that pushes new log entries for low-latency state sync (notes/sync.md, Subscriptions). A blind relay forwards a signal to its other subscribers of that label and keeps nothing; clients never re-forward. At most once, best effort, in order per sender per connection. A node connected to several relays may see a signal twice; latest-wins values are idempotent, event-style signals carry a sender sequence.
- Targeting an actor: a thing shared with them, with its own label. Targeting one device: the target node field; the actor's other nodes drop it silently. No label per device.
- Late joiners see nothing until the next signal. Presence apps heartbeat; "last seen" is a normal aspect written at low rate.
- A signal on a thing without its own label reaches every subscriber of the enclosing group, who decrypt and drop it. Busy channels get their own group, same as selective sync.
- Not provided: delivery guarantees, buffering, replay. What must survive a receiver being offline is state: inbox pattern (receiver-owned list, senders append, owner deletes elements, expiry as backstop), or a list with expiry.
- Cost: an envelope is about the size of a minimal commit; latency is one relay hop.

## Expiry (decided 2026-10-15)
A commit may carry `expires at T` in its header; schema default per AK as a duration from write (notes/data-model.md). Orthogonal to the retention classes: `undefined`/`preserve`/`purge` say what happens before T, expiry says that at T it is gone regardless.
- At T every node treats the commit's deltas as purged and any live content they carry as reset at T (reset timestamp T, so a write stamped before T that arrives late is superseded, a write stamped after T is new state). Deterministic from the commit: clock skew moves the moment, not the outcome. No undo after T, like purge. A multi-aspect commit expires whole, same granularity as the retention class.
- Blind nodes: T is carried in plaintext entry metadata beside the generation and token hash. At T the entry is deleted, no bin, no retire, no generation bump, no writer online. Uploads whose T has passed are refused, so a stale peer cannot resurrect them. Leak, accepted by owner 2026-10-15: a blind node learns which entries expire and when.
- Trusted nodes drop bodies and every local reference at T under the purge rules (nonce destroyed, index entries gone, notes/crdt-sync.md).
- Covers: disappearing messages (write-based timer in core; read-based timers and earlier deletion are app writes; core expiry is the hard upper bound and what lets a server wipe them unattended), events buffered for a while (a list aspect with a one-hour default), "keep at least until T" (`preserve` plus expiry). Cheaper than `purge`-on-supersede: nothing has to be retired.
- Not provided: server-enforced minimum retention (legal hold). If ever wanted it is a per-label policy beside the grace period, and it cannot apply to `purge`-class content, which the server cannot tell apart.

## The all-nodes predicate (decided 2026-10-15)
"All nodes a thing syncs to" is computable at trusted nodes (every node of every member, nodes are leaf actors) and is a state predicate, never a protocol condition.
- Each node publishes on its node thing (`/node`, notes/data-model.md): software revision, schema revisions and forms it reads, last sync time. Written at a low rate (on change, last-sync hourly at most). Accepted by owner 2026-10-15.
- Policies read it: write the new form once every node reads it (fixes the read-only old app that the writer-revision heuristic in notes/versioning.md cannot see), drop old-form history after that, clean up an inbox once every own device has acked.
- Dead nodes: a lost phone blocks "all" forever, so every such policy pairs the predicate with an age cutoff on last sync or an explicit node removal. The predicate never gates deletion at blind nodes, which know no members and must not wait on liveness.
- "Buffer until all have seen it" = inbox pattern plus this predicate plus expiry as backstop. Fine as a core helper later; not sync machinery.
