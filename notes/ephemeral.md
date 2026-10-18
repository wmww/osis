# Ephemeral data: rationale and patterns
> Summary: Why signals, expiry and the all-nodes predicate are three separate concepts (decided with owner), how apps use them, and the all-nodes predicate as a policy helper. Mechanisms: spec/sync.md §9 (signals), spec/commits.md §6 and spec/crdt.md §4.7 (expiry).

## Why three, not one
Owner's goal: event-stream-like apps on the same infrastructure, first-class if it helps, no cruft. "Keep until every receiver has seen it" is not decidable: the receiver set is open (a member adds a device later), nodes die, and blind nodes know no members. Every approximation (caps on a label, TTL guesses by the writer) was the cruft. So a signal is never stored; anything that must outlive the moment is state, and state can expire at a time everyone knows.

## Signals
- Dedicated API (`send_signal`, `listen_signals`, notes/api.md), not `set_aspect`. Kinds are declared in the schema so generic tools understand them; a signal is never readable as an aspect.
- Targeting an actor: a thing shared with them, with its own label. Targeting one device: the target-node field. No label per device.
- A signal on a thing without its own label reaches every subscriber of the enclosing group, who decrypt and drop it. Busy channels get their own group.
- A node connected to several relays may see a signal twice: latest-wins values are idempotent; event-style signals carry a sender sequence.
- Late joiners see nothing until the next signal: presence apps heartbeat; "last seen" is a normal aspect written at a low rate.
- What must survive a receiver being offline is state: inbox pattern (receiver-owned list, senders append, owner deletes, expiry as backstop) or a list with expiry.
- Cost: an envelope is about a minimal commit; latency one relay hop. A junk signal costs subscribers a signature check.

## Expiry
- Expiry is death by timer (spec/crdt.md §4.8): the values die at T and the body follows, whatever the deltas' keep bounds. "Keep at least until T" is a retention bound (spec/commits.md §5), a different thing.
- Covers disappearing messages (write-based timer in core; read-based timers and earlier deletion are app writes; core expiry is the hard upper bound and lets a server wipe them unattended) and buffered events (a list aspect with a one-hour default). Cheaper than keep-at-most 0: nothing has to be deleted by hand, and the server does it unattended.
- Leak accepted by owner: a blind node learns which entries expire and when.
- Not provided: server-enforced minimum retention (legal hold). Keep-at-least binds honest nodes; a blind node deletes whatever a token or its label delete key tells it to.

## The all-nodes predicate
"All nodes a thing syncs to" is a state predicate computable at trusted nodes, never a protocol condition. Per label: the nodes with a valid chain that published `/node` under the thing's label (not "every node of every member", which needs rosters readers never see).
- Each node re-puts its node card (`/node`, spec/permissions.md §4) under each label it tracks at a low rate (daily at most), so the newest copy's `ts` under L is its last sync of L (accepted by owner). A reader's copy enters by deposit, so the rate must stay far below the label's deposit budget.
- Uses: write a new schema form once every node reads it (fixes the read-only old app the header heuristic cannot see), drop old-form history after that, clean up an inbox once every own device has acked.
- Dead nodes: a lost phone blocks "all" forever, so every policy pairs the predicate with an age cutoff or an explicit node removal. Never gates deletion at blind nodes.
- "Buffer until all have seen it" = inbox pattern plus this predicate plus expiry as backstop. Fine as a core helper later; not sync machinery.
