# Cheap reconnects
> Summary: Two nodes that reconnect often share many mostly idle sync IDs; today a reconnect opens and checks each shared sync ID (and co-reader serving keeps its log in memory, so a restart replays). A reconnect should cost about what changed. Options: a per-peer cursor on one node-wide log, or reconciling per-sync-ID digests. Design open, with issues/net-shared-set.md. Part of issues/net-rework.md (Tess: important).
> Priority: normal
> Tags: sync, node, proto, tess-call

## Today
Each connection opens every wanted label (one Open each) and resumes each from its own cursor at that peer. Co-reader serving keeps its log in memory (`Feed`, a fresh log ID per start, notes/peers.md), so after a restart peers replay. So a reconnect costs at least one round per shared sync ID, idle or not.

## Options
- **One log per node, one cursor per peer.** A node keeps one durable log over everything it holds; a peer keeps one cursor into it. A reconnect asks "what changed in our shared sync IDs since position p", so cost follows changes. Needs the serving side to filter by the shared set (known from the last connection or issues/net-shared-set.md), recognising the peer across connections, and a durable log with a retention horizon (beyond it, fall back to full reconciliation).
- **Digest reconciliation.** Each node keeps a running digest per sync ID of what it holds there; on reconnect the two reconcile the (sync ID, digest) pairs of their shared set by range reconciliation (as osis-proto does for entries), so matching ones drop out in a few rounds. Needs both sides to agree on what "same" is: two readers in sync may hold different bodies (keep bounds, dropped and covered bodies, log-only mode), so the digest's input must be something they share (the entry set? stamped entries only?).
- Either may let a reconnect skip the shared-set step: the last connection's set plus changes.

## Unsure
- (design) Which option, or both (cursor for known peers, digests for the rest).
- (design) Whether recognising a peer across connections is acceptable (it links its connections, at least to that peer), and what identifies it (its dialable key rotates).
- (design) Restart: a durable log means a growth bound (notes/growth.md).
- (design) Interaction with subscriptions and push (spec/sync.md §8): live connections already push; this is only about reconnects.
