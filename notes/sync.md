# Sync: blob reconciliation, blind nodes, compaction
> Summary: One sync protocol for all nodes: per-group set reconciliation over encrypted commit/chunk blobs; blind (keyless) nodes store and serve without seeing AKs, tids, sizes or structure; generations for compaction and deletion. Discussed with owner 2026-10-09; goals and unification decided, mechanism is proposal.

## Goals (decided by owner 2026-10-09)
- Untrusted always-on nodes (backup servers) exist and sync efficiently.
- They learn no AKs, tids, value or thing sizes, thing/aspect counts, authorship, membership or nesting. Overlap between groups synced to the same server is an acceptable leak.
- One protocol for every node. Trusted peers and blind nodes differ only in which keys they hold. Replaces the state Merkle tree over the group hierarchy (see Dropped).
- Nothing in the earlier sync proposal is sacred; keep the plan as simple as possible while covering everything below.

## Model
- **Blob**: an encrypted commit (header, signature and deltas all inside the ciphertext) or a fixed-size encrypted chunk of a large body. ID = BLAKE3 of the ciphertext. Indistinguishable to a keyless node. Encrypted under the owning actor's content key (notes/permissions.md), so a commit has one ID regardless of which groups contain it.
- Every node holds a set of blobs. A node with keys decrypts commits and joins deltas into local aspect states. State is local only: never synced, never hashed for sync.
- **Sync unit = group** (notes/data-model.md). "Blobs of G" = commits touching any thing in G's transitive closure, plus the chunks they reference. Each member computes this from its own data: commits are tagged with their things' `/groups` on arrival and retagged when group membership changes. Fixpoint, so cycles need nothing special; nesting depth does not affect sync cost, only retagging cost, which `/groups` already implies.
- **Protocol**: per synced group, range-based set reconciliation over blob IDs within the live generation (Negentropy / Willow RBSR style), then transfer of the missing blobs. Cost proportional to diff times log of set size. A connection may sync many groups. No other sync messages.
- **Blind node**: knows a group only as an opaque label (its sync public key) over a flat set of blob IDs. Same blob under two labels = one transfer, one stored copy, two label entries; that is the overlap leak.
- **Partial trusted peers**: each reconciles with its current view; newly received group data may grow the closure, so repeat until a pass has no diff. Closure only grows within a session, so this terminates.
- The receiver keeps blobs a peer puts in G even if its own closure disagrees (checked after decrypt when it can); stale extras leave at compaction.
- **Mixed keys**: a node may hold keys for some owners in a group and not others. It is trusted for those blobs and blind for the rest, in one protocol. The chat pattern (notes/permissions.md) needs nothing extra.
- Partial restore from a blind node requires the subgroup to be synced to it under its own label, since blind nodes cannot filter. Possible later: an encrypted table-of-contents blob.
- Rejected sync unit: owner actor. Dedups perfectly but forces a new actor (a hand-over) for every separately syncable subset; groups are free and overlapping.

## Compaction, deletion, generations
- Per group label, a generation counter. Reconciliation runs only within the live generation, so retired blobs cannot resurrect from a stale peer.
- Compact: a member uploads snapshot commits (full aspect states as deltas) tagged with generation N+1, then signs "retire N, keep [ids]". The keep-list moves untouched blobs to N+1, so compaction costs proportional to churn, not group size. Concurrent compactions are harmless: snapshots join.
- A returning member holding generation-N commits re-uploads into the live generation only those whose join still changes state.
- Blind nodes keep retired generations for a grace period (recycle bin). An ex-member still holding the sync key can force a restore, not a loss.
- Permanent deletion reaches blind nodes at compaction, together with read-key rotation; until then deleted content sits there as ciphertext under the current key. Members drop it immediately (LWW reset, notes/crdt-sync.md).
- Nodes keep commit bodies for the live generation in order to serve them. Previously an optional retention window, now required. `history` flag = bodies never compacted.
- Generations apply between trusted peers too; same protocol.

## Authorization of blind nodes
- Each group has a sync keypair stored in the group thing's data (encrypted like all data under the group thing's owner's read key). Anyone who can read the group can sign uploads and retires. The public key is the label; the blind node learns no membership.
- A read-only member can upload garbage; members reject it at signature check. Same class as the accepted "authenticated malicious writer".

## What a blind node learns
One label per group synced to it, overlaps between them, blob count, blob sizes rounded to buckets (chunks are fixed size), arrival times (clients may batch uploads), generation numbers and retire events, client addresses. Not: AKs, tids, thing or aspect counts, value sizes, authors, membership, nesting. Key epoch after a rotation: readers try the few live keys rather than a cleartext epoch byte (proposal).

## Interaction with other notes
- Receipt-time revocation rule: a blind node's receipt never counts, it is not a member. Statements are ordinary commits.
- Atomic application: a commit applies once its blob and all referenced chunks are present.
- Value hashes remain for links, dedup and undo; no state hash exists. The group hierarchy is a local index, not a sync tree.

## Dropped (2026-10-09)
Per-aspect state Merkle tree, Merkle tree over the group hierarchy, per-aspect context exchange, the state-vs-context Merkle leaf question, "one connection syncs one group". A state Merkle tree exposes shape to relays and must follow a cyclic hierarchy; blob reconciliation hides shape and makes nesting a local index problem. Note the earlier per-edit cost (a thing in many groups updated many roots) is gone: one blob, N index entries.

## Open
- Default compaction policy: when, and which member.
- Sync key rotation: with the owner's read key, or on explicit admin action. A new label means re-labeling or re-upload.
- Lazy chunk fetch for huge bodies a device does not want locally (local policy; reconciliation just reports the IDs it lacks).
- Encrypted table of contents for partial restore from blind nodes.
- Size bucketing scheme; upload batching.
- Peer discovery, transport, crypto primitives: not discussed yet.
