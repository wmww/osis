# Constraints
> Summary: The requirements osis must satisfy, the threat model, and the calls made where goals collide. Mechanism-free: how each requirement is met lives in the other notes and may change without touching this file. Check every design against it.

Items are hard unless a section says goal. Never weaken an item to fit a design; record the collision under Tensions.

## Purpose
- End-user apps with small-to-large interconnected data across users and devices. Many apps, app versions, generic tools and agents share the same data, like a file format.
- Simple, safe Rust. Nothing on the wire path depends on third-party parsers or serialization frameworks.

## Decentralization
- No central or trusted coordinator, consensus or sequencer. Peer-to-peer like git; any node may be offline indefinitely and return.
- No global registry. Identifiers are minted offline and cannot be hijacked. Total data may exceed what any node tracks.
- Every node that can read data verifies identity and authorization itself from what travels with the data. Nothing trusts a server's word.
- No unit that must be synced whole. Groupings overlap, nest, may be cyclic and change over time. Syncing one row or one column of a table must each be efficient without duplicating the table at rest or in transfer.
- Convergence under any delivery order, duplicates and partial receipt. No ordered delivery.
- A change may atomically cover any set of things, across owners and reader sets: a node that may read and syncs several of them sees all of it or none.
- Deterministic: a node's state and its judgment of every write are functions of the data it holds and what it has itself witnessed, never of arrival order.

## Offline and network
- Every operation completes with nobody else online. Only propagation waits.
- No helper is required: relays, discovery and hosted servers are replaceable and self-hostable. Works over LAN, through any untrusted node, or to a known address.
- No dependence on one transport. Sync works over any ordered byte stream, including files carried by hand.
- The network layer identifies devices to untrusted nodes and relays no further than the network itself does (addresses).

## Cost (goal)
- Bytes transferred are close to the size of the change: about 1.2x for large changes is fine, 2x-10x is not. Small changes may carry a fixed overhead of a few hundred bytes.
- Round trips: a small constant in the common incremental case, logarithmic at worst.
- Nothing a node already holds is sent again. A thing in many groups is stored and transferred once per node.
- Compaction, deletion and membership changes cost proportional to what changed, not to group size or history.
- Connected nodes see each other's changes promptly, pushed, not polled.

## Untrusted (blind) nodes
- Keyless always-on nodes are first-class: every property here holds for them, and two briefly-online devices syncing only through one is a primary use case.
- They may learn volume and the structure selective sync needs: which opaque groups a blob is in and how groups overlap, counts, padded sizes, timing, addresses. They must not learn identifiers, keys, values, authors, membership, device identities, or structure beyond that.
- Different groups of one owner are unlinkable beyond their overlap.
- One protocol for all nodes. Trusted and untrusted peers differ only in which keys they hold.
- An untrusted node may be the only backup. Read access never allows deleting its data or forcing a re-upload. Destruction needs write rights at least, and is recoverable for a grace period unless done by an admin or by the data's author.
- It knows no members and never waits on their liveness.
- Goal: it can limit abuse (storage, rate) without learning identities.

## Confidentiality between readers
- A reader learns only what it may read. Sharing one thing reveals nothing of another beyond the fact that one change touched both.
- No identifier on the wire is predictable without a read key. Nothing derives from plaintext that could be guessed.
- Readers of shared data may learn each other's device identities and the chain that authorizes each author, never rosters they are not part of.
- Deleting content leaves the fact, time, author and aspect of the edit visible to readers.
- No secret ever passes where an untrusted node could read it.

## Deletion
- Three retention classes: purge (immediate and irrevocable everywhere once the deletion is seen), preserve (history kept until explicitly purged), undefined (local policy). Defaults per aspect, overridable per change. Preserved history can be purged explicitly by its author or an admin.
- Data may carry an expiry at which every node, untrusted ones included, drops it with nobody online.
- Purge is prompt: no honest node keeps purged content once it has seen the deletion. No batching.
- Granularity is one edit of one aspect. Part of a value's history can be purged.
- No fingerprint: nothing retained lets anyone, even a reader, confirm a guess of purged content, however low-entropy.
- Forward secure: a node that deleted honestly and is compromised later yields nothing. A node that lost access to data yields nothing it can no longer read.
- Nothing depends on retaining full history.

## Ephemeral data
- Signals: never stored, reach connected nodes only, no delivery guarantee. Same rights and verification as writes.
- Nothing is kept "until everyone has seen it". Whether others are alive is never a protocol condition.

## Scale
- Many GB per node, multi-GB single values, maps with millions of keys, millions of blobs per group. No operation is O(total data) or O(history). A change inside a huge value costs O(change).
- Every wire object has a fixed maximum size. Peer input never causes unbounded allocation, work, storage or diagnostics.
- Runs in browsers. Large values stream; no whole value is ever needed in memory.

## Generality (goal)
- No usage rules ("don't group data this way", "don't change this too often") are needed for the properties above to hold. Exceptions are rare and listed under Tensions.

## Versioning
- Never discard, reject or crash on data not understood: store it, relay it, merge what can be merged, re-examine after upgrade.
- Old data stays readable forever. Nodes write what older nodes can read until a new feature is actually used.
- Everything on the wire is open and only grows: no identifier reused, nothing removed, no in-place change of meaning. Nothing in the data is irreversible.
- Each aspect has one schema authority. Merge needs no schema. The core distributes no schemas.
- An app update never by itself changes stored data. No migrations. No global agreement on who has upgraded.
- Cryptographic primitives can be replaced without re-encrypting or re-signing old data.

## Data model
- One canonical serialization, byte-identical everywhere. One hash function.
- Every datum is an aspect of a thing. Values are typed by the writer's schema. References may dangle.
- Per-aspect merge with one conflict rule everywhere. A newer write never loses to an older removal. Collaborative text and lists in v1.
- Secrets that must stay secret for years resist a future quantum attacker. Signatures need not.

## Permissions
- Three concepts only: actor, membership, ownership. Every thing has exactly one owner, fixed at creation. Sharing never changes a thing's identity. Transfer of ownership is rare.
- Grouping for sync grants no rights.
- Every write is attributable to a device and verifiable. Hiding authorship is a deliberate choice, never the default.
- Whether an edit by a revoked member counts is judged by what authorized members witnessed, never by the author's own timestamps.
- Rights held by different parties never combine into a right neither has alone.
- Removing a member never re-encrypts existing content.

## API
- Plain values and listeners. No CRDT concepts, no conflict UI, no correctness that depends on "surfacing it to the user". Diagnostics are informational.
- Atomic, not isolated: concurrent changes merge, so app invariants must hold under merge.
- Untyped access always works on any stored data.
- Large values are usable both materialized and streamed.
- Never panic on peer input. A wrong local clock harms only that node's own writes.

## Out of scope
- Hostile admins. Authenticated malicious writers are bounded, not prevented. Malicious readers can only waste storage.
- Deletion against offline copies, dishonest nodes, memory or swap.
- Recovery of a lost owning key.
- Revocation reaches a group only when one of the revoker's members next syncs it.
- Anonymity against network, timing and style analysis.

## Tensions
Where two goals cannot both hold: what collides, and which yields.
1. **Transfer finality vs no consensus.** A former owner can always publish a competing transfer. Ownership is immutable; transfer is aliasing, a former owner can fork, and forks resolve deterministically for readers with a stake in one branch, else by the reader's choice. Moving a thing out of its owner's tree should be rare.
2. **Selective sync from untrusted nodes vs hiding structure.** Structure leaks as far as selection needs it.
3. **Cheap edits of large values vs hiding sizes.** Sizes leak, padded coarsely.
4. **Prompt deletion vs history, undo and recovery.** Purge is immediate; undo yields to others' deletions; untrusted nodes keep a recoverable bin for a grace period, except for purge-class content.
5. **Atomic multi-thing changes vs partial fetch and purge.** Atomicity wins: a node syncing part of a change over-fetches, purging part of it rewrites it.
6. **Witness-based revocation vs untrusted-only topology.** An untrusted node's receipt never counts. A revoker syncs before stamping its revoke, so edits parked at untrusted nodes it reaches count; edits at nodes it does not reach, in transit, or passed over by an offline or backdated revoke can be lost until re-grant.
7. **Lazy key rotation vs forward secrecy against dishonest untrusted nodes.** An ex-member plus a dishonest untrusted node can read old content.
8. **Immediate purge at untrusted nodes vs backup safety.** Authors may hard-delete their own entries, admins anything; writers only soft-delete; readers neither.
9. **Bounded clocks vs revocation precision.** A window the size of the clock skew.
10. **Deduplication vs forward-secure deletion.** Deduplicate only against content the editor already holds.
11. **Removals beating unseen concurrent adds vs no-fingerprint purge.** An add the remover never saw survives.
12. **Verifiable membership history vs bounded history.** The owner chain may restart a thing's authorization history at a snapshot; grants in flight before it are lost, and briefly-wrong rosters are possible until re-snapshot. Ownership-transfer records are kept forever.
13. **Lazy rotation vs per-thing sharing.** Removing a party costs proportional to the things shared with it one by one. Usage rule: share sets through one shared actor.
14. **Bounded state vs never discarding an edit.** State grows with edit history, not live size; no horizon drops edits. Usage rule: commit per editing pause, never per keystroke.
15. **Membership decidable from records alone vs completeness.** Only the demoter's own receipts decide which of the demoted actor's grants survive, never other admins'. The demoter syncs the actor's label first, so loss is limited to grants in transit or passed over by an offline or backdated demotion, and re-grant recovers them.
16. **Explicit sync placement vs complete backup.** Nothing syncs by being owned; apps place things into synced groups explicitly, and a forgotten placement leaves a thing local-only.
17. **Readers relaying vs junk at untrusted nodes.** Readers may upload; junk is discarded by members and capped by servers.
18. **Readers relaying vs reader-proof metadata at untrusted nodes.** An untrusted node cannot check a wrap, an expiry or a delete-token commitment, so a reader that uploads a blob before its author sets them. Rules bound the damage (expiry only ever extends, wraps are re-asserted by any key holder, a spoiled commitment leaves admin deletion) and the author's own upload is first in the primary pattern, but a reader who wins the race can make the server's copy unreadable or short-lived until an honest holder syncs again; data no honest node still holds is then lost at that server. "Malicious readers can only waste storage" yields by this much.
