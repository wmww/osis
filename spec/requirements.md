# Requirements
> Summary: The requirements osis must satisfy, the threat model, and the calls made where requirements collide (tensions, numbered and cited elsewhere). Mechanism-free; check every design against it.

Items are hard unless a section says goal. Never weaken an item to fit a design; record the collision under Tensions. Tension numbers are stable.

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
- Deterministic: a node's state and its judgment of every write are functions of the data it holds, never of arrival order.

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
- An untrusted node may be the only backup. Read access never allows deleting its data or forcing a re-upload. Only the roles an edit names (its author, admins, or any writer where the author allowed it) can destroy it.
- Read access never allows storing arbitrary content there. It stores content only on a writer's word, beyond a small flagged budget per group open to anyone who must reach the group's members, which members can clear.
- It knows no members and never waits on their liveness.
- Goal: it can limit abuse (storage, rate) without learning identities.

## Confidentiality between readers
- A reader learns only what it may read. Sharing one thing reveals nothing of another beyond the fact that one change touched both.
- No identifier on the wire is predictable without a read key. Nothing derives from plaintext that could be guessed.
- Readers of shared data may learn each other's device identities and the chain that authorizes each author, never rosters they are not part of.
- Deleting content leaves the fact, time, author and aspect of the edit visible to readers.
- No secret ever passes where an untrusted node could read it.

## Deletion
- Retention per edit: who may purge it (nobody, admins, the author, any writer) and how long its history is kept (at least and at most, absolute or after it is replaced). Defaults per aspect, overridable per change, immutable once written.
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
- Per-aspect merge with one conflict rule everywhere. A newer write never loses to an older removal. Collaborative text and lists.
- Secrets that must stay secret for years resist a future quantum attacker. Signatures need not.

## Permissions
- Three concepts only: actor, membership, ownership. Every thing has exactly one owner, fixed at creation; moving a thing to another owner is a copy, and rare. Sharing never changes a thing's identity.
- Grouping for sync grants no rights.
- Every write is attributable to a signing key actor (normally a device) and verifiable. Hiding authorship is a deliberate choice, never the default.
- Whether an edit by a revoked member counts is judged by what the revoker had received, never by the author's own timestamps.
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
1. **Transfer finality vs no consensus.** A former owner can always publish a competing story about where a thing went, and nothing tells it from an ex-device's forgery. So a thing never changes owner: moving it is a copy under a new tid with its history imported, and the former owner keeps power only over the old thing and its pointer, never over the copy. A reference by the old tid resolves through the copy's own claim for things whose owner has rights in the copy, else through the pointer. Moving a thing out of its owner's tree should be rare.
2. **Selective sync from untrusted nodes vs hiding structure.** Structure leaks as far as selection needs it.
3. **Cheap edits of large values vs hiding sizes.** Sizes leak, padded coarsely.
4. **Prompt deletion vs history, undo and recovery.** Purge is immediate; undo yields to others' deletions; what a right holder dropped is recoverable only from nodes whose retention still holds it. No node keeps a bin.
5. **Atomic multi-thing changes vs partial fetch and purge.** Atomicity wins: a node syncing part of a change over-fetches, purging part of it rewrites it. Atomicity is about application, not validity: each delta is judged on its own thing, so a revocation on one thing un-merges that delta alone (a node syncing only the other things could not judge it otherwise).
6. **Revocation decidable from records alone vs completeness.** Only the revoker's own receipts decide which of the revoked actor's writes survive, never other members' or an untrusted node's. A revoker syncs before stamping its revoke, so edits parked at untrusted nodes it reaches count; edits at nodes it does not reach, in transit, or passed over by an offline or backdated revoke are lost until re-grant.
7. **Lazy key rotation vs forward secrecy against dishonest untrusted nodes.** An ex-member plus a dishonest untrusted node can read old content, and the box map of the rotation that removed it (that commit is wrapped under the epoch it replaces so members can open it).
8. **Immediate purge at untrusted nodes vs backup safety.** Only the roles an edit names may delete it there, readers never; an edit that allows any writer can be wiped from a server by one at once.
9. **Bounded clocks vs revocation precision.** A window the size of the clock skew.
10. **Deduplication vs forward-secure deletion.** Deduplicate only against content the editor already holds.
11. **Removals beating unseen concurrent adds vs no-fingerprint purge.** An add the remover never saw survives.
12. **Verifiable membership history vs bounded history.** The owner chain may restart a thing's authorization history at a snapshot; grants in flight before it are lost, and briefly-wrong rosters are possible until re-snapshot. Whoever verifies a chain through the snapshot learns the roster's size (never its entries) and pays header bytes proportional to it (one delta hash per edge), so direct rosters should stay in the thousands: nest larger ones.
13. **Lazy rotation vs per-thing sharing.** Removing a party costs proportional to the things shared with it one by one. Usage rule: share sets through one shared actor.
14. **Bounded state vs never discarding an edit.** State grows with edit history, not live size; no horizon drops edits, a sequence reset keeps every old element as a bare anchor so that newer concurrent inserts stay placeable, and set, bag and map tombstones live until the collection is reset. Usage rules: commit per editing pause, never per keystroke; ephemeral membership (presence, selections) uses expiring commits, not add/remove.
15. Merged into 6.
16. **Explicit sync placement vs complete backup.** Nothing syncs by being owned; apps place things into synced groups explicitly, and a forgotten placement leaves a thing local-only.
17. **Reader-originated writes vs junk at untrusted nodes.** A reader's own membership writes, node card and heartbeats, and grants from anyone holding an actor's `/keys`, enter a label only through its deposit budget; junk there is discarded by members and bounded by the budget, and a flooded budget delays grants and readers' own writes until an admin cleans it.
18. Retired.
19. **Byte-identical serialization vs no-fingerprint purge of large values.** Chunk keys must be random (a content-derived key would make a retained blob ID a fingerprint), so two independent writes of one large value differ in their link bytes. Equality of a large value is its keyed content hash, never its bytes.
20. **One schema authority per aspect vs no registry.** Authority over an AK is by convention (namespaced AKs, a schema ID in every header); a collision between two schemas is detected at read time, never prevented, and until detected their writes merge like any concurrent writes.
21. **Lazy rotation vs membership cost proportional to the change.** Removing a member re-seals one box per remaining direct member and role of every actor whose secret it could open (the actor it left and every thing with secrets of its own that it reached through it), so a removal costs proportional to those rosters, never to content or history; and a demotion below write carries a frontier proportional to the breadth of what the demoted authority wrote (per aspect and device), kept in the tenure ledger. Usage rule: share sets through one shared actor (tension 13).
22. **Timed and self-declared removals vs timeline testimony.** An edge ending by `until` or by self-removal audits nothing, so a backdated write by that member stands until another node publishes an explicit demotion; a link key is signed by every holder, so its own claimed times constrain nothing, and link expiry and single use hold against hostile holders only once a sharer's device publishes a real removal.
23. **Newer write never loses vs whole enum values.** An edit inside an enum payload that is concurrent with and newer than a case change stays hidden: surfacing it would flip the case back with a half-written payload. The one place a newer write yields to an older removal.
24. **Newer write never loses vs whole values.** A field write concurrent with and newer than a replace or removal of its container (struct, map entry, list element) survives alone, so the container reappears holding only that field; typed reads see missing fields until someone writes the rest. Inherent to diff-granular writes without causal contexts.
25. **Timed history deletion vs blind backup.** Honest nodes drop a replaced body at its keep-at-most bound; a blind node drops it only on an explicit or timed delete from a right holder, so a body whose right holders were offline at the replacement outlives its bound there.
26. **Purge needs current write permission vs unrevokable delete tokens.** Honest nodes judge a purge by the requester's role now. A blind node checks a token fixed at the edit plus a label key, and the token cannot be revoked without re-encrypting, so an ex-writer or ex-admin that is still a reader can delete its own old `author` bodies, or old `admin` bodies, at a server until a member's next sync re-uploads them.
27. **Lockout-safe rotation vs prompt read cut-off.** Readers never rotate (a rotation sealed to an incomplete roster locks members out), so an actor a person only reads keeps wrapping new content to a lost device until a writer or admin of it next writes.
28. **Bearer links vs per-joiner revocation.** A redeemer may keep the link seed and read as the link key, so one joiner is revoked only together with the link; the remaining joiners get a new one.
29. **Sync-key gating vs bootstrap liveness.** A blind node serves a label only to holders of its current sync key or of a claim key its current step lists, so a member listed in no step since its last sync (a grant the registrar had not seen), or whose missed rotations have been compacted away (after `MEMBERSHIP_KEEP`), or that knows only servers where a removed admin squatted the label, reads the label again only through a later step that lists it or a re-seal by a member that may rotate; re-sealing is triggered by a stranded heartbeat or a missing box, never guaranteed. Recovery and link keys read from the current step once it lists them.
30. **Bounded wire objects vs atomic edits.** One commit is one blob, so an edit larger than a blob is several commits that are not atomic together; other members may see the intermediate states.
31. **Chunk deduplication vs per-delta purge rights.** A chunk carries the tokens of the delta that created it, so an author's purge cannot delete at blind nodes the chunks it reused from another author's version; an admin can, and honest nodes drop the keys.
32. **Fixed ownership and rights-free grouping vs "rights follow the folder".** Rights live on edges, never on group placement, and a thing's owner never changes, so a folder whose rights should cover its contents is an actor that owns them (and moving a thing out of it is a copy), or a helper that mirrors the folder's edges onto each thing it holds. Things a collaborator creates in a shared folder are owned by the collaborator or by the folder actor, as the app chooses at creation.
33. **Passive readers vs participation.** A read member of a label cannot stamp uploads (only deposit under a budget and signal under the deposit key), so anyone who must post or react in a shared space needs write on the space's actor; viewers are passive.
