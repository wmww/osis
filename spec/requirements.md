# Requirements
> Summary: What osis must satisfy and what it deliberately does not: hard requirements, goals, the limits the design accepts, and the threat model. Mechanism-free; every design is checked against it.

Items are hard unless a section says goal. A design that cannot meet an item does not get a footnote: the item is changed to say what actually holds (significant changes need owner sign-off).

## Purpose
- End-user apps with small-to-large interconnected data across users and devices. Many apps, app versions, generic tools and agents share the same data, like a file format.
- Simple, safe Rust. Nothing on the wire path depends on third-party parsers or serialization frameworks. Runs in browsers.

## Decentralization
- No central or trusted coordinator, consensus or sequencer. Peer-to-peer like git; any node may be offline indefinitely and return.
- No global registry. Identifiers are minted offline and cannot be hijacked. Total data may exceed what any node tracks.
- Every node that can read data verifies identity and authorization itself from what travels with the data. Nothing trusts a server's word.
- No unit that must be synced whole. Groupings overlap, nest, may be cyclic and change over time. Syncing one row or one column of a table must each be efficient without duplicating the table at rest or in transfer.
- Convergence under any delivery order, duplicates and partial receipt. No ordered delivery.
- Deterministic: a node's state and its judgment of every write are functions of the data it holds, never of arrival order.
- A change may touch any number of things, of any owners and reader sets, with no size limit. A node applies all the parts it may read and syncs at once, or none of them.
- Each part of a change is authorized on its own thing. Revoking the author on one thing removes only that part.

## Offline and network
- Every operation completes with nobody else online. Only propagation waits.
- No helper is required: relays, discovery and hosted servers are replaceable and self-hostable. Works over LAN, through any untrusted node, or to a known address.
- No dependence on one transport. Sync works over any ordered byte stream, including files carried by hand.
- To untrusted nodes and relays the network layer reveals no more about a device than the network itself does: addresses, never identities.
- Nothing syncs by being owned: apps place things into synced groups explicitly, and a thing placed nowhere stays local.

## Cost (goal)
- Bytes transferred are close to the size of the change: about 1.2x for large changes is fine, 2x-10x is not. Small changes may carry a fixed overhead of a few hundred bytes.
- Round trips: a small constant in the common incremental case, logarithmic at worst; a member that missed k membership rotations may need k.
- Nothing a node already holds is sent again. A thing in many groups is stored and transferred once per node.
- Compaction and deletion cost proportional to what changed, not to group size or history.
- Removing a member costs proportional to the rosters of the actors and things it could read, plus one entry per aspect it wrote, never to content or history.
- Connected nodes see each other's changes promptly, pushed, not polled.

## Untrusted (blind) nodes
- Keyless nodes without access to the data they store or relay are a first-class feature.
- They may learn volume and the structure selective sync needs: which opaque groups a blob is in and how groups overlap, counts, padded sizes, timing, addresses, and what they must act on: each blob's expiry, its class (durable, ephemeral, presence, relayed), its deletion class and whether a reader deposited it. They must not learn identifiers, keys, values, authors, membership, device identities, or structure beyond that.
- Nothing stored or relayed links different groups of one owner beyond their overlap. What a connection reveals (its address, the labels it opens) is network metadata, hidden only by routing through a relay or an anonymity network.
- One protocol for all nodes. Trusted and untrusted peers differ only in which keys they hold.
- An untrusted node may hold the only copy. Reading never allows deleting data or forcing a re-upload.
- Read access never allows storing arbitrary content there. It stores content only on a writer's word, beyond a small flagged budget per group open to anyone who must reach the group's members. Members can clear the budget; while it is full, what goes through it (grants, readers' own membership writes) waits.
- It knows no members and never waits on their liveness.
- Goal: it can limit abuse (storage, rate) without learning identities.

## Confidentiality between readers
- A reader learns only what it may read. Sharing one thing reveals nothing of another beyond the fact that one change touched both.
- No identifier on the wire is predictable without a read key. Nothing derives from plaintext that could be guessed.
- Readers of shared data may learn each other's device identities, the chain that authorizes each author, and the sizes of the rosters in that chain, never the entries of rosters they are not part of.
- Deleting content leaves the fact, time, author and aspect of the edit visible to readers.
- No secret ever passes where an untrusted node could read it.
- Secrets that must stay secret for years resist a future quantum attacker. Signatures need not.

## Deletion
- Retention per edit: who may purge it (nobody, admins, the author, any writer) and how long its history is kept (at least and at most, absolute or after it is replaced). Defaults per aspect, overridable per change, immutable once written. Honest nodes judge the purge right at the time of the request. An untrusted node can only check the role the deleter held when the edit was written plus current membership, so a demoted member can still delete there what its old role allowed, until the next member sync restores the data.
- Data may carry an expiry at which every node, untrusted ones included, drops it with nobody online.
- Purge is prompt: no honest node keeps purged content once it has seen the deletion. No batching. Undo never brings back what another party purged. Purged content is recoverable only from nodes whose retention still holds it; no node keeps a bin.
- Untrusted nodes act on their own only for expiry and for deletes scheduled when a value is replaced. Every other retention bound takes effect at them when a right holder next syncs.
- Erasure is final: a body dropped at its keep-at-most bound stays dropped if the write that replaced it later turns invalid. This is the one place where nodes holding the same data may read differently: whether that erased value shows again.
- Granularity is one edit of one aspect. Part of a value's history can be purged. An author's purge of a large value removes at untrusted nodes only the chunks that author wrote; an admin's removes all of them.
- No fingerprint: nothing retained lets anyone, even a reader, confirm a guess of purged content, however low-entropy. Deduplication is therefore only against content the writer already holds.
- Forward secure: a node that deleted honestly and is compromised later yields nothing. A node that lost access to data yields nothing it can no longer read.
- Nothing depends on retaining full history.

## Ephemeral data
- Ephemeral state lives in memory, converges among the nodes holding it like any state, outlives contact with its author, and may be lost when no node holds it. A node that restarts gets it back from those that still do.
- Values tied to their author's presence converge once every holder sees the departure.
- Signals have no lasting value: they reach the devices connected at the time, once, with no delivery guarantee, and are held by nobody.
- Ephemeral writes need the rights the durable write would need and are verified like it; readers cannot write ephemeral data. Memory spent on others' ephemeral data is bounded per group, with a defined outcome past the bound.
- Ephemeral data is exempt from neither "Deterministic" nor "Convergence".
- Nothing is kept "until everyone has seen it". Whether others are alive is never a protocol condition.

## Scale
- Many GB per node, multi-GB single values, maps with millions of keys, millions of blobs per group. No operation is O(total data) or O(history). A change inside a huge value costs O(change).
- State grows with the number of edits and removals ever made, a few bytes each, not only with live data. No horizon ever drops an edit.
- Direct rosters hold thousands of members; larger ones nest.
- Every wire object has a fixed maximum size. Peer input never causes unbounded allocation, work, storage or diagnostics.
- Large values stream; no whole value is ever needed in memory.

## Generality (goal)
The properties above hold for any use of the data. The only usage rules are:
- Share a set of things through one shared actor, not one by one (removal cost).
- Commit per editing pause, never per keystroke (state growth).
- Ephemeral membership such as presence or selections uses presence aspects, not durable add and remove (state growth).
- Keep direct rosters in the thousands; nest larger ones (header cost).

## Versioning
Binds released formats only; until a stable release formats change in place (spec/overview.md, Conventions).
- Never discard, reject or crash on data not understood: store it, relay it, merge what can be merged, re-examine after upgrade.
- Old data stays readable forever. Nodes write what older nodes can read until a new feature is actually used.
- Everything on the wire is open and only grows: no identifier reused, nothing removed, no in-place change of meaning. Nothing in the data is irreversible.
- Each aspect has one schema authority, held by convention (namespaced keys); a collision between two schemas is detected at read time, never prevented. Merge needs no schema. The core distributes no schemas.
- An app update never by itself changes stored data. No migrations. No global agreement on who has upgraded.
- Cryptographic primitives can be replaced without re-encrypting or re-signing old data.

## Data model
- One canonical serialization, byte-identical everywhere. One hash function. The one exception is the random keys inside a large value: two writes of equal content differ in bytes, so large values compare by content hash.
- Every datum is an aspect of a thing. Values are typed by the writer's schema. References may dangle.
- Per-aspect merge with one conflict rule everywhere. A newer write never loses to an older removal: a write into a container concurrent with the container's removal brings the container back holding that write alone. The one exception is an enum: a write into a case's payload concurrent with a switch to another case stays hidden. Removing from a collection drops only what the remover had seen.
- Collaborative text and lists.

## Permissions
- Three concepts only: actor, membership, ownership. Every thing has exactly one owner, fixed at creation. Moving a thing to another owner is a copy with imported history, and rare; the old owner keeps power only over the original. Sharing never changes a thing's identity.
- Grouping for sync grants no rights.
- Readers only read: posting into a shared space needs write on its actor.
- Every write is attributable to a signing key actor (normally a device) and verifiable. Hiding authorship is a deliberate choice, never the default.
- Rights held by different parties never combine into a right neither has alone.
- Whether an edit by a revoked member counts is judged by what the revoker had received, never by the author's own timestamps. Edits the revoker had not received when it revoked are lost until re-grant, except those another writer compacted before it learned of the revocation, which stay.
- A removal nobody stamps (a timed grant ending, a self-removal, a link expiring) cuts off nothing by itself: until another member publishes an explicit demotion, the member's own timestamps decide, within the allowed clock drift.
- The owner may restart a thing's membership history at a roster snapshot; a membership write ordered before the snapshot that it did not include is lost.
- A share link is a bearer secret. One joiner is revoked only together with the link; the remaining joiners get a new one.
- Removing a member never re-encrypts existing content. The member stops reading new content of an actor once a writer or admin of that actor has written after the removal; readers never rotate keys.

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
- Forward secrecy against a removed member: what it could read before removal stays readable to it, from a copy it kept or from a dishonest untrusted node.
- A member an untrusted node does not list yet (its grant raced a rotation) or that missed more rotations than the kept membership history reads from that node again only after a member with rotation rights re-seals; re-sealing is triggered, never guaranteed.
- Anonymity against network, timing and style analysis.
