# Requirements
> Summary: What osis must satisfy: hard requirements, goals, the limits the design accepts, and the threat model. Mechanism-free; every design is checked against it.

Items are hard unless their section says goal. **Limit** marks something the design accepts.

Terms:
- **Thing**: anything with an identity. **Aspect**: one typed datum of a thing. **Group**: a thing that lists things; the unit of sync.
- **Change**: one signed, atomic edit (a commit). **Part**: what a change writes on one aspect. **Body**: the stored bytes of a part.
- **Actor**: a thing that can hold rights (a device, person, team, shared space). **Holder**: an actor with a role (read, write, admin) on something.
- **Untrusted (blind) node**: a node that stores or relays data it cannot read. **Host**: a node that stores and serves a group's data.

## Purpose
- End-user apps with small-to-large interconnected data across users and devices. Many apps, app versions, generic tools and agents share the same data, like a file format.
- Simple, safe Rust. Nothing on the wire path depends on third-party parsers or serialization frameworks. Runs in browsers.

## Threat model
- Hostile admins are not defended against.
- Authenticated malicious writers are bounded, not prevented.
- Malicious readers can only waste storage.
- Untrusted nodes are trusted for availability only: one can withhold, delay or lose what it holds, and honest nodes still converge through any other route.

## Decentralization
- No central or trusted coordinator, consensus or sequencer. Peer-to-peer like git; any node may be offline indefinitely and return.
- No global registry. Identifiers are minted offline and cannot be hijacked. Total data may exceed what any node tracks.
- Every node that can read data verifies identity and authorization itself from what travels with the data. Nothing trusts a host's word.
- No unit that must be synced whole. Groupings overlap, nest, may be cyclic and change over time. Syncing one row or one column of a table must each be efficient without duplicating the table at rest or in transfer.
- Convergence under any delivery order, duplicates and partial receipt. No ordered delivery.
- Deterministic: a node's state and its judgment of every write are functions of the data it holds, never of arrival order. Nodes holding the same bodies read alike; a node missing a body reads as if it never had it until it arrives. Limits:
  - Parts of a change across things that applied before one of those things entered what the node syncs stay applied, while the other parts stay away.
  - A holder may look removed on a node that joined late, until the rest of a roster snapshot arrives. Only a hiding host or lost author makes this last.
  - On an aspect with a keep-at-most bound or expiry, if a validity flip or purge lands after a body was dropped, nodes may read it differently until a writer holding it next compacts, or the next write of that data.
  - A part that expires before a node applies it counts as never received there: that node may read what came before it until a writer next compacts. The expired value itself never shows.
- A change may touch any number of things, of any owners and reader sets. Only its header's lists bound its size: about 140 GB of chunks in one change; past that the writer gets a plain refusal. A node applies all the parts it may read and syncs at once, or none of them.
- Each part of a change is authorized on its own thing. Revoking the author on one thing removes only that part.
- A wrong local clock harms only that node's own writes.

## Offline and network
- Every operation completes with nobody else online. Only propagation waits.
- No helper is required: relays, discovery and hosts are replaceable and self-hostable. Works over LAN, through any untrusted node, or to a known address.
- No dependence on one transport. Sync works over any ordered byte stream, including files carried by hand.
- To untrusted nodes and relays the network layer reveals no more about a device than the network itself does: addresses, never identities.
- Nothing syncs by being owned: apps place things into synced groups explicitly, and a thing placed nowhere stays local.

## Cost (goal)
- Bytes transferred are close to the size of the change: about 1.2x for large changes is fine, 2x-10x is not. Small changes may carry a fixed overhead of a few hundred bytes.
- Round trips: a small constant in the common incremental case, logarithmic at worst; a holder that missed k key rotations may need k.
- Nothing a node already holds is sent again. A thing in many groups is stored and transferred once per node.
- Compaction and deletion cost proportional to what changed, not to group size or history.
- Removing a holder costs proportional to the rosters of the actors and things it could read, plus its writes that compaction may not drop yet. Limit: on data whose history is kept, that is every kept write of the removed device (about 32 B each); a removal listing more than one header list holds (about 1.9 million writes) fails.
- Connected nodes see each other's changes promptly, pushed, not polled.

## Untrusted (blind) nodes
- Untrusted nodes are a first-class feature; one node may be blind to some groups and read others.
- They may learn volume and the structure selective sync needs: which opaque groups a blob is in and how groups overlap (one change's blob may sit under labels that share no thing), counts, padded sizes, timing, addresses, and what they must act on: each blob's expiry, its class (durable, ephemeral, relayed), its deletion classes and whether a reader deposited it. They must not learn identifiers, keys, values, authors, role grants, device identities, or structure beyond that.
- Nothing stored or relayed links different groups of one owner beyond their overlap and the changes that span them. What a connection reveals (its address, the labels it opens) is network metadata, hidden only by routing through a relay or an anonymity network.
- One protocol for all nodes. Trusted and untrusted peers differ only in which keys they hold.
- An untrusted node may hold the only copy. Reading never allows deleting data or forcing a re-upload.
- An untrusted node knows no role holders and never waits on their liveness.
- Read access never allows storing arbitrary content there. An untrusted node stores content only with a writer's signature, beyond a small flagged budget per group open to anyone who must reach the group's readers. While the budget is full, what goes through it (grants, readers' own edge writes) waits. Limits:
  - Anyone holding an actor's public keys can fill the budget of its inbox, per host, only while none of the inbox group's admins' devices is online, or by flooding without pause, up to the host's rates. That can push out invites its user has not answered. It empties when the flood stops.
  - A sender whose changes the actor's devices take unasked (one holding a role on a group the actor syncs) is limited by the host's rates and storage caps, not the budget, until the actor removes it. Its entries stay up to 90 days, a copy of each grant longer.
- Goal: an untrusted node can limit abuse (storage, rate) without learning identities.

## Confidentiality between readers
- A reader learns only what it may read. Sharing one thing does not reveal values from another, and only metadata if both things are part of the same commit.
- No identifier on the wire is predictable without a read key. Nothing derives from plaintext that could be guessed.
- Readers of shared data may learn each other's device identities, the chain that authorizes each author, and the sizes of the rosters in that chain, never the entries of rosters they are not part of.
- Deleting content leaves the fact, time, author and aspect of the edit visible to readers.
- No secret ever passes where an untrusted node could read it.
- Secrets that must stay secret for years resist a future quantum attacker. Signatures need not.

## Deletion
- Retention per edit: who may purge it (nobody, admins, the author, the author or admins, any writer) and how long its history is kept (at least: absolute or a while after it is replaced; at most: absolute, or gone once replaced). Defaults per aspect, overridable per change, immutable once written.
- Honest nodes judge the purge right at the time of the request. Limit: an untrusted node can only check the role the deleter held when the edit was written plus current roles, so a demoted holder can still delete there what its old role allowed, until a co-reader's next sync restores the data.
- Data may carry an expiry at which every node, untrusted ones included, drops it with nobody online. A change has one expiry, and data nobody may purge shares a change only with such data; a write mixing either is several changes.
- Purge is prompt: no honest node keeps purged content once it has seen the deletion. No batching. Undo never brings back what another party purged, once the undoing device has seen the purge; an earlier undo is its own change, purged on its own. Purged content is recoverable only from nodes whose retention still holds it; no node keeps a bin.
- Limit: deletion does not reach offline copies, dishonest nodes, memory or swap. A purge made after a removal may stay undone in a copy the removal let the holder keep.
- Untrusted nodes act on their own only for expiry. Every other retention bound takes effect at them when a right holder next syncs.
- A body dropped at its keep-at-most bound stays dropped only at nodes that cannot get it back: if the write that replaced it turns out invalid, the value is live and returns from any node that still holds it. Expired and purged content never returns. Exception: an admin's demotion that leaves a purge out of its frontier undoes that purge wherever a copy is left.
- Granularity is one edit of one aspect. Part of a value's history can be purged. An author's purge of a large value removes at untrusted nodes only the chunks that author wrote; an admin's removes all of them.
- No fingerprint: nothing retained lets anyone, even a reader, confirm a guess of purged content, however low-entropy. Deduplication is therefore only against content the writer already holds.
- Forward secure where the platform offers erasable key storage (a hardware keystore, a TPM): a node that deleted honestly and is compromised later yields nothing. Elsewhere, browsers included, deleted data is unrecoverable through the platform's own storage only. A node that lost access to data yields nothing it can no longer read, unless its removal said to keep a read-only copy; the default is to erase.
- Nothing depends on retaining full history.

## Ephemeral data
- Ephemeral state lives in memory, converges among the nodes holding it like any state, outlives contact with its author, and may be lost when no node holds it. A node that restarts gets it back from those that still do.
- A value that should live only while its author is there (a cursor, a selection) is ephemeral with an expiry its author renews by rewriting it while there; once the author is gone it is gone everywhere by its last write's expiry, with no departure seen by anyone.
- Signals have no lasting value: they reach the devices connected at the time, once, with no delivery guarantee, and are held by nobody.
- Ephemeral writes need the rights the durable write would need and are verified like it; readers cannot write ephemeral data. Memory spent on others' ephemeral data is bounded per group, with a defined outcome past the bound.
- "Deterministic" and "Convergence" bind ephemeral data too.
- Nothing is kept "until everyone has seen it". Whether others are alive is never a protocol condition.

## Scale
- Many GB per node, multi-GB single values, maps with millions of keys, millions of blobs per group. No operation is O(total data) or O(history). A change inside a huge value costs O(change).
- State grows with the number of edits and removals ever made, a few bytes each, not only with live data. No horizon ever drops an edit.
- Direct rosters hold thousands of holders; larger ones nest.
- Every wire object has a fixed maximum size. Peer input never causes a panic or unbounded allocation, work, storage or diagnostics.
- Large values stream; no whole value is ever needed in memory.

## Generality (goal)
The properties above hold for any use of the data. The only usage rules are:
- Share a set of things through one shared actor, not one by one (removal cost).
- Commit per editing pause, never per keystroke (state growth).
- Presence and selections use expiring ephemeral writes, not durable add and remove (state growth).
- Nest rosters past the thousands (header cost).

## Versioning
Binds released formats only; until a stable release formats change in place.
- Never discard, reject or crash on data not understood: store it, relay it, merge what can be merged, re-examine after upgrade.
- Old data stays readable forever. Nodes write what older nodes can read until a new feature is actually used.
- Everything on the wire is open and only grows: no identifier reused, nothing removed, no in-place change of meaning. Nothing in the data is irreversible.
- Each aspect has one schema authority, by naming convention. Nothing on the wire names a schema, so a collision between two schemas is never prevented and is detected only where their types differ, as a typed-read failure. Merge needs no schema. The core distributes no schemas.
- An app update never by itself changes stored data. No migrations. No global agreement on who has upgraded.
- Cryptographic primitives can be replaced without re-encrypting or re-signing old data.

## Data model
- One canonical serialization, byte-identical everywhere. One hash function. The one exception is the random keys inside a large value: two writes of equal content differ in bytes, so large values compare by content hash.
- Every datum is an aspect of a thing. Values are typed by the writer's schema. References may dangle.
- Per-aspect merge with one conflict rule everywhere: at a position the later write wins, and a removal is final.
  - At a position (a register, a struct's field, an aspect) a write newer than a concurrent reset shows.
  - A write inside a map entry, list element or enum case shows only while that entry, element or case is live (its creation or case write survives). A write never brings back what was removed, expired or switched away from; only a new creation does. So an edit concurrent with the removal of what it is in is lost.
  - Removing from a collection drops only what the remover had seen.
- Collaborative text and lists.

## Permissions
- Three concepts only: actor, role, ownership. Every thing has exactly one owner, fixed at creation; a thing never changes owner. Sharing never changes a thing's identity.
- Grouping for sync grants no rights. A placement may be written together with a grant tied to it, which ends when the placement does.
- Readers only read: posting into a shared space needs write on its actor.
- Every write is attributable to a signing key actor (normally a device) and verifiable. Hiding authorship is a deliberate choice, never the default.
- Rights held by different parties never combine into a right neither has alone.
- Whether an edit by a revoked holder counts is judged by what the revoker had received, never by the author's own timestamps. Edits the revoker had not received when it revoked are lost until re-grant, except those another writer compacted before it learned of the revocation, which stay.
- A removal nobody stamps (a timed grant ending, a self-removal, a link expiring) cuts off nothing by itself: until another holder publishes an explicit demotion, the removed holder's own timestamps decide, within the allowed clock drift. A timed grant's end is finalized by the next writer about to write after it (an admin for an admin grant), whose removal rotates.
- The owner may restart a thing's role history at a roster snapshot; a role change ordered before the snapshot that it did not include is lost.
- A share link is a bearer secret. One joiner is revoked only together with the link; the remaining joiners get a new one.
- Removing a holder never re-encrypts existing content. The holder stops reading new content of an actor once a writer or admin of that actor has written after the removal; readers never rotate keys. Limit: what it could read before removal stays readable to it, from a copy it kept or from a dishonest untrusted node.
- Limit: a holder an untrusted node does not list yet (its grant raced a key rotation), or that missed more rotations than the kept role history, reads from that node again only after a holder with rotation rights re-seals. Re-sealing is triggered, never guaranteed.

## API
- Plain values and listeners. No CRDT concepts, no conflict UI, no correctness that depends on "surfacing it to the user". Diagnostics are informational.
- Atomic, not isolated: concurrent changes merge, so app invariants must hold under merge. Exception: a node may show a commit without a part that is still to arrive when a later snapshot of that part's aspect, by a possible writer of it, is held.
- Untyped access always works on any stored data.
- Large values are usable both materialized and streamed.
