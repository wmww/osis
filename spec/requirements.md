# Requirements
> Summary: What osis must satisfy: hard requirements, goals, the limits the design accepts, and the threat model. Mechanism-free; every design is checked against it.

Items are hard unless their section says goal. **Limit** marks something the design accepts.

Terms:
- **Thing**: anything with an identity. **Aspect**: one typed datum of a thing. **Group**: a thing that lists things; the unit of sync.
- **Commit**: one signed, atomic edit. **Part**: what a commit writes on one aspect. **Body**: the stored bytes of a part.
- **Actor**: a thing that can hold roles and act (a node, an account, a team, a shared space). Thing, group and actor are overlapping capabilities of one object, not kinds. **Holder**: an actor with a role (read, write, admin) on something.
- **Node**: a running osis instance with its own identity and store. It reads what it holds keys for and keeps the rest encrypted, in any mix; nothing else separates nodes. **Host**: a role, not a kind of node: a node hosts a group by storing it and serving it to others, whether or not it can read it. A node is **untrusted** for data it cannot read.
- **Peer**: another node a node syncs with directly. **Relay**: forwards a connection's encrypted bytes and stores nothing; not a node. **Client**: anything using the osis client protocol to reach a node out of process, on the same machine or another; a node may be one too, for data it doesn't sync itself. **Thin client**: a client that is not a node. Machine, transport and acting actor are independent: which actors a client may act as is a node's policy, not a property of where the client runs.

## Purpose
- End-user apps with small-to-large interconnected data across users and their machines. Many apps, app versions, generic tools and agents share the same data, like a file format.
- Simple, safe Rust. Nothing on the wire path depends on third-party parsers or serialization frameworks. Runs in browsers.

## Threat model
- Hostile admins are not defended against.
- Authenticated malicious writers are bounded, not prevented.
- Malicious readers can only waste storage.
- For data it cannot read a node is trusted for availability only: it can withhold, delay or lose what it holds, and honest nodes still converge through any other route.

## Decentralization
- No central or trusted coordinator, consensus or sequencer. Peer-to-peer like git; any node may be offline indefinitely and return.
- No global registry. Identifiers are minted offline and cannot be hijacked. Total data may exceed what any node tracks.
- Every node that can read data verifies identity and authorization itself from what travels with the data. Nothing trusts the word of the node it came from.
- No unit that must be synced whole. Groupings overlap, nest, may be cyclic and change over time. Syncing one row or one column of a table must each be efficient without duplicating the table at rest or in transfer.
- Convergence under any delivery order, duplicates and partial receipt. No ordered delivery.
- Deterministic: a node's state and its judgment of every write are functions of the data it holds and its trust set (Permissions), never of arrival order. Nodes holding the same bodies and trust sets read alike; a node missing a body reads as if it never had it until it arrives. Limit: a part still waiting for its commit at its expiry goes for good, a body dropped under a compaction snapshot that later turns invalid is missing until a copy arrives, so is an edit a re-grant brings back at a node that dropped it while it did not count, and a purge that falls brings content back only as copies arrive; until a writer next compacts or writes that data, nodes can read differently.
- A commit may touch any number of things, of any reader sets, up to a fixed maximum size (about 140 GB). A node applies all the parts of a commit it may read on things it holds at once, or none; a part on a thing it starts holding later joins then.
- Each part of a commit is authorized on its own thing. Revoking the author on one thing removes only that part.
- A wrong local clock harms only that node's own writes.

## Offline and network
- Every operation completes with nobody else online. Only propagation waits.
- No helper is required: relays, discovery and nodes serving others are replaceable, and anyone can run them. Works over LAN, through any node whether or not it can read the data, or to a known address.
- No public-IP server, always-on node or internet connection is assumed. Every feature (creating accounts, sharing, recovery and the rest) works in every configuration, however atypical, including a dynamic mesh with no internet at all.
- Nodes that share data sync directly by default, between different users too. Privacy of who sees whose address is handled without turning that off.
- Nothing is special-cased by how much of a store is readable: a normal store holds some data it can read and some it cannot.
- No dependence on one transport. Sync works over any ordered byte stream, including files carried by hand.
- A node shows which node, actor or account it is only to nodes of actors it already knows (it holds their keys). To any other node, a relay, or a node holding data it cannot read, it shows only its address, whoever dialed.
- Nothing syncs by being created under an actor: apps add things to synced groups explicitly, and a thing in no synced group stays local.

## Cost (goal)
- Bytes transferred are close to the size of the commit: about 1.2x for large commits is fine, 2x-10x is not. Small commits may carry a fixed overhead of a few hundred bytes.
- Round trips: a small constant in the common incremental case, logarithmic at worst; a holder that missed k key rotations may need k.
- Nothing a node already holds is sent again. A thing in many groups is stored and transferred once per node.
- Compaction and deletion cost proportional to what changed, not to group size or history.
- Removing a holder costs proportional to the rosters of the actors and things it could read, plus its writes the remover and the other writers had received (32 bytes each, at each writer that lists them; on data whose history is kept, every one). Limit: a removal that would list more than about 1.9 million role-class and admin-only writes fails.
- Connected nodes see each other's commits promptly, pushed, not polled.

## Data a node cannot read
- Holding and serving data it cannot read is a first-class feature of every node; one node may read some groups and not others.
- For such data a node may learn volume and the structure selective sync needs: which opaque groups a blob is in and how groups overlap (a commit spanning groups links them), counts, padded sizes, timing, addresses, and what they must act on: each blob's expiry, its class (durable, ephemeral, relayed), its deletion classes and whether a reader deposited it. They must not learn identifiers, keys, values, authors, role grants, node identities, or structure beyond that.
- Nothing stored or relayed links different groups of one actor beyond their overlap and the commits that span them. What a connection reveals (its address, the labels it opens) is network metadata, hidden only by routing through a relay or an anonymity network.
- One protocol for all nodes. Peers differ only in which keys they hold.
- A node that cannot read data may hold its only copy. Reading never allows deleting data or forcing a re-upload.
- For data it cannot read, a node knows no role holders and never waits on their liveness.
- Read access never allows storing arbitrary content at a node that cannot read it. Such a node stores content only with a writer's signature, beyond a small budget per group open to anyone who must reach the group's readers (grants, readers' own edge writes). Limit: anyone holding an actor's public keys can fill its inbox's budget at a node serving it, up to that node's rates, while none of the inbox's admin nodes is online or by flooding without pause; meanwhile grants wait and unanswered invites may be pushed out.
- Goal: a node can limit abuse (storage, rate) of data it cannot read without learning identities.

## Confidentiality between readers
- A reader learns only what it may read. Sharing one thing does not reveal values from another, and only metadata if both things are part of the same commit.
- No identifier on the wire is predictable without a read key. Nothing derives from plaintext that could be guessed.
- Readers of shared data may learn each other's node identities, the roster of every actor holding a role on it (directly or through other actors), and the chain that authorizes each author, never the entries of other rosters.
- Deleting content leaves the fact, time, author and aspect of the edit visible to readers.
- No secret ever passes where a node without the keys meant to open it could read it.
- Secrets that must stay secret for years resist a future quantum attacker. Signatures need not.

## Deletion
- Retention per edit: who may purge it (nobody, admins, the author, the author or admins, any writer) and what happens to its history once it is replaced (by default nothing is promised; kept until a time and/or a while after it is replaced; or purged once replaced). Defaults per aspect, overridable per write, immutable once written.
- A purge counts only if its author had the right to make it, judged as the validity of an edit is (removals and re-grants included). Limit: a node that cannot read the data checks only the role the deleter held when the edit was written and current roles, so a demoted holder can still delete there what its old role allowed, until a reader holding the data next syncs it back.
- Data may carry an expiry at which every node, whether or not it can read it, drops it with nobody online.
- Purge is prompt: no honest node keeps purged content once it has seen the deletion. No batching. Undo never brings back what another party purged, once the undoing node has seen the purge; an earlier undo is its own commit, purged on its own. Purged content is recoverable only from nodes whose retention still holds it; no node keeps a bin.
- Limit: deletion does not reach offline copies, copies a removed holder kept, dishonest nodes, memory or swap.
- A node without write on data acts on its own only for expiry. Every other drop is a right holder's (a purge, or a compaction snapshot covering the body), taking effect elsewhere when it arrives.
- Purge on replace: replaced content is gone at every writer holding it as soon as it holds the replacement, and everywhere else when such a writer's snapshot arrives. Limit: while no writer holding both is online, other nodes keep it. Limit: if the replacing write later turns invalid, the snapshot written after it still carries it, so the replaced content does not come back. Expired and purged content never returns while the purge counts.
- Granularity is one edit of one aspect. Part of a value's history can be purged.
- No fingerprint: nothing retained lets anyone, even a reader, confirm a guess of purged content, however low-entropy.
- Forward secure where the platform offers erasable key storage (a hardware keystore, a TPM): a node that deleted honestly and is compromised later yields nothing. Elsewhere, browsers included, deleted data is unrecoverable through the platform's own storage only. A node that lost access to data yields nothing it can no longer read, unless its removal said to keep a read-only copy; the default is to erase.
- Nothing depends on retaining full history.

## Ephemeral data
- Ephemeral state lives in memory, converges among the nodes holding it like any state, outlives contact with its author, and may be lost when no node holds it. A node that restarts gets it back from those that still do.
- A value that should live only while its author is there (a cursor, a selection) is ephemeral with an expiry its author renews by rewriting it while there; once the author is gone it is gone everywhere by its last write's expiry, with no departure seen by anyone.
- Signals have no lasting value: they reach the nodes connected at the time, once, with no delivery guarantee, and are held by nobody.
- Ephemeral writes need the rights the durable write would need and are verified like it; readers cannot write ephemeral data. Memory spent on others' ephemeral data is bounded per group, with a defined outcome past the bound.
- "Deterministic" and "Convergence" bind ephemeral data too.
- Nothing is kept "until everyone has seen it". Whether others are alive is never a protocol condition.

## Scale
- Many GB per node, multi-GB single values, maps with millions of keys, millions of blobs per group. No operation is O(total data) or O(history). A change inside a huge value costs O(change).
- State grows with the number of edits and removals ever made, a few bytes each, not only with live data. No horizon ever drops an edit.
- Exception: a thing's role history. It keeps every role change ever made, a few hundred bytes each, and a node that starts holding the thing fetches and judges all of it.
- Exception the app chooses: under "purge on replace", every edit that replaces earlier content costs a snapshot of that aspect, O(the aspect's state), at each writer holding the replaced content uncovered: on a 2000-entry map (about 250 KB) about 0.5 MB written and 0.2 s per edit, against 36 KB and 1 ms with no history promised.
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
- One canonical serialization and one hash function: equal values compare equal on every node.
- Every datum is an aspect of a thing. Values are typed by the writer's schema. References may dangle.
- Per-aspect merge with one conflict rule everywhere: at a position the later write wins, and a removal is final.
  - At a position (a register, a struct's field, an aspect) a write newer than a concurrent reset shows.
  - A write inside a map entry, list element or enum case shows only while that entry, element or case is live (its creation or case write survives). A write never brings back what was removed, expired or switched away from; only a new creation does. So an edit concurrent with the removal of what it is in is lost.
  - Removing from a collection drops only what the remover had seen.
- Collaborative text and lists.

## Permissions
- Two concepts only: actor and role. Every thing's creation names its first admin, fixed in its identity; the first admin is an ordinary admin, removable like any other. Sharing never changes a thing's identity.
- Grouping for sync grants no rights. A membership may be written together with a grant tied to it, which ends when the membership does.
- Readers only read: posting into a shared space needs write on its actor.
- Every write is attributable to a signing key actor (normally a node) and verifiable. Hiding authorship is a deliberate choice, never the default.
- Rights held by different parties never combine into a right neither has alone. Limit: a writer who lies about when it received an edit can make a removed party's own signed edit count (spec/permissions.md §5.2, addenda).
- Whether an edit by a revoked holder counts is judged by what the revoker and the other writers had received by the revocation, never by the author's own timestamps; readers and hosts vouch for nothing. Limit: edits no writer had received when it revoked are lost, and so are others' edits that the other writers held only in the revoked writer's compacted copies. Re-granting the holder brings back only the lost edits some node still has. Limit: a removed holder's write that another writer compacted before the removal reached it stays wherever that snapshot is held, and is removed by an admin's reset or revert.
- Admins are equals: no admin outranks another, and no removal settles a fight between admins (a removal voided by writes its author had not received, the removed admin's own or another admin's). Each node settles such a dispute for itself, by a trust set that is an input to its judgment, and reports it; nodes on different sides read the disputed thing and what it reaches differently until they side alike. A side changes nothing outside the disputed thing's reach. Limit: a removed admin's backdated writes stand at every node that has not sided against them.
- A removal nobody stamps (a timed grant ending, a self-removal, a link expiring) cuts off nothing by itself: until another holder publishes an explicit demotion, the removed holder's own timestamps decide, within the allowed clock drift.
- A share link is a bearer secret. One joiner is revoked only together with the link; the remaining joiners get a new one.
- A secret once shared cannot be un-shared: a party that held a key keeps everything it opens, and any holder of a key may hand it to another. Removing a holder never re-encrypts existing content; what it could read before removal stays readable to it, from a copy it kept or from a dishonest node. The holder stops reading new content of an actor once a writer or admin of that actor has written after the removal; readers never rotate keys.
- A role an actor M holds on A reaches the parties holding roles on M; A never depends on who they are. A party removed from M stops reading A's new content once M's keys were changed knowing the removal and a writer or admin of A has written since. Limit: until then it may read A's content written since the removal, not only new content.
- Actors may hold roles on each other in a cycle; the grant that would close a cycle of read access gives its holder no read access through it (the earlier grant wins). Limit: a party removed from an actor on such a cycle may read the other actors' new content until a writer that has seen every grant of the cycle has written.
- Limit: a holder whose grant raced a key rotation, or that missed more rotations than a node that cannot read the data keeps role history for, cannot read through that node until a holder with rotation rights re-seals to it, which nothing guarantees.

## API
- Plain values and listeners. No CRDT concepts, no conflict UI, no correctness that depends on "surfacing it to the user". Diagnostics are informational.
- Atomic (Decentralization), not isolated: concurrent commits merge, so app invariants must hold under merge. A commit is never split: a write is one commit or is refused. Limit: one commit cannot mix expiries, or mix data nobody may purge with other data; the app writes those as separate commits.
- Untyped access always works on any stored data.
- Large values are usable both materialized and streamed.
