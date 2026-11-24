# Requirements
> Summary: The basic concepts of osis and the properties any build of it must have, as users and app developers observe them. Mechanism-free; the precise rules are in the subsystem specs.

Each item is a property that must hold, hard unless its section says goal. A property that holds only in a weaker form is stated in that form. Where a build falls short of an item, that is an issue to fix, never an exception written here; what is acceptable is already inside the items as stated. Nothing here describes how osis is built, and nothing is promised that nobody needs.

## Concepts
- **Thing**: anything with an identity. **Aspect**: one typed datum of a thing. Every datum is an aspect of a thing.
- **Reference**: a value pointing at a thing. A **strong** reference says its target belongs with the thing holding it; a **weak** one only points. Holding a reference grants nothing.
- **Closure** of a thing: it and everything it references strongly, directly or through other things. Its **sync unit**: the part of its closure it can itself read, which is what syncs as one.
- **Commit**: one signed, atomic edit. **Part**: what a commit writes on one aspect.
- A thing is **created** by its creation record, which names its mint admin, and **destroyed** when its creation is purged or expires. A node **releases** a thing when nothing it holds references it strongly any more; a released thing is not destroyed.
- **Role**: sync, read, write or admin, held by one thing on another. A **holder** is a thing with a role on something. Sync stores and serves data without reading it.
- **Node**: a running osis instance with its own key and store. It reads what it holds keys for and stores and serves the rest encrypted, in any mix; nothing else separates nodes. A node is **untrusted** for data it cannot read.
- **Account**: the identity a person's (or anything else's) nodes act as, and where others reach it: an ordinary thing its nodes hold roles on.
- **Actor**: a thing a write is made through: the thing whose key signs it, then each thing whose role it uses, in order (a node, its account, a thing the account holds a role on). Being an actor is a part played in a write, not a kind of thing.
- **Peer**: another node a node syncs with directly. **Relay**: forwards a connection's encrypted bytes and stores nothing; not a node. **Client**: anything using the osis client protocol to reach a node out of process, on the same machine or another. Which accounts a client may act as is the node's policy, not a property of where the client runs.

## Purpose
- End-user apps with small-to-large interconnected data across users and their machines. Many apps, app versions, generic tools and agents share the same data, like a file format.
- Simple, safe Rust. Nothing on the wire path depends on third-party parsers or serialization frameworks. Runs in browsers.

## Threat model
- Hostile admins are not defended against.
- Authenticated malicious writers are bounded, not prevented.
- Malicious readers can only waste storage.
- For data it cannot read a node is trusted for availability only: it can withhold, delay or lose what it holds, and honest nodes still converge through any other route.
- Deletion and removal bind honest nodes that receive them. Nothing recalls data, or a key, from a party that had it.

## Decentralization
- No central or trusted coordinator, consensus or sequencer. Peer-to-peer like git; any node may be offline indefinitely and return, and its edits still merge.
- No global registry. Identifiers are minted offline and cannot be hijacked. Total data may exceed what any node tracks.
- Every node that can read data verifies identity and authorization itself from what travels with the data. Nothing trusts the word of the node it came from.
- No unit that must be synced whole. References overlap, nest, may be cyclic and change over time. Syncing one row or one column of a table must each be efficient without duplicating the table at rest or in transfer.
- Deterministic: what a node reads and which writes it counts as valid are functions of the data it holds and its trust set (Permissions). A node missing some data reads as if it never had it until it arrives.
- Convergence: nodes that exchange what they hold come to read alike, whatever the order, duplication or partial receipt, at the latest once a writer of that data has synced with them. No ordered delivery.
- A commit may touch thousands of things, of any reader sets, with values of any size; a write too large for one commit is refused whole, never split. A node applies all the parts of a commit it may read on things it holds at once, or none; a part on a thing it starts holding later joins then.
- Each part of a commit is authorized on its own thing. Revoking the author on one thing removes only that part.
- A wrong local clock harms only that node's own writes.

## Offline and network
- Every operation completes with nobody else online. Only propagation waits.
- No helper is required: relays, discovery and nodes serving others are replaceable, and anyone can run them. Works over LAN, through any node whether or not it can read the data, or to a known address.
- No public-IP server, always-on node or internet connection is assumed. Every feature works in every configuration, however atypical, including a dynamic mesh with no internet at all.
- Nodes that share data sync directly by default, between different users too. Privacy of who sees whose address is handled without turning that off.
- Nothing is special-cased by how much of a store is readable: a normal store holds some data it can read and some it cannot.
- No dependence on one transport. Sync works over any ordered byte stream, including files carried by hand.
- Which nodes a node connects to, identifies itself to and syncs with is its account's (and node's) choice.
- A node holds exactly what its own references reach. Nothing syncs for having been created with some admin, and a thing is shared only by granting a role; the grantee's node syncs it once a strong reference it holds reaches it and it has learned where the thing is, from the grant's notice or from something it already syncs. A grant is the granted thing's own: its holder may be unable to reach the thing, or not know of the grant.

## Cost (goal)
- Bytes transferred and stored are close to the size of what changed. A small commit carries a small fixed overhead; a thing that was never shared directly costs little more than its content.
- Round trips: a small constant in the common incremental case; a holder that missed key changes may need one per change.
- Nothing a node already holds is sent again. Data reachable from many places is stored and transferred once per node.
- Every operation costs in proportion to what it changes, never to the size of what holds it, to total data, or to history.
- Removing a holder costs in proportion to the rosters of what it could read and to those of its edits the other writers still hold.
- A role change that arrives out of order (stamped before role changes a node already holds on that thing) may cost in proportion to the role history after it on that thing.
- Connected nodes see each other's commits promptly, pushed, not polled.

## Data a node cannot read
- Holding and serving data it cannot read is a first-class feature of every node; one node may read some things and not others. One protocol for all nodes: peers differ only in which keys they hold.
- For such data a node learns only what storing and selective sync need: volume, which opaque sync units each blob is in and how they overlap, padded sizes, timing, addresses, and what it must act on (a blob's expiry, whether it is durable, which kinds of right may delete it, whether someone without write left it). It may learn that units it keeps share a writer, and may know the account it keeps data for. A node granted sync on a thing learns that thing's identifier and who granted it. Never keys, values, what a thing is, or its role grants.
- What a connection reveals (its address, the sync units it opens) is network metadata, hidden only by routing through a relay or an anonymity network.
- A node that cannot read data may hold its only copy, knows none of its role holders and never waits on their liveness.
- Reading never allows deleting data, forcing it to be sent again, or storing arbitrary content at a node that cannot read it. Such a node stores content only with a writer's signature, beyond a small bounded budget per thing for parties that must reach the thing's readers without write (a grant from outside, a reader leaving). The budget is best effort: it can be used up, and what needs it then waits.
- A node can limit abuse (storage, rate) of data it cannot read, knowing at most the accounts it keeps data for.

## Confidentiality between readers
- A reader learns only what it may read. Sharing one thing reveals no value of another; things written in one commit show each other's readers that they were written together.
- No identifier on the wire is predictable without a read key. Nothing derives from plaintext that could be guessed.
- Readers of a thing may learn who holds roles on it, directly or through other things, and the actors of each change to it. They learn nothing of rosters that give no role on it.
- A write hides who made it only by its author's deliberate choice, never by default.
- Deleting content leaves the fact, time, author and aspect of the edit visible to readers.
- No secret ever passes where a node without the keys meant to open it could read it.
- Secrets that must stay secret for years resist a future quantum attacker. Signatures need not.

## Deletion
- Who may purge an edit is fixed when it is written: admins always, and by the aspect's default or the writer's choice also its author, or any writer.
- What happens to replaced content is set per thing and aspect by the thing's admins and may change at any time: nothing promised (the default), kept for a time, or purged once replaced. A change applies to the history nodes still hold and brings back nothing already dropped.
- Data may carry an expiry at which every node, whether or not it can read it, drops it with nobody online. An edit keeps the expiry it was written with.
- A purge counts only if its author had the right to make it, judged as an edit's validity is. A node that cannot read the data cannot judge that: it acts on a deletion by anyone who ever held the right, and a reader holding the data restores what was wrongly dropped.
- Purging or expiring a thing's creation destroys the thing at every node: each drops it and ignores later writes to it. What it held roles on or was admin of keeps working for the other holders, and what was written through it still shows so. It comes back only if the purge turns out invalid.
- Purge is prompt: no honest node keeps purged content once it holds the deletion and what it needs to check it. No batching, and no bin: purged content is recoverable only from a node whose retention still holds it, and undo never brings back what another party purged.
- A node deletes data on its own only where nothing promises to keep it: at expiry, and history its thing's settings no longer keep. Purging is the act of a right holder, taking effect elsewhere when it arrives.
- Purge on replace: content replaced while it is set is gone at every writer holding it as soon as that writer holds the replacement, and at other nodes once they hear from such a writer. It never becomes history, whatever is set later, and does not return even if the replacing write turns out invalid.
- Expired and purged content never returns while the purge counts.
- Granularity is one edit of one aspect. Part of a value's history can be purged.
- No fingerprint: nothing retained lets anyone, even a reader, confirm a guess of purged content, however low-entropy.
- Forward secure where the platform offers erasable key storage: a node that deleted honestly and is compromised later yields nothing. Elsewhere, deleted data is unrecoverable through the platform's own storage. A node that lost access to data keeps nothing it can no longer read, unless its removal said to keep a read-only copy.
- Nothing depends on retaining full history.

## Ephemeral data
- Ephemeral state lives in memory, converges among the nodes holding it like any state, outlives contact with its author, and may be lost when no node holds it. A node that restarts gets it back from those that still do.
- A value that should live only while its author is there (a cursor, a selection) is ephemeral with an expiry its author renews by rewriting it; once the author is gone it is gone everywhere by its last write's expiry, with no departure seen by anyone.
- A signal has no current value, only entries; an entry's author can replace it, and readers see the newest version in the original's place. An ephemeral signal is held by nobody: it reaches the nodes connected at the time, once, with no delivery guarantee. Otherwise its entries are kept as long as its thing's settings say.
- Ephemeral writes need the rights the durable write would need and are verified like it. Memory spent on others' ephemeral data is bounded per thing, with a defined outcome past the bound.
- Determinism and convergence bind ephemeral data too.
- Nothing is kept "until everyone has seen it". Whether others are alive is never a protocol condition.

## Scale
- Many GB per node, multi-GB single values, maps with millions of keys, millions of things referenced from one thing, millions of things that were never shared directly. A change inside a huge value costs in proportion to the change. Large values stream; no whole value is ever needed in memory.
- Storage follows live data and the history a setting keeps, never the number of writes ever made: writing a value again and again where its history is not kept, or making and releasing things again and again, does not grow a node's storage without bound. A long-lived thing may grow modestly with the number of role changes made on it, or on what its writers act through.
- Every wire object has a fixed maximum size. Peer input never causes a panic or unbounded allocation, work, storage or diagnostics.

## Generality (goal)
The properties above hold for any use of the data, and any arrangement of things, roles and references osis allows works: none is refused for being unusual. The API and apps steer toward what costs less:
- Share a set of things through one thing that holds the role, not one by one.
- Commit per editing pause, not per keystroke.
- Presence and selections use expiring ephemeral writes, not durable add and remove.
- Nest rosters that grow into the thousands.

## Versioning
Binds released formats only; until a stable release formats change in place.
- Never discard, reject or crash on data not understood: store it, relay it, merge what can be merged, re-examine after upgrade.
- Old data stays readable forever. Nodes write what older nodes can read until a new feature is actually used.
- Everything on the wire is open and only grows: no identifier reused, nothing removed, no in-place change of meaning.
- Each aspect has one schema authority, by naming convention. Nothing on the wire names a schema, merge needs none, and the core distributes none.
- An app update never by itself changes stored data. No migrations. No global agreement on who has upgraded.
- Cryptographic primitives can be replaced without re-encrypting or re-signing old data.

## Data model
- One canonical serialization and one hash function: equal values compare equal on every node.
- Values are typed by the writer's schema. Untyped access always works on any stored data. References may dangle.
- A thing is kept while something references it strongly and released when nothing does. Release is not prompt and is not erasure: a released thing may still exist on, and come back from, a node that holds it, and changes not yet synced when it is released are lost. A cycle nothing outside it references is released whole. A node that releases everything is left with its own identity; an account is kept by its node's references like any thing.
- A thing takes with it, to whoever syncs it, its sync unit; a reference from something that cannot read its target does not keep the target. Sharing a thing more narrowly than what holds it, or changing its admins, changes none of that.
- Per-aspect merge with one conflict rule everywhere: at a position the later write wins, and a removal is final. A write never brings back what was removed, so an edit concurrent with the removal of what it is in is lost; removing from a collection drops only what the remover had seen.
- Collaborative text and lists.

## Permissions
- Roles that things hold on things, and nothing else. A role M holds on A reaches the parties holding roles on M; A never depends on who they are.
- A thing's mint admin is fixed in its identity and is an ordinary admin, removable like any other. Sharing a thing, or changing its admins, never changes its identity or how it behaves, only what it costs.
- Referencing a thing grants no rights, and removing a reference revokes none. A grant lasts until it expires or someone who may remove it does.
- Readers only read. A thing's writers may grant roles to it. From anyone else it takes messages, or grants of roles to it, only where its admins allow.
- Every write states its actors, from the key that signs it to a holder of the role it uses on what it writes, and is judged along them alone. Anyone who may read the write can verify each step.
- Rights held by different parties never combine into a right neither has alone.
- When a writer is removed, those of its edits the remover or another remaining writer vouches for having received by then are kept; the rest are discarded, since nothing shows they were made before the removal. Its changes to roles are kept only where the remover's own removal names them. Removing a node from an account works the same way.
- Admins are equals, and a fight between them has no right answer inside osis: both sides go on working, each node sides by a trust set that is an input to its judgment, reports the dispute, and lets its user switch. Sides are never merged and no winner is picked for everyone; a side changes nothing outside what the disputed thing reaches. The same holds between the nodes of an account.
- A removal nobody states (a timed grant ending, a self-removal, a link expiring) cuts off by the removed party's own timestamps until another holder states it.
- A share link is a bearer secret. One joiner is revoked only together with the link.
- A secret once shared cannot be un-shared: a party that held a key keeps everything it opens and may hand it on. Removing a holder never re-encrypts existing content. The holder stops reading new content once a party with the right to change the keys has done so knowing of the removal and a writer has written since; readers never change keys.
- Things may hold roles on each other in a cycle; the grant that would close a cycle of read access gives no read access through it.
- A holder that missed key changes for long, or was granted its role while keys were changing, may be unable to read until a current holder with the right to change keys acts for it.

## API
- Plain values and listeners. No CRDT concepts, no conflict UI, no correctness that depends on "surfacing it to the user". Diagnostics are informational.
- Atomic, not isolated: concurrent commits merge, so app invariants must hold under merge. A write is one commit or is refused.
- Nothing an app can observe depends on how osis stores or keys a thing; the docs may say where a cost differs.
- Large values are usable both materialized and streamed.
