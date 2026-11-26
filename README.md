# osis
*Open Structured Information System*

osis is a decentralized data layer and set of software built on it. It aims to be a foundation for modern multi-device, multi-user apps that is private, secure, reasonably performant and user-empowering. osis takes inspiration from projects like git, AT protocol and Matrix, but aims to address limitations that prevent them from generalizing outside their target usecases.

## Motivation
In the early days of computing, data was stored in files and the user interacted with their files via the programs they chose. This philosophy did not survive into the age of phones or clouds. These days most people use a patchwork of apps and ecosystems, each with a walled-off world only the controlling company has full access to. AI can now perform arbitrary tasks on arbitrary data but your agents must still navigate a digital landscape built for the 2010s. Privacy continues to be an afterthought.

I don't believe the situation is unsalvageable. The shift away from user sovereignty was partly a power grab by monopolistic companies, but also had real technical motivations. Building a decentralized, interoperable app is hard and unprofitable. Building a data layer that makes arbitrary decentralized, interoperable apps easy has previously proven basically impossible. But AI is both motivating and enabling rapid changes to all sorts of tech up and down our software stacks. Lets do data better this time.

## Features
osis supports a highly composable feature set, carefully chosen to balance API simplicity, implementability and the needs of a wide range of applications:
- **Reference graph**: each osis thing has a permanent globally unique ID, so renaming and reorganizing never breaks references.
- **Flexible data model**: inspired by the entity component system architecture, osis allows a single thing to have arbitrary strongly-typed aspects.
- **True decentralization**: osis is fully functional both offline, and when connected to any subset of peers.
- **Real-time sync**: simultaneous changes from multiple devices merge without user intervention.
- **Pay for what you sync**: osis has no concept like a repo. Syncing a thing pulls in the things it depends on, but no larger pool.
- **Granular permissions**: any osis thing may be shared (by an admin of that thing) with anyone at any time. Admin, write and read permissions may be granted and revoked (meaning adminship may be fully transferred).
- **Semi-atomic commits**: a commit may touch many things, and all valid parts are applied at the same time.¹
- **Reasonable scaling properties**: a node may sync millions of things. A thing may contain gigabytes of data. An arbitrary number of writes and thing churn does not result in storage growth.²
- **Configurable history**: history of each thing may be efficiently stored and synced for any amount of time, including none and forever.
- **Permanent deletion**: data (including specific changes) may expire for everyone at a preset time, or be explicitly purged network-wide.³
- **Simple API**: sync, crypto, etc are almost entirely abstracted away.
- **Schema language**: allows defining richly typed and versioned formats, so multiple applications can reliably interact with the same data.
- **Garbage collection**: strong and weak references control how data is retained, cycles are detected and dropped.
- **Cryptographic verification**: as is necessary without a centralized server, only data encrypted/signed with a counterparty's keys is trusted.
- **At-rest encryption on untrusted nodes**: peers can be permitted to sync data without the keys to decrypt it.
- **Not a crypto scam**: no blockchain involved, and there will never be an osis coin.

## Limitations
- osis does not aim to be competitive with SQLite on performance, or Firebase on scale. Decentralization and flexibility have costs.
- ¹ Edge cases like permission changes and purging may invalidate some but not all of a commit, breaking strict atomicity.
- ² History obviously results in storage growth per-write, as long as the relevant thing is retained. Some operations such as purging may leave a tombstone, and thus also result in growth.
- ³ Nothing prevents a someone from preserving expired/purged data in some way. Permanent deletion applies when you trust your counterparty to respect it (or simply to not use technical means to subvert it).

## Concepts
- **Node**: an instance of the osis software that manages its own data and keys.
- **Thing**: generic container of aspects. The unit of permissions, sync and referencing. An entity in ECS terminology.
- **Tid**: Thing ID. Permanent and globally unique 120-bit ID. 20 base64 URL characters when formatted.
- **Value**: raw data. Has a type. May contain arbitrarily deep nestings (in the case of a recursive type), but may not be recursive/self-referential.
- **Type**: cleanly maps to types in Rust and other languages. May be recursive.
- **Aspect**: key/value pair attached to a thing. Component in ECS terminology.
  - **Value aspect**: an aspect which, if present, has a current value. (most data)
  - **Signal**: an aspect representing an action/event.
- **AK**: aspect key. A short string containing an aspect's name, namespace (if any), version, and a few other properties.
- **Reference**: A tid stored in an aspect, and tracked by osis.
  - **Strong reference**: syncs the target thing along with the referrer (where possible), and prevents the target being garbage collected as long as referrer is retained.
  - **Weak reference**: no effect on storage or garbage collection.
  - **Referrer**: the thing containing the reference.
  - **Target**: the thing being referred to.
- **Closure** (of a thing): itself, and all the things reachable by strong references from it.
- **Sync unit** (of a thing): its closure, except only references to things it has at least read on are considered.
- **Commit**: a signed, semi-atomic action. contains an arbitrary number of parts touching an arbitrary number of things.
- **Role**: The level of permissions one thing holds on another. Each role is a superset of the permissions of the previous role.
  - **`sync`**: allows receiving the data but not decrypting it.
  - **`read`**: allows decrypting.
  - **`write`**: allows editing/firing signals.
  - **`admin`**: allows editing permissions and other admin-only data.
  - **`may_grant`**: optional flag that applies to any role, allows granting other things up to its role.
- **Actor**: a thing which authorizes an action.
- **Signer**: the actor which holds the keys that sign a commit.
- **Actor chain**: starts with the commit's signer and ends with the thing being acted on. Each actor holds at least `write` on the next.
- **Peer**: another node a node syncs with directly.
- **Relay**: forwards a connection's encrypted data. Stores nothing, and is not a node.
- **Client**: anything using the osis client protocol to reach a node, on the same machine or another.
- **Schema**: a file defining aspects and their types. Uses a DSL and the .osis file extension.
- **Core**: the library that implements osis, the API. Excludes osis, the app, osis, the CLI and other software built on the API.

## High-level design

### Architecture
The **osis API** allows applications to store, query and listen for changes to osis data. A **node** (generally an instance of [osis core](core/)) implements the API. Nodes sync with each other in a mesh network. Each node locally stores the data it syncs. The permission system offers fine-grained control for which nodes have access to what data. The node software can be embedded in an app, a system service or running on a server.

### Things
In osis a **thing** is the unit of sync, permissions and references. Each thing has a permanent and globally unique **tid** (thing ID), commonly displayed as 20 base64 URL characters.

### Aspects
Data is stored on a thing as a collection of aspects. Each **aspect** is a key/value pair, with at most one aspect of a given key per thing. Aspect keys are compact strings containing name, version and other metadata.

### Schema & types
A **schema** specifies aspect keys, their types, versioning info, etc. Schema are written in a domain-specific language, stored in .osis files and generally compiled into apps. Aspects should generally have keys defined in included schema, and values of the type the schema defines. A single thing may contain aspects defined in multiple schemas. A node does not reject aspects from unknown schemas or with incorrect types at sync, but reading or writing them may produce an error.

### Reference graph
Aspect values may contain **references** to other things. A reference may be **strong** or **weak**. The graph of things directly and indirectly accessible via strong references is known as the root thing's **closure**. Each node has a **node root** thing, and its closure determines which things are stored and synced by the node. When the node's root closure no longer contains a thing it's garbage collected on that node.

### Permissions
A **holder** holds a **role** on a thing. Holders may be other things, keys or "the public" (anyone with access to the thing). A role grants the holder rights to interact with the thing. A thing may have any number of holders with the same or different roles. Each role is a superset of previous roles. The roles are:
- **`sync`**: allows receiving the data but not decrypting it.
- **`read`**: allows decrypting.
- **`write`**: allows editing/firing signals.
- **`admin`**: allows editing permissions and other admin-only data.

In }addition to its role, a holder may be given `may_grant`, which allows that holder to grant other holders up to the same role as itself. Roles may be used indirectly—a holder on a thing which itself has a role on another thing may act on the latter with the minimum role of the chain.

### Sync
Connected nodes sync changes to the things they have in common. Nodes with the `sync` role on a thing sync only metadata and encrypted data, without getting the keys to decrypt it. Things sync along with the subset of their closure they hold at least `read` on, so a node can receive a new thing when a strong reference is added from a thing it already syncs.

### Stubs
Where a strong reference would sync a target's closure along with the referrer, a weak reference syncs a stub. A stub contains information needed to sync a thing, without most of its data or closure. If a strong ref is written to something a node only syncs as a stub, that node (and any that sync the strong ref) begin syncing the target using the stub. If no syncing node syncs the target (in full or its stub) the ref remains dangling until one does.

### Data merging
Values use conflict-free replicated data types (CRDTs). Two simultaneous edits (or edits when two nodes are disconnected) are merged without user intervention. For some types this just means the most recent write wins (there is no meaningful way to merge two cases of an enum). Others, especially containers and strings, merge changes. Data merges recursively, strings inside map values merge just as top-level strings.
