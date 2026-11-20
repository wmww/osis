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
- **Decentralization**: osis is fully functional both offline, and when connected to a limited set of peers.
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
- **Thing**: generic container of aspects, an entity in ECS terminology.
- **Tid**: Thing ID, permanent and globally unique 120-bit ID, formatted as 20 base64 URL characters.
- **Aspect**: key/value pair attached to a thing. Value should be of the correct type for the key (as defined by a schema). Each thing may have at most one aspect per key. Component in ECS terminology.
  - **Value aspect**: an aspect which, if present, has a current value. (most data)
  - **Signal**: an aspect representing an action/event.
- **AK**: aspect key. A short string containing an aspect's name, namespace (if any), version, and a few other properties.
- **Reference**: A tid stored in an aspect, and tracked by osis.
  - **Strong reference**: syncs the target thing with the referrer (where possible), and prevents the target being garbage collected.
  - **Weak reference**: no effect on storage or garbage collection.
- **Closure** (of a thing): itself, and all the things reachable by strong references from it.
- **Commit**: a signed, semi-atomic action. contains an arbitrary number of parts touching an arbitrary number of things.
- **Role**: The level of permissions one thing holds on another. Each role is a superset of the permissions of the previous role.
  - **`sync`**: allows receiving the data but not decrypting it.
  - **`read`**: allows decrypting.
  - **`write`**: allows editing/firing signals.
  - **`admin`**: allows editing permissions and other admin-only data.
- **Node**: an osis instance with its own key and store.
- **Actor**: a thing which authorizes an action.
- **Signer**: the actor which holds the keys that sign a commit.
- **Actor chain**: Starts with the commit's signer and ends with the thing being acted on. Each actor holds at least `write` on the next.
- **Peer**: another node a node syncs with directly.
- **Relay**: forwards a connection's encrypted data. Stores nothing, and is not a node.
- **Client**: anything using the osis client protocol to reach a node, on the same machine or another.
- **Schema**: a file defining aspects and their types. Uses a DSL and the .osis file extension.
