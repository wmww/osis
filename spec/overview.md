# osis specification
> Summary: Index of the spec, notation and status conventions. The spec holds what a compatible implementation needs; rationale, rejected options and open questions live in notes/.

osis (Open Structured Information System) is a decentralized, reactive data layer: typed data on things, merged by CRDTs, synced as encrypted blobs between devices, users and untrusted hosts.

## Documents
- spec/requirements.md: hard requirements, goals, the limits the design accepts, and what is out of scope.
- spec/data-model.md: things, tids, aspects, types, values and their canonical CBOR encoding, large values, groups, core aspects.
- spec/versioning.md: format version, extension points, the parking rule, schema identity and evolution rules.
- spec/crdt.md: merge encodings: state, delta grammar, join, read, ops, slots, paging, structural diff.
- spec/commits.md: commits: header, kinds, dot forms, atomic apply, retention, purge, expiry, undo.
- spec/crypto.md: primitives, key derivations, sealed boxes, wraps, links, delete keys, agility.
- spec/permissions.md: actors, role grants, ownership, rotation, certificates, the validity rules, roster snapshots, moving a thing, purge rights, links.
- spec/wire.md: byte layouts of everything on the wire, format constants, the node-to-node protocol, bundles, decoder limits.
- spec/sync.md: blobs, labels, labeling, inbox blobs, host operations (stamps, deposits, claims), the sync protocol, convergence and compaction, subscriptions, ephemeral commits and signals, transports, bundles.

## Conventions
- MUST, MUST NOT, SHOULD are normative. Everything not marked otherwise is normative.
- **Pre-release**: until a stable release, formats change in place; the compatibility rules (spec/versioning.md, spec/requirements.md Versioning) bind released formats only, and data written by an earlier pre-release build need not load.
- **TBD**: a detail not fixed yet (none are left; byte layouts and constants are in spec/wire.md).
- Notation: `[a, b]` is a CBOR array, `{k: v}` a CBOR map. `||` is byte concatenation. `le64(i)` is i as 8 little-endian bytes. `kdf`, `derive_key`, `keyed_hash` are defined in spec/crypto.md.
- "Node": an osis instance on a device. A node **hosts** a label when it stores the label's entries and serves them to anyone holding the label's role keys (spec/sync.md §4-§5); the label's **hosts** are the addresses in its `label.0` record. A node is **blind to** a label when it holds no read secret of it; a host may be blind to some labels it hosts and read others. On a connection the dialer is the **client** and the other side the **serving side**. "Holder": an actor with a role on an actor or thing; "member" is reserved for groups (spec/data-model.md §8). "Writer" of a label: a holder of its write key.
- Format constants (`MAX_BLOB`, `CHUNK_THRESHOLD`, `PAGE_TARGET`, `MAX_DRIFT`, `ROLE_KEEP`, `INBOX_LIFETIME`, `HEARTBEAT_MIN_LIFETIME`, `HEARTBEAT_MAX_LIFETIME`, `HEARTBEAT_MIN_INTERVAL`) are fixed by the format version (spec/versioning.md §1); values in spec/wire.md §2. `TOMBSTONE_LIFETIME` and the deposit budget are host policy.
- Domain strings such as `"osis v1 commit"` are fixed byte strings; their `v1` is not a protocol version.
