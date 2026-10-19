# osis specification
> Summary: Index of the spec, notation and status conventions. The spec holds what a compatible implementation needs; rationale, rejected options and open questions live in notes/.

osis (Open Structured Information System) is a decentralized, reactive data layer: typed data on things, merged by CRDTs, synced as encrypted blobs between devices, users and untrusted servers.

## Documents
- spec/requirements.md: hard requirements, goals, the limits the design accepts, and what is out of scope.
- spec/data-model.md: things, tids, aspects, types, values and their canonical CBOR encoding, large values, groups, core aspects.
- spec/versioning.md: format version, extension points, the parking rule, schema identity and evolution rules.
- spec/crdt.md: merge encodings: state, delta grammar, join, read, ops, slots, paging, structural diff.
- spec/commits.md: commits: header, kinds, dot forms, atomic apply, retention, purge, expiry, undo.
- spec/crypto.md: primitives, key derivations, sealed boxes, wraps, links, delete tokens, agility.
- spec/permissions.md: actors, membership, ownership, rotation, certificates, the validity rules, roster snapshots, moving a thing, purge rights, links.
- spec/wire.md: byte layouts of everything on the wire, format constants, the node-to-node protocol, bundles, decoder limits.
- spec/sync.md: blobs, labels, labeling, inbox blobs, blind-node operations (stamps, deposits, claims), the sync protocol, convergence and compaction, subscriptions, signals, transports, bundles.

## Conventions
- MUST, MUST NOT, SHOULD are normative. Everything not marked otherwise is normative.
- **TBD**: a detail not fixed yet (byte layouts, constants). plans/protocol-spec.md tracks them.
- Notation: `[a, b]` is a CBOR array, `{k: v}` a CBOR map. `||` is byte concatenation. `le64(i)` is i as 8 little-endian bytes. `kdf`, `derive_key`, `keyed_hash` are defined in spec/crypto.md.
- "Node": an osis instance on a device. "Blind node": a node holding no read secret of a label it stores; "server" is a blind node used as one. "Member": an actor with a role on an actor or thing. "Writer" of a label: a holder of its write key.
- Format constants (`MAX_BLOB`, `CHUNK_THRESHOLD`, `PAGE_TARGET`, `MAX_DRIFT`, `MEMBERSHIP_KEEP`, `INBOX_LIFETIME`, `HEARTBEAT_MIN_LIFETIME`, `HEARTBEAT_MAX_LIFETIME`, `HEARTBEAT_MIN_INTERVAL`) are fixed by the format version (spec/versioning.md §1); values in spec/wire.md §2. `TOMBSTONE_LIFETIME` and the deposit budget are blind-node policy.
- Domain strings such as `"osis v1 commit"` are fixed byte strings; their `v1` is not a protocol version.
