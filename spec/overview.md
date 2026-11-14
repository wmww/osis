# osis specification
> Summary: Index of the spec and its notation. The spec holds what a compatible implementation needs; rationale, rejected options and open questions live in notes/.

osis (Open Structured Information System) is a decentralized, reactive data layer: typed data on things, merged by CRDTs, synced as encrypted blobs between nodes, including nodes that cannot read them.

## Documents
- spec/requirements.md: hard requirements, goals, accepted limits, threat model.
- spec/data-model.md: things, tids, aspects, types, values and their canonical CBOR encoding, large values, groups, core aspects.
- spec/versioning.md: format version, extension points, the parking rule, schemas as local knowledge, evolution rules.
- spec/crdt.md: merge encodings: state, delta grammar, join, read, ops, slots, paging, structural diff.
- spec/commits.md: commits: header, kinds, dot forms, verification and apply, retention, purge, expiry, undo.
- spec/crypto.md: primitives, key derivations, sealed boxes, wraps, links, delete keys, agility.
- spec/permissions.md: actors, role grants, first admins, rotation, certificates, the validity rules, purge rights, links.
- spec/wire.md: byte layouts of everything on the wire, constants, the node-to-node protocol, bundles, decoder limits.
- spec/sync.md: overview of sync: its words, the one kind of node, the two holdings of a sync ID (read, kept unread), each area's principle and the sync file map.
- spec/sync-set.md: the synced group, the sync set, leaving, invitations and accepting, group sources.
- spec/sync-ids.md: blobs, sync IDs and role keys, steps and claim sets, `sync.0`, the store per sync ID and the operations on it.
- spec/sync-opens.md: connections, connection proofs, records and agreement, the shared set, filters, Offer, ending opens.
- spec/sync-judgement.md: what goes under a sync ID, the required set and judgement, acting on it, logged again once, destruction and emptying, kept unread.
- spec/sync-compaction.md: compaction and deletion, ephemeral and relay-only commits.
- spec/sync-inbox.md: inboxes, inbox blobs, deposits, promotion and clearing, grant copies and contact cards, links.
- spec/sync-streams.md: framing, clock and flow control, pushes, the node log and cursor, the stream, first sync, bundles.
- spec/sync-status.md: sources and caught up, held elsewhere, status and waits.
- spec/sync-hostile.md: bounds on hostile peers and the stated limits.
- spec/sync-transport.md: byte streams and addresses, QUIC, `peer://` and relays, LAN discovery, listeners, local and client sessions.

## Conventions
- MUST, MUST NOT, SHOULD are normative. Everything not marked otherwise is normative.
- **Pre-release**: until a stable release, formats change in place; the compatibility rules (spec/versioning.md, spec/requirements.md Versioning) bind released formats only, and data written by an earlier pre-release build need not load.
- Notation: `[a, b]` is a CBOR array, `{k: v}` a CBOR map, `Opt(X) := [] | [X]`. `||` is byte concatenation. `le64(i)` is i as 8 little-endian bytes. `kdf`, `derive_key`, `keyed_hash` are defined in spec/crypto.md.
- "Node": a running osis instance. A node holds each sync ID it syncs either **read** (it holds the read secret) or **kept unread** (it holds only the sync secret), and serves it from its own store either way (spec/sync.md §3). "Holder": an actor with a role on an actor or thing; "member" is reserved for groups (spec/data-model.md §8). "Writer" of a sync ID: a holder of its write key.
- Constants: names in capitals are defined in spec/wire.md §2, with which ones the format version fixes.
- Domain strings such as `"osis v1 commit"` are fixed byte strings; their `v1` is not a protocol version.
