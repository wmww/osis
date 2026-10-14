# Constraints and goals
> Summary: Every hard requirement and design goal in one place (decentralization, sync cost, privacy from blind nodes, deletion, scale, generality, permissions, API), plus the list of goal pairs that cannot both hold and the call made on each. Check new designs against this. Collected 2026-10-11 from owner and earlier notes.

Rules: mark each item hard (must hold) or goal (hold unless a listed tension says why not). When a design violates one, add it to Tensions, do not quietly weaken the item.

## Scope
- End-user apps with small-to-large interconnected data across users and devices; many apps, versions, tools and agents share the same data like a file format (notes/overview.md).
- Simple, safe Rust. Hand-written parsers, own CBOR codec, no serde on the wire.

## Decentralization (hard)
- No central or trusted coordinator, no consensus mechanism, no sequencer. Truly peer-to-peer like git; any node can be offline indefinitely and return.
- No single registry of things; total things may exceed what any node can track. Tids are self-certifying and minted offline.
- Identity and authorization are verified cryptographically by every node; nothing trusts a server's word.
- No "repo": a thing belongs to no cluster that must be synced whole. Groups overlap, nest, may be cyclic, and membership changes. Syncing one row or one column of a table must each be efficient, without duplicating the table at rest or in upload. (A 2D grid is the test case, not the goal: complexly intersecting groups in general.)
- Convergence under any delivery order, duplicates and partial receipt; no ordered delivery or commit DAG required.

## Sync cost (goal, numbers from owner 2026-10-11)
- Bytes up and down are close to the size of the change: about 1.2x for large changes is fine, 2x-10x is not. Small changes may carry fixed overhead, but a reasonable one (about 200 bytes per commit plus 48 per label accepted 2026-10-11).
- Round trips: a small constant for the common incremental case; log(n) is the acceptable worst case.
- No data a node already holds is sent again; a thing in many groups is stored and transferred once per node.
- Compaction, deletion and membership changes cost proportional to what changed, not to group size or history.

## Encrypted (blind) nodes (hard)
- Keyless always-on nodes are first-class: every property above holds for them, and two briefly-online trusted nodes syncing only through a blind node is a primary use case.
- A blind node may learn data volume, and limited structure when selective sync needs it (which opaque labels a blob is under, label overlap, blob count). It must not learn AKs, tids, values, authors, membership, nesting, or thing/aspect counts beyond what label structure implies.
- One protocol for all nodes; trusted and blind peers differ only in which keys they hold.
- A blind node may be the only backup of rarely accessed data. Read access to a group never allows deleting its blobs at a blind node or forcing a re-upload (owner 2026-10-11). Destruction needs write rights at least, and is recoverable for a grace period unless done by an admin, or by a current writer presenting a per-entry delete token (held by the author, or by all writers for `purge`-class content) (notes/sync.md, decided 2026-10-11, amended 2026-10-12).

## Deletion (hard)
- Three retention classes are expressible (owner 2026-10-11): purge (every node that sees the deleting commit drops the content immediately and irrevocably), preserve (history kept and synced until explicitly purged), undefined (nodes drop superseded content by local policy). Defaults per AK in the schema, overridable per change. Explicit purge of a preserved aspect's history must exist; the delta's author or an admin may issue it (decided 2026-10-11, notes/permissions.md).
- For purge: no honest node intentionally keeps the content once it has synced the deleting commit; a partial-value deletion uploads its snapshot and retires in the same sync, no batching (owner 2026-10-12). Offline copies and dishonest nodes are out of scope.
- Nothing depends on retaining full history. Purging bodies keeps commit identity and signatures valid.
- Purge granularity is one delta, that is one (commit, aspect) pair (owner 2026-10-11). A commit touching several aspects can lose any subset of its deltas. Removing part of a value's history (one paragraph) purges every delta that carries it and replaces the aspect's history with a snapshot; a signed delta is never rewritten.
- Purge leaves no fingerprint: a retained header, link, blob ID or index entry must not let anyone confirm a guess of the purged content, even a low-entropy one (a bool, a PIN), and even someone holding the read key. So every delta body carries a random nonce that purge destroys, outward hashes are keyed, and purge also drops every local reference to the content: links, chunk IDs, tombstones past their horizon, index entries (notes/crdt-sync.md).
- Deletion is forward-secure (owner 2026-10-11): a node that deleted honestly and is compromised later yields nothing. Knowing a value once never implies being able to recover it after deleting it. Design: every content key is random and crypto-shreddable, and all local plaintext lives in an encrypted store with erasable unit keys (notes/local-store.md, decided 2026-10-12, implementation deferred).

## Scale (hard)
- Data up to many GB per node, single values up to multi-GB, maps with millions of keys, millions of blobs per group. Nothing in sync, storage or reconciliation is O(total data) per operation.

## Generality (goal)
- No usage rules like "don't group data this way" or "don't change this too often" are needed for the properties above to hold. Exceptions must be listed under Tensions and be rare (currently: avoid moving a thing out of its owner's tree).

## Versioning (hard, decided 2026-10-14, notes/versioning.md)
- Parking rule: a node never discards, rejects or panics on data it cannot interpret (unknown format version, merge encoding, field ID, AK). It stores, relays, joins what it can, and re-examines after upgrade. Not understood is treated like not yet received.
- Compatibility surface is blob contents only (commit header, delta encodings, chunk format, value CBOR); everything local may change freely. One format version: readers accept all older versions forever, writers emit the oldest version that can express the delta.
- Each AK belongs to exactly one schema with a single source of truth; only that schema extends it or allocates its IDs.
- Merge needs no schema; the wire schema only grows (integer IDs never reused, open structs); breaking changes are a new ID/AK plus a retire, never an in-place type change.
- Old app versions keep working on current data until the schema author retires what they depend on; nothing requires global agreement on who has upgraded.

## Data model and serialization (hard)
- One canonical, byte-identical serialization across platforms and versions; bytes on the wire are stored as received. BLAKE3 is the only hash.
- Every piece of data is an aspect of a thing; values are type-checked against the writer's schema; tids may dangle.
- Merge is per-aspect delta-state CRDT; LWW reset is the only removal mechanism. Text/list CRDT ships in v1.

## Permissions (decided)
- Actor, membership, ownership are the only concepts. Every thing has exactly one owner, fixed by tid; ownership is immutable, hand-over is lazy aliasing. Membership edges may target plain things, so sharing within the owner's tree never changes a tid; hand-over is only for moving a thing out of it (2026-10-11).
- Writes: own-node signatures plus membership chain. Reads: key wrapping; each blob has its own key, wrapped per label.
- Revocation vs offline edits: receipt-time rule, member clocks only. Author timestamps never decide validity.
- Out of scope: hostile admins and authenticated malicious writers (clock gaming, garbage uploads are rejected, not prevented).

## API and apps (decided)
- Apps see plain values and listeners. No CRDT concepts, no conflict UI, no "surface it to the user" as a correctness mechanism. The diagnostics channel is informational only; nothing may depend on it being read.
- Never panic on peer-caused input.

## Tensions: goals that cannot all hold
Each entry: what collides, the call, status.
1. **Ownership transfer finality vs no consensus.** A former owner can always sign a competing transfer (double spend). Call: ownership immutable, lazy hand-over with aliases and forks; sharing within the owner's tree uses edges on things, so transfers are rare. Accepted 2026-09-29, narrowed 2026-10-11.
2. **Selective sync from a blind node vs hiding structure.** Fetching one row or column from a keyless server requires the server to distinguish them, so it learns which labels each blob is under. Only private information retrieval would avoid it. Call: allowed, that is the "limited structure" a blind node may see. Accepted 2026-10-11 (covered by owner's criterion).
3. **Edit efficiency on large values vs hiding sizes.** Content-defined chunking is what makes an insert into a multi-GB blob cheap, and it exposes chunk size distribution; padding to hide it costs bandwidth. Call: volume may leak (owner criterion), so chunk by content and pad only coarsely (Padmé, at most 12%). Accepted 2026-10-11.
4. **Prompt permanent deletion vs serving history, undo and recovery.** Bodies are kept to serve peers, for the author's undo, and by blind nodes as a recycle bin. Call: retention classes (above); purge retires bodies immediately, one snapshot per edit for partial-value purges (a debounce was rejected 2026-10-12 as softening the guarantee; the cost is the point of the class), undo yields to others' resets, blind-node grace period is a per-group policy carried in the retire. Decided 2026-10-11; purge rights (notes/permissions.md) and the 30-day grace default (notes/sync.md) decided 2026-10-11 and 2026-10-12.
5. **Atomic multi-thing commits vs per-thing fetch and purge.** Call: one blob per commit; a node syncing only some of a commit's things over-fetches, and purging one aspect rewrites the commit's blob. Accepted 2026-10-11: atomicity matters more, and such partial syncs are rare.
6. **Receipt-time revocation vs blind-only topology.** A blind node's receipt never counts, so an honest member's edits parked on the server before a revoke are still dropped if no member downloaded them in time. Trusting the server's arrival order would fix it and makes the server a coordinator. Call: keep the rule, trust the server for nothing it need not be trusted for. Accepted 2026-10-11.
7. **Lazy key rotation vs forward secrecy against dishonest blind nodes.** History is not re-encrypted on member removal; an ex-member plus a dishonest blind node can read old content. Re-encrypting is O(group) per removal. Call: lazy rotation, dishonest nodes out of scope. Accepted 2026-09-29.
8. **Immediate purge at blind nodes vs backup safety.** A blind node can only check signatures, so any key allowed to hard-delete there can wipe everything it covers; but the purge class wants the resetting node to delete at blind nodes at once. Call: admins hard-delete by label key; the author of a body hard-deletes it by a per-entry delete token, which leaks no authorship; any other writer's retire is soft and recoverable for the grace period; readers get neither. Label keys derive from the group thing's role secrets, so a writer on that group thing can soft-retire the whole label; rights on some other thing inside the group give nothing at the label. Decided 2026-10-11 (notes/sync.md). Amended 2026-10-12: the token alone is an unrevocable capability and a blind node may be the only copy of current state, so a hard delete needs the token plus a signature under the label's current writer key; `purge`-class tokens derive from the writer role secret so any writer finishes an ephemeral reset at once, with no role flag for the server to see. Resolved.
9. **Bounded clocks vs revocation precision.** Member clock skew leaves a window of at most the skew. Accepted 2026-09-29.
10. **Chunk dedup vs forward-secure deletion.** Chunk keys and IDs derive from the thing's dedup secret, which derives from the creation nonce every reader keeps forever, so crypto-shredding cannot cover chunks: a compromised node re-derives any guessed chunk's key and ID. Only byte erasure helps there, and commit-key wraps live in the same database, so both reduce to a small node-local key store that can truly forget. Call: chunk keys are random and stored in links, dedup is by reuse from the current tree, and a node-local encrypted store with a key tree rooted in platform erasable storage holds every plaintext and wrap; the dedup secret keys hashes only. Resolved 2026-10-12 (notes/local-store.md).
