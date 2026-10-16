# Constraints and goals
> Summary: Every hard requirement and design goal in one place (decentralization, sync cost, privacy from blind nodes, deletion, scale, generality, versioning, permissions, API), plus the goal pairs that cannot both hold and the call made on each. Check new designs against this. Collected 2026-10-11 from owner and earlier notes; reviewed and extended 2026-10-16.

Rules: mark each item hard (must hold) or goal (hold unless a listed tension says why not). When a design violates one, add it to Tensions, do not quietly weaken the item.

## Scope
- End-user apps with small-to-large interconnected data across users and devices; many apps, versions, tools and agents share the same data like a file format (notes/overview.md).
- Simple, safe Rust. Hand-written parsers, own CBOR codec, no serde on the wire.

## Decentralization (hard)
- No central or trusted coordinator, no consensus mechanism, no sequencer. Truly peer-to-peer like git; any node can be offline indefinitely and return.
- No single registry of things; total things may exceed what any node can track. Tids are self-certifying and minted offline.
- Identity and authorization are verified cryptographically by every node that can read the data (blind nodes check only label-key signatures); nothing trusts a server's word.
- No "repo": a thing belongs to no cluster that must be synced whole. Groups overlap, nest, may be cyclic, and membership changes. Syncing one row or one column of a table must each be efficient, without duplicating the table at rest or in upload. (A 2D grid is the test case, not the goal: complexly intersecting groups in general.)
- Convergence under any delivery order, duplicates and partial receipt; no ordered delivery or commit DAG required.
- Atomic multi-thing commits (owner 2026-10-16): one commit may change any set of things, across owners and reader sets, and every node that may read and syncs several of them sees all of those changes or none (notes/sync.md, Projection). Only membership-class writes get commits of their own (notes/permissions.md).
- Deterministic (review 2026-10-16): a node's state, the validity of every write, the membership timeline and alias resolution are functions of the set of blobs it holds, never of arrival order. Local policy (compaction thresholds, lazy fetch, clocks) never changes anything wire-visible.

## Sync cost (goal, numbers from owner 2026-10-11)
- Bytes up and down are close to the size of the change: about 1.2x for large changes is fine, 2x-10x is not. Small changes may carry fixed overhead, but a reasonable one (about 200 bytes per commit plus 48 per label accepted 2026-10-11).
- Round trips: a small constant for the common incremental case; log(n) is the acceptable worst case.
- No data a node already holds is sent again; a thing in many groups is stored and transferred once per node. Exception: a commit covering things with different reader sets is uploaded once per reader set as a projection, each repeating the header (tension 5).
- Compaction, deletion and membership changes cost proportional to what changed, not to group size or history.

## Encrypted (blind) nodes (hard)
- Keyless always-on nodes are first-class: every property above holds for them, and two briefly-online trusted nodes syncing only through a blind node is a primary use case.
- A blind node may learn data volume, and limited structure when selective sync needs it (which opaque labels a blob is under, label overlap, blob count, which entries are chunks, expiry times). It must not learn AKs, tids, values, authors, membership, or nesting and thing/aspect counts beyond what label structure implies.
- Labels of one owner are unlinkable at a blind node beyond overlap: label role keys and wraps derive from each group thing's own or tid-derived secrets, never from the owner's secrets directly (review 2026-10-16, notes/sync.md).
- One protocol for all nodes; trusted and blind peers differ only in which keys they hold.
- A blind node may be the only backup of rarely accessed data. Read access to a group never allows deleting its blobs at a blind node or forcing a re-upload (owner 2026-10-11). Destruction needs write rights at least, and is recoverable for a grace period unless done by an admin, or by a current writer presenting a per-entry delete token (notes/sync.md, decided 2026-10-11, amended 2026-10-12).

## Confidentiality between readers (hard, review 2026-10-16)
- A reader learns only things it may read. A blob is decryptable by exactly the readers of every thing whose deltas it carries: a commit touching things with different readers is uploaded as projections, one blob per reader set, each without the deltas that set may not read, all with the same header and commit ID (notes/sync.md, Projection). Headers name every touched (tid, AK) regardless, so a reader learns which unreadable aspects the same write touched; tids and AKs are not secret.
- Every wire ID (blob, commit, chunk, label, dot) is unpredictable without a read key; no ID derives from plaintext anyone else could guess (generalizes the no-fingerprint rule below).

## Deletion (hard)
- Three retention classes are expressible (owner 2026-10-11): purge (every node that sees the deleting commit drops the content immediately and irrevocably), preserve (history kept and synced until explicitly purged), undefined (nodes drop superseded content by local policy). Defaults per AK in the schema, overridable per change. Explicit purge of a preserved aspect's history must exist; the delta's author or an admin may issue it (decided 2026-10-11, notes/permissions.md).
- A commit may carry an expiry time; at that time every node drops its content, blind nodes without anyone online, and the time is visible to blind nodes (accepted leak, owner 2026-10-15; notes/ephemeral.md). Signals are never stored and reach only connected nodes.
- For purge: no honest node intentionally keeps the content once it has synced the deleting commit; a partial-value deletion uploads its snapshot and retires in the same sync, no batching (owner 2026-10-12). Offline copies and dishonest nodes are out of scope.
- Nothing depends on retaining full history: membership history retires at roster snapshots by the owner chain, attestations at content snapshots, only `/handover` record chains are kept forever (tension 12). Purging bodies keeps commit identity and signatures valid.
- Purge granularity is one delta, that is one (commit, aspect) pair (owner 2026-10-11). A commit touching several aspects can lose any subset of its deltas. Removing part of a value's history (one paragraph) purges every delta that carries it and replaces the aspect's history with a snapshot; a signed delta is never rewritten.
- Purge leaves no fingerprint: a retained header, link, blob ID or index entry must not let anyone confirm a guess of the purged content, even a low-entropy one (a bool, a PIN), and even someone holding the read key. So every delta body carries a random nonce that purge destroys, outward hashes are keyed, purge also drops every local reference to the content: links, chunk IDs, index entries, and collection tombstones are dots, never value hashes or keys (notes/crdt-sync.md; tension 11 resolved 2026-10-15).
- Deletion is forward-secure (owner 2026-10-11): a node that deleted honestly and is compromised later yields nothing. Design: every content key is random and crypto-shreddable, and all local plaintext lives in an encrypted store with erasable unit keys (notes/local-store.md, decided 2026-10-12, implementation deferred).

## Scale (hard)
- Data up to many GB per node, single values up to multi-GB, maps with millions of keys, millions of blobs per group. Nothing in sync, storage or reconciliation is O(total data) per operation.
- Local store units are paged so a write or a purge inside a million-key map costs O(entry), not O(map) (notes/local-store.md Open; must close in v1).
- Every wire object has a fixed maximum size in its format version (blob, header entry counts, protocol message); peer input never causes unbounded allocation.
- The core builds for wasm32 (browsers sync over WebSocket) and never needs a whole large value in memory: encode, decode, hash and chunk stream.

## Generality (goal)
- No usage rules like "don't group data this way" or "don't change this too often" are needed for the properties above to hold. Exceptions must be listed under Tensions and be rare (currently: avoid moving a thing out of its owner's tree; share sets through one share actor rather than thing by thing, tension 13).

## Versioning (hard, decided 2026-10-14, notes/versioning.md)
- Parking rule: a node never discards, rejects or panics on data it cannot interpret (unknown format version, merge encoding, field ID, AK). It stores, relays, joins what it can, and re-examines after upgrade. Not understood is treated like not yet received.
- Compatibility surface is blob contents only (commit header, delta encodings, chunk format, value CBOR); everything local may change freely. One format version: readers accept all older versions forever, writers emit the oldest version that can express the delta.
- Every wire struct, not only values (commit header, label entry metadata, protocol messages), is open: unknown fields are preserved and ignored (review 2026-10-16).
- Each AK belongs to exactly one schema with a single source of truth; only that schema extends it or allocates its IDs.
- Merge needs no schema; the wire schema only grows (integer IDs never reused, open structs, enum cases never removed); a representation change is a transition to new IDs (`succeeds`), both forms stay readable and writable, never an in-place type change; nothing in the data is irreversible. Transitions, conversions and the tie-break between forms are codegen conventions the core never interprets.
- An app update never by itself changes what is stored: which form is written is runtime policy per write, so old app versions keep working until a group actually uses the new form; nothing requires global agreement on who has upgraded. The core has no migration concept; an import is ordinary writes. The core does not distribute schemas; headers carry the writer's type hash and revision.

## Data model and serialization (hard)
- One canonical, byte-identical serialization across platforms and versions; bytes on the wire are stored as received. BLAKE3 is the only hash osis computes; suite 1 is Ed25519, XChaCha20-Poly1305, BLAKE3 and a hybrid X25519 + ML-KEM-768 sealed box (notes/crypto.md, 2026-10-16).
- Every piece of data is an aspect of a thing; values are type-checked against the writer's schema; tids may dangle.
- Merge is per-aspect delta-state CRDT; LWW reset is the only removal mechanism, addressed by aspect or by a collection element's creation dot, never by value or key (2026-10-15). A newer write never loses to an older removal. Text/list CRDT ships in v1.

## Permissions (decided)
- Actor, membership, ownership are the only concepts. Every thing has exactly one owner, fixed by tid; ownership is immutable, hand-over is lazy aliasing. Membership edges may target plain things, so sharing within the owner's tree never changes a tid; hand-over is only for moving a thing out of it (2026-10-11).
- Group membership grants no rights. A sync label receives only blobs of things its group actor may read, so a group used as a shared label is made a read member of its contents (2026-10-15, follows from the rejected "group edge extends to contents"; notes/permissions.md).
- Writes: own-node signatures plus membership chain. Reads: key wrapping; each blob has its own key, wrapped per label.
- Revocation vs offline edits: receipt-time rule, member clocks only. Author timestamps never decide validity.
- Out of scope: hostile admins and authenticated malicious writers (clock gaming, garbage uploads are rejected, not prevented).

## API and apps (decided)
- Apps see plain values and listeners. No CRDT concepts, no conflict UI, no "surface it to the user" as a correctness mechanism. The diagnostics channel is informational only; nothing may depend on it being read.
- Never panic on peer-caused input.
- A node with a wrong clock harms only its own writes: a stamp beyond the drift cap is parked until local time catches up (notes/crdt-sync.md, Dots and clock; review 2026-10-16).

## Tensions: goals that cannot all hold
Each entry: what collides, the call, status.
1. **Ownership transfer finality vs no consensus.** A former owner can always sign a competing transfer (double spend). Call: ownership immutable, lazy hand-over with aliases and forks (resolution by standing, then a per-person follow choice, as a read-time view; decided 2026-10-15); sharing within the owner's tree uses edges on things, so transfers are rare. Accepted 2026-09-29, narrowed 2026-10-11.
2. **Selective sync from a blind node vs hiding structure.** Fetching one row or column from a keyless server requires the server to distinguish them, so it learns which labels each blob is under. Only private information retrieval would avoid it. Call: allowed, that is the "limited structure" a blind node may see. Accepted 2026-10-11.
3. **Edit efficiency on large values vs hiding sizes.** Content-defined chunking makes an insert into a multi-GB blob cheap and exposes chunk size distribution; padding to hide it costs bandwidth. Call: volume may leak, so chunk by content and pad only coarsely (Padmé, at most 12%). Accepted 2026-10-11.
4. **Prompt permanent deletion vs serving history, undo and recovery.** Bodies are kept to serve peers, for the author's undo, and by blind nodes as a recycle bin. Call: retention classes; purge retires bodies immediately, one snapshot per edit for partial-value purges (a debounce was rejected 2026-10-12 as softening the guarantee), undo yields to others' resets, blind-node grace period is a per-label policy (30-day default). Decided 2026-10-11/12.
5. **Atomic multi-thing commits vs per-thing fetch and purge.** Call: one blob per commit; a node syncing only some of a commit's things over-fetches, and purging one aspect rewrites the commit's blob. Accepted 2026-10-11: atomicity matters more, such partial syncs are rare. 2026-10-16 (Confidentiality): a commit spanning reader sets is uploaded as one projection per reader set; atomicity is kept by holding a commit until every readable delta of it a node syncs has arrived.
6. **Receipt-time revocation vs blind-only topology.** A blind node's receipt never counts, so an honest member's edits parked on the server before a revoke are still dropped if no member downloaded them in time. Trusting the server's arrival order would make it a coordinator. Call: keep the rule. Accepted 2026-10-11.
7. **Lazy key rotation vs forward secrecy against dishonest blind nodes.** History is not re-encrypted on member removal; an ex-member plus a dishonest blind node can read old content. Re-encrypting is O(group) per removal. Call: lazy rotation, dishonest nodes out of scope. Accepted 2026-09-29.
8. **Immediate purge at blind nodes vs backup safety.** A blind node only checks signatures, so any key that hard-deletes there can wipe everything it covers. Call: admins hard-delete by label key; a per-entry delete token plus a signature under the label's current writer key hard-deletes one entry (token alone is an unrevocable capability); `purge`-class tokens derive from the writer role secret so any writer finishes a reset at once; other retires are soft and recoverable for the grace period; readers get neither. Resolved 2026-10-12 (notes/sync.md).
9. **Bounded clocks vs revocation precision.** Member clock skew leaves a window of at most the skew. Accepted 2026-09-29.
10. **Chunk dedup vs forward-secure deletion.** Keys derived from a shared dedup secret cannot be shredded. Call: chunk keys are random and stored in links, dedup is by reuse from the current tree, all plaintext and wraps live in a node-local encrypted store with erasable keys; the dedup secret keys hashes only. Resolved 2026-10-12 (notes/local-store.md).
11. **Removal that defeats unseen concurrent adds vs no-fingerprint purge.** A remove can only beat an add it never saw by naming the value or key, and that name is a fingerprint in every reader's state. Call: collection removals are resets addressed by observed creation dots, so tombstones are content-free and an unseen concurrent add of the same value or key survives instead of being decided by clock (notes/crdt-sync.md, worst case recorded there). Resolved 2026-10-15.
12. **Membership validity vs bounded history.** The demoter-frontier timeline is a function of every membership write of an actor, and content validity of revoked authors needs attestations, so naively neither could ever be compacted. Call (2026-10-16): a roster snapshot by the thing's owner chain starts the timeline, since its own standing depends only on the chain above, never on the thing's earlier writes; content snapshots carry elements on the compactor's authority, so attestations retire with the commits they cover. Costs accepted: finality at each snapshot (in-flight pre-snapshot grants die), a compacted node sees an empty roster when a backdated removal un-applies its epoch start until the remover re-snapshots, a person's own device roster compacts only when its recovery key signs (notes/permissions.md, Roster snapshots).
13. **Lazy rotation vs per-thing sharing.** Removing a member or device rotates every explicit secret it could open: one box per remaining member per rotated role per thing, plus a label re-registration per server. Sharing many things one by one with the same party makes a removal O(things). Call: accept; share sets through one share actor (a folder actor made a read member of each thing), which the API's sharing helpers default to. Review 2026-10-16.
