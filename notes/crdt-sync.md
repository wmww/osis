# Commits, CRDTs, retention and purge
> Summary: Commits and per-aspect delta-state CRDTs with one rule everywhere (timestamp plus author dot, later wins, removal is an LWW reset, no causal contexts; decided 2026-10-14), the movable text/list CRDT, dots, undo, retention classes and purge mechanics. Sync itself in notes/sync.md.

## Decided
- Sync unit is a group; mechanism is blob-set reconciliation (notes/sync.md).
- Movable text/list CRDT ships in v1, as good as we can make it, with whatever fuzzing and testing that takes.
- Apps see a value they can edit and listen to. No CRDT details (resets, contexts, lost writes) reach the API. A lost concurrent write is observed like any LWW loss: the listener fires with the current value.
- Authenticated malicious writers are out of scope: a writer gaming HLC to win LWW is not a concern.
- One conflict rule everywhere (owner 2026-10-14): every state element carries a timestamp and an author dot, later timestamp wins, removal is a reset. No causal contexts: sets and maps are LWW-element, not observed-remove. No `mv` register in v1 (needs contexts).
- `set_aspect` defaults to structural diff; explicit replace variant for a reset (owner 2026-10-14).
- Every composite type merges recursively down to leaf registers: struct fields, map entries, list/text element content, enum payloads (owner 2026-10-14). Enum cases never merge with each other.
- Merge encodings form an upgrade lattice (notes/versioning.md): join converts the poorer side along a core-defined embedding, so changing an aspect's encoding is not breaking. No terminal reset / retire marker (rejected 2026-10-14): representation changes are transitions to new IDs.
- Retention classes, purge granularity and rights, expiry: below and notes/constraints.md.
- Everything else is proposal.

## Layers (each a canonical CBOR value)
- **Aspect state**: delta-state CRDT (join-semilattice, single `join` op). Stored per aspect, local only: never synced, never hashed.
- **Delta**: a small state of the same lattice; applying = join. Idempotent, order-free, tolerates duplicates. No op log or ordered delivery.
- **Commit**: signed header plus one delta per touched aspect. Header: format version, author node, actor, HLC timestamp, writer type hash and schema revision, per-aspect dot ranges, list of (tid, ak, delta hash, encoding), retention class override, optional expiry time, optional purge request, delete token hash for the commit and one per chunk blob the deltas introduce (notes/sync.md), signature. Commit ID = hash(header). Header plus unpurged deltas form one encrypted blob. A commit applies whole or not at all on every node that tracks any of its things.

## Guarantees
- Convergence under any delivery order.
- Atomic visibility: all deltas of a commit for tracked aspects joined in one storage txn, listeners after. Soft where a node receives a commit partially (partial tracking, snapshots replacing purged bodies).
- Not isolation: concurrent commits merge; app invariants must be merge-compatible. "Repair via listeners" only works if the repair is a deterministic function of state, otherwise two nodes ping-pong.
- Causality is intra-aspect only (tids may dangle), so no commit DAG.

## Removal: LWW reset
- Every deletion-like op (delete_thing, remove_aspect, replace, map key removal, compaction) is a **reset**: a write of a reset timestamp at the granularity being removed (aspect, or map entry). State carries `reset: HLC`; join takes the max and drops every element/register/dot whose write time is older. Delta = reset time plus optional new content written at or after it. Concurrent resets need no tiebreak, the later dominates.
- A concurrent edit newer than the reset survives if self-contained (register, field, map entry). A newer text insert whose anchor was dropped is hidden by the unknown-anchor rule and swept by the next reset. An older concurrent edit is dropped, like a losing register write.
- Permanent deletion falls out: after a reset the state is a timestamp. Offline copies are unavoidable.
- Undo of a reset = paste-like reinsert of the pre-reset value with fresh IDs, from the local undo buffer. Others' concurrent edits inside the removed state are gone.
- Parked deltas (encoding or format this node does not know, notes/versioning.md) are never compacted away by this node; it accepts blob-level snapshots and retires from newer nodes.
- Tombstone compaction: none in v1 (owner 2026-10-14: worse merging after long separation is acceptable, discarding edits is not). Deleted content is dropped immediately; what remains per text tombstone is ID + pos, run-compressed, so state grows with the number of edit runs, not live size. Yjs does the same and copes. LWW set/map tombstones keep (element hash or key, timestamp) until the aspect is reset; that identity is a fingerprint under `purge` (constraints tension 11, issues/tombstone-identity.md). Apps wanting a fresh start use an explicit replace (reset).
- Rejected: wall-clock staleness horizon (drop tombstones older than H). Two nodes separated longer than H diverge or lose a side's edits; any independent reset-style compaction has the same problem.
- Possible later, lossless: stability-based GC. A tombstone can go once every node that may write the aspect has acknowledged it, since any later add is newer by HLC. Needs per-node acknowledgement frontiers, stalls while a member is offline (removal unblocks). Add only if the size benchmark or tension 11 demands it.

## Retention, expiry, purge (owner's direction 2026-10-11, mechanics proposal)
Three retention classes for content:
- `purge`: once content is reset or superseded, every node applying that commit drops the body immediately and irrevocably; the resetting node also retires the body at blind nodes.
- `preserve`: bodies kept and synced until an explicit purge.
- `undefined` (default): nodes may drop superseded bodies by local policy. Dropping is a compaction (snapshot of live content, then retire), so current state stays servable.
Set as schema default per AK (notes/data-model.md), overridable per commit for that commit's deltas. Orthogonal: a commit may carry `expires at T` (2026-10-15, notes/ephemeral.md): at T its deltas count as purged and their live content as reset at T on every node; blind nodes drop the entry unattended. A purge request names prior bodies or whole aspect histories ("bank details pasted into a versioned shared doc").

Mechanics:
- Purge drops bodies, never headers: fact, time, author and AK of every edit remain, including the purge itself. Headers keep hash(delta), so a purged commit stays verifiable.
- A multi-aspect commit purged for one aspect is rewritten as a blob without that delta: same commit ID, new blob ID, cost proportional to the remaining deltas. Compaction of a commit with mixed-class deltas works the same way.
- Deleting a whole thing with `purge`: retire its bodies, no snapshot. Deleting part of a value (a paragraph, a map entry): the resetting node uploads a snapshot of the aspect's live content and retires the old bodies in the same sync, per commit, no batching (owner 2026-10-12). Every edit to `purge`-class content costs O(changed chunks plus tree path) upload and a retire at every blind node.
- Undo: a node keeps its own bodies locally only while nobody has reset their content; others' `purge` resets win over undo. `purge`-class content has no undo at all: the undo buffer is just another copy.
- No fingerprints: every delta body carries a random nonce (hashed, destroyed by purge), and outward hashes (deltas, links) are keyed with the thing's dedup secret (notes/data-model.md). Blind nodes store but cannot verify bodies.
- Chunks and tree nodes of large values are encrypted under random keys stored in their parent links, so a purged version's chunks are crypto-shredded with its commit wraps (notes/local-store.md). Every local plaintext, wrap and index entry lives in the encrypted local store so dropping it is a key erasure.
- Caveat (accepted 2026-10-14): a node receiving a multi-aspect commit after one delta was purged applies the rest, so it may briefly observe an aspect combination no author produced. Final state is unaffected.

Who may purge: the delta's author or an admin (notes/permissions.md); at blind nodes by delete token plus current writer signature (notes/sync.md). Enforcement is only against honest nodes.

## Merge per type (encoding is self-describing; schema picks the minimum)
- scalars/tid/blob: LWW (HLC + node tiebreak). Knobs: int/float `counter` (PN), `max`, `min`.
- string: LWW; `markdown`/`text` knob -> text CRDT below.
- struct: per-field. map: LWW-element map, recursive values, key removal = reset of the entry. set: LWW-element set: each element is a register (present/absent, timestamp, dot); concurrent add vs remove settled by timestamp, a removed element leaves one tombstone until the aspect is reset. Rejected: OR-set/OR-map (needs a causal context in every state and delta, a second conflict rule).
- enum: case is an LWW register; a case change is a reset of the enum value plus the new payload. Payload merges recursively while both sides are in the same case. A newer edit inside a case that lost stays hidden and is swept by the next reset.
- list<T>: the text CRDT with recursive element content, so a field of one element can be edited in place. Index paths in the API are resolved to element IDs against local state at write time; deltas never carry indices. Caveat: `set_aspect` diff on a list is a heuristic; if it reads a changed entry as delete+insert, a concurrent edit to that entry is lost. Apps that edit list entries concurrently should use the path ops.

### Text/list CRDT (text = list<char> with run compaction)
Each element has an immutable ID (creation dot), content, and two LWW registers: `pos` (anchor element ID or HEAD) and `deleted` (bool). Insert, move, delete, undelete, cut/paste are all register writes. No causal context: existence is grow-only, deletion is a register.

Read = linearization, a deterministic function of state, so cycles and races are semantics/performance questions, not correctness ones. Spec fully before code:
- Tree: X's children are the elements with `pos = X`, ordered by `pos` write time newest first (RGA). DFS from HEAD. Deleted elements are skipped but stay as anchors.
- Sibling key is the `pos` *write* time, not creation time: a moved element must land directly after its target, ahead of the target's older children.
- Cycles (only among move-written `pos` registers): break at the edge with the oldest write. `pos` keeps its previous value as a second slot so that element falls back to its previous position. One extra pointer on moved elements only.
- Unknown anchor (delta arrived before its anchor's insert, or anchor swept by a reset): hidden until it arrives.
- Incremental: cache the linear order, patch per delta.

Operations:
- Move of a DFS range: write `pos` only for the range's subtree roots, never interior elements (rewriting them changes their sibling keys and reorders concurrent neighbours). Consecutive roots anchor to the visual last element of the previous root's subtree. Re-anchor known outside descendants (typically the range's successor) to the range's predecessor. Concurrent inserts inside the range follow with order preserved: FOOBAR + insert x after O / move FOO to end -> BARFOOx. Concurrent moves of the same root resolve by timestamp; never duplicate.
- Delete = `deleted` write, not a move (moving to a TRASH position would drag concurrently inserted descendants along). Content of a deleted element is dropped from state immediately: ID and `pos` stay as anchor. Undo and paste deltas carry content (undo buffer / clipboard). If a concurrent edit resurrects an element whose content this node dropped, the node requests the specific blobs that carried it (notes/sync.md), not a state comparison.
- Cut = delete range; paste = move roots + undelete range (IDs preserved, so others' concurrent edits inside the cut text travel with it). Client remembers the cut ID range next to clipboard text; on paste emit move+undelete if it matches, else diff -> moves + inserts. Cross-aspect paste = insert. Optional osis clipboard MIME type with (aspect, ID ranges); the protocol has no clipboard concept.
- Undo of a delete = undelete with original IDs (keeps others' anchors valid).
- Delete vs concurrent move resolve independently (flag vs `pos`): a moved-and-deleted element is a hidden anchor at the new place.

Encoding and size:
- IDs on the wire: node-table index + varint aspect-local counter (2-4 bytes typical), mostly implicit via runs. Cost scales with run count, not value size.
- State size target: 1.5x-3x plain text on real editing traces. Benchmark against Kleppmann's automerge-paper trace before calling it done; only then consider stability GC.
- Testing: proptest against a sequential model for the single-writer case; convergence and linearization sanity under random concurrent operation sets; fuzz the wire decoder.

## Dots and clock
- Dot = (node, aspect-local counter), not commit seq. Commit header maps each touched aspect to a counter range; a node's dots in an aspect are contiguous, gaps only from out-of-order arrival.
- Every state element (register, set element, map entry, text element, counter contribution) carries its dot (decided 2026-10-14). Revocation (notes/permissions.md) drops by dot and witnesses frontiers per (aspect, author node). A bool aspect is value + timestamp + dot.
- No causal contexts: nothing records what a writer had seen. Rejected: attributing through commit headers (zero bytes in state, history lookup at revocation) for non-uniformity.
- Clock: HLC (wall ms, counter, node tiebreak, advanced on receipt, drift capped).

## Undo/redo
- Undo = new commit that cancels a specific earlier commit; header has `undoes: commit id`. Signed, replicated, atomic across the original's aspects. Never removes history; purged commits are not undoable.
- Cancel per dot, not "apply inverse": undo insert = delete that ID; undo set-add = write absent only if own add is still the winner; undo counter inc = cancel that dot (idempotent across devices); undo register write = write old value only if own write is still the winner; undo delete = undelete original IDs; undo reset = reinsert (above).
- Stack is derived, not stored: actor's own commits in scope, minus undone, plus undo commits for redo. Replicates for free -> cross-device undo. Scope = set of aspects or a group, app-chosen.
- Per actor by default (owner 2026-10-12). Also an API to view every available change in scope regardless of author, from which an admin may remove (undo) others' changes.
- An actor's own bodies (and pre-reset snapshots) are kept locally at least for the undo horizon.

## Research
- Loro's movable list and movable tree: production implementations of Kleppmann 2020 "Moving Elements in List CRDTs" and of tree cycle handling.
- Eg-walker (Gentle & Kleppmann 2024): op-based, but its text representation and size ideas transfer.
- Kleppmann & Beresford "A Conflict-Free Replicated JSON Datatype": nested composition, key removal vs concurrent nested edit.
- Kleppmann & Brattli "Undo and redo support for replicated registers and sets": matches dot-cancel undo.
- Almeida/Shoker/Baquero "Delta State Replicated Data Types": delta-state framework; its observed-remove `clear` is not used here.
