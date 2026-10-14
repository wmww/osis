# Commits, CRDTs and sync primitives
> Summary: Model for commits, per-aspect delta-state CRDTs, LWW reset as the single removal mechanism, movable text CRDT and content purging. Core shape decided 2026-10-14: one rule everywhere (timestamp + author dot, later wins), no causal contexts. Sync itself in notes/sync.md.

## Decided so far
- Sync unit is a group; mechanism is blob-set reconciliation, notes/sync.md (replaced the Merkle-tree design 2026-10-09).
- Movable text/list CRDT ships in v1, as good as we can make it, with whatever fuzzing and testing that takes.
- Apps see a value they can edit and listen to. No CRDT details (resets, contexts, lost writes) reach the API. A lost concurrent write is observed like any LWW loss: the listener fires with the current value.
- Authenticated malicious writers are out of scope: a writer gaming HLC to win LWW is not a concern.
- One conflict rule everywhere (owner 2026-10-14): every state element carries a timestamp and an author dot, later timestamp wins, removal is a reset. No causal contexts anywhere: sets and maps are LWW-element, not observed-remove. No `mv` register in v1 (needs contexts).
- `set_aspect` defaults to structural diff; explicit replace variant for a reset (owner 2026-10-14).
- Every composite type merges recursively down to leaf registers: struct fields, map entries, list/text element content, enum payloads (owner 2026-10-14). Enum cases never merge with each other.
- No terminal reset / retire in the lattice (rejected 2026-10-14, notes/versioning.md): breaking schema changes are new IDs with legacy old ones; ordinary resets cover everything.
- Merge encodings form an upgrade lattice (notes/versioning.md): join converts the poorer side along a core-defined embedding, so changing an aspect's encoding is not breaking. Replaces the "changing = breaking" line below.
- Everything else below is proposal.

## Layers (each a canonical CBOR value with a hash)
- **Aspect state**: delta-state CRDT (join-semilattice, single `join` op). Stored per aspect, local only (not synced or hashed).
- **Delta**: a small state of the same lattice; applying = join. Idempotent, order-free, tolerates duplicates. No op log or ordered delivery needed.
- **Commit**: signed header + one delta per touched aspect. Header: format version, author node, actor, HLC timestamp, writer schema hash and revision, per-aspect dot ranges, list of (tid, ak, delta hash), retention class, optional purge request, delete token hash for the commit and one beside each chunk reference (notes/sync.md), signature. Commit ID = hash(header). Bodies addressed by own hash. On the wire header plus the deltas not yet purged form one encrypted blob (notes/sync.md). Atomicity is decided: a commit applies whole or not at all on every node that tracks any of its things.

## Guarantees
- Convergence under any delivery order (so "reorder/rebase" is meaningless).
- Atomic visibility: all deltas of a commit for tracked aspects joined in one storage txn, listeners after. Soft where a node receives a commit partially (partial tracking, snapshots replacing purged bodies).
- Not isolation: concurrent commits merge; app invariants must be merge-compatible. "Repair via listeners" only works if the repair is a deterministic function of state, otherwise two nodes ping-pong.
- Causality is intra-aspect only (tids may dangle, see notes/data-model.md), so no commit DAG/parents required.

## Removal: one mechanism, LWW reset
- Every deletion-like op (delete_thing, remove_aspect, replace, map key removal, compaction) is a **reset**: a write of a reset timestamp at the granularity being removed (aspect, or map entry). State carries `reset: HLC`; join takes the max and drops every element/register/dot whose write time is older. Delta = reset time plus optional new content written at or after it. Concurrent resets need no tiebreak, the later dominates.
- Consistent with the rest of the design: removal is just another LWW write. A concurrent edit newer than the reset survives if self-contained (register, field, map entry). A newer text insert whose anchor was dropped is hidden by the unknown-anchor rule and swept by the next reset. An older concurrent edit is dropped, like a losing register write.
- Permanent deletion falls out: after a reset the state is a timestamp. Every node that receives it drops its copy. Offline copies are unavoidable.
- Replaces the earlier epoch-counter idea (causal remove-wins, concurrent-bump ambiguity, would have needed a "superseded" signal to apps). Observed-remove alternative for reference: `clear` in Almeida/Shoker/Baquero "Delta State Replicated Data Types"; not used for aspects.
- Undo of a reset = paste-like reinsert of the pre-reset value with fresh IDs, taken from the local undo buffer. Others' concurrent edits inside the removed state are gone.
- Parked deltas (encoding or format this node does not know, notes/versioning.md) are never compacted away by this node; it accepts blob-level snapshots and retires from newer nodes.
- Tombstone compaction: none in v1 (owner direction 2026-10-14: worse merging after long separation is acceptable, discarding edits is not). Deleted content is dropped immediately (below); what remains per tombstone is ID + pos, run-compressed, so state grows with the number of edit runs in the aspect's history, not with live size. Yjs does the same and copes. Same for LWW set/map tombstones (value hash + timestamp per removed element). Apps that want a fresh start use an explicit replace (reset) with its known loss.
- Rejected: wall-clock staleness horizon (drop tombstones older than H, discard writes older than H). Two nodes separated for longer than H diverge or lose one side's whole month depending on the variant; any independent reset-style compaction has the same problem, because two compactions that forgot different things cannot merge.
- Possible later, lossless and additive: stability-based GC. A tombstone can be dropped once every node that may write the aspect has acknowledged it, since any later add is newer by HLC and wins without it. Needs per-node acknowledgement frontiers for the group, stalls while a member is offline (removing the member unblocks), changes nothing about merge semantics. Add only if the size benchmark demands it.

## Retention and purge (owner's direction 2026-10-11; details proposal)
Three retention classes for content, all expressible:
- `purge`: once content is reset or superseded, every node applying that commit drops the body holding it immediately and irrevocably; the node that wrote the reset also retires the body at blind nodes.
- `preserve`: bodies kept and synced until an explicit purge (today's `history` flag).
- `undefined` (default): nodes may drop superseded bodies by local policy (age, size, cache-like). Dropping is a compaction (snapshot of live content, then retire), so current state stays servable.
All three are compaction policies: now, never (except explicit purge), or whenever. Possible later: "preserve until DATE", "delete by DATE".

Where set: schema default per AK (`history` = preserve, proposed `ephemeral` = purge, neither = undefined); per-commit override in the header for that commit's deltas; and a purge request naming prior bodies or whole aspect histories, for "oops, bank details pasted into a versioned shared doc".

Mechanics:
- Purge drops bodies (values), never headers: fact, time, author and AK of every edit remain, including the purge itself. Headers keep hash(delta), so a purged commit is still verifiable.
- A multi-aspect commit purged for one aspect is rewritten as a blob without that delta: same commit ID, new blob ID, cost proportional to the commit's remaining deltas (notes/sync.md).
- Deleting a whole thing with `purge`: retire its bodies, no snapshot (state after reset is a timestamp). Deleting part of a value (a paragraph, a map entry): the resetting node uploads a snapshot of the aspect's live content and retires the old bodies in the same sync, per commit, no batching (owner 2026-10-12). So every edit to `purge`-class content costs a snapshot: O(changed chunks plus tree path) upload and a retire at every blind node. That is the price of the guarantee; use the class only where immediate deletion is worth it (notes/data-model.md).
- Undo horizon: a node keeps its own bodies locally only while nobody has reset their content; others' resets with `purge` win over undo. `purge`-class content has no undo: the deleting node's own undo buffer is just another copy and falls under the deletion constraint, so it is dropped with the commit like everything else.
- Guessable preimages: a low-entropy delta (bool, PIN) could be brute-forced from hash(delta) after purge. Fix: every delta body carries a random nonce (hash covers it; purge destroys it). Also key outward-facing hashes (deltas, states, chunks) with BLAKE3 keyed mode using the thing's dedup secret (KDF of its creation nonce, which every reader holds; notes/permissions.md); closes known-file confirmation by anyone without it. Blind nodes store but cannot verify bodies.
- Chunks and tree nodes of large values are encrypted under random keys stored in their parent links, so a purged version's chunks are crypto-shredded with its commit wraps and chunk IDs are not fingerprints (notes/local-store.md; replaces the earlier derivation from the dedup secret). Forward-secure deletion also requires every local plaintext, wrap and index entry to live in the encrypted local store, so that dropping it is a key erasure.
- Caveat (accepted by owner 2026-10-14): a node receiving a multi-aspect commit after one delta was purged applies the rest without it, so it may briefly observe an aspect combination no author produced. Final state is unaffected (the purged content was superseded anyway); same blur as snapshots.

Who may purge: the delta's author or an admin (decided 2026-10-11, notes/permissions.md, Purge rights); at blind nodes by delete token plus current writer signature (notes/sync.md). Enforcement is only against honest nodes.

## Merge per type (encoding is self-describing; schema picks the minimum; upgrades along embedding edges are not breaking, see Decided)
- scalars/tid/blob: LWW (HLC + node tiebreak). Knobs: int/float `counter` (PN), `max`, `min`. (`mv` dropped from v1: needs causal contexts.)
- string: LWW; `markdown`/`text` knob -> text CRDT below.
- struct: per-field. map: LWW-element map, recursive values, key removal = reset of the entry. set: LWW-element set: each element is a register (present/absent, timestamp, dot); concurrent add vs remove is settled by timestamp, a removed element leaves one tombstone until the aspect is reset. Rejected: OR-set/OR-map (observed-remove, add-wins; needs a causal context in every state and delta, a second conflict rule).
- enum: case is an LWW register; a case change is a reset of the enum value plus the new payload. Payload merges recursively while both sides are in the same case. A newer edit inside a case that lost is kept hidden in state and swept by the next reset (same as a text insert on an unknown anchor). No merging across cases.
- list<T>: the text CRDT below with recursive element content, so a field of one element can be edited in place. Index paths in the API are resolved to element IDs against local state at write time; deltas never carry indices. So "edit entry 3" and a concurrent "insert at 2" merge as intended: the edit follows the element to index 4. Caveat: `set_aspect` diff on a list is a heuristic; if it reads a changed entry as delete+insert rather than an edit, a concurrent edit to that entry is lost. Apps that edit list entries concurrently should use the path ops.

### Text/list CRDT (text = list<char> with run compaction)
Each element has an immutable ID (creation dot), content, and two LWW registers: `pos` (anchor element ID or HEAD) and `deleted` (bool). Insert, move, delete, undelete, cut/paste are all register writes. No causal context: existence is grow-only, deletion is a register.

Read = linearization, a deterministic function of state. Convergence is trivial (same state everywhere), so cycles and races are semantics/performance questions, not correctness ones. Spec the function fully before code:
- Tree: X's children are the elements with `pos = X`, ordered by `pos` write time newest first (RGA). DFS from HEAD. Deleted elements are skipped but stay in the tree as anchors.
- Sibling key is the `pos` *write* time, not creation time: a moved element must land directly after its target, ahead of the target's older children.
- Cycles (only among move-written `pos` registers, or an element moved under its own descendant): break at the edge with the oldest write. `pos` keeps its previous value as a second slot so that element falls back to its previous position. Cost: one extra pointer on moved elements only.
- Unknown anchor (delta arrived before its anchor's insert, or anchor swept by a reset): hidden until it arrives.
- Incremental: cache the linear order, patch per delta.

Operations:
- Move of a DFS range: write `pos` only for the range's subtree roots, never interior elements (rewriting them changes their sibling keys and reorders concurrent neighbours). Consecutive roots anchor to the visual last element of the previous root's subtree, like inserts. Re-anchor known outside descendants (typically the range's successor) to the range's predecessor. Concurrent inserts inside the range follow with their order preserved: FOOBAR + insert x after O / move FOO to end -> BARFOOx. Concurrent moves of the same root resolve by timestamp; never duplicate.
- Delete = `deleted` write, not a move (moving to a TRASH position would drag concurrently inserted descendants along). Content of a deleted element is dropped from state immediately: ID and `pos` stay as anchor, the bytes go. Undo and paste deltas carry content (the client has it in undo buffer / clipboard). If a concurrent edit resurrects an element whose content this node dropped, state hashes differ, sync joins the peer's state and refills. Deleted text is gone from every node that applied the delete.
- Cut = delete range; paste = move roots + undelete range (IDs preserved, so others' concurrent edits inside the cut text travel with it). Client remembers the cut ID range next to clipboard text; on paste emit move+undelete if it matches, else diff cut range vs pasted text -> moves + inserts. Cross-aspect paste = insert. Optional osis clipboard MIME type with (aspect, ID ranges). Protocol has no clipboard concept.
- Undo of a delete = undelete with original IDs (keeps others' anchors valid).
- Delete vs concurrent move resolve independently (flag vs `pos`): a moved-and-deleted element is a hidden anchor at the new place.

Encoding and size:
- IDs on the wire: node-table index + varint aspect-local counter (2-4 bytes typical), mostly implicit via runs. Cost scales with run count, not value size.
- State size target: 1.5x-3x plain text on real editing traces (run-length encoded runs, node-id table, delta-coded counters). Benchmark against Kleppmann's automerge-paper trace before calling it done.
- Testing: proptest against a sequential model for the single-writer case; convergence and linearization sanity under random concurrent operation sets; fuzz the wire decoder.

## Dots
- Dot = (node, aspect-local counter), not commit seq. Commit header maps each touched aspect to a counter range; a node's dots in an aspect are contiguous, gaps only from out-of-order arrival.
- Every state element (register, set element, map entry, text element, counter contribution) carries its dot (decided 2026-10-14). Revocation (notes/permissions.md) drops by dot and witnesses state frontiers per (aspect, author node) as a counter. A bool aspect is value + timestamp + dot, a couple of bytes more than timestamp alone.
- No causal contexts: nothing records what a writer had seen. Alternative (attribute through commit headers, zero bytes in state, history lookup at revocation) rejected for non-uniformity.

## Undo/redo
- Undo = new commit that cancels a specific earlier commit; header has `undoes: commit id`. Signed, replicated, atomic across the original's aspects. Never removes history; purged commits are not undoable.
- Cancel per dot, not "apply inverse": undo insert = delete that ID; undo set-add = write absent only if own add is still the winner (same rule as registers); undo counter inc = cancel that dot (idempotent if two devices undo concurrently); undo register write = write old value only if own write is still the winner; undo delete = undelete original IDs; undo reset = reinsert (above).
- Stack is derived, not stored: actor's own commits in scope, minus undone, plus undo commits for redo. Replicates for free -> cross-device undo. Scope = set of aspects or a group, app-chosen.
- Per actor by default (decided by owner 2026-10-12). Also an API to view every available change in scope regardless of author, from which an admin may remove (undo) others' changes.
- An actor's own bodies (and pre-reset snapshots) are kept locally at least for the undo horizon.

## Sync
Moved to notes/sync.md. Kept here because they touch CRDT state:
- Clock: HLC (wall ms, counter, node tiebreak, advanced on receipt, drift capped).
- API needs path-based ops (set field, insert/remove index, add/remove key, splice text, increment). `set_aspect` = structural diff (default, decided) + explicit replace (reset) variant.
- Bodies: retention class decides (purge/preserve/undefined, above). A node must always be able to serve current state: bodies or a snapshot (state sent as a delta).
- Content refill after a drop (text CRDT resurrect case) is a request for specific blobs, not a state comparison.

## Before code
- Spec the text linearization function fully (tree order, sibling key = pos write time, cycle breaking, unknown anchors), then build; benchmark state size against the automerge-paper trace (target 1.5x-3x plain text) and only then consider stability GC.

## Research
- Loro's movable list and movable tree: production implementations of Kleppmann 2020 "Moving Elements in List CRDTs" and of tree cycle handling.
- Eg-walker (Gentle & Kleppmann 2024): op-based, but its text representation and size ideas transfer.
- Kleppmann & Beresford "A Conflict-Free Replicated JSON Datatype": nested struct/map/list composition, key removal vs concurrent nested edit.
- Kleppmann & Brattli "Undo and redo support for replicated registers and sets": matches dot-cancel undo.
- Willow/Meadowcap, Keyhive/Beelay, iroh: sync and permission shape, not merge semantics.
