# Commits, CRDTs and sync primitives
> Summary: Proposed model for commits, per-aspect delta-state CRDTs, LWW reset as the single removal mechanism, movable text CRDT and content purging; discussed with owner 2026-09-25, mostly proposal. Sync itself moved to notes/sync.md (2026-10-09).

## Decided so far
- Sync unit is a group; mechanism is blob-set reconciliation, notes/sync.md (replaced the Merkle-tree design 2026-10-09).
- Movable text/list CRDT ships in v1, as good as we can make it, with whatever fuzzing and testing that takes.
- Apps see a value they can edit and listen to. No CRDT details (resets, contexts, lost writes) reach the API. A lost concurrent write is observed like any LWW loss: the listener fires with the current value.
- Authenticated malicious writers are out of scope: a writer gaming HLC to win LWW is not a concern.
- Everything else below is proposal.

## Layers (each a canonical CBOR value with a hash)
- **Aspect state**: delta-state CRDT (join-semilattice, single `join` op). Stored per aspect, local only (not synced or hashed).
- **Delta**: a small state of the same lattice; applying = join. Idempotent, order-free, tolerates duplicates. No op log or ordered delivery needed.
- **Commit**: signed header + one delta per touched aspect. Header: author node, actor, HLC timestamp, per-aspect dot ranges, list of (tid, ak, delta hash), retention class, optional purge request, delete token hash for the commit and one beside each chunk reference (notes/sync.md), signature. Commit ID = hash(header). Bodies addressed by own hash. On the wire header plus the deltas not yet purged form one encrypted blob (notes/sync.md). Atomicity is decided: a commit applies whole or not at all on every node that tracks any of its things.

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
- Compaction of a text bloated with tombstone IDs = reset + reinsert live content with fresh IDs; loses concurrent pre-reset edits, so rare or never. Yjs never compacts IDs and copes: deleted content is dropped (below), IDs are run-compressed.

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
- Deleting a whole thing with `purge`: retire its bodies, no snapshot (state after reset is a timestamp). Deleting part of a value (a paragraph, a map entry): a snapshot of the aspect's live content must be uploaded first, so batch with a short debounce. The deletion constraint (notes/constraints.md) is met within that debounce, which must be bounded.
- Undo horizon: a node keeps its own bodies locally only while nobody has reset their content; others' resets with `purge` win over undo. For `purge`-class content the deleting node's own undo buffer falls under the deletion constraint, so the partial-purge debounce is also the undo window.
- Guessable preimages: a low-entropy delta (bool, PIN) could be brute-forced from hash(delta) after purge. Fix: every delta body carries a random nonce (hash covers it; purge destroys it). Also key outward-facing hashes (deltas, states, chunks) with BLAKE3 keyed mode using the thing's dedup secret (KDF of its creation nonce, which every reader holds; notes/permissions.md); closes known-file confirmation by anyone without it. Blind nodes store but cannot verify bodies.
- Chunks and tree nodes of large values are encrypted under random keys stored in their parent links, so a purged version's chunks are crypto-shredded with its commit wraps and chunk IDs are not fingerprints (notes/local-store.md; replaces the earlier derivation from the dedup secret). Forward-secure deletion also requires every local plaintext, wrap and index entry to live in the encrypted local store, so that dropping it is a key erasure.
- Caveat: cross-aspect atomicity against a purged aspect is lost for old commits. Deleted text content is already gone from state; only IDs remain.

Who may purge: the delta's author or an admin (decided 2026-10-11, notes/permissions.md, Purge rights); at blind nodes by delete tokens (notes/sync.md). Enforcement is only against honest nodes.

## Merge per type (encoding is self-describing; schema picks it, enforced at write time; changing = breaking, so entangled with AK versioning)
- scalars/tid/blob: LWW (HLC + node tiebreak). Knobs: `mv`; int/float `counter` (PN), `max`, `min`.
- string: LWW; `markdown`/`text` knob -> text CRDT below.
- struct: per-field. map: OR-map, recursive values, key removal = reset of the entry. set: OR-set. Knob `add_wins` (default) / `remove_wins`. Alternative: LWW-element-set (no causal context, one tombstone per removed element until the aspect is reset).
- enum: LWW whole value; same-case payload merge deferred.

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

## Dots and causal context
- Dot = (node, aspect-local counter), not commit seq. Per-aspect contexts collapse to one interval per node; gaps only from out-of-order arrival. Commit header maps each touched aspect to a counter range.
- Revocation (notes/permissions.md) needs every write attributable to an author node and dot, and droppable by dot. Timestamp-only registers are not enough; reconcile.
- Only OR-set/OR-map carry contexts. Registers, counters and text carry timestamps only, so a bool aspect is a value plus a timestamp.

## Undo/redo
- Undo = new commit that cancels a specific earlier commit; header has `undoes: commit id`. Signed, replicated, atomic across the original's aspects. Never removes history; purged commits are not undoable.
- Cancel per dot, not "apply inverse": undo insert = delete that ID; undo set-add = remove own dot only; undo counter inc = cancel that dot (idempotent if two devices undo concurrently); undo register write = write old value only if own write is still the winner; undo delete = undelete original IDs; undo reset = reinsert (above).
- Stack is derived, not stored: actor's own commits in scope, minus undone, plus undo commits for redo. Replicates for free -> cross-device undo. Scope = set of aspects or a group, app-chosen.
- An actor's own bodies (and pre-reset snapshots) are kept locally at least for the undo horizon.

## Sync
Moved to notes/sync.md. Kept here because they touch CRDT state:
- Clock: HLC (wall ms, counter, node tiebreak, advanced on receipt, drift capped).
- API needs path-based ops (set field, insert/remove index, add/remove key, splice text, increment). `set_aspect` = structural diff convenience + explicit replace (reset) variant.
- Bodies: retention class decides (purge/preserve/undefined, above). A node must always be able to serve current state: bodies or a snapshot (state sent as a delta).
- Content refill after a drop (text CRDT resurrect case) is a request for specific blobs, not a state comparison.

## Open (owner to decide)
- `set_aspect` default: diff vs replace.
- Expose `mv` register to apps in v1?
- Undo stack per actor (cross-device, but two active devices share an interleaved stack) or per node?
- set/map: OR with causal context vs LWW-element.
- Keyed hashes for multi-group things: answered, per-thing dedup secret from the creation nonce (notes/permissions.md); blobs carry their own keys (notes/sync.md).

## Research
- Loro's movable list and movable tree: production implementations of Kleppmann 2020 "Moving Elements in List CRDTs" and of tree cycle handling.
- Eg-walker (Gentle & Kleppmann 2024): op-based, but its text representation and size ideas transfer.
- Kleppmann & Beresford "A Conflict-Free Replicated JSON Datatype": nested struct/map/list composition, key removal vs concurrent nested edit.
- Kleppmann & Brattli "Undo and redo support for replicated registers and sets": matches dot-cancel undo.
- Willow/Meadowcap, Keyhive/Beelay, iroh: sync and permission shape, not merge semantics.
