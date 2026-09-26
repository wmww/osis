# Commits, CRDTs and sync primitives
> Summary: Proposed model for commits, per-aspect delta-state CRDTs, history purging and Merkle sync; discussed with owner 2026-09-25, proposal not yet confirmed.

## Decided so far
- A sync `connection` syncs one group (a thing with `/group`). Merkle trees compare and sync changed data; the group hierarchy (items, subgroups) forms the tree. Everything below is proposal.

## Layers (each a canonical CBOR value with a hash)
- **Aspect state**: delta-state CRDT (join-semilattice, single `join` op). Carries its own causal context (set of dots absorbed). Stored per aspect; hashed by the Merkle tree.
- **Delta**: a small state of the same lattice; applying = join. Idempotent, order-free, tolerates duplicates. No op log or ordered delivery needed.
- **Commit**: signed header + one delta per touched aspect. Header: author node, actor, HLC timestamp, per-node seq, list of (tid, ak, delta hash), signature. Commit ID = hash(header). Bodies addressed by own hash.

## Guarantees
- Convergence under any delivery order (so "reorder/rebase" is meaningless).
- Atomic visibility: all deltas of a commit for tracked aspects joined in one storage txn, listeners after.
- Not isolation: concurrent commits merge; app invariants must be merge-compatible or repaired via listeners.
- Causality is intra-aspect only (tids may dangle, see notes/data-model.md), so no commit DAG/parents required.

## History purge
- Delete bodies for one aspect; headers/signatures/IDs stay valid because bodies are by hash.
- Replacement = snapshot = the aspect's state sent as a delta.
- Caveats: sequence CRDT tombstones retain purged text until a hard reset (epoch bump); cross-aspect atomicity vs. purged aspect is lost for old commits.
- Guessable preimages: header keeps hash(delta), so a low-entropy delta (bool, PIN) could be brute-forced after purge. Fix: every delta body carries a random nonce (hash covers it; purge destroys it). Also key outward-facing hashes (deltas, states, chunks) with BLAKE3 keyed mode using a key derived from the thing/group read key; closes known-file confirmation on dedup'd chunks. Dots are not hashes, so a fully purged commit's header can be dropped too. Purge removes values, not the fact/time/AK of an edit.

## Merge per type (encoding is self-describing; schema picks it, enforced at write time; changing = breaking)
- scalars/tid/blob: LWW (HLC + node tiebreak). Knobs: `mv`; int/float `counter` (PN), `max`, `min`.
- string: LWW; `markdown`/`text` knob -> sequence CRDT over grapheme runs.
- struct: per-field. map: OR-map, recursive values. set: OR-set. Knob `add_wins` (default) / `remove_wins`.
- list and text are the same structure (text = list<char> with run compaction). Each element has a position register (LWW): "after element X" or TRASH. Insert, delete, move, undelete, cut/paste are all writes to it. Range move = one record "elements a..b after X at t" (compressed per-element writes; Kleppmann 2020 "Moving Elements in List CRDTs"). Concurrently inserted neighbours have no record so they follow their anchor: "FOOBAR" + insert x / move FOO -> "BARFOxO". Concurrent moves of the same range resolve per element by timestamp, never duplicate.
- Cut = move to TRASH, paste = move out of TRASH (IDs preserved, so others' concurrent edits inside the cut text travel with it; edits in between don't interfere). Client remembers cut ID range next to clipboard text; on paste emit move if it matches, else diff cut range vs pasted text -> moves + inserts. Cross-aspect paste = insert. Optional osis clipboard MIME type with (aspect, ID ranges). Protocol has no clipboard concept.
- Tradeoff: delete is LWW, not a permanent tombstone. Delete vs concurrent move -> timestamp decides, move may resurrect. TRASH elements are retained as anchors.
- Undo of a delete = move out of TRASH with original IDs (better than re-insert; keeps others' anchors valid).
- IDs on the wire: node-table index + varint seq + varint idx (2-4 bytes typical), mostly implicit via runs. Cost scales with run count, not value size. Needs prototype + adversarial tests.
- text state size target: 1.5x-3x plain text on real editing traces (run-length encoded runs, node-id table, delta-coded seqs). Benchmark against Kleppmann's automerge-paper trace before calling the text CRDT done.
- enum: LWW whole value; same-case payload merge deferred (needs epochs).
- **Reset/epoch** primitive: deltas tagged with epoch; join keeps max epoch, drops lower. Used by remove_aspect, delete_thing, map key removal, replace, hard purge. Observed-remove = add-wins flavor; epoch bump = remove-wins. Prior art: `clear` in Almeida/Shoker/Baquero "Delta State Replicated Data Types".

## Other consequences
- Merkle tree must hash *states* not values (equal values can have different contexts). Keep value hash for links/dedup; add state hash for sync. notes/data-model.md Hashing section says value hash; reconcile when deciding.
- Sync flow: compare trees -> divergent aspects -> transfer whole commits restricted to tracked aspects -> snapshots where bodies pruned.
- Dots = (node tid, commit seq, index). Per-aspect contexts are sparse interval sets per node.
- Clock: HLC (wall ms, counter, node tiebreak, advanced on receipt, drift capped).
- API needs path-based ops (set field, insert/remove index, add/remove key, splice text, increment). `set_aspect` = structural diff convenience + explicit replace variant.
- `history` flag: state always kept; bodies kept for a retention window, forever with `history`. An actor's own bodies are kept at least for the undo horizon regardless.

## Undo/redo
- Undo = new commit that cancels a specific earlier commit; header has `undoes: commit id`. Signed, replicated, atomic across the original's aspects. Never removes history; purged commits are not undoable.
- Cancel per dot, not "apply inverse": undo insert = delete that ID; undo set-add = remove own dot only; undo counter inc = cancel that dot (idempotent if two devices undo concurrently); undo register write = restore old value only if own write is still the winner; undo delete = move out of TRASH (original IDs).
- Stack is derived, not stored: actor's own commits in scope, minus undone, plus undo commits for redo. Replicates for free -> cross-device undo. Scope = set of aspects or a group, app-chosen.
- Chunking/prolly trees (see serialization.md) must apply to CRDT states too.
- Group Merkle tree: prolly tree over flattened sorted member set is simpler than following the cyclic hierarchy.

## Open (owner to decide)
- `set_aspect` default: diff vs replace.
- remove_aspect / delete_thing: observed-remove vs epoch bump.
- Expose `mv` register to apps in v1?
- Undo stack per actor (cross-device, but two active devices share an interleaved stack) or per node?
